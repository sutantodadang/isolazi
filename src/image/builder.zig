//! Image Builder
//!
//! Builds container images from Isolazifile/Dockerfile specifications.
//! Supports:
//! - FROM: Pull base image
//! - RUN: Execute commands in temporary container and commit layer
//! - COPY/ADD: Copy files from build context
//! - ENV/WORKDIR/EXPOSE/CMD/ENTRYPOINT: Set image configuration
//!
//! The build process creates OCI-compliant images stored in the local cache.

const std = @import("std");
const builtin = @import("builtin");
const isolazifile = @import("isolazifile.zig");
const cache = @import("cache.zig");
const layer = @import("layer.zig");
const reference = @import("reference.zig");
const executor = @import("executor.zig");
const mod = @import("mod.zig");

/// Build argument
pub const BuildArg = struct {
    name: []const u8,
    value: []const u8,
};

/// Build options
pub const BuildOptions = struct {
    /// Build context directory (where Isolazifile and source files are)
    context_path: []const u8,
    /// Path to Isolazifile (default: Isolazifile or Dockerfile in context)
    file_path: ?[]const u8 = null,
    /// Image tag (e.g., myimage:latest)
    tag: ?[]const u8 = null,
    /// Build arguments (--build-arg)
    build_args: []const BuildArg = &[_]BuildArg{},
    /// Force rebuild all layers (--no-cache)
    no_cache: bool = false,
    /// Target platform (e.g., linux/amd64)
    platform: ?[]const u8 = null,
    /// Quiet mode (suppress build output)
    quiet: bool = false,
};

/// Build result
pub const BuildResult = struct {
    /// Image reference for the built image
    image_ref: reference.ImageReference,
    /// Image ID (digest)
    image_id: []const u8,
    /// Total layers created
    layers_count: usize,
    /// Build duration in milliseconds
    duration_ms: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *BuildResult) void {
        self.allocator.free(self.image_id);
        // ImageReference is a simple struct with slice references, no deinit needed
    }
};

/// Build stage for progress reporting
pub const BuildStage = enum {
    parsing,
    pulling_base,
    building_layer,
    copying_files,
    committing,
    complete,
};

/// Progress callback
pub const ProgressCallback = *const fn (stage: BuildStage, detail: []const u8) void;

/// Build error
pub const BuildError = error{
    InvalidBuildContext,
    IsolazifileNotFound,
    InvalidIsolazifile,
    BaseImagePullFailed,
    LayerBuildFailed,
    FileCopyFailed,
    CommitFailed,
    OutOfMemory,
    IoError,
    AccessDenied,
    InvalidPath,
    ContextPathOutsideRoot,
    CommandFailed,
    ArchiveFailed,
};

/// Image builder
pub const Builder = struct {
    allocator: std.mem.Allocator,
    img_cache: *cache.ImageCache,
    progress_callback: ?ProgressCallback,
    executor: executor.Executor,
    layers: std.ArrayListUnmanaged([]const u8),

    const Self = @This();

    /// Initialize builder
    pub fn init(allocator: std.mem.Allocator, img_cache: *cache.ImageCache) Self {
        return Self{
            .allocator = allocator,
            .img_cache = img_cache,
            .progress_callback = null,
            .executor = executor.Executor.init(allocator),
            .layers = .empty,
        };
    }

    /// Deinitialize builder
    pub fn deinit(self: *Self) void {
        for (self.layers.items) |layer_digest| {
            self.allocator.free(layer_digest);
        }
        self.layers.deinit(self.allocator);
    }

    /// Set progress callback
    pub fn setProgressCallback(self: *Self, callback: ProgressCallback) void {
        self.progress_callback = callback;
    }

    /// Report progress
    fn reportProgress(self: *Self, stage: BuildStage, detail: []const u8) void {
        if (self.progress_callback) |cb| {
            cb(stage, detail);
        }
    }

    /// Build an image from Isolazifile
    pub fn build(self: *Self, options: BuildOptions) BuildError!BuildResult {
        const start_time = std.time.milliTimestamp();

        // Validate build context
        std.fs.cwd().access(options.context_path, .{}) catch {
            return BuildError.InvalidBuildContext;
        };

        // Find and parse Isolazifile
        self.reportProgress(.parsing, "Parsing Isolazifile");

        const isolazifile_path = try self.findIsolazifile(options.context_path, options.file_path);
        defer self.allocator.free(isolazifile_path);

        var parsed = isolazifile.parseFile(self.allocator, isolazifile_path) catch |err| {
            return switch (err) {
                isolazifile.ParseError.FileNotFound => BuildError.IsolazifileNotFound,
                else => BuildError.InvalidIsolazifile,
            };
        };
        defer parsed.deinit();

        // Apply build args
        for (options.build_args) |arg| {
            const key = self.allocator.dupe(u8, arg.name) catch return BuildError.OutOfMemory;
            const value = self.allocator.dupe(u8, arg.value) catch {
                self.allocator.free(key);
                return BuildError.OutOfMemory;
            };
            parsed.args.put(key, value) catch {
                self.allocator.free(key);
                self.allocator.free(value);
                return BuildError.OutOfMemory;
            };
        }

        // Get base image
        const base_image = parsed.getBaseImage() orelse return BuildError.InvalidIsolazifile;
        const base_ref = base_image.getReference(self.allocator) catch return BuildError.OutOfMemory;
        defer self.allocator.free(base_ref);

        // Pull base image
        self.reportProgress(.pulling_base, base_ref);

        const pulled_ref = mod.pullImage(
            self.allocator,
            base_ref,
            self.img_cache,
            null,
            null,
        ) catch {
            return BuildError.BaseImagePullFailed;
        };
        _ = pulled_ref;

        // Create build container from base image
        var current_container_id = try self.createBuildContainer(base_ref);
        defer self.allocator.free(current_container_id);

        // Track parent digest for cache keys
        var parent_digest = try self.allocator.dupe(u8, base_ref);
        defer self.allocator.free(parent_digest);

        var layers_created: usize = 0;

        // Image configuration accumulated from instructions
        var image_config = ImageConfig{
            .env = .empty,
            .cmd = null,
            .entrypoint = null,
            .workdir = null,
            .exposed_ports = .empty,
            .labels = std.StringHashMap([]const u8).init(self.allocator),
            .user = null,
            .volumes = .empty,
        };
        defer {
            for (image_config.env.items) |e| self.allocator.free(e);
            image_config.env.deinit(self.allocator);
            if (image_config.cmd) |c| self.allocator.free(c);
            if (image_config.entrypoint) |e| self.allocator.free(e);
            if (image_config.workdir) |w| self.allocator.free(w);
            image_config.exposed_ports.deinit(self.allocator);
            var label_iter = image_config.labels.iterator();
            while (label_iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            image_config.labels.deinit();
            if (image_config.user) |u| self.allocator.free(u);
            for (image_config.volumes.items) |v| self.allocator.free(v);
            image_config.volumes.deinit(self.allocator);
        }

        // Process instructions
        const total_steps = parsed.instructions.len;
        for (parsed.instructions, 0..) |inst, i| {
            switch (inst) {
                .from => |from_inst| {
                    const detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] FROM {s}", .{ i + 1, total_steps, from_inst.image }) catch "FROM ...";
                    defer if (std.mem.startsWith(u8, detail, "[")) self.allocator.free(detail);
                    self.reportProgress(.parsing, detail);
                },
                .run => |run| {
                    const detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] RUN {s}", .{ i + 1, total_steps, run.command }) catch "RUN ...";
                    defer if (std.mem.startsWith(u8, detail, "[")) self.allocator.free(detail);

                    self.reportProgress(.building_layer, detail);

                    // Execute RUN command in container
                    // Check cache first
                    var used_cache = false;
                    if (!options.no_cache) {
                        const cache_key = try self.calculateCacheKey(parent_digest, run.command, &image_config.env);
                        defer self.allocator.free(cache_key);

                        const maybe_cached = self.img_cache.getBuildCache(cache_key) catch |err| switch (err) {
                            error.OutOfMemory => return BuildError.OutOfMemory,
                            else => null,
                        };
                        if (maybe_cached) |cached_digest| {
                            defer self.allocator.free(cached_digest);
                            self.reportProgress(.building_layer, "Using cache");

                            // Rehydrate state from cache
                            try self.layers.append(self.allocator, try self.allocator.dupe(u8, cached_digest));

                            self.allocator.free(current_container_id);
                            current_container_id = try self.createBuildContainerFromLayer(cached_digest);

                            // Update parent digest
                            self.allocator.free(parent_digest);
                            parent_digest = try self.allocator.dupe(u8, cached_digest);

                            used_cache = true;
                        }
                    }

                    if (!used_cache) {
                        try self.executeRunInstruction(current_container_id, run, image_config.workdir);

                        // Commit changes as new layer
                        const commit_detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] Committing layer", .{ i + 1, total_steps }) catch "Committing layer";
                        defer if (std.mem.startsWith(u8, commit_detail, "[")) self.allocator.free(commit_detail);

                        self.reportProgress(.committing, commit_detail);
                        const new_layer_digest = try self.commitLayer(current_container_id);
                        try self.layers.append(self.allocator, try self.allocator.dupe(u8, new_layer_digest));
                        defer self.allocator.free(new_layer_digest); // kept in layers array

                        // Update cache
                        if (!options.no_cache) {
                            const cache_key = try self.calculateCacheKey(parent_digest, run.command, &image_config.env);
                            defer self.allocator.free(cache_key);
                            self.img_cache.putBuildCache(cache_key, new_layer_digest) catch |err| switch (err) {
                                error.OutOfMemory => return BuildError.OutOfMemory,
                                else => {},
                            };
                        }

                        // Update parent digest
                        self.allocator.free(parent_digest);
                        parent_digest = try self.allocator.dupe(u8, new_layer_digest);

                        // Update container to use new layer
                        self.allocator.free(current_container_id);
                        current_container_id = try self.createBuildContainerFromLayer(new_layer_digest);
                    }
                    layers_created += 1;
                },
                .copy => |copy_inst| {
                    var detail_buf: [256]u8 = undefined;
                    const copy_info = std.fmt.bufPrint(&detail_buf, "COPY {s} -> {s}", .{
                        if (copy_inst.sources.len > 0) copy_inst.sources[0] else ".",
                        copy_inst.destination,
                    }) catch "COPY files";

                    const detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] {s}", .{ i + 1, total_steps, copy_info }) catch "COPY ...";
                    defer if (std.mem.startsWith(u8, detail, "[")) self.allocator.free(detail);

                    self.reportProgress(.copying_files, detail);

                    try self.executeCopyInstruction(
                        current_container_id,
                        copy_inst,
                        options.context_path,
                    );

                    // Commit COPY changes as layer
                    // Commit COPY changes as layer
                    const commit_detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] Committing layer", .{ i + 1, total_steps }) catch "Committing layer";
                    defer if (std.mem.startsWith(u8, commit_detail, "[")) self.allocator.free(commit_detail);

                    self.reportProgress(.committing, commit_detail);
                    const new_layer_digest = try self.commitLayer(current_container_id);
                    try self.layers.append(self.allocator, try self.allocator.dupe(u8, new_layer_digest));
                    defer self.allocator.free(new_layer_digest);

                    self.allocator.free(parent_digest);
                    parent_digest = try self.allocator.dupe(u8, new_layer_digest);

                    self.allocator.free(current_container_id);
                    current_container_id = try self.createBuildContainerFromLayer(new_layer_digest);

                    layers_created += 1;
                },
                .add => |add_inst| {
                    const detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] ADD ...", .{ i + 1, total_steps }) catch "ADD ...";
                    defer if (std.mem.startsWith(u8, detail, "[")) self.allocator.free(detail);

                    self.reportProgress(.copying_files, detail);

                    // ADD is like COPY but with URL and tar extraction support
                    try self.executeAddInstruction(
                        current_container_id,
                        add_inst,
                        options.context_path,
                    );

                    // Commit ADD changes as layer
                    const commit_detail = std.fmt.allocPrint(self.allocator, "[{d}/{d}] Committing layer", .{ i + 1, total_steps }) catch "Committing layer";
                    defer if (std.mem.startsWith(u8, commit_detail, "[")) self.allocator.free(commit_detail);

                    self.reportProgress(.committing, commit_detail);
                    const new_layer_digest = try self.commitLayer(current_container_id);
                    try self.layers.append(self.allocator, try self.allocator.dupe(u8, new_layer_digest));
                    defer self.allocator.free(new_layer_digest);

                    self.allocator.free(parent_digest);
                    parent_digest = try self.allocator.dupe(u8, new_layer_digest);

                    self.allocator.free(current_container_id);
                    current_container_id = try self.createBuildContainerFromLayer(new_layer_digest);

                    layers_created += 1;
                },
                .env => |env| {
                    // Accumulate environment variables
                    for (env.vars) |v| {
                        const env_str = std.fmt.allocPrint(self.allocator, "{s}={s}", .{ v.key, v.value }) catch return BuildError.OutOfMemory;
                        image_config.env.append(self.allocator, env_str) catch return BuildError.OutOfMemory;
                    }
                },
                .workdir => |wd| {
                    // Set working directory
                    if (image_config.workdir) |old| self.allocator.free(old);
                    image_config.workdir = self.allocator.dupe(u8, wd.path) catch return BuildError.OutOfMemory;
                },
                .expose => |exp| {
                    // Document exposed ports
                    for (exp.ports) |p| {
                        image_config.exposed_ports.append(self.allocator, p.port) catch return BuildError.OutOfMemory;
                    }
                },
                .cmd => |cmd| {
                    // Set default command
                    if (image_config.cmd) |old| self.allocator.free(old);
                    if (cmd.is_exec_form and cmd.exec_args.len > 0) {
                        // Serialize exec form to JSON
                        image_config.cmd = try self.serializeExecForm(cmd.exec_args);
                    } else {
                        image_config.cmd = self.allocator.dupe(u8, cmd.command) catch return BuildError.OutOfMemory;
                    }
                },
                .entrypoint => |ep| {
                    // Set entrypoint
                    if (image_config.entrypoint) |old| self.allocator.free(old);
                    if (ep.is_exec_form and ep.exec_args.len > 0) {
                        image_config.entrypoint = try self.serializeExecForm(ep.exec_args);
                    } else {
                        image_config.entrypoint = self.allocator.dupe(u8, ep.command) catch return BuildError.OutOfMemory;
                    }
                },
                .arg => {
                    // Already handled during parsing
                },
                .label => |lbl| {
                    // Add labels to image metadata
                    for (lbl.labels) |l| {
                        const key = self.allocator.dupe(u8, l.key) catch return BuildError.OutOfMemory;
                        const value = self.allocator.dupe(u8, l.value) catch {
                            self.allocator.free(key);
                            return BuildError.OutOfMemory;
                        };
                        image_config.labels.put(key, value) catch {
                            self.allocator.free(key);
                            self.allocator.free(value);
                            return BuildError.OutOfMemory;
                        };
                    }
                },
                .user => |usr| {
                    if (image_config.user) |old| self.allocator.free(old);
                    image_config.user = self.allocator.dupe(u8, usr.user) catch return BuildError.OutOfMemory;
                },
                .volume => |vol| {
                    for (vol.paths) |p| {
                        image_config.volumes.append(
                            self.allocator,
                            self.allocator.dupe(u8, p) catch return BuildError.OutOfMemory,
                        ) catch return BuildError.OutOfMemory;
                    }
                },
            }
        }

        // Create final image with config
        self.reportProgress(.complete, "Build complete");

        const image_id = try self.createFinalImage(
            current_container_id,
            options.tag,
            &image_config,
        );

        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

        // Create image reference
        var final_ref: reference.ImageReference = undefined;
        if (options.tag) |tag| {
            final_ref = reference.parse(tag) catch {
                return BuildError.InvalidPath;
            };
        } else {
            // Generate a default tag
            final_ref = .{
                .registry = "localhost",
                .repository = "built-image",
                .tag = "latest",
                .digest = null,
            };
        }

        return BuildResult{
            .image_ref = final_ref,
            .image_id = image_id,
            .layers_count = layers_created,
            .duration_ms = duration,
            .allocator = self.allocator,
        };
    }

    /// Find Isolazifile path
    fn findIsolazifile(self: *Self, context_path: []const u8, file_path: ?[]const u8) BuildError![]const u8 {
        if (file_path) |fp| {
            return self.allocator.dupe(u8, fp) catch return BuildError.OutOfMemory;
        }

        // Try Isolazifile first, then Dockerfile
        const candidates = [_][]const u8{ "Isolazifile", "Dockerfile" };
        for (candidates) |candidate| {
            const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ context_path, candidate }) catch return BuildError.OutOfMemory;
            if (std.fs.cwd().access(path, .{})) |_| {
                return path;
            } else |_| {
                self.allocator.free(path);
            }
        }

        return BuildError.IsolazifileNotFound;
    }

    /// Calculate build cache key
    fn calculateCacheKey(self: *Builder, parent_digest: []const u8, instruction: []const u8, env: *std.ArrayList([]const u8)) ![]const u8 {
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(parent_digest);
        sha.update(instruction);
        for (env.items) |e| {
            sha.update(e);
        }

        const digest = sha.finalResult();
        const hex = std.fmt.bytesToHex(digest, .lower);
        return self.allocator.dupe(u8, &hex);
    }

    /// Create a temporary build container from base image
    fn createBuildContainer(self: *Self, base_ref: []const u8) BuildError![]const u8 {
        // Generate container ID
        var id_buf: [16]u8 = undefined;
        std.crypto.random.bytes(&id_buf);

        var container_id: [32]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (id_buf, 0..) |byte, i| {
            container_id[i * 2] = hex_chars[byte >> 4];
            container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        const container_id_slice = self.allocator.dupe(u8, &container_id) catch return BuildError.OutOfMemory;
        errdefer self.allocator.free(container_id_slice);

        // Get base image manifest and extract layers
        const ref = reference.parse(base_ref) catch return BuildError.InvalidPath;

        // Get manifest from cache
        const manifest_json = self.img_cache.readManifest(&ref) catch return BuildError.IsolazifileNotFound;
        defer self.allocator.free(manifest_json);

        // Parse manifest to get layers
        const ManifestLayer = struct {
            digest: []const u8,
        };
        const Manifest = struct {
            layers: []const ManifestLayer,
        };

        const parsed = std.json.parseFromSlice(Manifest, self.allocator, manifest_json, .{ .ignore_unknown_fields = true }) catch return BuildError.InvalidIsolazifile;
        defer parsed.deinit();

        // Extract layers
        var layer_digests: std.ArrayList([]const u8) = .empty;
        defer layer_digests.deinit(self.allocator);

        for (parsed.value.layers) |l| {
            const digest_copy = try self.allocator.dupe(u8, l.digest);
            try self.layers.append(self.allocator, digest_copy);
            try layer_digests.append(self.allocator, l.digest);
        }

        // Prepare container (extract layers)
        const rootfs_path = self.img_cache.prepareContainer(container_id_slice, layer_digests.items) catch return BuildError.IoError;
        self.allocator.free(rootfs_path);

        return container_id_slice;
    }

    /// Create build container from existing layer
    fn createBuildContainerFromLayer(self: *Self, layer_digest: []const u8) BuildError![]const u8 {
        // Similar to createBuildContainer but uses specific layer
        var id_buf: [16]u8 = undefined;
        std.crypto.random.bytes(&id_buf);

        var container_id: [32]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (id_buf, 0..) |byte, i| {
            container_id[i * 2] = hex_chars[byte >> 4];
            container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        const container_id_slice = self.allocator.dupe(u8, &container_id) catch return BuildError.OutOfMemory;
        errdefer self.allocator.free(container_id_slice);

        // Extract just the provided layer (since commitLayer creates full snapshots)
        var layer_digests: std.ArrayList([]const u8) = .empty;
        defer layer_digests.deinit(self.allocator);

        try layer_digests.append(self.allocator, layer_digest);

        const rootfs_path = self.img_cache.prepareContainer(container_id_slice, layer_digests.items) catch return BuildError.IoError;
        self.allocator.free(rootfs_path);

        return container_id_slice;
    }

    /// Execute RUN instruction
    fn executeRunInstruction(
        self: *Self,
        container_id: []const u8,
        run: isolazifile.RunInstruction,
        workdir: ?[]const u8,
    ) BuildError!void {

        // Platform-specific execution via Executor
        const rootfs_path = self.img_cache.getContainerPath(container_id) catch return BuildError.IoError;
        defer self.allocator.free(rootfs_path);

        // Env vars to slice
        var env_vars: std.ArrayList(isolazifile.EnvInstruction.EnvVar) = .empty;
        defer env_vars.deinit(self.allocator);

        // TODO: Merge inherited env vars from base image config here

        self.executor.runCommand(
            rootfs_path,
            run.command,
            env_vars.items,
            workdir,
        ) catch |err| {
            std.debug.print("Execute failed: {}\n", .{err});
            return BuildError.CommandFailed;
        };
    }

    /// Execute COPY instruction
    fn executeCopyInstruction(
        self: *Self,
        container_id: []const u8,
        copy_inst: isolazifile.CopyInstruction,
        context_path: []const u8,
    ) BuildError!void {
        const rootfs_path = self.img_cache.getContainerPath(container_id) catch return BuildError.IoError;
        defer self.allocator.free(rootfs_path);

        // Resolve destination path
        const dest_path = std.fmt.allocPrint(
            self.allocator,
            "{s}{s}",
            .{ rootfs_path, copy_inst.destination },
        ) catch return BuildError.OutOfMemory;
        defer self.allocator.free(dest_path);

        // Copy each source
        for (copy_inst.sources) |src| {
            const src_path = std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}",
                .{ context_path, src },
            ) catch return BuildError.OutOfMemory;
            defer self.allocator.free(src_path);

            // Check source exists
            std.fs.cwd().access(src_path, .{}) catch return BuildError.FileCopyFailed;

            // Create destination directory
            if (std.fs.path.dirname(dest_path)) |dir| {
                std.fs.cwd().makePath(dir) catch {};
            }

            // Copy file or directory
            // For now, use platform command
            const copy_result = std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = if (builtin.os.tag == .windows)
                    &[_][]const u8{ "cmd", "/c", "copy", src_path, dest_path }
                else
                    &[_][]const u8{ "cp", "-r", src_path, dest_path },
            }) catch return BuildError.FileCopyFailed;
            defer {
                self.allocator.free(copy_result.stdout);
                self.allocator.free(copy_result.stderr);
            }
        }
    }

    /// Execute ADD instruction
    fn executeAddInstruction(
        self: *Self,
        container_id: []const u8,
        add_inst: isolazifile.AddInstruction,
        context_path: []const u8,
    ) BuildError!void {
        // ADD is similar to COPY but:
        // 1. Can download from URLs
        // 2. Auto-extracts tar files

        for (add_inst.sources) |src| {
            // Check if source is a URL
            if (std.mem.startsWith(u8, src, "http://") or std.mem.startsWith(u8, src, "https://")) {
                // Download URL
                // For now, skip URL downloads - would need HTTP client
                continue;
            }

            // Check if source is a tar file to extract
            const is_tar = std.mem.endsWith(u8, src, ".tar") or
                std.mem.endsWith(u8, src, ".tar.gz") or
                std.mem.endsWith(u8, src, ".tgz") or
                std.mem.endsWith(u8, src, ".tar.bz2") or
                std.mem.endsWith(u8, src, ".tar.xz");

            if (is_tar) {
                const rootfs_path = self.img_cache.getContainerPath(container_id) catch return BuildError.IoError;
                defer self.allocator.free(rootfs_path);

                const src_path = std.fmt.allocPrint(
                    self.allocator,
                    "{s}/{s}",
                    .{ context_path, src },
                ) catch return BuildError.OutOfMemory;
                defer self.allocator.free(src_path);

                const dest_path = std.fmt.allocPrint(
                    self.allocator,
                    "{s}{s}",
                    .{ rootfs_path, add_inst.destination },
                ) catch return BuildError.OutOfMemory;
                defer self.allocator.free(dest_path);

                // Extract tar
                _ = layer.extractLayer(self.allocator, src_path, dest_path, null) catch {
                    return BuildError.FileCopyFailed;
                };
            } else {
                // Regular copy
                try self.executeCopyInstruction(container_id, .{
                    .sources = &[_][]const u8{src},
                    .destination = add_inst.destination,
                    .chown = add_inst.chown,
                    .chmod = add_inst.chmod,
                    .from_stage = null,
                }, context_path);
            }
        }
    }

    /// Commit container changes as a new layer
    fn commitLayer(self: *Self, container_id: []const u8) BuildError![]const u8 {
        // Get container rootfs
        const rootfs_path = self.img_cache.getContainerPath(container_id) catch return BuildError.IoError;
        defer self.allocator.free(rootfs_path);

        // Create tar of container contents
        const layer_tar_path = std.fmt.allocPrint(
            self.allocator,
            "{s}/tmp/layer_{s}.tar.gz",
            .{ self.img_cache.base_path, container_id[0..12] },
        ) catch return BuildError.OutOfMemory;
        defer self.allocator.free(layer_tar_path);

        // Ensure tmp directory exists
        const tmp_dir = std.fmt.allocPrint(
            self.allocator,
            "{s}/tmp",
            .{self.img_cache.base_path},
        ) catch return BuildError.OutOfMemory;
        defer self.allocator.free(tmp_dir);
        std.fs.cwd().makePath(tmp_dir) catch {};

        // Create tar archive using executor
        self.executor.archiveDirectory(rootfs_path, layer_tar_path) catch return BuildError.CommitFailed;

        // Calculate digest of layer
        var hash: [32]u8 = undefined;
        {
            const file = std.fs.cwd().openFile(layer_tar_path, .{}) catch return BuildError.IoError;
            defer file.close();

            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            var buf: [32 * 1024]u8 = undefined;

            while (true) {
                const n = file.read(&buf) catch return BuildError.IoError;
                if (n == 0) break;
                hasher.update(buf[0..n]);
            }
            hash = hasher.finalResult();
        }

        var digest_buf: [128]u8 = undefined;
        const digest = std.fmt.bufPrint(&digest_buf, "sha256:{x}", .{
            hash,
        }) catch return BuildError.OutOfMemory;

        // Store layer in cache
        self.img_cache.storeBlobFromFile(digest, layer_tar_path) catch return BuildError.IoError;

        // Cleanup tmp file
        std.fs.cwd().deleteFile(layer_tar_path) catch {};

        return self.allocator.dupe(u8, digest) catch return BuildError.OutOfMemory;
    }

    /// Create final image with config
    fn createFinalImage(
        self: *Self,
        container_id: []const u8,
        tag: ?[]const u8,
        config: *const ImageConfig,
    ) BuildError![]const u8 {
        _ = container_id; // Unused, we use accumulated self.layers

        // 1. Create Image Config JSON
        // ===========================
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        var root = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };

        try root.object.put("architecture", std.json.Value{ .string = "amd64" });
        try root.object.put("os", std.json.Value{ .string = "linux" });

        // Config object
        var config_obj = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };

        // Env
        if (config.env.items.len > 0) {
            var env_arr = std.json.Array.init(arena_alloc);
            for (config.env.items) |e| {
                try env_arr.append(std.json.Value{ .string = e });
            }
            try config_obj.object.put("Env", std.json.Value{ .array = env_arr });
        }

        // Cmd
        if (config.cmd) |c| {
            if (std.mem.startsWith(u8, c, "[")) {
                // Parse existing JSON array string
                const parsed_cmd = std.json.parseFromSlice(std.json.Value, arena_alloc, c, .{}) catch return BuildError.InvalidIsolazifile;
                try config_obj.object.put("Cmd", parsed_cmd.value);
            } else {
                // Shell form
                var cmd_arr = std.json.Array.init(arena_alloc);
                try cmd_arr.append(std.json.Value{ .string = "/bin/sh" });
                try cmd_arr.append(std.json.Value{ .string = "-c" });
                try cmd_arr.append(std.json.Value{ .string = c });
                try config_obj.object.put("Cmd", std.json.Value{ .array = cmd_arr });
            }
        }

        // Entrypoint
        if (config.entrypoint) |ep| {
            if (std.mem.startsWith(u8, ep, "[")) {
                const parsed_ep = std.json.parseFromSlice(std.json.Value, arena_alloc, ep, .{}) catch return BuildError.InvalidIsolazifile;
                try config_obj.object.put("Entrypoint", parsed_ep.value);
            } else {
                var ep_arr = std.json.Array.init(arena_alloc);
                try ep_arr.append(std.json.Value{ .string = "/bin/sh" });
                try ep_arr.append(std.json.Value{ .string = "-c" });
                try ep_arr.append(std.json.Value{ .string = ep });
                try config_obj.object.put("Entrypoint", std.json.Value{ .array = ep_arr });
            }
        }

        // WorkingDir
        if (config.workdir) |wd| {
            try config_obj.object.put("WorkingDir", std.json.Value{ .string = wd });
        }

        // ExposedPorts
        if (config.exposed_ports.items.len > 0) {
            var ports_obj = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };
            for (config.exposed_ports.items) |p| {
                const port_key = std.fmt.allocPrint(arena_alloc, "{d}/tcp", .{p}) catch return BuildError.OutOfMemory;
                try ports_obj.object.put(port_key, std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) });
            }
            try config_obj.object.put("ExposedPorts", ports_obj);
        }

        try root.object.put("config", config_obj);

        // RootFS
        var rootfs_obj = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };
        try rootfs_obj.object.put("type", std.json.Value{ .string = "layers" });

        var diff_ids_arr = std.json.Array.init(arena_alloc);
        for (self.layers.items) |l| {
            // Note: Should be uncompressed digest, but we use compressed for now
            try diff_ids_arr.append(std.json.Value{ .string = l });
        }
        try rootfs_obj.object.put("diff_ids", std.json.Value{ .array = diff_ids_arr });

        try root.object.put("rootfs", rootfs_obj);
        try root.object.put("history", std.json.Value{ .array = std.json.Array.init(arena_alloc) });

        // Serialize Config
        const config_json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(root, .{})});
        defer self.allocator.free(config_json);

        // Store Config Blob
        var digest_buf: [128]u8 = undefined;
        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        sha256.update(config_json);
        const config_hash = sha256.finalResult();
        const config_digest = std.fmt.bufPrint(&digest_buf, "sha256:{x}", .{config_hash}) catch return BuildError.OutOfMemory;

        self.img_cache.storeBlob(config_digest, config_json) catch return BuildError.IoError;

        // 2. Create Manifest JSON
        // =======================
        // Reuse arena for manifest structure

        var manifest = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };
        try manifest.object.put("schemaVersion", std.json.Value{ .integer = 2 });
        try manifest.object.put("mediaType", std.json.Value{ .string = "application/vnd.oci.image.manifest.v1+json" });

        // Manifest Config Reference
        var m_config = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };
        try m_config.object.put("mediaType", std.json.Value{ .string = "application/vnd.oci.image.config.v1+json" });
        try m_config.object.put("digest", std.json.Value{ .string = config_digest });
        try m_config.object.put("size", std.json.Value{ .integer = @intCast(config_json.len) });
        try manifest.object.put("config", m_config);

        // Layers
        var layers_arr = std.json.Array.init(arena_alloc);
        for (self.layers.items) |l_digest| {
            var layer_obj = std.json.Value{ .object = std.json.ObjectMap.init(arena_alloc) };
            try layer_obj.object.put("mediaType", std.json.Value{ .string = "application/vnd.oci.image.layer.v1.tar+gzip" });
            try layer_obj.object.put("digest", std.json.Value{ .string = l_digest });

            // Get size from cache file
            const blob_path = self.img_cache.getBlobPath(l_digest) catch return BuildError.IoError;
            const stat = std.fs.cwd().statFile(blob_path) catch {
                self.allocator.free(blob_path);
                return BuildError.IoError;
            };
            self.allocator.free(blob_path);

            try layer_obj.object.put("size", std.json.Value{ .integer = @intCast(stat.size) });
            try layers_arr.append(layer_obj);
        }
        try manifest.object.put("layers", std.json.Value{ .array = layers_arr });

        // Serialize Manifest
        const manifest_json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(manifest, .{})});
        defer self.allocator.free(manifest_json);

        // Calculate Manifest ID (digest) for return value
        var man_hash: [32]u8 = undefined;
        var sha_man = std.crypto.hash.sha2.Sha256.init(.{});
        sha_man.update(manifest_json);
        man_hash = sha_man.finalResult();
        _ = std.fmt.bufPrint(&digest_buf, "sha256:{x}", .{man_hash}) catch return BuildError.OutOfMemory;
        const config_digest_ptr = self.allocator.dupe(u8, config_digest) catch return BuildError.OutOfMemory; // Return stored ID

        // 3. Store Manifest if tag provided
        if (tag) |t| {
            const ref = reference.parse(t) catch return BuildError.InvalidPath;
            // No need to deinit ref (slices)
            self.img_cache.storeManifest(&ref, manifest_json) catch return BuildError.IoError;
        }

        return config_digest_ptr; // Traditionally Image ID is Config Digest
    }

    /// Serialize exec form to JSON array string
    fn serializeExecForm(self: *Self, args: []const []const u8) BuildError![]const u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        result.append(self.allocator, '[') catch return BuildError.OutOfMemory;
        for (args, 0..) |arg, i| {
            if (i > 0) result.append(self.allocator, ',') catch return BuildError.OutOfMemory;
            result.append(self.allocator, '"') catch return BuildError.OutOfMemory;
            result.appendSlice(self.allocator, arg) catch return BuildError.OutOfMemory;
            result.append(self.allocator, '"') catch return BuildError.OutOfMemory;
        }
        result.append(self.allocator, ']') catch return BuildError.OutOfMemory;

        return result.toOwnedSlice(self.allocator) catch return BuildError.OutOfMemory;
    }
};

/// Accumulated image configuration
const ImageConfig = struct {
    env: std.ArrayList([]const u8),
    cmd: ?[]const u8,
    entrypoint: ?[]const u8,
    workdir: ?[]const u8,
    exposed_ports: std.ArrayList(u16),
    labels: std.StringHashMap([]const u8),
    user: ?[]const u8,
    volumes: std.ArrayList([]const u8),
};

// =============================================================================
// Tests
// =============================================================================

test "Builder init" {
    const allocator = std.testing.allocator;

    var img_cache = try cache.ImageCache.init(allocator);
    defer img_cache.deinit();

    const builder = Builder.init(allocator, &img_cache);
    _ = builder;
}
