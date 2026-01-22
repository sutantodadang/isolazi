//! OCI Image Local Cache
//!
//! Manages local storage of pulled OCI images using content-addressable storage.
//! Structure:
//!   ~/.isolazi/
//!     images/
//!       blobs/
//!         sha256/
//!           <digest>  -- raw blob data
//!       manifests/
//!         <registry>/
//!           <repository>/
//!             <tag>.json  -- manifest file
//!       index.json  -- image index with metadata
//!     containers/
//!       <container-id>/
//!         rootfs/  -- extracted container filesystem

const std = @import("std");
const reference = @import("reference.zig");
const layer = @import("layer.zig");

const ImageReference = reference.ImageReference;

pub const CacheError = error{
    CacheNotInitialized,
    ImageNotFound,
    ManifestNotFound,
    BlobNotFound,
    CorruptedCache,
    DiskFull,
    AccessDenied,
    OutOfMemory,
};

/// Info about a cached image (for listing)
pub const CachedImageInfo = struct {
    registry: []const u8,
    repository: []const u8,
    tag: []const u8,

    pub fn deinit(self: *CachedImageInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.registry);
        allocator.free(self.repository);
        allocator.free(self.tag);
    }
};

/// Cached image metadata
pub const CachedImage = struct {
    reference: ImageReference,
    manifest_digest: []const u8,
    config_digest: []const u8,
    layers: []const []const u8,
    size: u64,
    created: i64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CachedImage) void {
        self.allocator.free(self.manifest_digest);
        self.allocator.free(self.config_digest);
        for (self.layers) |l| {
            self.allocator.free(l);
        }
        self.allocator.free(self.layers);
        self.reference.deinit();
    }
};

/// Image cache manager
pub const ImageCache = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,

    const Self = @This();

    /// Initialize the image cache
    pub fn init(allocator: std.mem.Allocator) !Self {
        // Get home directory
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => blk: {
                // Try USERPROFILE for Windows
                break :blk std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
                    return CacheError.CacheNotInitialized;
                };
            },
            else => return CacheError.CacheNotInitialized,
        };
        defer allocator.free(home);

        // Create base path: ~/.isolazi
        const base_path = try std.fmt.allocPrint(allocator, "{s}/.isolazi", .{home});

        // Create directory structure
        const dirs = [_][]const u8{
            "",
            "/images",
            "/images/blobs",
            "/images/blobs/sha256",
            "/images/manifests",
            "/containers",
        };

        for (dirs) |dir| {
            const full_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base_path, dir });
            defer allocator.free(full_path);
            std.fs.cwd().makePath(full_path) catch |e| switch (e) {
                error.PathAlreadyExists => {},
                else => return CacheError.AccessDenied,
            };
        }

        return Self{
            .allocator = allocator,
            .base_path = base_path,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.base_path);
    }

    /// Get the path for a blob by its digest
    pub fn getBlobPath(self: *const Self, digest: []const u8) ![]const u8 {
        // Digest format: sha256:hexstring
        if (!std.mem.startsWith(u8, digest, "sha256:")) {
            return CacheError.CorruptedCache;
        }
        const hash = digest[7..];
        return std.fmt.allocPrint(self.allocator, "{s}/images/blobs/sha256/{s}", .{ self.base_path, hash });
    }

    /// Check if a blob exists in cache
    pub fn hasBlob(self: *const Self, digest: []const u8) !bool {
        const blob_path = try self.getBlobPath(digest);
        defer self.allocator.free(blob_path);

        std.fs.cwd().access(blob_path, .{}) catch return false;
        return true;
    }

    /// Store a blob in the cache
    pub fn storeBlob(self: *const Self, digest: []const u8, data: []const u8) !void {
        const blob_path = try self.getBlobPath(digest);
        defer self.allocator.free(blob_path);

        const file = std.fs.cwd().createFile(blob_path, .{}) catch return CacheError.AccessDenied;
        defer file.close();
        file.writeAll(data) catch return CacheError.AccessDenied;
    }

    /// Store a blob from a file (for large blobs)
    pub fn storeBlobFromFile(self: *const Self, digest: []const u8, source_path: []const u8) !void {
        const blob_path = try self.getBlobPath(digest);
        defer self.allocator.free(blob_path);

        std.fs.cwd().copyFile(source_path, std.fs.cwd(), blob_path, .{}) catch return CacheError.AccessDenied;
    }

    /// Read a blob from cache
    pub fn readBlob(self: *const Self, digest: []const u8) ![]u8 {
        const blob_path = try self.getBlobPath(digest);
        defer self.allocator.free(blob_path);

        return std.fs.cwd().readFileAlloc(self.allocator, blob_path, 100 * 1024 * 1024) catch {
            return CacheError.BlobNotFound;
        };
    }

    /// Get manifest path for an image reference
    pub fn getManifestPath(self: *const Self, ref: *const ImageReference) ![]const u8 {
        const tag_or_digest = if (ref.digest) |d| d else (ref.tag orelse "latest");

        // Sanitize repository path (replace / with _)
        var repo_safe: [512]u8 = undefined;
        var repo_len: usize = 0;
        for (ref.repository) |c| {
            if (c == '/') {
                repo_safe[repo_len] = '_';
            } else {
                repo_safe[repo_len] = c;
            }
            repo_len += 1;
            if (repo_len >= repo_safe.len) break;
        }

        return std.fmt.allocPrint(
            self.allocator,
            "{s}/images/manifests/{s}/{s}/{s}.json",
            .{ self.base_path, ref.registry, repo_safe[0..repo_len], tag_or_digest },
        );
    }

    /// Store a manifest in cache
    pub fn storeManifest(self: *const Self, ref: *const ImageReference, manifest_json: []const u8) !void {
        const manifest_path = try self.getManifestPath(ref);
        defer self.allocator.free(manifest_path);

        // Create parent directories
        if (std.fs.path.dirname(manifest_path)) |parent| {
            std.fs.cwd().makePath(parent) catch {};
        }

        const file = std.fs.cwd().createFile(manifest_path, .{}) catch return CacheError.AccessDenied;
        defer file.close();
        file.writeAll(manifest_json) catch return CacheError.AccessDenied;
    }

    /// Read a cached manifest
    pub fn readManifest(self: *const Self, ref: *const ImageReference) ![]u8 {
        const manifest_path = try self.getManifestPath(ref);
        defer self.allocator.free(manifest_path);

        return std.fs.cwd().readFileAlloc(self.allocator, manifest_path, 10 * 1024 * 1024) catch {
            return CacheError.ManifestNotFound;
        };
    }

    /// Check if an image is cached
    pub fn hasImage(self: *const Self, ref: *const ImageReference) !bool {
        const manifest_path = try self.getManifestPath(ref);
        defer self.allocator.free(manifest_path);

        std.fs.cwd().access(manifest_path, .{}) catch return false;
        return true;
    }

    /// Get container rootfs path
    pub fn getContainerPath(self: *const Self, container_id: []const u8) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/containers/{s}/rootfs",
            .{ self.base_path, container_id },
        );
    }

    /// Extract image layers to create container rootfs
    pub fn prepareContainer(
        self: *const Self,
        container_id: []const u8,
        layer_digests: []const []const u8,
    ) ![]const u8 {
        const rootfs_path = try self.getContainerPath(container_id);
        errdefer self.allocator.free(rootfs_path);

        // Create container directory
        std.fs.cwd().makePath(rootfs_path) catch {};

        // Extract each layer in order
        for (layer_digests) |digest| {
            const layer_path = try self.getBlobPath(digest);
            defer self.allocator.free(layer_path);

            _ = layer.extractLayer(
                self.allocator,
                layer_path,
                rootfs_path,
                null,
            ) catch |err| {
                std.debug.print("Warning: Layer extraction issue: {}\n", .{err});
                continue;
            };
        }

        return rootfs_path;
    }

    /// Remove a container's rootfs
    pub fn removeContainer(self: *const Self, container_id: []const u8) !void {
        const container_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/containers/{s}",
            .{ self.base_path, container_id },
        );
        defer self.allocator.free(container_path);

        std.fs.cwd().deleteTree(container_path) catch {};
    }

    /// Remove an image by reference string (e.g., "postgres:16-alpine")
    pub fn removeImage(self: *const Self, image_ref: []const u8) !void {
        const ref = reference.parse(image_ref) catch return error.ImageNotFound;

        // Build manifest path
        var repo_encoded: [512]u8 = undefined;
        var repo_len: usize = 0;
        for (ref.repository) |c| {
            repo_encoded[repo_len] = if (c == '/') '_' else c;
            repo_len += 1;
            if (repo_len >= repo_encoded.len) break;
        }

        const manifest_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/images/manifests/{s}/{s}/{s}.json",
            .{ self.base_path, ref.registry, repo_encoded[0..repo_len], ref.tag },
        );
        defer self.allocator.free(manifest_path);

        // Delete manifest file
        std.fs.cwd().deleteFile(manifest_path) catch {};
    }

    /// Remove all images (for prune)
    pub fn removeAllImages(self: *const Self) !u64 {
        var removed: u64 = 0;

        const manifests_path = try std.fmt.allocPrint(self.allocator, "{s}/images/manifests", .{self.base_path});
        defer self.allocator.free(manifests_path);

        // Delete entire manifests directory and recreate structure
        std.fs.cwd().deleteTree(manifests_path) catch {};
        std.fs.cwd().makePath(manifests_path) catch {};

        // Count and delete blobs
        const blobs_path = try std.fmt.allocPrint(self.allocator, "{s}/images/blobs/sha256", .{self.base_path});
        defer self.allocator.free(blobs_path);

        var blobs_dir = std.fs.cwd().openDir(blobs_path, .{ .iterate = true }) catch return removed;
        defer blobs_dir.close();

        var blob_iter = blobs_dir.iterate();
        while (try blob_iter.next()) |entry| {
            if (entry.kind == .file) {
                blobs_dir.deleteFile(entry.name) catch continue;
                removed += 1;
            }
        }

        return removed;
    }

    /// Remove all containers (for prune)
    pub fn removeAllContainers(self: *const Self) !u64 {
        var removed: u64 = 0;

        const containers_path = try std.fmt.allocPrint(self.allocator, "{s}/containers", .{self.base_path});
        defer self.allocator.free(containers_path);

        var containers_dir = std.fs.cwd().openDir(containers_path, .{ .iterate = true }) catch return removed;
        defer containers_dir.close();

        var iter = containers_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                const container_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ containers_path, entry.name });
                defer self.allocator.free(container_path);
                std.fs.cwd().deleteTree(container_path) catch continue;
                removed += 1;
            }
        }

        return removed;
    }

    /// List all cached images
    pub fn listImages(self: *const Self, allocator: std.mem.Allocator) ![]CachedImageInfo {
        var images: std.ArrayList(CachedImageInfo) = .empty;
        errdefer {
            for (images.items) |*img| {
                img.deinit(allocator);
            }
            images.deinit(allocator);
        }

        const manifests_path = try std.fmt.allocPrint(allocator, "{s}/images/manifests", .{self.base_path});
        defer allocator.free(manifests_path);

        var manifests_dir = std.fs.cwd().openDir(manifests_path, .{ .iterate = true }) catch return images.toOwnedSlice(allocator);
        defer manifests_dir.close();

        // Iterate registries
        var reg_iter = manifests_dir.iterate();
        while (try reg_iter.next()) |registry_entry| {
            if (registry_entry.kind != .directory) continue;

            const reg_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ manifests_path, registry_entry.name });
            defer allocator.free(reg_path);

            var reg_dir = std.fs.cwd().openDir(reg_path, .{ .iterate = true }) catch continue;
            defer reg_dir.close();

            // Iterate repositories
            var repo_iter = reg_dir.iterate();
            while (try repo_iter.next()) |repo_entry| {
                if (repo_entry.kind != .directory) continue;

                const repo_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ reg_path, repo_entry.name });
                defer allocator.free(repo_path);

                var repo_dir = std.fs.cwd().openDir(repo_path, .{ .iterate = true }) catch continue;
                defer repo_dir.close();

                // Iterate tags
                var tag_iter = repo_dir.iterate();
                while (try tag_iter.next()) |tag_entry| {
                    if (tag_entry.kind != .file) continue;
                    if (!std.mem.endsWith(u8, tag_entry.name, ".json")) continue;

                    // Get tag name (remove .json)
                    const tag_name = tag_entry.name[0 .. tag_entry.name.len - 5];

                    // Convert repo name back (replace _ with /)
                    var repo_name: [512]u8 = undefined;
                    var repo_len: usize = 0;
                    for (repo_entry.name) |c| {
                        repo_name[repo_len] = if (c == '_') '/' else c;
                        repo_len += 1;
                        if (repo_len >= repo_name.len) break;
                    }

                    // Create owned strings for the image info
                    const info = CachedImageInfo{
                        .registry = try allocator.dupe(u8, registry_entry.name),
                        .repository = try allocator.dupe(u8, repo_name[0..repo_len]),
                        .tag = try allocator.dupe(u8, tag_name),
                    };
                    try images.append(allocator, info);
                }
            }
        }

        return images.toOwnedSlice(allocator);
    }

    /// Get cache statistics
    pub fn getStats(self: *const Self) !CacheStats {
        var stats = CacheStats{
            .total_blobs = 0,
            .total_manifests = 0,
            .total_size = 0,
        };

        // Count blobs
        const blobs_path = try std.fmt.allocPrint(self.allocator, "{s}/images/blobs/sha256", .{self.base_path});
        defer self.allocator.free(blobs_path);

        var blobs_dir = std.fs.cwd().openDir(blobs_path, .{ .iterate = true }) catch return stats;
        defer blobs_dir.close();

        var blob_iter = blobs_dir.iterate();
        while (try blob_iter.next()) |entry| {
            if (entry.kind == .file) {
                stats.total_blobs += 1;
                const stat = blobs_dir.statFile(entry.name) catch continue;
                stats.total_size += stat.size;
            }
        }

        return stats;
    }
};

pub const CacheStats = struct {
    total_blobs: u64,
    total_manifests: u64,
    total_size: u64,
};

/// Generate a unique container ID
pub fn generateContainerId() [12]u8 {
    var id: [12]u8 = undefined;
    const timestamp = @as(u64, @intCast(std.time.timestamp()));

    // Simple ID generation based on timestamp
    const hex_chars = "0123456789abcdef";
    var n = timestamp;
    for (&id) |*c| {
        c.* = hex_chars[n % 16];
        n = n / 16 +% @as(u64, @intCast(c.*));
    }

    return id;
}

// =============================================================================
// Tests
// =============================================================================

test "generateContainerId produces valid hex" {
    const id = generateContainerId();
    for (id) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}
