//! macOS container run implementation.
//!
//! Runs containers on macOS using Apple Virtualization Framework (via Lima).

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");
const runmod = @import("../run.zig");

// Access macos module (only available on macOS builds)
const macos = if (builtin.os.tag == .macos) isolazi.macos else struct {
    pub const virtualization = struct {
        pub fn isLimaInstalled(_: std.mem.Allocator) bool {
            return false;
        }
        pub const EnvPair = struct { key: []const u8, value: []const u8 };
        pub const VolumePair = struct { host_path: []const u8, container_path: []const u8 };
        pub const PortMapping = struct { host_port: u16, container_port: u16, protocol: enum { tcp, udp } };
        pub const RunResult = struct { exit_code: u8, pid: ?i32 = null };
        pub fn runWithLima(_: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype) !RunResult {
            return RunResult{ .exit_code = 1 };
        }
    };
};

/// Run container on macOS using Apple Virtualization
pub fn runContainer(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Check if Lima is installed
    if (!macos.virtualization.isLimaInstalled(allocator)) {
        try stderr.writeAll("Error: Lima is not installed.\n");
        try stderr.writeAll("\nPlease install Lima to run containers on macOS:\n");
        try stderr.writeAll("  brew install lima\n");
        try stderr.flush();
        return 1;
    }

    // Parse run options (env vars, volumes, etc.)
    const opts = runmod.parseRunOptions(allocator, args) catch |err| {
        try stderr.print("Error: Failed to parse run options: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer opts.deinit(allocator);

    if (opts.image_name.len == 0) {
        runmod.printUsage(stderr);
        return 1;
    }

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    // Parse the image reference
    const ref = isolazi.image.reference.parse(opts.image_name) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{opts.image_name});
        try stderr.flush();
        return 1;
    };

    // Check if image is cached, pull if not
    const has_image = cache.hasImage(&ref) catch false;
    if (!has_image) {
        try stdout.print("Unable to find image '{s}' locally\n", .{opts.image_name});
        try stdout.flush();

        // Pull the image
        const progress_cb = struct {
            fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
                const stage_str = switch (stage) {
                    .cached => "Cached",
                    .authenticating => "Authenticating",
                    .fetching_manifest => "Fetching manifest",
                    .downloading_layer => "Pulling",
                    .downloading_progress => "Progress",
                    .layer_cached => "Layer exists",
                    .extracting => "Extracting",
                    .complete => "Status",
                };
                std.debug.print("{s}: {s}\n", .{ stage_str, detail });
            }
        }.cb;

        const download_progress_cb = struct {
            fn cb(progress: isolazi.image.DownloadProgress) void {
                var size_buf: [32]u8 = undefined;
                var total_buf: [32]u8 = undefined;
                var speed_buf: [32]u8 = undefined;

                const downloaded_str = isolazi.image.DownloadProgress.formatBytes(progress.bytes_downloaded, &size_buf);
                const total_str = if (progress.total_bytes > 0)
                    isolazi.image.DownloadProgress.formatBytes(progress.total_bytes, &total_buf)
                else
                    "???";
                const speed_str = isolazi.image.DownloadProgress.formatBytes(progress.bytes_per_second, &speed_buf);

                const percent = progress.percentComplete();
                const bar_width: usize = 30;
                const filled = (percent * bar_width) / 100;

                var bar: [32]u8 = undefined;
                for (0..bar_width) |i| {
                    bar[i] = if (i < filled) '=' else ' ';
                }

                std.debug.print("\r  Layer {d}/{d}: [{s}] {d}% {s}/{s} @ {s}/s   ", .{
                    progress.layer_index,
                    progress.total_layers,
                    bar[0..bar_width],
                    percent,
                    downloaded_str,
                    total_str,
                    speed_str,
                });

                if (percent == 100) {
                    std.debug.print("\n", .{});
                }
            }
        }.cb;

        _ = isolazi.image.pullImage(allocator, opts.image_name, &cache, &progress_cb, &download_progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("Downloaded newer image for {s}\n", .{opts.image_name});
        try stdout.flush();
    }

    // Read manifest to get layer digests
    const manifest_data = cache.readManifest(&ref) catch |err| {
        try stderr.print("Error: Failed to read manifest: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(manifest_data);

    // Parse manifest for layers
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
        try stderr.writeAll("Error: Invalid manifest format\n");
        try stderr.flush();
        return 1;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const layers_json = root.object.get("layers") orelse {
        try stderr.writeAll("Error: No layers in manifest\n");
        try stderr.flush();
        return 1;
    };

    // Collect layer digests
    var layer_digests: std.ArrayList([]const u8) = .empty;
    defer layer_digests.deinit(allocator);

    for (layers_json.array.items) |layer_obj| {
        const digest = layer_obj.object.get("digest") orelse continue;
        try layer_digests.append(allocator, digest.string);
    }

    // Generate container ID
    var container_id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&container_id_buf);
    var container_id: [32]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (container_id_buf, 0..) |byte, i| {
        container_id[i * 2] = hex_chars[byte >> 4];
        container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    // Prepare container rootfs
    if (!opts.detach_mode) {
        try stdout.print("Preparing container {s}...\n", .{container_id[0..12]});
        try stdout.flush();
    }

    const rootfs_path = cache.prepareContainer(&container_id, layer_digests.items) catch |err| {
        try stderr.print("Error: Failed to prepare container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(rootfs_path);

    // Register container with ContainerManager for state tracking
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    // Build command string for state tracking
    var cmd_display: [256]u8 = undefined;
    var cmd_display_len: usize = 0;

    // Get command to run (default: /bin/sh, or entrypoint for known images)
    var cmd_args: std.ArrayList([]const u8) = .empty;
    defer cmd_args.deinit(allocator);

    const is_postgres = std.mem.indexOf(u8, opts.image_name, "postgres") != null;
    const is_rabbitmq = std.mem.indexOf(u8, opts.image_name, "rabbitmq") != null;

    if (opts.command_args.len > 0) {
        for (opts.command_args) |arg| {
            try cmd_args.append(allocator, arg);
            // Build display string
            if (cmd_display_len > 0 and cmd_display_len < 255) {
                cmd_display[cmd_display_len] = ' ';
                cmd_display_len += 1;
            }
            const copy_len = @min(arg.len, 255 - cmd_display_len);
            @memcpy(cmd_display[cmd_display_len..][0..copy_len], arg[0..copy_len]);
            cmd_display_len += copy_len;
        }
    } else if (is_postgres) {
        try cmd_args.append(allocator, "docker-entrypoint.sh");
        try cmd_args.append(allocator, "postgres");
        const entry = "docker-entrypoint.sh postgres";
        @memcpy(cmd_display[0..entry.len], entry);
        cmd_display_len = entry.len;
    } else if (is_rabbitmq) {
        try cmd_args.append(allocator, "docker-entrypoint.sh");
        try cmd_args.append(allocator, "rabbitmq-server");
        const entry = "docker-entrypoint.sh rabbitmq-server";
        @memcpy(cmd_display[0..entry.len], entry);
        cmd_display_len = entry.len;
    } else {
        try cmd_args.append(allocator, "/bin/sh");
        const sh = "/bin/sh";
        @memcpy(cmd_display[0..sh.len], sh);
        cmd_display_len = sh.len;
    }

    if (opts.detach_mode) {
        try stdout.print("{s}\n", .{container_id});
        try stdout.flush();
    } else {
        try stdout.print("Starting container...\n", .{});
        try stdout.flush();
    }

    // Convert env_vars to virtualization format
    var env_pairs: std.ArrayList(macos.virtualization.EnvPair) = .empty;
    defer env_pairs.deinit(allocator);

    // For postgres, auto-set PGDATA if not provided
    var has_pgdata = false;
    // Track dynamically allocated env values to free later
    var dynamic_env_values: std.ArrayList([]const u8) = .empty;
    defer {
        for (dynamic_env_values.items) |v| allocator.free(v);
        dynamic_env_values.deinit(allocator);
    }
    for (opts.env_vars) |e| {
        if (std.mem.eql(u8, e.key, "PGDATA")) has_pgdata = true;
        try env_pairs.append(allocator, .{ .key = e.key, .value = e.value });
    }
    // Always add the ISOLAZI_ID tag to environment for detection
    try env_pairs.append(allocator, .{ .key = "ISOLAZI_ID", .value = try allocator.dupe(u8, container_id[0..]) });
    try dynamic_env_values.append(allocator, env_pairs.items[env_pairs.items.len - 1].value);

    if (is_postgres and !has_pgdata) {
        // Find volume mount for /var/lib/postgresql
        for (opts.volumes) |vol| {
            if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                const pgdata = try std.fmt.allocPrint(allocator, "{s}/data", .{vol.container_path});
                try dynamic_env_values.append(allocator, pgdata); // Track for cleanup later
                try env_pairs.append(allocator, .{ .key = "PGDATA", .value = pgdata });
                has_pgdata = true;
                break;
            }
        }
        if (!has_pgdata) {
            try env_pairs.append(allocator, .{ .key = "PGDATA", .value = "/var/lib/postgresql/data" });
        }
    }

    // Convert volumes to virtualization format, expanding ~ to $HOME
    var vol_pairs: std.ArrayList(macos.virtualization.VolumePair) = .empty;
    defer vol_pairs.deinit(allocator);
    // Track allocations for expanded paths
    var expanded_paths: std.ArrayList([]const u8) = .empty;
    defer {
        for (expanded_paths.items) |p| allocator.free(p);
        expanded_paths.deinit(allocator);
    }
    for (opts.volumes) |v| {
        const host_path = blk: {
            if (std.mem.startsWith(u8, v.host_path, "~/")) {
                const home = std.posix.getenv("HOME") orelse "/tmp";
                const expanded = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ home, v.host_path[2..] });
                try expanded_paths.append(allocator, expanded);
                break :blk expanded;
            } else if (std.mem.eql(u8, v.host_path, "~")) {
                const home = std.posix.getenv("HOME") orelse "/tmp";
                const expanded = try allocator.dupe(u8, home);
                try expanded_paths.append(allocator, expanded);
                break :blk expanded;
            } else {
                break :blk v.host_path;
            }
        };

        // Ensure host path exists (create directory if missing)
        if (std.fs.cwd().access(host_path, .{})) |_| {} else |err| switch (err) {
            error.FileNotFound => {
                std.fs.cwd().makePath(host_path) catch |mk_err| {
                    try stderr.print("Error: Failed to create host volume path '{s}': {}\n", .{ host_path, mk_err });
                    try stderr.flush();
                    return 1;
                };
            },
            else => {
                try stderr.print("Error: Host volume path '{s}' is not accessible: {}\n", .{ host_path, err });
                try stderr.flush();
                return 1;
            },
        }

        try vol_pairs.append(allocator, .{ .host_path = host_path, .container_path = v.container_path });
    }

    // Convert port mappings to virtualization format
    var port_pairs: std.ArrayList(macos.virtualization.PortMapping) = .empty;
    defer port_pairs.deinit(allocator);
    for (opts.ports) |p| {
        try port_pairs.append(allocator, .{
            .host_port = p.host_port,
            .container_port = p.container_port,
            .protocol = if (p.protocol == .udp) .udp else .tcp,
        });
    }

    // Print port mappings
    for (opts.ports) |port| {
        if (port.host_port == port.container_port) {
            try stdout.print("Port {d} published\n", .{port.host_port});
        } else {
            try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
        }
    }
    if (opts.ports.len > 0) {
        try stdout.flush();
    }

    // Register container state with persisted ports/volumes/env for restart support
    {
        // Convert to state.zig format for persistence
        var persist_ports: std.ArrayList(isolazi.container.state.PortMapping) = .empty;
        defer persist_ports.deinit(allocator);
        for (opts.ports) |p| {
            try persist_ports.append(allocator, .{
                .host_port = p.host_port,
                .container_port = p.container_port,
                .protocol = if (p.protocol == .udp) .udp else .tcp,
            });
        }

        var persist_vols: std.ArrayList(isolazi.container.state.VolumeMount) = .empty;
        defer persist_vols.deinit(allocator);
        for (vol_pairs.items) |v| {
            try persist_vols.append(allocator, .{
                .host_path = v.host_path,
                .container_path = v.container_path,
            });
        }

        var persist_envs: std.ArrayList(isolazi.container.state.EnvVar) = .empty;
        defer persist_envs.deinit(allocator);
        for (env_pairs.items) |e| {
            try persist_envs.append(allocator, .{
                .key = e.key,
                .value = e.value,
            });
        }

        _ = manager.createContainerWithId(
            &container_id,
            opts.image_name,
            cmd_display[0..cmd_display_len],
            null,
            opts.restart_policy,
            persist_ports.items,
            persist_vols.items,
            persist_envs.items,
        ) catch {};
    }

    // Run in VM using appropriate hypervisor
    var exit_code: u8 = 0;
    try stdout.print("Running in Lima VM...\n", .{});
    try stdout.flush();

    // Setup logging for detach mode
    var stdout_path: ?[]const u8 = null;
    var stderr_path: ?[]const u8 = null;
    if (opts.detach_mode) {
        const logs = try isolazi.container.logs.createLogFiles(allocator, &container_id);
        stdout_path = logs.stdout_path;
        stderr_path = logs.stderr_path;
    }
    defer {
        if (stdout_path) |p| allocator.free(p);
        if (stderr_path) |p| allocator.free(p);
    }

    // Use Lima
    const run_res = macos.virtualization.runWithLima(
        allocator,
        "", // Lima manages its own kernel
        rootfs_path,
        cmd_args.items,
        env_pairs.items,
        vol_pairs.items,
        port_pairs.items,
        opts.rootless,
        opts.detach_mode,
        opts.restart_policy,
        stdout_path,
        stderr_path,
    ) catch |err| {
        try stderr.print("Error: Failed to run container in VM: {}\n", .{err});
        try stderr.flush();
        manager.updateState(&container_id, .stopped, null, 1) catch {};
        return 1;
    };

    if (run_res.exit_code == 0) {
        if (opts.detach_mode) {
            // For detach mode, we consider it "running" if launch started successfully
            manager.updateState(&container_id, .running, null, null) catch {};
            exit_code = 0;
        } else {
            // Interactive mode finished successfully
            exit_code = 0;
            manager.updateState(&container_id, .stopped, null, exit_code) catch {};
        }
    } else {
        exit_code = run_res.exit_code;
        manager.updateState(&container_id, .stopped, null, exit_code) catch {};
    }

    return exit_code;
}
