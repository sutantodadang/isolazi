//! Windows container run implementation.
//!
//! Runs containers on Windows using WSL2 as the backend.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");
const runmod = @import("../run.zig");

// Windows module - conditionally compiled
const windows = if (builtin.os.tag == .windows) isolazi.windows else struct {
    pub fn isWslAvailable(_: std.mem.Allocator) bool {
        return false;
    }
    pub fn windowsToWslPath(_: std.mem.Allocator, path: []const u8) ![]const u8 {
        return path;
    }
};

/// Run container on Windows using WSL2 backend
pub fn runContainer(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Parse run options
    const opts = runmod.parseRunOptions(allocator, args) catch {
        try stderr.writeAll("Error: Failed to parse run options\n");
        try stderr.flush();
        return 1;
    };
    defer opts.deinit(allocator);

    // Check if we have an image argument
    if (opts.image_name.len == 0) {
        runmod.printUsage(stderr);
        return 1;
    }

    const image_name = opts.image_name;

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    // Parse the image reference
    const ref = isolazi.image.reference.parse(image_name) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{image_name});
        try stderr.flush();
        return 1;
    };

    // Check if image is cached, pull if not (like Docker)
    const has_image = cache.hasImage(&ref) catch false;
    if (!has_image) {
        try stdout.print("Unable to find image '{s}' locally\n", .{image_name});
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

        _ = isolazi.image.pullImage(allocator, image_name, &cache, &progress_cb, &download_progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("Downloaded newer image for {s}\n", .{image_name});
        try stdout.flush();
    }

    // Check if WSL is available
    if (!windows.isWslAvailable(allocator)) {
        try stderr.writeAll("Error: WSL2 is required to run containers on Windows.\n");
        try stderr.writeAll("\nTo install WSL2:\n");
        try stderr.writeAll("  1. Open PowerShell as Administrator\n");
        try stderr.writeAll("  2. Run: wsl --install\n");
        try stderr.writeAll("  3. Restart your computer\n");
        try stderr.flush();
        return 1;
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

    // Create log files in the container directory (parent of rootfs)
    const container_dir = std.fs.path.dirname(rootfs_path) orelse rootfs_path;
    const stdout_log_path = try std.fmt.allocPrint(allocator, "{s}/stdout.log", .{container_dir});
    defer allocator.free(stdout_log_path);
    const stderr_log_path = try std.fmt.allocPrint(allocator, "{s}/stderr.log", .{container_dir});
    defer allocator.free(stderr_log_path);

    // Create empty log files
    {
        const stdout_file = std.fs.cwd().createFile(stdout_log_path, .{}) catch |err| {
            try stderr.print("Warning: Failed to create stdout.log: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        stdout_file.close();

        const stderr_file = std.fs.cwd().createFile(stderr_log_path, .{}) catch |err| {
            try stderr.print("Warning: Failed to create stderr.log: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        stderr_file.close();
    }

    // Convert log paths to WSL paths
    const wsl_stdout_log = windows.windowsToWslPath(allocator, stdout_log_path) catch |err| {
        try stderr.print("Error: Failed to convert stdout log path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_stdout_log);

    const wsl_stderr_log = windows.windowsToWslPath(allocator, stderr_log_path) catch |err| {
        try stderr.print("Error: Failed to convert stderr log path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_stderr_log);

    // Convert Windows path to WSL path
    const wsl_rootfs = windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
        try stderr.print("Error: Failed to convert path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_rootfs);

    // Get command to run (default: /bin/sh)
    var cmd_args: std.ArrayList([]const u8) = .empty;
    defer cmd_args.deinit(allocator);

    if (opts.command_args.len > 0) {
        // User specified command
        for (opts.command_args) |arg| {
            try cmd_args.append(allocator, arg);
        }
    } else {
        // Check if this is a postgres image - auto-run entrypoint
        if (std.mem.indexOf(u8, image_name, "postgres") != null) {
            try cmd_args.append(allocator, "docker-entrypoint.sh");
            try cmd_args.append(allocator, "postgres");
        } else if (std.mem.indexOf(u8, image_name, "rabbitmq") != null) {
            try cmd_args.append(allocator, "docker-entrypoint.sh");
            try cmd_args.append(allocator, "rabbitmq-server");
        } else {
            // Default command
            try cmd_args.append(allocator, "/bin/sh");
        }
    }

    // Build the command to run in WSL
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");

    // For detach mode, wrap everything in nohup/setsid
    if (opts.detach_mode) {
        try wsl_cmd.append(allocator, "setsid");
    }

    // Always use shell script approach for proper setup
    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");

    // Add user namespace for rootless containers
    if (opts.rootless) {
        try wsl_cmd.append(allocator, "--user");
        try wsl_cmd.append(allocator, "--map-root-user");
    }

    try wsl_cmd.append(allocator, "sh");
    try wsl_cmd.append(allocator, "-c");

    var script_buf: std.ArrayList(u8) = .empty;
    defer script_buf.deinit(allocator);

    // Track allocated paths for cleanup
    var allocated_paths: [64][]const u8 = undefined;
    var alloc_count: usize = 0;
    defer {
        for (allocated_paths[0..alloc_count]) |p| {
            allocator.free(p);
        }
    }

    // Mount proc inside the rootfs
    try script_buf.appendSlice(allocator, "mount -t proc proc ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/proc && ");

    // Create /dev/fd symlink for bash process substitution
    try script_buf.appendSlice(allocator, "ln -sf /proc/self/fd ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/fd 2>/dev/null; ");

    // Ensure /dev exists inside the rootfs and bind common device nodes
    try script_buf.appendSlice(allocator, "mkdir -p ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev && ");
    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/null && mount --bind /dev/null ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/null 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/tty && mount --bind /dev/tty ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/tty 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/random && mount --bind /dev/random ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/random 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/urandom && mount --bind /dev/urandom ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/urandom 2>/dev/null; ");

    // For postgres images, set up required directories on tmpfs
    const is_postgres = std.mem.indexOf(u8, image_name, "postgres") != null;
    if (is_postgres) {
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && chown 70:70 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && chmod 775 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && ");

        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && chown 70:70 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && ");
    }

    // For rabbitmq images, set up required directories on tmpfs
    const is_rabbitmq = std.mem.indexOf(u8, image_name, "rabbitmq") != null;
    if (is_rabbitmq) {
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/rabbitmq && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/rabbitmq && chown 999:999 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/rabbitmq && chmod 700 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/rabbitmq && ");

        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/log/rabbitmq && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/log/rabbitmq && chown 999:999 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/log/rabbitmq && chmod 755 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/log/rabbitmq && ");
    }

    // Mount each volume
    for (opts.volumes) |vol| {
        const wsl_host = windows.windowsToWslPath(allocator, vol.host_path) catch vol.host_path;
        if (wsl_host.ptr != vol.host_path.ptr and alloc_count < allocated_paths.len) {
            allocated_paths[alloc_count] = wsl_host;
            alloc_count += 1;
        }
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_host);
        try script_buf.appendSlice(allocator, " && ");
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, vol.container_path);
        try script_buf.appendSlice(allocator, " && mount --bind ");
        if (vol.read_only) {
            try script_buf.appendSlice(allocator, "-o ro ");
        }
        try script_buf.appendSlice(allocator, wsl_host);
        try script_buf.append(allocator, ' ');
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, vol.container_path);
        try script_buf.appendSlice(allocator, " && ");
    }

    // Set up port forwarding using iptables in WSL2
    for (opts.ports) |port| {
        const proto_str = if (port.protocol == .udp) "udp" else "tcp";
        var host_port_buf: [8]u8 = undefined;
        const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
        var cont_port_buf: [8]u8 = undefined;
        const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";

        try script_buf.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ");
        try script_buf.appendSlice(allocator, proto_str);
        try script_buf.appendSlice(allocator, " --dport ");
        try script_buf.appendSlice(allocator, host_port_str);
        try script_buf.appendSlice(allocator, " -j REDIRECT --to-port ");
        try script_buf.appendSlice(allocator, cont_port_str);
        try script_buf.appendSlice(allocator, " 2>/dev/null; ");

        try script_buf.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ");
        try script_buf.appendSlice(allocator, proto_str);
        try script_buf.appendSlice(allocator, " --dport ");
        try script_buf.appendSlice(allocator, host_port_str);
        try script_buf.appendSlice(allocator, " -j REDIRECT --to-port ");
        try script_buf.appendSlice(allocator, cont_port_str);
        try script_buf.appendSlice(allocator, " 2>/dev/null; ");
    }

    // Add chroot command with env vars
    try script_buf.appendSlice(allocator, "chroot ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, " /usr/bin/env -i ");

    // Set minimal required environment
    try script_buf.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin ");
    try script_buf.appendSlice(allocator, "HOME=/root ");
    try script_buf.appendSlice(allocator, "TERM=xterm ");
    try script_buf.appendSlice(allocator, "LANG=C.UTF-8 ");
    try script_buf.appendSlice(allocator, "ISOLAZI_ID=");
    try script_buf.appendSlice(allocator, container_id[0..]);
    try script_buf.appendSlice(allocator, " ");

    // For postgres, auto-set PGDATA if not provided
    var has_pgdata = false;
    for (opts.env_vars) |env| {
        if (std.mem.eql(u8, env.key, "PGDATA")) {
            has_pgdata = true;
            break;
        }
    }
    if (is_postgres and !has_pgdata) {
        for (opts.volumes) |vol| {
            if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                try script_buf.appendSlice(allocator, "PGDATA=");
                if (std.mem.endsWith(u8, vol.container_path, "/data")) {
                    try script_buf.appendSlice(allocator, vol.container_path);
                } else {
                    try script_buf.appendSlice(allocator, vol.container_path);
                    try script_buf.appendSlice(allocator, "/data");
                }
                try script_buf.append(allocator, ' ');
                has_pgdata = true;
                break;
            }
        }
        if (!has_pgdata) {
            try script_buf.appendSlice(allocator, "PGDATA=/var/lib/postgresql/data ");
        }
    }

    // Export environment variables
    for (opts.env_vars) |env| {
        try script_buf.appendSlice(allocator, env.key);
        try script_buf.appendSlice(allocator, "=");
        try script_buf.appendSlice(allocator, env.value);
        try script_buf.append(allocator, ' ');
    }

    // Run the command with log capture
    if (opts.detach_mode) {
        for (cmd_args.items) |arg| {
            try runmod.quoteArg(&script_buf, allocator, arg);
        }
    } else {
        for (cmd_args.items) |arg| {
            try runmod.quoteArg(&script_buf, allocator, arg);
        }
        try script_buf.appendSlice(allocator, "2>&1 | tee ");
        try script_buf.appendSlice(allocator, wsl_stdout_log);
    }

    // For detach mode, add redirections at the end
    if (opts.detach_mode) {
        try script_buf.appendSlice(allocator, " >> ");
        try script_buf.appendSlice(allocator, wsl_stdout_log);
        try script_buf.appendSlice(allocator, " 2>> ");
        try script_buf.appendSlice(allocator, wsl_stderr_log);
    }

    try wsl_cmd.append(allocator, script_buf.items);

    if (opts.detach_mode) {
        try stdout.print("{s}\n", .{container_id});
        for (opts.ports) |port| {
            if (port.host_port == port.container_port) {
                try stdout.print("Port {d} published\n", .{port.host_port});
            } else {
                try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
            }
        }
        try stdout.flush();
    } else {
        try stdout.print("Starting container...\n", .{});
        for (opts.ports) |port| {
            if (port.host_port == port.container_port) {
                try stdout.print("Port {d} published\n", .{port.host_port});
            } else {
                try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
            }
        }
        try stdout.flush();
    }

    // Register container with ContainerManager
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    // Build command string for state
    var cmd_str_buf: [512]u8 = undefined;
    var cmd_str_len: usize = 0;
    for (cmd_args.items, 0..) |arg, i| {
        if (i > 0) {
            cmd_str_buf[cmd_str_len] = ' ';
            cmd_str_len += 1;
        }
        const copy_len = @min(arg.len, cmd_str_buf.len - cmd_str_len);
        @memcpy(cmd_str_buf[cmd_str_len..][0..copy_len], arg[0..copy_len]);
        cmd_str_len += copy_len;
    }

    _ = manager.createContainerWithId(&container_id, image_name, cmd_str_buf[0..cmd_str_len], null, .no, &[_]isolazi.container.state.PortMapping{}, &[_]isolazi.container.state.VolumeMount{}, &[_]isolazi.container.state.EnvVar{}) catch |err| {
        try stderr.print("Warning: Failed to register container: {}\n", .{err});
    };

    // Execute in WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (opts.detach_mode) {
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
    } else {
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
    }

    try child.spawn();

    if (opts.detach_mode) {
        manager.updateState(&container_id, .running, null, null) catch {};
        return 0;
    }

    manager.updateState(&container_id, .running, null, null) catch {};

    const term = try child.wait();

    const exit_code: u8 = switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
    manager.updateState(&container_id, .stopped, null, exit_code) catch {};

    return exit_code;
}
