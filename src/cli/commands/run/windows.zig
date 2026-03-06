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

    // Get command to run - read from OCI image config if not specified
    var cmd_args: std.ArrayList([]const u8) = .empty;
    defer cmd_args.deinit(allocator);
    // Storage for image config data (kept alive so cmd_args can reference strings from it)
    var img_config_data: ?[]u8 = null;
    defer if (img_config_data) |d| allocator.free(d);
    var img_config_parsed: ?std.json.Parsed(std.json.Value) = null;
    defer if (img_config_parsed) |*p| p.deinit();
    var workdir: []const u8 = "/"; // Default working directory (overridden by OCI WorkingDir)
    if (opts.command_args.len > 0) {
        // User specified command
        for (opts.command_args) |arg| {
            try cmd_args.append(allocator, arg);
        }
    } else {
        // Read Entrypoint/Cmd from OCI image config
        var got_cmd = false;
        read_config: {
            const config_ref = root.object.get("config") orelse break :read_config;
            const config_digest = (config_ref.object.get("digest") orelse break :read_config).string;
            const config_data = cache.readBlob(config_digest) catch break :read_config;
            img_config_data = config_data;
            const config_json = std.json.parseFromSlice(std.json.Value, allocator, config_data, .{}) catch break :read_config;
            img_config_parsed = config_json;

            const cfg = config_json.value.object.get("config") orelse break :read_config;

            // Extract WorkingDir from OCI config
            if (cfg.object.get("WorkingDir")) |wd| {
                if (wd == .string and wd.string.len > 0) {
                    workdir = wd.string;
                }
            }

            // Docker behavior: Entrypoint + Cmd combined
            if (cfg.object.get("Entrypoint")) |ep| {
                if (ep == .array) {
                    for (ep.array.items) |item| {
                        if (item == .string) {
                            try cmd_args.append(allocator, item.string);
                            got_cmd = true;
                        }
                    }
                }
            }
            if (cfg.object.get("Cmd")) |cmd| {
                if (cmd == .array) {
                    for (cmd.array.items) |item| {
                        if (item == .string) {
                            try cmd_args.append(allocator, item.string);
                            got_cmd = true;
                        }
                    }
                }
            }
        }
        if (!got_cmd) {
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
    try wsl_cmd.append(allocator, "sh");
    try wsl_cmd.append(allocator, "-c");

    // Overlay paths for this container
    const overlay_dir = try std.fmt.allocPrint(allocator, "/tmp/isolazi/{s}", .{container_id});
    defer allocator.free(overlay_dir);
    const overlay_upper = try std.fmt.allocPrint(allocator, "{s}/upper", .{overlay_dir});
    defer allocator.free(overlay_upper);
    const overlay_work = try std.fmt.allocPrint(allocator, "{s}/work", .{overlay_dir});
    defer allocator.free(overlay_work);
    const overlay_merged = try std.fmt.allocPrint(allocator, "{s}/merged", .{overlay_dir});
    defer allocator.free(overlay_merged);

    // Build outer wrapper script that writes pidfile BEFORE entering unshare PID namespace.
    // We use sh -c 'OUTER' 'INNER' pattern: the outer script references $0 which expands to
    // the INNER script argument, avoiding single-quote escaping issues.
    var outer_buf: std.ArrayList(u8) = .empty;
    defer outer_buf.deinit(allocator);

    // Outer script: create overlay dir, write host-visible PID, then run unshare.
    // For restart policies (always/on-failure), wrap in a loop instead of exec.
    try outer_buf.appendSlice(allocator, "mkdir -p ");
    try outer_buf.appendSlice(allocator, overlay_upper);
    try outer_buf.appendSlice(allocator, " ");
    try outer_buf.appendSlice(allocator, overlay_work);
    try outer_buf.appendSlice(allocator, " ");
    try outer_buf.appendSlice(allocator, overlay_merged);
    try outer_buf.appendSlice(allocator, " && echo $$ > ");
    try outer_buf.appendSlice(allocator, overlay_dir);
    try outer_buf.appendSlice(allocator, "/pid");

    const needs_restart_loop = opts.restart_policy == .always or opts.restart_policy == .on_failure;
    if (needs_restart_loop) {
        // Restart loop: re-run unshare on exit, with 1s delay to avoid tight loops
        try outer_buf.appendSlice(allocator, " && while true; do unshare --mount --uts --ipc --pid --fork ");
        if (opts.rootless) {
            try outer_buf.appendSlice(allocator, "--user --map-root-user ");
        }
        try outer_buf.appendSlice(allocator, "sh ");
        try outer_buf.appendSlice(allocator, overlay_dir);
        try outer_buf.appendSlice(allocator, "/run.sh; EXIT_CODE=$?; ");
        if (opts.restart_policy == .on_failure) {
            // on-failure: only restart if exit code != 0
            try outer_buf.appendSlice(allocator, "[ $EXIT_CODE -eq 0 ] && break; ");
        }
        try outer_buf.appendSlice(allocator, "sleep 1; done");
    } else {
        // No restart: exec directly into unshare
        try outer_buf.appendSlice(allocator, " && exec unshare --mount --uts --ipc --pid --fork ");
        if (opts.rootless) {
            try outer_buf.appendSlice(allocator, "--user --map-root-user ");
        }
        try outer_buf.appendSlice(allocator, "sh ");
        try outer_buf.appendSlice(allocator, overlay_dir);
        try outer_buf.appendSlice(allocator, "/run.sh");
    }

    // Inner script: overlay setup, mounts, chroot (runs INSIDE unshare namespace)
    var script_buf: std.ArrayList(u8) = .empty;
    defer script_buf.deinit(allocator);

    // Mount overlay: NTFS rootfs (lower/read-only) + tmpfs upper (writable) = merged
    try script_buf.appendSlice(allocator, "mount -t overlay overlay -o lowerdir=");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, ",upperdir=");
    try script_buf.appendSlice(allocator, overlay_upper);
    try script_buf.appendSlice(allocator, ",workdir=");
    try script_buf.appendSlice(allocator, overlay_work);
    try script_buf.appendSlice(allocator, " ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, " && ");

    // Mount proc inside the overlay merged rootfs
    try script_buf.appendSlice(allocator, "mount -t proc proc ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/proc && ");

    // Create /dev/fd symlink for bash process substitution
    try script_buf.appendSlice(allocator, "ln -sf /proc/self/fd ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/fd 2>/dev/null; ");

    // Ensure /dev exists inside the rootfs and bind common device nodes
    try script_buf.appendSlice(allocator, "mkdir -p ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev && ");
    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/null && mount --bind /dev/null ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/null 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/tty && mount --bind /dev/tty ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/tty 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/random && mount --bind /dev/random ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/random 2>/dev/null; ");

    try script_buf.appendSlice(allocator, "touch ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/urandom && mount --bind /dev/urandom ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/urandom 2>/dev/null; ");

    // Mount /dev/shm as tmpfs (needed by postgres and many services)
    try script_buf.appendSlice(allocator, "mkdir -p ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/shm && mount -t tmpfs tmpfs ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/dev/shm 2>/dev/null; ");

    // Mount /tmp as tmpfs for all containers
    try script_buf.appendSlice(allocator, "mount -t tmpfs tmpfs ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/tmp 2>/dev/null; ");

    // Mount /run as tmpfs (needed by many init scripts and services)
    try script_buf.appendSlice(allocator, "mkdir -p ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/run && mount -t tmpfs tmpfs ");
    try script_buf.appendSlice(allocator, overlay_merged);
    try script_buf.appendSlice(allocator, "/run 2>/dev/null; ");

    // Track allocated paths for cleanup
    var allocated_paths: [32][]const u8 = undefined;
    var alloc_count: usize = 0;
    defer for (allocated_paths[0..alloc_count]) |p| allocator.free(p);

    // Mount each volume (named volumes use WSL-native paths for proper permission support)
    const is_postgres = std.mem.indexOf(u8, image_name, "postgres") != null;
    for (opts.volumes) |vol| {
        // Detect named volumes (not absolute paths) and resolve to WSL-native path
        const is_named_volume = vol.host_path.len > 0 and vol.host_path[0] != '/' and
            !(vol.host_path.len >= 2 and vol.host_path[1] == ':');

        var wsl_host: []const u8 = undefined;
        if (is_named_volume) {
            // Named volumes → WSL-native path for full Linux fs permissions (chmod/chown)
            wsl_host = try std.fmt.allocPrint(allocator, "/tmp/isolazi/volumes/{s}", .{vol.host_path});
            if (alloc_count < allocated_paths.len) {
                allocated_paths[alloc_count] = wsl_host;
                alloc_count += 1;
            }
        } else {
            wsl_host = windows.windowsToWslPath(allocator, vol.host_path) catch vol.host_path;
            if (wsl_host.ptr != vol.host_path.ptr and alloc_count < allocated_paths.len) {
                allocated_paths[alloc_count] = wsl_host;
                alloc_count += 1;
            }
        }
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_host);
        try script_buf.appendSlice(allocator, " && ");
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, overlay_merged);
        try script_buf.appendSlice(allocator, vol.container_path);
        try script_buf.appendSlice(allocator, " && mount --bind ");
        if (vol.read_only) {
            try script_buf.appendSlice(allocator, "-o ro ");
        }
        try script_buf.appendSlice(allocator, wsl_host);
        try script_buf.append(allocator, ' ');
        try script_buf.appendSlice(allocator, overlay_merged);
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

    // Add chroot command with env vars (chroot into overlay merged)
    try script_buf.appendSlice(allocator, "chroot ");
    try script_buf.appendSlice(allocator, overlay_merged);
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

    // Set working directory from OCI config (e.g., /data for redis, /var/lib/postgresql for postgres)
    if (!std.mem.eql(u8, workdir, "/")) {
        try script_buf.appendSlice(allocator, "sh -c 'cd ");
        try script_buf.appendSlice(allocator, workdir);
        try script_buf.appendSlice(allocator, " && exec ");
        for (cmd_args.items) |arg| {
            try runmod.quoteArg(&script_buf, allocator, arg);
        }
        // Close the sh -c quoted command
        try script_buf.appendSlice(allocator, "'");
    } else {
        for (cmd_args.items) |arg| {
            try runmod.quoteArg(&script_buf, allocator, arg);
        }
    }

    // Run the command with log capture
    if (opts.detach_mode) {
        try script_buf.appendSlice(allocator, " >> ");
        try script_buf.appendSlice(allocator, wsl_stdout_log);
        try script_buf.appendSlice(allocator, " 2>> ");
        try script_buf.appendSlice(allocator, wsl_stderr_log);
    } else {
        try script_buf.appendSlice(allocator, " 2>&1 | tee ");
        try script_buf.appendSlice(allocator, wsl_stdout_log);
    }

    // Append outer wrapper script only (inner script written to file separately)
    try wsl_cmd.append(allocator, outer_buf.items);

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

    // Convert ports to state format for persistence
    var state_ports_buf: [32]isolazi.container.state.PortMapping = undefined;
    for (opts.ports, 0..) |p, i| {
        state_ports_buf[i] = .{
            .host_port = p.host_port,
            .container_port = p.container_port,
            .protocol = if (p.protocol == .udp) .udp else .tcp,
        };
    }
    const state_ports = state_ports_buf[0..opts.ports.len];

    // Convert volumes to state format for persistence
    var state_vols_buf: [32]isolazi.container.state.VolumeMount = undefined;
    for (opts.volumes, 0..) |v, i| {
        state_vols_buf[i] = .{
            .host_path = v.host_path,
            .container_path = v.container_path,
        };
    }
    const state_vols = state_vols_buf[0..opts.volumes.len];

    // Convert env vars to state format for persistence
    var state_envs_buf: [64]isolazi.container.state.EnvVar = undefined;
    for (opts.env_vars, 0..) |e, i| {
        state_envs_buf[i] = .{
            .key = e.key,
            .value = e.value,
        };
    }
    const state_envs = state_envs_buf[0..opts.env_vars.len];

    _ = manager.createContainerWithId(&container_id, image_name, cmd_str_buf[0..cmd_str_len], opts.name, opts.restart_policy, state_ports, state_vols, state_envs, workdir) catch |err| {
        try stderr.print("Warning: Failed to register container: {}\n", .{err});
    };

    // Write inner script to file in WSL before spawning the container process
    {
        const run_sh_path = try std.fmt.allocPrint(allocator, "{s}/run.sh", .{overlay_dir});
        defer allocator.free(run_sh_path);
        const write_sh_cmd = try std.fmt.allocPrint(allocator, "mkdir -p {s} && cat > {s}", .{ overlay_dir, run_sh_path });
        defer allocator.free(write_sh_cmd);
        var write_cmd = [_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", write_sh_cmd };
        var write_child = std.process.Child.init(&write_cmd, allocator);
        write_child.stdin_behavior = .Pipe;
        write_child.stdout_behavior = .Ignore;
        write_child.stderr_behavior = .Ignore;
        try write_child.spawn();
        if (write_child.stdin) |stdin| {
            stdin.writeAll(script_buf.items) catch {};
            stdin.close();
            write_child.stdin = null;
        }
        _ = write_child.wait() catch {};
    }

    // Execute in WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (opts.detach_mode) {
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        // Detach from parent's console to prevent the WSL process from being
        // killed when the parent process chain exits (e.g., compose up).
        // Without this, WSL processes inherit the console and may receive
        // CTRL_CLOSE_EVENT when a parent in the chain terminates.
        child.create_no_window = true;
    } else {
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
    }

    try child.spawn();

    if (opts.detach_mode) {
        // Wait briefly for the WSL process to start and write its PID to the pidfile
        std.Thread.sleep(200 * std.time.ns_per_ms);

        // Read the PID from the pidfile to enable reliable liveness checks
        var wsl_pid: ?i32 = null;
        {
            const pid_cmd = try std.fmt.allocPrint(allocator, "cat {s}/pid 2>/dev/null", .{overlay_dir});
            defer allocator.free(pid_cmd);
            const pid_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", pid_cmd },
            }) catch null;
            if (pid_result) |res| {
                defer allocator.free(res.stdout);
                defer allocator.free(res.stderr);
                const trimmed = std.mem.trim(u8, res.stdout, &[_]u8{ ' ', '\n', '\r', '\t' });
                wsl_pid = std.fmt.parseInt(i32, trimmed, 10) catch null;
            }
        }

        manager.updateState(&container_id, .running, wsl_pid, null) catch {};
        return 0;
    }

    // Read PID for foreground mode too
    var fg_pid: ?i32 = null;
    {
        std.Thread.sleep(100 * std.time.ns_per_ms);
        const pid_cmd = try std.fmt.allocPrint(allocator, "cat {s}/pid 2>/dev/null", .{overlay_dir});
        defer allocator.free(pid_cmd);
        const pid_result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", pid_cmd },
        }) catch null;
        if (pid_result) |res| {
            defer allocator.free(res.stdout);
            defer allocator.free(res.stderr);
            const trimmed = std.mem.trim(u8, res.stdout, &[_]u8{ ' ', '\n', '\r', '\t' });
            fg_pid = std.fmt.parseInt(i32, trimmed, 10) catch null;
        }
    }

    manager.updateState(&container_id, .running, fg_pid, null) catch {};

    const term = try child.wait();

    const exit_code: u8 = switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
    manager.updateState(&container_id, .stopped, null, exit_code) catch {};

    return exit_code;
}
