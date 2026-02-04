//! Linux container run implementation.
//!
//! Runs containers natively on Linux using namespaces and cgroups.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");

/// Run container on Linux
pub fn runContainer(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Parse using main CLI parser to get run options
    const command = isolazi.cli.parse(args) catch |err| {
        try isolazi.cli.printError(stderr, err);
        try stderr.flush();
        return 1;
    };

    switch (command) {
        .run => |run_cmd| return runContainerImpl(allocator, run_cmd, stdout, stderr),
        else => {
            // This happens if the arguments don't parse as a 'run' command
            // (Note: caller should have already filtered for 'run', but parse re-evaluates)
            try stderr.writeAll("Error: Arguments do not match 'run' command syntax\n");
            return 1;
        },
    }
}

fn runContainerImpl(
    allocator: std.mem.Allocator,
    run_cmd: isolazi.cli.RunCommand,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Check if running as root
    const uid = std.os.linux.getuid();
    if (uid != 0) {
        try stderr.writeAll("Error: Isolazi must be run as root.\n");
        try stderr.writeAll("Container namespaces require CAP_SYS_ADMIN privileges.\n");
        try stderr.writeAll("\nHint: Run with 'sudo isolazi run ...'\n");
        try stderr.flush();
        return 1;
    }

    // Determine rootfs path
    var rootfs_path: []const u8 = undefined;
    var container_id: ?[12]u8 = null;
    var cache_opt: ?isolazi.image.ImageCache = null;
    defer {
        if (cache_opt) |*c| {
            // Cleanup container if we created one
            if (container_id) |cid| {
                c.removeContainer(&cid) catch {};
            }
            if (rootfs_path.ptr != run_cmd.rootfs.ptr) {
                allocator.free(rootfs_path);
            }
            c.deinit();
        }
    }

    if (run_cmd.is_image) {
        // It's an OCI image reference - pull and extract
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        cache_opt = cache;

        // Pull image if needed
        const ref = isolazi.image.pullImage(allocator, run_cmd.rootfs, &cache, null, null) catch |err| {
            try stderr.print("Error: Failed to pull image '{s}': {}\n", .{ run_cmd.rootfs, err });
            try stderr.flush();
            return 1;
        };

        // Get manifest and layer digests
        const manifest_data = cache.readManifest(&ref) catch |err| {
            try stderr.print("Error: Failed to read manifest: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(manifest_data);

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
            try stderr.writeAll("Error: Invalid manifest format\n");
            try stderr.flush();
            return 1;
        };
        defer parsed.deinit();

        // Extract layer digests
        const layers = parsed.value.object.get("layers") orelse {
            try stderr.writeAll("Error: No layers in manifest\n");
            try stderr.flush();
            return 1;
        };

        var layer_digests: std.ArrayList([]const u8) = .empty;
        defer layer_digests.deinit(allocator);

        for (layers.array.items) |layer_obj| {
            if (layer_obj.object.get("digest")) |digest| {
                try layer_digests.append(allocator, digest.string);
            }
        }

        // Generate container ID and extract layers
        container_id = isolazi.image.generateContainerId();
        rootfs_path = cache.prepareContainer(&container_id.?, layer_digests.items) catch |err| {
            try stderr.print("Error: Failed to prepare container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
    } else {
        // It's a filesystem path
        rootfs_path = run_cmd.rootfs;

        if (!isolazi.fs.validateRootfs(rootfs_path)) {
            try stderr.print("Error: Invalid rootfs at '{s}'\n", .{rootfs_path});
            try stderr.writeAll("The rootfs must be a directory containing /bin or /usr/bin.\n");
            try stderr.flush();
            return 1;
        }
    }

    // Build configuration with resolved rootfs
    var modified_run_cmd = run_cmd;
    modified_run_cmd.rootfs = rootfs_path;

    // Check if this is a postgres or rabbitmq image - auto-configure
    const is_postgres = std.mem.indexOf(u8, run_cmd.rootfs, "postgres") != null;
    const is_rabbitmq = std.mem.indexOf(u8, run_cmd.rootfs, "rabbitmq") != null;

    // If no command specified, use entrypoint for known images
    const cmd_slice = modified_run_cmd.command orelse "";
    if (cmd_slice.len == 0 or std.mem.eql(u8, cmd_slice, "/bin/sh")) {
        if (is_postgres or is_rabbitmq) {
            modified_run_cmd.command = "docker-entrypoint.sh";
            // Args will be set after buildConfig
        }
    }

    var cfg = isolazi.cli.buildConfig(&modified_run_cmd) catch |err| {
        try stderr.print("Error: Failed to build configuration: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    // For postgres, add default arg "postgres" if entrypoint
    if (is_postgres and std.mem.eql(u8, modified_run_cmd.command orelse "", "docker-entrypoint.sh")) {
        cfg.addArg("postgres") catch {};
    }

    // For rabbitmq, add default arg "rabbitmq-server" if entrypoint
    if (is_rabbitmq and std.mem.eql(u8, modified_run_cmd.command orelse "", "docker-entrypoint.sh")) {
        cfg.addArg("rabbitmq-server") catch {};
    }

    // For postgres, auto-set PGDATA if not provided
    if (is_postgres) {
        var has_pgdata = false;
        for (run_cmd.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "PGDATA")) {
                has_pgdata = true;
                break;
            }
        }
        if (!has_pgdata) {
            // Find volume mount for /var/lib/postgresql
            for (run_cmd.volumes) |vol| {
                if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                    var buf: [256]u8 = undefined;
                    const pgdata = std.fmt.bufPrint(&buf, "PGDATA={s}/data", .{vol.container_path}) catch "PGDATA=/var/lib/postgresql/data";
                    cfg.addEnv(pgdata) catch {};
                    has_pgdata = true;
                    break;
                }
            }
            if (!has_pgdata) {
                cfg.addEnv("PGDATA=/var/lib/postgresql/data") catch {};
            }
        }
    }

    // Add container ID tag for robust process stopping
    {
        var cid_tag_buf: [64]u8 = undefined;
        const cid_tag = std.fmt.bufPrint(&cid_tag_buf, "ISOLAZI_ID={s}", .{if (container_id) |cid| cid[0..] else "unknown"}) catch "ISOLAZI_ID=unknown";
        cfg.addEnv(cid_tag) catch {};
    }

    // Create and run the container
    // Expand 12-byte container_id to 32-byte for state tracking
    var cid_buf_short: [12]u8 = if (container_id) |cid| cid else [_]u8{ 'u', 'n', 'k', 'n', 'o', 'w', 'n', '0', '0', '0', '0', '0' };
    var cid_buf: [32]u8 = undefined;
    @memcpy(cid_buf[0..12], &cid_buf_short);
    // Pad with zeros
    @memset(cid_buf[12..], '0');

    // Register container with ContainerManager for state tracking
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    // Build command string for state tracking
    var cmd_display: [256]u8 = undefined;
    const safe_cmd = run_cmd.command orelse "";
    const cmd_len = @min(safe_cmd.len, 255);
    @memcpy(cmd_display[0..cmd_len], safe_cmd[0..cmd_len]);

    // Register container (state will be updated to running with PID by runtime)
    _ = manager.createContainerWithId(&cid_buf, run_cmd.rootfs, cmd_display[0..cmd_len], null, .no, &[_]isolazi.container.state.PortMapping{}, &[_]isolazi.container.state.VolumeMount{}, &[_]isolazi.container.state.EnvVar{}) catch {};

    // Handle detached mode: fork a monitor process and exit
    if (run_cmd.detach) {
        // Fork the monitor process
        const pid = isolazi.linux.fork() catch |err| {
            try stderr.print("Error: Failed to fork monitor process: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        if (pid > 0) {
            // Parent process - print container ID and return success
            // The defer manager.deinit() will run on return
            try stdout.print("{s}\n", .{cid_buf_short});
            try stdout.flush();
            return 0;
        }

        // Child process (monitor)
        // Start a new session to detach from controlling terminal
        _ = std.os.linux.setsid();

        // Redirect stdin/stdout/stderr to /dev/null to prevent EPIPE/SIGPIPE/IO errors
        // when the parent terminal closes or when writing to closed fds.
        {
            if (std.fs.cwd().openFile("/dev/null", .{ .mode = .read_write })) |null_file| {
                const fd = null_file.handle;
                _ = std.os.linux.dup2(fd, 0);
                _ = std.os.linux.dup2(fd, 1);
                _ = std.os.linux.dup2(fd, 2);
                if (fd > 2) null_file.close();
            } else |_| {
                // Ignore error
            }
        }

        // Close inherited resources from parent
        manager.deinit();

        // Run the container synchronously in this monitor process
        const result = isolazi.runtime.run(&cfg, allocator, &cid_buf_short) catch {
            // If runtime fails, update state to stopped with error
            var mon_mgr = isolazi.container.ContainerManager.init(allocator) catch {
                std.process.exit(1);
            };
            defer mon_mgr.deinit();
            mon_mgr.updateState(&cid_buf, .stopped, null, 1) catch {};

            // We can't easily print to stderr since we detached, maybe log to file?
            // For now just exit
            std.process.exit(1);
        };

        // Update container state to stopped with exit code
        {
            var mon_mgr = isolazi.container.ContainerManager.init(allocator) catch {
                std.process.exit(0);
            };
            defer mon_mgr.deinit();
            mon_mgr.updateState(&cid_buf, .stopped, null, result.exit_code) catch {};
        }

        std.process.exit(0);
    }

    const result = isolazi.runtime.run(&cfg, allocator, &cid_buf_short) catch |err| {
        // Update state to stopped on error
        manager.updateState(&cid_buf, .stopped, null, 1) catch {};
        try stderr.print("Error: Container execution failed: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    // Update container state to stopped
    manager.updateState(&cid_buf, .stopped, null, result.exit_code) catch {};

    // Return the container's exit code
    if (result.signaled) {
        try stderr.print("Container killed by signal {}\n", .{result.signal});
        try stderr.flush();
    }

    return result.exit_code;
}
