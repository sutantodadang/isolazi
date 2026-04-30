//! Container Lifecycle Commands
//!
//! Commands for stopping, starting, and removing containers.
//! Consolidated from platform-specific implementations.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../root.zig");
const runmod = @import("run.zig");

// Windows module - conditionally compiled
const windows = if (builtin.os.tag == .windows) isolazi.windows else struct {
    pub fn isWslAvailable(_: std.mem.Allocator) bool {
        return false;
    }
    pub fn windowsToWslPath(_: std.mem.Allocator, path: []const u8) ![]const u8 {
        return path;
    }
};

/// Stop a running container
///
/// Returns 0 on success, 1 on error.
pub fn stopContainer(
    allocator: std.mem.Allocator,
    stop_cmd: isolazi.cli.StopCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const query = stop_cmd.container_id;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    // Find the container
    const container_id = manager.findContainer(query) catch {
        stderr.print("Error: No such container: {s}\n", .{query}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(container_id);

    // Stop the container
    manager.stopContainer(container_id) catch |err| {
        if (err == error.ContainerNotRunning) {
            stderr.print("Error: Container {s} is not running\n", .{query}) catch {};
            stderr.flush() catch {};
            return 1;
        }
        stderr.print("Error: Failed to stop container: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };

    stdout.print("{s}\n", .{container_id[0..12]}) catch {};
    stdout.flush() catch {};
    return 0;
}

/// Start a stopped container
///
/// Reconstructs the WSL execution from persisted state.json configuration
/// (image, command, ports, volumes, env_vars, workdir, restart_policy).
/// Returns 0 on success, 1 on error.
pub fn startContainer(
    allocator: std.mem.Allocator,
    start_cmd: isolazi.cli.StartCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const query = start_cmd.container_id;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    // Find the container
    const full_id = manager.findContainer(query) catch {
        stderr.print("Error: Container not found: error.ContainerNotFound\n", .{}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(full_id);

    // Get info
    var info = manager.getContainer(full_id) catch |err| {
        stderr.print("Error: Failed to get container info: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer info.deinit();

    if (info.state == .running) {
        stderr.print("Container {s} is already running\n", .{info.shortId()}) catch {};
        stderr.flush() catch {};
        return 0;
    }

    // Platform-specific start
    if (builtin.os.tag == .windows) {
        return startContainerWSL(allocator, &manager, full_id, &info, stdout, stderr);
    } else if (builtin.os.tag == .macos) {
        const macos_virt = isolazi.macos.virtualization;
        macos_virt.startContainer(allocator, full_id, &info) catch |err| {
            stderr.print("Error: Failed to start container on macOS: {}\n", .{err}) catch {};
            stderr.flush() catch {};
            return 1;
        };
    } else if (builtin.os.tag == .linux) {
        return startContainerLinux(allocator, &manager, full_id, &info, stdout, stderr);
    } else {
        stderr.print("Error: 'start' not implemented for this platform yet\n", .{}) catch {};
        return 1;
    }

    stdout.print("{s}\n", .{full_id[0..12]}) catch {};
    stdout.flush() catch {};

    return 0;
}

/// Start a stopped container on Windows using WSL2
///
/// Rebuilds the overlay mount + chroot script from persisted container config.
fn startContainerWSL(
    allocator: std.mem.Allocator,
    manager: *isolazi.container.ContainerManager,
    full_id: []const u8,
    info: *isolazi.container.state.ContainerInfo,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Check WSL availability
    if (!windows.isWslAvailable(allocator)) {
        stderr.print("Error: WSL2 is required to run containers on Windows.\n", .{}) catch {};
        stderr.flush() catch {};
        return 1;
    }

    // Get the existing rootfs path
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer cache.deinit();

    const rootfs_path = cache.getContainerPath(full_id) catch |err| {
        stderr.print("Error: Failed to get container rootfs path: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(rootfs_path);

    // Check rootfs exists
    std.fs.cwd().access(rootfs_path, .{}) catch {
        stderr.print("Error: Container rootfs not found. Image may need to be re-pulled.\n", .{}) catch {};
        stderr.flush() catch {};
        return 1;
    };

    // Get log file paths
    const container_dir = std.fs.path.dirname(rootfs_path) orelse rootfs_path;
    const stdout_log_path = std.fmt.allocPrint(allocator, "{s}/stdout.log", .{container_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(stdout_log_path);
    const stderr_log_path = std.fmt.allocPrint(allocator, "{s}/stderr.log", .{container_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(stderr_log_path);

    // Convert paths to WSL
    const wsl_rootfs = windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
        stderr.print("Error: Failed to convert rootfs path: {}\n", .{err}) catch {};
        return 1;
    };
    defer allocator.free(wsl_rootfs);
    const wsl_stdout_log = windows.windowsToWslPath(allocator, stdout_log_path) catch |err| {
        stderr.print("Error: Failed to convert stdout log path: {}\n", .{err}) catch {};
        return 1;
    };
    defer allocator.free(wsl_stdout_log);
    const wsl_stderr_log = windows.windowsToWslPath(allocator, stderr_log_path) catch |err| {
        stderr.print("Error: Failed to convert stderr log path: {}\n", .{err}) catch {};
        return 1;
    };
    defer allocator.free(wsl_stderr_log);

    // Overlay paths
    const overlay_dir = std.fmt.allocPrint(allocator, "/tmp/isolazi/{s}", .{full_id}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(overlay_dir);
    const overlay_upper = std.fmt.allocPrint(allocator, "{s}/upper", .{overlay_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(overlay_upper);
    const overlay_work = std.fmt.allocPrint(allocator, "{s}/work", .{overlay_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(overlay_work);
    const overlay_merged = std.fmt.allocPrint(allocator, "{s}/merged", .{overlay_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(overlay_merged);

    // Build outer wrapper script
    var outer_buf: std.ArrayList(u8) = .empty;
    defer outer_buf.deinit(allocator);
    outer_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_upper) catch return 1;
    outer_buf.appendSlice(allocator, " ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_work) catch return 1;
    outer_buf.appendSlice(allocator, " ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_merged) catch return 1;
    outer_buf.appendSlice(allocator, " && echo $$ > ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_dir) catch return 1;
    outer_buf.appendSlice(allocator, "/pid && exec unshare --mount --uts --ipc --pid --fork sh ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_dir) catch return 1;
    outer_buf.appendSlice(allocator, "/run.sh") catch return 1;

    // Build inner script
    var script_buf: std.ArrayList(u8) = .empty;
    defer script_buf.deinit(allocator);

    // Overlay mount
    script_buf.appendSlice(allocator, "mount -t overlay overlay -o lowerdir=") catch return 1;
    script_buf.appendSlice(allocator, wsl_rootfs) catch return 1;
    script_buf.appendSlice(allocator, ",upperdir=") catch return 1;
    script_buf.appendSlice(allocator, overlay_upper) catch return 1;
    script_buf.appendSlice(allocator, ",workdir=") catch return 1;
    script_buf.appendSlice(allocator, overlay_work) catch return 1;
    script_buf.appendSlice(allocator, " ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, " && ") catch return 1;

    // Mount proc
    script_buf.appendSlice(allocator, "mount -t proc proc ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/proc && ") catch return 1;

    // /dev/fd symlink
    script_buf.appendSlice(allocator, "ln -sf /proc/self/fd ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/dev/fd 2>/dev/null; ") catch return 1;

    // /dev setup
    script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/dev && ") catch return 1;

    // Bind device nodes
    const devices = [_][]const u8{ "/dev/null", "/dev/tty", "/dev/random", "/dev/urandom" };
    for (devices) |dev| {
        script_buf.appendSlice(allocator, "touch ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " && mount --bind ") catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // /dev/shm, /tmp, /run as tmpfs
    const tmpfs_mounts = [_][]const u8{ "/dev/shm", "/tmp", "/run" };
    for (tmpfs_mounts) |mnt| {
        script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, mnt) catch return 1;
        script_buf.appendSlice(allocator, " && mount -t tmpfs tmpfs ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, mnt) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // Track allocated paths for cleanup
    var allocated_paths: [32][]const u8 = undefined;
    var alloc_count: usize = 0;
    defer for (allocated_paths[0..alloc_count]) |p| allocator.free(p);

    // Mount volumes from persisted config
    const is_postgres = std.mem.indexOf(u8, info.image, "postgres") != null;
    for (info.volumes) |vol| {
        const is_named_volume = vol.host_path.len > 0 and vol.host_path[0] != '/' and
            !(vol.host_path.len >= 2 and vol.host_path[1] == ':');

        var wsl_host: []const u8 = undefined;
        if (is_named_volume) {
            wsl_host = std.fmt.allocPrint(allocator, "/tmp/isolazi/volumes/{s}", .{vol.host_path}) catch return 1;
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
        script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, wsl_host) catch return 1;
        script_buf.appendSlice(allocator, " && mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, vol.container_path) catch return 1;
        script_buf.appendSlice(allocator, " && mount --bind ") catch return 1;
        script_buf.appendSlice(allocator, wsl_host) catch return 1;
        script_buf.append(allocator, ' ') catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, vol.container_path) catch return 1;
        script_buf.appendSlice(allocator, " && ") catch return 1;
    }

    // Port forwarding
    for (info.ports) |port| {
        const proto_str = if (port.protocol == .udp) "udp" else "tcp";
        var host_port_buf: [8]u8 = undefined;
        const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
        var cont_port_buf: [8]u8 = undefined;
        const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";

        script_buf.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ") catch return 1;
        script_buf.appendSlice(allocator, proto_str) catch return 1;
        script_buf.appendSlice(allocator, " --dport ") catch return 1;
        script_buf.appendSlice(allocator, host_port_str) catch return 1;
        script_buf.appendSlice(allocator, " -j REDIRECT --to-port ") catch return 1;
        script_buf.appendSlice(allocator, cont_port_str) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;

        script_buf.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ") catch return 1;
        script_buf.appendSlice(allocator, proto_str) catch return 1;
        script_buf.appendSlice(allocator, " --dport ") catch return 1;
        script_buf.appendSlice(allocator, host_port_str) catch return 1;
        script_buf.appendSlice(allocator, " -j REDIRECT --to-port ") catch return 1;
        script_buf.appendSlice(allocator, cont_port_str) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // Chroot with env vars
    script_buf.appendSlice(allocator, "chroot ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, " /usr/bin/env -i ") catch return 1;

    // Minimal environment
    script_buf.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin ") catch return 1;
    script_buf.appendSlice(allocator, "HOME=/root ") catch return 1;
    script_buf.appendSlice(allocator, "TERM=xterm ") catch return 1;
    script_buf.appendSlice(allocator, "LANG=C.UTF-8 ") catch return 1;
    script_buf.appendSlice(allocator, "ISOLAZI_ID=") catch return 1;
    script_buf.appendSlice(allocator, full_id) catch return 1;
    script_buf.appendSlice(allocator, " ") catch return 1;

    // Auto-set PGDATA for postgres
    var has_pgdata = false;
    for (info.env_vars) |env| {
        if (std.mem.eql(u8, env.key, "PGDATA")) {
            has_pgdata = true;
            break;
        }
    }
    if (is_postgres and !has_pgdata) {
        for (info.volumes) |vol| {
            if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                script_buf.appendSlice(allocator, "PGDATA=") catch return 1;
                if (std.mem.endsWith(u8, vol.container_path, "/data")) {
                    script_buf.appendSlice(allocator, vol.container_path) catch return 1;
                } else {
                    script_buf.appendSlice(allocator, vol.container_path) catch return 1;
                    script_buf.appendSlice(allocator, "/data") catch return 1;
                }
                script_buf.append(allocator, ' ') catch return 1;
                has_pgdata = true;
                break;
            }
        }
        if (!has_pgdata) {
            script_buf.appendSlice(allocator, "PGDATA=/var/lib/postgresql/data ") catch return 1;
        }
    }

    // Export environment variables from persisted config
    for (info.env_vars) |env| {
        script_buf.appendSlice(allocator, env.key) catch return 1;
        script_buf.appendSlice(allocator, "=") catch return 1;
        script_buf.appendSlice(allocator, env.value) catch return 1;
        script_buf.append(allocator, ' ') catch return 1;
    }

    // Parse the persisted command string back into args for quoting
    const workdir_val = info.workdir;
    if (!std.mem.eql(u8, workdir_val, "/")) {
        script_buf.appendSlice(allocator, "sh -c 'cd ") catch return 1;
        script_buf.appendSlice(allocator, workdir_val) catch return 1;
        script_buf.appendSlice(allocator, " && exec ") catch return 1;
        script_buf.appendSlice(allocator, info.command) catch return 1;
        script_buf.appendSlice(allocator, "'") catch return 1;
    } else {
        script_buf.appendSlice(allocator, info.command) catch return 1;
    }

    // Redirect output to logs (detach mode)
    script_buf.appendSlice(allocator, " >> ") catch return 1;
    script_buf.appendSlice(allocator, wsl_stdout_log) catch return 1;
    script_buf.appendSlice(allocator, " 2>> ") catch return 1;
    script_buf.appendSlice(allocator, wsl_stderr_log) catch return 1;

    // Write inner script to WSL
    {
        const run_sh_path = std.fmt.allocPrint(allocator, "{s}/run.sh", .{overlay_dir}) catch return 1;
        defer allocator.free(run_sh_path);
        const write_sh_cmd = std.fmt.allocPrint(allocator, "mkdir -p {s} && cat > {s}", .{ overlay_dir, run_sh_path }) catch return 1;
        defer allocator.free(write_sh_cmd);
        var write_cmd = [_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", write_sh_cmd };
        var write_child = std.process.Child.init(&write_cmd, allocator);
        write_child.stdin_behavior = .Pipe;
        write_child.stdout_behavior = .Ignore;
        write_child.stderr_behavior = .Ignore;
        write_child.spawn() catch |err| {
            stderr.print("Error: Failed to write run script: {}\n", .{err}) catch {};
            return 1;
        };
        if (write_child.stdin) |stdin| {
            stdin.writeAll(script_buf.items) catch {};
            stdin.close();
            write_child.stdin = null;
        }
        _ = write_child.wait() catch {};
    }

    // Build WSL command
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);
    wsl_cmd.append(allocator, "wsl") catch return 1;
    wsl_cmd.append(allocator, "-u") catch return 1;
    wsl_cmd.append(allocator, "root") catch return 1;
    wsl_cmd.append(allocator, "--") catch return 1;
    wsl_cmd.append(allocator, "sh") catch return 1;
    wsl_cmd.append(allocator, "-c") catch return 1;
    wsl_cmd.append(allocator, outer_buf.items) catch return 1;

    // Launch detached (start always runs in background)
    var child = std.process.Child.init(wsl_cmd.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.create_no_window = true;

    child.spawn() catch |err| {
        stderr.print("Error: Failed to start container process: {}\n", .{err}) catch {};
        return 1;
    };

    // Wait for PID file
    std.Thread.sleep(200 * std.time.ns_per_ms);

    // Read PID
    var wsl_pid: ?i32 = null;
    {
        const pid_cmd = std.fmt.allocPrint(allocator, "cat {s}/pid 2>/dev/null", .{overlay_dir}) catch return 1;
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

    manager.updateState(full_id, .running, wsl_pid, null) catch {};

    stdout.print("{s}\n", .{full_id[0..12]}) catch {};
    stdout.flush() catch {};
    return 0;
}

/// Start a stopped container on Linux using namespaces
fn startContainerLinux(
    allocator: std.mem.Allocator,
    manager: *isolazi.container.ContainerManager,
    full_id: []const u8,
    info: *isolazi.container.state.ContainerInfo,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Get the existing rootfs path
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer cache.deinit();

    const rootfs_path = cache.getContainerPath(full_id) catch |err| {
        stderr.print("Error: Failed to get container rootfs path: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(rootfs_path);

    // Check rootfs exists
    std.fs.cwd().access(rootfs_path, .{}) catch {
        stderr.print("Error: Container rootfs not found. Image may need to be re-pulled.\n", .{}) catch {};
        stderr.flush() catch {};
        return 1;
    };

    // Get log file paths
    const container_dir = std.fs.path.dirname(rootfs_path) orelse rootfs_path;
    const stdout_log_path = std.fmt.allocPrint(allocator, "{s}/stdout.log", .{container_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(stdout_log_path);
    const stderr_log_path = std.fmt.allocPrint(allocator, "{s}/stderr.log", .{container_dir}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(stderr_log_path);

    // Overlay paths
    const overlay_dir = std.fmt.allocPrint(allocator, "/tmp/isolazi/{s}", .{full_id}) catch {
        stderr.print("Error: Out of memory\n", .{}) catch {};
        return 1;
    };
    defer allocator.free(overlay_dir);
    const overlay_upper = std.fmt.allocPrint(allocator, "{s}/upper", .{overlay_dir}) catch return 1;
    defer allocator.free(overlay_upper);
    const overlay_work = std.fmt.allocPrint(allocator, "{s}/work", .{overlay_dir}) catch return 1;
    defer allocator.free(overlay_work);
    const overlay_merged = std.fmt.allocPrint(allocator, "{s}/merged", .{overlay_dir}) catch return 1;
    defer allocator.free(overlay_merged);

    // Build outer wrapper script
    var outer_buf: std.ArrayList(u8) = .empty;
    defer outer_buf.deinit(allocator);
    outer_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_upper) catch return 1;
    outer_buf.appendSlice(allocator, " ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_work) catch return 1;
    outer_buf.appendSlice(allocator, " ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_merged) catch return 1;
    outer_buf.appendSlice(allocator, " && echo $$ > ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_dir) catch return 1;
    outer_buf.appendSlice(allocator, "/pid && exec unshare --mount --uts --ipc --pid --fork sh ") catch return 1;
    outer_buf.appendSlice(allocator, overlay_dir) catch return 1;
    outer_buf.appendSlice(allocator, "/run.sh") catch return 1;

    // Build inner script
    var script_buf: std.ArrayList(u8) = .empty;
    defer script_buf.deinit(allocator);

    // Overlay mount
    script_buf.appendSlice(allocator, "mount -t overlay overlay -o lowerdir=") catch return 1;
    script_buf.appendSlice(allocator, rootfs_path) catch return 1;
    script_buf.appendSlice(allocator, ",upperdir=") catch return 1;
    script_buf.appendSlice(allocator, overlay_upper) catch return 1;
    script_buf.appendSlice(allocator, ",workdir=") catch return 1;
    script_buf.appendSlice(allocator, overlay_work) catch return 1;
    script_buf.appendSlice(allocator, " ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, " && ") catch return 1;

    // Mount proc
    script_buf.appendSlice(allocator, "mount -t proc proc ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/proc && ") catch return 1;

    // /dev/fd symlink
    script_buf.appendSlice(allocator, "ln -sf /proc/self/fd ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/dev/fd 2>/dev/null; ") catch return 1;

    // /dev setup
    script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, "/dev && ") catch return 1;

    // Bind device nodes
    const devices = [_][]const u8{ "/dev/null", "/dev/tty", "/dev/random", "/dev/urandom" };
    for (devices) |dev| {
        script_buf.appendSlice(allocator, "touch ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " && mount --bind ") catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, dev) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // /dev/shm, /tmp, /run as tmpfs
    const tmpfs_mounts = [_][]const u8{ "/dev/shm", "/tmp", "/run" };
    for (tmpfs_mounts) |mnt| {
        script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, mnt) catch return 1;
        script_buf.appendSlice(allocator, " && mount -t tmpfs tmpfs ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, mnt) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // Mount volumes
    for (info.volumes) |vol| {
        script_buf.appendSlice(allocator, "mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, vol.host_path) catch return 1;
        script_buf.appendSlice(allocator, " && mkdir -p ") catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, vol.container_path) catch return 1;
        script_buf.appendSlice(allocator, " && mount --bind ") catch return 1;
        script_buf.appendSlice(allocator, vol.host_path) catch return 1;
        script_buf.append(allocator, ' ') catch return 1;
        script_buf.appendSlice(allocator, overlay_merged) catch return 1;
        script_buf.appendSlice(allocator, vol.container_path) catch return 1;
        script_buf.appendSlice(allocator, " && ") catch return 1;
    }

    // Port forwarding
    for (info.ports) |port| {
        const proto_str = if (port.protocol == .udp) "udp" else "tcp";
        var host_port_buf: [8]u8 = undefined;
        const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
        var cont_port_buf: [8]u8 = undefined;
        const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";

        script_buf.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ") catch return 1;
        script_buf.appendSlice(allocator, proto_str) catch return 1;
        script_buf.appendSlice(allocator, " --dport ") catch return 1;
        script_buf.appendSlice(allocator, host_port_str) catch return 1;
        script_buf.appendSlice(allocator, " -j REDIRECT --to-port ") catch return 1;
        script_buf.appendSlice(allocator, cont_port_str) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;

        script_buf.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ") catch return 1;
        script_buf.appendSlice(allocator, proto_str) catch return 1;
        script_buf.appendSlice(allocator, " --dport ") catch return 1;
        script_buf.appendSlice(allocator, host_port_str) catch return 1;
        script_buf.appendSlice(allocator, " -j REDIRECT --to-port ") catch return 1;
        script_buf.appendSlice(allocator, cont_port_str) catch return 1;
        script_buf.appendSlice(allocator, " 2>/dev/null; ") catch return 1;
    }

    // Chroot with env vars
    script_buf.appendSlice(allocator, "chroot ") catch return 1;
    script_buf.appendSlice(allocator, overlay_merged) catch return 1;
    script_buf.appendSlice(allocator, " /usr/bin/env -i ") catch return 1;
    script_buf.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ") catch return 1;
    script_buf.appendSlice(allocator, "HOME=/root ") catch return 1;
    script_buf.appendSlice(allocator, "TERM=xterm ") catch return 1;
    script_buf.appendSlice(allocator, "LANG=C.UTF-8 ") catch return 1;
    script_buf.appendSlice(allocator, "ISOLAZI_ID=") catch return 1;
    script_buf.appendSlice(allocator, full_id) catch return 1;
    script_buf.appendSlice(allocator, " ") catch return 1;

    for (info.env_vars) |env| {
        script_buf.appendSlice(allocator, env.key) catch return 1;
        script_buf.appendSlice(allocator, "=") catch return 1;
        script_buf.appendSlice(allocator, env.value) catch return 1;
        script_buf.append(allocator, ' ') catch return 1;
    }

    const workdir_val = info.workdir;
    if (!std.mem.eql(u8, workdir_val, "/")) {
        script_buf.appendSlice(allocator, "sh -c 'cd ") catch return 1;
        script_buf.appendSlice(allocator, workdir_val) catch return 1;
        script_buf.appendSlice(allocator, " && exec ") catch return 1;
        script_buf.appendSlice(allocator, info.command) catch return 1;
        script_buf.appendSlice(allocator, "'") catch return 1;
    } else {
        script_buf.appendSlice(allocator, info.command) catch return 1;
    }

    script_buf.appendSlice(allocator, " >> ") catch return 1;
    script_buf.appendSlice(allocator, stdout_log_path) catch return 1;
    script_buf.appendSlice(allocator, " 2>> ") catch return 1;
    script_buf.appendSlice(allocator, stderr_log_path) catch return 1;

    // Write inner script to file
    {
        const run_sh_path = std.fmt.allocPrint(allocator, "{s}/run.sh", .{overlay_dir}) catch return 1;
        defer allocator.free(run_sh_path);
        std.fs.cwd().makePath(overlay_dir) catch {};
        const file = std.fs.cwd().createFile(run_sh_path, .{}) catch |err| {
            stderr.print("Error: Failed to write run script: {}\n", .{err}) catch {};
            return 1;
        };
        defer file.close();
        file.writeAll(script_buf.items) catch {};
    }

    // Execute
    var child_argv = [_][]const u8{ "sh", "-c", outer_buf.items };
    var child = std.process.Child.init(&child_argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| {
        stderr.print("Error: Failed to start container process: {}\n", .{err}) catch {};
        return 1;
    };

    // Wait for PID file
    std.Thread.sleep(200 * std.time.ns_per_ms);

    // Read PID
    var linux_pid: ?i32 = null;
    {
        const pid_cmd = std.fmt.allocPrint(allocator, "cat {s}/pid 2>/dev/null", .{overlay_dir}) catch return 1;
        defer allocator.free(pid_cmd);
        const pid_result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "sh", "-c", pid_cmd },
        }) catch null;
        if (pid_result) |res| {
            defer allocator.free(res.stdout);
            defer allocator.free(res.stderr);
            const trimmed = std.mem.trim(u8, res.stdout, &[_]u8{ ' ', '\n', '\r', '\t' });
            linux_pid = std.fmt.parseInt(i32, trimmed, 10) catch null;
        }
    }

    manager.updateState(full_id, .running, linux_pid, null) catch {};

    stdout.print("{s}\n", .{full_id[0..12]}) catch {};
    stdout.flush() catch {};
    return 0;
}

/// Remove a container
///
/// Returns 0 on success, 1 on error.
pub fn removeContainer(
    allocator: std.mem.Allocator,
    rm_cmd: isolazi.cli.RmCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const container_id = rm_cmd.container_id;
    const force = rm_cmd.force;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    // Find the container
    const full_id = manager.findContainer(container_id) catch {
        stderr.print("Error: No such container: {s}\n", .{container_id}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(full_id);

    // Remove the container
    manager.removeContainer(full_id, force) catch |err| {
        if (err == error.ContainerRunning) {
            stderr.print("Error: Container {s} is running. Use -f to force removal\n", .{full_id[0..12]}) catch {};
            stderr.flush() catch {};
            return 1;
        }
        stderr.print("Error: Failed to remove container: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };

    stdout.print("{s}\n", .{full_id[0..12]}) catch {};
    stdout.flush() catch {};
    return 0;
}
