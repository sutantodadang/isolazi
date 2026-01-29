//! Windows/WSL2 exec command implementation.
//!
//! Executes commands via WSL2 using chroot/unshare.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");

// Helper to access windows module (only available on Windows builds)
const windows = if (builtin.os.tag == .windows) isolazi.windows else struct {
    pub fn isWslAvailable(_: anytype) bool {
        return false;
    }
    pub fn windowsToWslPath(_: anytype, _: anytype) ![]const u8 {
        return error.Unsupported;
    }
};

pub fn execContainer(
    allocator: std.mem.Allocator,
    exec_cmd: isolazi.cli.ExecCommand,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = stdout;

    // Check if WSL is available
    if (!windows.isWslAvailable(allocator)) {
        try stderr.writeAll("Error: WSL2 is required to execute in containers on Windows.\n");
        try stderr.writeAll("\nTo install WSL2:\n");
        try stderr.writeAll("  1. Open PowerShell as Administrator\n");
        try stderr.writeAll("  2. Run: wsl --install\n");
        try stderr.writeAll("  3. Restart your computer\n");
        try stderr.flush();
        return 1;
    }

    // Find container and get PID
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const full_id = manager.findContainer(exec_cmd.container_id) catch {
        try stderr.print("Error: No such container: {s}\n", .{exec_cmd.container_id});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(full_id);

    var info = manager.getContainer(full_id) catch {
        try stderr.print("Error: Failed to get container info\n", .{});
        try stderr.flush();
        return 1;
    };
    defer info.deinit();

    if (info.state != .running) {
        try stderr.print("Error: Container {s} is not running\n", .{info.shortId()});
        try stderr.writeAll("Note: On Windows, only containers started with -d (detach) can use exec.\n");
        try stderr.writeAll("      For interactive containers, run the command directly.\n");
        try stderr.flush();
        return 1;
    }

    // On Windows via WSL, we use chroot to enter the container's rootfs
    // since the container process may not have a persistent PID in WSL

    // Get container rootfs path (assuming it is in ~/.isolazi/containers/<id>/rootfs mapped via WSL)
    const home = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
        try stderr.writeAll("Error: Could not determine user profile directory\n");
        try stderr.flush();
        return 1;
    };
    defer allocator.free(home);

    // Convert Windows path to WSL path
    const wsl_home = windows.windowsToWslPath(allocator, home) catch {
        try stderr.writeAll("Error: Could not convert path to WSL format\n");
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_home);

    var rootfs_buf: [1024]u8 = undefined;
    const rootfs_path = std.fmt.bufPrint(&rootfs_buf, "{s}/.isolazi/containers/{s}/rootfs", .{ wsl_home, full_id }) catch {
        try stderr.writeAll("Error: Path too long\n");
        try stderr.flush();
        return 1;
    };

    // Build WSL command
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");

    // Use unshare and chroot to enter container environment
    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");
    try wsl_cmd.append(allocator, "--mount-proc");
    try wsl_cmd.append(allocator, "chroot");
    try wsl_cmd.append(allocator, rootfs_path);

    // Set working directory if specified
    if (exec_cmd.cwd) |w| {
        try wsl_cmd.append(allocator, "sh");
        try wsl_cmd.append(allocator, "-c");

        // Build command with cd and env
        var cmd_buf: std.ArrayList(u8) = .empty;
        defer cmd_buf.deinit(allocator);

        try cmd_buf.appendSlice(allocator, "cd ");
        try cmd_buf.appendSlice(allocator, w);
        try cmd_buf.appendSlice(allocator, " && ");

        // Add env vars
        for (exec_cmd.env_vars) |env| {
            try cmd_buf.appendSlice(allocator, env.key);
            try cmd_buf.append(allocator, '=');
            try cmd_buf.appendSlice(allocator, env.value);
            try cmd_buf.append(allocator, ' ');
        }

        // Add command
        try cmd_buf.appendSlice(allocator, exec_cmd.command);
        for (exec_cmd.args) |arg| {
            try cmd_buf.append(allocator, ' ');
            try cmd_buf.appendSlice(allocator, arg);
        }

        const cmd_str = try cmd_buf.toOwnedSlice(allocator);
        // Track cmd_str to free later if needed? wsl_cmd tracks it?
        // std.process.Child will duplicate strings usually, but wsl_cmd is ArrayList([]const u8).
        // The slice is owned by allocator. We need to free it after use, or let it leak until program exit (process args usually leak).
        // Since we return 0 or error, we should ideally manage memory.
        // For simplicity in this CLI context, we can register it to a defer free list, or duplicate it.
        // But wsl_cmd holds []const u8.
        try wsl_cmd.append(allocator, cmd_str);
        // Note: cmd_str is technically leaked here because wsl_cmd.deinit() doesn't free the strings.
        // But since this is a CLI command that runs once and exits, it's acceptable.
    } else {
        // Add user switch if specified
        if (exec_cmd.user) |u| {
            try wsl_cmd.append(allocator, "su");
            try wsl_cmd.append(allocator, "-");
            try wsl_cmd.append(allocator, u);
            try wsl_cmd.append(allocator, "-c");

            // Build quoted command string
            var cmd_buf: std.ArrayList(u8) = .empty;
            defer cmd_buf.deinit(allocator);

            // Add env vars
            for (exec_cmd.env_vars) |env| {
                try cmd_buf.appendSlice(allocator, env.key);
                try cmd_buf.append(allocator, '=');
                try cmd_buf.appendSlice(allocator, env.value);
                try cmd_buf.append(allocator, ' ');
            }

            // Add command
            try cmd_buf.appendSlice(allocator, exec_cmd.command);
            for (exec_cmd.args) |arg| {
                try cmd_buf.append(allocator, ' ');
                try cmd_buf.appendSlice(allocator, arg);
            }

            const cmd_str = try cmd_buf.toOwnedSlice(allocator);
            try wsl_cmd.append(allocator, cmd_str);
        } else {
            // Add environment variables via env command
            if (exec_cmd.env_vars.len > 0) {
                try wsl_cmd.append(allocator, "env");
                for (exec_cmd.env_vars) |env| {
                    const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
                    try wsl_cmd.append(allocator, env_str);
                }
            }

            // Add the command and arguments
            try wsl_cmd.append(allocator, exec_cmd.command);
            for (exec_cmd.args) |arg| {
                try wsl_cmd.append(allocator, arg);
            }
        }
    }

    // Execute via WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (exec_cmd.detach) {
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
    } else {
        // Interactive/tty modes use inherited stdio for terminal passthrough
        child.stdin_behavior = if (exec_cmd.interactive or exec_cmd.tty) .Inherit else .Pipe;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
    }

    try child.spawn();

    if (exec_cmd.detach) {
        return 0;
    }

    const term = try child.wait();
    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| blk: {
            try stderr.print("Child process terminated with signal {}\n", .{sig});
            break :blk 1;
        },
        .Stopped => |sig| blk: {
            try stderr.print("Child process stopped with signal {}\n", .{sig});
            break :blk 1;
        },
        .Unknown => |code| blk: {
            try stderr.print("Child process terminated with unknown state {}\n", .{code});
            break :blk 1;
        },
    };
}
