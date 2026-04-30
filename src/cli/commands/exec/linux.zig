//! Linux exec command implementation.
//!
//! Executes commands natively on Linux using nsenter.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");

// Helper to access runtime module (only available on Linux)
const runtime = if (builtin.os.tag == .linux) isolazi.runtime else struct {
    pub const ExecConfig = struct {};
    pub fn execInContainer(_: std.mem.Allocator, _: anytype) !struct { exit_code: u8, signaled: bool, signal: u32 } {
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

    // Check if running as root
    // Only compile getuid if on Linux, otherwise runtime error
    if (builtin.os.tag == .linux) {
        if (std.os.linux.getuid() != 0) {
            try stderr.writeAll("Error: Isolazi exec must be run as root.\n");
            try stderr.writeAll("nsenter requires CAP_SYS_ADMIN privileges.\n");
            try stderr.writeAll("\nHint: Run with 'sudo isolazi exec ...'\n");
            try stderr.flush();
            return 1;
        }
    } else {
        return error.Unsupported;
    }

    // Find the container
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

    // Check container is running
    if (info.state != .running) {
        try stderr.print("Error: Container {s} is not running\n", .{info.shortId()});
        try stderr.flush();
        return 1;
    }

    const target_pid = info.pid orelse {
        try stderr.writeAll("Error: Container has no PID recorded\n");
        try stderr.flush();
        return 1;
    };

    // Build environment variables
    var env_list: std.ArrayList([]const u8) = .empty;
    defer env_list.deinit(allocator); // Note: this frees the ArrayList array, not the items.
    // We need to free the items.
    defer {
        for (env_list.items) |item| {
            allocator.free(item);
        }
    }

    for (exec_cmd.env_vars) |env| {
        var env_buf: [512]u8 = undefined;
        const env_str = std.fmt.bufPrint(&env_buf, "{s}={s}", .{ env.key, env.value }) catch continue;
        const duped = try allocator.dupe(u8, env_str);
        try env_list.append(allocator, duped);
    }

    // Create exec configuration
    const exec_cfg = isolazi.runtime.ExecConfig{
        .target_pid = target_pid,
        .command = exec_cmd.command,
        .args = exec_cmd.args,
        .env = env_list.items,
        .cwd = exec_cmd.cwd,
        .user = exec_cmd.user,
        .namespaces = .{
            .mount = true,
            .uts = true,
            .ipc = true,
            .net = true,
            .pid = true,
            .user = false, // Usually skip user ns for exec
            .cgroup = true,
        },
    };

    // Execute in container
    const result = isolazi.runtime.execInContainer(allocator, exec_cfg) catch |err| {
        try stderr.print("Error: Failed to execute in container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    if (result.signaled) {
        try stderr.print("Command killed by signal {}\n", .{result.signal});
        try stderr.flush();
    }

    return result.exit_code;
}
