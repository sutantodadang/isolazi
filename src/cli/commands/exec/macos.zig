//! macOS exec command implementation.
//!
//! Executes commands via Lima/vfkit using nsenter.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");

// Helper to access macos module safely
const macos = if (builtin.os.tag == .macos) isolazi.macos else struct {
    pub const virtualization = struct {
        pub fn isLimaInstalled(_: anytype) bool {
            return false;
        }
    };
};

pub fn execContainer(
    allocator: std.mem.Allocator,
    exec_cmd: isolazi.cli.ExecCommand,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = stdout;

    // Check if Lima is installed
    if (!macos.virtualization.isLimaInstalled(allocator)) {
        try stderr.writeAll("Error: Lima is not installed.\n");
        try stderr.writeAll("\nPlease install Lima to run containers on macOS:\n");
        try stderr.writeAll("  brew install lima\n");
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
        try stderr.flush();
        return 1;
    }

    const target_pid = info.pid orelse {
        try stderr.writeAll("Error: Container has no PID recorded\n");
        try stderr.flush();
        return 1;
    };

    // Build Lima/limactl command to exec via nsenter in VM
    var lima_cmd: std.ArrayList([]const u8) = .empty;
    defer lima_cmd.deinit(allocator);

    // Lima approach: limactl shell default nsenter ...
    try lima_cmd.append(allocator, "limactl");
    try lima_cmd.append(allocator, "shell");
    try lima_cmd.append(allocator, "default");
    try lima_cmd.append(allocator, "--");
    try lima_cmd.append(allocator, "sudo");

    // Use nsenter to enter container namespaces
    try lima_cmd.append(allocator, "nsenter");
    try lima_cmd.append(allocator, "--target");

    // Format PID as string
    var pid_buf: [16]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{target_pid}) catch "0";
    try lima_cmd.append(allocator, pid_str);

    // Enter all namespaces
    try lima_cmd.append(allocator, "--mount");
    try lima_cmd.append(allocator, "--uts");
    try lima_cmd.append(allocator, "--ipc");
    try lima_cmd.append(allocator, "--net");
    try lima_cmd.append(allocator, "--pid");
    try lima_cmd.append(allocator, "--cgroup");

    // Set user if specified
    if (exec_cmd.user) |u| {
        try lima_cmd.append(allocator, "--setuid");
        try lima_cmd.append(allocator, u);
    }

    // Set working directory if specified
    if (exec_cmd.cwd) |w| {
        try lima_cmd.append(allocator, "--wd");
        try lima_cmd.append(allocator, w);
    }

    // Add environment variables via env command
    if (exec_cmd.env_vars.len > 0) {
        try lima_cmd.append(allocator, "env");
        for (exec_cmd.env_vars) |env| {
            // Need "key=value" string
            const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
            // We need to track allocation to free later?
            // Usually exec command strings leak, but we can verify usage.
            // For now, let's append.
            try lima_cmd.append(allocator, env_str);
        }
    }

    // Add the command and arguments
    try lima_cmd.append(allocator, exec_cmd.command);
    for (exec_cmd.args) |arg| {
        try lima_cmd.append(allocator, arg);
    }

    // Execute via Lima
    var child = std.process.Child.init(lima_cmd.items, allocator);

    // Configure stdin/stdout/stderr behavior based on options
    if (exec_cmd.detach) {
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
    } else {
        // Interactive mode requires stdin, tty enables terminal passthrough
        // (interactive or tty is usually set by CLI parser default true, user can override)
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
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
}
