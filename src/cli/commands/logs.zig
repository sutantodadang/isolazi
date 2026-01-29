//! Logs Command Handler
//!
//! Shared container log viewing logic used by all platforms.
//! Consolidates previously duplicated code from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Show container logs
///
/// Returns 0 on success, 1 on error.
pub fn showLogs(
    allocator: std.mem.Allocator,
    logs_cmd: isolazi.cli.LogsCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const container_id = logs_cmd.container_id;
    const follow = logs_cmd.follow;
    const timestamps = logs_cmd.timestamps;
    const tail = logs_cmd.tail;
    const stdout_only = logs_cmd.stdout_only;
    const stderr_only = logs_cmd.stderr_only;

    if (container_id.len == 0) {
        stderr.writeAll("Error: Missing container ID\n") catch {};
        stderr.flush() catch {};
        return 1;
    }

    // Find container
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    const full_id = manager.findContainer(container_id) catch {
        stderr.print("Error: No such container: {s}\n", .{container_id}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(full_id);

    // Initialize container logs
    var logs = isolazi.container.ContainerLogs.init(allocator, full_id) catch |err| {
        stderr.print("Error: Failed to initialize logs: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer logs.deinit();

    // Determine which stream to show
    const stream: isolazi.container.LogStream = if (stdout_only and !stderr_only)
        .stdout
    else if (stderr_only and !stdout_only)
        .stderr
    else
        .both;

    // Stream logs to stdout
    const options = isolazi.container.LogOptions{
        .follow = follow,
        .timestamps = timestamps,
        .tail = tail,
        .stream = stream,
        .poll_interval_ms = 100,
    };

    logs.streamLogs(stdout, options) catch |err| {
        // In follow mode, this will block until interrupted
        if (err != error.BrokenPipe) {
            stderr.print("Error reading logs: {}\n", .{err}) catch {};
            stderr.flush() catch {};
            return 1;
        }
    };

    stdout.flush() catch {};
    return 0;
}
