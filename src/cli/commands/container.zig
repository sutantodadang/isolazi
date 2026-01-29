//! Container Lifecycle Commands
//!
//! Commands for stopping, starting, and removing containers.
//! Consolidated from platform-specific implementations.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../root.zig");

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
/// Returns 0 on success, 1 on error.
pub fn startContainer(
    allocator: std.mem.Allocator,
    start_cmd: isolazi.cli.StartCommand,
    _: anytype, // stdout - unused currently
    stderr: anytype,
) u8 {
    const container_id = start_cmd.container_id;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    // Verify container exists
    var info = manager.getContainer(container_id) catch |err| {
        stderr.print("Error: Container not found: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer info.deinit();

    if (info.state == .running) {
        stderr.print("Container {s} is already running\n", .{info.shortId()}) catch {};
        stderr.flush() catch {};
        return 0;
    }

    // Start is more complex as we need to re-execute the container
    // This would need platform-specific implementation
    stderr.writeAll("Note: Container restart not yet fully implemented\n") catch {};
    stderr.writeAll("Please use 'isolazi run' to start a new container\n") catch {};
    stderr.flush() catch {};

    return 1;
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
