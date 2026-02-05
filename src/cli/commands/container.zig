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

    // Platform-specific execution (comptime for cross-compilation)
    const macos_virt = if (builtin.os.tag == .macos) isolazi.macos.virtualization else struct {
        pub fn startContainer(_: std.mem.Allocator, _: []const u8, _: anytype) !void {
            return error.NotImplemented;
        }
    };

    if (builtin.os.tag == .macos) {
        macos_virt.startContainer(allocator, full_id, &info) catch |err| {
            stderr.print("Error: Failed to start container on macOS: {}\n", .{err}) catch {};
            stderr.flush() catch {};
            return 1;
        };
    } else if (builtin.os.tag == .linux) {
        // Placeholder for Linux start
        stderr.print("Error: 'start' not implemented for Linux yet\n", .{}) catch {};
        return 1;
    } else {
        stderr.print("Error: 'start' not implemented for this platform yet\n", .{}) catch {};
        return 1;
    }

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
