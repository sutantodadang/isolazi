//! Inspect Command Handler
//!
//! Shared container inspection logic used by all platforms.
//! Consolidates previously duplicated code from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Inspect a container
///
/// Returns 0 on success, 1 on error.
pub fn inspectContainer(
    allocator: std.mem.Allocator,
    inspect_cmd: isolazi.cli.InspectCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const query = inspect_cmd.container_id;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    // Find the container by name or ID prefix
    const container_id = manager.findContainer(query) catch {
        stderr.print("Error: No such container: {s}\n", .{query}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer allocator.free(container_id);

    // Get full container info
    var info = manager.getContainer(container_id) catch {
        stderr.print("Error: Failed to get container info\n", .{}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer info.deinit();

    // Output JSON-like format
    stdout.writeAll("{\n") catch {};
    stdout.print("  \"Id\": \"{s}\",\n", .{info.id}) catch {};
    stdout.print("  \"Image\": \"{s}\",\n", .{info.image}) catch {};
    stdout.print("  \"Command\": \"{s}\",\n", .{info.command}) catch {};
    stdout.print("  \"State\": \"{s}\",\n", .{info.state.toString()}) catch {};
    stdout.print("  \"Created\": {d},\n", .{info.created_at}) catch {};

    // Name (optional)
    if (info.name) |name| {
        stdout.print("  \"Name\": \"{s}\",\n", .{name}) catch {};
    } else {
        stdout.writeAll("  \"Name\": null,\n") catch {};
    }

    // StartedAt (optional)
    if (info.started_at) |t| {
        stdout.print("  \"StartedAt\": {d},\n", .{t}) catch {};
    } else {
        stdout.writeAll("  \"StartedAt\": null,\n") catch {};
    }

    // FinishedAt (optional)
    if (info.finished_at) |t| {
        stdout.print("  \"FinishedAt\": {d},\n", .{t}) catch {};
    } else {
        stdout.writeAll("  \"FinishedAt\": null,\n") catch {};
    }

    // Pid (optional)
    if (info.pid) |p| {
        stdout.print("  \"Pid\": {d},\n", .{p}) catch {};
    } else {
        stdout.writeAll("  \"Pid\": null,\n") catch {};
    }

    // ExitCode (optional - last field, no trailing comma)
    if (info.exit_code) |e| {
        stdout.print("  \"ExitCode\": {d}\n", .{e}) catch {};
    } else {
        stdout.writeAll("  \"ExitCode\": null\n") catch {};
    }

    stdout.writeAll("}\n") catch {};
    stdout.flush() catch {};
    return 0;
}
