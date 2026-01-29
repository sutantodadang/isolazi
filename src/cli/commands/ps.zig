//! PS (Container List) Command Handler
//!
//! Shared container listing logic used by all platforms.
//! Consolidates previously duplicated code from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// List containers
///
/// Returns 0 on success, 1 on error.
pub fn listContainers(
    allocator: std.mem.Allocator,
    ps_cmd: isolazi.cli.PsCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Parse -a/--all flag
    const show_all = ps_cmd.all;

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(show_all) catch |err| {
        stderr.print("Error: Failed to list containers: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer {
        for (containers) |*c| {
            @constCast(c).deinit();
        }
        allocator.free(containers);
    }

    // Print header
    stdout.writeAll("CONTAINER ID   IMAGE                    COMMAND         STATUS\n") catch {};

    if (containers.len == 0) {
        if (!show_all) {
            stdout.writeAll("(no running containers, use -a to show all)\n") catch {};
        } else {
            stdout.writeAll("(no containers)\n") catch {};
        }
    } else {
        for (containers) |c| {
            // Truncate image and command for display
            const image_display = if (c.image.len > 24) c.image[0..24] else c.image;
            const cmd_display = if (c.command.len > 15) c.command[0..15] else c.command;

            stdout.print("{s}   {s: <24} {s: <15} {s}\n", .{
                c.shortId(),
                image_display,
                cmd_display,
                c.state.toString(),
            }) catch {};
        }
    }

    stdout.flush() catch {};
    return 0;
}
