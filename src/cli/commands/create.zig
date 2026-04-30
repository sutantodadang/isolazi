//! Create Command Handler
//!
//! Creates a new container from an image without starting it.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Create a container
///
/// Returns 0 on success, exit code on failure.
pub fn createContainer(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi create [--name NAME] <image> [command...]\n");
        try stderr.flush();
        return 1;
    }

    // Parse arguments
    var name: ?[]const u8 = null;
    var image_idx: usize = 2;
    var arg_idx: usize = 2;

    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];
        if (std.mem.eql(u8, arg, "--name")) {
            arg_idx += 1;
            if (arg_idx >= args.len) {
                try stderr.writeAll("Error: --name requires a value\n");
                try stderr.flush();
                return 1;
            }
            name = args[arg_idx];
        } else if (arg.len > 0 and arg[0] != '-') {
            image_idx = arg_idx;
            break;
        }
    }

    if (image_idx >= args.len) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.flush();
        return 1;
    }

    const image_name = args[image_idx];

    // Collect command
    var command_buf: [1024]u8 = undefined;
    var command_len: usize = 0;
    if (args.len > image_idx + 1) {
        for (args[image_idx + 1 ..]) |arg| {
            if (command_len > 0) {
                command_buf[command_len] = ' ';
                command_len += 1;
            }
            const copy_len = @min(arg.len, command_buf.len - command_len);
            @memcpy(command_buf[command_len .. command_len + copy_len], arg[0..copy_len]);
            command_len += copy_len;
        }
    } else {
        const default_cmd = "/bin/sh";
        @memcpy(command_buf[0..default_cmd.len], default_cmd);
        command_len = default_cmd.len;
    }

    // Initialize image cache and pull if needed
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    const ref = isolazi.image.reference.parse(image_name) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{image_name});
        try stderr.flush();
        return 1;
    };

    const has_image = cache.hasImage(&ref) catch false;
    if (!has_image) {
        try stdout.print("Unable to find image '{s}' locally, pulling...\n", .{image_name});
        try stdout.flush();

        _ = isolazi.image.pullImage(allocator, image_name, &cache, null, null) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
    }

    // Create container
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const container_id = manager.createContainer(image_name, command_buf[0..command_len], name, .no) catch |err| {
        try stderr.print("Error: Failed to create container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    try stdout.print("{s}\n", .{container_id});
    try stdout.flush();
    return 0;
}
