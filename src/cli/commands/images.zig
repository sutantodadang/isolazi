//! Images Command Handler
//!
//! Shared image listing logic used by all platforms (Windows, Linux, macOS).
//! Consolidates previously duplicated code from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// List all cached images
///
/// This is the unified list function used by all platforms.
/// Returns 0 on success, 1 on error.
pub fn listImages(
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer cache.deinit();

    // Get list of images
    const images = cache.listImages(allocator) catch |err| {
        stderr.print("Error: Failed to list images: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer {
        for (images) |*img| {
            @constCast(img).deinit(allocator);
        }
        allocator.free(images);
    }

    // Print header
    stdout.writeAll("REPOSITORY                          TAG       \n") catch {};
    stdout.writeAll("--------------------------------------------\n") catch {};

    // Print images
    if (images.len == 0) {
        stdout.writeAll("(no images)\n") catch {};
    } else {
        for (images) |img| {
            stdout.print("{s}/{s}                  {s}\n", .{
                img.registry,
                img.repository,
                img.tag,
            }) catch {};
        }
    }

    // Print stats
    const stats = cache.getStats() catch |err| {
        stderr.print("Warning: Could not get cache stats: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        stdout.flush() catch {};
        return 0;
    };

    stdout.print("\nTotal: {d} images, {d} blobs, {d:.2} MB\n", .{
        images.len,
        stats.total_blobs,
        @as(f64, @floatFromInt(stats.total_size)) / 1024.0 / 1024.0,
    }) catch {};

    stdout.flush() catch {};
    return 0;
}
