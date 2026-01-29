//! Prune Command Handler
//!
//! Cleanup unused containers and images.
//! Consolidated from platform-specific implementations.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Helper function to prune only images (when container manager fails)
fn pruneImagesOnly(
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
    force: bool,
) u8 {
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Warning: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 0;
    };
    defer cache.deinit();

    const rootfs_removed: u64 = if (force) cache.removeAllContainers() catch 0 else 0;
    const images_removed = cache.removeAllImages() catch 0;

    stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed}) catch {};
    stdout.print("Deleted {d} image blobs\n", .{images_removed}) catch {};
    stdout.writeAll("Prune complete.\n") catch {};
    stdout.flush() catch {};
    return 0;
}

/// Prune all stopped containers and unused images
///
/// Returns 0 on success, 1 on error.
pub fn prune(
    allocator: std.mem.Allocator,
    prune_cmd: isolazi.cli.PruneCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    const force = prune_cmd.force;

    if (force) {
        stdout.writeAll("Pruning ALL containers (force) and unused images...\n") catch {};
    } else {
        stdout.writeAll("Pruning stopped containers and unused images...\n") catch {};
    }
    stdout.flush() catch {};

    var containers_removed: u64 = 0;
    var images_removed: u64 = 0;
    var rootfs_removed: u64 = 0;

    // Prune containers via ContainerManager
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        stderr.print("Warning: Failed to initialize container manager: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return pruneImagesOnly(allocator, stdout, stderr, force);
    };
    defer manager.deinit();
    containers_removed = manager.pruneContainers(force) catch 0;
    rootfs_removed = containers_removed;

    // Prune images via ImageCache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Warning: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        stdout.print("Deleted {d} containers\n", .{containers_removed}) catch {};
        stdout.flush() catch {};
        return 0;
    };
    defer cache.deinit();

    // Remove all images
    images_removed = cache.removeAllImages() catch 0;

    stdout.print("Deleted {d} containers\n", .{containers_removed}) catch {};
    stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed}) catch {};
    stdout.print("Deleted {d} image blobs\n", .{images_removed}) catch {};
    stdout.writeAll("Prune complete.\n") catch {};
    stdout.flush() catch {};

    return 0;
}
