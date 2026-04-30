//! Pull Command Handler
//!
//! Shared image pull logic used by all platforms (Windows, Linux, macOS).
//! Consolidates previously duplicated code from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Progress callback for pull stages
pub const ProgressCallback = *const fn (stage: isolazi.image.PullStage, detail: []const u8) void;

/// Progress callback for download progress
pub const DownloadProgressCallback = *const fn (progress: isolazi.image.DownloadProgress) void;

/// Default progress callback that prints stages to stderr
pub fn defaultProgressCallback(stage: isolazi.image.PullStage, detail: []const u8) void {
    const stage_str = switch (stage) {
        .cached => "Cached",
        .authenticating => "Authenticating",
        .fetching_manifest => "Fetching manifest",
        .downloading_layer => "Downloading",
        .downloading_progress => "Progress",
        .layer_cached => "Layer cached",
        .extracting => "Extracting",
        .complete => "Complete",
    };
    std.debug.print("  {s}: {s}\n", .{ stage_str, detail });
}

/// Default download progress callback with progress bar
pub fn defaultDownloadProgressCallback(progress: isolazi.image.DownloadProgress) void {
    var size_buf: [32]u8 = undefined;
    var total_buf: [32]u8 = undefined;
    var speed_buf: [32]u8 = undefined;

    const downloaded_str = isolazi.image.DownloadProgress.formatBytes(progress.bytes_downloaded, &size_buf);
    const total_str = if (progress.total_bytes > 0)
        isolazi.image.DownloadProgress.formatBytes(progress.total_bytes, &total_buf)
    else
        "???";
    const speed_str = isolazi.image.DownloadProgress.formatBytes(progress.bytes_per_second, &speed_buf);

    const percent = progress.percentComplete();
    const bar_width: usize = 30;
    const filled = (percent * bar_width) / 100;

    // Build progress bar
    var bar: [32]u8 = undefined;
    for (0..bar_width) |i| {
        bar[i] = if (i < filled) '=' else ' ';
    }

    // Print with carriage return for in-place update
    std.debug.print("\r  Layer {d}/{d}: [{s}] {d}% {s}/{s} @ {s}/s   ", .{
        progress.layer_index,
        progress.total_layers,
        bar[0..bar_width],
        percent,
        downloaded_str,
        total_str,
        speed_str,
    });

    // Print newline when complete
    if (percent == 100) {
        std.debug.print("\n", .{});
    }
}

/// Pull an image from a registry
///
/// This is the unified pull function used by all platforms.
/// Returns 0 on success, 1 on error.
pub fn pullImage(
    allocator: std.mem.Allocator,
    image_name: []const u8,
    stdout: anytype,
    stderr: anytype,
    progress_cb: ?ProgressCallback,
    download_progress_cb: ?DownloadProgressCallback,
) u8 {
    // Validate image name
    if (image_name.len == 0) {
        stderr.writeAll("Error: Missing image name\n") catch {};
        stderr.writeAll("Usage: isolazi pull <image>\n") catch {};
        stderr.flush() catch {};
        return 1;
    }

    stdout.print("Pulling {s}...\n", .{image_name}) catch {};
    stdout.flush() catch {};

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer cache.deinit();

    // Use provided callbacks or defaults
    const actual_progress_cb = progress_cb orelse &defaultProgressCallback;
    const actual_download_cb = download_progress_cb orelse &defaultDownloadProgressCallback;

    // Pull the image
    const ref = isolazi.image.pullImage(
        allocator,
        image_name,
        &cache,
        actual_progress_cb,
        actual_download_cb,
    ) catch |err| {
        stderr.print("Error: Failed to pull image: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    _ = ref;

    stdout.print("Successfully pulled {s}\n", .{image_name}) catch {};
    stdout.flush() catch {};
    return 0;
}

/// Pull image from command-line args
///
/// Parses args and calls pullImage.
/// args should be the full argv (including program name).
pub fn pullFromArgs(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) u8 {
    if (args.len < 3) {
        stderr.writeAll("Error: Missing image name\n") catch {};
        stderr.writeAll("Usage: isolazi pull <image>\n") catch {};
        stderr.flush() catch {};
        return 1;
    }

    const image_name = args[2];
    return pullImage(allocator, image_name, stdout, stderr, null, null);
}
