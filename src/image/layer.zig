//! OCI Image Layer Extraction
//!
//! Handles extracting tar.gz layers from OCI images to create a rootfs.
//! Layers are applied in order, with later layers overwriting earlier ones.
//!
//! OCI layers are gzipped tar archives. Each layer can:
//! - Add new files
//! - Modify existing files
//! - Delete files (via whiteout files: .wh.<filename>)

const std = @import("std");
const builtin = @import("builtin");

pub const ExtractionError = error{
    InvalidArchive,
    DecompressionFailed,
    FileSystemError,
    WhiteoutError,
    OutOfMemory,
    PathTooLong,
    AccessDenied,
    FileNotFound,
};

/// Extract a gzipped tar layer to the target directory
/// On Windows, uses WSL tar command for extraction
/// On Linux, uses native tar command
pub fn extractLayer(
    allocator: std.mem.Allocator,
    layer_path: []const u8,
    target_dir: []const u8,
    progress_callback: ?*const fn (files_extracted: u64) void,
) !u64 {
    _ = progress_callback;

    // Create target directory if it doesn't exist
    std.fs.cwd().makePath(target_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return ExtractionError.FileSystemError,
    };

    if (builtin.os.tag == .windows) {
        // On Windows, use WSL tar to extract
        return extractLayerWindows(allocator, layer_path, target_dir);
    } else {
        // On Linux, use native tar
        return extractLayerLinux(allocator, layer_path, target_dir);
    }
}

/// Extract layer using WSL on Windows
fn extractLayerWindows(allocator: std.mem.Allocator, layer_path: []const u8, target_dir: []const u8) !u64 {
    // Convert Windows paths to WSL paths
    const wsl_layer = try windowsToWslPath(allocator, layer_path);
    defer allocator.free(wsl_layer);

    const wsl_target = try windowsToWslPath(allocator, target_dir);
    defer allocator.free(wsl_target);

    // Use WSL tar to extract
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "wsl",
            "-u",
            "root",
            "--",
            "tar",
            "-xzf",
            wsl_layer,
            "-C",
            wsl_target,
            "--no-same-owner",
        },
    }) catch return ExtractionError.DecompressionFailed;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return ExtractionError.DecompressionFailed;
    }

    return 1; // Return 1 as we extracted the layer
}

/// Extract layer using native tar on Linux
fn extractLayerLinux(allocator: std.mem.Allocator, layer_path: []const u8, target_dir: []const u8) !u64 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "tar",
            "-xzf",
            layer_path,
            "-C",
            target_dir,
            "--no-same-owner",
        },
    }) catch return ExtractionError.DecompressionFailed;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return ExtractionError.DecompressionFailed;
    }

    return 1;
}

/// Convert Windows path to WSL path
fn windowsToWslPath(allocator: std.mem.Allocator, win_path: []const u8) ![]u8 {
    // Convert C:\path\to\file to /mnt/c/path/to/file
    if (win_path.len < 2 or win_path[1] != ':') {
        return allocator.dupe(u8, win_path);
    }

    const drive_letter = std.ascii.toLower(win_path[0]);
    const rest = if (win_path.len > 2) win_path[2..] else "";

    // Convert backslashes to forward slashes
    var result = try allocator.alloc(u8, 6 + rest.len); // "/mnt/c" + rest
    result[0] = '/';
    result[1] = 'm';
    result[2] = 'n';
    result[3] = 't';
    result[4] = '/';
    result[5] = drive_letter;

    for (rest, 0..) |c, i| {
        result[6 + i] = if (c == '\\') '/' else c;
    }

    return result;
}

/// Extract multiple layers in order to create a rootfs
pub fn extractLayers(
    allocator: std.mem.Allocator,
    layer_paths: []const []const u8,
    target_dir: []const u8,
    progress_callback: ?*const fn (layer_index: usize, total_layers: usize) void,
) !u64 {
    var total_files: u64 = 0;

    for (layer_paths, 0..) |layer_path, i| {
        if (progress_callback) |cb| {
            cb(i, layer_paths.len);
        }

        const files = try extractLayer(allocator, layer_path, target_dir, null);
        total_files += files;
    }

    return total_files;
}

/// Verify a layer file exists and is readable
pub fn verifyLayer(layer_path: []const u8) bool {
    std.fs.cwd().access(layer_path, .{}) catch return false;
    return true;
}

// =============================================================================
// Tests
// =============================================================================

test "windowsToWslPath" {
    const allocator = std.testing.allocator;

    {
        const result = try windowsToWslPath(allocator, "C:\\Users\\test\\file.txt");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/mnt/c/Users/test/file.txt", result);
    }

    {
        const result = try windowsToWslPath(allocator, "D:\\");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/mnt/d/", result);
    }
}
