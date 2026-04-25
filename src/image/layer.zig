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

    const list_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "tar", "-tzf", wsl_layer },
    }) catch return ExtractionError.InvalidArchive;
    defer allocator.free(list_result.stdout);
    defer allocator.free(list_result.stderr);

    if (list_result.term.Exited != 0) {
        return ExtractionError.InvalidArchive;
    }

    try validateTarListing(list_result.stdout);
    try processOpaqueWhiteoutsFromListing(allocator, target_dir, list_result.stdout);

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

    // Process OCI whiteouts (using the same logic, but we need to convert paths)
    try processWhiteouts(allocator, target_dir);

    return 1; // Return 1 as we extracted the layer
}

/// Extract layer using native tar on Linux
fn extractLayerLinux(allocator: std.mem.Allocator, layer_path: []const u8, target_dir: []const u8) !u64 {
    const list_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "tar", "-tzf", layer_path },
    }) catch return ExtractionError.InvalidArchive;
    defer allocator.free(list_result.stdout);
    defer allocator.free(list_result.stderr);

    if (list_result.term.Exited != 0) {
        return ExtractionError.InvalidArchive;
    }

    try validateTarListing(list_result.stdout);
    try processOpaqueWhiteoutsFromListing(allocator, target_dir, list_result.stdout);

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

    // Process OCI whiteouts
    try processWhiteouts(allocator, target_dir);

    return 1;
}

fn validateTarListing(listing: []const u8) !void {
    var iter = std.mem.tokenizeScalar(u8, listing, '\n');
    while (iter.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\r\n");
        if (entry.len == 0) continue;
        if (!isSafeArchivePath(entry)) {
            return ExtractionError.InvalidArchive;
        }
    }
}

fn isSafeArchivePath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/' or path[0] == '\\') return false;
    if (path.len >= 2 and path[1] == ':') return false;

    var components = std.mem.tokenizeAny(u8, path, "/\\");
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    return true;
}

fn processOpaqueWhiteoutsFromListing(allocator: std.mem.Allocator, target_dir: []const u8, listing: []const u8) !void {
    var iter = std.mem.tokenizeScalar(u8, listing, '\n');
    while (iter.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\r\n");
        if (entry.len == 0) continue;

        if (std.mem.eql(u8, tarBasename(entry), ".wh..wh..opq")) {
            const rel_dir = tarDirname(entry);
            const opaque_dir = try pathFromArchivePath(allocator, target_dir, rel_dir);
            defer allocator.free(opaque_dir);
            try deleteDirectoryContents(allocator, opaque_dir);
        }
    }
}

fn tarBasename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

fn tarDirname(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx == 0) return "";
        return path[0..idx];
    }
    return "";
}

fn pathFromArchivePath(allocator: std.mem.Allocator, target_dir: []const u8, archive_path: []const u8) ![]u8 {
    if (archive_path.len == 0 or std.mem.eql(u8, archive_path, ".")) {
        return allocator.dupe(u8, target_dir);
    }

    const native_path = try allocator.alloc(u8, archive_path.len);
    defer allocator.free(native_path);
    for (archive_path, 0..) |c, i| {
        native_path[i] = if (c == '/' or c == '\\') std.fs.path.sep else c;
    }

    return std.fs.path.join(allocator, &[_][]const u8{ target_dir, native_path });
}

fn deleteDirectoryContents(allocator: std.mem.Allocator, dir_path: []const u8) !void {
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return ExtractionError.FileSystemError,
    };
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return ExtractionError.FileSystemError) |entry| {
        const child_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        defer allocator.free(child_path);

        switch (entry.kind) {
            .directory => std.fs.cwd().deleteTree(child_path) catch |err| switch (err) {
                else => return ExtractionError.FileSystemError,
            },
            else => std.fs.cwd().deleteFile(child_path) catch |err| switch (err) {
                error.IsDir => std.fs.cwd().deleteTree(child_path) catch return ExtractionError.FileSystemError,
                else => return ExtractionError.FileSystemError,
            },
        }
    }
}

/// Handle OCI whiteout files (.wh.<filename>)
fn processWhiteouts(allocator: std.mem.Allocator, target_dir: []const u8) !void {
    // Find all whiteout files
    var result: std.process.Child.RunResult = undefined;

    if (builtin.os.tag == .windows) {
        const wsl_target = try windowsToWslPath(allocator, target_dir);
        defer allocator.free(wsl_target);

        result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "find", wsl_target, "-name", ".wh.*" },
        }) catch return;
    } else {
        result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "find", target_dir, "-name", ".wh.*" },
        }) catch return;
    }
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var iter = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    while (iter.next()) |wh_path| {
        const path = std.mem.trim(u8, wh_path, " \t\r\n");
        if (path.len == 0) continue;

        const basename = if (builtin.os.tag == .windows) tarBasename(path) else std.fs.path.basename(path);
        const dirname = if (builtin.os.tag == .windows) tarDirname(path) else (std.fs.path.dirname(path) orelse continue);

        if (std.mem.eql(u8, basename, ".wh..wh..opq")) {
            // Opaque directory contents were removed before extraction.
            if (builtin.os.tag == .windows) {
                if (std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "rm", "-f", path },
                })) |res| {
                    allocator.free(res.stdout);
                    allocator.free(res.stderr);
                } else |_| {}
            } else {
                std.fs.deleteFileAbsolute(path) catch {};
            }
        } else if (std.mem.startsWith(u8, basename, ".wh.")) {
            // Regular whiteout: remove the masked file
            const masked_name = basename[4..];
            const masked_path = try std.fs.path.join(allocator, &[_][]const u8{ dirname, masked_name });
            defer allocator.free(masked_path);

            // Recursively delete the masked file or directory
            if (builtin.os.tag == .windows) {
                const wsl_masked_path = try joinPosixPath(allocator, dirname, masked_name);
                defer allocator.free(wsl_masked_path);
                if (std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "rm", "-rf", wsl_masked_path },
                })) |res| {
                    allocator.free(res.stdout);
                    allocator.free(res.stderr);
                } else |_| {}
                // Also remove the whiteout marker itself via WSL
                if (std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "rm", "-f", path },
                })) |res| {
                    allocator.free(res.stdout);
                    allocator.free(res.stderr);
                } else |_| {}
            } else {
                const result_rm = std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &[_][]const u8{ "rm", "-rf", masked_path },
                }) catch null;
                if (result_rm) |r| {
                    allocator.free(r.stdout);
                    allocator.free(r.stderr);
                }
                // Remove the whiteout marker itself
                std.fs.deleteFileAbsolute(path) catch {};
            }
        }
    }
}

fn joinPosixPath(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
    if (dir.len == 0) return allocator.dupe(u8, name);
    if (dir[dir.len - 1] == '/') {
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ dir, name });
    }
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, name });
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

test "reject unsafe tar paths" {
    try std.testing.expect(isSafeArchivePath("usr/bin/sh"));
    try std.testing.expect(isSafeArchivePath("./usr/bin/sh"));
    try std.testing.expect(!isSafeArchivePath("/etc/passwd"));
    try std.testing.expect(!isSafeArchivePath("../etc/passwd"));
    try std.testing.expect(!isSafeArchivePath("usr/../../etc/passwd"));
    try std.testing.expect(!isSafeArchivePath("C:\\Windows\\System32"));
}
