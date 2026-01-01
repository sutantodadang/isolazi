//! Windows backend for Isolazi using WSL2.
//!
//! On Windows, container operations are delegated to WSL2 (Windows Subsystem for Linux).
//! This is the same approach used by Podman and Docker Desktop.
//!
//! Architecture:
//! ```
//! Windows Host                         WSL2 Linux VM
//! ────────────                         ─────────────
//!
//! isolazi.exe ──────────────────────► wsl isolazi run ...
//!     │                                    │
//!     │ (spawn wsl.exe)                    │ (native Linux execution)
//!     │                                    │
//!     └── wait for exit ◄──────────────────┘
//! ```
//!
//! Resource Limits (cgroup v2):
//! Resource limit flags (--memory, --cpus, etc.) are passed through to the
//! Linux isolazi binary running inside WSL2. The Linux binary handles cgroup
//! setup natively via /sys/fs/cgroup (cgroup v2).
//!
//! Requirements:
//! - WSL2 installed and configured
//! - A Linux distribution installed in WSL
//! - Isolazi Linux binary installed in WSL (or built from source)

const std = @import("std");
const builtin = @import("builtin");

pub const WslError = error{
    WslNotAvailable,
    WslExecutionFailed,
    DistroNotFound,
    CommandFailed,
    OutOfMemory,
};

/// WSL backend configuration
pub const WslConfig = struct {
    /// WSL distribution to use (null = default)
    distro: ?[]const u8 = null,
    /// Path to isolazi binary in WSL (null = assume in PATH)
    isolazi_path: ?[]const u8 = null,
    /// Run as root in WSL
    run_as_root: bool = true,
};

/// Check if WSL is available on this system.
pub fn isWslAvailable(allocator: std.mem.Allocator) bool {
    // Try to run 'wsl --status' to check if WSL is installed
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "wsl", "--status" },
    }) catch return false;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return result.term.Exited == 0;
}

/// Get list of installed WSL distributions.
pub fn listDistros(allocator: std.mem.Allocator) ![][]const u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "wsl", "--list", "--quiet" },
    });

    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        allocator.free(result.stdout);
        return WslError.WslNotAvailable;
    }

    // Parse the output (one distro per line)
    var distros: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (distros.items) |d| allocator.free(d);
        distros.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        // Skip empty lines and trim whitespace
        const trimmed = std.mem.trim(u8, line, " \t\r\n\x00");
        if (trimmed.len > 0) {
            const copy = try allocator.dupe(u8, trimmed);
            try distros.append(allocator, copy);
        }
    }

    allocator.free(result.stdout);
    return try distros.toOwnedSlice(allocator);
}

/// Execute a command in WSL.
pub fn execInWsl(
    allocator: std.mem.Allocator,
    config: WslConfig,
    args: []const []const u8,
) !u8 {
    // Build the WSL command
    var wsl_args: std.ArrayList([]const u8) = .empty;
    defer wsl_args.deinit(allocator);

    try wsl_args.append(allocator, "wsl");

    // Add distribution flag if specified
    if (config.distro) |distro| {
        try wsl_args.append(allocator, "-d");
        try wsl_args.append(allocator, distro);
    }

    // Run as root if requested
    if (config.run_as_root) {
        try wsl_args.append(allocator, "-u");
        try wsl_args.append(allocator, "root");
    }

    // Add the command to execute
    if (config.isolazi_path) |path| {
        try wsl_args.append(allocator, path);
    } else {
        try wsl_args.append(allocator, "isolazi");
    }

    // Add all the original arguments
    for (args) |arg| {
        try wsl_args.append(allocator, arg);
    }

    // Execute WSL
    var child = std.process.Child.init(wsl_args.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
}

/// Run Isolazi command through WSL.
/// This is the main entry point for Windows users.
pub fn runThroughWsl(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    config: WslConfig,
) !u8 {
    // Check if WSL is available
    if (!isWslAvailable(allocator)) {
        return WslError.WslNotAvailable;
    }

    // Execute the command in WSL
    return execInWsl(allocator, config, args);
}

/// Convert a Windows path to WSL path.
/// Example: C:\Users\foo\rootfs -> /mnt/c/Users/foo/rootfs
pub fn windowsToWslPath(allocator: std.mem.Allocator, windows_path: []const u8) ![]u8 {
    if (windows_path.len < 2) {
        return allocator.dupe(u8, windows_path);
    }

    // Check for drive letter pattern (e.g., C:\ or C:/)
    if (windows_path.len >= 2 and windows_path[1] == ':') {
        const drive_letter = std.ascii.toLower(windows_path[0]);

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Add /mnt/<drive>/
        try result.appendSlice(allocator, "/mnt/");
        try result.append(allocator, drive_letter);

        // Add rest of path, converting backslashes
        const rest = if (windows_path.len > 2) windows_path[2..] else "";
        for (rest) |c| {
            if (c == '\\') {
                try result.append(allocator, '/');
            } else {
                try result.append(allocator, c);
            }
        }

        return try result.toOwnedSlice(allocator);
    }

    // Not a Windows absolute path, just convert backslashes
    const result = try allocator.dupe(u8, windows_path);
    for (result) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    return result;
}

/// Convert a WSL path to Windows path.
/// Example: /mnt/c/Users/foo/rootfs -> C:\Users\foo\rootfs
pub fn wslToWindowsPath(allocator: std.mem.Allocator, wsl_path: []const u8) ![]u8 {
    // Check for /mnt/<drive>/ pattern
    if (wsl_path.len >= 6 and std.mem.startsWith(u8, wsl_path, "/mnt/")) {
        const drive_letter = std.ascii.toUpper(wsl_path[5]);

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Add drive letter
        try result.append(allocator, drive_letter);
        try result.appendSlice(allocator, ":");

        // Add rest of path, converting forward slashes
        const rest = if (wsl_path.len > 6) wsl_path[6..] else "";
        for (rest) |c| {
            if (c == '/') {
                try result.append(allocator, '\\');
            } else {
                try result.append(allocator, c);
            }
        }

        if (result.items.len == 2) {
            try result.append(allocator, '\\');
        }

        return try result.toOwnedSlice(allocator);
    }

    // Not a WSL mount path, return as-is
    return allocator.dupe(u8, wsl_path);
}

// =============================================================================
// Tests
// =============================================================================

test "windowsToWslPath converts drive letters" {
    const allocator = std.testing.allocator;

    const path1 = try windowsToWslPath(allocator, "C:\\Users\\test");
    defer allocator.free(path1);
    try std.testing.expectEqualStrings("/mnt/c/Users/test", path1);

    const path2 = try windowsToWslPath(allocator, "D:\\data\\rootfs");
    defer allocator.free(path2);
    try std.testing.expectEqualStrings("/mnt/d/data/rootfs", path2);
}

test "wslToWindowsPath converts mount paths" {
    const allocator = std.testing.allocator;

    const path1 = try wslToWindowsPath(allocator, "/mnt/c/Users/test");
    defer allocator.free(path1);
    try std.testing.expectEqualStrings("C:\\Users\\test", path1);

    const path2 = try wslToWindowsPath(allocator, "/mnt/d/data/rootfs");
    defer allocator.free(path2);
    try std.testing.expectEqualStrings("D:\\data\\rootfs", path2);
}
