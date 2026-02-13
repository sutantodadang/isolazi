//! Update Command Handler
//!
//! Self-update functionality for isolazi.
//! Downloads and installs the latest version.

const std = @import("std");
const builtin = @import("builtin");

/// Update isolazi to the latest version
///
/// Returns 0 on success, 1 on error.
pub fn selfUpdate(
    allocator: std.mem.Allocator,
    _: []const []const u8, // args unused
    stdout: anytype,
    _: anytype, // stderr unused
) u8 {
    stdout.writeAll("Updating isolazi to the latest version...\n") catch {};
    stdout.flush() catch {};

    if (builtin.os.tag == .windows) {
        // On Windows, the running executable is locked and cannot be overwritten.
        // We must rename it to .old before running the update script.
        const self_exe = std.fs.selfExePathAlloc(allocator) catch |err| {
            std.debug.print("Error getting self path: {}\n", .{err});
            return 1;
        };
        defer allocator.free(self_exe);

        const old_exe = std.fmt.allocPrint(allocator, "{s}.old", .{self_exe}) catch |err| {
            std.debug.print("Error creating backup path: {}\n", .{err});
            return 1;
        };
        defer allocator.free(old_exe);

        // Remove existing .old file if it exists
        std.fs.deleteFileAbsolute(old_exe) catch |err| {
            if (err != error.FileNotFound) {
                // If we can't delete the old file, we probably can't rename the current one to it
                std.debug.print("Error removing old executable backup: {}\n", .{err});
                // We'll try to proceed anyway, maybe the rename will overwrite or fail with a clear error
            }
        };

        // Rename current executable to .old
        std.fs.renameAbsolute(self_exe, old_exe) catch |err| {
            std.debug.print("Error renaming current executable: {}\n", .{err});
            return 1;
        };

        // On Windows, use PowerShell to download and run install.ps1
        stdout.writeAll("Running PowerShell install script...\n") catch {};
        stdout.flush() catch {};

        var child = std.process.Child.init(&[_][]const u8{
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "& { iwr -useb https://raw.githubusercontent.com/sutantodadang/isolazi/main/install.ps1 | iex }",
        }, allocator);

        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        _ = child.spawn() catch {
            // If spawning fails, try to rename back
            std.fs.renameAbsolute(old_exe, self_exe) catch {};
            return 1;
        };

        const term = child.wait() catch {
            // If waiting fails, we can't easily restore, but the script might have run
            return 1;
        };

        return switch (term) {
            .Exited => |code| code,
            else => 1,
        };
    } else {
        // On Unix (macOS/Linux), use curl to download and run install.sh
        stdout.writeAll("Downloading and running install script...\n") catch {};
        stdout.flush() catch {};

        var child = std.process.Child.init(&[_][]const u8{
            "bash",
            "-c",
            "curl -fsSL https://raw.githubusercontent.com/sutantodadang/isolazi/main/install.sh | bash",
        }, allocator);

        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        child.spawn() catch return 1;
        const term = child.wait() catch return 1;

        return switch (term) {
            .Exited => |code| code,
            .Signal => |sig| @truncate(128 +% sig),
            else => 1,
        };
    }
}
