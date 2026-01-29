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

        child.spawn() catch return 1;
        const term = child.wait() catch return 1;
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
