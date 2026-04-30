//! VM Management Command Handler (macOS only)
//!
//! Manages the lightweight Linux VM used for running containers on macOS.
//! Backed by Lima.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../root.zig");

/// Execute VM management commands
pub fn run(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (builtin.os.tag != .macos) {
        try stderr.writeAll("Error: 'vm' command is only available on macOS\n");
        try stderr.flush();
        return 1;
    }

    // args[0] is binary name, args[1] is "vm"
    if (args.len < 3) {
        try stdout.writeAll("VM Management Commands:\n\n");
        try stdout.writeAll("  isolazi vm status   - Show VM status\n");
        try stdout.writeAll("  isolazi vm start    - Start or create the Linux VM\n");
        try stdout.writeAll("  isolazi vm stop     - Stop the Linux VM\n");
        try stdout.writeAll("  isolazi vm ssh      - Open a shell inside the VM\n");
        try stdout.writeAll("  isolazi vm info     - Show VM configuration\n");
        try stdout.flush();
        return 0;
    }

    const subcmd = args[2];
    const macos = isolazi.macos;

    if (std.mem.eql(u8, subcmd, "status")) {
        try stdout.writeAll("VM Status: ");
        if (macos.isVirtualizationAvailable(allocator)) {
            if (macos.virtualization.isLimaInstalled(allocator)) {
                const status = macos.virtualization.checkLimaStatus(allocator);
                switch (status) {
                    .Running => try stdout.writeAll("Running\n"),
                    .Stopped => try stdout.writeAll("Stopped\n"),
                    .NotExists => try stdout.writeAll("Not Created (will be created on first run)\n"),
                    .Unknown => try stdout.writeAll("Unknown\n"),
                }
            } else {
                try stdout.writeAll("Lima not installed (required for VM)\n");
            }
        } else {
            try stdout.writeAll("Virtualization not available on this system\n");
        }
        try stdout.flush();
        return 0;
    }

    if (std.mem.eql(u8, subcmd, "start")) {
        try stdout.writeAll("Ensuring VM is running...\n");
        try stdout.flush();

        macos.virtualization.ensureVMRunning(allocator) catch |err| {
            try stderr.print("Error: Failed to start VM: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.writeAll("VM is ready.\n");
        try stdout.flush();
        return 0;
    }

    if (std.mem.eql(u8, subcmd, "stop")) {
        try stdout.writeAll("Stopping VM...\n");
        try stdout.flush();

        macos.virtualization.stopLimaInstance(allocator) catch |err| {
            try stderr.print("Error: Failed to stop VM: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.writeAll("VM stopped.\n");
        try stdout.flush();
        return 0;
    }

    if (std.mem.eql(u8, subcmd, "ssh")) {
        // exec into shell
        var child = std.process.Child.init(&[_][]const u8{ "limactl", "shell", "isolazi" }, allocator);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        try child.spawn();
        const term = try child.wait();
        return switch (term) {
            .Exited => |code| code,
            else => 1,
        };
    }

    if (std.mem.eql(u8, subcmd, "info")) {
        try stdout.writeAll("VM Configuration:\n");
        try stdout.writeAll("  Hypervisor: Apple Virtualization Framework (via Lima)\n");
        try stdout.writeAll("  OS: Ubuntu 24.04 LTS (Cloud Image)\n");
        try stdout.writeAll("  CPUs: 2\n");
        try stdout.writeAll("  Memory: 2 GiB\n");
        try stdout.writeAll("  Disk: 10 GiB\n");

        const data_dir = macos.virtualization.getDataDir(allocator) catch "unknown";
        defer if (!std.mem.eql(u8, data_dir, "unknown")) allocator.free(data_dir);

        try stdout.print("  Data dir: {s}\n", .{data_dir});
        try stdout.flush();
        return 0;
    }

    try stderr.print("Unknown VM command: {s}\n", .{subcmd});
    try stderr.flush();
    return 1;
}
