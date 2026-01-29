//! Exec command module with platform-specific implementations.

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("../../../root.zig");

// Platform-specific implementations
const platform_impl = switch (builtin.os.tag) {
    .windows => @import("windows.zig"),
    .macos => @import("macos.zig"),
    .linux => @import("linux.zig"),
    else => struct {
        pub fn execContainer(_: std.mem.Allocator, _: isolazi.cli.ExecCommand, _: anytype, _: anytype) !u8 {
            return 1; // Not implemented on this platform
        }
    },
};

pub const execContainer = platform_impl.execContainer;
