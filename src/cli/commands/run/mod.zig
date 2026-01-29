//! Run command module.
//!
//! Platform-agnostic entry point for the `run` command.
//! Re-exports platform-specific implementations.

const std = @import("std");
const builtin = @import("builtin");

// Re-export shared types and utilities from parent run.zig
const run_base = @import("../run.zig");
pub const RunOptions = run_base.RunOptions;
pub const parseRunOptions = run_base.parseRunOptions;
pub const printUsage = run_base.printUsage;
pub const quoteArg = run_base.quoteArg;

// Platform-specific implementations
pub const platform = switch (builtin.os.tag) {
    .windows => @import("windows.zig"),
    .macos => @import("macos.zig"),
    .linux => @import("linux.zig"),
    else => struct {
        pub fn runContainer(_: std.mem.Allocator, _: []const []const u8, _: anytype, _: anytype) !u8 {
            return 1; // Not implemented on this platform
        }
    },
};
