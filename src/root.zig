//! Isolazi - Minimal Container Runtime
//!
//! A CLI-driven container runtime written in Zig, inspired by Docker, Podman,
//! and OCI runtimes (runc, crun, youki).
//!
//! ## Features
//! - Process isolation using Linux namespaces (PID, mount, UTS, IPC)
//! - Filesystem isolation using pivot_root or chroot
//! - Bind mount support
//! - Simple CLI interface
//!
//! ## Usage
//! ```
//! isolazi run <rootfs> <command> [args...]
//! ```
//!
//! ## Example
//! ```
//! # Create a minimal rootfs (e.g., using debootstrap or alpine-minirootfs)
//! # Then run:
//! sudo isolazi run /path/to/rootfs /bin/sh
//! ```
//!
//! ## Requirements
//! - Linux kernel with namespace support
//! - Root privileges (CAP_SYS_ADMIN)
//!
//! ## Security Notes
//! This is an educational implementation. For production use, consider:
//! - User namespace support (rootless containers)
//! - Seccomp filters
//! - AppArmor/SELinux profiles
//! - Proper cgroup limits

const std = @import("std");
const builtin = @import("builtin");

// Import all modules
// Linux-specific modules (only compiled on Linux)
pub const linux = if (builtin.os.tag == .linux) @import("linux/mod.zig") else struct {};
pub const fs = if (builtin.os.tag == .linux) @import("fs/mod.zig") else struct {};
pub const runtime = if (builtin.os.tag == .linux) @import("runtime/mod.zig") else struct {};

// Cross-platform modules
pub const config = @import("config/mod.zig");
pub const cli = @import("cli/mod.zig");
pub const image = @import("image/mod.zig");
pub const container = @import("container/mod.zig");

// Windows-specific modules (WSL backend)
pub const windows = if (builtin.os.tag == .windows) @import("windows/mod.zig") else struct {};

// macOS-specific modules (Apple Virtualization backend)
pub const macos = if (builtin.os.tag == .macos) @import("macos/mod.zig") else struct {};

/// Check if we're running on Linux
pub fn isLinux() bool {
    return builtin.os.tag == .linux;
}

/// Check if we have Windows (for future Windows Container support)
pub fn isWindows() bool {
    return builtin.os.tag == .windows;
}

/// Check if we're running on macOS
pub fn isMacOS() bool {
    return builtin.os.tag == .macos;
}

// Re-export commonly used types
pub const Config = config.Config;
pub const Namespaces = config.Namespaces;

// Re-export Linux-only types when on Linux
pub const Runtime = if (builtin.os.tag == .linux) runtime.Runtime else void;
pub const RunResult = if (builtin.os.tag == .linux) runtime.RunResult else void;

test {
    // Import all test blocks from submodules
    std.testing.refAllDecls(@This());
}
