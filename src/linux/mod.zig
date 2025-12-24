//! Linux-specific functionality for container isolation.
//!
//! This module provides:
//! - Direct syscall wrappers (syscalls.zig)
//! - Namespace management helpers
//! - Constants and flags for Linux primitives
//!
//! PLATFORM: This module is Linux-only. Windows support requires
//! different isolation mechanisms (Windows Containers, Hyper-V).

pub const syscalls = @import("syscalls.zig");

// Re-export commonly used items
pub const CloneFlags = syscalls.CloneFlags;
pub const MountFlags = syscalls.MountFlags;
pub const SyscallError = syscalls.SyscallError;

pub const unshare = syscalls.unshare;
pub const mount = syscalls.mount;
pub const umount = syscalls.umount;
pub const pivotRoot = syscalls.pivotRoot;
pub const chroot = syscalls.chroot;
pub const setHostname = syscalls.setHostname;
pub const execve = syscalls.execve;
pub const fork = syscalls.fork;
pub const waitpid = syscalls.waitpid;
pub const chdir = syscalls.chdir;
pub const mkdir = syscalls.mkdir;
pub const rmdir = syscalls.rmdir;
pub const close = syscalls.close;
