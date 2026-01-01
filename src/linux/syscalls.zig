//! Low-level Linux syscall wrappers for container isolation.
//!
//! This module provides direct syscall interfaces for namespace creation,
//! filesystem isolation, and process management. We use direct syscalls
//! rather than libc wrappers for:
//! 1. Full control over flags and behavior
//! 2. Avoiding libc's internal state management issues (especially after clone)
//! 3. Explicit error handling
//!
//! SECURITY: All functions here are inherently unsafe from a security perspective.
//! They manipulate kernel-level isolation primitives. Callers must ensure:
//! - Proper capability checks (CAP_SYS_ADMIN, etc.)
//! - Valid memory regions for all pointers
//! - Correct sequencing of operations

const std = @import("std");
const linux = std.os.linux;
const native_arch = @import("builtin").cpu.arch;

// Get the proper syscall enum type for the current architecture
const SYS = linux.SYS;

/// Clone flags for namespace isolation.
/// Each flag creates a new namespace for the child process.
pub const CloneFlags = struct {
    /// Create new PID namespace (process ID isolation)
    pub const NEWPID: u64 = linux.CLONE.NEWPID;
    /// Create new mount namespace (filesystem isolation)
    pub const NEWNS: u64 = linux.CLONE.NEWNS;
    /// Create new UTS namespace (hostname/domainname isolation)
    pub const NEWUTS: u64 = linux.CLONE.NEWUTS;
    /// Create new IPC namespace (System V IPC isolation)
    pub const NEWIPC: u64 = linux.CLONE.NEWIPC;
    /// Create new network namespace (network isolation) - future use
    pub const NEWNET: u64 = linux.CLONE.NEWNET;
    /// Create new user namespace (UID/GID isolation) - future use
    pub const NEWUSER: u64 = linux.CLONE.NEWUSER;
    /// Create new cgroup namespace - future use
    pub const NEWCGROUP: u64 = linux.CLONE.NEWCGROUP;
};

/// Mount flags for filesystem operations.
pub const MountFlags = struct {
    pub const BIND: u32 = linux.MS.BIND;
    pub const RDONLY: u32 = linux.MS.RDONLY;
    pub const NOSUID: u32 = linux.MS.NOSUID;
    pub const NODEV: u32 = linux.MS.NODEV;
    pub const NOEXEC: u32 = linux.MS.NOEXEC;
    pub const PRIVATE: u32 = linux.MS.PRIVATE;
    pub const REC: u32 = linux.MS.REC;
    pub const REMOUNT: u32 = linux.MS.REMOUNT;
    pub const MOVE: u32 = linux.MS.MOVE;
};

/// Error types for syscall operations.
pub const SyscallError = error{
    PermissionDenied,
    InvalidArgument,
    OutOfMemory,
    ResourceBusy,
    NoSuchFile,
    NotADirectory,
    TooManySymlinks,
    NameTooLong,
    IoError,
    NotSupported,
    Unknown,
};

/// Convert Linux errno to our error type.
fn errnoToError(errno: linux.E) SyscallError {
    return switch (errno) {
        .PERM, .ACCES => SyscallError.PermissionDenied,
        .INVAL => SyscallError.InvalidArgument,
        .NOMEM => SyscallError.OutOfMemory,
        .BUSY => SyscallError.ResourceBusy,
        .NOENT => SyscallError.NoSuchFile,
        .NOTDIR => SyscallError.NotADirectory,
        .LOOP => SyscallError.TooManySymlinks,
        .NAMETOOLONG => SyscallError.NameTooLong,
        .IO => SyscallError.IoError,
        .NOSYS, .OPNOTSUPP => SyscallError.NotSupported,
        else => SyscallError.Unknown,
    };
}

/// Unshare namespaces from the calling process.
///
/// This creates new namespaces for the current process without creating
/// a new child process. Used to isolate the current process.
///
/// SECURITY: Requires CAP_SYS_ADMIN for most namespace types.
/// After unshare(CLONE_NEWPID), the calling process is NOT in the new
/// PID namespace - only its children will be.
///
/// # Arguments
/// * `flags` - Combination of CloneFlags.NEW* constants
///
/// # Example
/// ```zig
/// try unshare(CloneFlags.NEWNS | CloneFlags.NEWUTS);
/// ```
pub fn unshare(flags: u64) SyscallError!void {
    const result = linux.unshare(@intCast(flags));
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Mount a filesystem or perform a bind mount.
///
/// This is a direct wrapper around the mount(2) syscall.
///
/// SECURITY: Requires CAP_SYS_ADMIN in the mount namespace.
/// Bind mounts can expose files across namespace boundaries if not careful.
///
/// # Arguments
/// * `source` - Source path (or filesystem type for virtual filesystems)
/// * `target` - Mount point path
/// * `fstype` - Filesystem type (e.g., "proc", "tmpfs", null for bind mounts)
/// * `flags` - Mount flags (combination of MountFlags.*)
/// * `data` - Filesystem-specific options (usually null)
pub fn mount(
    source: ?[*:0]const u8,
    target: [*:0]const u8,
    fstype: ?[*:0]const u8,
    flags: u32,
    data: ?*const anyopaque,
) SyscallError!void {
    // UNSAFE: Direct syscall with raw pointers.
    // All pointers must be valid, null-terminated C strings.
    const result = linux.mount(source, target, fstype, flags, @intFromPtr(data));
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Unmount a filesystem.
///
/// # Arguments
/// * `target` - Path to unmount
/// * `flags` - Unmount flags (0 for normal unmount)
pub fn umount(target: [*:0]const u8, flags: u32) SyscallError!void {
    const result = linux.umount2(target, flags);
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Change root directory using pivot_root(2).
///
/// This is more secure than chroot because it moves the old root to
/// a known location where it can be unmounted, rather than leaving
/// it accessible.
///
/// SECURITY: Must be called after unshare(CLONE_NEWNS) to avoid
/// affecting other processes. The new_root must be a mount point.
///
/// # Arguments
/// * `new_root` - Path to the new root filesystem
/// * `put_old` - Path (relative to new_root) where old root will be moved
///
/// # Typical usage sequence:
/// 1. unshare(CLONE_NEWNS) - new mount namespace
/// 2. mount(new_root, new_root, MS_BIND) - make it a mount point
/// 3. mkdir put_old directory under new_root
/// 4. pivot_root(new_root, put_old)
/// 5. chdir("/")
/// 6. umount(put_old, MNT_DETACH)
/// 7. rmdir(put_old)
pub fn pivotRoot(new_root: [*:0]const u8, put_old: [*:0]const u8) SyscallError!void {
    // UNSAFE: Direct syscall. Both paths must be valid.
    // new_root must be a mount point, put_old must exist under new_root.
    // Use the architecture-specific syscall enum
    const result = linux.syscall2(.pivot_root, @intFromPtr(new_root), @intFromPtr(put_old));
    if (result > std.math.maxInt(usize) - 4096) {
        // Error: result is negative errno encoded as large usize
        const errno_val: u16 = @truncate(0 -% result);
        return errnoToError(@enumFromInt(errno_val));
    }
}

/// Change root directory using chroot(2).
///
/// Less secure than pivot_root because the old root remains accessible
/// via file descriptors opened before the chroot, and through /proc.
/// Use pivot_root when possible.
///
/// SECURITY: After chroot, always call chdir("/") to prevent escapes.
/// Requires CAP_SYS_CHROOT.
pub fn chroot(path: [*:0]const u8) SyscallError!void {
    // UNSAFE: Direct syscall. Path must be valid directory.
    const result = linux.chroot(path);
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Set hostname in the current UTS namespace.
///
/// Only affects the current UTS namespace (after unshare(CLONE_NEWUTS)).
pub fn setHostname(name: []const u8) SyscallError!void {
    // Use the architecture-specific syscall enum
    const result = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
    if (result > std.math.maxInt(usize) - 4096) {
        const errno_val: u16 = @truncate(0 -% result);
        return errnoToError(@enumFromInt(errno_val));
    }
}

/// Execute a program, replacing the current process.
///
/// This is the final step in container setup - executing the user's command.
///
/// # Arguments
/// * `path` - Path to executable
/// * `argv` - Argument array (first element is conventionally the program name)
/// * `envp` - Environment variables
pub fn execve(
    path: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) SyscallError!noreturn {
    // UNSAFE: Direct syscall that replaces the current process.
    // All pointers must be valid. This never returns on success.
    const result = linux.execve(path, argv, envp);
    // execve only returns on error
    return errnoToError(linux.E.init(result));
}

/// Fork the current process.
///
/// Returns the child PID to the parent, and 0 to the child.
pub fn fork() SyscallError!linux.pid_t {
    const result = linux.fork();
    if (result < 0) {
        return errnoToError(linux.E.init(@intCast(-result)));
    }
    return @intCast(result);
}

/// Wait for a child process to change state.
///
/// # Arguments
/// * `pid` - PID to wait for (-1 for any child)
/// * `options` - Wait options (0 for blocking wait)
///
/// # Returns
/// Tuple of (pid, status)
pub fn waitpid(pid: linux.pid_t, options: u32) SyscallError!struct { pid: linux.pid_t, status: u32 } {
    var status: u32 = 0;
    const result = linux.waitpid(pid, &status, options);
    if (result < 0) {
        return errnoToError(linux.E.init(@intCast(-result)));
    }
    return .{ .pid = @intCast(result), .status = status };
}

/// Change current working directory.
pub fn chdir(path: [*:0]const u8) SyscallError!void {
    const result = linux.chdir(path);
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Create a directory.
pub fn mkdir(path: [*:0]const u8, mode: linux.mode_t) SyscallError!void {
    const result = linux.mkdir(path, mode);
    if (result != 0) {
        const errno = linux.E.init(result);
        // EEXIST is acceptable for directory creation
        if (errno != .EXIST) {
            return errnoToError(errno);
        }
    }
}

/// Remove a directory.
pub fn rmdir(path: [*:0]const u8) SyscallError!void {
    const result = linux.rmdir(path);
    if (result != 0) {
        return errnoToError(linux.E.init(result));
    }
}

/// Close a file descriptor.
pub fn close(fd: i32) void {
    _ = linux.close(fd);
}

/// Namespace file descriptor flags for setns()
pub const NsType = struct {
    /// PID namespace
    pub const CLONE_NEWPID: i32 = @intCast(linux.CLONE.NEWPID);
    /// Mount namespace
    pub const CLONE_NEWNS: i32 = @intCast(linux.CLONE.NEWNS);
    /// UTS namespace (hostname)
    pub const CLONE_NEWUTS: i32 = @intCast(linux.CLONE.NEWUTS);
    /// IPC namespace
    pub const CLONE_NEWIPC: i32 = @intCast(linux.CLONE.NEWIPC);
    /// Network namespace
    pub const CLONE_NEWNET: i32 = @intCast(linux.CLONE.NEWNET);
    /// User namespace
    pub const CLONE_NEWUSER: i32 = @intCast(linux.CLONE.NEWUSER);
    /// Cgroup namespace
    pub const CLONE_NEWCGROUP: i32 = @intCast(linux.CLONE.NEWCGROUP);
};

/// Set namespace using setns(2) syscall.
///
/// Associates the calling thread with a namespace.
///
/// SECURITY: Requires appropriate capabilities (usually CAP_SYS_ADMIN).
/// The file descriptor must refer to a namespace file in /proc/<pid>/ns/.
///
/// # Arguments
/// * `fd` - File descriptor referring to a namespace (from /proc/<pid>/ns/*)
/// * `nstype` - Type of namespace to join (0 for any, or CLONE_NEW* flag)
///
/// # Example
/// ```zig
/// const fd = try std.posix.open("/proc/1234/ns/mnt", .{}, 0);
/// defer std.posix.close(fd);
/// try setns(fd, NsType.CLONE_NEWNS);
/// ```
pub fn setns(fd: i32, nstype: i32) SyscallError!void {
    const result = linux.syscall2(.setns, @intCast(fd), @intCast(nstype));
    if (result > std.math.maxInt(usize) - 4096) {
        const errno_val: u16 = @truncate(0 -% result);
        return errnoToError(@enumFromInt(errno_val));
    }
}

/// Open a file and return its file descriptor.
/// Wrapper around the open(2) syscall.
pub fn openFile(path: [*:0]const u8, flags: linux.O) SyscallError!i32 {
    const result = linux.open(path, flags, 0);
    if (@as(isize, @bitCast(result)) < 0) {
        const errno_val: u16 = @truncate(0 -% result);
        return errnoToError(@enumFromInt(errno_val));
    }
    return @intCast(result);
}

/// Namespace types available in /proc/<pid>/ns/
pub const NamespaceType = enum {
    mnt, // Mount namespace
    uts, // UTS (hostname) namespace
    ipc, // IPC namespace
    net, // Network namespace
    pid, // PID namespace
    user, // User namespace
    cgroup, // Cgroup namespace

    /// Get the filename for this namespace type
    pub fn toFilename(self: NamespaceType) []const u8 {
        return switch (self) {
            .mnt => "mnt",
            .uts => "uts",
            .ipc => "ipc",
            .net => "net",
            .pid => "pid",
            .user => "user",
            .cgroup => "cgroup",
        };
    }

    /// Get the clone flag for this namespace type
    pub fn toCloneFlag(self: NamespaceType) i32 {
        return switch (self) {
            .mnt => NsType.CLONE_NEWNS,
            .uts => NsType.CLONE_NEWUTS,
            .ipc => NsType.CLONE_NEWIPC,
            .net => NsType.CLONE_NEWNET,
            .pid => NsType.CLONE_NEWPID,
            .user => NsType.CLONE_NEWUSER,
            .cgroup => NsType.CLONE_NEWCGROUP,
        };
    }
};

/// Enter a namespace of a running process.
///
/// Opens /proc/<pid>/ns/<ns_type> and calls setns() to join that namespace.
///
/// SECURITY: Requires CAP_SYS_ADMIN or CAP_SYS_PTRACE depending on the namespace.
///
/// # Arguments
/// * `pid` - PID of the target process
/// * `ns_type` - Type of namespace to enter
///
/// # Example
/// ```zig
/// try enterNamespace(1234, .mnt);  // Enter mount namespace of PID 1234
/// try enterNamespace(1234, .pid);  // Enter PID namespace of PID 1234
/// ```
pub fn enterNamespace(pid: linux.pid_t, ns_type: NamespaceType) SyscallError!void {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/ns/{s}", .{
        pid,
        ns_type.toFilename(),
    }) catch return SyscallError.NameTooLong;

    // Open the namespace file read-only
    const fd = try openFile(path.ptr, .{});
    defer close(fd);

    // Join the namespace
    try setns(fd, ns_type.toCloneFlag());
}

/// Enter multiple namespaces of a running process.
///
/// This is the equivalent of `nsenter --target <pid> --mount --uts --ipc --net --pid`.
///
/// # Arguments
/// * `pid` - PID of the target process
/// * `namespaces` - Array of namespace types to enter
pub fn enterNamespaces(pid: linux.pid_t, namespaces: []const NamespaceType) SyscallError!void {
    // Order matters! User namespace should be entered first if present,
    // then other namespaces.
    for (namespaces) |ns| {
        try enterNamespace(pid, ns);
    }
}

// =============================================================================
// Tests
// =============================================================================

test "CloneFlags constants match linux definitions" {
    const testing = std.testing;
    try testing.expectEqual(CloneFlags.NEWPID, linux.CLONE.NEWPID);
    try testing.expectEqual(CloneFlags.NEWNS, linux.CLONE.NEWNS);
    try testing.expectEqual(CloneFlags.NEWUTS, linux.CLONE.NEWUTS);
    try testing.expectEqual(CloneFlags.NEWIPC, linux.CLONE.NEWIPC);
}

test "MountFlags constants match linux definitions" {
    const testing = std.testing;
    try testing.expectEqual(MountFlags.BIND, linux.MS.BIND);
    try testing.expectEqual(MountFlags.RDONLY, linux.MS.RDONLY);
    try testing.expectEqual(MountFlags.PRIVATE, linux.MS.PRIVATE);
}
