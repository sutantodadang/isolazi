//! Filesystem isolation and rootfs operations.
//!
//! This module handles:
//! - Setting up the container root filesystem
//! - Bind mounts for container directories
//! - pivot_root / chroot operations
//! - Mounting special filesystems (proc, dev, etc.)
//!
//! SECURITY CONSIDERATIONS:
//! - pivot_root is preferred over chroot (prevents escape via file descriptors)
//! - All mounts in container should be in a private mount namespace
//! - /proc should be mounted with appropriate hidepid option in production
//! - Device nodes should be carefully controlled

const std = @import("std");
const linux = @import("../linux/mod.zig");
const config_mod = @import("../config/mod.zig");

pub const FsError = error{
    MountFailed,
    PivotRootFailed,
    ChrootFailed,
    MkdirFailed,
    ChdirFailed,
    UnmountFailed,
    PathTooLong,
    InvalidRootfs,
} || linux.SyscallError;

/// Setup the container's root filesystem using pivot_root.
///
/// This is the secure way to change the root filesystem:
/// 1. Bind-mount the new rootfs to itself (makes it a mount point)
/// 2. Create a directory for the old root
/// 3. pivot_root to the new root, moving old root to the directory
/// 4. Unmount and remove the old root directory
///
/// After this, the old root is completely inaccessible.
///
/// SECURITY: Must be called after entering a new mount namespace.
/// The rootfs should be validated before calling this function.
pub fn setupPivotRoot(rootfs: [*:0]const u8) FsError!void {
    // Step 1: Bind mount the rootfs to itself
    // This ensures it's a mount point (required for pivot_root)
    // UNSAFE: Direct syscall with user-provided path
    try linux.mount(rootfs, rootfs, null, linux.MountFlags.BIND | linux.MountFlags.REC, null);

    // Step 2: Make the mount private to avoid propagation
    try linux.mount(null, rootfs, null, linux.MountFlags.PRIVATE | linux.MountFlags.REC, null);

    // Step 3: Change directory to the new root
    try linux.chdir(rootfs);

    // Step 4: Create directory for old root
    // The old root will be moved here temporarily
    const old_root = ".pivot_root";
    try linux.mkdir(old_root, 0o700);

    // Step 5: pivot_root - the core operation
    // After this, "/" is the new rootfs and ".pivot_root" contains the old root
    // UNSAFE: This is the critical security boundary operation
    try linux.pivotRoot(".", old_root);

    // Step 6: Change to new root
    try linux.chdir("/");

    // Step 7: Unmount the old root (now at /.pivot_root)
    // MNT_DETACH (2) allows unmounting even if busy
    const old_root_mounted = "/.pivot_root";
    try linux.umount(@ptrCast(old_root_mounted), 2); // MNT_DETACH

    // Step 8: Remove the old root directory
    try linux.rmdir(@ptrCast(old_root_mounted));
}

/// Setup the container's root filesystem using chroot.
///
/// Less secure than pivot_root but simpler and works in more cases.
/// The old root remains accessible through:
/// - File descriptors opened before chroot
/// - /proc/*/root and /proc/*/cwd symlinks
///
/// Use pivot_root when possible for better security.
pub fn setupChroot(rootfs: [*:0]const u8) FsError!void {
    // UNSAFE: Direct chroot syscall
    try linux.chroot(rootfs);
    try linux.chdir("/");
}

/// Mount the /proc filesystem inside the container.
///
/// /proc provides process information and is required for many tools.
/// In a PID namespace, /proc only shows processes in that namespace.
///
/// SECURITY: In production, consider:
/// - hidepid=2 to hide other processes
/// - subset=pid to limit exposed information
pub fn mountProc(target: [*:0]const u8) FsError!void {
    // Create mount point if it doesn't exist
    try linux.mkdir(target, 0o755);

    // Mount procfs
    // UNSAFE: Mounts a virtual filesystem that exposes kernel state
    try linux.mount(
        "proc",
        target,
        "proc",
        linux.MountFlags.NOSUID | linux.MountFlags.NODEV | linux.MountFlags.NOEXEC,
        null,
    );
}

/// Mount a tmpfs at the specified path.
///
/// Useful for /tmp, /run, etc.
pub fn mountTmpfs(target: [*:0]const u8) FsError!void {
    try linux.mkdir(target, 0o755);
    try linux.mount(
        "tmpfs",
        target,
        "tmpfs",
        linux.MountFlags.NOSUID | linux.MountFlags.NODEV,
        null,
    );
}

/// Mount devtmpfs or create minimal /dev.
///
/// /dev contains device nodes. For security, we mount a minimal devtmpfs
/// rather than bind-mounting the host's /dev.
pub fn mountDev(target: [*:0]const u8) FsError!void {
    try linux.mkdir(target, 0o755);

    // Mount a minimal tmpfs for /dev
    try linux.mount(
        "tmpfs",
        target,
        "tmpfs",
        linux.MountFlags.NOSUID,
        null,
    );

    // In a full implementation, we would:
    // 1. Create essential device nodes (null, zero, random, urandom, tty, etc.)
    // 2. Create symlinks (stdin, stdout, stderr -> /proc/self/fd/*)
    // 3. Create /dev/pts for pseudo-terminals
    // For now, this is left as a minimal implementation
}

/// Perform a bind mount.
///
/// Bind mounts expose host paths inside the container.
///
/// SECURITY: Be careful what paths you bind mount!
/// - Never mount sensitive host directories (/etc, /root, etc.)
/// - Use readonly mounts when possible
/// - Avoid mounting paths that could allow container escape
pub fn bindMount(source: [*:0]const u8, target: [*:0]const u8, readonly: bool) FsError!void {
    // Create target directory if needed
    try linux.mkdir(target, 0o755);

    // Initial bind mount
    try linux.mount(
        source,
        target,
        null,
        linux.MountFlags.BIND | linux.MountFlags.REC,
        null,
    );

    // If readonly, remount with readonly flag
    if (readonly) {
        try linux.mount(
            null,
            target,
            null,
            linux.MountFlags.BIND | linux.MountFlags.REMOUNT | linux.MountFlags.RDONLY,
            null,
        );
    }
}

/// Setup all bind mounts from configuration.
pub fn setupBindMounts(mounts: []const config_mod.Mount, mounts_count: usize) FsError!void {
    var i: usize = 0;
    while (i < mounts_count) : (i += 1) {
        const m = &mounts[i];
        if (!m.active) continue;
        try bindMount(m.getSource(), m.getDestination(), m.readonly);
    }
}

/// Setup essential filesystem mounts for a minimal container.
///
/// This creates the basic filesystem structure needed for most programs:
/// - /proc - process information
/// - /dev - device nodes (minimal)
/// - /tmp - temporary files
///
/// Call this after pivot_root/chroot.
pub fn setupMinimalMounts() FsError!void {
    // Mount /proc for process information
    try mountProc("/proc");

    // Mount minimal /dev
    // Note: In production, this needs more work for proper device access
    try mountDev("/dev");

    // Mount /tmp as tmpfs
    try mountTmpfs("/tmp");
}

/// Validate that a path looks like a valid rootfs.
///
/// Checks for essential directories that should exist in any rootfs.
/// This is a basic sanity check, not a security validation.
pub fn validateRootfs(rootfs_path: []const u8) bool {
    // For a minimal implementation, we just check if the path exists
    // and looks like it could be a rootfs (has /bin or /usr/bin)

    var path_buf: [config_mod.PATH_MAX]u8 = undefined;

    // Check for /bin
    const bin_path = std.fmt.bufPrint(&path_buf, "{s}/bin", .{rootfs_path}) catch return false;
    const bin_stat = std.fs.cwd().statFile(bin_path) catch return false;
    if (bin_stat.kind != .directory) {
        // Try /usr/bin instead
        const usr_bin_path = std.fmt.bufPrint(&path_buf, "{s}/usr/bin", .{rootfs_path}) catch return false;
        const usr_bin_stat = std.fs.cwd().statFile(usr_bin_path) catch return false;
        if (usr_bin_stat.kind != .directory) {
            return false;
        }
    }

    return true;
}

// =============================================================================
// Tests
// =============================================================================

test "validateRootfs returns false for non-existent path" {
    const result = validateRootfs("/nonexistent/path/that/should/not/exist");
    try std.testing.expect(!result);
}
