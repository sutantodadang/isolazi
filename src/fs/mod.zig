//! Filesystem module for container isolation.
//!
//! Provides:
//! - Root filesystem setup (pivot_root, chroot)
//! - Bind mount operations
//! - Special filesystem mounting (proc, dev, tmp)

pub const rootfs = @import("rootfs.zig");

pub const FsError = rootfs.FsError;

pub const setupPivotRoot = rootfs.setupPivotRoot;
pub const setupChroot = rootfs.setupChroot;
pub const mountProc = rootfs.mountProc;
pub const mountTmpfs = rootfs.mountTmpfs;
pub const mountDev = rootfs.mountDev;
pub const bindMount = rootfs.bindMount;
pub const setupBindMounts = rootfs.setupBindMounts;
pub const setupMinimalMounts = rootfs.setupMinimalMounts;
pub const validateRootfs = rootfs.validateRootfs;
