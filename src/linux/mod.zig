//! Linux-specific functionality for container isolation.
//!
//! This module provides:
//! - Direct syscall wrappers (syscalls.zig)
//! - Namespace management helpers
//! - Network namespace and container networking (network.zig)
//! - User namespace for rootless containers (userns.zig)
//! - Cgroup v2 resource management (cgroup.zig)
//! - Constants and flags for Linux primitives
//!
//! PLATFORM: This module is Linux-only. Windows support requires
//! different isolation mechanisms (Windows Containers, Hyper-V).

pub const syscalls = @import("syscalls.zig");
pub const network = @import("network.zig");
pub const userns = @import("userns.zig");
pub const cgroup = @import("cgroup.zig");

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

// Network module exports
pub const NetworkManager = network.NetworkManager;
pub const NetworkConfig = network.NetworkConfig;
pub const ContainerNetwork = network.ContainerNetwork;
pub const IpAllocator = network.IpAllocator;
pub const PortMapping = network.PortMapping;
pub const NetworkError = network.NetworkError;
pub const setupContainerNetworkHost = network.setupContainerNetworkHost;
pub const setupContainerNetworkContainer = network.setupContainerNetworkContainer;

// User namespace module exports
pub const UserNamespaceConfig = userns.UserNamespaceConfig;
pub const UserNamespaceError = userns.UserNamespaceError;
pub const setupUserNamespace = userns.setupUserNamespace;
pub const canCreateUserNamespace = userns.canCreateUserNamespace;
pub const isRoot = userns.isRoot;
pub const getCurrentUid = userns.getCurrentUid;
pub const getCurrentGid = userns.getCurrentGid;

// Cgroup v2 module exports
pub const CgroupManager = cgroup.CgroupManager;
pub const CgroupError = cgroup.CgroupError;
pub const ResourceLimits = cgroup.ResourceLimits;
pub const MemoryLimit = cgroup.MemoryLimit;
pub const CpuLimit = cgroup.CpuLimit;
pub const IoLimit = cgroup.IoLimit;
pub const OomConfig = cgroup.OomConfig;
pub const CpuStats = cgroup.CpuStats;
pub const isCgroupV2Available = cgroup.isCgroupV2Available;
pub const setupContainerCgroup = cgroup.setupContainerCgroup;
pub const cleanupContainerCgroup = cgroup.cleanupContainerCgroup;
