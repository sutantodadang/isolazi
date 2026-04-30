//! Linux-specific functionality for container isolation.
//!
//! This module provides:
//! - Direct syscall wrappers (syscalls.zig)
//! - Namespace management helpers
//! - Network namespace and container networking (network.zig)
//! - User namespace for rootless containers (userns.zig)
//! - Cgroup v2 resource management (cgroup.zig)
//! - Seccomp syscall filtering (seccomp.zig)
//! - AppArmor Linux Security Module (apparmor.zig)
//! - SELinux Linux Security Module (selinux.zig)
//! - Constants and flags for Linux primitives
//!
//! PLATFORM: This module is Linux-only. Windows support requires
//! different isolation mechanisms (Windows Containers, Hyper-V).

pub const syscalls = @import("syscalls.zig");
pub const network = @import("network.zig");
pub const userns = @import("userns.zig");
pub const cgroup = @import("cgroup.zig");
pub const seccomp = @import("seccomp.zig");
pub const apparmor = @import("apparmor.zig");
pub const selinux = @import("selinux.zig");

// Re-export commonly used items
pub const CloneFlags = syscalls.CloneFlags;
pub const MountFlags = syscalls.MountFlags;
pub const SyscallError = syscalls.SyscallError;
pub const NsType = syscalls.NsType;
pub const NamespaceType = syscalls.NamespaceType;

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
pub const setns = syscalls.setns;
pub const openFile = syscalls.openFile;
pub const enterNamespace = syscalls.enterNamespace;
pub const enterNamespaces = syscalls.enterNamespaces;

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

// Seccomp syscall filtering module exports
pub const SeccompError = seccomp.SeccompError;
pub const SeccompAction = seccomp.SeccompAction;
pub const SeccompRule = seccomp.SeccompRule;
pub const SeccompProfile = seccomp.SeccompProfile;
pub const SeccompConfig = seccomp.SeccompConfig;
pub const SeccompArg = seccomp.SeccompArg;
pub const SeccompOp = seccomp.SeccompOp;
pub const Syscall = seccomp.Syscall;
pub const installSeccompFilter = seccomp.installSeccompFilter;
pub const applySeccompFilter = seccomp.applySeccompFilter;
pub const isSeccompSupported = seccomp.isSeccompSupported;

// AppArmor Linux Security Module exports
pub const AppArmorError = apparmor.AppArmorError;
pub const AppArmorMode = apparmor.AppArmorMode;
pub const AppArmorProfile = apparmor.AppArmorProfile;
pub const AppArmorConfig = apparmor.AppArmorConfig;
pub const FilePermission = apparmor.FilePermission;
pub const FileRule = apparmor.FileRule;
pub const CapRule = apparmor.CapRule;
pub const NetworkPermission = apparmor.NetworkPermission;
pub const isAppArmorAvailable = apparmor.isAppArmorAvailable;
pub const isAppArmorEnforcing = apparmor.isAppArmorEnforcing;
pub const applyAppArmorConfig = apparmor.applyAppArmorConfig;
pub const changeAppArmorProfile = apparmor.changeProfile;
pub const setAppArmorExecProfile = apparmor.setExecProfile;
pub const getCurrentAppArmorProfile = apparmor.getCurrentProfile;
pub const isAppArmorProfileLoaded = apparmor.isProfileLoaded;

// SELinux Linux Security Module exports
pub const SELinuxError = selinux.SELinuxError;
pub const SELinuxMode = selinux.SELinuxMode;
pub const SecurityContext = selinux.SecurityContext;
pub const SELinuxConfig = selinux.SELinuxConfig;
pub const FileLabel = selinux.FileLabel;
pub const isSELinuxAvailable = selinux.isSELinuxAvailable;
pub const isSELinuxEnforcing = selinux.isSELinuxEnforcing;
pub const getSELinuxMode = selinux.getSELinuxMode;
pub const applySELinuxConfig = selinux.applySELinuxConfig;
pub const setSELinuxCurrentContext = selinux.setCurrentContext;
pub const setSELinuxExecContext = selinux.setExecContext;
pub const setSELinuxFileCreateContext = selinux.setFileCreateContext;
pub const getCurrentSELinuxContext = selinux.getCurrentContext;
pub const getSELinuxFileContext = selinux.getFileContext;
pub const setSELinuxFileContext = selinux.setFileContext;
