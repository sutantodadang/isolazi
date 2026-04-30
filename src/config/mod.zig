//! Container configuration module.
//!
//! Provides structures for defining container specifications:
//! - Rootfs path
//! - Command and arguments
//! - Environment variables
//! - Namespace configuration
//! - Bind mounts
//! - Resource limits (cgroup v2)
//! - Seccomp syscall filtering
//! - Linux Security Modules (AppArmor/SELinux)

pub const config = @import("config.zig");

pub const Config = config.Config;
pub const Namespaces = config.Namespaces;
pub const Mount = config.Mount;
pub const PortMapping = config.PortMapping;
pub const IdMapping = config.IdMapping;

// Resource limits types
pub const ResourceLimits = config.ResourceLimits;
pub const MemoryLimitConfig = config.MemoryLimitConfig;
pub const CpuLimitConfig = config.CpuLimitConfig;
pub const IoLimitConfig = config.IoLimitConfig;
pub const DeviceIoLimit = config.DeviceIoLimit;
pub const OomConfig = config.OomConfig;

// Seccomp types
pub const SeccompConfig = config.SeccompConfig;
pub const SeccompAction = config.SeccompAction;
pub const SeccompRuleConfig = config.SeccompRuleConfig;
pub const SeccompProfileType = config.SeccompProfileType;

// Linux Security Module (LSM) types - AppArmor
pub const AppArmorConfig = config.AppArmorConfig;
pub const AppArmorMode = config.AppArmorMode;

// Linux Security Module (LSM) types - SELinux
pub const SELinuxConfig = config.SELinuxConfig;
pub const SELinuxMode = config.SELinuxMode;
pub const SELinuxType = config.SELinuxType;

// Combined LSM configuration
pub const LSMConfig = config.LSMConfig;

pub const PATH_MAX = config.PATH_MAX;
pub const MAX_ARGS = config.MAX_ARGS;
pub const MAX_ENV = config.MAX_ENV;
pub const MAX_MOUNTS = config.MAX_MOUNTS;
pub const MAX_PORTS = config.MAX_PORTS;
pub const MAX_ID_MAPPINGS = config.MAX_ID_MAPPINGS;
pub const MAX_IO_DEVICES = config.MAX_IO_DEVICES;
pub const MAX_SECCOMP_RULES = config.MAX_SECCOMP_RULES;
pub const MAX_APPARMOR_PROFILE_NAME = config.MAX_APPARMOR_PROFILE_NAME;
pub const MAX_SELINUX_CONTEXT_LEN = config.MAX_SELINUX_CONTEXT_LEN;
pub const MAX_MCS_CATEGORIES = config.MAX_MCS_CATEGORIES;
