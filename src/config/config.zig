//! Container configuration structures.
//!
//! Inspired by OCI Runtime Specification but simplified for initial implementation.
//! See: https://github.com/opencontainers/runtime-spec
//!
//! Design decisions:
//! - No heap allocations in Config struct itself
//! - Fixed-size buffers for paths (PATH_MAX = 4096)
//! - Explicit defaults for all optional fields
//! - Validation at construction time

const std = @import("std");

/// Maximum path length (Linux PATH_MAX)
pub const PATH_MAX = 4096;

/// Maximum hostname length (Linux HOST_NAME_MAX)
pub const HOSTNAME_MAX = 64;

/// Maximum number of arguments
pub const MAX_ARGS = 64;

/// Maximum number of environment variables
pub const MAX_ENV = 128;

/// Maximum number of bind mounts
pub const MAX_MOUNTS = 32;

/// Maximum number of port mappings
pub const MAX_PORTS = 32;

/// Maximum number of UID/GID mappings for user namespace
pub const MAX_ID_MAPPINGS = 8;

/// Maximum number of I/O device limits
pub const MAX_IO_DEVICES = 8;

/// Maximum number of seccomp rules
pub const MAX_SECCOMP_RULES = 64;

/// Resource limits for memory
pub const MemoryLimitConfig = struct {
    /// Hard memory limit in bytes (0 = unlimited)
    max: u64 = 0,
    /// High watermark - triggers memory pressure at this level (0 = disabled)
    high: u64 = 0,
    /// Swap limit in bytes (0 = same as memory max)
    swap_max: u64 = 0,
    /// Enable swap (if false, swap_max is set to 0)
    swap_enabled: bool = true,

    /// Parse a memory string like "512m", "1g", "1024k", "1073741824"
    pub fn parse(s: []const u8) !u64 {
        if (s.len == 0) return 0;

        const last = s[s.len - 1];
        var multiplier: u64 = 1;
        var num_str = s;

        if (last == 'k' or last == 'K') {
            multiplier = 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 'm' or last == 'M') {
            multiplier = 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 'g' or last == 'G') {
            multiplier = 1024 * 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 't' or last == 'T') {
            multiplier = 1024 * 1024 * 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        }

        const value = std.fmt.parseInt(u64, num_str, 10) catch
            return error.InvalidMemoryLimit;

        if (value > std.math.maxInt(u64) / multiplier) {
            return error.InvalidMemoryLimit;
        }

        return value * multiplier;
    }
};

/// Resource limits for CPU
pub const CpuLimitConfig = struct {
    /// CPU quota in microseconds per period (0 = unlimited)
    quota: u64 = 0,
    /// CPU period in microseconds (default 100ms = 100000)
    period: u64 = 100000,
    /// CPU weight for scheduling (1-10000, default 100)
    weight: u32 = 100,

    /// Parse a CPU specification like "2" (cores), "0.5", "200%"
    pub fn parseSpec(s: []const u8) !CpuLimitConfig {
        var result = CpuLimitConfig{};

        if (std.mem.endsWith(u8, s, "%")) {
            const percent_str = s[0 .. s.len - 1];
            const percent = std.fmt.parseFloat(f64, percent_str) catch
                return error.InvalidCpuLimit;
            result.quota = @intFromFloat(percent * 1000);
            result.period = 100000;
        } else if (std.mem.indexOf(u8, s, ".")) |_| {
            const cores = std.fmt.parseFloat(f64, s) catch
                return error.InvalidCpuLimit;
            result.quota = @intFromFloat(cores * 100000);
            result.period = 100000;
        } else {
            const value = std.fmt.parseInt(u64, s, 10) catch
                return error.InvalidCpuLimit;
            if (value <= 128) {
                result.quota = value * 100000;
                result.period = 100000;
            } else {
                result.quota = value;
                result.period = 100000;
            }
        }

        return result;
    }
};

/// Device I/O limit entry
pub const DeviceIoLimit = struct {
    /// Device major number
    major: u32 = 0,
    /// Device minor number
    minor: u32 = 0,
    /// Read bytes per second limit (0 = unlimited)
    rbps: u64 = 0,
    /// Write bytes per second limit (0 = unlimited)
    wbps: u64 = 0,
    /// Read I/O operations per second (0 = unlimited)
    riops: u64 = 0,
    /// Write I/O operations per second (0 = unlimited)
    wiops: u64 = 0,
    /// Is this entry active?
    active: bool = false,
};

/// Resource limits for I/O
pub const IoLimitConfig = struct {
    /// I/O weight for scheduling (1-10000, default 100)
    weight: u32 = 100,
    /// Device-specific limits
    device_limits: [MAX_IO_DEVICES]DeviceIoLimit = std.mem.zeroes([MAX_IO_DEVICES]DeviceIoLimit),
    device_count: usize = 0,
};

/// OOM killer configuration
pub const OomConfig = struct {
    /// Disable OOM killer for this cgroup
    disable_oom_kill: bool = false,
    /// OOM score adjustment (-1000 to 1000)
    oom_score_adj: i16 = 0,
    /// Enable OOM kill for the entire cgroup
    oom_group: bool = false,
};

/// Complete resource limits configuration
pub const ResourceLimits = struct {
    /// Memory limits
    memory: MemoryLimitConfig = .{},
    /// CPU limits
    cpu: CpuLimitConfig = .{},
    /// I/O limits
    io: IoLimitConfig = .{},
    /// OOM configuration
    oom: OomConfig = .{},

    /// Are any limits configured?
    pub fn hasLimits(self: *const ResourceLimits) bool {
        return self.memory.max > 0 or
            self.memory.high > 0 or
            self.cpu.quota > 0 or
            self.cpu.weight != 100 or
            self.io.weight != 100 or
            self.io.device_count > 0 or
            self.oom.disable_oom_kill or
            self.oom.oom_score_adj != 0 or
            self.oom.oom_group;
    }
};

/// Seccomp syscall filtering action
pub const SeccompAction = enum(u8) {
    /// Kill the process on blocked syscall
    kill = 0,
    /// Return errno to the calling process
    errno = 1,
    /// Log the syscall but allow it
    log = 2,
    /// Allow the syscall
    allow = 3,
};

/// A seccomp rule for syscall filtering
pub const SeccompRuleConfig = struct {
    /// Syscall number to match
    syscall: u32 = 0,
    /// Action to take when matched
    action: SeccompAction = .kill,
    /// Errno to return (only used with action = .errno)
    errno_value: u16 = 1,
    /// Is this rule active?
    active: bool = false,
    /// Description of what this rule does (for logging/debugging)
    description: [64]u8 = std.mem.zeroes([64]u8),

    /// Create a block rule
    pub fn block(syscall: u32) SeccompRuleConfig {
        return SeccompRuleConfig{
            .syscall = syscall,
            .action = .kill,
            .active = true,
        };
    }

    /// Create an allow rule
    pub fn allow(syscall: u32) SeccompRuleConfig {
        return SeccompRuleConfig{
            .syscall = syscall,
            .action = .allow,
            .active = true,
        };
    }

    /// Create an errno rule
    pub fn denyWithErrno(syscall: u32, errno: u16) SeccompRuleConfig {
        return SeccompRuleConfig{
            .syscall = syscall,
            .action = .errno,
            .errno_value = errno,
            .active = true,
        };
    }
};

/// Seccomp profile type
pub const SeccompProfileType = enum {
    /// No seccomp filtering (disabled)
    disabled,
    /// Default container profile - blocks dangerous syscalls
    default_container,
    /// Minimal profile - only blocks most critical syscalls
    minimal,
    /// Strict allowlist profile - blocks everything except explicitly allowed
    strict,
    /// Custom profile - uses custom rules
    custom,
};

/// Seccomp configuration for container security
pub const SeccompConfig = struct {
    /// Is seccomp filtering enabled?
    enabled: bool = true,
    /// Profile type to use
    profile_type: SeccompProfileType = .default_container,
    /// Log blocked syscalls instead of killing
    log_blocked: bool = false,
    /// Return errno instead of killing on blocked syscalls
    errno_instead_of_kill: bool = false,
    /// Errno value to return when blocking (default EPERM = 1)
    errno_value: u16 = 1,
    /// Custom rules (only used when profile_type = .custom)
    custom_rules: [MAX_SECCOMP_RULES]SeccompRuleConfig = std.mem.zeroes([MAX_SECCOMP_RULES]SeccompRuleConfig),
    /// Number of custom rules
    custom_rules_count: usize = 0,

    /// Create default seccomp configuration (enabled with default profile)
    pub fn default_config() SeccompConfig {
        return SeccompConfig{};
    }

    /// Create disabled seccomp configuration
    pub fn disabled() SeccompConfig {
        return SeccompConfig{
            .enabled = false,
            .profile_type = .disabled,
        };
    }

    /// Create minimal seccomp configuration
    pub fn minimal() SeccompConfig {
        return SeccompConfig{
            .profile_type = .minimal,
        };
    }

    /// Create strict seccomp configuration
    pub fn strict() SeccompConfig {
        return SeccompConfig{
            .profile_type = .strict,
        };
    }

    /// Add a custom rule
    pub fn addCustomRule(self: *SeccompConfig, rule: SeccompRuleConfig) !void {
        if (self.custom_rules_count >= MAX_SECCOMP_RULES) {
            return error.TooManySeccompRules;
        }
        self.custom_rules[self.custom_rules_count] = rule;
        self.custom_rules_count += 1;
        self.profile_type = .custom;
    }

    /// Check if seccomp filtering is effective
    pub fn hasFilter(self: *const SeccompConfig) bool {
        return self.enabled and self.profile_type != .disabled;
    }
};

// =============================================================================
// Linux Security Module (LSM) Configuration - AppArmor
// =============================================================================

/// Maximum length for AppArmor profile names
pub const MAX_APPARMOR_PROFILE_NAME = 256;

/// AppArmor enforcement mode
pub const AppArmorMode = enum(u8) {
    /// Profile is disabled (unconfined)
    unconfined = 0,
    /// Violations are logged but allowed (for debugging/testing)
    complain = 1,
    /// Violations are blocked and logged (production mode)
    enforce = 2,

    /// Parse mode from string
    pub fn fromString(s: []const u8) ?AppArmorMode {
        if (std.mem.eql(u8, s, "unconfined") or std.mem.eql(u8, s, "disabled")) {
            return .unconfined;
        } else if (std.mem.eql(u8, s, "complain") or std.mem.eql(u8, s, "permissive")) {
            return .complain;
        } else if (std.mem.eql(u8, s, "enforce") or std.mem.eql(u8, s, "enforcing")) {
            return .enforce;
        }
        return null;
    }

    /// Convert to string for display
    pub fn toString(self: AppArmorMode) []const u8 {
        return switch (self) {
            .unconfined => "unconfined",
            .complain => "complain",
            .enforce => "enforce",
        };
    }
};

/// AppArmor configuration for container security
pub const AppArmorConfig = struct {
    /// Is AppArmor enforcement enabled for this container?
    enabled: bool = false,

    /// Enforcement mode
    mode: AppArmorMode = .enforce,

    /// Profile name to use (empty = use default container profile "isolazi-default")
    profile_name: [MAX_APPARMOR_PROFILE_NAME]u8 = std.mem.zeroes([MAX_APPARMOR_PROFILE_NAME]u8),
    profile_name_len: usize = 0,

    /// Create default AppArmor configuration (disabled)
    pub fn default_config() AppArmorConfig {
        return AppArmorConfig{};
    }

    /// Create enabled AppArmor configuration with default profile
    pub fn withDefaultProfile() AppArmorConfig {
        var config = AppArmorConfig{
            .enabled = true,
            .mode = .enforce,
        };
        const default_name = "isolazi-default";
        @memcpy(config.profile_name[0..default_name.len], default_name);
        config.profile_name_len = default_name.len;
        return config;
    }

    /// Create AppArmor configuration with a specific profile name
    pub fn withProfile(name: []const u8) AppArmorConfig {
        var config = AppArmorConfig{
            .enabled = true,
            .mode = .enforce,
        };
        const len = @min(name.len, MAX_APPARMOR_PROFILE_NAME - 1);
        @memcpy(config.profile_name[0..len], name[0..len]);
        config.profile_name_len = len;
        return config;
    }

    /// Create AppArmor configuration in complain (permissive) mode
    pub fn complainMode(name: []const u8) AppArmorConfig {
        var config = AppArmorConfig{
            .enabled = true,
            .mode = .complain,
        };
        const len = @min(name.len, MAX_APPARMOR_PROFILE_NAME - 1);
        @memcpy(config.profile_name[0..len], name[0..len]);
        config.profile_name_len = len;
        return config;
    }

    /// Create disabled/unconfined AppArmor configuration
    pub fn unconfined() AppArmorConfig {
        return AppArmorConfig{
            .enabled = false,
            .mode = .unconfined,
        };
    }

    /// Get profile name as slice
    pub fn getProfileName(self: *const AppArmorConfig) []const u8 {
        if (self.profile_name_len > 0) {
            return self.profile_name[0..self.profile_name_len];
        }
        return "isolazi-default";
    }

    /// Set the profile name
    pub fn setProfileName(self: *AppArmorConfig, name: []const u8) void {
        const len = @min(name.len, MAX_APPARMOR_PROFILE_NAME - 1);
        @memset(&self.profile_name, 0);
        @memcpy(self.profile_name[0..len], name[0..len]);
        self.profile_name_len = len;
    }

    /// Check if AppArmor is effectively enabled
    pub fn isEnabled(self: *const AppArmorConfig) bool {
        return self.enabled and self.mode != .unconfined;
    }
};

// =============================================================================
// Linux Security Module (LSM) Configuration - SELinux
// =============================================================================

/// Maximum length for SELinux context strings
pub const MAX_SELINUX_CONTEXT_LEN = 1024;

/// Maximum number of MCS categories
pub const MAX_MCS_CATEGORIES: u16 = 1024;

/// SELinux enforcement mode
pub const SELinuxMode = enum(u8) {
    /// SELinux is disabled
    disabled = 0,
    /// Permissive mode: violations are logged but not enforced
    permissive = 1,
    /// Enforcing mode: violations are blocked and logged
    enforcing = 2,

    /// Parse mode from string
    pub fn fromString(s: []const u8) ?SELinuxMode {
        if (std.mem.eql(u8, s, "disabled") or std.mem.eql(u8, s, "Disabled")) {
            return .disabled;
        } else if (std.mem.eql(u8, s, "permissive") or std.mem.eql(u8, s, "Permissive")) {
            return .permissive;
        } else if (std.mem.eql(u8, s, "enforcing") or std.mem.eql(u8, s, "Enforcing")) {
            return .enforcing;
        }
        return null;
    }

    /// Convert to string for display
    pub fn toString(self: SELinuxMode) []const u8 {
        return switch (self) {
            .disabled => "Disabled",
            .permissive => "Permissive",
            .enforcing => "Enforcing",
        };
    }
};

/// SELinux process type (domain)
pub const SELinuxType = enum(u8) {
    /// Standard container process (container_t) - restricted
    container_t = 0,
    /// Super-privileged container (spc_t) - less restricted
    spc_t = 1,
    /// Unconfined (unconfined_t) - no SELinux restrictions
    unconfined_t = 2,
    /// Custom type specified in context string
    custom = 3,

    /// Get the type string
    pub fn toString(self: SELinuxType) []const u8 {
        return switch (self) {
            .container_t => "container_t",
            .spc_t => "spc_t",
            .unconfined_t => "unconfined_t",
            .custom => "custom",
        };
    }

    /// Parse from string
    pub fn fromString(s: []const u8) ?SELinuxType {
        if (std.mem.eql(u8, s, "container_t") or std.mem.eql(u8, s, "container")) {
            return .container_t;
        } else if (std.mem.eql(u8, s, "spc_t") or std.mem.eql(u8, s, "super-privileged")) {
            return .spc_t;
        } else if (std.mem.eql(u8, s, "unconfined_t") or std.mem.eql(u8, s, "unconfined")) {
            return .unconfined_t;
        }
        return .custom;
    }
};

/// SELinux configuration for container security
pub const SELinuxConfig = struct {
    /// Is SELinux enforcement enabled for this container?
    enabled: bool = false,

    /// SELinux type (domain) for the container process
    selinux_type: SELinuxType = .container_t,

    /// Use MCS (Multi-Category Security) for container isolation
    use_mcs: bool = true,

    /// MCS category 1 (0-1023)
    mcs_category1: u16 = 0,

    /// MCS category 2 (0-1023)
    mcs_category2: u16 = 0,

    /// Custom security context (overrides type and MCS if set)
    /// Format: user:role:type:level (e.g., "system_u:system_r:container_t:s0:c1,c2")
    custom_context: [MAX_SELINUX_CONTEXT_LEN]u8 = std.mem.zeroes([MAX_SELINUX_CONTEXT_LEN]u8),
    custom_context_len: usize = 0,

    /// Mount label for container filesystem
    mount_label: [MAX_SELINUX_CONTEXT_LEN]u8 = std.mem.zeroes([MAX_SELINUX_CONTEXT_LEN]u8),
    mount_label_len: usize = 0,

    /// Create default SELinux configuration (disabled)
    pub fn default_config() SELinuxConfig {
        return SELinuxConfig{};
    }

    /// Create SELinux configuration with default container context
    pub fn withDefaultContext() SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .selinux_type = .container_t,
            .use_mcs = true,
        };
    }

    /// Create SELinux configuration with specific MCS categories
    pub fn withMCS(category1: u16, category2: u16) SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .selinux_type = .container_t,
            .use_mcs = true,
            .mcs_category1 = @min(category1, MAX_MCS_CATEGORIES - 1),
            .mcs_category2 = @min(category2, MAX_MCS_CATEGORIES - 1),
        };
    }

    /// Create SELinux configuration with custom context
    pub fn withContext(context: []const u8) SELinuxConfig {
        var config = SELinuxConfig{
            .enabled = true,
            .selinux_type = .custom,
        };
        const len = @min(context.len, MAX_SELINUX_CONTEXT_LEN - 1);
        @memcpy(config.custom_context[0..len], context[0..len]);
        config.custom_context_len = len;
        return config;
    }

    /// Create unconfined SELinux configuration (no restrictions)
    pub fn unconfined() SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .selinux_type = .unconfined_t,
            .use_mcs = false,
        };
    }

    /// Create super-privileged container SELinux configuration
    pub fn superPrivileged() SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .selinux_type = .spc_t,
            .use_mcs = false,
        };
    }

    /// Get the effective security context string
    /// Returns the context in format: user:role:type:level
    pub fn getContextString(self: *const SELinuxConfig, buf: []u8) []const u8 {
        if (self.custom_context_len > 0) {
            const len = @min(self.custom_context_len, buf.len);
            @memcpy(buf[0..len], self.custom_context[0..len]);
            return buf[0..len];
        }

        const type_str = self.selinux_type.toString();

        if (self.use_mcs) {
            const result = std.fmt.bufPrint(buf, "system_u:system_r:{s}:s0:c{d},c{d}", .{
                type_str,
                @min(self.mcs_category1, self.mcs_category2),
                @max(self.mcs_category1, self.mcs_category2),
            }) catch return "";
            return result;
        } else {
            const result = std.fmt.bufPrint(buf, "system_u:system_r:{s}:s0", .{type_str}) catch return "";
            return result;
        }
    }

    /// Set custom security context
    pub fn setContext(self: *SELinuxConfig, context: []const u8) void {
        const len = @min(context.len, MAX_SELINUX_CONTEXT_LEN - 1);
        @memset(&self.custom_context, 0);
        @memcpy(self.custom_context[0..len], context[0..len]);
        self.custom_context_len = len;
        self.selinux_type = .custom;
    }

    /// Set mount label
    pub fn setMountLabel(self: *SELinuxConfig, label: []const u8) void {
        const len = @min(label.len, MAX_SELINUX_CONTEXT_LEN - 1);
        @memset(&self.mount_label, 0);
        @memcpy(self.mount_label[0..len], label[0..len]);
        self.mount_label_len = len;
    }

    /// Get mount label as slice
    pub fn getMountLabel(self: *const SELinuxConfig) []const u8 {
        if (self.mount_label_len > 0) {
            return self.mount_label[0..self.mount_label_len];
        }
        return "";
    }

    /// Generate random MCS categories for container isolation
    pub fn generateMCSCategories(self: *SELinuxConfig) void {
        // Use current time as seed for randomness
        var prng = std.Random.DefaultPrng.init(@bitCast(std.time.milliTimestamp()));
        const random = prng.random();

        self.mcs_category1 = random.intRangeAtMost(u16, 0, MAX_MCS_CATEGORIES - 1);
        self.mcs_category2 = random.intRangeAtMost(u16, 0, MAX_MCS_CATEGORIES - 1);

        // Ensure categories are different
        while (self.mcs_category2 == self.mcs_category1) {
            self.mcs_category2 = random.intRangeAtMost(u16, 0, MAX_MCS_CATEGORIES - 1);
        }

        self.use_mcs = true;
    }

    /// Check if SELinux is effectively enabled
    pub fn isEnabled(self: *const SELinuxConfig) bool {
        return self.enabled and self.selinux_type != .unconfined_t;
    }
};

// =============================================================================
// Combined LSM Configuration
// =============================================================================

/// Linux Security Module (LSM) configuration combining AppArmor and SELinux
/// Only one LSM should be enabled at a time (they are mutually exclusive on most systems)
pub const LSMConfig = struct {
    /// AppArmor configuration
    apparmor: AppArmorConfig = AppArmorConfig.default_config(),

    /// SELinux configuration
    selinux: SELinuxConfig = SELinuxConfig.default_config(),

    /// Create default LSM configuration (both disabled)
    pub fn default_config() LSMConfig {
        return LSMConfig{};
    }

    /// Create LSM configuration with AppArmor enabled
    pub fn withAppArmor(profile_name: []const u8) LSMConfig {
        return LSMConfig{
            .apparmor = AppArmorConfig.withProfile(profile_name),
        };
    }

    /// Create LSM configuration with default AppArmor profile
    pub fn withDefaultAppArmor() LSMConfig {
        return LSMConfig{
            .apparmor = AppArmorConfig.withDefaultProfile(),
        };
    }

    /// Create LSM configuration with SELinux enabled
    pub fn withSELinux(category1: u16, category2: u16) LSMConfig {
        return LSMConfig{
            .selinux = SELinuxConfig.withMCS(category1, category2),
        };
    }

    /// Create LSM configuration with default SELinux context
    pub fn withDefaultSELinux() LSMConfig {
        return LSMConfig{
            .selinux = SELinuxConfig.withDefaultContext(),
        };
    }

    /// Check if any LSM is enabled
    pub fn isEnabled(self: *const LSMConfig) bool {
        return self.apparmor.isEnabled() or self.selinux.isEnabled();
    }

    /// Check if AppArmor is the active LSM
    pub fn isAppArmorActive(self: *const LSMConfig) bool {
        return self.apparmor.isEnabled();
    }

    /// Check if SELinux is the active LSM
    pub fn isSELinuxActive(self: *const LSMConfig) bool {
        return self.selinux.isEnabled();
    }
};

/// A UID/GID mapping entry for user namespaces
/// Maps a range of IDs from parent namespace to child namespace
pub const IdMapping = struct {
    /// First ID in the child (container) namespace
    container_id: u32 = 0,
    /// First ID in the parent (host) namespace
    host_id: u32 = 0,
    /// Number of consecutive IDs to map
    count: u32 = 1,
    /// Is this mapping active?
    active: bool = false,

    /// Create a simple 1:1 mapping
    pub fn single(host_id: u32, container_id: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = 1,
            .active = true,
        };
    }

    /// Create a range mapping
    pub fn range(host_id: u32, container_id: u32, count: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
            .active = true,
        };
    }

    /// Parse a mapping string like "0:1000:1" (container:host:count)
    pub fn parse(spec: []const u8) !IdMapping {
        var iter = std.mem.splitScalar(u8, spec, ':');

        const container_str = iter.next() orelse return error.InvalidIdMapping;
        const host_str = iter.next() orelse return error.InvalidIdMapping;
        const count_str = iter.next() orelse "1";

        const container_id = std.fmt.parseInt(u32, container_str, 10) catch
            return error.InvalidIdMapping;
        const host_id = std.fmt.parseInt(u32, host_str, 10) catch
            return error.InvalidIdMapping;
        const count = std.fmt.parseInt(u32, count_str, 10) catch
            return error.InvalidIdMapping;

        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
            .active = true,
        };
    }
};

/// A port mapping specification (host:container).
pub const PortMapping = struct {
    /// Host port to listen on
    host_port: u16 = 0,
    /// Container port to forward to
    container_port: u16 = 0,
    /// Protocol (tcp/udp)
    protocol: Protocol = .tcp,
    /// Is this mapping active?
    active: bool = false,

    pub const Protocol = enum(u8) {
        tcp = 0,
        udp = 1,
    };

    /// Create a port mapping.
    pub fn init(host_port: u16, container_port: u16, protocol: Protocol) PortMapping {
        return PortMapping{
            .host_port = host_port,
            .container_port = container_port,
            .protocol = protocol,
            .active = true,
        };
    }

    /// Parse a port mapping string like "8080:80" or "8080:80/udp"
    pub fn parse(spec: []const u8) !PortMapping {
        // Check for protocol suffix
        var protocol: Protocol = .tcp;
        var port_spec = spec;

        if (std.mem.endsWith(u8, spec, "/udp")) {
            protocol = .udp;
            port_spec = spec[0 .. spec.len - 4];
        } else if (std.mem.endsWith(u8, spec, "/tcp")) {
            port_spec = spec[0 .. spec.len - 4];
        }

        // Parse host:container
        const colon_idx = std.mem.indexOf(u8, port_spec, ":") orelse return error.InvalidPortMapping;
        const host_str = port_spec[0..colon_idx];
        const container_str = port_spec[colon_idx + 1 ..];

        const host_port = std.fmt.parseInt(u16, host_str, 10) catch return error.InvalidPortNumber;
        const container_port = std.fmt.parseInt(u16, container_str, 10) catch return error.InvalidPortNumber;

        return PortMapping.init(host_port, container_port, protocol);
    }
};

/// Namespace configuration flags.
pub const Namespaces = packed struct {
    pid: bool = true,
    mount: bool = true,
    uts: bool = true,
    ipc: bool = true,
    network: bool = true, // Network namespace with veth/bridge
    user: bool = false, // User namespace for rootless containers
    cgroup: bool = false, // Cgroup namespace for resource isolation

    /// Return the combined clone flags for namespace creation.
    pub fn toCloneFlags(self: Namespaces) u64 {
        const linux = @import("../linux/mod.zig");
        var flags: u64 = 0;
        if (self.pid) flags |= linux.CloneFlags.NEWPID;
        if (self.mount) flags |= linux.CloneFlags.NEWNS;
        if (self.uts) flags |= linux.CloneFlags.NEWUTS;
        if (self.ipc) flags |= linux.CloneFlags.NEWIPC;
        if (self.network) flags |= linux.CloneFlags.NEWNET;
        if (self.user) flags |= linux.CloneFlags.NEWUSER;
        if (self.cgroup) flags |= linux.CloneFlags.NEWCGROUP;
        return flags;
    }

    /// Default configuration with PID, mount, UTS, IPC, and network namespaces.
    pub const default = Namespaces{};

    /// Minimal configuration (mount only, for testing).
    pub const minimal = Namespaces{
        .pid = false,
        .mount = true,
        .uts = false,
        .ipc = false,
        .network = false,
        .user = false,
        .cgroup = false,
    };

    /// Full isolation including cgroup namespace.
    pub const full = Namespaces{
        .pid = true,
        .mount = true,
        .uts = true,
        .ipc = true,
        .network = true,
        .user = false,
        .cgroup = true,
    };
};

/// A bind mount specification.
pub const Mount = struct {
    /// Source path on the host (null-terminated)
    source: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),
    /// Destination path in the container (null-terminated)
    destination: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),
    /// Mount options
    readonly: bool = false,
    /// Is this mount configured?
    active: bool = false,

    /// Create a mount specification.
    pub fn init(source: []const u8, destination: []const u8, readonly: bool) !Mount {
        if (source.len >= PATH_MAX or destination.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        var m = Mount{
            .readonly = readonly,
            .active = true,
        };
        @memcpy(m.source[0..source.len], source);
        @memcpy(m.destination[0..destination.len], destination);
        return m;
    }

    /// Get source as a null-terminated slice.
    pub fn getSource(self: *const Mount) [*:0]const u8 {
        return &self.source;
    }

    /// Get destination as a null-terminated slice.
    pub fn getDestination(self: *const Mount) [*:0]const u8 {
        return &self.destination;
    }
};

/// Container configuration.
///
/// This struct contains all the information needed to create and run a container.
/// It uses fixed-size buffers to avoid heap allocation.
pub const Config = struct {
    /// Path to the root filesystem
    rootfs: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Working directory inside the container
    cwd: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Hostname for the container
    hostname: [HOSTNAME_MAX:0]u8 = std.mem.zeroes([HOSTNAME_MAX:0]u8),

    /// Command to execute (path to executable)
    command: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Arguments to the command (including argv[0])
    /// Each argument is a null-terminated string stored contiguously
    args: [MAX_ARGS][PATH_MAX:0]u8 = undefined,
    args_count: usize = 0,

    /// Environment variables (KEY=VALUE format)
    env: [MAX_ENV][PATH_MAX:0]u8 = undefined,
    env_count: usize = 0,

    /// Bind mounts
    mounts: [MAX_MOUNTS]Mount = std.mem.zeroes([MAX_MOUNTS]Mount),
    mounts_count: usize = 0,

    /// Port mappings (host:container)
    port_mappings: [MAX_PORTS]PortMapping = std.mem.zeroes([MAX_PORTS]PortMapping),
    port_count: usize = 0,

    /// Namespace configuration
    namespaces: Namespaces = Namespaces.default,

    /// Use pivot_root instead of chroot (more secure)
    use_pivot_root: bool = true,

    /// User namespace configuration for rootless containers
    /// UID mappings (container_id:host_id:count format)
    uid_mappings: [MAX_ID_MAPPINGS]IdMapping = std.mem.zeroes([MAX_ID_MAPPINGS]IdMapping),
    uid_map_count: usize = 0,

    /// GID mappings (container_id:host_id:count format)
    gid_mappings: [MAX_ID_MAPPINGS]IdMapping = std.mem.zeroes([MAX_ID_MAPPINGS]IdMapping),
    gid_map_count: usize = 0,

    /// Enable rootless mode (user namespace with current user mapped to root)
    rootless: bool = false,

    /// Resource limits (memory, CPU, I/O, OOM)
    resource_limits: ResourceLimits = .{},

    /// Seccomp syscall filtering configuration
    seccomp: SeccompConfig = SeccompConfig.default_config(),

    /// Linux Security Module (LSM) configuration (AppArmor/SELinux)
    lsm: LSMConfig = LSMConfig.default_config(),

    /// Initialize a new configuration with the given rootfs path.
    pub fn init(rootfs: []const u8) !Config {
        if (rootfs.len >= PATH_MAX) {
            return error.PathTooLong;
        }

        var config = Config{};

        // Set rootfs
        @memcpy(config.rootfs[0..rootfs.len], rootfs);

        // Default cwd is "/"
        config.cwd[0] = '/';

        // Default hostname
        const default_hostname = "container";
        @memcpy(config.hostname[0..default_hostname.len], default_hostname);

        // Initialize args array
        config.args = std.mem.zeroes([MAX_ARGS][PATH_MAX:0]u8);

        // Initialize env array with basic environment
        config.env = std.mem.zeroes([MAX_ENV][PATH_MAX:0]u8);
        try config.addEnv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin");
        try config.addEnv("TERM=xterm");

        return config;
    }

    /// Set the command to execute.
    pub fn setCommand(self: *Config, cmd: []const u8) !void {
        if (cmd.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.command, 0);
        @memcpy(self.command[0..cmd.len], cmd);
    }

    /// Add an argument.
    pub fn addArg(self: *Config, arg: []const u8) !void {
        if (self.args_count >= MAX_ARGS) {
            return error.TooManyArguments;
        }
        if (arg.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.args[self.args_count], 0);
        @memcpy(self.args[self.args_count][0..arg.len], arg);
        self.args_count += 1;
    }

    /// Add an environment variable (KEY=VALUE format).
    pub fn addEnv(self: *Config, env: []const u8) !void {
        if (self.env_count >= MAX_ENV) {
            return error.TooManyEnvVars;
        }
        if (env.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.env[self.env_count], 0);
        @memcpy(self.env[self.env_count][0..env.len], env);
        self.env_count += 1;
    }

    /// Add a bind mount.
    pub fn addMount(self: *Config, source: []const u8, destination: []const u8, readonly: bool) !void {
        if (self.mounts_count >= MAX_MOUNTS) {
            return error.TooManyMounts;
        }
        self.mounts[self.mounts_count] = try Mount.init(source, destination, readonly);
        self.mounts_count += 1;
    }

    /// Add a port mapping.
    pub fn addPort(self: *Config, host_port: u16, container_port: u16, protocol: PortMapping.Protocol) !void {
        if (self.port_count >= MAX_PORTS) {
            return error.TooManyPorts;
        }
        self.port_mappings[self.port_count] = PortMapping.init(host_port, container_port, protocol);
        self.port_count += 1;
    }

    /// Add a port mapping from a spec string like "8080:80" or "8080:80/udp".
    pub fn addPortFromSpec(self: *Config, spec: []const u8) !void {
        const mapping = try PortMapping.parse(spec);
        if (self.port_count >= MAX_PORTS) {
            return error.TooManyPorts;
        }
        self.port_mappings[self.port_count] = mapping;
        self.port_count += 1;
    }

    /// Add a UID mapping for user namespace.
    pub fn addUidMapping(self: *Config, host_id: u32, container_id: u32, count: u32) !void {
        if (self.uid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.uid_mappings[self.uid_map_count] = IdMapping.range(host_id, container_id, count);
        self.uid_map_count += 1;
    }

    /// Add a UID mapping from a spec string like "0:1000:1" (container:host:count).
    pub fn addUidMappingFromSpec(self: *Config, spec: []const u8) !void {
        if (self.uid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.uid_mappings[self.uid_map_count] = try IdMapping.parse(spec);
        self.uid_map_count += 1;
    }

    /// Add a GID mapping for user namespace.
    pub fn addGidMapping(self: *Config, host_id: u32, container_id: u32, count: u32) !void {
        if (self.gid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.gid_mappings[self.gid_map_count] = IdMapping.range(host_id, container_id, count);
        self.gid_map_count += 1;
    }

    /// Add a GID mapping from a spec string like "0:1000:1" (container:host:count).
    pub fn addGidMappingFromSpec(self: *Config, spec: []const u8) !void {
        if (self.gid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.gid_mappings[self.gid_map_count] = try IdMapping.parse(spec);
        self.gid_map_count += 1;
    }

    /// Enable rootless mode with default mappings (current user -> root in container).
    pub fn enableRootless(self: *Config) void {
        self.rootless = true;
        self.namespaces.user = true;
        // Default mapping: current user to root (0) inside container
        // The actual UID/GID will be determined at runtime
        self.uid_map_count = 0;
        self.gid_map_count = 0;
    }

    /// Set memory limit from a spec string like "512m", "1g", "1024k"
    pub fn setMemoryLimit(self: *Config, spec: []const u8) !void {
        self.resource_limits.memory.max = try MemoryLimitConfig.parse(spec);
        // Enable cgroup namespace when resource limits are used
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Set memory high watermark from a spec string
    pub fn setMemoryHigh(self: *Config, spec: []const u8) !void {
        self.resource_limits.memory.high = try MemoryLimitConfig.parse(spec);
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Set swap limit from a spec string (or "0" to disable swap)
    pub fn setSwapLimit(self: *Config, spec: []const u8) !void {
        if (std.mem.eql(u8, spec, "0") or std.mem.eql(u8, spec, "none")) {
            self.resource_limits.memory.swap_enabled = false;
        } else {
            self.resource_limits.memory.swap_max = try MemoryLimitConfig.parse(spec);
        }
    }

    /// Set CPU limit from a spec string like "2", "0.5", "200%"
    pub fn setCpuLimit(self: *Config, spec: []const u8) !void {
        self.resource_limits.cpu = try CpuLimitConfig.parseSpec(spec);
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Set CPU quota directly (microseconds per period)
    pub fn setCpuQuota(self: *Config, quota: u64) void {
        self.resource_limits.cpu.quota = quota;
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Set CPU period (microseconds)
    pub fn setCpuPeriod(self: *Config, period: u64) void {
        self.resource_limits.cpu.period = period;
    }

    /// Set CPU weight (1-10000)
    pub fn setCpuWeight(self: *Config, weight: u32) void {
        self.resource_limits.cpu.weight = weight;
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Set I/O weight (1-10000)
    pub fn setIoWeight(self: *Config, weight: u32) void {
        self.resource_limits.io.weight = weight;
        if (self.resource_limits.hasLimits()) {
            self.namespaces.cgroup = true;
        }
    }

    /// Add a device I/O limit
    pub fn addDeviceIoLimit(
        self: *Config,
        major: u32,
        minor: u32,
        rbps: u64,
        wbps: u64,
        riops: u64,
        wiops: u64,
    ) !void {
        if (self.resource_limits.io.device_count >= MAX_IO_DEVICES) {
            return error.TooManyDeviceLimits;
        }
        self.resource_limits.io.device_limits[self.resource_limits.io.device_count] = .{
            .major = major,
            .minor = minor,
            .rbps = rbps,
            .wbps = wbps,
            .riops = riops,
            .wiops = wiops,
            .active = true,
        };
        self.resource_limits.io.device_count += 1;
        self.namespaces.cgroup = true;
    }

    /// Set OOM score adjustment (-1000 to 1000)
    pub fn setOomScoreAdj(self: *Config, adj: i16) !void {
        if (adj < -1000 or adj > 1000) {
            return error.InvalidOomScoreAdj;
        }
        self.resource_limits.oom.oom_score_adj = adj;
    }

    /// Disable OOM killer for the container
    pub fn disableOomKiller(self: *Config) void {
        self.resource_limits.oom.disable_oom_kill = true;
        self.namespaces.cgroup = true;
    }

    /// Enable cgroup-level OOM kill (kills all processes in cgroup on OOM)
    pub fn enableOomGroup(self: *Config) void {
        self.resource_limits.oom.oom_group = true;
        self.namespaces.cgroup = true;
    }

    // =========================================================================
    // Seccomp Configuration Methods
    // =========================================================================

    /// Enable seccomp filtering with default container profile
    pub fn enableSeccomp(self: *Config) void {
        self.seccomp.enabled = true;
        self.seccomp.profile_type = .default_container;
    }

    /// Disable seccomp filtering
    pub fn disableSeccomp(self: *Config) void {
        self.seccomp.enabled = false;
        self.seccomp.profile_type = .disabled;
    }

    /// Set seccomp profile type
    pub fn setSeccompProfile(self: *Config, profile_type: SeccompProfileType) void {
        self.seccomp.profile_type = profile_type;
        if (profile_type == .disabled) {
            self.seccomp.enabled = false;
        } else {
            self.seccomp.enabled = true;
        }
    }

    /// Enable logging of blocked syscalls instead of killing
    pub fn setSeccompLogBlocked(self: *Config, log_blocked: bool) void {
        self.seccomp.log_blocked = log_blocked;
    }

    /// Set seccomp to return errno instead of killing
    pub fn setSeccompErrnoMode(self: *Config, errno_value: u16) void {
        self.seccomp.errno_instead_of_kill = true;
        self.seccomp.errno_value = errno_value;
    }

    /// Add a custom seccomp rule to block a syscall
    pub fn addSeccompBlockRule(self: *Config, syscall: u32) !void {
        try self.seccomp.addCustomRule(SeccompRuleConfig.block(syscall));
    }

    /// Add a custom seccomp rule to allow a syscall
    pub fn addSeccompAllowRule(self: *Config, syscall: u32) !void {
        try self.seccomp.addCustomRule(SeccompRuleConfig.allow(syscall));
    }

    /// Check if seccomp is enabled and has effective filtering
    pub fn hasSeccompFilter(self: *const Config) bool {
        return self.seccomp.hasFilter();
    }

    // =========================================================================
    // Linux Security Module (LSM) Configuration Methods
    // =========================================================================

    /// Enable AppArmor with default container profile
    pub fn enableAppArmor(self: *Config) void {
        self.lsm.apparmor = AppArmorConfig.withDefaultProfile();
    }

    /// Enable AppArmor with a specific profile name
    pub fn setAppArmorProfile(self: *Config, profile_name: []const u8) void {
        self.lsm.apparmor = AppArmorConfig.withProfile(profile_name);
    }

    /// Enable AppArmor in complain (permissive) mode
    pub fn setAppArmorComplainMode(self: *Config, profile_name: []const u8) void {
        self.lsm.apparmor = AppArmorConfig.complainMode(profile_name);
    }

    /// Disable AppArmor
    pub fn disableAppArmor(self: *Config) void {
        self.lsm.apparmor = AppArmorConfig.unconfined();
    }

    /// Enable SELinux with default container context
    pub fn enableSELinux(self: *Config) void {
        self.lsm.selinux = SELinuxConfig.withDefaultContext();
        // Generate random MCS categories for container isolation
        self.lsm.selinux.generateMCSCategories();
    }

    /// Enable SELinux with specific MCS categories
    pub fn setSELinuxMCS(self: *Config, category1: u16, category2: u16) void {
        self.lsm.selinux = SELinuxConfig.withMCS(category1, category2);
    }

    /// Enable SELinux with custom context string
    pub fn setSELinuxContext(self: *Config, context: []const u8) void {
        self.lsm.selinux = SELinuxConfig.withContext(context);
    }

    /// Set SELinux type (container_t, spc_t, unconfined_t)
    pub fn setSELinuxType(self: *Config, selinux_type: SELinuxType) void {
        self.lsm.selinux.enabled = true;
        self.lsm.selinux.selinux_type = selinux_type;
    }

    /// Disable SELinux (set to unconfined)
    pub fn disableSELinux(self: *Config) void {
        self.lsm.selinux = SELinuxConfig.unconfined();
    }

    /// Enable super-privileged container mode (SELinux spc_t)
    pub fn enableSuperPrivileged(self: *Config) void {
        self.lsm.selinux = SELinuxConfig.superPrivileged();
    }

    /// Check if any LSM is enabled
    pub fn hasLSMEnabled(self: *const Config) bool {
        return self.lsm.isEnabled();
    }

    /// Get active UID mappings.
    pub fn getUidMappings(self: *const Config) []const IdMapping {
        return self.uid_mappings[0..self.uid_map_count];
    }

    /// Get active GID mappings.
    pub fn getGidMappings(self: *const Config) []const IdMapping {
        return self.gid_mappings[0..self.gid_map_count];
    }

    /// Set the hostname.
    pub fn setHostname(self: *Config, name: []const u8) !void {
        if (name.len >= HOSTNAME_MAX) {
            return error.HostnameTooLong;
        }
        @memset(&self.hostname, 0);
        @memcpy(self.hostname[0..name.len], name);
    }

    /// Set the working directory.
    pub fn setCwd(self: *Config, path: []const u8) !void {
        if (path.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.cwd, 0);
        @memcpy(self.cwd[0..path.len], path);
    }

    /// Get rootfs path as null-terminated pointer.
    pub fn getRootfs(self: *const Config) [*:0]const u8 {
        return &self.rootfs;
    }

    /// Get cwd as null-terminated pointer.
    pub fn getCwd(self: *const Config) [*:0]const u8 {
        return &self.cwd;
    }

    /// Get hostname as a slice.
    pub fn getHostname(self: *const Config) []const u8 {
        return std.mem.sliceTo(&self.hostname, 0);
    }

    /// Get command as null-terminated pointer.
    pub fn getCommand(self: *const Config) [*:0]const u8 {
        return &self.command;
    }

    /// Build argv array for execve.
    /// Returns array of pointers suitable for execve.
    /// The array is null-terminated.
    pub fn buildArgv(self: *const Config, buf: *[MAX_ARGS + 1]?[*:0]const u8) [*:null]const ?[*:0]const u8 {
        var i: usize = 0;
        while (i < self.args_count) : (i += 1) {
            buf[i] = &self.args[i];
        }
        buf[i] = null;
        return @ptrCast(buf);
    }

    /// Build envp array for execve.
    /// Returns array of pointers suitable for execve.
    /// The array is null-terminated.
    pub fn buildEnvp(self: *const Config, buf: *[MAX_ENV + 1]?[*:0]const u8) [*:null]const ?[*:0]const u8 {
        var i: usize = 0;
        while (i < self.env_count) : (i += 1) {
            buf[i] = &self.env[i];
        }
        buf[i] = null;
        return @ptrCast(buf);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Config initialization" {
    const testing = std.testing;
    const config = try Config.init("/tmp/rootfs");

    // Check rootfs was set
    const rootfs = std.mem.sliceTo(&config.rootfs, 0);
    try testing.expectEqualStrings("/tmp/rootfs", rootfs);

    // Check default cwd
    const cwd = std.mem.sliceTo(&config.cwd, 0);
    try testing.expectEqualStrings("/", cwd);

    // Check default hostname
    try testing.expectEqualStrings("container", config.getHostname());

    // Check default namespaces
    try testing.expect(config.namespaces.pid);
    try testing.expect(config.namespaces.mount);
    try testing.expect(config.namespaces.uts);
    try testing.expect(config.namespaces.ipc);
    try testing.expect(config.namespaces.network); // Network is now enabled by default
}

test "Config add arguments" {
    const testing = std.testing;
    var config = try Config.init("/tmp/rootfs");
    try config.setCommand("/bin/sh");
    try config.addArg("/bin/sh");
    try config.addArg("-c");
    try config.addArg("echo hello");

    try testing.expectEqual(@as(usize, 3), config.args_count);

    const arg0 = std.mem.sliceTo(&config.args[0], 0);
    try testing.expectEqualStrings("/bin/sh", arg0);

    const arg1 = std.mem.sliceTo(&config.args[1], 0);
    try testing.expectEqualStrings("-c", arg1);
}

test "Config add mount" {
    const testing = std.testing;
    var config = try Config.init("/tmp/rootfs");
    try config.addMount("/host/data", "/data", true);

    try testing.expectEqual(@as(usize, 1), config.mounts_count);
    try testing.expect(config.mounts[0].active);
    try testing.expect(config.mounts[0].readonly);

    const src = std.mem.sliceTo(&config.mounts[0].source, 0);
    try testing.expectEqualStrings("/host/data", src);
}

test "Namespaces toCloneFlags" {
    const ns = Namespaces.default;
    const flags = ns.toCloneFlags();
    try std.testing.expect(flags != 0);
}
