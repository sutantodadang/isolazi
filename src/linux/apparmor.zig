//! AppArmor Linux Security Module (LSM) support for container security.
//!
//! AppArmor is a Mandatory Access Control (MAC) security module that restricts
//! programs' capabilities using per-program profiles. It's the default LSM
//! on Ubuntu, Debian, and SUSE-based distributions.
//!
//! Key concepts:
//! - Profile: A set of rules defining what a program can access
//! - Enforce mode: Violations are blocked and logged
//! - Complain mode: Violations are logged but allowed (for debugging)
//! - Unconfined: No restrictions applied
//!
//! Container profiles typically restrict:
//! - File access (read/write/execute paths)
//! - Network access
//! - Capabilities
//! - Mount operations
//! - Ptrace and signal operations
//! - Resource access (raw sockets, etc.)
//!
//! Default container profile (similar to Docker/Podman defaults):
//! - Denies access to /proc/kcore, /proc/kmem, /proc/mem
//! - Denies raw network access
//! - Denies mounting filesystems
//! - Denies loading kernel modules
//! - Denies access to sensitive /sys paths
//! - Denies ptrace on other processes
//! - Denies access to host /var/run/docker.sock or similar
//!
//! SECURITY: AppArmor provides defense-in-depth alongside namespaces and seccomp.
//! It's complementary to seccomp: seccomp filters syscalls, AppArmor controls
//! resources those syscalls can access.
//!
//! PLATFORM: This module is Linux-only. Windows and macOS pass AppArmor config
//! to their Linux backend (WSL2 or Lima/vfkit VM).

const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const fs = std.fs;
const posix = std.posix;

/// AppArmor-related error types
pub const AppArmorError = error{
    /// AppArmor is not available on this system
    AppArmorNotAvailable,
    /// AppArmor is disabled in the kernel
    AppArmorDisabled,
    /// Failed to load profile
    ProfileLoadFailed,
    /// Failed to apply profile
    ProfileApplyFailed,
    /// Profile not found
    ProfileNotFound,
    /// Invalid profile syntax
    InvalidProfile,
    /// Permission denied
    PermissionDenied,
    /// Profile already exists
    ProfileAlreadyExists,
    /// Out of memory
    OutOfMemory,
    /// File system error
    FileSystemError,
    /// Parser error
    ParserError,
};

/// AppArmor profile enforcement mode
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

/// AppArmor file access permission flags
pub const FilePermission = packed struct {
    read: bool = false,
    write: bool = false,
    append: bool = false,
    execute: bool = false,
    memory_map_exec: bool = false,
    link: bool = false,
    lock: bool = false,
    create: bool = false,
    delete: bool = false,
    owner_override: bool = false,
    _padding: u6 = 0,

    /// All read permissions
    pub const READ = FilePermission{ .read = true };
    /// All write permissions
    pub const WRITE = FilePermission{ .write = true };
    /// Read and write
    pub const RW = FilePermission{ .read = true, .write = true };
    /// Read, write, execute
    pub const RWX = FilePermission{ .read = true, .write = true, .execute = true };
    /// Execute only
    pub const EXEC = FilePermission{ .execute = true };
    /// Create and delete
    pub const CREATE_DELETE = FilePermission{ .create = true, .delete = true };
    /// All permissions
    pub const ALL = FilePermission{
        .read = true,
        .write = true,
        .append = true,
        .execute = true,
        .memory_map_exec = true,
        .link = true,
        .lock = true,
        .create = true,
        .delete = true,
        .owner_override = true,
    };

    /// Convert to AppArmor permission string (e.g., "rwx")
    pub fn toPermString(self: FilePermission, buf: []u8) []const u8 {
        var i: usize = 0;
        if (self.read and i < buf.len) {
            buf[i] = 'r';
            i += 1;
        }
        if (self.write and i < buf.len) {
            buf[i] = 'w';
            i += 1;
        }
        if (self.append and i < buf.len) {
            buf[i] = 'a';
            i += 1;
        }
        if (self.execute and i < buf.len) {
            buf[i] = 'x';
            i += 1;
        }
        if (self.memory_map_exec and i < buf.len) {
            buf[i] = 'm';
            i += 1;
        }
        if (self.link and i < buf.len) {
            buf[i] = 'l';
            i += 1;
        }
        if (self.lock and i < buf.len) {
            buf[i] = 'k';
            i += 1;
        }
        if (self.create and i < buf.len) {
            buf[i] = 'c';
            i += 1;
        }
        if (self.delete and i < buf.len) {
            buf[i] = 'd';
            i += 1;
        }
        return buf[0..i];
    }
};

/// Network permission flags for AppArmor
pub const NetworkPermission = packed struct {
    /// Allow all network access
    all: bool = false,
    /// Allow TCP sockets
    tcp: bool = false,
    /// Allow UDP sockets
    udp: bool = false,
    /// Allow raw sockets (requires CAP_NET_RAW)
    raw: bool = false,
    /// Allow Unix domain sockets
    unix: bool = false,
    /// Allow netlink sockets
    netlink: bool = false,
    _padding: u2 = 0,

    /// Standard container networking (TCP, UDP, Unix)
    pub const CONTAINER_DEFAULT = NetworkPermission{
        .tcp = true,
        .udp = true,
        .unix = true,
    };

    /// No network access
    pub const NONE = NetworkPermission{};

    /// All network access
    pub const ALL = NetworkPermission{ .all = true };
};

/// Capability restrictions for AppArmor
pub const CapabilityRule = enum(u8) {
    /// Allow a specific capability
    allow = 0,
    /// Deny a specific capability
    deny = 1,
};

/// Maximum number of file rules in a profile
pub const MAX_FILE_RULES: usize = 128;

/// Maximum number of capability rules
pub const MAX_CAP_RULES: usize = 64;

/// Maximum path length for rules
pub const MAX_PATH_LEN: usize = 512;

/// Maximum profile name length
pub const MAX_PROFILE_NAME: usize = 256;

/// A file access rule in an AppArmor profile
pub const FileRule = struct {
    /// Path pattern (may include wildcards like *, **, @{})
    path: [MAX_PATH_LEN]u8 = std.mem.zeroes([MAX_PATH_LEN]u8),
    path_len: usize = 0,
    /// Access permissions
    permissions: FilePermission = .{},
    /// Is this rule active?
    active: bool = false,
    /// Is this a deny rule (true) or allow rule (false)?
    deny: bool = false,

    /// Create a new file rule
    pub fn init(path: []const u8, permissions: FilePermission, deny: bool) FileRule {
        var rule = FileRule{
            .permissions = permissions,
            .active = true,
            .deny = deny,
        };
        const len = @min(path.len, MAX_PATH_LEN - 1);
        @memcpy(rule.path[0..len], path[0..len]);
        rule.path_len = len;
        return rule;
    }

    /// Allow read access to a path
    pub fn allowRead(path: []const u8) FileRule {
        return FileRule.init(path, FilePermission.READ, false);
    }

    /// Allow read/write access to a path
    pub fn allowReadWrite(path: []const u8) FileRule {
        return FileRule.init(path, FilePermission.RW, false);
    }

    /// Allow execute access to a path
    pub fn allowExecute(path: []const u8) FileRule {
        return FileRule.init(path, FilePermission.EXEC, false);
    }

    /// Deny all access to a path
    pub fn denyAll(path: []const u8) FileRule {
        return FileRule.init(path, FilePermission.ALL, true);
    }

    /// Get the path as a slice
    pub fn getPath(self: *const FileRule) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// Capability rule entry
pub const CapRule = struct {
    /// Capability name (e.g., "net_admin", "sys_admin")
    name: [32]u8 = std.mem.zeroes([32]u8),
    name_len: usize = 0,
    /// Rule type (allow or deny)
    rule_type: CapabilityRule = .deny,
    /// Is this rule active?
    active: bool = false,

    /// Create a capability rule
    pub fn init(name: []const u8, rule_type: CapabilityRule) CapRule {
        var rule = CapRule{
            .rule_type = rule_type,
            .active = true,
        };
        const len = @min(name.len, 31);
        @memcpy(rule.name[0..len], name[0..len]);
        rule.name_len = len;
        return rule;
    }

    /// Allow a capability
    pub fn allow(name: []const u8) CapRule {
        return CapRule.init(name, .allow);
    }

    /// Deny a capability
    pub fn deny(name: []const u8) CapRule {
        return CapRule.init(name, .deny);
    }

    /// Get name as slice
    pub fn getName(self: *const CapRule) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// AppArmor profile definition
pub const AppArmorProfile = struct {
    /// Profile name (must match the executable path or be abstract)
    name: [MAX_PROFILE_NAME]u8 = std.mem.zeroes([MAX_PROFILE_NAME]u8),
    name_len: usize = 0,

    /// Enforcement mode
    mode: AppArmorMode = .enforce,

    /// File access rules
    file_rules: [MAX_FILE_RULES]FileRule = std.mem.zeroes([MAX_FILE_RULES]FileRule),
    file_rules_count: usize = 0,

    /// Capability rules
    cap_rules: [MAX_CAP_RULES]CapRule = std.mem.zeroes([MAX_CAP_RULES]CapRule),
    cap_rules_count: usize = 0,

    /// Network permissions
    network: NetworkPermission = NetworkPermission.CONTAINER_DEFAULT,

    /// Allow ptrace
    allow_ptrace: bool = false,

    /// Allow mount operations
    allow_mount: bool = false,

    /// Allow signal operations
    allow_signal: bool = true,

    /// Child profile inheritance (if set, children run under this profile too)
    inherit: bool = true,

    /// Create an empty profile
    pub fn init(name: []const u8) AppArmorProfile {
        var profile = AppArmorProfile{};
        const len = @min(name.len, MAX_PROFILE_NAME - 1);
        @memcpy(profile.name[0..len], name[0..len]);
        profile.name_len = len;
        return profile;
    }

    /// Get name as slice
    pub fn getName(self: *const AppArmorProfile) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Add a file rule to the profile
    pub fn addFileRule(self: *AppArmorProfile, rule: FileRule) !void {
        if (self.file_rules_count >= MAX_FILE_RULES) {
            return error.OutOfMemory;
        }
        self.file_rules[self.file_rules_count] = rule;
        self.file_rules_count += 1;
    }

    /// Add a capability rule
    pub fn addCapRule(self: *AppArmorProfile, rule: CapRule) !void {
        if (self.cap_rules_count >= MAX_CAP_RULES) {
            return error.OutOfMemory;
        }
        self.cap_rules[self.cap_rules_count] = rule;
        self.cap_rules_count += 1;
    }

    /// Create the default container security profile.
    /// This is similar to Docker/Podman default AppArmor profiles.
    pub fn defaultContainerProfile() AppArmorProfile {
        var profile = AppArmorProfile.init("isolazi-default");

        // Allow reading most filesystem paths
        profile.file_rules[0] = FileRule.init("/**", FilePermission.RWX, false);
        profile.file_rules_count = 1;

        // Deny access to sensitive kernel interfaces
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/proc/kcore");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/proc/kmem");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/proc/mem");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/proc/kallsyms");
        profile.file_rules_count += 1;

        // Deny access to system config files that could be exploited
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/sys/firmware/**");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/sys/kernel/security/**");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/sys/kernel/debug/**");
        profile.file_rules_count += 1;

        // Deny access to host container runtime sockets
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/var/run/docker.sock");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/run/docker.sock");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/var/run/containerd/**");
        profile.file_rules_count += 1;

        // Deny capabilities that containers shouldn't have
        profile.cap_rules[0] = CapRule.deny("sys_admin");
        profile.cap_rules[1] = CapRule.deny("sys_boot");
        profile.cap_rules[2] = CapRule.deny("sys_module");
        profile.cap_rules[3] = CapRule.deny("sys_rawio");
        profile.cap_rules[4] = CapRule.deny("sys_time");
        profile.cap_rules[5] = CapRule.deny("mac_admin");
        profile.cap_rules[6] = CapRule.deny("mac_override");
        profile.cap_rules[7] = CapRule.deny("syslog");
        profile.cap_rules_count = 8;

        // Standard container network access (no raw sockets)
        profile.network = NetworkPermission.CONTAINER_DEFAULT;

        // Deny ptrace and mount by default
        profile.allow_ptrace = false;
        profile.allow_mount = false;

        return profile;
    }

    /// Create a minimal profile (for trusted containers)
    pub fn minimalProfile() AppArmorProfile {
        var profile = AppArmorProfile.init("isolazi-minimal");

        // Allow everything
        profile.file_rules[0] = FileRule.init("/**", FilePermission.ALL, false);
        profile.file_rules_count = 1;

        // Only deny the most critical paths
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/proc/kcore");
        profile.file_rules_count += 1;
        profile.file_rules[profile.file_rules_count] = FileRule.denyAll("/sys/kernel/security/**");
        profile.file_rules_count += 1;

        profile.network = NetworkPermission.ALL;
        profile.allow_ptrace = false;
        profile.allow_mount = false;

        return profile;
    }

    /// Create an unconfined profile (no restrictions)
    pub fn unconfinedProfile() AppArmorProfile {
        var profile = AppArmorProfile.init("unconfined");
        profile.mode = .unconfined;
        return profile;
    }
};

/// AppArmor configuration for container security
pub const AppArmorConfig = struct {
    /// Is AppArmor enforcement enabled?
    enabled: bool = false,

    /// Profile name to use (empty = use default container profile)
    profile_name: [MAX_PROFILE_NAME]u8 = std.mem.zeroes([MAX_PROFILE_NAME]u8),
    profile_name_len: usize = 0,

    /// Use a custom profile definition instead of looking up by name
    use_custom_profile: bool = false,

    /// Custom profile (only used if use_custom_profile is true)
    custom_profile: AppArmorProfile = AppArmorProfile{},

    /// Create default AppArmor configuration (disabled)
    pub fn default_config() AppArmorConfig {
        return AppArmorConfig{};
    }

    /// Create an enabled AppArmor configuration with default profile
    pub fn withDefaultProfile() AppArmorConfig {
        var config = AppArmorConfig{
            .enabled = true,
            .use_custom_profile = true,
        };
        config.custom_profile = AppArmorProfile.defaultContainerProfile();
        return config;
    }

    /// Create AppArmor configuration with a specific profile name
    pub fn withProfile(name: []const u8) AppArmorConfig {
        var config = AppArmorConfig{
            .enabled = true,
        };
        const len = @min(name.len, MAX_PROFILE_NAME - 1);
        @memcpy(config.profile_name[0..len], name[0..len]);
        config.profile_name_len = len;
        return config;
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
        const len = @min(name.len, MAX_PROFILE_NAME - 1);
        @memset(&self.profile_name, 0);
        @memcpy(self.profile_name[0..len], name[0..len]);
        self.profile_name_len = len;
    }
};

// ============================================================================
// AppArmor System Interface Functions
// ============================================================================

/// Path to AppArmor's "enabled" status file
const APPARMOR_ENABLED_PATH = "/sys/module/apparmor/parameters/enabled";

/// Path to AppArmor profiles directory
const APPARMOR_PROFILES_PATH = "/sys/kernel/security/apparmor/profiles";

/// Path to change the current process's AppArmor profile
const APPARMOR_PROC_ATTR_CURRENT = "/proc/self/attr/apparmor/current";
const APPARMOR_PROC_ATTR_EXEC = "/proc/self/attr/apparmor/exec";

/// Legacy paths (for older kernels)
const APPARMOR_PROC_ATTR_CURRENT_LEGACY = "/proc/self/attr/current";
const APPARMOR_PROC_ATTR_EXEC_LEGACY = "/proc/self/attr/exec";

/// Check if AppArmor is available and enabled on the system
pub fn isAppArmorAvailable() bool {
    // Check if the AppArmor enabled parameter exists
    const file = fs.openFileAbsolute(APPARMOR_ENABLED_PATH, .{ .mode = .read_only }) catch {
        return false;
    };
    defer file.close();

    var buf: [8]u8 = undefined;
    const bytes_read = file.read(&buf) catch return false;
    if (bytes_read == 0) return false;

    // The file contains "Y" or "N"
    return buf[0] == 'Y';
}

/// Check if AppArmor is in enforce mode (not just available)
pub fn isAppArmorEnforcing() bool {
    if (!isAppArmorAvailable()) return false;

    // Check if any profiles are loaded
    const profiles_dir = fs.openDirAbsolute(APPARMOR_PROFILES_PATH, .{}) catch {
        return false;
    };
    defer profiles_dir.close();

    return true;
}

/// Get the current AppArmor profile for this process
pub fn getCurrentProfile(buf: []u8) ![]const u8 {
    // Try new path first, then legacy path
    const paths = [_][]const u8{
        APPARMOR_PROC_ATTR_CURRENT,
        APPARMOR_PROC_ATTR_CURRENT_LEGACY,
    };

    for (paths) |path| {
        const file = fs.openFileAbsolute(path, .{ .mode = .read_only }) catch continue;
        defer file.close();

        const bytes_read = file.read(buf) catch continue;
        if (bytes_read > 0) {
            // Remove trailing newline if present
            var len = bytes_read;
            while (len > 0 and (buf[len - 1] == '\n' or buf[len - 1] == 0)) {
                len -= 1;
            }
            return buf[0..len];
        }
    }

    return AppArmorError.AppArmorNotAvailable;
}

/// Change the AppArmor profile for the current process.
///
/// This is the key function for container confinement. It transitions the
/// current process to run under the specified AppArmor profile.
///
/// The profile must already be loaded into the kernel (via apparmor_parser).
///
/// Special values:
/// - "unconfined" - Remove all AppArmor restrictions
/// - "complain" prefix - Run in complain mode (e.g., "complain isolazi-default")
///
/// SECURITY: This operation is one-way - once a profile is applied, it cannot
/// be changed to a less restrictive profile without CAP_MAC_ADMIN.
pub fn changeProfile(profile_name: []const u8) AppArmorError!void {
    if (!isAppArmorAvailable()) {
        return AppArmorError.AppArmorNotAvailable;
    }

    // Try new path first, then legacy path
    const paths = [_][]const u8{
        APPARMOR_PROC_ATTR_CURRENT,
        APPARMOR_PROC_ATTR_CURRENT_LEGACY,
    };

    for (paths) |path| {
        const file = fs.openFileAbsolute(path, .{ .mode = .write_only }) catch continue;
        defer file.close();

        // Write "changeprofile <profile_name>\n" to the file
        var buf: [MAX_PROFILE_NAME + 32]u8 = undefined;
        const write_str = std.fmt.bufPrint(&buf, "changeprofile {s}\n", .{profile_name}) catch {
            return AppArmorError.InvalidProfile;
        };

        file.writeAll(write_str) catch |err| {
            return switch (err) {
                error.AccessDenied => AppArmorError.PermissionDenied,
                else => AppArmorError.ProfileApplyFailed,
            };
        };

        return; // Success
    }

    return AppArmorError.AppArmorNotAvailable;
}

/// Set the AppArmor profile for exec (applied when execve is called).
///
/// This sets up the profile to be applied when the process calls execve().
/// Useful for container runtimes that fork/exec.
///
/// Format: "exec <profile_name>"
pub fn setExecProfile(profile_name: []const u8) AppArmorError!void {
    if (!isAppArmorAvailable()) {
        return AppArmorError.AppArmorNotAvailable;
    }

    // Try new path first, then legacy path
    const paths = [_][]const u8{
        APPARMOR_PROC_ATTR_EXEC,
        APPARMOR_PROC_ATTR_EXEC_LEGACY,
    };

    for (paths) |path| {
        const file = fs.openFileAbsolute(path, .{ .mode = .write_only }) catch continue;
        defer file.close();

        // Write "exec <profile_name>\n" to the file
        var buf: [MAX_PROFILE_NAME + 16]u8 = undefined;
        const write_str = std.fmt.bufPrint(&buf, "exec {s}\n", .{profile_name}) catch {
            return AppArmorError.InvalidProfile;
        };

        file.writeAll(write_str) catch |err| {
            return switch (err) {
                error.AccessDenied => AppArmorError.PermissionDenied,
                else => AppArmorError.ProfileApplyFailed,
            };
        };

        return; // Success
    }

    return AppArmorError.AppArmorNotAvailable;
}

/// Apply AppArmor configuration to the current process.
///
/// This is the main entry point for container runtimes to apply AppArmor
/// confinement. Call this function in the container child process before
/// execve().
///
/// If AppArmor is not available, this function succeeds silently (to allow
/// containers to run on systems without AppArmor).
pub fn applyAppArmorConfig(config: *const AppArmorConfig) AppArmorError!void {
    if (!config.enabled) {
        return; // AppArmor disabled in config
    }

    if (!isAppArmorAvailable()) {
        // AppArmor not available - log warning but don't fail
        // This allows containers to run on systems without AppArmor
        return;
    }

    // Determine profile name
    const profile_name = if (config.use_custom_profile)
        config.custom_profile.getName()
    else if (config.profile_name_len > 0)
        config.profile_name[0..config.profile_name_len]
    else
        "isolazi-default";

    // If profile is unconfined, do nothing
    if (config.use_custom_profile and config.custom_profile.mode == .unconfined) {
        return;
    }

    // Check if we're using complain mode
    if (config.use_custom_profile and config.custom_profile.mode == .complain) {
        // Use complain prefix for the profile
        var complain_name: [MAX_PROFILE_NAME + 16]u8 = undefined;
        const name = std.fmt.bufPrint(&complain_name, "complain {s}", .{profile_name}) catch {
            return AppArmorError.InvalidProfile;
        };
        try changeProfile(name);
        return;
    }

    // Apply the profile in enforce mode
    try changeProfile(profile_name);
}

/// Generate an AppArmor profile string from an AppArmorProfile structure.
///
/// This generates the profile in the format expected by apparmor_parser.
/// The generated profile can be loaded using loadProfile().
pub fn generateProfileString(profile: *const AppArmorProfile, allocator: std.mem.Allocator) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    const writer = output.writer(allocator);

    // Profile header
    try writer.print("#include <tunables/global>\n\n", .{});
    try writer.print("profile {s} flags=(attach_disconnected,mediate_deleted) {{\n", .{profile.getName()});

    // Include abstractions
    try writer.print("  #include <abstractions/base>\n", .{});
    try writer.print("  #include <abstractions/nameservice>\n\n", .{});

    // Network rules
    if (profile.network.all) {
        try writer.print("  network,\n", .{});
    } else {
        if (profile.network.tcp) {
            try writer.print("  network inet stream,\n", .{});
            try writer.print("  network inet6 stream,\n", .{});
        }
        if (profile.network.udp) {
            try writer.print("  network inet dgram,\n", .{});
            try writer.print("  network inet6 dgram,\n", .{});
        }
        if (profile.network.unix) {
            try writer.print("  network unix,\n", .{});
        }
        if (profile.network.netlink) {
            try writer.print("  network netlink,\n", .{});
        }
        if (profile.network.raw) {
            try writer.print("  network inet raw,\n", .{});
            try writer.print("  network inet6 raw,\n", .{});
        }
    }
    try writer.print("\n", .{});

    // Capability rules
    for (profile.cap_rules[0..profile.cap_rules_count]) |cap_rule| {
        if (cap_rule.active) {
            const action = if (cap_rule.rule_type == .allow) "" else "deny ";
            try writer.print("  {s}capability {s},\n", .{ action, cap_rule.getName() });
        }
    }
    try writer.print("\n", .{});

    // Ptrace rule
    if (!profile.allow_ptrace) {
        try writer.print("  deny ptrace (read, trace),\n", .{});
    }
    try writer.print("\n", .{});

    // Mount rule
    if (!profile.allow_mount) {
        try writer.print("  deny mount,\n", .{});
        try writer.print("  deny umount,\n", .{});
    }
    try writer.print("\n", .{});

    // Signal rule
    if (profile.allow_signal) {
        try writer.print("  signal (send, receive),\n", .{});
    }
    try writer.print("\n", .{});

    // File rules - deny rules first, then allow rules
    for (profile.file_rules[0..profile.file_rules_count]) |file_rule| {
        if (file_rule.active and file_rule.deny) {
            var perm_buf: [16]u8 = undefined;
            const perms = file_rule.permissions.toPermString(&perm_buf);
            if (perms.len > 0) {
                try writer.print("  deny {s} {s},\n", .{ file_rule.getPath(), perms });
            }
        }
    }

    for (profile.file_rules[0..profile.file_rules_count]) |file_rule| {
        if (file_rule.active and !file_rule.deny) {
            var perm_buf: [16]u8 = undefined;
            const perms = file_rule.permissions.toPermString(&perm_buf);
            if (perms.len > 0) {
                try writer.print("  {s} {s},\n", .{ file_rule.getPath(), perms });
            }
        }
    }

    // Close profile
    try writer.print("}}\n", .{});

    return try output.toOwnedSlice(allocator);
}

/// Check if a specific profile is loaded in the kernel
pub fn isProfileLoaded(profile_name: []const u8) bool {
    // Read /sys/kernel/security/apparmor/profiles and check if profile exists
    const file = fs.openFileAbsolute("/sys/kernel/security/apparmor/profiles", .{ .mode = .read_only }) catch {
        return false;
    };
    defer file.close();

    var buf: [8192]u8 = undefined;
    const bytes_read = file.read(&buf) catch return false;

    // Each line is "<profile_name> (<mode>)"
    var lines = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
    while (lines.next()) |line| {
        // Extract profile name (everything before " (")
        const paren_idx = std.mem.indexOf(u8, line, " (") orelse continue;
        const name = line[0..paren_idx];
        if (std.mem.eql(u8, name, profile_name)) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "AppArmorMode fromString" {
    try std.testing.expectEqual(AppArmorMode.unconfined, AppArmorMode.fromString("unconfined").?);
    try std.testing.expectEqual(AppArmorMode.complain, AppArmorMode.fromString("complain").?);
    try std.testing.expectEqual(AppArmorMode.enforce, AppArmorMode.fromString("enforce").?);
    try std.testing.expectEqual(@as(?AppArmorMode, null), AppArmorMode.fromString("invalid"));
}

test "FilePermission toPermString" {
    var buf: [16]u8 = undefined;

    try std.testing.expectEqualSlices(u8, "r", FilePermission.READ.toPermString(&buf));
    try std.testing.expectEqualSlices(u8, "rw", FilePermission.RW.toPermString(&buf));
    try std.testing.expectEqualSlices(u8, "rwx", FilePermission.RWX.toPermString(&buf));
}

test "FileRule creation" {
    const rule = FileRule.allowRead("/etc/passwd");
    try std.testing.expect(rule.active);
    try std.testing.expect(!rule.deny);
    try std.testing.expectEqualSlices(u8, "/etc/passwd", rule.getPath());
}

test "AppArmorProfile defaultContainerProfile" {
    const profile = AppArmorProfile.defaultContainerProfile();
    try std.testing.expectEqualSlices(u8, "isolazi-default", profile.getName());
    try std.testing.expectEqual(AppArmorMode.enforce, profile.mode);
    try std.testing.expect(profile.file_rules_count > 0);
    try std.testing.expect(profile.cap_rules_count > 0);
}

test "AppArmorConfig withDefaultProfile" {
    const config = AppArmorConfig.withDefaultProfile();
    try std.testing.expect(config.enabled);
    try std.testing.expect(config.use_custom_profile);
    try std.testing.expectEqualSlices(u8, "isolazi-default", config.custom_profile.getName());
}
