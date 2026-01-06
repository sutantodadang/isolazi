//! SELinux (Security-Enhanced Linux) support for container security.
//!
//! SELinux is a Mandatory Access Control (MAC) security module that provides
//! fine-grained access control based on security labels. It's the default LSM
//! on Red Hat, CentOS, Fedora, and RHEL-based distributions.
//!
//! Key concepts:
//! - Security Context/Label: A string of the form user:role:type:level
//!   Example: "system_u:system_r:container_t:s0:c1,c2"
//! - Domain: The type associated with a process
//! - Type Enforcement: Rules defining which domains can access which types
//! - MCS (Multi-Category Security): Labels for container isolation (s0:c1,c2)
//! - MLS (Multi-Level Security): Hierarchical security levels
//!
//! Container security contexts typically use:
//! - User: system_u (system user)
//! - Role: system_r (system role)
//! - Type: container_t (container domain) or spc_t (super-privileged container)
//! - Level: s0:c1,c2 (MCS categories for isolation between containers)
//!
//! Default container types:
//! - container_t: Standard container processes (restricted)
//! - container_file_t: Container file content
//! - container_runtime_t: Container runtime processes
//! - spc_t: Super-privileged container (less restricted)
//!
//! MCS categories (c1, c2, etc.) provide isolation:
//! - Each container gets unique categories
//! - Containers cannot access files with different categories
//! - Provides container-to-container isolation even if one is compromised
//!
//! SECURITY: SELinux provides defense-in-depth alongside namespaces and seccomp.
//! It's complementary: seccomp filters syscalls, SELinux controls access by label.
//!
//! PLATFORM: This module is Linux-only. Windows and macOS pass SELinux config
//! to their Linux backend (WSL2 or Lima/vfkit VM).

const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const fs = std.fs;
const posix = std.posix;

/// SELinux-related error types
pub const SELinuxError = error{
    /// SELinux is not available on this system
    SELinuxNotAvailable,
    /// SELinux is disabled
    SELinuxDisabled,
    /// Failed to get/set security context
    ContextError,
    /// Invalid security context format
    InvalidContext,
    /// Policy does not allow this operation
    PolicyDenied,
    /// Permission denied
    PermissionDenied,
    /// Type not defined in policy
    TypeNotDefined,
    /// Failed to transition to new context
    TransitionFailed,
    /// Out of memory
    OutOfMemory,
    /// File system error
    FileSystemError,
    /// Label not found
    LabelNotFound,
};

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

/// Maximum length for SELinux context strings
pub const MAX_CONTEXT_LEN: usize = 1024;

/// Maximum number of MCS categories
pub const MAX_MCS_CATEGORIES: usize = 1024;

/// SELinux security context (label)
/// Format: user:role:type:level
/// Example: "system_u:system_r:container_t:s0:c1,c2"
pub const SecurityContext = struct {
    /// SELinux user (e.g., "system_u", "unconfined_u")
    user: [64]u8 = std.mem.zeroes([64]u8),
    user_len: usize = 0,

    /// SELinux role (e.g., "system_r", "object_r")
    role: [64]u8 = std.mem.zeroes([64]u8),
    role_len: usize = 0,

    /// SELinux type/domain (e.g., "container_t", "spc_t")
    type_field: [128]u8 = std.mem.zeroes([128]u8),
    type_len: usize = 0,

    /// Security level (MCS/MLS) (e.g., "s0", "s0:c1,c2", "s0-s15:c0.c1023")
    level: [256]u8 = std.mem.zeroes([256]u8),
    level_len: usize = 0,

    /// Create a security context from components
    pub fn init(user: []const u8, role: []const u8, type_field: []const u8, level: []const u8) SecurityContext {
        var ctx = SecurityContext{};

        const user_len = @min(user.len, 63);
        @memcpy(ctx.user[0..user_len], user[0..user_len]);
        ctx.user_len = user_len;

        const role_len = @min(role.len, 63);
        @memcpy(ctx.role[0..role_len], role[0..role_len]);
        ctx.role_len = role_len;

        const type_len = @min(type_field.len, 127);
        @memcpy(ctx.type_field[0..type_len], type_field[0..type_len]);
        ctx.type_len = type_len;

        const level_len = @min(level.len, 255);
        @memcpy(ctx.level[0..level_len], level[0..level_len]);
        ctx.level_len = level_len;

        return ctx;
    }

    /// Parse a security context string
    /// Format: user:role:type:level or user:role:type
    pub fn parse(context_str: []const u8) !SecurityContext {
        var ctx = SecurityContext{};
        var iter = std.mem.splitScalar(u8, context_str, ':');

        // User
        const user = iter.next() orelse return SELinuxError.InvalidContext;
        const user_len = @min(user.len, 63);
        @memcpy(ctx.user[0..user_len], user[0..user_len]);
        ctx.user_len = user_len;

        // Role
        const role = iter.next() orelse return SELinuxError.InvalidContext;
        const role_len = @min(role.len, 63);
        @memcpy(ctx.role[0..role_len], role[0..role_len]);
        ctx.role_len = role_len;

        // Type
        const type_field = iter.next() orelse return SELinuxError.InvalidContext;
        const type_len = @min(type_field.len, 127);
        @memcpy(ctx.type_field[0..type_len], type_field[0..type_len]);
        ctx.type_len = type_len;

        // Level (optional - may contain colons for MLS ranges like s0:c1,c2-s15:c0.c1023)
        // Collect the rest as the level
        var level_parts: [4][]const u8 = undefined;
        var level_count: usize = 0;
        while (iter.next()) |part| {
            if (level_count < 4) {
                level_parts[level_count] = part;
                level_count += 1;
            }
        }

        if (level_count > 0) {
            // Reconstruct level from parts
            var level_buf: [256]u8 = undefined;
            var level_pos: usize = 0;

            for (level_parts[0..level_count], 0..) |part, i| {
                if (i > 0 and level_pos < 255) {
                    level_buf[level_pos] = ':';
                    level_pos += 1;
                }
                const copy_len = @min(part.len, 255 - level_pos);
                @memcpy(level_buf[level_pos .. level_pos + copy_len], part[0..copy_len]);
                level_pos += copy_len;
            }

            @memcpy(ctx.level[0..level_pos], level_buf[0..level_pos]);
            ctx.level_len = level_pos;
        }

        return ctx;
    }

    /// Get user as slice
    pub fn getUser(self: *const SecurityContext) []const u8 {
        return self.user[0..self.user_len];
    }

    /// Get role as slice
    pub fn getRole(self: *const SecurityContext) []const u8 {
        return self.role[0..self.role_len];
    }

    /// Get type as slice
    pub fn getType(self: *const SecurityContext) []const u8 {
        return self.type_field[0..self.type_len];
    }

    /// Get level as slice
    pub fn getLevel(self: *const SecurityContext) []const u8 {
        return self.level[0..self.level_len];
    }

    /// Format the context as a string
    pub fn toString(self: *const SecurityContext, buf: []u8) ![]const u8 {
        if (self.level_len > 0) {
            return std.fmt.bufPrint(buf, "{s}:{s}:{s}:{s}", .{
                self.getUser(),
                self.getRole(),
                self.getType(),
                self.getLevel(),
            }) catch return SELinuxError.OutOfMemory;
        } else {
            return std.fmt.bufPrint(buf, "{s}:{s}:{s}", .{
                self.getUser(),
                self.getRole(),
                self.getType(),
            }) catch return SELinuxError.OutOfMemory;
        }
    }

    // ========================================================================
    // Common container security contexts
    // ========================================================================

    /// Standard container process context
    /// system_u:system_r:container_t:s0
    pub fn containerProcess() SecurityContext {
        return SecurityContext.init("system_u", "system_r", "container_t", "s0");
    }

    /// Container process with MCS categories for isolation
    pub fn containerProcessWithMCS(category1: u16, category2: u16) SecurityContext {
        var ctx = SecurityContext.init("system_u", "system_r", "container_t", "");
        // Build level string "s0:c<N>,c<M>"
        var level_buf: [64]u8 = undefined;
        const level_str = std.fmt.bufPrint(&level_buf, "s0:c{d},c{d}", .{
            @min(category1, category2),
            @max(category1, category2),
        }) catch return ctx;
        @memcpy(ctx.level[0..level_str.len], level_str);
        ctx.level_len = level_str.len;
        return ctx;
    }

    /// Super-privileged container (spc_t) - less restricted
    pub fn superPrivilegedContainer() SecurityContext {
        return SecurityContext.init("system_u", "system_r", "spc_t", "s0");
    }

    /// Container file context
    pub fn containerFile() SecurityContext {
        return SecurityContext.init("system_u", "object_r", "container_file_t", "s0");
    }

    /// Container runtime context
    pub fn containerRuntime() SecurityContext {
        return SecurityContext.init("system_u", "system_r", "container_runtime_t", "s0");
    }

    /// Unconfined context (no SELinux restrictions)
    pub fn unconfined() SecurityContext {
        return SecurityContext.init("unconfined_u", "unconfined_r", "unconfined_t", "s0");
    }
};

/// SELinux label for file labeling
pub const FileLabel = struct {
    /// Path pattern (supports wildcards)
    path: [512]u8 = std.mem.zeroes([512]u8),
    path_len: usize = 0,

    /// Security context to apply
    context: SecurityContext = SecurityContext{},

    /// Is this label active?
    active: bool = false,

    /// Create a file label
    pub fn init(path: []const u8, context: SecurityContext) FileLabel {
        var label = FileLabel{
            .context = context,
            .active = true,
        };
        const len = @min(path.len, 511);
        @memcpy(label.path[0..len], path[0..len]);
        label.path_len = len;
        return label;
    }

    /// Get path as slice
    pub fn getPath(self: *const FileLabel) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// Maximum number of file labels
pub const MAX_FILE_LABELS: usize = 64;

/// SELinux configuration for container security
pub const SELinuxConfig = struct {
    /// Is SELinux enforcement enabled for this container?
    enabled: bool = false,

    /// Use MCS (Multi-Category Security) for container isolation
    use_mcs: bool = true,

    /// MCS category 1 (0-1023)
    mcs_category1: u16 = 0,

    /// MCS category 2 (0-1023)
    mcs_category2: u16 = 0,

    /// Custom process context (overrides default container_t)
    process_context: SecurityContext = SecurityContext{},
    use_custom_process_context: bool = false,

    /// Custom file context for container filesystem
    file_context: SecurityContext = SecurityContext{},
    use_custom_file_context: bool = false,

    /// File labels to apply within container rootfs
    file_labels: [MAX_FILE_LABELS]FileLabel = std.mem.zeroes([MAX_FILE_LABELS]FileLabel),
    file_labels_count: usize = 0,

    /// Use unconfined context (disable SELinux for this container)
    unconfined: bool = false,

    /// Mount label for container filesystem (usually matches file context)
    mount_label: [MAX_CONTEXT_LEN]u8 = std.mem.zeroes([MAX_CONTEXT_LEN]u8),
    mount_label_len: usize = 0,

    /// Create default SELinux configuration (disabled)
    pub fn default_config() SELinuxConfig {
        return SELinuxConfig{};
    }

    /// Create SELinux configuration with default container context
    pub fn withDefaultContext() SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .use_mcs = true,
        };
    }

    /// Create SELinux configuration with specific MCS categories
    pub fn withMCS(category1: u16, category2: u16) SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .use_mcs = true,
            .mcs_category1 = @min(category1, MAX_MCS_CATEGORIES - 1),
            .mcs_category2 = @min(category2, MAX_MCS_CATEGORIES - 1),
        };
    }

    /// Create SELinux configuration with custom process context
    pub fn withContext(context: SecurityContext) SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .process_context = context,
            .use_custom_process_context = true,
        };
    }

    /// Create unconfined SELinux configuration (no restrictions)
    pub fn unconfinedConfig() SELinuxConfig {
        return SELinuxConfig{
            .enabled = true,
            .unconfined = true,
        };
    }

    /// Get the effective process context
    pub fn getProcessContext(self: *const SELinuxConfig) SecurityContext {
        if (self.unconfined) {
            return SecurityContext.unconfined();
        }
        if (self.use_custom_process_context) {
            return self.process_context;
        }
        if (self.use_mcs) {
            return SecurityContext.containerProcessWithMCS(self.mcs_category1, self.mcs_category2);
        }
        return SecurityContext.containerProcess();
    }

    /// Get the effective file context
    pub fn getFileContext(self: *const SELinuxConfig) SecurityContext {
        if (self.use_custom_file_context) {
            return self.file_context;
        }
        return SecurityContext.containerFile();
    }

    /// Add a file label
    pub fn addFileLabel(self: *SELinuxConfig, path: []const u8, context: SecurityContext) !void {
        if (self.file_labels_count >= MAX_FILE_LABELS) {
            return SELinuxError.OutOfMemory;
        }
        self.file_labels[self.file_labels_count] = FileLabel.init(path, context);
        self.file_labels_count += 1;
    }

    /// Set mount label for container filesystem
    pub fn setMountLabel(self: *SELinuxConfig, label: []const u8) void {
        const len = @min(label.len, MAX_CONTEXT_LEN - 1);
        @memset(&self.mount_label, 0);
        @memcpy(self.mount_label[0..len], label[0..len]);
        self.mount_label_len = len;
    }

    /// Get mount label as slice
    pub fn getMountLabel(self: *const SELinuxConfig) []const u8 {
        if (self.mount_label_len > 0) {
            return self.mount_label[0..self.mount_label_len];
        }
        // Default to file context
        var buf: [MAX_CONTEXT_LEN]u8 = undefined;
        const ctx = self.getFileContext();
        const label = ctx.toString(&buf) catch return "";
        return label;
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
};

// ============================================================================
// SELinux System Interface Functions
// ============================================================================

/// Path to SELinux enforce status
const SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce";

/// Path to SELinux enabled status
const SELINUX_MNT_PATH = "/sys/fs/selinux";

/// Path to check SELinux availability
const SELINUX_FS_PATH = "/proc/filesystems";

/// Path to get/set process context
const SELINUX_PROC_ATTR_CURRENT = "/proc/self/attr/current";
const SELINUX_PROC_ATTR_EXEC = "/proc/self/attr/exec";
const SELINUX_PROC_ATTR_FSCREATE = "/proc/self/attr/fscreate";
const SELINUX_PROC_ATTR_KEYCREATE = "/proc/self/attr/keycreate";
const SELINUX_PROC_ATTR_SOCKCREATE = "/proc/self/attr/sockcreate";

/// Check if SELinux is available on the system
pub fn isSELinuxAvailable() bool {
    // Check if selinuxfs is mounted
    fs.accessAbsolute(SELINUX_MNT_PATH, .{}) catch return false;

    // Check if /proc/filesystems contains selinuxfs
    const file = fs.openFileAbsolute(SELINUX_FS_PATH, .{ .mode = .read_only }) catch return false;
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = file.read(&buf) catch return false;

    // Look for "selinuxfs" in the output
    return std.mem.indexOf(u8, buf[0..bytes_read], "selinuxfs") != null;
}

/// Get the current SELinux enforcement mode
pub fn getSELinuxMode() SELinuxMode {
    if (!isSELinuxAvailable()) {
        return .disabled;
    }

    const file = fs.openFileAbsolute(SELINUX_ENFORCE_PATH, .{ .mode = .read_only }) catch {
        return .disabled;
    };
    defer file.close();

    var buf: [8]u8 = undefined;
    const bytes_read = file.read(&buf) catch return .disabled;
    if (bytes_read == 0) return .disabled;

    // The file contains "1" (enforcing) or "0" (permissive)
    if (buf[0] == '1') {
        return .enforcing;
    } else if (buf[0] == '0') {
        return .permissive;
    }

    return .disabled;
}

/// Check if SELinux is enforcing
pub fn isSELinuxEnforcing() bool {
    return getSELinuxMode() == .enforcing;
}

/// Get the current process's security context
pub fn getCurrentContext(buf: []u8) ![]const u8 {
    const file = fs.openFileAbsolute(SELINUX_PROC_ATTR_CURRENT, .{ .mode = .read_only }) catch {
        return SELinuxError.SELinuxNotAvailable;
    };
    defer file.close();

    const bytes_read = file.read(buf) catch return SELinuxError.ContextError;
    if (bytes_read == 0) return SELinuxError.ContextError;

    // Remove trailing null/newline
    var len = bytes_read;
    while (len > 0 and (buf[len - 1] == '\n' or buf[len - 1] == 0)) {
        len -= 1;
    }

    return buf[0..len];
}

/// Set the current process's security context.
///
/// SECURITY: This is a privileged operation. The target context must be:
/// - Allowed by the current SELinux policy
/// - A valid transition from the current context
///
/// This is the key function for container confinement.
pub fn setCurrentContext(context: *const SecurityContext) SELinuxError!void {
    if (!isSELinuxAvailable()) {
        return SELinuxError.SELinuxNotAvailable;
    }

    var context_str: [MAX_CONTEXT_LEN]u8 = undefined;
    const str = context.toString(&context_str) catch return SELinuxError.InvalidContext;

    const file = fs.openFileAbsolute(SELINUX_PROC_ATTR_CURRENT, .{ .mode = .write_only }) catch {
        return SELinuxError.SELinuxNotAvailable;
    };
    defer file.close();

    file.writeAll(str) catch |err| {
        return switch (err) {
            error.AccessDenied => SELinuxError.PermissionDenied,
            else => SELinuxError.ContextError,
        };
    };
}

/// Set the security context for the next exec.
///
/// This sets the context that will be applied when the process calls execve().
/// The kernel will validate the transition at exec time.
pub fn setExecContext(context: *const SecurityContext) SELinuxError!void {
    if (!isSELinuxAvailable()) {
        return SELinuxError.SELinuxNotAvailable;
    }

    var context_str: [MAX_CONTEXT_LEN]u8 = undefined;
    const str = context.toString(&context_str) catch return SELinuxError.InvalidContext;

    const file = fs.openFileAbsolute(SELINUX_PROC_ATTR_EXEC, .{ .mode = .write_only }) catch {
        return SELinuxError.SELinuxNotAvailable;
    };
    defer file.close();

    file.writeAll(str) catch |err| {
        return switch (err) {
            error.AccessDenied => SELinuxError.PermissionDenied,
            else => SELinuxError.TransitionFailed,
        };
    };
}

/// Set the security context for new files.
///
/// Files created after this call will have the specified context.
pub fn setFileCreateContext(context: *const SecurityContext) SELinuxError!void {
    if (!isSELinuxAvailable()) {
        return SELinuxError.SELinuxNotAvailable;
    }

    var context_str: [MAX_CONTEXT_LEN]u8 = undefined;
    const str = context.toString(&context_str) catch return SELinuxError.InvalidContext;

    const file = fs.openFileAbsolute(SELINUX_PROC_ATTR_FSCREATE, .{ .mode = .write_only }) catch {
        return SELinuxError.SELinuxNotAvailable;
    };
    defer file.close();

    file.writeAll(str) catch |err| {
        return switch (err) {
            error.AccessDenied => SELinuxError.PermissionDenied,
            else => SELinuxError.ContextError,
        };
    };
}

/// Clear the exec context (use default transition rules)
pub fn clearExecContext() SELinuxError!void {
    if (!isSELinuxAvailable()) {
        return SELinuxError.SELinuxNotAvailable;
    }

    const file = fs.openFileAbsolute(SELINUX_PROC_ATTR_EXEC, .{ .mode = .write_only }) catch {
        return SELinuxError.SELinuxNotAvailable;
    };
    defer file.close();

    // Writing empty string clears the exec context
    file.writeAll("") catch return SELinuxError.ContextError;
}

/// Get the security context of a file
pub fn getFileContext(path: []const u8, buf: []u8) ![]const u8 {
    // Use getxattr to get the security.selinux extended attribute
    var path_buf: [512]u8 = undefined;
    if (path.len >= path_buf.len) return SELinuxError.InvalidContext;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const attr_name = "security.selinux";
    var attr_name_buf: [32]u8 = undefined;
    @memcpy(attr_name_buf[0..attr_name.len], attr_name);
    attr_name_buf[attr_name.len] = 0;

    // Use lgetxattr syscall (222 on x86_64)
    const result = linux.syscall5(
        .lgetxattr,
        @intFromPtr(&path_buf),
        @intFromPtr(&attr_name_buf),
        @intFromPtr(buf.ptr),
        buf.len,
        0,
    );

    if (result < 0) {
        return SELinuxError.ContextError;
    }

    const len = @as(usize, @intCast(result));

    // Remove trailing null if present
    if (len > 0 and buf[len - 1] == 0) {
        return buf[0 .. len - 1];
    }

    return buf[0..len];
}

/// Set the security context of a file
pub fn setFileContext(path: []const u8, context: *const SecurityContext) SELinuxError!void {
    var context_str: [MAX_CONTEXT_LEN]u8 = undefined;
    const str = context.toString(&context_str) catch return SELinuxError.InvalidContext;

    var path_buf: [512]u8 = undefined;
    if (path.len >= path_buf.len) return SELinuxError.InvalidContext;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const attr_name = "security.selinux";
    var attr_name_buf: [32]u8 = undefined;
    @memcpy(attr_name_buf[0..attr_name.len], attr_name);
    attr_name_buf[attr_name.len] = 0;

    // Use lsetxattr syscall (223 on x86_64)
    const result = linux.syscall5(
        .lsetxattr,
        @intFromPtr(&path_buf),
        @intFromPtr(&attr_name_buf),
        @intFromPtr(str.ptr),
        str.len,
        0, // flags
    );

    if (@as(isize, @bitCast(result)) < 0) {
        return SELinuxError.ContextError;
    }
}

/// Apply SELinux configuration to the current process.
///
/// This is the main entry point for container runtimes to apply SELinux
/// confinement. Call this function in the container child process before
/// execve().
///
/// If SELinux is not available, this function succeeds silently (to allow
/// containers to run on systems without SELinux).
pub fn applySELinuxConfig(config: *const SELinuxConfig) SELinuxError!void {
    if (!config.enabled) {
        return; // SELinux disabled in config
    }

    if (!isSELinuxAvailable()) {
        // SELinux not available - log warning but don't fail
        // This allows containers to run on systems without SELinux
        return;
    }

    const mode = getSELinuxMode();
    if (mode == .disabled) {
        // SELinux is disabled on this system
        return;
    }

    // Get the effective process context
    const context = config.getProcessContext();

    // Set the exec context (applied at execve)
    setExecContext(&context) catch |err| {
        if (mode == .enforcing) {
            return err;
        }
        // In permissive mode, log but continue
    };

    // Set file creation context if configured
    if (config.use_custom_file_context) {
        setFileCreateContext(&config.file_context) catch |err| {
            if (mode == .enforcing) {
                return err;
            }
        };
    }
}

/// Generate mount options string for SELinux labeling
pub fn generateMountOptions(config: *const SELinuxConfig, buf: []u8) ![]const u8 {
    if (!config.enabled or config.unconfined) {
        return "";
    }

    const context = config.getFileContext();
    var context_str: [MAX_CONTEXT_LEN]u8 = undefined;
    const ctx_str = context.toString(&context_str) catch return SELinuxError.InvalidContext;

    // Generate mount option: context="<context>"
    return std.fmt.bufPrint(buf, "context=\"{s}\"", .{ctx_str}) catch return SELinuxError.OutOfMemory;
}

// ============================================================================
// Tests
// ============================================================================

test "SELinuxMode fromString" {
    try std.testing.expectEqual(SELinuxMode.disabled, SELinuxMode.fromString("disabled").?);
    try std.testing.expectEqual(SELinuxMode.permissive, SELinuxMode.fromString("permissive").?);
    try std.testing.expectEqual(SELinuxMode.enforcing, SELinuxMode.fromString("enforcing").?);
    try std.testing.expectEqual(@as(?SELinuxMode, null), SELinuxMode.fromString("invalid"));
}

test "SecurityContext init" {
    const ctx = SecurityContext.init("system_u", "system_r", "container_t", "s0:c1,c2");
    try std.testing.expectEqualSlices(u8, "system_u", ctx.getUser());
    try std.testing.expectEqualSlices(u8, "system_r", ctx.getRole());
    try std.testing.expectEqualSlices(u8, "container_t", ctx.getType());
    try std.testing.expectEqualSlices(u8, "s0:c1,c2", ctx.getLevel());
}

test "SecurityContext parse" {
    const ctx = try SecurityContext.parse("system_u:system_r:container_t:s0:c1,c2");
    try std.testing.expectEqualSlices(u8, "system_u", ctx.getUser());
    try std.testing.expectEqualSlices(u8, "system_r", ctx.getRole());
    try std.testing.expectEqualSlices(u8, "container_t", ctx.getType());
    try std.testing.expectEqualSlices(u8, "s0:c1,c2", ctx.getLevel());
}

test "SecurityContext toString" {
    const ctx = SecurityContext.containerProcess();
    var buf: [256]u8 = undefined;
    const str = try ctx.toString(&buf);
    try std.testing.expectEqualSlices(u8, "system_u:system_r:container_t:s0", str);
}

test "SecurityContext containerProcessWithMCS" {
    const ctx = SecurityContext.containerProcessWithMCS(100, 200);
    var buf: [256]u8 = undefined;
    const str = try ctx.toString(&buf);
    try std.testing.expectEqualSlices(u8, "system_u:system_r:container_t:s0:c100,c200", str);
}

test "SELinuxConfig withMCS" {
    const config = SELinuxConfig.withMCS(42, 128);
    try std.testing.expect(config.enabled);
    try std.testing.expect(config.use_mcs);
    try std.testing.expectEqual(@as(u16, 42), config.mcs_category1);
    try std.testing.expectEqual(@as(u16, 128), config.mcs_category2);
}

test "SELinuxConfig getProcessContext" {
    var config = SELinuxConfig.withMCS(10, 20);
    const ctx = config.getProcessContext();
    try std.testing.expectEqualSlices(u8, "container_t", ctx.getType());
    try std.testing.expectEqualSlices(u8, "s0:c10,c20", ctx.getLevel());
}
