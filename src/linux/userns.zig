//! User Namespace Support for Rootless Containers
//!
//! This module provides user namespace (CLONE_NEWUSER) functionality for
//! running containers without root privileges. Key features:
//!
//! - UID/GID mapping between host and container
//! - Unprivileged namespace creation
//! - setgroups deny for security
//!
//! User namespaces allow a process to have different UIDs inside vs outside
//! the namespace. This enables rootless containers where:
//! - The user appears as root (UID 0) inside the container
//! - But is actually an unprivileged user on the host
//!
//! Security considerations:
//! - Writing to uid_map/gid_map requires CAP_SETUID/CAP_SETGID in parent namespace
//! - For unprivileged users, only single UID/GID mapping is allowed
//! - setgroups must be set to "deny" before writing gid_map for unprivileged users
//!
//! See: user_namespaces(7), newuidmap(1), newgidmap(1)

const std = @import("std");
const builtin = @import("builtin");

/// User namespace error types
pub const UserNamespaceError = error{
    /// Failed to write to uid_map
    UidMapFailed,
    /// Failed to write to gid_map
    GidMapFailed,
    /// Failed to write to setgroups
    SetgroupsFailed,
    /// Invalid UID/GID mapping specification
    InvalidMapping,
    /// Not enough privileges for the requested mapping
    InsufficientPrivileges,
    /// User namespace not supported
    NotSupported,
    /// Process not found
    ProcessNotFound,
    /// Generic I/O error
    IoError,
    /// Permission denied
    PermissionDenied,
};

/// Maximum number of UID/GID mappings per namespace
/// Linux allows up to 340 mappings as of kernel 5.x
pub const MAX_MAPPINGS = 32;

/// A single UID or GID mapping entry
/// Maps a range of IDs from the parent namespace to the child namespace
pub const IdMapping = struct {
    /// First ID in the child (container) namespace
    container_id: u32 = 0,
    /// First ID in the parent (host) namespace
    host_id: u32 = 0,
    /// Number of consecutive IDs to map
    count: u32 = 1,

    /// Create a simple 1:1 mapping (e.g., map host UID 1000 to container UID 0)
    pub fn single(host_id: u32, container_id: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = 1,
        };
    }

    /// Create a range mapping
    pub fn range(host_id: u32, container_id: u32, count: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
        };
    }

    /// Format as string for writing to uid_map/gid_map
    /// Format: "container_id host_id count\n"
    pub fn format(self: IdMapping, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{d} {d} {d}\n", .{
            self.container_id,
            self.host_id,
            self.count,
        }) catch return UserNamespaceError.InvalidMapping;
    }

    /// Parse a mapping string like "0:1000:1" (container:host:count)
    pub fn parse(spec: []const u8) !IdMapping {
        var iter = std.mem.splitScalar(u8, spec, ':');

        const container_str = iter.next() orelse return UserNamespaceError.InvalidMapping;
        const host_str = iter.next() orelse return UserNamespaceError.InvalidMapping;
        const count_str = iter.next() orelse "1";

        const container_id = std.fmt.parseInt(u32, container_str, 10) catch
            return UserNamespaceError.InvalidMapping;
        const host_id = std.fmt.parseInt(u32, host_str, 10) catch
            return UserNamespaceError.InvalidMapping;
        const count = std.fmt.parseInt(u32, count_str, 10) catch
            return UserNamespaceError.InvalidMapping;

        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
        };
    }
};

/// User namespace configuration
pub const UserNamespaceConfig = struct {
    /// UID mappings (container UID -> host UID)
    uid_mappings: [MAX_MAPPINGS]IdMapping = std.mem.zeroes([MAX_MAPPINGS]IdMapping),
    uid_count: usize = 0,

    /// GID mappings (container GID -> host GID)
    gid_mappings: [MAX_MAPPINGS]IdMapping = std.mem.zeroes([MAX_MAPPINGS]IdMapping),
    gid_count: usize = 0,

    /// Whether to deny setgroups (required for unprivileged gid_map writes)
    deny_setgroups: bool = true,

    /// Whether running in rootless mode (unprivileged)
    rootless: bool = false,

    /// Create a default configuration for rootless operation
    /// Maps current user to root (UID/GID 0) inside container
    pub fn defaultRootless() UserNamespaceConfig {
        var config = UserNamespaceConfig{
            .rootless = true,
            .deny_setgroups = true,
        };

        // Get current user's UID/GID
        const uid = std.os.linux.getuid();
        const gid = std.os.linux.getgid();

        // Map current user to root inside container
        config.uid_mappings[0] = IdMapping.single(uid, 0);
        config.uid_count = 1;

        config.gid_mappings[0] = IdMapping.single(gid, 0);
        config.gid_count = 1;

        return config;
    }

    /// Create a configuration with full UID/GID range mapping (requires root)
    pub fn fullMapping() UserNamespaceConfig {
        var config = UserNamespaceConfig{
            .rootless = false,
            .deny_setgroups = false,
        };

        // Map full range: container 0-65535 to host 0-65535
        config.uid_mappings[0] = IdMapping.range(0, 0, 65536);
        config.uid_count = 1;

        config.gid_mappings[0] = IdMapping.range(0, 0, 65536);
        config.gid_count = 1;

        return config;
    }

    /// Add a UID mapping
    pub fn addUidMapping(self: *UserNamespaceConfig, mapping: IdMapping) !void {
        if (self.uid_count >= MAX_MAPPINGS) {
            return UserNamespaceError.InvalidMapping;
        }
        self.uid_mappings[self.uid_count] = mapping;
        self.uid_count += 1;
    }

    /// Add a GID mapping
    pub fn addGidMapping(self: *UserNamespaceConfig, mapping: IdMapping) !void {
        if (self.gid_count >= MAX_MAPPINGS) {
            return UserNamespaceError.InvalidMapping;
        }
        self.gid_mappings[self.gid_count] = mapping;
        self.gid_count += 1;
    }

    /// Get active UID mappings
    pub fn getUidMappings(self: *const UserNamespaceConfig) []const IdMapping {
        return self.uid_mappings[0..self.uid_count];
    }

    /// Get active GID mappings
    pub fn getGidMappings(self: *const UserNamespaceConfig) []const IdMapping {
        return self.gid_mappings[0..self.gid_count];
    }
};

/// Write UID/GID mappings for a process in a new user namespace.
/// This must be called from the parent process after the child has been created
/// with CLONE_NEWUSER but before the child proceeds.
///
/// Parameters:
///   pid: PID of the child process in the new user namespace
///   config: User namespace configuration with mappings
pub fn setupUserNamespace(pid: std.posix.pid_t, config: *const UserNamespaceConfig) UserNamespaceError!void {
    if (builtin.os.tag != .linux) {
        return UserNamespaceError.NotSupported;
    }

    // Step 1: Write "deny" to /proc/PID/setgroups if required
    // This must be done BEFORE writing to gid_map for unprivileged users
    if (config.deny_setgroups) {
        try writeSetgroups(pid, .deny);
    }

    // Step 2: Write UID mappings to /proc/PID/uid_map
    if (config.uid_count > 0) {
        try writeUidMap(pid, config.getUidMappings());
    }

    // Step 3: Write GID mappings to /proc/PID/gid_map
    if (config.gid_count > 0) {
        try writeGidMap(pid, config.getGidMappings());
    }
}

/// Setgroups mode for user namespace
pub const SetgroupsMode = enum {
    allow,
    deny,
};

/// Write to /proc/PID/setgroups
fn writeSetgroups(pid: std.posix.pid_t, mode: SetgroupsMode) UserNamespaceError!void {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/setgroups", .{pid}) catch
        return UserNamespaceError.IoError;

    const content: []const u8 = switch (mode) {
        .allow => "allow\n",
        .deny => "deny\n",
    };

    const file = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        return switch (err) {
            error.FileNotFound => UserNamespaceError.ProcessNotFound,
            error.AccessDenied => UserNamespaceError.PermissionDenied,
            else => UserNamespaceError.IoError,
        };
    };
    defer file.close();

    file.writeAll(content) catch return UserNamespaceError.SetgroupsFailed;
}

/// Write UID mappings to /proc/PID/uid_map
fn writeUidMap(pid: std.posix.pid_t, mappings: []const IdMapping) UserNamespaceError!void {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/uid_map", .{pid}) catch
        return UserNamespaceError.IoError;

    const file = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        return switch (err) {
            error.FileNotFound => UserNamespaceError.ProcessNotFound,
            error.AccessDenied => UserNamespaceError.PermissionDenied,
            else => UserNamespaceError.IoError,
        };
    };
    defer file.close();

    // Write all mappings
    var buf: [256]u8 = undefined;
    for (mappings) |mapping| {
        const line = mapping.format(&buf) catch return UserNamespaceError.UidMapFailed;
        file.writeAll(line) catch return UserNamespaceError.UidMapFailed;
    }
}

/// Write GID mappings to /proc/PID/gid_map
fn writeGidMap(pid: std.posix.pid_t, mappings: []const IdMapping) UserNamespaceError!void {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/gid_map", .{pid}) catch
        return UserNamespaceError.IoError;

    const file = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        return switch (err) {
            error.FileNotFound => UserNamespaceError.ProcessNotFound,
            error.AccessDenied => UserNamespaceError.PermissionDenied,
            else => UserNamespaceError.IoError,
        };
    };
    defer file.close();

    // Write all mappings
    var buf: [256]u8 = undefined;
    for (mappings) |mapping| {
        const line = mapping.format(&buf) catch return UserNamespaceError.GidMapFailed;
        file.writeAll(line) catch return UserNamespaceError.GidMapFailed;
    }
}

/// Check if the current process can create user namespaces
pub fn canCreateUserNamespace() bool {
    if (builtin.os.tag != .linux) {
        return false;
    }

    // Check /proc/sys/kernel/unprivileged_userns_clone
    // If it exists and is 0, unprivileged user namespaces are disabled
    const file = std.fs.openFileAbsolute("/proc/sys/kernel/unprivileged_userns_clone", .{}) catch {
        // File doesn't exist, assume enabled (older kernels)
        return true;
    };
    defer file.close();

    var buf: [8]u8 = undefined;
    const len = file.read(&buf) catch return true;

    if (len > 0 and buf[0] == '0') {
        return false;
    }

    return true;
}

/// Check if the current user is root (UID 0)
pub fn isRoot() bool {
    if (builtin.os.tag != .linux) {
        return false;
    }
    return std.os.linux.getuid() == 0;
}

/// Get the current user's UID
pub fn getCurrentUid() u32 {
    if (builtin.os.tag != .linux) {
        return 0;
    }
    return std.os.linux.getuid();
}

/// Get the current user's GID
pub fn getCurrentGid() u32 {
    if (builtin.os.tag != .linux) {
        return 0;
    }
    return std.os.linux.getgid();
}

/// Generate shell commands for setting up user namespace (for use in WSL2/Lima)
/// Returns commands that can be prepended to the unshare command
pub fn generateUserNamespaceCommands(config: *const UserNamespaceConfig, allocator: std.mem.Allocator) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    // For rootless mode with simple mapping, use --map-root-user
    if (config.rootless and config.uid_count == 1 and config.gid_count == 1) {
        const uid_map = config.uid_mappings[0];
        const gid_map = config.gid_mappings[0];

        if (uid_map.container_id == 0 and uid_map.count == 1 and
            gid_map.container_id == 0 and gid_map.count == 1)
        {
            // Simple case: map current user to root
            try buf.appendSlice("--map-root-user ");
            return try buf.toOwnedSlice();
        }
    }

    // Complex mappings need newuidmap/newgidmap or manual /proc writes
    // For now, return empty and let the caller handle it
    return try buf.toOwnedSlice();
}

// =============================================================================
// Tests
// =============================================================================

test "IdMapping.single" {
    const mapping = IdMapping.single(1000, 0);
    try std.testing.expectEqual(@as(u32, 0), mapping.container_id);
    try std.testing.expectEqual(@as(u32, 1000), mapping.host_id);
    try std.testing.expectEqual(@as(u32, 1), mapping.count);
}

test "IdMapping.range" {
    const mapping = IdMapping.range(1000, 0, 65536);
    try std.testing.expectEqual(@as(u32, 0), mapping.container_id);
    try std.testing.expectEqual(@as(u32, 1000), mapping.host_id);
    try std.testing.expectEqual(@as(u32, 65536), mapping.count);
}

test "IdMapping.parse" {
    const mapping = try IdMapping.parse("0:1000:1");
    try std.testing.expectEqual(@as(u32, 0), mapping.container_id);
    try std.testing.expectEqual(@as(u32, 1000), mapping.host_id);
    try std.testing.expectEqual(@as(u32, 1), mapping.count);
}

test "IdMapping.format" {
    const mapping = IdMapping.single(1000, 0);
    var buf: [64]u8 = undefined;
    const result = try mapping.format(&buf);
    try std.testing.expectEqualStrings("0 1000 1\n", result);
}

test "UserNamespaceConfig.addUidMapping" {
    var config = UserNamespaceConfig{};
    try config.addUidMapping(IdMapping.single(1000, 0));
    try std.testing.expectEqual(@as(usize, 1), config.uid_count);
}
