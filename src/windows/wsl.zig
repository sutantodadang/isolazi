//! Windows backend for Isolazi using WSL2.
//!
//! On Windows, container operations are delegated to WSL2 (Windows Subsystem for Linux).
//! This is the same approach used by Podman and Docker Desktop.
//!
//! Architecture:
//! ```
//! Windows Host                         WSL2 Linux VM
//! ────────────                         ─────────────
//!
//! isolazi.exe ──────────────────────► wsl isolazi run ...
//!     │                                    │
//!     │ (spawn wsl.exe)                    │ (native Linux execution)
//!     │                                    │
//!     └── wait for exit ◄──────────────────┘
//! ```
//!
//! Resource Limits (cgroup v2):
//! Resource limit flags (--memory, --cpus, etc.) are passed through to the
//! Linux isolazi binary running inside WSL2. The Linux binary handles cgroup
//! setup natively via /sys/fs/cgroup (cgroup v2).
//!
//! Requirements:
//! - WSL2 installed and configured
//! - A Linux distribution installed in WSL
//! - Isolazi Linux binary installed in WSL (or built from source)

const std = @import("std");
const builtin = @import("builtin");

pub const WslError = error{
    WslNotAvailable,
    WslExecutionFailed,
    DistroNotFound,
    CommandFailed,
    OutOfMemory,
};

/// AppArmor enforcement mode for WSL passthrough
pub const AppArmorMode = enum {
    /// No AppArmor restrictions
    unconfined,
    /// Log violations but don't enforce
    complain,
    /// Full enforcement (default)
    enforce,

    /// Convert to CLI argument string
    pub fn toCmdString(self: AppArmorMode) []const u8 {
        return switch (self) {
            .unconfined => "unconfined",
            .complain => "complain",
            .enforce => "enforce",
        };
    }
};

/// SELinux type for container processes
pub const SELinuxType = enum {
    /// Standard container type
    container_t,
    /// Container with network access
    container_net_t,
    /// Container with file access
    container_file_t,
    /// Privileged container (use with caution)
    spc_t,
    /// Custom type (use selinux_context instead)
    custom,

    /// Convert to CLI argument string
    pub fn toCmdString(self: SELinuxType) []const u8 {
        return switch (self) {
            .container_t => "container_t",
            .container_net_t => "container_net_t",
            .container_file_t => "container_file_t",
            .spc_t => "spc_t",
            .custom => "custom",
        };
    }
};

/// Linux Security Module (LSM) configuration for WSL passthrough
/// These settings are passed through to the Linux isolazi binary inside WSL2.
pub const LSMConfig = struct {
    // AppArmor settings
    /// Enable AppArmor confinement
    apparmor_enabled: bool = false,
    /// AppArmor profile name (null = use default "isolazi-default")
    apparmor_profile: ?[]const u8 = null,
    /// AppArmor enforcement mode
    apparmor_mode: AppArmorMode = .enforce,

    // SELinux settings
    /// Enable SELinux labeling
    selinux_enabled: bool = false,
    /// Custom SELinux context string (format: user:role:type:level)
    selinux_context: ?[]const u8 = null,
    /// SELinux type for container process
    selinux_type: SELinuxType = .container_t,
    /// MCS category 1 for container isolation (null = auto-assign)
    selinux_mcs_category1: ?u16 = null,
    /// MCS category 2 for container isolation (null = auto-assign)
    selinux_mcs_category2: ?u16 = null,

    /// Check if any LSM is enabled
    pub fn hasLSMEnabled(self: *const LSMConfig) bool {
        return self.apparmor_enabled or self.selinux_enabled;
    }

    /// Build command line arguments for isolazi inside WSL
    /// Caller is responsible for freeing all allocated strings and the ArrayList.
    pub fn toCmdArgs(self: *const LSMConfig, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        var args: std.ArrayList([]const u8) = .empty;
        errdefer {
            // Free any allocated strings on error
            for (args.items) |item| {
                // Only free strings we allocated (the formatted ones)
                if (std.mem.startsWith(u8, item, "c") or std.mem.startsWith(u8, item, "s")) {
                    // Check if it looks like our allocated MCS string
                    var is_allocated = false;
                    for (item) |c| {
                        if (c == ',') {
                            is_allocated = true;
                            break;
                        }
                    }
                    if (is_allocated) allocator.free(item);
                }
            }
            args.deinit(allocator);
        }

        // AppArmor arguments
        if (self.apparmor_enabled) {
            try args.append(allocator, "--apparmor");
            if (self.apparmor_profile) |profile| {
                try args.append(allocator, profile);
            }

            try args.append(allocator, "--apparmor-mode");
            try args.append(allocator, self.apparmor_mode.toCmdString());
        }

        // SELinux arguments
        if (self.selinux_enabled) {
            try args.append(allocator, "--selinux");

            if (self.selinux_context) |context| {
                // Use custom context if provided
                try args.append(allocator, context);
            } else {
                // Build context from type and MCS categories
                try args.append(allocator, "--selinux-type");
                try args.append(allocator, self.selinux_type.toCmdString());

                // Add MCS categories if specified
                if (self.selinux_mcs_category1) |cat1| {
                    try args.append(allocator, "--selinux-mcs");
                    if (self.selinux_mcs_category2) |cat2| {
                        const mcs_str = try std.fmt.allocPrint(allocator, "c{d},c{d}", .{ cat1, cat2 });
                        try args.append(allocator, mcs_str);
                    } else {
                        const mcs_str = try std.fmt.allocPrint(allocator, "c{d}", .{cat1});
                        try args.append(allocator, mcs_str);
                    }
                }
            }
        }

        return args;
    }
};

/// WSL backend configuration
pub const WslConfig = struct {
    /// WSL distribution to use (null = default)
    distro: ?[]const u8 = null,
    /// Path to isolazi binary in WSL (null = assume in PATH)
    isolazi_path: ?[]const u8 = null,
    /// Run as root in WSL
    run_as_root: bool = true,
    /// Linux Security Module configuration (optional)
    lsm_config: ?LSMConfig = null,
};

/// Check if WSL is available on this system.
pub fn isWslAvailable(allocator: std.mem.Allocator) bool {
    // Try to run 'wsl --status' to check if WSL is installed
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "wsl", "--status" },
    }) catch return false;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return result.term.Exited == 0;
}

/// Get list of installed WSL distributions.
pub fn listDistros(allocator: std.mem.Allocator) ![][]const u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "wsl", "--list", "--quiet" },
    });

    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        allocator.free(result.stdout);
        return WslError.WslNotAvailable;
    }

    // Parse the output (one distro per line)
    var distros: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (distros.items) |d| allocator.free(d);
        distros.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        // Skip empty lines and trim whitespace
        const trimmed = std.mem.trim(u8, line, " \t\r\n\x00");
        if (trimmed.len > 0) {
            const copy = try allocator.dupe(u8, trimmed);
            try distros.append(allocator, copy);
        }
    }

    allocator.free(result.stdout);
    return try distros.toOwnedSlice(allocator);
}

/// Execute a command in WSL.
pub fn execInWsl(
    allocator: std.mem.Allocator,
    config: WslConfig,
    args: []const []const u8,
) !u8 {
    // Build the WSL command
    var wsl_args: std.ArrayList([]const u8) = .empty;
    defer wsl_args.deinit(allocator);

    // Track dynamically allocated strings for cleanup
    var dynamic_allocs: std.ArrayList([]const u8) = .empty;
    defer {
        for (dynamic_allocs.items) |alloc| {
            allocator.free(alloc);
        }
        dynamic_allocs.deinit(allocator);
    }

    try wsl_args.append(allocator, "wsl");

    // Add distribution flag if specified
    if (config.distro) |distro| {
        try wsl_args.append(allocator, "-d");
        try wsl_args.append(allocator, distro);
    }

    // Run as root if requested
    if (config.run_as_root) {
        try wsl_args.append(allocator, "-u");
        try wsl_args.append(allocator, "root");
    }

    // Add the command to execute
    if (config.isolazi_path) |path| {
        try wsl_args.append(allocator, path);
    } else {
        try wsl_args.append(allocator, "isolazi");
    }

    // Add all the original arguments
    for (args) |arg| {
        try wsl_args.append(allocator, arg);
    }

    // Add LSM configuration arguments if provided
    if (config.lsm_config) |lsm| {
        var lsm_args = try lsm.toCmdArgs(allocator);
        defer lsm_args.deinit(allocator);

        for (lsm_args.items) |lsm_arg| {
            // Check if this is a dynamically allocated string (contains comma for MCS)
            var is_dynamic = false;
            for (lsm_arg) |c| {
                if (c == ',') {
                    is_dynamic = true;
                    break;
                }
            }
            if (is_dynamic or (lsm_arg.len > 1 and lsm_arg[0] == 'c' and std.ascii.isDigit(lsm_arg[1]))) {
                // This is an allocated MCS string, need to dupe and track
                const duped = try allocator.dupe(u8, lsm_arg);
                try dynamic_allocs.append(allocator, duped);
                try wsl_args.append(allocator, duped);
            } else {
                try wsl_args.append(allocator, lsm_arg);
            }
        }
    }

    // Execute WSL
    var child = std.process.Child.init(wsl_args.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
}

/// Run Isolazi command through WSL.
/// This is the main entry point for Windows users.
pub fn runThroughWsl(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    config: WslConfig,
) !u8 {
    // Check if WSL is available
    if (!isWslAvailable(allocator)) {
        return WslError.WslNotAvailable;
    }

    // Execute the command in WSL
    return execInWsl(allocator, config, args);
}

/// Convert a Windows path to WSL path.
/// Example: C:\Users\foo\rootfs -> /mnt/c/Users/foo/rootfs
pub fn windowsToWslPath(allocator: std.mem.Allocator, windows_path: []const u8) ![]u8 {
    if (windows_path.len < 2) {
        return allocator.dupe(u8, windows_path);
    }

    // Check for drive letter pattern (e.g., C:\ or C:/)
    if (windows_path.len >= 2 and windows_path[1] == ':') {
        const drive_letter = std.ascii.toLower(windows_path[0]);

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Add /mnt/<drive>/
        try result.appendSlice(allocator, "/mnt/");
        try result.append(allocator, drive_letter);

        // Add rest of path, converting backslashes
        const rest = if (windows_path.len > 2) windows_path[2..] else "";
        for (rest) |c| {
            if (c == '\\') {
                try result.append(allocator, '/');
            } else {
                try result.append(allocator, c);
            }
        }

        return try result.toOwnedSlice(allocator);
    }

    // Not a Windows absolute path, just convert backslashes
    const result = try allocator.dupe(u8, windows_path);
    for (result) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    return result;
}

/// Convert a WSL path to Windows path.
/// Example: /mnt/c/Users/foo/rootfs -> C:\Users\foo\rootfs
pub fn wslToWindowsPath(allocator: std.mem.Allocator, wsl_path: []const u8) ![]u8 {
    // Check for /mnt/<drive>/ pattern
    if (wsl_path.len >= 6 and std.mem.startsWith(u8, wsl_path, "/mnt/")) {
        const drive_letter = std.ascii.toUpper(wsl_path[5]);

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Add drive letter
        try result.append(allocator, drive_letter);
        try result.appendSlice(allocator, ":");

        // Add rest of path, converting forward slashes
        const rest = if (wsl_path.len > 6) wsl_path[6..] else "";
        for (rest) |c| {
            if (c == '/') {
                try result.append(allocator, '\\');
            } else {
                try result.append(allocator, c);
            }
        }

        if (result.items.len == 2) {
            try result.append(allocator, '\\');
        }

        return try result.toOwnedSlice(allocator);
    }

    // Not a WSL mount path, return as-is
    return allocator.dupe(u8, wsl_path);
}

// =============================================================================
// Tests
// =============================================================================

test "windowsToWslPath converts drive letters" {
    const allocator = std.testing.allocator;

    const path1 = try windowsToWslPath(allocator, "C:\\Users\\test");
    defer allocator.free(path1);
    try std.testing.expectEqualStrings("/mnt/c/Users/test", path1);

    const path2 = try windowsToWslPath(allocator, "D:\\data\\rootfs");
    defer allocator.free(path2);
    try std.testing.expectEqualStrings("/mnt/d/data/rootfs", path2);
}

test "wslToWindowsPath converts mount paths" {
    const allocator = std.testing.allocator;

    const path1 = try wslToWindowsPath(allocator, "/mnt/c/Users/test");
    defer allocator.free(path1);
    try std.testing.expectEqualStrings("C:\\Users\\test", path1);

    const path2 = try wslToWindowsPath(allocator, "/mnt/d/data/rootfs");
    defer allocator.free(path2);
    try std.testing.expectEqualStrings("D:\\data\\rootfs", path2);
}
