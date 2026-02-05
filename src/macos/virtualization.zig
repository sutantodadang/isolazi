//! Apple Virtualization.framework bindings for running Linux VMs.
//!
//! This module provides a Zig interface to Apple's Virtualization framework,
//! enabling lightweight Linux VMs for container execution on macOS.
//!
//! The Virtualization framework (introduced in macOS 11) provides:
//! - Hardware-accelerated virtualization
//! - VirtIO device support (block, network, console)
//! - Rosetta 2 support for x86_64 on Apple Silicon
//!
//! Key concepts:
//! - VZVirtualMachine: The main VM object
//! - VZVirtualMachineConfiguration: VM settings (CPU, memory, devices)
//! - VZLinuxBootLoader: Boots Linux kernel directly
//! - VZVirtioNetworkDeviceConfiguration: NAT or bridged networking
//! - VZVirtioBlockDeviceConfiguration: Disk images
//!
//! PLATFORM: This module is macOS-only (darwin).

const std = @import("std");
const builtin = @import("builtin");
const config_mod = @import("../config/config.zig");

pub const VirtualizationError = error{
    VirtualizationNotAvailable,
    VMCreationFailed,
    VMStartFailed,
    VMStopFailed,
    ConfigurationInvalid,
    KernelNotFound,
    InitramfsNotFound,
    DiskImageNotFound,
    NetworkConfigFailed,
    OutOfMemory,
    CommandFailed,
    Timeout,
};

/// Resource limits configuration for macOS (passed to Linux VM)
/// These are applied using cgroup v2 inside the Lima/vfkit Linux VM.
pub const ResourceLimitsConfig = struct {
    /// Memory limit in bytes (0 = unlimited)
    memory_max: u64 = 0,
    /// CPU quota in microseconds per period (0 = unlimited)
    cpu_quota: u64 = 0,
    /// CPU period in microseconds (default 100ms)
    cpu_period: u64 = 100000,
    /// CPU weight (1-10000, default 100)
    cpu_weight: u32 = 100,
    /// I/O weight (1-10000, default 100)
    io_weight: u32 = 100,
    /// OOM score adjustment (-1000 to 1000)
    oom_score_adj: i16 = 0,
    /// Disable OOM killer
    oom_kill_disable: bool = false,

    /// Check if any limits are configured
    pub fn hasLimits(self: *const ResourceLimitsConfig) bool {
        return self.memory_max > 0 or
            self.cpu_quota > 0 or
            self.cpu_weight != 100 or
            self.io_weight != 100 or
            self.oom_score_adj != 0 or
            self.oom_kill_disable;
    }

    /// Build command line arguments for isolazi inside the VM
    pub fn toCmdArgs(self: *const ResourceLimitsConfig, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        var args: std.ArrayList([]const u8) = .empty;

        if (self.memory_max > 0) {
            try args.append(allocator, "--memory");
            const mem_str = try std.fmt.allocPrint(allocator, "{d}", .{self.memory_max});
            try args.append(allocator, mem_str);
        }

        if (self.cpu_quota > 0) {
            try args.append(allocator, "--cpu-quota");
            const quota_str = try std.fmt.allocPrint(allocator, "{d}", .{self.cpu_quota});
            try args.append(allocator, quota_str);

            try args.append(allocator, "--cpu-period");
            const period_str = try std.fmt.allocPrint(allocator, "{d}", .{self.cpu_period});
            try args.append(allocator, period_str);
        }

        if (self.cpu_weight != 100) {
            try args.append(allocator, "--cpu-weight");
            const weight_str = try std.fmt.allocPrint(allocator, "{d}", .{self.cpu_weight});
            try args.append(allocator, weight_str);
        }

        if (self.io_weight != 100) {
            try args.append(allocator, "--io-weight");
            const io_str = try std.fmt.allocPrint(allocator, "{d}", .{self.io_weight});
            try args.append(allocator, io_str);
        }

        if (self.oom_score_adj != 0) {
            try args.append(allocator, "--oom-score-adj");
            const oom_str = try std.fmt.allocPrint(allocator, "{d}", .{self.oom_score_adj});
            try args.append(allocator, oom_str);
        }

        if (self.oom_kill_disable) {
            try args.append(allocator, "--oom-kill-disable");
        }

        return args;
    }
};

/// AppArmor enforcement mode for macOS VM passthrough
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

/// SELinux type for container processes in VM
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

/// Linux Security Module (LSM) configuration for macOS VM passthrough.
/// These settings are passed through to the Linux isolazi binary running
/// inside the Lima or vfkit virtual machine.
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

    /// Build command line arguments for isolazi inside the VM.
    /// Caller is responsible for freeing all allocated strings and the ArrayList.
    pub fn toCmdArgs(self: *const LSMConfig, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        var args: std.ArrayList([]const u8) = .empty;
        errdefer args.deinit(allocator);

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

    /// Build shell script snippet for applying LSM configuration.
    /// This generates the necessary commands for the Lima shell script.
    pub fn toShellScript(self: *const LSMConfig, script: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        // Note: In Lima, we use direct unshare/chroot rather than calling isolazi binary,
        // so we need to apply LSM using shell commands if available.
        // This uses aa-exec for AppArmor and runcon for SELinux.

        if (self.apparmor_enabled) {
            // Use aa-exec to run under an AppArmor profile
            try script.appendSlice(allocator, "if command -v aa-exec >/dev/null 2>&1 && [ -f /sys/module/apparmor/parameters/enabled ]; then ");
            try script.appendSlice(allocator, "AA_EXEC_ARGS=\"");

            // Add profile argument
            if (self.apparmor_profile) |profile| {
                try script.appendSlice(allocator, "-p ");
                try script.appendSlice(allocator, profile);
            } else {
                try script.appendSlice(allocator, "-p isolazi-default");
            }

            // Add mode-specific arguments
            switch (self.apparmor_mode) {
                .complain => try script.appendSlice(allocator, " --complain"),
                .unconfined => {
                    // For unconfined mode, don't use aa-exec
                    try script.appendSlice(allocator, "\"; AA_EXEC_PREFIX=\"\"; ");
                    try script.appendSlice(allocator, "else AA_EXEC_PREFIX=\"\"; fi; ");
                    return;
                },
                .enforce => {}, // Default behavior
            }

            try script.appendSlice(allocator, "\"; AA_EXEC_PREFIX=\"aa-exec $AA_EXEC_ARGS -- \"; ");
            try script.appendSlice(allocator, "else AA_EXEC_PREFIX=\"\"; fi; ");
        }

        if (self.selinux_enabled) {
            // Use runcon to run with SELinux context
            try script.appendSlice(allocator, "if command -v runcon >/dev/null 2>&1 && [ -d /sys/fs/selinux ]; then ");
            try script.appendSlice(allocator, "SELINUX_CONTEXT=\"");

            if (self.selinux_context) |context| {
                try script.appendSlice(allocator, context);
            } else {
                // Build context from type and MCS
                try script.appendSlice(allocator, "system_u:system_r:");
                try script.appendSlice(allocator, self.selinux_type.toCmdString());
                try script.appendSlice(allocator, ":s0");

                // Add MCS categories if specified
                if (self.selinux_mcs_category1) |cat1| {
                    var cat1_buf: [16]u8 = undefined;
                    const cat1_str = std.fmt.bufPrint(&cat1_buf, ":c{d}", .{cat1}) catch "";
                    try script.appendSlice(allocator, cat1_str);

                    if (self.selinux_mcs_category2) |cat2| {
                        var cat2_buf: [16]u8 = undefined;
                        const cat2_str = std.fmt.bufPrint(&cat2_buf, ",c{d}", .{cat2}) catch "";
                        try script.appendSlice(allocator, cat2_str);
                    }
                }
            }

            try script.appendSlice(allocator, "\"; RUNCON_PREFIX=\"runcon $SELINUX_CONTEXT \"; ");
            try script.appendSlice(allocator, "else RUNCON_PREFIX=\"\"; fi; ");
        }
    }
};

/// Check if Apple Virtualization is available on this system.
/// Returns true on macOS 12.0+ with virtualization entitlement.
pub fn isVirtualizationAvailable(allocator: std.mem.Allocator) bool {
    if (builtin.os.tag != .macos) {
        return false;
    }

    // Check macOS version (need 12.0+)
    // Use sw_vers to get the version
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sw_vers", "-productVersion" },
    }) catch return false;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return false;
    }

    // Parse version (e.g., "14.2.1" or "12.0")
    const version_str = std.mem.trim(u8, result.stdout, " \t\r\n");
    var parts = std.mem.splitScalar(u8, version_str, '.');
    const major_str = parts.next() orelse return false;
    const major = std.fmt.parseInt(u32, major_str, 10) catch return false;

    // Virtualization.framework requires macOS 11.0+ for basic support,
    // but Linux VM support was improved in 12.0
    return major >= 12;
}

/// Get the default isolazi data directory on macOS
pub fn getDataDir(allocator: std.mem.Allocator) ![]const u8 {
    // Use ~/Library/Application Support/isolazi on macOS
    const home = std.posix.getenv("HOME") orelse return error.HomeNotFound;
    return try std.fmt.allocPrint(
        allocator,
        "{s}/Library/Application Support/isolazi",
        .{home},
    );
}

/// Check if Lima is installed and likely to work.
pub fn isLimaInstalled(allocator: std.mem.Allocator) bool {
    const lima_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "which", "limactl" },
    }) catch return false;

    defer allocator.free(lima_result.stdout);
    defer allocator.free(lima_result.stderr);

    if (lima_result.term.Exited == 0 and lima_result.stdout.len > 0) {
        return true;
    }

    return false;
}

/// Environment variable pair
pub const RunResult = struct {
    exit_code: u8,
    pid: ?std.process.Child.Id = null,
};

pub const EnvPair = struct {
    key: []const u8,
    value: []const u8,
};

/// Volume mount pair
pub const VolumePair = struct {
    host_path: []const u8,
    container_path: []const u8,
};

/// Port mapping for container networking
pub const PortMapping = struct {
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

    pub const Protocol = enum {
        tcp,
        udp,
    };
};

/// Run using Lima (Linux virtual machines on macOS)
/// Lima provides a seamless Linux VM experience with automatic file sharing.
/// Resource limits are applied inside the Linux VM using cgroup v2.
pub fn runWithLima(
    allocator: std.mem.Allocator,
    _: []const u8, // kernel_path - Lima manages its own kernel
    rootfs_path: []const u8,
    command: []const []const u8,
    env_vars: []const EnvPair,
    volumes: []const VolumePair,
    port_mappings: []const PortMapping,
    rootless: bool,
    detach: bool,
    restart_policy: config_mod.Config.RestartPolicy,
    stdout_path: ?[]const u8,
    stderr_path: ?[]const u8,
) !RunResult {
    return runWithLimaEx(allocator, "", rootfs_path, command, env_vars, volumes, port_mappings, rootless, detach, restart_policy, null, null, stdout_path, stderr_path);
}

/// Extended Lima runner with resource limits and LSM support
pub fn runWithLimaEx(
    allocator: std.mem.Allocator,
    _: []const u8, // kernel_path - Lima manages its own kernel
    rootfs_path: []const u8,
    command: []const []const u8,
    env_vars: []const EnvPair,
    volumes: []const VolumePair,
    port_mappings: []const PortMapping,
    rootless: bool,
    detach: bool,
    restart_policy: config_mod.Config.RestartPolicy,
    resource_limits: ?*const ResourceLimitsConfig,
    lsm_config: ?*const LSMConfig,
    stdout_path: ?[]const u8,
    stderr_path: ?[]const u8,
) !RunResult {
    // Check Lima status
    const status = checkLimaStatus(allocator);
    switch (status) {
        .Running => {}, // Proceed
        .NotExists => {
            // Create and start the VM
            _ = try createLimaInstance(allocator);
            return runWithLimaEx(allocator, "", rootfs_path, command, env_vars, volumes, port_mappings, rootless, detach, restart_policy, resource_limits, lsm_config, stdout_path, stderr_path);
        },

        .Stopped, .Unknown => {
            // VM exists but stopped (or unknown), try to start it
            const start_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "limactl", "start", "isolazi" },
            }) catch return VirtualizationError.VMStartFailed;

            defer allocator.free(start_result.stdout);
            defer allocator.free(start_result.stderr);

            if (start_result.term.Exited != 0) {
                // If it failed and status was Unknown, maybe it didn't exist?
                // But checkLimaStatus handles NotExists separately.
                // So this is a real start failure.
                return VirtualizationError.VMStartFailed;
            }
        },
    }

    // Build the lima shell command
    // Lima automatically mounts the home directory, so we can access rootfs directly
    var lima_args: std.ArrayList([]const u8) = .empty;
    defer lima_args.deinit(allocator);

    // Keep track of all allocations to free after spawn
    var dynamic_allocs: std.ArrayList([]const u8) = .empty;
    defer {
        for (dynamic_allocs.items) |alloc| {
            allocator.free(alloc);
        }
        dynamic_allocs.deinit(allocator);
    }

    try lima_args.append(allocator, "limactl");
    try lima_args.append(allocator, "shell");
    try lima_args.append(allocator, "isolazi");
    try lima_args.append(allocator, "--");
    try lima_args.append(allocator, "sudo");

    // Use env -i to clear inherited environment and set fresh vars
    try lima_args.append(allocator, "env");
    try lima_args.append(allocator, "-i");

    // Set minimal required environment
    try lima_args.append(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    try lima_args.append(allocator, "HOME=/root");
    try lima_args.append(allocator, "TERM=xterm");
    try lima_args.append(allocator, "LANG=C.UTF-8");

    // Tag the process for easy stopping/lookup
    const container_id_dir = std.fs.path.dirname(rootfs_path) orelse rootfs_path;
    const parent_dir = std.fs.path.basename(container_id_dir);

    // Add user environment variables (these override defaults)
    for (env_vars) |env| {
        const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
        try dynamic_allocs.append(allocator, env_str);
        try lima_args.append(allocator, env_str);
    }

    // Build a shell script that handles all setup and runs the container command
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(allocator);

    // Put the tag at the very beginning to be visible in ps output
    try script.appendSlice(allocator, "# ISOLAZI_ID=");
    try script.appendSlice(allocator, parent_dir);
    try script.appendSlice(allocator, "\n");

    // Mount essential filesystems
    try script.appendSlice(allocator, "mkdir -p ");
    try script.appendSlice(allocator, rootfs_path);
    try script.appendSlice(allocator, "/proc ");
    try script.appendSlice(allocator, rootfs_path);
    try script.appendSlice(allocator, "/sys ");
    try script.appendSlice(allocator, rootfs_path);
    try script.appendSlice(allocator, "/dev && ");

    // Create runtime directories
    try script.appendSlice(allocator, "mkdir -p ");
    try script.appendSlice(allocator, rootfs_path);
    try script.appendSlice(allocator, "/run ");
    try script.appendSlice(allocator, rootfs_path);
    try script.appendSlice(allocator, "/tmp && ");

    // Create volume directories on host
    for (volumes) |vol| {
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, vol.container_path);
        try script.appendSlice(allocator, " && ");
    }

    // Set up port forwarding using iptables DNAT (for when host_port != container_port)
    for (port_mappings) |port| {
        if (port.host_port == port.container_port) continue;
        const proto_str = if (port.protocol == .udp) "udp" else "tcp";
        var host_port_buf: [8]u8 = undefined;
        const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
        var cont_port_buf: [8]u8 = undefined;
        const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";

        // PREROUTING rule for incoming traffic
        try script.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ");
        try script.appendSlice(allocator, proto_str);
        try script.appendSlice(allocator, " --dport ");
        try script.appendSlice(allocator, host_port_str);
        try script.appendSlice(allocator, " -j REDIRECT --to-port ");
        try script.appendSlice(allocator, cont_port_str);
        try script.appendSlice(allocator, " 2>/dev/null; ");

        // OUTPUT rule for localhost traffic
        try script.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ");
        try script.appendSlice(allocator, proto_str);
        try script.appendSlice(allocator, " --dport ");
        try script.appendSlice(allocator, host_port_str);
        try script.appendSlice(allocator, " -j REDIRECT --to-port ");
        try script.appendSlice(allocator, cont_port_str);
        try script.appendSlice(allocator, " 2>/dev/null; ");
    }

    // Write setup script for inside the namespace
    const setup_script_path = try std.fmt.allocPrint(allocator, "{s}/setup.sh", .{container_id_dir});
    try dynamic_allocs.append(allocator, setup_script_path);

    var setup_script: std.ArrayList(u8) = .empty;
    defer setup_script.deinit(allocator);

    try setup_script.appendSlice(allocator, "#!/bin/sh\n");

    // Safety: prevent propagation back to host
    try setup_script.appendSlice(allocator, "mount --make-rprivate /\n");

    // Mount proc (which unshare --mount-proc mounted to /proc in new ns) to destination
    try setup_script.appendSlice(allocator, "mount --bind /proc \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "/proc\"\n");

    // Mount sysfs
    try setup_script.appendSlice(allocator, "mount -t sysfs sysfs \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "/sys\"\n");

    // Mount dev
    try setup_script.appendSlice(allocator, "mount --bind /dev \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "/dev\"\n");

    // Mount tmpfs run
    try setup_script.appendSlice(allocator, "mount -t tmpfs tmpfs \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "/run\"\n");

    // Mount tmpfs tmp
    try setup_script.appendSlice(allocator, "mount -t tmpfs tmpfs \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "/tmp\"\n");

    // Handle volume mounts
    for (volumes) |vol| {
        try setup_script.appendSlice(allocator, "mount --bind \"");
        try setup_script.appendSlice(allocator, vol.host_path);
        try setup_script.appendSlice(allocator, "\" \"");
        try setup_script.appendSlice(allocator, rootfs_path);
        try setup_script.appendSlice(allocator, vol.container_path);
        try setup_script.appendSlice(allocator, "\"\n");
    }

    // Add LSM configuration setup
    if (lsm_config) |lsm| {
        try lsm.toShellScript(&setup_script, allocator);
    } else {
        try setup_script.appendSlice(allocator, "AA_EXEC_PREFIX=\"\"; RUNCON_PREFIX=\"\";\n");
    }

    // Exec chroot with LSM wrappers
    try setup_script.appendSlice(allocator, "exec $AA_EXEC_PREFIX $RUNCON_PREFIX chroot \"");
    try setup_script.appendSlice(allocator, rootfs_path);
    try setup_script.appendSlice(allocator, "\" /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin ");

    // Add env vars
    for (env_vars) |env| {
        try setup_script.appendSlice(allocator, env.key);
        try setup_script.append(allocator, '=');
        try setup_script.appendSlice(allocator, env.value);
        try setup_script.append(allocator, ' ');
    }

    // Add the command
    for (command) |arg| {
        try setup_script.appendSlice(allocator, arg);
        try setup_script.append(allocator, ' ');
    }

    const setup_file = try std.fs.cwd().createFile(setup_script_path, .{ .mode = 0o755 });
    defer setup_file.close();
    try setup_file.writeAll(setup_script.items);

    // Finalize main run script
    try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc -- /bin/sh \"");
    try script.appendSlice(allocator, setup_script_path);
    try script.appendSlice(allocator, "\"");

    // Write script to file
    const run_script_path = try std.fmt.allocPrint(allocator, "{s}/run.sh", .{container_id_dir});
    try dynamic_allocs.append(allocator, run_script_path);
    const run_file = try std.fs.cwd().createFile(run_script_path, .{ .mode = 0o755 });
    defer run_file.close();
    try run_file.writeAll(script.items);

    // Now construct the execution command based on restart policy
    if (restart_policy == .no) {
        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, run_script_path);
    } else {
        // Use systemd-run
        try lima_args.append(allocator, "systemd-run");

        // Unit name: isolazi-<id>
        const unit_name = try std.fmt.allocPrint(allocator, "isolazi-{s}", .{parent_dir});
        try dynamic_allocs.append(allocator, unit_name);
        try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--unit={s}", .{unit_name}));
        try dynamic_allocs.append(allocator, lima_args.items[lima_args.items.len - 1]);

        try lima_args.append(allocator, "--service-type=simple");

        // Restart policy
        // systemd-run uses --property=Restart=... for transient units
        // Mapping:
        // no -> no
        // always -> always
        // on-failure -> on-failure
        // unless-stopped -> always (systemd doesn't have unless-stopped, but strict always behaves similarly for units)
        const policy_str = switch (restart_policy) {
            .no => "no",
            .always => "always",
            .on_failure => "on-failure",
            .unless_stopped => "always",
        };
        try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--property=Restart={s}", .{policy_str}));
        try dynamic_allocs.append(allocator, lima_args.items[lima_args.items.len - 1]);

        // Default TasksMax might be too low for some containers/distros
        try lima_args.append(allocator, "--property=TasksMax=infinity");
        try lima_args.append(allocator, "--property=Delegate=yes");
        try lima_args.append(allocator, "--property=LimitNOFILE=infinity");
        try lima_args.append(allocator, "--property=LimitNPROC=infinity");

        // Working directory (rootfs? or container dir?)
        // Let's use container dir so we can find things if needed
        try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--working-directory={s}", .{container_id_dir}));
        try dynamic_allocs.append(allocator, lima_args.items[lima_args.items.len - 1]);

        // Logs: Use strict file path for output logging.
        // systemd-run doesn't support -p StandardOutput=file:... easily with appending,
        // but StandardOutput=append:/path works in recent systemd.
        // Lima usually runs recent Ubuntu (24.04), so it should work.
        // We need to ensure the path is correct. stdout_path passed here is relative or absolute on host.
        // Lima mounts home, so if log path is in home, it works.
        // However, stdout_path is optional.

        if (stdout_path) |path| {
            try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--property=StandardOutput=append:{s}", .{path}));
            try dynamic_allocs.append(allocator, lima_args.items[lima_args.items.len - 1]);
        }

        if (stderr_path) |path| {
            try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--property=StandardError=append:{s}", .{path}));
            try dynamic_allocs.append(allocator, lima_args.items[lima_args.items.len - 1]);
        }

        // Collect logs/status
        // Note: With StandardOutput=file, --collect might not be strict requirement for logs,
        // but it helps keep the unit loaded for status check.
        try lima_args.append(allocator, "--collect");

        // The command to run
        try lima_args.append(allocator, "--");
        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, run_script_path);
    }

    // Execute via Lima
    var child = std.process.Child.init(lima_args.items, allocator);

    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    if (!detach) {
        child.stdin_behavior = .Inherit;
    }

    // Save current stdout/stderr to restore later
    const saved_stdout = try std.posix.dup(std.posix.STDOUT_FILENO);
    defer std.posix.close(saved_stdout);
    const saved_stderr = try std.posix.dup(std.posix.STDERR_FILENO);
    defer std.posix.close(saved_stderr);

    // Redirect stdout
    if (stdout_path) |path| {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = false });
        defer f.close();
        try std.posix.dup2(f.handle, std.posix.STDOUT_FILENO);
    } else if (detach) {
        const null_fd = try std.posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
        defer std.posix.close(null_fd);
        try std.posix.dup2(null_fd, std.posix.STDOUT_FILENO);
    }

    // Redirect stderr
    if (stderr_path) |path| {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = false });
        defer f.close();
        try std.posix.dup2(f.handle, std.posix.STDERR_FILENO);
    } else if (detach) {
        const null_fd = try std.posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
        defer std.posix.close(null_fd);
        try std.posix.dup2(null_fd, std.posix.STDERR_FILENO);
    }

    try child.spawn();

    // Restore original stdout/stderr for parent
    try std.posix.dup2(saved_stdout, std.posix.STDOUT_FILENO);
    try std.posix.dup2(saved_stderr, std.posix.STDERR_FILENO);

    if (detach) {
        return RunResult{ .exit_code = 0, .pid = child.id };
    } else {
        const term = try child.wait();
        const exit_code: u8 = switch (term) {
            .Exited => |code| code,
            .Signal => |sig| @truncate(128 +% sig),
            else => 1,
        };
        return RunResult{ .exit_code = exit_code, .pid = child.id };
    }
}

/// Create a Lima instance configured for isolazi
fn createLimaInstance(allocator: std.mem.Allocator) !void {
    // Create a minimal Lima configuration for isolazi
    const lima_config =
        \\# Lima configuration for isolazi container runtime
        \\images:
        \\  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
        \\    arch: "x86_64"
        \\  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
        \\    arch: "aarch64"
        \\cpus: 2
        \\memory: "2GiB"
        \\disk: "10GiB"
        \\mounts:
        \\  - location: "~"
        \\    writable: true
        \\  - location: "/tmp/isolazi"
        \\    writable: true
        \\provision:
        \\  - mode: system
        \\    script: |
        \\      apt-get update && apt-get install -y iptables uidmap procps
        \\containerd:
        \\  system: false
        \\  user: false
        \\portForwards:
        \\  - guestIP: "0.0.0.0"
        \\    guestPortRange: [1, 65535]
        \\    hostIP: "127.0.0.1"
    ;

    // Write config to temporary file
    const data_dir = try getDataDir(allocator);
    defer allocator.free(data_dir);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/isolazi.yaml", .{data_dir});
    defer allocator.free(config_path);

    // Create directory if needed
    std.fs.makeDirAbsolute(data_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };

    // Write config
    const file = try std.fs.createFileAbsolute(config_path, .{});
    defer file.close();
    try file.writeAll(lima_config);

    // Create Lima instance
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "create", "--name=isolazi", config_path },
    }) catch return VirtualizationError.VMCreationFailed;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return VirtualizationError.VMCreationFailed;
    }

    // Start the instance
    const start_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "start", "isolazi" },
    }) catch return VirtualizationError.VMStartFailed;

    defer allocator.free(start_result.stdout);
    defer allocator.free(start_result.stderr);

    if (start_result.term.Exited != 0) {
        return VirtualizationError.VMStartFailed;
    }
}

pub fn stopInLima(allocator: std.mem.Allocator, container_id: []const u8) !void {
    // 1. Try to stop systemd service first (if it exists)
    // The unit name is isolazi-<id>
    const systemctl_cmd = try std.fmt.allocPrint(allocator, "sudo systemctl stop isolazi-{s}", .{container_id});
    defer allocator.free(systemctl_cmd);

    const sc_res = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sh", "-c", systemctl_cmd },
    });
    if (sc_res) |res| {
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    } else |_| {}

    // 2. Fallback: Find PIDs via /proc/*/environ using grep
    // Use grep -a -l to find files containing the ID, then extract PID
    const find_cmd = try std.fmt.allocPrint(allocator, "sudo grep -l -a 'ISOLAZI_ID={s}' /proc/[0-9]*/environ 2>/dev/null | cut -d/ -f3", .{container_id});
    defer allocator.free(find_cmd);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sh", "-c", find_cmd },
    }) catch return;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var it = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
    while (it.next()) |pid_str| {
        const kill_res = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sudo", "kill", "-TERM", pid_str },
        }) catch continue;
        allocator.free(kill_res.stdout);
        allocator.free(kill_res.stderr);
    }
}

/// Refresh Lima port forwarding by signaling the host agent to re-scan ports.
/// This is called after stopping a container to ensure port bindings are released.
pub fn refreshLimaPortForwarding(allocator: std.mem.Allocator) void {
    // Send SIGHUP to Lima's hostagent to trigger port forwarding refresh
    if (std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "pkill", "-HUP", "-f", "limactl.*hostagent.*isolazi" },
    })) |res| {
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    } else |_| {}

    // Also try to signal the ssh tunnel process that handles port forwarding
    if (std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "pkill", "-HUP", "-f", "ssh.*lima.*isolazi" },
    })) |res| {
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    } else |_| {}
}

pub fn isContainerAliveInLima(allocator: std.mem.Allocator, container_id: []const u8) !bool {
    // First check if Lima is actually running
    if (!isLimaRunning(allocator)) return false;

    // 1. Check systemd status first
    const systemctl_cmd = try std.fmt.allocPrint(allocator, "sudo systemctl is-active isolazi-{s}", .{container_id});
    defer allocator.free(systemctl_cmd);

    const sc_res = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sh", "-c", systemctl_cmd },
    }) catch {
        // Fallthrough on error
        return false;
    };
    defer allocator.free(sc_res.stdout);
    defer allocator.free(sc_res.stderr);

    const status = std.mem.trim(u8, sc_res.stdout, " \t\r\n");
    if (std.mem.eql(u8, status, "active") or std.mem.eql(u8, status, "activating")) {
        return true;
    }

    // 2. Fallback: Search /proc/*/environ for the tag using grep
    // Use grep -a -q to search in binary files directly and exit on first match
    const grep_cmd = try std.fmt.allocPrint(allocator, "sudo grep -a -q 'ISOLAZI_ID={s}' /proc/[0-9]*/environ", .{container_id});
    defer allocator.free(grep_cmd);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sh", "-c", grep_cmd },
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return result.term.Exited == 0;
}

/// Stop the Lima instance
pub fn stopLimaInstance(allocator: std.mem.Allocator) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "stop", "isolazi" },
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
}

/// Check if Lima instance exists and is running
pub fn isLimaRunning(allocator: std.mem.Allocator) bool {
    return checkLimaStatus(allocator) == .Running;
}

/// Ensure the Lima VM is created and running
pub fn ensureVMRunning(allocator: std.mem.Allocator) !void {
    const status = checkLimaStatus(allocator);
    switch (status) {
        .Running => return,
        .NotExists => {
            // Create and start the VM
            try createLimaInstance(allocator);
        },
        .Stopped, .Unknown => {
            // VM exists but stopped (or unknown), try to start it
            const start_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "limactl", "start", "isolazi" },
            }) catch return VirtualizationError.VMStartFailed;

            defer allocator.free(start_result.stdout);
            defer allocator.free(start_result.stderr);

            if (start_result.term.Exited != 0) {
                return VirtualizationError.VMStartFailed;
            }
        },
    }
}

pub const LimaStatus = enum {
    Running,
    Stopped,
    NotExists,
    Unknown,
};

pub fn checkLimaStatus(allocator: std.mem.Allocator) LimaStatus {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "list", "--format={{.Status}}", "isolazi" },
    }) catch return .Unknown;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return .NotExists;
    }

    const status = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (std.mem.eql(u8, status, "Running")) return .Running;
    if (std.mem.eql(u8, status, "Stopped")) return .Stopped;
    return .Unknown; // e.g. "Starting"
}

/// Start a stopped container by re-executing its run.sh script within Lima
pub fn startContainer(
    allocator: std.mem.Allocator,
    container_id: []const u8,
    info: *const @import("../container/state.zig").ContainerInfo,
) !void {
    // Ensure VM is running
    try ensureVMRunning(allocator);

    // Get home directory for constructing paths
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        return VirtualizationError.ConfigurationInvalid;
    };
    defer allocator.free(home);

    // Construct the run script path
    const run_script_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.isolazi/containers/{s}/run.sh",
        .{ home, container_id },
    );
    defer allocator.free(run_script_path);

    // Verify script exists (via Lima test -f)
    const check_cmd = try std.fmt.allocPrint(allocator, "test -f \"{s}\"", .{run_script_path});
    defer allocator.free(check_cmd);

    const check_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "shell", "isolazi", "sh", "-c", check_cmd },
    }) catch return VirtualizationError.CommandFailed;
    defer allocator.free(check_result.stdout);
    defer allocator.free(check_result.stderr);

    if (check_result.term.Exited != 0) {
        return VirtualizationError.ConfigurationInvalid; // run.sh doesn't exist
    }

    // Execute the run script based on restart policy
    var lima_args: std.ArrayList([]const u8) = .empty;
    defer lima_args.deinit(allocator);

    try lima_args.append(allocator, "limactl");
    try lima_args.append(allocator, "shell");
    try lima_args.append(allocator, "isolazi");

    // Environment variables for the container tag - need sudo for mounts
    try lima_args.append(allocator, "--");
    try lima_args.append(allocator, "sudo");
    try lima_args.append(allocator, "env");

    const isolazi_id_env = try std.fmt.allocPrint(allocator, "ISOLAZI_ID={s}", .{container_id});
    defer allocator.free(isolazi_id_env);
    try lima_args.append(allocator, isolazi_id_env);

    // Track dynamic allocations that need cleanup after run()
    var dynamic_allocs: std.ArrayList([]const u8) = .empty;
    defer {
        for (dynamic_allocs.items) |ptr| allocator.free(ptr);
        dynamic_allocs.deinit(allocator);
    }

    if (info.restart_policy == .no) {
        // Simple execution - run in background via sh -c
        const log_path = try std.fmt.allocPrint(allocator, "{s}/.isolazi/containers/{s}/stdout.log", .{ home, container_id });
        try dynamic_allocs.append(allocator, log_path);
        const bg_cmd = try std.fmt.allocPrint(allocator, "ISOLAZI_ID={s} sh \"{s}\" >> \"{s}\" 2>&1 &", .{ container_id, run_script_path, log_path });
        try dynamic_allocs.append(allocator, bg_cmd);

        // Clear the existing args and build a simpler command
        lima_args.clearAndFree(allocator);
        try lima_args.append(allocator, "limactl");
        try lima_args.append(allocator, "shell");
        try lima_args.append(allocator, "isolazi");
        try lima_args.append(allocator, "--");
        try lima_args.append(allocator, "sudo");
        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, "-c");
        try lima_args.append(allocator, bg_cmd);
    } else {
        // Use systemd-run for restart policies
        try lima_args.append(allocator, "systemd-run");

        const unit_name = try std.fmt.allocPrint(allocator, "--unit=isolazi-{s}", .{container_id});
        try dynamic_allocs.append(allocator, unit_name);
        try lima_args.append(allocator, unit_name);

        try lima_args.append(allocator, "--service-type=simple");

        const policy_str = switch (info.restart_policy) {
            .no => "no",
            .always => "always",
            .on_failure => "on-failure",
            .unless_stopped => "always",
        };
        const restart_prop = try std.fmt.allocPrint(allocator, "--property=Restart={s}", .{policy_str});
        try dynamic_allocs.append(allocator, restart_prop);
        try lima_args.append(allocator, restart_prop);

        try lima_args.append(allocator, "--property=TasksMax=infinity");
        try lima_args.append(allocator, "--property=Delegate=yes");
        try lima_args.append(allocator, "--property=LimitNOFILE=infinity");
        try lima_args.append(allocator, "--property=LimitNPROC=infinity");

        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, run_script_path);
    }

    // Execute
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = lima_args.items,
    }) catch return VirtualizationError.CommandFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Update container state via ContainerManager
    var manager = @import("../container/state.zig").ContainerManager.init(allocator) catch {
        return VirtualizationError.ConfigurationInvalid;
    };
    defer manager.deinit();

    manager.updateState(container_id, .running, null, null) catch {};

    // Refresh port forwarding to re-establish bindings
    if (info.ports.len > 0) {
        refreshLimaPortForwarding(allocator);
    }
}
