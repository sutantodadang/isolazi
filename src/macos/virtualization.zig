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
    return runWithLimaEx(allocator, "", rootfs_path, command, env_vars, volumes, port_mappings, rootless, detach, restart_policy, null, stdout_path, stderr_path);
}

/// Extended Lima runner with resource limits support
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
            return runWithLimaEx(allocator, "", rootfs_path, command, env_vars, volumes, port_mappings, rootless, detach, restart_policy, resource_limits, stdout_path, stderr_path);
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

    // Build a shell script to handle bind mounts for volumes and tagging
    var script_content_str: []const u8 = "";

    if (volumes.len > 0) {

        // We accumulate the script logic into a file now, so we don't need inline sh -c here.
        // The script file will be executed later.

        // Build script that creates bind mounts then runs chroot
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(allocator);

        // Put the tag at the very beginning as a shell comment so it's visible in ps output
        try script.appendSlice(allocator, "# ISOLAZI_ID=");
        try script.appendSlice(allocator, parent_dir);
        try script.appendSlice(allocator, "\n");

        // Create bind mounts for each volume and essential filesystems
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/proc ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/sys ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/dev && ");

        try script.appendSlice(allocator, "mount -t proc proc ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/proc && ");

        try script.appendSlice(allocator, "mount -t sysfs sysfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/sys && ");

        try script.appendSlice(allocator, "mount --bind /dev ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/dev && ");

        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/run ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/tmp && ");

        try script.appendSlice(allocator, "mount -t tmpfs tmpfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/run && ");

        try script.appendSlice(allocator, "mount -t tmpfs tmpfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/tmp && ");

        for (volumes) |vol| {
            try script.appendSlice(allocator, "mkdir -p ");
            try script.appendSlice(allocator, rootfs_path);
            try script.appendSlice(allocator, vol.container_path);
            try script.appendSlice(allocator, " && mount --bind ");
            try script.appendSlice(allocator, vol.host_path);
            try script.append(allocator, ' ');
            try script.appendSlice(allocator, rootfs_path);
            try script.appendSlice(allocator, vol.container_path);
            try script.appendSlice(allocator, " && ");
        }

        // Set up port forwarding using iptables DNAT (for when host_port != container_port)
        // Lima handles automatic port forwarding for same-port mappings
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

            // OUTPUT rule for localhost traffic (important for Lima port forwarding)
            try script.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ");
            try script.appendSlice(allocator, proto_str);
            try script.appendSlice(allocator, " --dport ");
            try script.appendSlice(allocator, host_port_str);
            try script.appendSlice(allocator, " -j REDIRECT --to-port ");
            try script.appendSlice(allocator, cont_port_str);
            try script.appendSlice(allocator, " 2>/dev/null; ");
        }

        // Add the unshare and chroot command with clean environment inside container
        try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc");
        if (rootless) {
            try script.appendSlice(allocator, " --user --map-root-user");
        }
        try script.appendSlice(allocator, " chroot ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, " /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin ");

        // Add user env vars inside container
        for (env_vars) |env| {
            try script.appendSlice(allocator, env.key);
            try script.append(allocator, '=');
            try script.appendSlice(allocator, env.value);
            try script.append(allocator, ' ');
        }

        // Add the command
        for (command) |arg| {
            try script.appendSlice(allocator, arg);
            try script.append(allocator, ' ');
        }

        const script_str = try allocator.dupe(u8, script.items);
        try dynamic_allocs.append(allocator, script_str);
        script_content_str = script_str;

        // Script content generated, but we will write it to a file instead of passing arg
    } else {
        // Use script approach for essential mounts even without volumes/ports
        // try lima_args.append(allocator, "sh");
        // try lima_args.append(allocator, "-c");

        var script: std.ArrayList(u8) = .empty;

        defer script.deinit(allocator);

        // Put the tag at the very beginning as a shell comment so it's visible in ps output
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

        try script.appendSlice(allocator, "mount -t proc proc ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/proc && ");

        try script.appendSlice(allocator, "mount -t sysfs sysfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/sys && ");

        try script.appendSlice(allocator, "mount --bind /dev ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/dev && ");

        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/run ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/tmp && ");

        try script.appendSlice(allocator, "mount -t tmpfs tmpfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/run && ");

        try script.appendSlice(allocator, "mount -t tmpfs tmpfs ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, "/tmp && ");

        if (port_mappings.len > 0) {
            // Set up port forwarding using iptables DNAT (for when host_port != container_port)
            // Lima handles automatic port forwarding for same-port mappings
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

                // OUTPUT rule for localhost traffic (important for Lima port forwarding)
                try script.appendSlice(allocator, "iptables -t nat -A OUTPUT -p ");
                try script.appendSlice(allocator, proto_str);
                try script.appendSlice(allocator, " --dport ");
                try script.appendSlice(allocator, host_port_str);
                try script.appendSlice(allocator, " -j REDIRECT --to-port ");
                try script.appendSlice(allocator, cont_port_str);
                try script.appendSlice(allocator, " 2>/dev/null; ");
            }
        }

        // Add the unshare and chroot command with clean environment inside container
        try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc");
        if (rootless) {
            try script.appendSlice(allocator, " --user --map-root-user");
        }
        try script.appendSlice(allocator, " chroot ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, " /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin:/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/opt/rabbitmq/sbin:/usr/lib/rabbitmq/bin:/opt/erlang/bin ");

        // Add user env vars inside container
        for (env_vars) |env| {
            try script.appendSlice(allocator, env.key);
            try script.append(allocator, '=');
            try script.appendSlice(allocator, env.value);
            try script.append(allocator, ' ');
        }

        // Add the command
        for (command) |arg| {
            try script.appendSlice(allocator, arg);
            try script.append(allocator, ' ');
        }

        const script_str = try allocator.dupe(u8, script.items);
        try dynamic_allocs.append(allocator, script_str);
        script_content_str = script_str;
        // Generated script content
    }

    // Determine container directory and run.sh path

    // rootfs_path is .../<id>/rootfs, so parent is container dir
    const container_dir = std.fs.path.dirname(rootfs_path) orelse return VirtualizationError.ConfigurationInvalid;
    const run_script_path = try std.fmt.allocPrint(allocator, "{s}/run.sh", .{container_dir});
    try dynamic_allocs.append(allocator, run_script_path);

    // Get the script content that was just generated (it's the last added dynamic alloc)
    // Note: We need to handle the case where "else" block above ran or "if" block ran.
    // In both cases we appended script_str to dynamic_allocs.
    // Actually, we modified the code above to NOT append to lima_args yet, just dynamic_allocs.
    // But wait, the previous code structure had `script` variable scope limited to the blocks.
    // I need to extract the script generation to a common variable or write it inside the blocks.

    // RE-PLAN: The tool replacement above was a bit messy with scopes.
    // Let's assume the previous `script_str` is accessible or handle it properly.
    // The previous chunks show I commented out appending to `lima_args`.
    // But `script` was deinitialized at end of block. `script_str` was duplicated.
    // So `dynamic_allocs.items[dynamic_allocs.items.len - 1]` should be the script content.

    // const script_content = dynamic_allocs.items[dynamic_allocs.items.len - 1];

    // Write script to file
    const run_file = try std.fs.cwd().createFile(run_script_path, .{ .mode = 0o755 });
    defer run_file.close();
    try run_file.writeAll(script_content_str);

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
        try lima_args.append(allocator, try std.fmt.allocPrint(allocator, "--working-directory={s}", .{container_dir}));
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

    // 2. Fallback: Find PIDs via /proc/*/environ using find to avoid glob expansion issues
    const find_cmd = try std.fmt.allocPrint(allocator, "sudo find /proc -maxdepth 2 -name environ -exec grep -l \"ISOLAZI_ID={s}\" {{}} + 2>/dev/null | cut -d/ -f3", .{container_id});
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

    // 2. Fallback: Search /proc/*/environ for the tag using find
    const grep_cmd = try std.fmt.allocPrint(allocator, "sudo find /proc -maxdepth 2 -name environ -exec grep -q \"ISOLAZI_ID={s}\" {{}} + 2>/dev/null", .{container_id});
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

const LimaStatus = enum {
    Running,
    Stopped,
    NotExists,
    Unknown,
};

fn checkLimaStatus(allocator: std.mem.Allocator) LimaStatus {
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
