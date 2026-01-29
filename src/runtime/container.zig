//! Container runtime - the core execution engine.
//!
//! This module orchestrates container creation and execution:
//! 1. Fork a new process
//! 2. In the child: set up namespaces, filesystem, network, then exec the command
//! 3. In the parent: set up host-side networking (veth, bridge), wait for completion
//!
//! Design decisions:
//! - Fork-based model (similar to runc) rather than clone with CLONE_PARENT
//! - Synchronous execution (no daemon)
//! - All isolation setup happens in the child process
//! - Network setup requires coordination between parent and child
//!
//! The execution flow:
//! ```
//! Parent Process                    Child Process
//! ──────────────                    ─────────────
//!      │
//!      ├── fork() ─────────────────────┐
//!      │                               │
//!      │                               ├── unshare(namespaces)
//!      │                               │
//!      │                               ├── signal ready (pipe)
//!      │                               │
//!      ├── create veth pair            │
//!      │                               │
//!      ├── move veth to child ns       │
//!      │                               │
//!      ├── setup port forwarding       │
//!      │                               │
//!      ├── signal done (pipe)          │
//!      │                               │
//!      │                               ├── configure container network
//!      │                               │
//!      │                               ├── setup rootfs (pivot_root)
//!      │                               │
//!      │                               ├── mount /proc, /dev, etc.
//!      │                               │
//!      │                               ├── set hostname
//!      │                               │
//!      │                               ├── execve(command)
//!      │                               │
//!      ├── waitpid() ◄─────────────────┘
//!      │
//!      └── return exit code
//! ```

const std = @import("std");
const linux = @import("../linux/mod.zig");
const config_mod = @import("../config/mod.zig");
const fs_mod = @import("../fs/mod.zig");
const container_mod = @import("../container/mod.zig");

const Config = config_mod.Config;

pub const RuntimeError = error{
    ForkFailed,
    NamespaceSetupFailed,
    FilesystemSetupFailed,
    NetworkSetupFailed,
    ExecFailed,
    WaitFailed,
    ConfigurationError,
    InvalidRootfs,
    PipeError,
    CgroupSetupFailed,
} || linux.SyscallError || fs_mod.FsError;

/// Result of container execution.
pub const RunResult = struct {
    /// Exit code of the container process (0-255)
    exit_code: u8,
    /// True if the process was killed by a signal
    signaled: bool,
    /// Signal number if signaled is true
    signal: u8,
};

/// Container runtime state.
pub const Runtime = struct {
    config: *const Config,
    allocator: std.mem.Allocator,
    container_id: []const u8,
    /// Network configuration (populated during run if network namespace enabled)
    network_config: ?linux.ContainerNetwork = null,
    /// Cgroup manager (populated if resource limits are configured)
    cgroup_manager: ?*linux.CgroupManager = null,

    pub fn init(cfg: *const Config, allocator: std.mem.Allocator, container_id: []const u8) Runtime {
        return Runtime{
            .config = cfg,
            .allocator = allocator,
            .container_id = container_id,
        };
    }

    /// Run the container and wait for it to complete.
    ///
    /// This is the main entry point for container execution.
    /// It forks a child process, sets up isolation, and waits for completion.
    ///
    /// SECURITY: This function should be called with appropriate capabilities:
    /// - CAP_SYS_ADMIN (for namespaces, pivot_root, mount)
    /// - CAP_SYS_CHROOT (for chroot fallback)
    /// - CAP_NET_ADMIN (for network namespace)
    /// For rootless mode (user namespace), no special capabilities are needed.
    pub fn run(self: *Runtime) RuntimeError!RunResult {
        const cfg = self.config;

        // Create pipes for parent-child synchronization
        // These are needed for:
        // 1. User namespace: parent must write uid_map/gid_map after child unshares
        // 2. Network namespace: parent creates veth and moves to child ns
        // 3. Cgroup: parent creates cgroup and adds child PID
        var child_ready_pipe: [2]std.posix.fd_t = undefined;
        var parent_done_pipe: [2]std.posix.fd_t = undefined;

        // We need pipes if network, user namespace, or cgroup is enabled
        const needs_sync = cfg.namespaces.network or cfg.namespaces.user or cfg.resource_limits.hasLimits();

        if (needs_sync) {
            child_ready_pipe = std.posix.pipe() catch return RuntimeError.PipeError;
            parent_done_pipe = std.posix.pipe() catch {
                std.posix.close(child_ready_pipe[0]);
                std.posix.close(child_ready_pipe[1]);
                return RuntimeError.PipeError;
            };
        }

        // Fork the container process
        const pid = try linux.fork();

        if (pid == 0) {
            // Child process - this becomes the container
            if (needs_sync) {
                // Close unused pipe ends
                std.posix.close(child_ready_pipe[0]); // Close read end
                std.posix.close(parent_done_pipe[1]); // Close write end
            }

            self.childProcess(
                if (needs_sync) child_ready_pipe[1] else null,
                if (needs_sync) parent_done_pipe[0] else null,
            ) catch |err| {
                // If setup fails, print error and exit with code 1
                std.debug.print("Container setup failed: {}\n", .{err});
                std.process.exit(1);
            };
            // childProcess never returns on success (it calls execve)
            unreachable;
        } else {
            // Parent process
            if (needs_sync) {
                // Close unused pipe ends
                std.posix.close(child_ready_pipe[1]); // Close write end
                std.posix.close(parent_done_pipe[0]); // Close read end
            }

            // Update container state with PID immediately after fork
            // This allows 'inspect' to show the running container's PID
            if (self.container_id.len > 0) {
                var manager = container_mod.ContainerManager.init(self.allocator) catch |err| {
                    std.debug.print("Warning: Failed to init container manager for PID tracking: {}\n", .{err});
                    // Continue anyway - PID tracking is not critical for execution
                    return self.parentProcess(
                        pid,
                        if (needs_sync) child_ready_pipe[0] else null,
                        if (needs_sync) parent_done_pipe[1] else null,
                    );
                };
                defer manager.deinit();
                manager.updateState(self.container_id, .running, pid, null) catch |err| {
                    std.debug.print("Warning: Failed to update state with PID: {}\n", .{err});
                };
            }

            // Set up user namespace mappings, cgroup, network and wait for the container to finish
            return self.parentProcess(
                pid,
                if (needs_sync) child_ready_pipe[0] else null,
                if (needs_sync) parent_done_pipe[1] else null,
            );
        }
    }

    /// Child process: set up isolation and execute the command.
    ///
    /// This function never returns on success - it calls execve.
    fn childProcess(
        self: *const Runtime,
        child_ready_write: ?std.posix.fd_t,
        parent_done_read: ?std.posix.fd_t,
    ) RuntimeError!noreturn {
        const cfg = self.config;

        // Step 1: Enter new namespaces
        // unshare() creates new namespaces for the current process.
        // Note: For PID namespace, the current process is NOT moved into it;
        // only its children will be. Since we'll exec, this is fine.
        // Note: Cgroup namespace is entered here but resource limits are applied by parent
        const ns_flags = cfg.namespaces.toCloneFlags();
        try linux.unshare(ns_flags);

        // Step 2: Synchronize with parent for user namespace, cgroup, and/or network setup
        const needs_sync = cfg.namespaces.network or cfg.namespaces.user or cfg.resource_limits.hasLimits();

        if (needs_sync) {
            if (child_ready_write) |fd| {
                // Signal parent that we've entered the namespaces
                // Parent will:
                // - Write uid_map/gid_map if user namespace is enabled
                // - Set up cgroup and add this process if resource limits are configured
                // - Set up network if network namespace is enabled
                const ready_byte: [1]u8 = .{1};
                _ = std.posix.write(fd, &ready_byte) catch {};
                std.posix.close(fd);
            }

            if (parent_done_read) |fd| {
                // Wait for parent to complete user namespace mapping, cgroup, and/or network setup
                var done_byte: [1]u8 = undefined;
                _ = std.posix.read(fd, &done_byte) catch {};
                std.posix.close(fd);
            }
        }

        // Step 3: Configure container-side network if enabled
        if (cfg.namespaces.network) {
            // Configure container-side network (eth0, IP, routes)
            // This is done after we receive the veth from parent
            var net_config = linux.ContainerNetwork.init(self.container_id, 2);
            linux.setupContainerNetworkContainer(
                self.allocator,
                &net_config,
            ) catch {
                // Network config failed, but continue - container may work without full networking
                std.debug.print("Warning: Container network configuration failed\n", .{});
            };
        }

        // Step 4: Set hostname (only works if we have UTS namespace)
        if (cfg.namespaces.uts) {
            const hostname = cfg.getHostname();
            if (hostname.len > 0) {
                try linux.setHostname(hostname);
            }
        }

        // Step 4: Set up the root filesystem
        if (cfg.use_pivot_root) {
            try fs_mod.setupPivotRoot(cfg.getRootfs());
        } else {
            try fs_mod.setupChroot(cfg.getRootfs());
        }

        // Step 5: Mount essential filesystems
        try fs_mod.setupMinimalMounts();

        // Step 6: Set up bind mounts
        try fs_mod.setupBindMounts(&cfg.mounts, cfg.mounts_count);

        // Step 7: Change to working directory
        try linux.chdir(cfg.getCwd());

        // Step 8: Apply Linux Security Module (AppArmor/SELinux) profiles
        // This must be done BEFORE execve but after filesystem setup
        // LSM profiles restrict file access, capabilities, network, etc.
        if (cfg.lsm.isEnabled()) {
            applyLSMFromConfig(cfg) catch |err| {
                std.debug.print("Warning: LSM profile application failed: {}\n", .{err});
                // Continue without LSM - some systems may not have AppArmor/SELinux enabled
            };
        }

        // Step 9: Apply seccomp filter (must be done BEFORE execve)
        // This restricts syscalls available to the container process
        if (cfg.seccomp.enabled and cfg.seccomp.profile_type != .disabled) {
            applySeccompFromConfig(cfg) catch |err| {
                std.debug.print("Warning: Seccomp filter installation failed: {}\n", .{err});
                // Continue without seccomp - some systems may not support it
            };
        }

        // Step 10: Execute the container command
        // Build argv and envp arrays (on stack)
        var argv_buf: [config_mod.MAX_ARGS + 1]?[*:0]const u8 = undefined;
        var envp_buf: [config_mod.MAX_ENV + 1]?[*:0]const u8 = undefined;

        const argv = cfg.buildArgv(&argv_buf);
        const envp = cfg.buildEnvp(&envp_buf);
        const cmd = cfg.getCommand();

        // POINT OF NO RETURN: execve replaces the process
        try linux.execve(cmd, argv, envp);
    }

    /// Parent process: setup user namespace mappings, network (if enabled), wait for container, cleanup.
    fn parentProcess(
        self: *Runtime,
        child_pid: std.os.linux.pid_t,
        child_ready_read: ?std.posix.fd_t,
        parent_done_write: ?std.posix.fd_t,
    ) RuntimeError!RunResult {
        const cfg = self.config;
        var net_config: ?linux.ContainerNetwork = null;

        const needs_sync = cfg.namespaces.network or cfg.namespaces.user or cfg.resource_limits.hasLimits();

        if (needs_sync) {
            if (child_ready_read) |fd| {
                // Wait for child to signal it has entered namespaces
                var ready_byte: [1]u8 = undefined;
                _ = std.posix.read(fd, &ready_byte) catch {};
                std.posix.close(fd);
            }

            // Step 1: Set up user namespace mappings if enabled
            if (cfg.namespaces.user) {
                // Build user namespace configuration
                var userns_config = linux.UserNamespaceConfig{
                    .rootless = cfg.rootless,
                    .deny_setgroups = cfg.rootless, // Required for unprivileged users
                };

                // Copy mappings from config or use defaults
                if (cfg.uid_map_count > 0) {
                    for (cfg.uid_mappings[0..cfg.uid_map_count], 0..) |mapping, i| {
                        if (mapping.active) {
                            userns_config.uid_mappings[i] = linux.userns.IdMapping{
                                .container_id = mapping.container_id,
                                .host_id = mapping.host_id,
                                .count = mapping.count,
                            };
                            userns_config.uid_count += 1;
                        }
                    }
                } else if (cfg.rootless) {
                    // Default rootless mapping: current user to root
                    userns_config.uid_mappings[0] = linux.userns.IdMapping.single(
                        linux.getCurrentUid(),
                        0,
                    );
                    userns_config.uid_count = 1;
                }

                if (cfg.gid_map_count > 0) {
                    for (cfg.gid_mappings[0..cfg.gid_map_count], 0..) |mapping, i| {
                        if (mapping.active) {
                            userns_config.gid_mappings[i] = linux.userns.IdMapping{
                                .container_id = mapping.container_id,
                                .host_id = mapping.host_id,
                                .count = mapping.count,
                            };
                            userns_config.gid_count += 1;
                        }
                    }
                } else if (cfg.rootless) {
                    // Default rootless mapping: current group to root
                    userns_config.gid_mappings[0] = linux.userns.IdMapping.single(
                        linux.getCurrentGid(),
                        0,
                    );
                    userns_config.gid_count = 1;
                }

                // Write uid_map and gid_map
                linux.setupUserNamespace(child_pid, &userns_config) catch |err| {
                    std.debug.print("Warning: User namespace setup failed: {}\n", .{err});
                    // Don't fail completely - child might still work with restricted permissions
                };
            }

            // Step 2: Set up network if enabled
            if (cfg.namespaces.network) {
                // Convert port mappings from config to network module format
                var port_mappings: [config_mod.MAX_PORTS]linux.PortMapping = undefined;
                var port_count: usize = 0;

                for (cfg.port_mappings[0..cfg.port_count]) |pm| {
                    if (pm.active) {
                        port_mappings[port_count] = linux.PortMapping{
                            .host_port = pm.host_port,
                            .container_port = pm.container_port,
                            .protocol = if (pm.protocol == .tcp) .tcp else .udp,
                        };
                        port_count += 1;
                    }
                }

                // Set up host-side networking (veth, bridge, NAT, port forwarding)
                net_config = linux.setupContainerNetworkHost(
                    self.allocator,
                    self.container_id,
                    port_mappings[0..port_count],
                    child_pid,
                ) catch |err| blk: {
                    std.debug.print("Warning: Network setup failed: {}\n", .{err});
                    break :blk null;
                };

                self.network_config = net_config;
            }

            // Step 3: Set up cgroup and apply resource limits if configured
            if (cfg.resource_limits.hasLimits()) {
                // Create cgroup and add child process
                if (linux.isCgroupV2Available()) {
                    self.cgroup_manager = linux.setupContainerCgroup(
                        self.allocator,
                        self.container_id,
                        &cfg.resource_limits,
                        child_pid,
                    ) catch |err| blk: {
                        std.debug.print("Warning: Cgroup setup failed: {}\n", .{err});
                        break :blk null;
                    };
                } else {
                    std.debug.print("Warning: Cgroup v2 not available, resource limits will not be applied\n", .{});
                }
            }

            if (parent_done_write) |fd| {
                // Signal child that user namespace mapping, cgroup, and network setup are complete
                const done_byte: [1]u8 = .{1};
                _ = std.posix.write(fd, &done_byte) catch {};
                std.posix.close(fd);
            }
        }

        // Wait for the child to exit
        const wait_result = try linux.waitpid(child_pid, 0);
        const status = wait_result.status;

        // Cleanup cgroup resources
        if (self.cgroup_manager) |cg_mgr| {
            linux.cleanupContainerCgroup(self.allocator, cg_mgr);
            self.cgroup_manager = null;
        }

        // Cleanup network resources
        if (net_config) |nc| {
            var net_mgr = linux.NetworkManager.init(self.allocator);
            net_mgr.cleanup(&nc);
        }

        // Decode wait status (see waitpid(2))
        // WIFEXITED: (status & 0x7f) == 0
        // WEXITSTATUS: (status >> 8) & 0xff
        // WIFSIGNALED: ((status & 0x7f) + 1) >> 1 > 0
        // WTERMSIG: status & 0x7f

        const signaled = ((status & 0x7f) + 1) >> 1 > 0;

        if (signaled) {
            // Process was killed by a signal
            return RunResult{
                .exit_code = 128 + @as(u8, @truncate(status & 0x7f)),
                .signaled = true,
                .signal = @truncate(status & 0x7f),
            };
        } else {
            // Process exited normally
            return RunResult{
                .exit_code = @truncate((status >> 8) & 0xff),
                .signaled = false,
                .signal = 0,
            };
        }
    }
};

/// Convenience function to run a container with the given configuration.
/// Note: For network support, use Runtime.init() directly to provide allocator and container_id.
pub fn run(config: *const Config, allocator: std.mem.Allocator, container_id: []const u8) RuntimeError!RunResult {
    var runtime = Runtime.init(config, allocator, container_id);
    return runtime.run();
}

/// Configuration for exec command
pub const ExecConfig = struct {
    /// Target container PID
    target_pid: std.os.linux.pid_t,
    /// Command to execute
    command: []const u8,
    /// Command arguments (argv[0] should be command)
    args: []const []const u8,
    /// Environment variables (KEY=VALUE format)
    env: []const []const u8,
    /// Working directory (null = inherit from container)
    cwd: ?[]const u8,
    /// User to run as (null = root)
    user: ?[]const u8,
    /// Which namespaces to enter
    namespaces: struct {
        mount: bool = true,
        uts: bool = true,
        ipc: bool = true,
        net: bool = true,
        pid: bool = true,
        user: bool = false, // Usually skip user ns for exec
        cgroup: bool = true,
    } = .{},
};

/// Execute a command in a running container's namespaces using nsenter.
///
/// This function:
/// 1. Forks a new process
/// 2. In child: enters the target container's namespaces using setns()
/// 3. Executes the specified command
/// 4. Parent waits for child and returns exit status
///
/// SECURITY: Requires CAP_SYS_ADMIN and CAP_SYS_PTRACE capabilities.
pub fn execInContainer(allocator: std.mem.Allocator, exec_cfg: ExecConfig) RuntimeError!RunResult {
    // Fork a new process
    const pid = try linux.fork();

    if (pid == 0) {
        // Child process - enter namespaces and exec

        // Build list of namespaces to enter
        // Order matters: user ns should be first if used
        var ns_list: [7]linux.NamespaceType = undefined;
        var ns_count: usize = 0;

        if (exec_cfg.namespaces.user) {
            ns_list[ns_count] = .user;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.mount) {
            ns_list[ns_count] = .mnt;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.uts) {
            ns_list[ns_count] = .uts;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.ipc) {
            ns_list[ns_count] = .ipc;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.net) {
            ns_list[ns_count] = .net;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.pid) {
            ns_list[ns_count] = .pid;
            ns_count += 1;
        }
        if (exec_cfg.namespaces.cgroup) {
            ns_list[ns_count] = .cgroup;
            ns_count += 1;
        }

        // Enter namespaces
        linux.enterNamespaces(exec_cfg.target_pid, ns_list[0..ns_count]) catch |err| {
            std.debug.print("Failed to enter namespaces: {}\n", .{err});
            std.process.exit(1);
        };

        // Change working directory if specified
        if (exec_cfg.cwd) |cwd| {
            var cwd_buf: [4096]u8 = undefined;
            const cwd_z = std.fmt.bufPrintZ(&cwd_buf, "{s}", .{cwd}) catch {
                std.debug.print("Working directory path too long\n", .{});
                std.process.exit(1);
            };
            linux.chdir(cwd_z.ptr) catch |err| {
                std.debug.print("Failed to change directory: {}\n", .{err});
                std.process.exit(1);
            };
        }

        // Build argv for execve
        // We need null-terminated strings for execve
        var argv_ptrs: [256]?[*:0]const u8 = undefined;
        var argv_count: usize = 0;

        for (exec_cfg.args) |arg| {
            if (argv_count >= argv_ptrs.len - 1) break;
            // Need to ensure args are null-terminated
            // Since they come from CLI, they should be from the arg slice
            // We'll use a buffer for safety
            var arg_buf: [4096]u8 = undefined;
            const arg_z = std.fmt.bufPrintZ(&arg_buf, "{s}", .{arg}) catch {
                std.debug.print("Argument too long\n", .{});
                std.process.exit(1);
            };
            // Store pointer - this is safe as arg_buf lives until execve
            // Actually we need heap allocation or static storage
            const duped = allocator.dupeZ(u8, arg_z) catch {
                std.debug.print("Out of memory\n", .{});
                std.process.exit(1);
            };
            argv_ptrs[argv_count] = duped.ptr;
            argv_count += 1;
        }
        argv_ptrs[argv_count] = null;

        // Build envp for execve
        var envp_ptrs: [256]?[*:0]const u8 = undefined;
        var envp_count: usize = 0;

        // Add default environment
        const default_env = [_][]const u8{
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm",
            "HOME=/root",
        };

        for (default_env) |env| {
            if (envp_count >= envp_ptrs.len - 1) break;
            const duped = allocator.dupeZ(u8, env) catch {
                std.debug.print("Out of memory\n", .{});
                std.process.exit(1);
            };
            envp_ptrs[envp_count] = duped.ptr;
            envp_count += 1;
        }

        // Add user-specified environment
        for (exec_cfg.env) |env| {
            if (envp_count >= envp_ptrs.len - 1) break;
            const duped = allocator.dupeZ(u8, env) catch {
                std.debug.print("Out of memory\n", .{});
                std.process.exit(1);
            };
            envp_ptrs[envp_count] = duped.ptr;
            envp_count += 1;
        }
        envp_ptrs[envp_count] = null;

        // Get command path
        var cmd_buf: [4096]u8 = undefined;
        const cmd_z = std.fmt.bufPrintZ(&cmd_buf, "{s}", .{exec_cfg.command}) catch {
            std.debug.print("Command path too long\n", .{});
            std.process.exit(1);
        };

        // Execute the command
        linux.execve(
            cmd_z.ptr,
            @ptrCast(&argv_ptrs),
            @ptrCast(&envp_ptrs),
        ) catch |err| {
            std.debug.print("Failed to execute command: {}\n", .{err});
            std.process.exit(127);
        };

        unreachable;
    } else {
        // Parent process - wait for child
        const wait_result = try linux.waitpid(pid, 0);
        const status = wait_result.status;

        const signaled = ((status & 0x7f) + 1) >> 1 > 0;

        if (signaled) {
            return RunResult{
                .exit_code = 128 + @as(u8, @truncate(status & 0x7f)),
                .signaled = true,
                .signal = @truncate(status & 0x7f),
            };
        } else {
            return RunResult{
                .exit_code = @truncate((status >> 8) & 0xff),
                .signaled = false,
                .signal = 0,
            };
        }
    }
}

// =============================================================================
// Seccomp Helper Functions
// =============================================================================

/// Convert config SeccompConfig to linux seccomp module format and apply.
/// This function bridges the config module's seccomp settings to the linux module's
/// seccomp BPF filter installation.
fn applySeccompFromConfig(cfg: *const Config) !void {
    const seccomp_cfg = &cfg.seccomp;

    // If seccomp is disabled, do nothing
    if (!seccomp_cfg.enabled or seccomp_cfg.profile_type == .disabled) {
        return;
    }

    // Create the appropriate profile based on config
    var linux_config = linux.SeccompConfig{
        .enabled = true,
        .log_blocked = seccomp_cfg.log_blocked,
        .errno_instead_of_kill = seccomp_cfg.errno_instead_of_kill,
        .errno_value = seccomp_cfg.errno_value,
        .profile = switch (seccomp_cfg.profile_type) {
            .disabled => linux.SeccompProfile.init(),
            .default_container => linux.SeccompProfile.defaultContainerProfile(),
            .minimal => linux.SeccompProfile.minimalProfile(),
            .strict => linux.SeccompProfile.allowlistProfile(),
            .custom => blk: {
                var profile = linux.SeccompProfile.init();
                // Add custom rules from config
                for (seccomp_cfg.custom_rules[0..seccomp_cfg.custom_rules_count]) |rule| {
                    if (!rule.active) continue;
                    const linux_rule = switch (rule.action) {
                        .kill => linux.SeccompRule.block(@enumFromInt(rule.syscall)),
                        .errno => linux.SeccompRule.denyWithErrno(@enumFromInt(rule.syscall), rule.errno_value),
                        .log => linux.SeccompRule.logOnly(@enumFromInt(rule.syscall)),
                        .allow => linux.SeccompRule.allow(@enumFromInt(rule.syscall)),
                    };
                    profile.addRule(linux_rule);
                }
                break :blk profile;
            },
        },
    };

    // Apply the seccomp filter
    try linux.applySeccompFilter(&linux_config);
}

// =============================================================================
// Linux Security Module (LSM) Helper Functions
// =============================================================================

/// Apply AppArmor and/or SELinux configurations from the container config.
///
/// This function applies Linux Security Module restrictions to the container process.
/// AppArmor and SELinux are mutually exclusive on most systems - only one will be
/// active at runtime. The function tries both but expects only one to succeed.
///
/// SECURITY: LSM restrictions are applied BEFORE execve() but AFTER filesystem setup.
/// This ensures the container process starts with the appropriate security context.
///
/// Order of operations:
/// 1. Apply AppArmor profile (if enabled and AppArmor is available)
/// 2. Apply SELinux context (if enabled and SELinux is available)
/// 3. Both will gracefully fail if the respective LSM is not available
fn applyLSMFromConfig(cfg: *const Config) !void {
    const lsm_cfg = &cfg.lsm;

    // Apply AppArmor if enabled
    if (lsm_cfg.apparmor.isEnabled()) {
        applyAppArmorFromConfig(&lsm_cfg.apparmor) catch |err| {
            // Log but don't fail - AppArmor may not be available
            std.debug.print("AppArmor application warning: {}\n", .{err});
        };
    }

    // Apply SELinux if enabled
    if (lsm_cfg.selinux.isEnabled()) {
        applySELinuxFromConfig(&lsm_cfg.selinux) catch |err| {
            // Log but don't fail - SELinux may not be available
            std.debug.print("SELinux application warning: {}\n", .{err});
        };
    }
}

/// Apply AppArmor profile from config.
///
/// Converts config AppArmorConfig to linux apparmor module format and applies.
fn applyAppArmorFromConfig(apparmor_cfg: *const config_mod.AppArmorConfig) !void {
    if (!apparmor_cfg.enabled) {
        return;
    }

    // Check if AppArmor is available on this system
    if (!linux.isAppArmorAvailable()) {
        std.debug.print("AppArmor not available on this system\n", .{});
        return;
    }

    // Convert config AppArmorMode to linux apparmor mode
    const profile_name = apparmor_cfg.getProfileName();

    // Handle different modes
    switch (apparmor_cfg.mode) {
        .unconfined => {
            // No AppArmor restrictions
            return;
        },
        .complain => {
            // Apply profile in complain mode
            // For complain mode, we prepend "complain" to the profile name when setting exec context
            var complain_buf: [config_mod.MAX_APPARMOR_PROFILE_NAME + 16]u8 = undefined;
            const complain_name = std.fmt.bufPrint(&complain_buf, "complain {s}", .{profile_name}) catch {
                return linux.AppArmorError.InvalidProfile;
            };
            try linux.setAppArmorExecProfile(complain_name);
        },
        .enforce => {
            // Apply profile in enforce mode
            try linux.setAppArmorExecProfile(profile_name);
        },
    }
}

/// Apply SELinux context from config.
///
/// Converts config SELinuxConfig to linux selinux module format and applies.
fn applySELinuxFromConfig(selinux_cfg: *const config_mod.SELinuxConfig) !void {
    if (!selinux_cfg.enabled) {
        return;
    }

    // Check if SELinux is available on this system
    if (!linux.isSELinuxAvailable()) {
        std.debug.print("SELinux not available on this system\n", .{});
        return;
    }

    // Check if SELinux is enforcing
    const mode = linux.getSELinuxMode();
    if (mode == .disabled) {
        std.debug.print("SELinux is disabled on this system\n", .{});
        return;
    }

    // Get the effective context string
    var context_buf: [config_mod.MAX_SELINUX_CONTEXT_LEN]u8 = undefined;
    const context_str = selinux_cfg.getContextString(&context_buf);

    if (context_str.len == 0) {
        return linux.SELinuxError.InvalidContext;
    }

    // Parse the context string
    const context = linux.SecurityContext.parse(context_str) catch {
        return linux.SELinuxError.InvalidContext;
    };

    // Set the exec context (applied at execve)
    linux.setSELinuxExecContext(&context) catch |err| {
        // In permissive mode, just log the error
        if (mode == .permissive) {
            std.debug.print("SELinux exec context failed (permissive mode): {}\n", .{err});
            return;
        }
        return err;
    };

    // Set file creation context if mount label is specified
    if (selinux_cfg.mount_label_len > 0) {
        const mount_label = selinux_cfg.getMountLabel();
        const file_context = linux.SecurityContext.parse(mount_label) catch {
            return;
        };
        linux.setSELinuxFileCreateContext(&file_context) catch {
            // Non-fatal - file creation context is optional
        };
    }
}

// =============================================================================
// Tests
// =============================================================================

test "Runtime initialization" {
    var config = try Config.init("/tmp/rootfs");
    // Disable network for test (no root/network access in test)
    config.namespaces.network = false;
    const runtime = Runtime.init(&config, std.testing.allocator, "test123");
    try std.testing.expect(runtime.config.namespaces.pid);
}

test "RunResult decoding" {
    // Test normal exit
    const normal_result = RunResult{
        .exit_code = 0,
        .signaled = false,
        .signal = 0,
    };
    try std.testing.expectEqual(@as(u8, 0), normal_result.exit_code);
    try std.testing.expect(!normal_result.signaled);

    // Test signaled exit
    const signaled_result = RunResult{
        .exit_code = 137,
        .signaled = true,
        .signal = 9, // SIGKILL
    };
    try std.testing.expect(signaled_result.signaled);
    try std.testing.expectEqual(@as(u8, 9), signaled_result.signal);
}
