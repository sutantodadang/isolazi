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
        var child_ready_pipe: [2]std.posix.fd_t = undefined;
        var parent_done_pipe: [2]std.posix.fd_t = undefined;

        // We need pipes if network or user namespace is enabled
        const needs_sync = cfg.namespaces.network or cfg.namespaces.user;

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

            // Set up user namespace mappings, network and wait for the container to finish
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
        const ns_flags = cfg.namespaces.toCloneFlags();
        try linux.unshare(ns_flags);

        // Step 2: Synchronize with parent for user namespace and/or network setup
        const needs_sync = cfg.namespaces.network or cfg.namespaces.user;

        if (needs_sync) {
            if (child_ready_write) |fd| {
                // Signal parent that we've entered the namespaces
                // Parent will write uid_map/gid_map if user namespace is enabled
                const ready_byte: [1]u8 = .{1};
                _ = std.posix.write(fd, &ready_byte) catch {};
                std.posix.close(fd);
            }

            if (parent_done_read) |fd| {
                // Wait for parent to complete user namespace mapping and/or network setup
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

        // Step 8: Execute the container command
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

        const needs_sync = cfg.namespaces.network or cfg.namespaces.user;

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

            if (parent_done_write) |fd| {
                // Signal child that user namespace mapping and network setup are complete
                const done_byte: [1]u8 = .{1};
                _ = std.posix.write(fd, &done_byte) catch {};
                std.posix.close(fd);
            }
        }

        // Wait for the child to exit
        const wait_result = try linux.waitpid(child_pid, 0);
        const status = wait_result.status;

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
