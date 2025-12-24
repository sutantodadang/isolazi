//! Container runtime - the core execution engine.
//!
//! This module orchestrates container creation and execution:
//! 1. Fork a new process
//! 2. In the child: set up namespaces, filesystem, then exec the command
//! 3. In the parent: wait for the child to complete
//!
//! Design decisions:
//! - Fork-based model (similar to runc) rather than clone with CLONE_PARENT
//! - Synchronous execution (no daemon)
//! - All isolation setup happens in the child process
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
    ExecFailed,
    WaitFailed,
    ConfigurationError,
    InvalidRootfs,
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

    pub fn init(cfg: *const Config) Runtime {
        return Runtime{
            .config = cfg,
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
    pub fn run(self: *const Runtime) RuntimeError!RunResult {
        // Fork the container process
        const pid = try linux.fork();

        if (pid == 0) {
            // Child process - this becomes the container
            self.childProcess() catch |err| {
                // If setup fails, print error and exit with code 1
                std.debug.print("Container setup failed: {}\n", .{err});
                std.process.exit(1);
            };
            // childProcess never returns on success (it calls execve)
            unreachable;
        } else {
            // Parent process - wait for the container to finish
            return self.parentProcess(pid);
        }
    }

    /// Child process: set up isolation and execute the command.
    ///
    /// This function never returns on success - it calls execve.
    fn childProcess(self: *const Runtime) RuntimeError!noreturn {
        const cfg = self.config;

        // Step 1: Enter new namespaces
        // unshare() creates new namespaces for the current process.
        // Note: For PID namespace, the current process is NOT moved into it;
        // only its children will be. Since we'll exec, this is fine.
        const ns_flags = cfg.namespaces.toCloneFlags();
        try linux.unshare(ns_flags);

        // Step 2: Set hostname (only works if we have UTS namespace)
        if (cfg.namespaces.uts) {
            const hostname = cfg.getHostname();
            if (hostname.len > 0) {
                try linux.setHostname(hostname);
            }
        }

        // Step 3: Set up the root filesystem
        if (cfg.use_pivot_root) {
            try fs_mod.setupPivotRoot(cfg.getRootfs());
        } else {
            try fs_mod.setupChroot(cfg.getRootfs());
        }

        // Step 4: Mount essential filesystems
        try fs_mod.setupMinimalMounts();

        // Step 5: Set up bind mounts
        try fs_mod.setupBindMounts(&cfg.mounts, cfg.mounts_count);

        // Step 6: Change to working directory
        try linux.chdir(cfg.getCwd());

        // Step 7: Execute the container command
        // Build argv and envp arrays (on stack)
        var argv_buf: [config_mod.MAX_ARGS + 1]?[*:0]const u8 = undefined;
        var envp_buf: [config_mod.MAX_ENV + 1]?[*:0]const u8 = undefined;

        const argv = cfg.buildArgv(&argv_buf);
        const envp = cfg.buildEnvp(&envp_buf);
        const cmd = cfg.getCommand();

        // POINT OF NO RETURN: execve replaces the process
        try linux.execve(cmd, argv, envp);
    }

    /// Parent process: wait for container and return result.
    fn parentProcess(_: *const Runtime, child_pid: std.os.linux.pid_t) RuntimeError!RunResult {
        // Wait for the child to exit
        const wait_result = try linux.waitpid(child_pid, 0);
        const status = wait_result.status;

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
pub fn run(config: *const Config) RuntimeError!RunResult {
    const runtime = Runtime.init(config);
    return runtime.run();
}

// =============================================================================
// Tests
// =============================================================================

test "Runtime initialization" {
    const config = try Config.init("/tmp/rootfs");
    const runtime = Runtime.init(&config);
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
