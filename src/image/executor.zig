//! Build Executor
//!
//! Abstracts platform-specific logic for executing build steps:
//! - Windows: Uses WSL2 to run commands and file operations
//! - macOS: Uses Lima VM
//! - Linux: Uses native namespaces
//!
//! This ensures inconsistent build behavior across platforms while keeping
//! the main builder logic platform-agnostic.

const std = @import("std");
const builtin = @import("builtin");
const isolazifile = @import("isolazifile.zig");

pub const Executor = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Executor {
        return .{ .allocator = allocator };
    }

    /// Escape single quotes for embedding inside a single-quoted shell string.
    /// Replaces each ' with '\'' (end quote, escaped quote, start quote).
    fn shellEscapeSingleQuotes(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);
        for (input) |c| {
            if (c == '\'') {
                try result.appendSlice(allocator, "'\\''");
            } else {
                try result.append(allocator, c);
            }
        }
        return result.toOwnedSlice(allocator);
    }

    /// Append mount setup commands for /dev, /sys, /dev/pts, /dev/shm inside chroot.
    fn appendMountSetup(script: *std.ArrayList(u8), allocator: std.mem.Allocator, rootfs: []const u8) !void {
        // Mount proc
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/proc && ");
        try script.appendSlice(allocator, "mount -t proc proc ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/proc && ");

        // Bind-mount /dev
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev && ");
        try script.appendSlice(allocator, "mount --bind /dev ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev && ");

        // Mount devpts
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev/pts && ");
        try script.appendSlice(allocator, "mount -t devpts devpts ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev/pts 2>/dev/null || true; ");

        // Mount sysfs
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/sys && ");
        try script.appendSlice(allocator, "mount -t sysfs sysfs ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/sys && ");

        // Mount tmpfs for /dev/shm
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev/shm && ");
        try script.appendSlice(allocator, "mount -t tmpfs tmpfs ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/dev/shm && ");

        // Copy resolv.conf for DNS resolution
        try script.appendSlice(allocator, "mkdir -p ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/etc && ");
        try script.appendSlice(allocator, "cp /etc/resolv.conf ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, "/etc/resolv.conf && ");
    }

    /// Append cleanup (umount) trap so mounts are removed even on failure.
    fn appendCleanupTrap(script: *std.ArrayList(u8), allocator: std.mem.Allocator, rootfs: []const u8) !void {
        try script.appendSlice(allocator, "cleanup() { ");
        // Unmount in reverse order; ignore errors if not mounted
        const mounts = [_][]const u8{ "/dev/shm", "/sys", "/dev/pts", "/dev", "/proc" };
        for (mounts) |mnt| {
            try script.appendSlice(allocator, "umount ");
            try script.appendSlice(allocator, rootfs);
            try script.appendSlice(allocator, mnt);
            try script.appendSlice(allocator, " 2>/dev/null || true; ");
        }
        try script.appendSlice(allocator, "}; trap cleanup EXIT; ");
    }

    /// Append chroot command with env vars, workdir, and the user command.
    fn appendChrootCommand(
        script: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        rootfs: []const u8,
        command: []const u8,
        env_vars: []const isolazifile.EnvInstruction.EnvVar,
        workdir: ?[]const u8,
    ) !void {
        try script.appendSlice(allocator, "chroot ");
        try script.appendSlice(allocator, rootfs);
        try script.appendSlice(allocator, " /bin/sh -c '");

        // Standard environment
        try script.appendSlice(allocator, "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ");
        try script.appendSlice(allocator, "export HOME=/root; ");

        // User-defined environment variables with proper escaping
        for (env_vars) |env| {
            const escaped_value = try shellEscapeSingleQuotes(allocator, env.value);
            defer allocator.free(escaped_value);
            try script.appendSlice(allocator, "export ");
            try script.appendSlice(allocator, env.key);
            try script.appendSlice(allocator, "='");
            try script.appendSlice(allocator, escaped_value);
            try script.appendSlice(allocator, "'; ");
        }

        if (workdir) |wd| {
            try script.appendSlice(allocator, "cd ");
            try script.appendSlice(allocator, wd);
            try script.appendSlice(allocator, " && ");
        }

        // Escape single quotes in the command itself
        const escaped_cmd = try shellEscapeSingleQuotes(allocator, command);
        defer allocator.free(escaped_cmd);
        try script.appendSlice(allocator, escaped_cmd);
        try script.appendSlice(allocator, "'");
    }

    /// Check child process termination status and return error with stderr output.
    fn checkTermResult(term: std.process.Child.Term, stderr: []const u8) !void {
        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    if (stderr.len > 0) {
                        // Print last 2000 chars of stderr to avoid flooding
                        const start = if (stderr.len > 2000) stderr.len - 2000 else 0;
                        std.debug.print("Build command failed (exit code {d}):\n{s}\n", .{ code, stderr[start..] });
                    } else {
                        std.debug.print("Build command failed with exit code {d} (no stderr output)\n", .{code});
                    }
                    return error.CommandFailed;
                }
            },
            .Signal => |sig| {
                std.debug.print("Build command killed by signal {d}\n", .{sig});
                if (stderr.len > 0) {
                    const start = if (stderr.len > 2000) stderr.len - 2000 else 0;
                    std.debug.print("{s}\n", .{stderr[start..]});
                }
                return error.CommandFailed;
            },
            .Stopped => |sig| {
                std.debug.print("Build command stopped by signal {d}\n", .{sig});
                return error.CommandFailed;
            },
            .Unknown => |code| {
                std.debug.print("Build command terminated with unknown status {d}\n", .{code});
                return error.CommandFailed;
            },
        }
    }

    /// Run a command inside the build container
    pub fn runCommand(
        self: *Executor,
        rootfs_path: []const u8,
        command: []const u8,
        env_vars: []const isolazifile.EnvInstruction.EnvVar,
        workdir: ?[]const u8,
    ) !void {
        if (builtin.os.tag == .windows) {
            return self.runWindows(rootfs_path, command, env_vars, workdir);
        } else if (builtin.os.tag == .macos) {
            return self.runMacos(rootfs_path, command, env_vars, workdir);
        } else {
            return self.runLinux(rootfs_path, command, env_vars, workdir);
        }
    }

    /// Archive a directory (create layer tarball)
    pub fn archiveDirectory(
        self: *Executor,
        source_path: []const u8,
        dest_tar_path: []const u8,
    ) !void {
        if (builtin.os.tag == .windows) {
            return self.archiveWindows(source_path, dest_tar_path);
        } else if (builtin.os.tag == .macos) {
            return self.archiveMacos(source_path, dest_tar_path);
        } else {
            return self.archiveLinux(source_path, dest_tar_path);
        }
    }

    // =========================================================================
    // Windows Implementation (WSL2)
    // =========================================================================

    fn runWindows(
        self: *Executor,
        rootfs_path: []const u8,
        command: []const u8,
        env_vars: []const isolazifile.EnvInstruction.EnvVar,
        workdir: ?[]const u8,
    ) !void {
        var wsl_cmd: std.ArrayList([]const u8) = .empty;
        defer wsl_cmd.deinit(self.allocator);

        try wsl_cmd.append(self.allocator, "wsl");
        try wsl_cmd.append(self.allocator, "-u");
        try wsl_cmd.append(self.allocator, "root");
        try wsl_cmd.append(self.allocator, "--");
        try wsl_cmd.append(self.allocator, "unshare");
        try wsl_cmd.append(self.allocator, "--mount");
        try wsl_cmd.append(self.allocator, "--uts");
        try wsl_cmd.append(self.allocator, "--ipc");
        try wsl_cmd.append(self.allocator, "--pid");
        try wsl_cmd.append(self.allocator, "--fork");
        try wsl_cmd.append(self.allocator, "sh");
        try wsl_cmd.append(self.allocator, "-c");

        const wsl_rootfs = try self.windowsToWslPath(rootfs_path);
        defer self.allocator.free(wsl_rootfs);

        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(self.allocator);

        // Setup cleanup trap to unmount on exit
        try appendCleanupTrap(&script, self.allocator, wsl_rootfs);

        // Mount all required filesystems (/proc, /dev, /dev/pts, /sys, /dev/shm, resolv.conf)
        try appendMountSetup(&script, self.allocator, wsl_rootfs);

        // Chroot and execute the command
        try appendChrootCommand(&script, self.allocator, wsl_rootfs, command, env_vars, workdir);

        try wsl_cmd.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = wsl_cmd.items,
            .max_output_bytes = 10 * 1024 * 1024, // 10MB to capture large apt-get output
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        try checkTermResult(result.term, result.stderr);
    }

    fn archiveWindows(self: *Executor, source_path: []const u8, dest_tar_path: []const u8) !void {
        const wsl_source = try self.windowsToWslPath(source_path);
        defer self.allocator.free(wsl_source);

        const wsl_dest = try self.windowsToWslPath(dest_tar_path);
        defer self.allocator.free(wsl_dest);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "wsl",      "-u",   "root",   "--",
                "tar",      "-czf", wsl_dest, "-C",
                wsl_source, ".",
            },
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) {
            std.debug.print("Archive failed: {s}\n", .{result.stderr});
            return error.ArchiveFailed;
        }
    }

    fn windowsToWslPath(self: *Executor, windows_path: []const u8) ![]const u8 {
        // C:\Users\foo -> /mnt/c/Users/foo
        // This is a simplified conversion
        if (windows_path.len < 3 or windows_path[1] != ':') return self.allocator.dupe(u8, windows_path);

        const drive = std.ascii.toLower(windows_path[0]);
        const path = windows_path[3..];

        // Convert backslashes
        var wsl_path_buf: std.ArrayList(u8) = .empty;
        defer wsl_path_buf.deinit(self.allocator);

        try std.fmt.format(wsl_path_buf.writer(self.allocator), "/mnt/{c}/", .{drive});

        for (path) |c| {
            if (c == '\\') {
                try wsl_path_buf.append(self.allocator, '/');
            } else {
                try wsl_path_buf.append(self.allocator, c);
            }
        }

        return wsl_path_buf.toOwnedSlice(self.allocator);
    }

    // =========================================================================
    // Linux Implementation (Native)
    // =========================================================================

    fn runLinux(
        self: *Executor,
        rootfs_path: []const u8,
        command: []const u8,
        env_vars: []const isolazifile.EnvInstruction.EnvVar,
        workdir: ?[]const u8,
    ) !void {
        var cmd_list: std.ArrayList([]const u8) = .empty;
        defer cmd_list.deinit(self.allocator);

        try cmd_list.append(self.allocator, "unshare");
        try cmd_list.append(self.allocator, "--mount");
        try cmd_list.append(self.allocator, "--uts");
        try cmd_list.append(self.allocator, "--ipc");
        try cmd_list.append(self.allocator, "--pid");
        try cmd_list.append(self.allocator, "--fork");
        try cmd_list.append(self.allocator, "sh");
        try cmd_list.append(self.allocator, "-c");

        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(self.allocator);

        // Setup cleanup trap to unmount on exit
        try appendCleanupTrap(&script, self.allocator, rootfs_path);

        // Mount all required filesystems
        try appendMountSetup(&script, self.allocator, rootfs_path);

        // Chroot and execute the command
        try appendChrootCommand(&script, self.allocator, rootfs_path, command, env_vars, workdir);

        try cmd_list.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = cmd_list.items,
            .max_output_bytes = 10 * 1024 * 1024,
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        try checkTermResult(result.term, result.stderr);
    }

    fn archiveLinux(self: *Executor, source_path: []const u8, dest_tar_path: []const u8) !void {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "tar", "-czf", dest_tar_path, "-C", source_path, ".",
            },
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) return error.ArchiveFailed;
    }

    // =========================================================================
    // macOS Implementation (Lima)
    // =========================================================================

    fn runMacos(
        self: *Executor,
        rootfs_path: []const u8,
        command: []const u8,
        env_vars: []const isolazifile.EnvInstruction.EnvVar,
        workdir: ?[]const u8,
    ) !void {
        var lima_cmd: std.ArrayList([]const u8) = .empty;
        defer lima_cmd.deinit(self.allocator);

        try lima_cmd.append(self.allocator, "lima");
        try lima_cmd.append(self.allocator, "sudo");
        try lima_cmd.append(self.allocator, "unshare");
        try lima_cmd.append(self.allocator, "--mount");
        try lima_cmd.append(self.allocator, "--uts");
        try lima_cmd.append(self.allocator, "--ipc");
        try lima_cmd.append(self.allocator, "--pid");
        try lima_cmd.append(self.allocator, "--fork");
        try lima_cmd.append(self.allocator, "sh");
        try lima_cmd.append(self.allocator, "-c");

        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(self.allocator);

        // Setup cleanup trap to unmount on exit
        try appendCleanupTrap(&script, self.allocator, rootfs_path);

        // Mount all required filesystems
        try appendMountSetup(&script, self.allocator, rootfs_path);

        // Chroot and execute the command
        try appendChrootCommand(&script, self.allocator, rootfs_path, command, env_vars, workdir);

        try lima_cmd.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = lima_cmd.items,
            .max_output_bytes = 10 * 1024 * 1024,
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        try checkTermResult(result.term, result.stderr);
    }

    fn archiveMacos(self: *Executor, source_path: []const u8, dest_tar_path: []const u8) !void {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "lima", "sudo", "tar", "-czf", dest_tar_path, "-C", source_path, ".",
            },
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) return error.ArchiveFailed;
    }
};
