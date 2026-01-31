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
        // Construct WSL command to run in container environment
        // wsl -u root -- unshare --mount --uts --ipc --pid --fork sh -c "setup && command"

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

        // Convert Windows path to WSL path
        const wsl_rootfs = try self.windowsToWslPath(rootfs_path);
        defer self.allocator.free(wsl_rootfs);

        // Build the setup script + command
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(self.allocator);

        // 1. Mount proc
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, wsl_rootfs);
        try script.appendSlice(self.allocator, "/proc && ");

        try script.appendSlice(self.allocator, "mount -t proc proc ");
        try script.appendSlice(self.allocator, wsl_rootfs);
        try script.appendSlice(self.allocator, "/proc && ");

        // Copy resolv.conf
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, wsl_rootfs);
        try script.appendSlice(self.allocator, "/etc && ");
        try script.appendSlice(self.allocator, "cp /etc/resolv.conf ");
        try script.appendSlice(self.allocator, wsl_rootfs);
        try script.appendSlice(self.allocator, "/etc/resolv.conf && ");

        // 2. Chroot and run
        try script.appendSlice(self.allocator, "chroot ");
        try script.appendSlice(self.allocator, wsl_rootfs);
        try script.appendSlice(self.allocator, " /bin/sh -c '");

        // Environment variables
        try script.appendSlice(self.allocator, "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ");
        try script.appendSlice(self.allocator, "export HOME=/root; ");

        for (env_vars) |env| {
            try script.appendSlice(self.allocator, "export ");
            try script.appendSlice(self.allocator, env.key);
            try script.appendSlice(self.allocator, "='");
            // Simple escaping
            try script.appendSlice(self.allocator, env.value);
            try script.appendSlice(self.allocator, "'; ");
        }

        if (workdir) |wd| {
            try script.appendSlice(self.allocator, "cd ");
            try script.appendSlice(self.allocator, wd);
            try script.appendSlice(self.allocator, " && ");
        }
        try script.appendSlice(self.allocator, command);
        try script.appendSlice(self.allocator, "'");

        try wsl_cmd.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = wsl_cmd.items,
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) {
            std.debug.print("Build command failed: {s}\n", .{result.stderr});
            return error.CommandFailed;
        }
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

        // Mount proc
        // Mount proc
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/proc && ");
        try script.appendSlice(self.allocator, "mount -t proc proc ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/proc && ");

        // Copy resolv.conf
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/etc && ");
        try script.appendSlice(self.allocator, "cp /etc/resolv.conf ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/etc/resolv.conf && ");

        // Chroot and run
        try script.appendSlice(self.allocator, "chroot ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, " /bin/sh -c '");

        try script.appendSlice(self.allocator, "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ");
        try script.appendSlice(self.allocator, "export HOME=/root; ");

        for (env_vars) |env| {
            try script.appendSlice(self.allocator, "export ");
            try script.appendSlice(self.allocator, env.key);
            try script.appendSlice(self.allocator, "='");
            try script.appendSlice(self.allocator, env.value);
            try script.appendSlice(self.allocator, "'; ");
        }

        if (workdir) |wd| {
            try script.appendSlice(self.allocator, "cd ");
            try script.appendSlice(self.allocator, wd);
            try script.appendSlice(self.allocator, " && ");
        }
        try script.appendSlice(self.allocator, command);
        try script.appendSlice(self.allocator, "'");

        try cmd_list.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = cmd_list.items,
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) {
            return error.CommandFailed;
        }
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
        try lima_cmd.append(self.allocator, "sudo"); // Need root in VM
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

        // Mount proc
        // Mount proc
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/proc && ");
        try script.appendSlice(self.allocator, "mount -t proc proc ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/proc && ");

        // Copy resolv.conf
        try script.appendSlice(self.allocator, "mkdir -p ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/etc && ");
        try script.appendSlice(self.allocator, "cp /etc/resolv.conf ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, "/etc/resolv.conf && ");

        // Chroot
        try script.appendSlice(self.allocator, "chroot ");
        try script.appendSlice(self.allocator, rootfs_path);
        try script.appendSlice(self.allocator, " /bin/sh -c '");

        try script.appendSlice(self.allocator, "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ");
        try script.appendSlice(self.allocator, "export HOME=/root; ");

        for (env_vars) |env| {
            try script.appendSlice(self.allocator, "export ");
            try script.appendSlice(self.allocator, env.key);
            try script.appendSlice(self.allocator, "='");
            try script.appendSlice(self.allocator, env.value);
            try script.appendSlice(self.allocator, "'; ");
        }

        if (workdir) |wd| {
            try script.appendSlice(self.allocator, "cd ");
            try script.appendSlice(self.allocator, wd);
            try script.appendSlice(self.allocator, " && ");
        }
        try script.appendSlice(self.allocator, command);
        try script.appendSlice(self.allocator, "'");

        try lima_cmd.append(self.allocator, script.items);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = lima_cmd.items,
        });
        defer {
            self.allocator.free(result.stdout);
            self.allocator.free(result.stderr);
        }

        if (result.term.Exited != 0) return error.CommandFailed;
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
