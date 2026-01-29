//! Isolazi - Minimal Container Runtime
//!
//! Main entry point for the CLI application.
//!
//! Platform support:
//! - Linux: Native container execution using namespaces
//! - Windows: Delegates to WSL2 for container operations
//! - macOS: Uses Apple Virtualization framework for Linux VMs

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("isolazi");
const commands = isolazi.cli.commands;
const runmod = @import("isolazi").cli.commands.run_platform; // Run platform module with Windows impl

// Platform-specific module aliases for compile-time conditional access
const windows = if (builtin.os.tag == .windows) isolazi.windows else struct {
    pub fn isWslAvailable(_: std.mem.Allocator) bool {
        return false;
    }
    pub fn windowsToWslPath(_: std.mem.Allocator, path: []const u8) ![]const u8 {
        return path;
    }
    pub const WslConfig = struct {
        distro: ?[]const u8,
        isolazi_path: ?[]const u8,
        run_as_root: bool,
    };
    pub fn execInWsl(_: std.mem.Allocator, _: WslConfig, _: []const []const u8) !u8 {
        return 1;
    }
};

pub fn main() !u8 {
    // Get the writer for stdout/stderr
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    const stderr = &stderr_writer.interface;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get command-line arguments
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch |err| {
        try stderr.print("Failed to get arguments: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer std.process.argsFree(allocator, args);

    // Platform-specific execution
    if (isolazi.isWindows()) {
        return runOnWindows(allocator, args, stdout, stderr);
    } else if (isolazi.isLinux()) {
        return runOnLinux(allocator, args, stdout, stderr);
    } else if (isolazi.isMacOS()) {
        return runOnMacOS(allocator, args, stdout, stderr);
    } else {
        try stderr.writeAll("Error: Unsupported platform.\n");
        try stderr.writeAll("Isolazi supports Linux, Windows (via WSL2), and macOS (via Virtualization).\n");
        try stderr.flush();
        return 1;
    }
}

/// Windows-specific functions - only compiled on Windows
const runOnWindows = if (builtin.os.tag == .windows) struct {
    fn call(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        // Handle help and version locally (no need for WSL)
        // Handle update command (special case not in CLI parser yet)
        if (args.len >= 2 and std.mem.eql(u8, args[1], "update")) {
            return commands.update.selfUpdate(allocator, args, stdout, stderr);
        }

        // Parse CLI arguments
        const command = isolazi.cli.parse(args) catch |err| {
            try isolazi.cli.printError(stderr, err);
            try stderr.flush();
            return 1;
        };

        switch (command) {
            .version => {
                try isolazi.cli.printVersion(stdout);
                try stdout.writeAll("Platform: Windows (native image pull, WSL2 for container run)\n");
                try stdout.flush();
                return 0;
            },
            .help => {
                try isolazi.cli.printHelp(stdout);
                try stdout.writeAll("\nWindows Note: Image pull/list work natively. Running containers requires Linux.\n");
                try stdout.flush();
                return 0;
            },
            .run => |_| return runmod.platform.runContainer(allocator, args, stdout, stderr),
            .exec => |exec_cmd| return commands.exec.execContainer(allocator, exec_cmd, stdout, stderr),
            .create => |_| return commands.create.createContainer(allocator, args, stdout, stderr),
            .pull => |cmd| return commands.pull.pullImage(allocator, cmd.image, stdout, stderr, null, null),
            .images => return commands.images.listImages(allocator, stdout, stderr),
            .ps => |cmd| return commands.ps.listContainers(allocator, cmd, stdout, stderr),
            .start => |cmd| return commands.container.startContainer(allocator, cmd, stdout, stderr),
            .stop => |cmd| return commands.container.stopContainer(allocator, cmd, stdout, stderr),
            .rm => |cmd| return commands.container.removeContainer(allocator, cmd, stdout, stderr),
            .inspect => |cmd| return commands.inspect.inspectContainer(allocator, cmd, stdout, stderr),
            .logs => |cmd| return commands.logs.showLogs(allocator, cmd, stdout, stderr),
            .prune => |cmd| return commands.prune.prune(allocator, cmd, stdout, stderr),
        }

        // Check if WSL is available (only needed for 'run' command)
        if (!windows.isWslAvailable(allocator)) {
            try stderr.writeAll("Error: WSL2 is not available.\n");
            try stderr.writeAll("\nIsolazi on Windows requires WSL2 (Windows Subsystem for Linux).\n");
            try stderr.writeAll("\nTo install WSL2:\n");
            try stderr.writeAll("  1. Open PowerShell as Administrator\n");
            try stderr.writeAll("  2. Run: wsl --install\n");
            try stderr.writeAll("  3. Restart your computer\n");
            try stderr.writeAll("  4. Install Isolazi in WSL: zig build -Doptimize=ReleaseFast\n");
            try stderr.flush();
            return 1;
        }

        // Convert Windows paths to WSL paths for the 'run' command
        var wsl_args: std.ArrayList([]const u8) = .empty;
        defer {
            for (wsl_args.items) |item| {
                // Only free if it's not pointing to original args
                var is_original = false;
                for (args) |orig| {
                    if (item.ptr == orig.ptr) {
                        is_original = true;
                        break;
                    }
                }
                if (!is_original) allocator.free(item);
            }
            wsl_args.deinit(allocator);
        }

        // Skip args[0] (program name), process the rest
        for (args[1..]) |arg| {
            // Check if this looks like a Windows path (has drive letter)
            if (arg.len >= 2 and arg[1] == ':') {
                const wsl_path = windows.windowsToWslPath(allocator, arg) catch |err| {
                    try stderr.print("Error converting path '{s}': {}\n", .{ arg, err });
                    try stderr.flush();
                    return 1;
                };
                try wsl_args.append(allocator, wsl_path);
            } else {
                try wsl_args.append(allocator, arg);
            }
        }

        // Execute through WSL
        const wsl_config = windows.WslConfig{
            .distro = null, // Use default distro
            .isolazi_path = null, // Assume isolazi is in PATH
            .run_as_root = true, // Containers need root
        };

        return windows.execInWsl(allocator, wsl_config, wsl_args.items) catch |err| {
            try stderr.print("Error executing in WSL: {}\n", .{err});
            try stderr.writeAll("\nMake sure:\n");
            try stderr.writeAll("  1. WSL2 is properly installed\n");
            try stderr.writeAll("  2. Isolazi is installed in your WSL distribution\n");
            try stderr.writeAll("  3. The rootfs path is accessible from WSL\n");
            try stderr.flush();
            return 1;
        };
    }
}.call else struct {
    fn call(_: std.mem.Allocator, _: []const []const u8, _: anytype, stderr: anytype) !u8 {
        try stderr.writeAll("Error: Windows support is not available on this platform.\n");
        try stderr.flush();
        return 1;
    }
}.call;

/// Pull image on Windows (native, no WSL needed)
/// Pull image on Windows (delegated to shared pull command)
// pullImageWindows and listImagesWindows removed (delegated)

// RunOptions and parseRunOptions moved to cli/commands/run.zig
// runContainerWindows moved to cli/commands/run/windows.zig

// listContainersWindows removed (delegated)

/// Create a container without starting it
// createContainerWindows moved to cli/commands/create.zig

// start/stop/rm/inspect/prune/logs Windows removed (delegated)

/// Execute a command in a running container on Windows via WSL nsenter
// execContainerWindows moved to cli/commands/exec/windows.zig

/// Run on macOS using Apple Virtualization framework.
/// Only compiled on macOS platforms.
const runOnMacOS = if (builtin.os.tag == .macos) struct {
    fn call(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        // Handle help and version locally
        if (args.len >= 2) {
            const cmd = args[1];
            if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
                try isolazi.cli.printHelp(stdout);
                try stdout.writeAll("\nmacOS Note: Containers run in a lightweight Linux VM using Apple Virtualization.\n");
                try stdout.flush();
                return 0;
            }
            if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
                try isolazi.cli.printVersion(stdout);
                try stdout.writeAll("Platform: macOS (Apple Virtualization framework)\n");
                try stdout.flush();
                return 0;
            }
            // Handle special commands (not in standard CLI parser)
            if (std.mem.eql(u8, cmd, "update")) return commands.update.selfUpdate(allocator, args, stdout, stderr);
            if (std.mem.eql(u8, cmd, "vm")) return commands.vm.run(allocator, args, stdout, stderr);
        }

        // Parse arguments
        const command = isolazi.cli.parse(args) catch |err| {
            try isolazi.cli.printError(stderr, err);
            try stderr.flush();
            return 1;
        };

        switch (command) {
            .version => {
                try isolazi.cli.printVersion(stdout);
                try stdout.writeAll("Platform: macOS (Apple Virtualization framework)\n");
                try stdout.flush();
                return 0;
            },
            .help => {
                try isolazi.cli.printHelp(stdout);
                try stdout.writeAll("\nmacOS Note: Uses native Apple Virtualization framework.\n");
                try stdout.flush();
                return 0;
            },
            .run => |_| return runmod.platform.runContainer(allocator, args, stdout, stderr),
            .exec => |exec_cmd| return commands.exec.execContainer(allocator, exec_cmd, stdout, stderr),
            .create => |_| return commands.create.createContainer(allocator, args, stdout, stderr),
            .pull => |pull_cmd| return commands.pull.pullImage(allocator, pull_cmd.image, stdout, stderr, null, null),
            .images => return commands.images.listImages(allocator, stdout, stderr),
            .ps => |ps_cmd| return commands.ps.listContainers(allocator, ps_cmd, stdout, stderr),
            .start => |start_cmd| return commands.container.startContainer(allocator, start_cmd, stdout, stderr),
            .stop => |stop_cmd| return commands.container.stopContainer(allocator, stop_cmd, stdout, stderr),
            .rm => |rm_cmd| return commands.container.removeContainer(allocator, rm_cmd, stdout, stderr),
            .inspect => |inspect_cmd| return commands.inspect.inspectContainer(allocator, inspect_cmd, stdout, stderr),
            .logs => |logs_cmd| return commands.logs.showLogs(allocator, logs_cmd, stdout, stderr),
            .prune => |prune_cmd| return commands.prune.prune(allocator, prune_cmd, stdout, stderr),
        }
    }

    // start/stop/rm/inspect/prune/logs MacOS removed (delegated)

    // runContainerMacOS moved to cli/commands/run/macos.zig

    // createContainerMacOS moved to cli/commands/create.zig

    // execContainerMacOS moved to cli/commands/exec/macos.zig

    // vmCommandMacOS moved to cli/commands/vm.zig

}.call else struct {
    fn call(
        _: std.mem.Allocator,
        _: []const []const u8,
        _: anytype,
        stderr: anytype,
    ) !u8 {
        try stderr.writeAll("Error: macOS runtime not available on this platform.\n");
        try stderr.flush();
        return 1;
    }
}.call;

/// Run natively on Linux.
/// Only compiled on Linux platforms.
const runOnLinux = if (builtin.os.tag == .linux) struct {
    fn call(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        // Handle update command specially (not part of CLI parser)
        if (args.len >= 2 and std.mem.eql(u8, args[1], "update")) {
            return commands.update.selfUpdate(allocator, args, stdout, stderr);
        }

        // Parse CLI arguments
        const command = isolazi.cli.parse(args) catch |err| {
            try isolazi.cli.printError(stderr, err);
            try stderr.flush();
            return 1;
        };

        // Dispatch command
        // Dispatch command
        switch (command) {
            .version => {
                try isolazi.cli.printVersion(stdout);
                try stdout.flush();
                return 0;
            },
            .help => {
                try isolazi.cli.printHelp(stdout);
                try stdout.flush();
                return 0;
            },
            .pull => |cmd| return commands.pull.pullImage(allocator, cmd.image, stdout, stderr, null, null),
            .images => return commands.images.listImages(allocator, stdout, stderr),
            .run => |_| return runmod.platform.runContainer(allocator, args, stdout, stderr),
            .exec => |exec_cmd| return commands.exec.execContainer(allocator, exec_cmd, stdout, stderr),
            .logs => |logs_cmd| return commands.logs.showLogs(allocator, logs_cmd, stdout, stderr),
            .prune => |prune_cmd| return commands.prune.prune(allocator, prune_cmd, stdout, stderr),
            .ps => |cmd| return commands.ps.listContainers(allocator, cmd, stdout, stderr),
            .start => |cmd| return commands.container.startContainer(allocator, cmd, stdout, stderr),
            .stop => |cmd| return commands.container.stopContainer(allocator, cmd, stdout, stderr),
            .rm => |cmd| return commands.container.removeContainer(allocator, cmd, stdout, stderr),
            .inspect => |cmd| return commands.inspect.inspectContainer(allocator, cmd, stdout, stderr),
            .create => |_| return commands.create.createContainer(allocator, args, stdout, stderr),
        }
    }

    // Linux-specific implementations
    // Note: Other commands (ps, stop, etc.) are delegated to shared implementation

    // runContainerLinuxImpl moved to cli/commands/run/linux.zig

    /// Execute a command in a running container on Linux using nsenter
    // execContainerLinuxImpl moved to cli/commands/exec/linux.zig

    /// Display container logs on Linux
    fn logsContainerLinuxImpl(
        allocator: std.mem.Allocator,
        logs_cmd: isolazi.cli.LogsCommand,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        // Find container
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const full_id = manager.findContainer(logs_cmd.container_id) catch {
            try stderr.print("Error: No such container: {s}\n", .{logs_cmd.container_id});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(full_id);

        // Initialize container logs
        var logs = isolazi.container.ContainerLogs.init(allocator, full_id) catch |err| {
            try stderr.print("Error: Failed to initialize logs: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer logs.deinit();

        // Determine which stream to show
        const stream: isolazi.container.LogStream = if (logs_cmd.stdout_only and !logs_cmd.stderr_only)
            .stdout
        else if (logs_cmd.stderr_only and !logs_cmd.stdout_only)
            .stderr
        else
            .both;

        // Stream logs to stdout
        const options = isolazi.container.LogOptions{
            .follow = logs_cmd.follow,
            .timestamps = logs_cmd.timestamps,
            .tail = logs_cmd.tail,
            .stream = stream,
            .poll_interval_ms = 100,
        };

        logs.streamLogs(stdout, options) catch |err| {
            // In follow mode, this will block until interrupted
            if (err != error.BrokenPipe) {
                try stderr.print("Error reading logs: {}\n", .{err});
                try stderr.flush();
                return 1;
            }
        };

        try stdout.flush();
        return 0;
    }
}.call else struct {
    fn call(
        _: std.mem.Allocator,
        _: []const []const u8,
        _: anytype,
        stderr: anytype,
    ) !u8 {
        try stderr.writeAll("Error: Linux runtime not available on this platform.\n");
        try stderr.flush();
        return 1;
    }
}.call;

// updateIsolazi moved to cli/commands/update.zig
