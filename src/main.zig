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
        if (args.len >= 2) {
            const cmd = args[1];
            if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
                try isolazi.cli.printHelp(stdout);
                try stdout.writeAll("\nWindows Note: Image pull/list work natively. Running containers requires Linux.\n");
                try stdout.flush();
                return 0;
            }
            if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
                try isolazi.cli.printVersion(stdout);
                try stdout.writeAll("Platform: Windows (native image pull, WSL2 for container run)\n");
                try stdout.flush();
                return 0;
            }
            // Handle pull and images commands locally (don't need WSL)
            if (std.mem.eql(u8, cmd, "pull")) {
                return pullImageWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "images")) {
                return listImagesWindows(allocator, stdout, stderr);
            }
            // Handle run command - show message about Linux requirement
            if (std.mem.eql(u8, cmd, "run")) {
                return runContainerWindows(allocator, args, stdout, stderr);
            }
            // Handle exec command - execute in running container
            if (std.mem.eql(u8, cmd, "exec")) {
                return execContainerWindows(allocator, args, stdout, stderr);
            }
            // Container management commands
            if (std.mem.eql(u8, cmd, "ps")) {
                return listContainersWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "create")) {
                return createContainerWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "start")) {
                return startContainerWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "stop")) {
                return stopContainerWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "rm")) {
                return removeContainerWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "inspect")) {
                return inspectContainerWindows(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "prune")) {
                return pruneWindows(allocator, stdout, stderr);
            }
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
fn pullImageWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi pull <image>\n");
        try stderr.flush();
        return 1;
    }

    const image_name = args[2];
    try stdout.print("Pulling {s}...\n", .{image_name});
    try stdout.flush();

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    // Pull the image with progress reporting
    const progress_cb = struct {
        fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
            const stage_str = switch (stage) {
                .cached => "Cached",
                .authenticating => "Authenticating",
                .fetching_manifest => "Fetching manifest",
                .downloading_layer => "Downloading",
                .layer_cached => "Layer cached",
                .extracting => "Extracting",
                .complete => "Complete",
            };
            std.debug.print("  {s}: {s}\n", .{ stage_str, detail });
        }
    }.cb;

    const ref = isolazi.image.pullImage(allocator, image_name, &cache, &progress_cb) catch |err| {
        try stderr.print("Error: Failed to pull image: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    _ = ref;

    try stdout.print("Successfully pulled {s}\n", .{image_name});
    try stdout.flush();
    return 0;
}

/// List images on Windows (native, no WSL needed)
fn listImagesWindows(
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    const images = cache.listImages(allocator) catch |err| {
        try stderr.print("Error: Failed to list images: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer {
        for (images) |*img| {
            var mutable = img.*;
            mutable.deinit(allocator);
        }
        allocator.free(images);
    }

    try stdout.writeAll("REPOSITORY                          TAG       \n");
    try stdout.writeAll("--------------------------------------------\n");

    if (images.len == 0) {
        try stdout.writeAll("(no images)\n");
    } else {
        for (images) |img| {
            try stdout.print("{s}/{s}                  {s}\n", .{
                img.registry,
                img.repository,
                img.tag,
            });
        }
    }

    // Print stats
    const stats = cache.getStats() catch |err| {
        try stderr.print("Warning: Could not get cache stats: {}\n", .{err});
        try stderr.flush();
        return 0;
    };

    try stdout.print("\nTotal: {d} images, {d} blobs, {d:.2} MB\n", .{
        images.len,
        stats.total_blobs,
        @as(f64, @floatFromInt(stats.total_size)) / 1024.0 / 1024.0,
    });

    try stdout.flush();
    return 0;
}

/// Parsed options for run command (used in main.zig for all platforms)
const RunOptions = struct {
    detach_mode: bool = false,
    image_name: []const u8 = "",
    command_args: []const []const u8 = &[_][]const u8{},
    env_vars: []const EnvPair = &[_]EnvPair{},
    volumes: []const VolumePair = &[_]VolumePair{},
    ports: []const PortMapping = &[_]PortMapping{},
    rootless: bool = false,
    uid_maps: []const IdMapping = &[_]IdMapping{},
    gid_maps: []const IdMapping = &[_]IdMapping{},
    // Seccomp options
    seccomp_enabled: bool = true, // Default enabled
    seccomp_profile: SeccompProfileOption = .default_container,

    const EnvPair = struct {
        key: []const u8,
        value: []const u8,
    };

    const VolumePair = struct {
        host_path: []const u8,
        container_path: []const u8,
        read_only: bool,
    };

    const PortMapping = struct {
        host_port: u16,
        container_port: u16,
        protocol: Protocol = .tcp,

        pub const Protocol = enum {
            tcp,
            udp,
        };
    };

    const IdMapping = struct {
        container_id: u32,
        host_id: u32,
        count: u32 = 1,
    };

    const SeccompProfileOption = enum {
        disabled,
        default_container,
        minimal,
        strict,
    };
};

/// Parse run command arguments (shared by all platforms)
fn parseRunOptions(allocator: std.mem.Allocator, args: []const []const u8) !RunOptions {
    var opts = RunOptions{};

    // Static buffers for env vars, volumes, ports, and id maps
    var env_buf: [64]RunOptions.EnvPair = undefined;
    var env_count: usize = 0;
    var vol_buf: [32]RunOptions.VolumePair = undefined;
    var vol_count: usize = 0;
    var port_buf: [32]RunOptions.PortMapping = undefined;
    var port_count: usize = 0;
    var uid_map_buf: [8]RunOptions.IdMapping = undefined;
    var uid_map_count: usize = 0;
    var gid_map_buf: [8]RunOptions.IdMapping = undefined;
    var gid_map_count: usize = 0;

    // Command args buffer
    var cmd_buf: [64][]const u8 = undefined;
    var cmd_count: usize = 0;

    var arg_idx: usize = 2; // Skip "isolazi" and "run"
    var image_found = false;

    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];

        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
            opts.detach_mode = true;
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const env_str = args[arg_idx];

            // Support comma-separated KEY=VALUE,KEY2=VALUE2 format
            var env_iter = std.mem.splitScalar(u8, env_str, ',');
            while (env_iter.next()) |single_env| {
                if (std.mem.indexOf(u8, single_env, "=")) |eq_pos| {
                    if (env_count < env_buf.len) {
                        env_buf[env_count] = .{
                            .key = single_env[0..eq_pos],
                            .value = single_env[eq_pos + 1 ..],
                        };
                        env_count += 1;
                    }
                }
            }
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--volume")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const vol_str = args[arg_idx];

            // Parse /host:/container[:ro]
            if (parseVolume(vol_str)) |vol| {
                if (vol_count < vol_buf.len) {
                    vol_buf[vol_count] = vol;
                    vol_count += 1;
                }
            }
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "--publish")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const port_str = args[arg_idx];

            // Parse host_port:container_port
            if (parsePort(port_str)) |port| {
                if (port_count < port_buf.len) {
                    port_buf[port_count] = port;
                    port_count += 1;
                }
            }
        } else if (std.mem.eql(u8, arg, "--rootless") or std.mem.eql(u8, arg, "--userns")) {
            opts.rootless = true;
        } else if (std.mem.eql(u8, arg, "--no-seccomp") or std.mem.eql(u8, arg, "--disable-seccomp")) {
            opts.seccomp_enabled = false;
            opts.seccomp_profile = .disabled;
        } else if (std.mem.eql(u8, arg, "--seccomp")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const profile_str = args[arg_idx];
            if (std.mem.eql(u8, profile_str, "disabled") or std.mem.eql(u8, profile_str, "none")) {
                opts.seccomp_enabled = false;
                opts.seccomp_profile = .disabled;
            } else if (std.mem.eql(u8, profile_str, "default") or std.mem.eql(u8, profile_str, "default-container")) {
                opts.seccomp_profile = .default_container;
            } else if (std.mem.eql(u8, profile_str, "minimal")) {
                opts.seccomp_profile = .minimal;
            } else if (std.mem.eql(u8, profile_str, "strict")) {
                opts.seccomp_profile = .strict;
            }
        } else if (std.mem.eql(u8, arg, "--uid-map") or std.mem.eql(u8, arg, "--uidmap")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const map_str = args[arg_idx];
            if (parseIdMap(map_str)) |id_map| {
                if (uid_map_count < uid_map_buf.len) {
                    uid_map_buf[uid_map_count] = id_map;
                    uid_map_count += 1;
                }
            }
        } else if (std.mem.eql(u8, arg, "--gid-map") or std.mem.eql(u8, arg, "--gidmap")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const map_str = args[arg_idx];
            if (parseIdMap(map_str)) |id_map| {
                if (gid_map_count < gid_map_buf.len) {
                    gid_map_buf[gid_map_count] = id_map;
                    gid_map_count += 1;
                }
            }
        } else if (arg.len > 0 and arg[0] == '-') {
            // Skip flags with values (these will be passed through to Linux binary)
            if (std.mem.eql(u8, arg, "--hostname") or
                std.mem.eql(u8, arg, "--cwd") or
                std.mem.eql(u8, arg, "-m") or
                std.mem.eql(u8, arg, "--memory") or
                std.mem.eql(u8, arg, "--memory-swap") or
                std.mem.eql(u8, arg, "-c") or
                std.mem.eql(u8, arg, "--cpus") or
                std.mem.eql(u8, arg, "--cpu-quota") or
                std.mem.eql(u8, arg, "--cpu-period") or
                std.mem.eql(u8, arg, "--cpu-weight") or
                std.mem.eql(u8, arg, "--cpu-shares") or
                std.mem.eql(u8, arg, "--io-weight") or
                std.mem.eql(u8, arg, "--blkio-weight") or
                std.mem.eql(u8, arg, "--oom-score-adj"))
            {
                arg_idx += 1; // Skip the value
            }
            // Boolean flags (no value to skip): --oom-kill-disable, --chroot
        } else if (!image_found) {
            opts.image_name = arg;
            image_found = true;
        } else {
            // This is a command argument (after image, not a flag)
            if (cmd_count < cmd_buf.len) {
                cmd_buf[cmd_count] = arg;
                cmd_count += 1;
            }
        }
    }

    // Allocate command args
    if (cmd_count > 0) {
        const cmd_slice = try allocator.alloc([]const u8, cmd_count);
        @memcpy(cmd_slice, cmd_buf[0..cmd_count]);
        opts.command_args = cmd_slice;
    }

    // Allocate and copy env vars
    if (env_count > 0) {
        const env_slice = try allocator.alloc(RunOptions.EnvPair, env_count);
        @memcpy(env_slice, env_buf[0..env_count]);
        opts.env_vars = env_slice;
    }

    // Allocate and copy volumes
    if (vol_count > 0) {
        const vol_slice = try allocator.alloc(RunOptions.VolumePair, vol_count);
        @memcpy(vol_slice, vol_buf[0..vol_count]);
        opts.volumes = vol_slice;
    }

    // Allocate and copy ports
    if (port_count > 0) {
        const port_slice = try allocator.alloc(RunOptions.PortMapping, port_count);
        @memcpy(port_slice, port_buf[0..port_count]);
        opts.ports = port_slice;
    }

    // Allocate and copy UID mappings
    if (uid_map_count > 0) {
        const uid_map_slice = try allocator.alloc(RunOptions.IdMapping, uid_map_count);
        @memcpy(uid_map_slice, uid_map_buf[0..uid_map_count]);
        opts.uid_maps = uid_map_slice;
    }

    // Allocate and copy GID mappings
    if (gid_map_count > 0) {
        const gid_map_slice = try allocator.alloc(RunOptions.IdMapping, gid_map_count);
        @memcpy(gid_map_slice, gid_map_buf[0..gid_map_count]);
        opts.gid_maps = gid_map_slice;
    }

    return opts;
}

fn parseVolume(s: []const u8) ?RunOptions.VolumePair {
    // Handle Windows paths (C:\path)
    var colon_pos: usize = 0;
    if (s.len >= 2 and s[1] == ':' and ((s[0] >= 'A' and s[0] <= 'Z') or (s[0] >= 'a' and s[0] <= 'z'))) {
        colon_pos = if (std.mem.indexOf(u8, s[2..], ":")) |pos| pos + 2 else return null;
    } else {
        colon_pos = std.mem.indexOf(u8, s, ":") orelse return null;
    }

    const host_path = s[0..colon_pos];
    const rest = s[colon_pos + 1 ..];

    var container_path: []const u8 = rest;
    var read_only = false;

    if (std.mem.lastIndexOf(u8, rest, ":")) |last_colon| {
        const suffix = rest[last_colon + 1 ..];
        if (std.mem.eql(u8, suffix, "ro")) {
            read_only = true;
            container_path = rest[0..last_colon];
        } else if (std.mem.eql(u8, suffix, "rw")) {
            container_path = rest[0..last_colon];
        }
    }

    if (container_path.len == 0) return null;

    return .{
        .host_path = host_path,
        .container_path = container_path,
        .read_only = read_only,
    };
}

/// Parse port mapping (host_port:container_port)
fn parsePort(s: []const u8) ?RunOptions.PortMapping {
    // Parse protocol suffix (e.g., "8080:80/tcp" or "8080:80/udp")
    var port_str = s;
    var protocol: RunOptions.PortMapping.Protocol = .tcp;
    if (std.mem.indexOf(u8, s, "/")) |slash_pos| {
        const proto_str = s[slash_pos + 1 ..];
        if (std.mem.eql(u8, proto_str, "udp")) {
            protocol = .udp;
        }
        port_str = s[0..slash_pos];
    }

    const colon_pos = std.mem.indexOf(u8, port_str, ":") orelse {
        // Single port means same for host and container
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return .{ .host_port = port, .container_port = port, .protocol = protocol };
    };

    const host_str = port_str[0..colon_pos];
    const container_str = port_str[colon_pos + 1 ..];

    const host_port = std.fmt.parseInt(u16, host_str, 10) catch return null;
    const container_port = std.fmt.parseInt(u16, container_str, 10) catch return null;

    return .{ .host_port = host_port, .container_port = container_port, .protocol = protocol };
}

/// Parse ID mapping (container_id:host_id[:count])
fn parseIdMap(s: []const u8) ?RunOptions.IdMapping {
    var iter = std.mem.splitScalar(u8, s, ':');

    const container_str = iter.next() orelse return null;
    const host_str = iter.next() orelse return null;
    const count_str = iter.next() orelse "1";

    const container_id = std.fmt.parseInt(u32, container_str, 10) catch return null;
    const host_id = std.fmt.parseInt(u32, host_str, 10) catch return null;
    const count = std.fmt.parseInt(u32, count_str, 10) catch return null;

    return .{
        .container_id = container_id,
        .host_id = host_id,
        .count = count,
    };
}

/// Run container on Windows using WSL2 backend
fn runContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Parse run options
    const opts = parseRunOptions(allocator, args) catch {
        try stderr.writeAll("Error: Failed to parse run options\n");
        try stderr.flush();
        return 1;
    };
    defer {
        if (opts.env_vars.len > 0) allocator.free(opts.env_vars);
        if (opts.volumes.len > 0) allocator.free(opts.volumes);
        if (opts.ports.len > 0) allocator.free(opts.ports);
        if (opts.command_args.len > 0) allocator.free(opts.command_args);
    }

    // Check if we have an image argument
    if (opts.image_name.len == 0) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi run [options] <image> [command...]\n");
        try stderr.writeAll("\nOptions:\n");
        try stderr.writeAll("  -d, --detach              Run in background\n");
        try stderr.writeAll("  -e, --env KEY=VALUE       Set environment variable\n");
        try stderr.writeAll("  -v, --volume SRC:DST[:ro] Mount a volume\n");
        try stderr.writeAll("  -p, --port HOST:CONTAINER Publish port\n");
        try stderr.flush();
        return 1;
    }

    const image_name = opts.image_name;

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    // Parse the image reference
    const ref = isolazi.image.reference.parse(image_name) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{image_name});
        try stderr.flush();
        return 1;
    };

    // Check if image is cached, pull if not (like Docker)
    const has_image = cache.hasImage(&ref) catch false;
    if (!has_image) {
        try stdout.print("Unable to find image '{s}' locally\n", .{image_name});
        try stdout.flush();

        // Pull the image
        const progress_cb = struct {
            fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
                const stage_str = switch (stage) {
                    .cached => "Cached",
                    .authenticating => "Authenticating",
                    .fetching_manifest => "Fetching manifest",
                    .downloading_layer => "Pulling",
                    .layer_cached => "Layer exists",
                    .extracting => "Extracting",
                    .complete => "Status",
                };
                std.debug.print("{s}: {s}\n", .{ stage_str, detail });
            }
        }.cb;

        _ = isolazi.image.pullImage(allocator, image_name, &cache, &progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("Downloaded newer image for {s}\n", .{image_name});
        try stdout.flush();
    }

    // Check if WSL is available
    if (!windows.isWslAvailable(allocator)) {
        try stderr.writeAll("Error: WSL2 is required to run containers on Windows.\n");
        try stderr.writeAll("\nTo install WSL2:\n");
        try stderr.writeAll("  1. Open PowerShell as Administrator\n");
        try stderr.writeAll("  2. Run: wsl --install\n");
        try stderr.writeAll("  3. Restart your computer\n");
        try stderr.flush();
        return 1;
    }

    // Read manifest to get layer digests
    const manifest_data = cache.readManifest(&ref) catch |err| {
        try stderr.print("Error: Failed to read manifest: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(manifest_data);

    // Parse manifest for layers
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
        try stderr.writeAll("Error: Invalid manifest format\n");
        try stderr.flush();
        return 1;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const layers_json = root.object.get("layers") orelse {
        try stderr.writeAll("Error: No layers in manifest\n");
        try stderr.flush();
        return 1;
    };

    // Collect layer digests
    var layer_digests: std.ArrayList([]const u8) = .empty;
    defer layer_digests.deinit(allocator);

    for (layers_json.array.items) |layer_obj| {
        const digest = layer_obj.object.get("digest") orelse continue;
        try layer_digests.append(allocator, digest.string);
    }

    // Generate container ID
    var container_id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&container_id_buf);
    var container_id: [32]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (container_id_buf, 0..) |byte, i| {
        container_id[i * 2] = hex_chars[byte >> 4];
        container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    // Prepare container rootfs
    if (!opts.detach_mode) {
        try stdout.print("Preparing container {s}...\n", .{container_id[0..12]});
        try stdout.flush();
    }

    const rootfs_path = cache.prepareContainer(&container_id, layer_digests.items) catch |err| {
        try stderr.print("Error: Failed to prepare container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(rootfs_path);

    // Convert Windows path to WSL path
    const wsl_rootfs = windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
        try stderr.print("Error: Failed to convert path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_rootfs);

    // Get command to run (default: /bin/sh)
    var cmd_args: std.ArrayList([]const u8) = .empty;
    defer cmd_args.deinit(allocator);

    if (opts.command_args.len > 0) {
        // User specified command
        for (opts.command_args) |arg| {
            try cmd_args.append(allocator, arg);
        }
    } else {
        // Check if this is a postgres image - auto-run entrypoint
        if (std.mem.indexOf(u8, image_name, "postgres") != null) {
            try cmd_args.append(allocator, "docker-entrypoint.sh");
            try cmd_args.append(allocator, "postgres");
        } else {
            // Default command
            try cmd_args.append(allocator, "/bin/sh");
        }
    }

    // Build the command to run in WSL
    // We use unshare to create namespaces and chroot into the rootfs
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");

    // For detach mode, wrap everything in nohup/setsid
    if (opts.detach_mode) {
        try wsl_cmd.append(allocator, "setsid");
    }

    // Always use shell script approach for proper setup
    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");

    // Add user namespace for rootless containers
    if (opts.rootless) {
        try wsl_cmd.append(allocator, "--user");
        try wsl_cmd.append(allocator, "--map-root-user");
    }

    try wsl_cmd.append(allocator, "sh");
    try wsl_cmd.append(allocator, "-c");

    var script_buf: std.ArrayList(u8) = .empty;
    defer script_buf.deinit(allocator);

    // Track allocated paths for cleanup
    var allocated_paths: [64][]const u8 = undefined;
    var alloc_count: usize = 0;
    defer {
        for (allocated_paths[0..alloc_count]) |p| {
            allocator.free(p);
        }
    }

    // Mount proc inside the rootfs
    try script_buf.appendSlice(allocator, "mount -t proc proc ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/proc && ");

    // Create /dev/fd symlink for bash process substitution
    try script_buf.appendSlice(allocator, "ln -sf /proc/self/fd ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, "/dev/fd 2>/dev/null; ");

    // For postgres images, set up required directories on tmpfs (Windows FS doesn't support chmod)
    const is_postgres = std.mem.indexOf(u8, image_name, "postgres") != null;
    if (is_postgres) {
        // Mount tmpfs for /var/run/postgresql (unix socket directory)
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && chown 70:70 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && chmod 775 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/run/postgresql && ");

        // Mount tmpfs for /var/lib/postgresql/data (PGDATA needs chmod support)
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && mount -t tmpfs tmpfs ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && chown 70:70 ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, "/var/lib/postgresql/data && ");
    }

    // Mount each volume
    for (opts.volumes) |vol| {
        const wsl_host = windows.windowsToWslPath(allocator, vol.host_path) catch vol.host_path;
        // Track allocation if it's different from original (meaning it was allocated)
        if (wsl_host.ptr != vol.host_path.ptr and alloc_count < allocated_paths.len) {
            allocated_paths[alloc_count] = wsl_host;
            alloc_count += 1;
        }
        try script_buf.appendSlice(allocator, "mkdir -p ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, vol.container_path);
        try script_buf.appendSlice(allocator, " && mount --bind ");
        if (vol.read_only) {
            try script_buf.appendSlice(allocator, "-o ro ");
        }
        try script_buf.appendSlice(allocator, wsl_host);
        try script_buf.append(allocator, ' ');
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.appendSlice(allocator, vol.container_path);
        try script_buf.appendSlice(allocator, " && ");
    }

    // Set up port forwarding using iptables in WSL2
    // This forwards from WSL2's network namespace to the container
    for (opts.ports) |port| {
        // Enable IP forwarding and set up DNAT rule
        try script_buf.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ");
        if (port.protocol == .udp) {
            try script_buf.appendSlice(allocator, "udp");
        } else {
            try script_buf.appendSlice(allocator, "tcp");
        }
        try script_buf.appendSlice(allocator, " --dport ");
        var host_port_buf: [8]u8 = undefined;
        const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
        try script_buf.appendSlice(allocator, host_port_str);
        try script_buf.appendSlice(allocator, " -j REDIRECT --to-port ");
        var cont_port_buf: [8]u8 = undefined;
        const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";
        try script_buf.appendSlice(allocator, cont_port_str);
        try script_buf.appendSlice(allocator, " 2>/dev/null; ");
    }

    // Add chroot command with env vars
    // Use env -i to clear inherited environment and set fresh vars
    try script_buf.appendSlice(allocator, "exec chroot ");
    try script_buf.appendSlice(allocator, wsl_rootfs);
    try script_buf.appendSlice(allocator, " /usr/bin/env -i ");

    // Set minimal required environment
    try script_buf.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ");
    try script_buf.appendSlice(allocator, "HOME=/root ");
    try script_buf.appendSlice(allocator, "TERM=xterm ");
    try script_buf.appendSlice(allocator, "LANG=C.UTF-8 ");

    // For postgres, auto-set PGDATA if not provided
    var has_pgdata = false;
    for (opts.env_vars) |env| {
        if (std.mem.eql(u8, env.key, "PGDATA")) {
            has_pgdata = true;
            break;
        }
    }
    if (is_postgres and !has_pgdata) {
        // Find volume mount for /var/lib/postgresql and set PGDATA
        for (opts.volumes) |vol| {
            if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                try script_buf.appendSlice(allocator, "PGDATA=");
                // If mounting directly to /var/lib/postgresql/data, use as-is
                // Otherwise append /data
                if (std.mem.endsWith(u8, vol.container_path, "/data")) {
                    try script_buf.appendSlice(allocator, vol.container_path);
                } else {
                    try script_buf.appendSlice(allocator, vol.container_path);
                    try script_buf.appendSlice(allocator, "/data");
                }
                try script_buf.append(allocator, ' ');
                has_pgdata = true;
                break;
            }
        }
        if (!has_pgdata) {
            // Default PGDATA
            try script_buf.appendSlice(allocator, "PGDATA=/var/lib/postgresql/data ");
        }
    }

    // Export environment variables
    for (opts.env_vars) |env| {
        try script_buf.appendSlice(allocator, env.key);
        try script_buf.appendSlice(allocator, "=");
        try script_buf.appendSlice(allocator, env.value);
        try script_buf.append(allocator, ' ');
    }

    // Run the command
    for (cmd_args.items) |arg| {
        try script_buf.appendSlice(allocator, arg);
        try script_buf.append(allocator, ' ');
    }

    // For detach mode, redirect output inside the script
    if (opts.detach_mode) {
        try script_buf.appendSlice(allocator, ">/dev/null 2>&1");
    }

    try wsl_cmd.append(allocator, script_buf.items);

    if (opts.detach_mode) {
        // For detach mode, print container ID and return immediately
        try stdout.print("{s}\n", .{container_id});
        // Print port mappings
        for (opts.ports) |port| {
            if (port.host_port == port.container_port) {
                try stdout.print("Port {d} published\n", .{port.host_port});
            } else {
                try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
            }
        }
        try stdout.flush();
    } else {
        try stdout.print("Starting container...\n", .{});
        // Print port mappings
        for (opts.ports) |port| {
            if (port.host_port == port.container_port) {
                try stdout.print("Port {d} published\n", .{port.host_port});
            } else {
                try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
            }
        }
        try stdout.flush();
    }

    // Register container with ContainerManager
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    // Build command string for state
    var cmd_str_buf: [512]u8 = undefined;
    var cmd_str_len: usize = 0;
    for (cmd_args.items, 0..) |arg, i| {
        if (i > 0) {
            cmd_str_buf[cmd_str_len] = ' ';
            cmd_str_len += 1;
        }
        const copy_len = @min(arg.len, cmd_str_buf.len - cmd_str_len);
        @memcpy(cmd_str_buf[cmd_str_len..][0..copy_len], arg[0..copy_len]);
        cmd_str_len += copy_len;
    }

    _ = manager.createContainerWithId(&container_id, image_name, cmd_str_buf[0..cmd_str_len], null) catch |err| {
        try stderr.print("Warning: Failed to register container: {}\n", .{err});
    };

    // Execute in WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (opts.detach_mode) {
        // In detach mode, don't inherit stdio
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
    } else {
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
    }

    try child.spawn();

    if (opts.detach_mode) {
        // Update state to running and return
        manager.updateState(&container_id, .running, null, null) catch {};
        return 0;
    }

    // Update state to running while container executes
    manager.updateState(&container_id, .running, null, null) catch {};

    const term = try child.wait();

    // Update state to stopped after container exits
    const exit_code: u8 = switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
    manager.updateState(&container_id, .stopped, null, exit_code) catch {};

    return exit_code;
}

/// List containers (like docker ps)
fn listContainersWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Parse -a/--all flag
    var show_all = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            show_all = true;
        }
    }

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(show_all) catch |err| {
        try stderr.print("Error: Failed to list containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer {
        for (containers) |*c| {
            @constCast(c).deinit();
        }
        allocator.free(containers);
    }

    // Print header
    try stdout.writeAll("CONTAINER ID   IMAGE                    COMMAND         STATUS\n");

    if (containers.len == 0) {
        if (!show_all) {
            try stdout.writeAll("(no running containers, use -a to show all)\n");
        } else {
            try stdout.writeAll("(no containers)\n");
        }
    } else {
        for (containers) |c| {
            // Truncate image and command for display
            const image_display = if (c.image.len > 24) c.image[0..24] else c.image;
            const cmd_display = if (c.command.len > 15) c.command[0..15] else c.command;

            try stdout.print("{s}   {s: <24} {s: <15} {s}\n", .{
                c.shortId(),
                image_display,
                cmd_display,
                c.state.toString(),
            });
        }
    }

    try stdout.flush();
    return 0;
}

/// Create a container without starting it
fn createContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi create [--name NAME] <image> [command...]\n");
        try stderr.flush();
        return 1;
    }

    // Parse arguments
    var name: ?[]const u8 = null;
    var image_idx: usize = 2;
    var arg_idx: usize = 2;

    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];
        if (std.mem.eql(u8, arg, "--name")) {
            arg_idx += 1;
            if (arg_idx >= args.len) {
                try stderr.writeAll("Error: --name requires a value\n");
                try stderr.flush();
                return 1;
            }
            name = args[arg_idx];
        } else if (arg.len > 0 and arg[0] != '-') {
            image_idx = arg_idx;
            break;
        }
    }

    if (image_idx >= args.len) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.flush();
        return 1;
    }

    const image_name = args[image_idx];

    // Collect command
    var command_buf: [1024]u8 = undefined;
    var command_len: usize = 0;
    if (args.len > image_idx + 1) {
        for (args[image_idx + 1 ..]) |arg| {
            if (command_len > 0) {
                command_buf[command_len] = ' ';
                command_len += 1;
            }
            const copy_len = @min(arg.len, command_buf.len - command_len);
            @memcpy(command_buf[command_len .. command_len + copy_len], arg[0..copy_len]);
            command_len += copy_len;
        }
    } else {
        const default_cmd = "/bin/sh";
        @memcpy(command_buf[0..default_cmd.len], default_cmd);
        command_len = default_cmd.len;
    }

    // Initialize image cache and pull if needed
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    const ref = isolazi.image.reference.parse(image_name) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{image_name});
        try stderr.flush();
        return 1;
    };

    const has_image = cache.hasImage(&ref) catch false;
    if (!has_image) {
        try stdout.print("Unable to find image '{s}' locally, pulling...\n", .{image_name});
        try stdout.flush();

        _ = isolazi.image.pullImage(allocator, image_name, &cache, null) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
    }

    // Create container
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const container_id = manager.createContainer(image_name, command_buf[0..command_len], name) catch |err| {
        try stderr.print("Error: Failed to create container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    try stdout.print("{s}\n", .{container_id});
    try stdout.flush();
    return 0;
}

/// Start a stopped container
fn startContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.writeAll("Usage: isolazi start <container>\n");
        try stderr.flush();
        return 1;
    }

    const query = args[2];

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    // Find container
    const container_id = manager.findContainer(query) catch {
        try stderr.print("Error: No such container: {s}\n", .{query});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(container_id);

    // Get container info
    var info = manager.getContainer(container_id) catch {
        try stderr.print("Error: Failed to get container info\n", .{});
        try stderr.flush();
        return 1;
    };
    defer info.deinit();

    if (info.state == .running) {
        try stderr.print("Error: Container {s} is already running\n", .{info.shortId()});
        try stderr.flush();
        return 1;
    }

    // Initialize image cache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer cache.deinit();

    // Parse image reference
    const ref = isolazi.image.reference.parse(info.image) catch {
        try stderr.print("Error: Invalid image reference: {s}\n", .{info.image});
        try stderr.flush();
        return 1;
    };

    // Read manifest for layers
    const manifest_data = cache.readManifest(&ref) catch |err| {
        try stderr.print("Error: Failed to read manifest: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(manifest_data);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
        try stderr.writeAll("Error: Invalid manifest format\n");
        try stderr.flush();
        return 1;
    };
    defer parsed.deinit();

    const layers_json = parsed.value.object.get("layers") orelse {
        try stderr.writeAll("Error: No layers in manifest\n");
        try stderr.flush();
        return 1;
    };

    var layer_digests: std.ArrayList([]const u8) = .empty;
    defer layer_digests.deinit(allocator);

    for (layers_json.array.items) |layer_obj| {
        const digest = layer_obj.object.get("digest") orelse continue;
        try layer_digests.append(allocator, digest.string);
    }

    // Prepare rootfs
    const rootfs_path = cache.prepareContainer(&info.id, layer_digests.items) catch |err| {
        try stderr.print("Error: Failed to prepare container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(rootfs_path);

    // Convert to WSL path
    const wsl_rootfs = windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
        try stderr.print("Error: Failed to convert path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_rootfs);

    // Build WSL command
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");
    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");
    try wsl_cmd.append(allocator, "--mount-proc");
    try wsl_cmd.append(allocator, "chroot");
    try wsl_cmd.append(allocator, wsl_rootfs);

    // Parse and add command
    var iter = std.mem.splitScalar(u8, info.command, ' ');
    while (iter.next()) |part| {
        if (part.len > 0) {
            try wsl_cmd.append(allocator, part);
        }
    }

    // Update state to running
    manager.updateState(container_id, .running, null, null) catch {};

    try stdout.print("{s}\n", .{info.shortId()});
    try stdout.flush();

    // Execute
    var child = std.process.Child.init(wsl_cmd.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    // Update state to stopped
    const exit_code: u8 = switch (term) {
        .Exited => |code| code,
        else => 1,
    };
    manager.updateState(container_id, .stopped, null, exit_code) catch {};

    return exit_code;
}

/// Stop a running container
fn stopContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.writeAll("Usage: isolazi stop <container>\n");
        try stderr.flush();
        return 1;
    }

    const query = args[2];

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const container_id = manager.findContainer(query) catch {
        try stderr.print("Error: No such container: {s}\n", .{query});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(container_id);

    manager.stopContainer(container_id) catch |err| {
        if (err == error.ContainerNotRunning) {
            try stderr.print("Error: Container {s} is not running\n", .{query});
            try stderr.flush();
            return 1;
        }
        try stderr.print("Error: Failed to stop container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    try stdout.print("{s}\n", .{container_id[0..12]});
    try stdout.flush();
    return 0;
}

/// Remove a container
fn removeContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.writeAll("Usage: isolazi rm [-f|--force] <container>\n");
        try stderr.flush();
        return 1;
    }

    // Parse flags
    var force = false;
    var container_query: ?[]const u8 = null;

    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            force = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            container_query = arg;
        }
    }

    if (container_query == null) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.flush();
        return 1;
    }

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const container_id = manager.findContainer(container_query.?) catch {
        try stderr.print("Error: No such container: {s}\n", .{container_query.?});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(container_id);

    manager.removeContainer(container_id, force) catch |err| {
        if (err == error.ContainerRunning) {
            try stderr.print("Error: Container {s} is running. Use -f to force remove.\n", .{container_id[0..12]});
            try stderr.flush();
            return 1;
        }
        try stderr.print("Error: Failed to remove container: {}\n", .{err});
        try stderr.flush();
        return 1;
    };

    try stdout.print("{s}\n", .{container_id[0..12]});
    try stdout.flush();
    return 0;
}

/// Inspect container details
fn inspectContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (args.len < 3) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.writeAll("Usage: isolazi inspect <container>\n");
        try stderr.flush();
        return 1;
    }

    const query = args[2];

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const container_id = manager.findContainer(query) catch {
        try stderr.print("Error: No such container: {s}\n", .{query});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(container_id);

    var info = manager.getContainer(container_id) catch {
        try stderr.print("Error: Failed to get container info\n", .{});
        try stderr.flush();
        return 1;
    };
    defer info.deinit();

    // Output JSON-like format
    try stdout.writeAll("{\n");
    try stdout.print("  \"Id\": \"{s}\",\n", .{info.id});
    try stdout.print("  \"Image\": \"{s}\",\n", .{info.image});
    try stdout.print("  \"Command\": \"{s}\",\n", .{info.command});
    try stdout.print("  \"State\": \"{s}\",\n", .{info.state.toString()});
    try stdout.print("  \"Created\": {d},\n", .{info.created_at});
    if (info.name) |name| {
        try stdout.print("  \"Name\": \"{s}\",\n", .{name});
    } else {
        try stdout.writeAll("  \"Name\": null,\n");
    }
    if (info.started_at) |t| {
        try stdout.print("  \"StartedAt\": {d},\n", .{t});
    } else {
        try stdout.writeAll("  \"StartedAt\": null,\n");
    }
    if (info.finished_at) |t| {
        try stdout.print("  \"FinishedAt\": {d},\n", .{t});
    } else {
        try stdout.writeAll("  \"FinishedAt\": null,\n");
    }
    if (info.pid) |p| {
        try stdout.print("  \"Pid\": {d},\n", .{p});
    } else {
        try stdout.writeAll("  \"Pid\": null,\n");
    }
    if (info.exit_code) |e| {
        try stdout.print("  \"ExitCode\": {d}\n", .{e});
    } else {
        try stdout.writeAll("  \"ExitCode\": null\n");
    }
    try stdout.writeAll("}\n");
    try stdout.flush();

    return 0;
}

/// Helper function to prune only images (when container manager fails)
fn pruneImagesOnly(
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        return 0;
    };
    defer cache.deinit();

    const rootfs_removed = cache.removeAllContainers() catch 0;
    const images_removed = cache.removeAllImages() catch 0;

    try stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed});
    try stdout.print("Deleted {d} image blobs\n", .{images_removed});
    try stdout.writeAll("Prune complete.\n");
    try stdout.flush();
    return 0;
}

/// Prune all stopped containers and unused images
fn pruneWindows(
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    try stdout.writeAll("Pruning stopped containers and unused images...\n");
    try stdout.flush();

    var containers_removed: u64 = 0;
    var images_removed: u64 = 0;

    // Prune containers via ContainerManager
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return pruneImagesOnly(allocator, stdout, stderr);
    };
    defer manager.deinit();
    containers_removed = manager.pruneContainers() catch 0;

    // Prune images via ImageCache
    var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
        try stderr.print("Warning: Failed to initialize image cache: {}\n", .{err});
        try stderr.flush();
        try stdout.print("Deleted {d} containers\n", .{containers_removed});
        try stdout.flush();
        return 0;
    };
    defer cache.deinit();

    // Remove all container rootfs from cache
    const rootfs_removed = cache.removeAllContainers() catch 0;

    // Remove all images
    images_removed = cache.removeAllImages() catch 0;

    try stdout.print("Deleted {d} containers\n", .{containers_removed});
    try stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed});
    try stdout.print("Deleted {d} image blobs\n", .{images_removed});
    try stdout.writeAll("Prune complete.\n");
    try stdout.flush();

    return 0;
}

/// Execute a command in a running container on Windows via WSL nsenter
fn execContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = stdout;

    // Parse exec options
    if (args.len < 4) {
        try stderr.writeAll("Error: Missing container ID or command\n");
        try stderr.writeAll("Usage: isolazi exec [options] <container> <command> [args...]\n");
        try stderr.writeAll("\nOptions:\n");
        try stderr.writeAll("  -i, --interactive    Keep STDIN open\n");
        try stderr.writeAll("  -t, --tty            Allocate a pseudo-TTY\n");
        try stderr.writeAll("  -d, --detach         Run in background\n");
        try stderr.writeAll("  -e, --env KEY=VALUE  Set environment variable\n");
        try stderr.writeAll("  -u, --user <user>    Run as specified user\n");
        try stderr.writeAll("  -w, --workdir <path> Working directory\n");
        try stderr.flush();
        return 1;
    }

    // Check if WSL is available
    if (!windows.isWslAvailable(allocator)) {
        try stderr.writeAll("Error: WSL2 is required to execute in containers on Windows.\n");
        try stderr.writeAll("\nTo install WSL2:\n");
        try stderr.writeAll("  1. Open PowerShell as Administrator\n");
        try stderr.writeAll("  2. Run: wsl --install\n");
        try stderr.writeAll("  3. Restart your computer\n");
        try stderr.flush();
        return 1;
    }

    // Parse arguments
    var container_id: ?[]const u8 = null;
    var command_start: usize = 0;
    var interactive = false;
    var tty = false;
    var detach = false;
    var user: ?[]const u8 = null;
    var workdir: ?[]const u8 = null;
    var env_vars: std.ArrayList([]const u8) = .empty;
    defer env_vars.deinit(allocator);

    var arg_idx: usize = 2; // Skip "isolazi" and "exec"
    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];

        if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
            interactive = true;
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tty")) {
            tty = true;
        } else if (std.mem.eql(u8, arg, "-it")) {
            interactive = true;
            tty = true;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
            detach = true;
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
            arg_idx += 1;
            if (arg_idx >= args.len) {
                try stderr.writeAll("Error: --user requires a value\n");
                try stderr.flush();
                return 1;
            }
            user = args[arg_idx];
        } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--workdir")) {
            arg_idx += 1;
            if (arg_idx >= args.len) {
                try stderr.writeAll("Error: --workdir requires a value\n");
                try stderr.flush();
                return 1;
            }
            workdir = args[arg_idx];
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
            arg_idx += 1;
            if (arg_idx >= args.len) {
                try stderr.writeAll("Error: --env requires a value\n");
                try stderr.flush();
                return 1;
            }
            try env_vars.append(allocator, args[arg_idx]);
        } else if (arg.len > 0 and arg[0] != '-') {
            if (container_id == null) {
                container_id = arg;
            } else {
                command_start = arg_idx;
                break;
            }
        }
    }

    if (container_id == null) {
        try stderr.writeAll("Error: Missing container ID\n");
        try stderr.flush();
        return 1;
    }

    if (command_start == 0) {
        try stderr.writeAll("Error: Missing command to execute\n");
        try stderr.flush();
        return 1;
    }

    // Find container and get PID
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const full_id = manager.findContainer(container_id.?) catch {
        try stderr.print("Error: No such container: {s}\n", .{container_id.?});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(full_id);

    var info = manager.getContainer(full_id) catch {
        try stderr.print("Error: Failed to get container info\n", .{});
        try stderr.flush();
        return 1;
    };
    defer info.deinit();

    if (info.state != .running) {
        try stderr.print("Error: Container {s} is not running\n", .{info.shortId()});
        try stderr.writeAll("Note: On Windows, only containers started with -d (detach) can use exec.\n");
        try stderr.writeAll("      For interactive containers, run the command directly.\n");
        try stderr.flush();
        return 1;
    }

    // On Windows via WSL, we use chroot to enter the container's rootfs
    // since the container process may not have a persistent PID in WSL

    // Get container rootfs path
    const home = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
        try stderr.writeAll("Error: Could not determine user profile directory\n");
        try stderr.flush();
        return 1;
    };
    defer allocator.free(home);

    // Convert Windows path to WSL path
    const wsl_home = windows.windowsToWslPath(allocator, home) catch {
        try stderr.writeAll("Error: Could not convert path to WSL format\n");
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_home);

    var rootfs_buf: [1024]u8 = undefined;
    const rootfs_path = std.fmt.bufPrint(&rootfs_buf, "{s}/.isolazi/containers/{s}/rootfs", .{ wsl_home, full_id }) catch {
        try stderr.writeAll("Error: Path too long\n");
        try stderr.flush();
        return 1;
    };

    // Build WSL command using chroot (not nsenter, since container may not have persistent PID)
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");

    // Use unshare and chroot to enter container environment
    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");
    try wsl_cmd.append(allocator, "--mount-proc");
    try wsl_cmd.append(allocator, "chroot");
    try wsl_cmd.append(allocator, rootfs_path);

    // Set working directory if specified
    if (workdir) |w| {
        try wsl_cmd.append(allocator, "sh");
        try wsl_cmd.append(allocator, "-c");

        // Build command with cd and env
        var cmd_buf: [2048]u8 = undefined;
        var cmd_len: usize = 0;

        // Add cd
        const cd_prefix = "cd ";
        @memcpy(cmd_buf[cmd_len..][0..cd_prefix.len], cd_prefix);
        cmd_len += cd_prefix.len;
        @memcpy(cmd_buf[cmd_len..][0..w.len], w);
        cmd_len += w.len;
        cmd_buf[cmd_len] = ' ';
        cmd_len += 1;
        cmd_buf[cmd_len] = '&';
        cmd_len += 1;
        cmd_buf[cmd_len] = '&';
        cmd_len += 1;
        cmd_buf[cmd_len] = ' ';
        cmd_len += 1;

        // Add env vars
        for (env_vars.items) |env| {
            @memcpy(cmd_buf[cmd_len..][0..env.len], env);
            cmd_len += env.len;
            cmd_buf[cmd_len] = ' ';
            cmd_len += 1;
        }

        // Add command
        for (args[command_start..]) |arg| {
            @memcpy(cmd_buf[cmd_len..][0..arg.len], arg);
            cmd_len += arg.len;
            cmd_buf[cmd_len] = ' ';
            cmd_len += 1;
        }

        const cmd_str = try allocator.dupe(u8, cmd_buf[0..cmd_len]);
        defer allocator.free(cmd_str);
        try wsl_cmd.append(allocator, cmd_str);
    } else {
        // Add user switch if specified
        if (user) |u| {
            try wsl_cmd.append(allocator, "su");
            try wsl_cmd.append(allocator, "-");
            try wsl_cmd.append(allocator, u);
            try wsl_cmd.append(allocator, "-c");

            // Build quoted command string
            var cmd_buf: [2048]u8 = undefined;
            var cmd_len: usize = 0;

            // Add env vars
            for (env_vars.items) |env| {
                @memcpy(cmd_buf[cmd_len..][0..env.len], env);
                cmd_len += env.len;
                cmd_buf[cmd_len] = ' ';
                cmd_len += 1;
            }

            // Add command
            for (args[command_start..]) |arg| {
                @memcpy(cmd_buf[cmd_len..][0..arg.len], arg);
                cmd_len += arg.len;
                cmd_buf[cmd_len] = ' ';
                cmd_len += 1;
            }

            const cmd_str = try allocator.dupe(u8, cmd_buf[0..cmd_len]);
            defer allocator.free(cmd_str);
            try wsl_cmd.append(allocator, cmd_str);
        } else {
            // Add environment variables via env command
            if (env_vars.items.len > 0) {
                try wsl_cmd.append(allocator, "env");
                for (env_vars.items) |env| {
                    try wsl_cmd.append(allocator, env);
                }
            }

            // Add the command and arguments
            for (args[command_start..]) |arg| {
                try wsl_cmd.append(allocator, arg);
            }
        }
    }

    // Execute via WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (detach) {
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
    } else {
        // Interactive/tty modes use inherited stdio for terminal passthrough
        child.stdin_behavior = if (interactive or tty) .Inherit else .Pipe;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
    }

    try child.spawn();

    if (detach) {
        return 0;
    }

    const term = try child.wait();
    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
}

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
            // Handle pull and images commands locally (native, no VM needed)
            if (std.mem.eql(u8, cmd, "pull")) {
                return pullImageMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "images")) {
                return listImagesMacOS(allocator, stdout, stderr);
            }
            // Handle run command - requires VM
            if (std.mem.eql(u8, cmd, "run")) {
                return runContainerMacOS(allocator, args, stdout, stderr);
            }
            // Container management commands
            if (std.mem.eql(u8, cmd, "ps")) {
                return listContainersMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "create")) {
                return createContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "start")) {
                return startContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "stop")) {
                return stopContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "rm")) {
                return removeContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "inspect")) {
                return inspectContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "prune")) {
                return pruneMacOS(allocator, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "exec")) {
                return execContainerMacOS(allocator, args, stdout, stderr);
            }
            if (std.mem.eql(u8, cmd, "vm")) {
                return vmCommandMacOS(allocator, args, stdout, stderr);
            }
        }

        // No command or unknown command - show help
        try isolazi.cli.printHelp(stdout);
        try stdout.flush();
        return 0;
    }

    /// Pull image on macOS (native, no VM needed)
    fn pullImageMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing image name\n");
            try stderr.writeAll("Usage: isolazi pull <image>\n");
            try stderr.flush();
            return 1;
        }

        const image_name = args[2];
        try stdout.print("Pulling {s}...\n", .{image_name});
        try stdout.flush();

        // Initialize image cache
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer cache.deinit();

        // Pull the image with progress reporting
        const progress_cb = struct {
            fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
                const stage_str = switch (stage) {
                    .cached => "Cached",
                    .authenticating => "Authenticating",
                    .fetching_manifest => "Fetching manifest",
                    .downloading_layer => "Downloading",
                    .layer_cached => "Layer cached",
                    .extracting => "Extracting",
                    .complete => "Complete",
                };
                std.debug.print("  {s}: {s}\n", .{ stage_str, detail });
            }
        }.cb;

        const ref = isolazi.image.pullImage(allocator, image_name, &cache, &progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        _ = ref;

        try stdout.print("Successfully pulled {s}\n", .{image_name});
        try stdout.flush();
        return 0;
    }

    /// List images on macOS (native, no VM needed)
    fn listImagesMacOS(
        allocator: std.mem.Allocator,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer cache.deinit();

        const images = cache.listImages(allocator) catch |err| {
            try stderr.print("Error: Failed to list images: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer {
            for (images) |*img| {
                var mutable = img.*;
                mutable.deinit(allocator);
            }
            allocator.free(images);
        }

        try stdout.writeAll("REPOSITORY                          TAG       \n");
        try stdout.writeAll("--------------------------------------------\n");

        if (images.len == 0) {
            try stdout.writeAll("(no images)\n");
        } else {
            for (images) |img| {
                try stdout.print("{s}/{s}                  {s}\n", .{
                    img.registry,
                    img.repository,
                    img.tag,
                });
            }
        }

        // Print stats
        const stats = cache.getStats() catch |err| {
            try stderr.print("Warning: Could not get cache stats: {}\n", .{err});
            try stderr.flush();
            return 0;
        };

        try stdout.print("\nTotal: {d} images, {d} blobs, {d:.2} MB\n", .{
            images.len,
            stats.total_blobs,
            @as(f64, @floatFromInt(stats.total_size)) / 1024.0 / 1024.0,
        });

        try stdout.flush();
        return 0;
    }

    /// Run container on macOS using Apple Virtualization
    fn runContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        // Check if virtualization is available
        if (!isolazi.macos.isVirtualizationAvailable(allocator)) {
            try stderr.writeAll("Error: Apple Virtualization is not available.\n");
            try stderr.writeAll("\nRequirements:\n");
            try stderr.writeAll("  - macOS 12.0 (Monterey) or later\n");
            try stderr.writeAll("  - Virtualization-capable hardware\n");
            try stderr.flush();
            return 1;
        }

        // Check for hypervisor backend
        const hypervisor = isolazi.macos.virtualization.findHypervisor(allocator);
        if (hypervisor == null) {
            try stderr.writeAll("Error: No hypervisor backend found.\n");
            try stderr.writeAll("\nInstall one of the following:\n");
            try stderr.writeAll("  - vfkit (recommended): brew install vfkit\n");
            try stderr.writeAll("  - Lima: brew install lima\n");
            try stderr.flush();
            return 1;
        }

        // Parse run options (env vars, volumes, etc.)
        const opts = parseRunOptions(allocator, args) catch |err| {
            try stderr.print("Error: Failed to parse run options: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        if (opts.image_name.len == 0) {
            try stderr.writeAll("Error: Missing image name\n");
            try stderr.writeAll("Usage: isolazi run [options] <image> [command...]\n");
            try stderr.writeAll("\nOptions:\n");
            try stderr.writeAll("  -d, --detach       Run container in background\n");
            try stderr.writeAll("  -e KEY=VALUE       Set environment variable (can be used multiple times)\n");
            try stderr.writeAll("  -v HOST:CONTAINER  Bind mount volume (can be used multiple times)\n");
            try stderr.flush();
            return 1;
        }

        // Initialize image cache
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer cache.deinit();

        // Parse the image reference
        const ref = isolazi.image.reference.parse(opts.image_name) catch {
            try stderr.print("Error: Invalid image reference: {s}\n", .{opts.image_name});
            try stderr.flush();
            return 1;
        };

        // Check if image is cached, pull if not
        const has_image = cache.hasImage(&ref) catch false;
        if (!has_image) {
            try stdout.print("Unable to find image '{s}' locally\n", .{opts.image_name});
            try stdout.flush();

            // Pull the image
            const progress_cb = struct {
                fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
                    const stage_str = switch (stage) {
                        .cached => "Cached",
                        .authenticating => "Authenticating",
                        .fetching_manifest => "Fetching manifest",
                        .downloading_layer => "Pulling",
                        .layer_cached => "Layer exists",
                        .extracting => "Extracting",
                        .complete => "Status",
                    };
                    std.debug.print("{s}: {s}\n", .{ stage_str, detail });
                }
            }.cb;

            _ = isolazi.image.pullImage(allocator, opts.image_name, &cache, &progress_cb) catch |err| {
                try stderr.print("Error: Failed to pull image: {}\n", .{err});
                try stderr.flush();
                return 1;
            };

            try stdout.print("Downloaded newer image for {s}\n", .{opts.image_name});
            try stdout.flush();
        }

        // Read manifest to get layer digests
        const manifest_data = cache.readManifest(&ref) catch |err| {
            try stderr.print("Error: Failed to read manifest: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(manifest_data);

        // Parse manifest for layers
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
            try stderr.writeAll("Error: Invalid manifest format\n");
            try stderr.flush();
            return 1;
        };
        defer parsed.deinit();

        const root = parsed.value;
        const layers_json = root.object.get("layers") orelse {
            try stderr.writeAll("Error: No layers in manifest\n");
            try stderr.flush();
            return 1;
        };

        // Collect layer digests
        var layer_digests: std.ArrayList([]const u8) = .empty;
        defer layer_digests.deinit(allocator);

        for (layers_json.array.items) |layer_obj| {
            const digest = layer_obj.object.get("digest") orelse continue;
            try layer_digests.append(allocator, digest.string);
        }

        // Generate container ID
        var container_id_buf: [16]u8 = undefined;
        std.crypto.random.bytes(&container_id_buf);
        var container_id: [32]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (container_id_buf, 0..) |byte, i| {
            container_id[i * 2] = hex_chars[byte >> 4];
            container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        // Prepare container rootfs
        if (!opts.detach_mode) {
            try stdout.print("Preparing container {s}...\n", .{container_id[0..12]});
            try stdout.flush();
        }

        const rootfs_path = cache.prepareContainer(&container_id, layer_digests.items) catch |err| {
            try stderr.print("Error: Failed to prepare container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(rootfs_path);

        // Register container with ContainerManager for state tracking
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        // Build command string for state tracking
        var cmd_display: [256]u8 = undefined;
        var cmd_display_len: usize = 0;

        // Get command to run (default: /bin/sh, or entrypoint for known images)
        var cmd_args: std.ArrayList([]const u8) = .empty;
        defer cmd_args.deinit(allocator);

        const is_postgres = std.mem.indexOf(u8, opts.image_name, "postgres") != null;

        if (opts.command_args.len > 0) {
            for (opts.command_args) |arg| {
                try cmd_args.append(allocator, arg);
                // Build display string
                if (cmd_display_len > 0 and cmd_display_len < 255) {
                    cmd_display[cmd_display_len] = ' ';
                    cmd_display_len += 1;
                }
                const copy_len = @min(arg.len, 255 - cmd_display_len);
                @memcpy(cmd_display[cmd_display_len..][0..copy_len], arg[0..copy_len]);
                cmd_display_len += copy_len;
            }
        } else if (is_postgres) {
            try cmd_args.append(allocator, "docker-entrypoint.sh");
            try cmd_args.append(allocator, "postgres");
            const entry = "docker-entrypoint.sh postgres";
            @memcpy(cmd_display[0..entry.len], entry);
            cmd_display_len = entry.len;
        } else {
            try cmd_args.append(allocator, "/bin/sh");
            const sh = "/bin/sh";
            @memcpy(cmd_display[0..sh.len], sh);
            cmd_display_len = sh.len;
        }

        // Register container state
        _ = manager.createContainerWithId(&container_id, opts.image_name, cmd_display[0..cmd_display_len], null) catch {};

        if (opts.detach_mode) {
            try stdout.print("{s}\n", .{container_id});
            try stdout.flush();
        } else {
            try stdout.print("Starting container with {s}...\n", .{hypervisor.?});
            try stdout.flush();
        }

        // Convert env_vars to virtualization format
        var env_pairs: std.ArrayList(isolazi.macos.virtualization.EnvPair) = .empty;
        defer env_pairs.deinit(allocator);

        // For postgres, auto-set PGDATA if not provided
        var has_pgdata = false;
        for (opts.env_vars) |e| {
            if (std.mem.eql(u8, e.key, "PGDATA")) has_pgdata = true;
            try env_pairs.append(allocator, .{ .key = e.key, .value = e.value });
        }
        if (is_postgres and !has_pgdata) {
            // Find volume mount for /var/lib/postgresql
            for (opts.volumes) |vol| {
                if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                    const pgdata = try std.fmt.allocPrint(allocator, "{s}/data", .{vol.container_path});
                    defer allocator.free(pgdata);
                    try env_pairs.append(allocator, .{ .key = "PGDATA", .value = pgdata });
                    has_pgdata = true;
                    break;
                }
            }
            if (!has_pgdata) {
                try env_pairs.append(allocator, .{ .key = "PGDATA", .value = "/var/lib/postgresql/data" });
            }
        }

        // Convert volumes to virtualization format
        var vol_pairs: std.ArrayList(isolazi.macos.virtualization.VolumePair) = .empty;
        defer vol_pairs.deinit(allocator);
        for (opts.volumes) |v| {
            try vol_pairs.append(allocator, .{ .host_path = v.host_path, .container_path = v.container_path });
        }

        // Convert port mappings to virtualization format
        var port_pairs: std.ArrayList(isolazi.macos.virtualization.PortMapping) = .empty;
        defer port_pairs.deinit(allocator);
        for (opts.ports) |p| {
            try port_pairs.append(allocator, .{
                .host_port = p.host_port,
                .container_port = p.container_port,
                .protocol = if (p.protocol == .udp) .udp else .tcp,
            });
        }

        // Print port mappings
        for (opts.ports) |port| {
            if (port.host_port == port.container_port) {
                try stdout.print("Port {d} published\n", .{port.host_port});
            } else {
                try stdout.print("Port {d} -> {d} published\n", .{ port.host_port, port.container_port });
            }
        }
        if (opts.ports.len > 0) {
            try stdout.flush();
        }

        // Ensure VM assets are available (only needed for vfkit)
        const VMAssets = struct {
            kernel_path: []const u8,
            initramfs_path: ?[]const u8,
        };
        var vm_assets: ?VMAssets = null;

        if (std.mem.eql(u8, hypervisor.?, "vfkit")) {
            const assets = isolazi.macos.virtualization.ensureVMAssets(allocator) catch {
                try stderr.writeAll("Error: Linux VM kernel not found.\n");
                try stderr.writeAll("\nTo setup the VM environment:\n");
                try stderr.writeAll("  1. Download Linux kernel and initramfs for ARM64:\n");
                try stderr.writeAll("     - https://github.com/gokrazy/kernel.arm64/releases\n");
                try stderr.writeAll("  2. Place files at:\n");
                try stderr.writeAll("     ~/Library/Application Support/isolazi/vm/vmlinuz\n");
                try stderr.writeAll("     ~/Library/Application Support/isolazi/vm/initramfs\n");
                try stderr.writeAll("\nAlternatively, use Lima as the backend (brew install lima).\n");
                try stderr.flush();
                return 1;
            };
            vm_assets = VMAssets{
                .kernel_path = assets.kernel_path,
                .initramfs_path = assets.initramfs_path,
            };
        }
        defer {
            if (vm_assets) |assets| {
                allocator.free(assets.kernel_path);
                if (assets.initramfs_path) |p| allocator.free(p);
            }
        }

        // Run in VM using appropriate hypervisor
        // Update state to running
        manager.updateState(&container_id, .running, null, null) catch {};

        var exit_code: u8 = 0;
        if (std.mem.eql(u8, hypervisor.?, "vfkit")) {
            exit_code = isolazi.macos.virtualization.runWithVfkit(
                allocator,
                vm_assets.?.kernel_path,
                vm_assets.?.initramfs_path,
                rootfs_path,
                cmd_args.items,
                env_pairs.items,
                vol_pairs.items,
                port_pairs.items,
                opts.rootless,
            ) catch |err| {
                manager.updateState(&container_id, .stopped, null, 1) catch {};
                try stderr.print("Error: Failed to run in VM: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
        } else {
            // Use Lima
            exit_code = isolazi.macos.virtualization.runWithLima(
                allocator,
                "", // Lima manages its own kernel
                rootfs_path,
                cmd_args.items,
                env_pairs.items,
                vol_pairs.items,
                port_pairs.items,
                opts.rootless,
            ) catch |err| {
                manager.updateState(&container_id, .stopped, null, 1) catch {};
                try stderr.print("Error: Failed to run with Lima: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
        }

        // Update state to stopped after container exits
        manager.updateState(&container_id, .stopped, null, exit_code) catch {};
        return exit_code;
    }

    /// List containers on macOS
    fn listContainersMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        var show_all = false;
        for (args[2..]) |arg| {
            if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
                show_all = true;
            }
        }

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const containers = manager.listContainers(show_all) catch |err| {
            try stderr.print("Error: Failed to list containers: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer {
            for (containers) |*c| {
                @constCast(c).deinit();
            }
            allocator.free(containers);
        }

        try stdout.writeAll("CONTAINER ID   IMAGE                    COMMAND         STATUS\n");

        if (containers.len == 0) {
            if (!show_all) {
                try stdout.writeAll("(no running containers, use -a to show all)\n");
            } else {
                try stdout.writeAll("(no containers)\n");
            }
        } else {
            for (containers) |c| {
                const image_display = if (c.image.len > 24) c.image[0..24] else c.image;
                const cmd_display = if (c.command.len > 15) c.command[0..15] else c.command;

                try stdout.print("{s}   {s: <24} {s: <15} {s}\n", .{
                    c.shortId(),
                    image_display,
                    cmd_display,
                    c.state.toString(),
                });
            }
        }

        try stdout.flush();
        return 0;
    }

    /// Create container on macOS
    fn createContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing image name\n");
            try stderr.writeAll("Usage: isolazi create [--name <name>] <image> [command...]\n");
            try stderr.flush();
            return 1;
        }

        var container_name: ?[]const u8 = null;
        var image_idx: usize = 2;

        var arg_idx: usize = 2;
        while (arg_idx < args.len) : (arg_idx += 1) {
            const arg = args[arg_idx];
            if (std.mem.eql(u8, arg, "--name") and arg_idx + 1 < args.len) {
                container_name = args[arg_idx + 1];
                arg_idx += 1;
            } else if (arg.len > 0 and arg[0] != '-') {
                image_idx = arg_idx;
                break;
            }
        }

        if (image_idx >= args.len) {
            try stderr.writeAll("Error: Missing image name\n");
            try stderr.flush();
            return 1;
        }

        const image_name = args[image_idx];

        // Get command
        var command: []const u8 = "/bin/sh";
        if (args.len > image_idx + 1) {
            command = args[image_idx + 1];
        }

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const container_id = manager.createContainer(image_name, command, container_name) catch |err| {
            try stderr.print("Error: Failed to create container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("{s}\n", .{container_id});
        try stdout.flush();
        return 0;
    }

    /// Start container on macOS
    fn startContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.writeAll("Usage: isolazi start <container>\n");
            try stderr.flush();
            return 1;
        }

        const query = args[2];

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const container_id = manager.findContainer(query) catch {
            try stderr.print("Error: No such container: {s}\n", .{query});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(container_id);

        // Get container info
        var info = manager.getContainer(container_id) catch {
            try stderr.print("Error: Failed to get container info\n", .{});
            try stderr.flush();
            return 1;
        };
        defer info.deinit();

        // Check if virtualization is available
        if (!isolazi.macos.isVirtualizationAvailable(allocator)) {
            try stderr.writeAll("Error: Apple Virtualization is not available.\n");
            try stderr.flush();
            return 1;
        }

        // Update state to running
        manager.updateState(container_id, .running, null, null) catch {};

        try stdout.print("{s}\n", .{info.shortId()});
        try stdout.flush();

        // TODO: Actually start the container in VM
        // For now, just update state
        return 0;
    }

    /// Stop container on macOS
    fn stopContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.writeAll("Usage: isolazi stop <container>\n");
            try stderr.flush();
            return 1;
        }

        const query = args[2];

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const container_id = manager.findContainer(query) catch {
            try stderr.print("Error: No such container: {s}\n", .{query});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(container_id);

        manager.stopContainer(container_id) catch |err| {
            if (err == error.ContainerNotRunning) {
                try stderr.print("Error: Container {s} is not running\n", .{query});
                try stderr.flush();
                return 1;
            }
            try stderr.print("Error: Failed to stop container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("{s}\n", .{container_id[0..12]});
        try stdout.flush();
        return 0;
    }

    /// Remove container on macOS
    fn removeContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.writeAll("Usage: isolazi rm [-f|--force] <container>\n");
            try stderr.flush();
            return 1;
        }

        var force = false;
        var container_query: ?[]const u8 = null;

        for (args[2..]) |arg| {
            if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
                force = true;
            } else if (arg.len > 0 and arg[0] != '-') {
                container_query = arg;
            }
        }

        if (container_query == null) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.flush();
            return 1;
        }

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const container_id = manager.findContainer(container_query.?) catch {
            try stderr.print("Error: No such container: {s}\n", .{container_query.?});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(container_id);

        manager.removeContainer(container_id, force) catch |err| {
            if (err == error.ContainerRunning) {
                try stderr.print("Error: Container {s} is running. Use -f to force remove.\n", .{container_id[0..12]});
                try stderr.flush();
                return 1;
            }
            try stderr.print("Error: Failed to remove container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("{s}\n", .{container_id[0..12]});
        try stdout.flush();
        return 0;
    }

    /// Inspect container on macOS
    fn inspectContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.writeAll("Usage: isolazi inspect <container>\n");
            try stderr.flush();
            return 1;
        }

        const query = args[2];

        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const container_id = manager.findContainer(query) catch {
            try stderr.print("Error: No such container: {s}\n", .{query});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(container_id);

        var info = manager.getContainer(container_id) catch {
            try stderr.print("Error: Failed to get container info\n", .{});
            try stderr.flush();
            return 1;
        };
        defer info.deinit();

        // Output JSON-like format
        try stdout.writeAll("{\n");
        try stdout.print("  \"Id\": \"{s}\",\n", .{info.id});
        try stdout.print("  \"Image\": \"{s}\",\n", .{info.image});
        try stdout.print("  \"Command\": \"{s}\",\n", .{info.command});
        try stdout.print("  \"State\": \"{s}\",\n", .{info.state.toString()});
        try stdout.print("  \"Created\": {d},\n", .{info.created_at});
        try stdout.writeAll("  \"Platform\": \"macOS (Apple Virtualization)\",\n");
        if (info.name) |name| {
            try stdout.print("  \"Name\": \"{s}\",\n", .{name});
        } else {
            try stdout.writeAll("  \"Name\": null,\n");
        }
        if (info.started_at) |t| {
            try stdout.print("  \"StartedAt\": {d},\n", .{t});
        } else {
            try stdout.writeAll("  \"StartedAt\": null,\n");
        }
        if (info.finished_at) |t| {
            try stdout.print("  \"FinishedAt\": {d},\n", .{t});
        } else {
            try stdout.writeAll("  \"FinishedAt\": null,\n");
        }
        if (info.pid) |p| {
            try stdout.print("  \"Pid\": {d},\n", .{p});
        } else {
            try stdout.writeAll("  \"Pid\": null,\n");
        }
        if (info.exit_code) |e| {
            try stdout.print("  \"ExitCode\": {d}\n", .{e});
        } else {
            try stdout.writeAll("  \"ExitCode\": null\n");
        }
        try stdout.writeAll("}\n");
        try stdout.flush();

        return 0;
    }

    /// Helper function to prune only images on macOS (when container manager fails)
    fn pruneMacOSImagesOnly(
        allocator: std.mem.Allocator,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Warning: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 0;
        };
        defer cache.deinit();

        const rootfs_removed = cache.removeAllContainers() catch 0;
        const images_removed = cache.removeAllImages() catch 0;

        try stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed});
        try stdout.print("Deleted {d} image blobs\n", .{images_removed});
        try stdout.writeAll("Prune complete.\n");
        try stdout.flush();
        return 0;
    }

    /// Prune all stopped containers and unused images
    fn pruneMacOS(
        allocator: std.mem.Allocator,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        try stdout.writeAll("Pruning stopped containers and unused images...\n");
        try stdout.flush();

        var containers_removed: u64 = 0;
        var images_removed: u64 = 0;

        // Prune containers via ContainerManager
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return pruneMacOSImagesOnly(allocator, stdout, stderr);
        };
        defer manager.deinit();
        containers_removed = manager.pruneContainers() catch 0;

        // Prune images via ImageCache
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Warning: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            try stdout.print("Deleted {d} containers\n", .{containers_removed});
            try stdout.flush();
            return 0;
        };
        defer cache.deinit();

        // Remove all container rootfs from cache
        const rootfs_removed = cache.removeAllContainers() catch 0;

        // Remove all images
        images_removed = cache.removeAllImages() catch 0;

        try stdout.print("Deleted {d} containers\n", .{containers_removed});
        try stdout.print("Deleted {d} container rootfs\n", .{rootfs_removed});
        try stdout.print("Deleted {d} image blobs\n", .{images_removed});
        try stdout.writeAll("Prune complete.\n");
        try stdout.flush();

        return 0;
    }

    /// Execute a command in a running container on macOS via Lima/vfkit
    fn execContainerMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        _ = stdout;

        // Parse exec options
        if (args.len < 4) {
            try stderr.writeAll("Error: Missing container ID or command\n");
            try stderr.writeAll("Usage: isolazi exec [options] <container> <command> [args...]\n");
            try stderr.writeAll("\nOptions:\n");
            try stderr.writeAll("  -i, --interactive    Keep STDIN open\n");
            try stderr.writeAll("  -t, --tty            Allocate a pseudo-TTY\n");
            try stderr.writeAll("  -d, --detach         Run in background\n");
            try stderr.writeAll("  -e, --env KEY=VALUE  Set environment variable\n");
            try stderr.writeAll("  -u, --user <user>    Run as specified user\n");
            try stderr.writeAll("  -w, --workdir <path> Working directory\n");
            try stderr.flush();
            return 1;
        }

        // Check for hypervisor backend
        const hypervisor = isolazi.macos.virtualization.findHypervisor(allocator);
        if (hypervisor == null) {
            try stderr.writeAll("Error: No hypervisor backend found.\n");
            try stderr.writeAll("\nInstall one of the following:\n");
            try stderr.writeAll("  - Lima (recommended): brew install lima\n");
            try stderr.writeAll("  - vfkit: brew install vfkit\n");
            try stderr.flush();
            return 1;
        }

        // Parse arguments
        var container_id: ?[]const u8 = null;
        var command_start: usize = 0;
        var interactive = false;
        var tty = false;
        var detach = false;
        var user: ?[]const u8 = null;
        var workdir: ?[]const u8 = null;
        var env_vars: std.ArrayList([]const u8) = .empty;
        defer env_vars.deinit(allocator);

        var arg_idx: usize = 2; // Skip "isolazi" and "exec"
        while (arg_idx < args.len) : (arg_idx += 1) {
            const arg = args[arg_idx];

            if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
                interactive = true;
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tty")) {
                tty = true;
            } else if (std.mem.eql(u8, arg, "-it")) {
                interactive = true;
                tty = true;
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
                detach = true;
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
                arg_idx += 1;
                if (arg_idx >= args.len) {
                    try stderr.writeAll("Error: --user requires a value\n");
                    try stderr.flush();
                    return 1;
                }
                user = args[arg_idx];
            } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--workdir")) {
                arg_idx += 1;
                if (arg_idx >= args.len) {
                    try stderr.writeAll("Error: --workdir requires a value\n");
                    try stderr.flush();
                    return 1;
                }
                workdir = args[arg_idx];
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
                arg_idx += 1;
                if (arg_idx >= args.len) {
                    try stderr.writeAll("Error: --env requires a value\n");
                    try stderr.flush();
                    return 1;
                }
                try env_vars.append(allocator, args[arg_idx]);
            } else if (arg.len > 0 and arg[0] != '-') {
                if (container_id == null) {
                    container_id = arg;
                } else {
                    command_start = arg_idx;
                    break;
                }
            }
        }

        if (container_id == null) {
            try stderr.writeAll("Error: Missing container ID\n");
            try stderr.flush();
            return 1;
        }

        if (command_start == 0) {
            try stderr.writeAll("Error: Missing command to execute\n");
            try stderr.flush();
            return 1;
        }

        // Find container and get PID
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const full_id = manager.findContainer(container_id.?) catch {
            try stderr.print("Error: No such container: {s}\n", .{container_id.?});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(full_id);

        var info = manager.getContainer(full_id) catch {
            try stderr.print("Error: Failed to get container info\n", .{});
            try stderr.flush();
            return 1;
        };
        defer info.deinit();

        if (info.state != .running) {
            try stderr.print("Error: Container {s} is not running\n", .{info.shortId()});
            try stderr.flush();
            return 1;
        }

        const target_pid = info.pid orelse {
            try stderr.writeAll("Error: Container has no PID recorded\n");
            try stderr.flush();
            return 1;
        };

        // Build Lima/limactl command to exec via nsenter in VM
        var lima_cmd: std.ArrayList([]const u8) = .empty;
        defer lima_cmd.deinit(allocator);

        if (std.mem.eql(u8, hypervisor.?, "limactl") or std.mem.eql(u8, hypervisor.?, "lima")) {
            // Lima approach: limactl shell default nsenter ...
            try lima_cmd.append(allocator, "limactl");
            try lima_cmd.append(allocator, "shell");
            try lima_cmd.append(allocator, "default");
            try lima_cmd.append(allocator, "--");
            try lima_cmd.append(allocator, "sudo");
        } else {
            // vfkit or other - use SSH approach
            // For simplicity, assume lima is available
            try stderr.writeAll("Error: exec currently requires Lima on macOS\n");
            try stderr.writeAll("\nInstall Lima: brew install lima\n");
            try stderr.writeAll("Start Lima: limactl start\n");
            try stderr.flush();
            return 1;
        }

        // Use nsenter to enter container namespaces
        try lima_cmd.append(allocator, "nsenter");
        try lima_cmd.append(allocator, "--target");

        // Format PID as string
        var pid_buf: [16]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{target_pid}) catch "0";
        try lima_cmd.append(allocator, pid_str);

        // Enter all namespaces
        try lima_cmd.append(allocator, "--mount");
        try lima_cmd.append(allocator, "--uts");
        try lima_cmd.append(allocator, "--ipc");
        try lima_cmd.append(allocator, "--net");
        try lima_cmd.append(allocator, "--pid");
        try lima_cmd.append(allocator, "--cgroup");

        // Set user if specified
        if (user) |u| {
            try lima_cmd.append(allocator, "--setuid");
            try lima_cmd.append(allocator, u);
        }

        // Set working directory if specified
        if (workdir) |w| {
            try lima_cmd.append(allocator, "--wd");
            try lima_cmd.append(allocator, w);
        }

        // Add environment variables via env command
        if (env_vars.items.len > 0) {
            try lima_cmd.append(allocator, "env");
            for (env_vars.items) |env| {
                try lima_cmd.append(allocator, env);
            }
        }

        // Add the command and arguments
        for (args[command_start..]) |arg| {
            try lima_cmd.append(allocator, arg);
        }

        // Execute via Lima
        var child = std.process.Child.init(lima_cmd.items, allocator);

        // Configure stdin/stdout/stderr behavior based on options
        if (detach) {
            child.stdin_behavior = .Ignore;
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
        } else {
            // Interactive mode requires stdin, tty enables terminal passthrough
            child.stdin_behavior = if (interactive or tty) .Inherit else .Pipe;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;
        }

        try child.spawn();

        if (detach) {
            return 0;
        }

        const term = try child.wait();
        return switch (term) {
            .Exited => |code| code,
            .Signal => |sig| @truncate(128 +% sig),
            else => 1,
        };
    }

    /// VM management commands (macOS specific)
    fn vmCommandMacOS(
        allocator: std.mem.Allocator,
        args: []const []const u8,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        if (args.len < 3) {
            try stdout.writeAll("VM Management Commands:\n\n");
            try stdout.writeAll("  isolazi vm status   - Show VM status\n");
            try stdout.writeAll("  isolazi vm start    - Start the Linux VM\n");
            try stdout.writeAll("  isolazi vm stop     - Stop the Linux VM\n");
            try stdout.writeAll("  isolazi vm ssh      - SSH into the VM\n");
            try stdout.writeAll("  isolazi vm info     - Show VM configuration\n");
            try stdout.flush();
            return 0;
        }

        const subcmd = args[2];

        if (std.mem.eql(u8, subcmd, "status")) {
            try stdout.writeAll("VM Status: ");
            if (isolazi.macos.isVirtualizationAvailable(allocator)) {
                try stdout.writeAll("Virtualization available\n");
                if (isolazi.macos.virtualization.findHypervisor(allocator)) |hyp| {
                    try stdout.print("Hypervisor: {s}\n", .{hyp});
                } else {
                    try stdout.writeAll("Hypervisor: Not found\n");
                }
            } else {
                try stdout.writeAll("Virtualization not available\n");
            }
            try stdout.flush();
            return 0;
        }

        if (std.mem.eql(u8, subcmd, "info")) {
            try stdout.writeAll("VM Configuration:\n");
            try stdout.writeAll("  CPUs: 2\n");
            try stdout.writeAll("  Memory: 2048 MB\n");

            const data_dir = isolazi.macos.virtualization.getDataDir(allocator) catch {
                try stdout.writeAll("  Data dir: (error)\n");
                try stdout.flush();
                return 0;
            };
            defer allocator.free(data_dir);

            try stdout.print("  Data dir: {s}\n", .{data_dir});

            // Check for kernel
            const vm_dir = isolazi.macos.virtualization.getVMAssetsDir(allocator) catch {
                try stdout.writeAll("  Kernel: (error)\n");
                try stdout.flush();
                return 0;
            };
            defer allocator.free(vm_dir);

            var kernel_path_buf: [512]u8 = undefined;
            const kernel_path = std.fmt.bufPrint(&kernel_path_buf, "{s}/vmlinuz", .{vm_dir}) catch {
                try stdout.writeAll("  Kernel: (error)\n");
                try stdout.flush();
                return 0;
            };

            const kernel_exists = blk: {
                std.fs.accessAbsolute(kernel_path, .{}) catch break :blk false;
                break :blk true;
            };

            if (kernel_exists) {
                try stdout.print("  Kernel: {s}\n", .{kernel_path});
            } else {
                try stdout.writeAll("  Kernel: Not found\n");
            }

            try stdout.flush();
            return 0;
        }

        if (std.mem.eql(u8, subcmd, "start")) {
            try stdout.writeAll("Starting VM...\n");
            // TODO: Implement persistent VM
            try stderr.writeAll("Note: Persistent VM not yet implemented. VMs start on-demand with 'run'.\n");
            try stderr.flush();
            return 0;
        }

        if (std.mem.eql(u8, subcmd, "stop")) {
            try stdout.writeAll("Stopping VM...\n");
            // TODO: Implement persistent VM
            try stderr.writeAll("Note: Persistent VM not yet implemented.\n");
            try stderr.flush();
            return 0;
        }

        try stderr.print("Unknown VM command: {s}\n", .{subcmd});
        try stderr.flush();
        return 1;
    }
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
        // Parse CLI arguments
        const command = isolazi.cli.parse(args) catch |err| {
            try isolazi.cli.printError(stderr, err);
            try stderr.flush();
            return 1;
        };

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
            .pull => |pull_cmd| {
                return pullImageLinuxImpl(allocator, pull_cmd, stdout, stderr);
            },
            .images => {
                return listImagesLinuxImpl(allocator, stdout, stderr);
            },
            .run => |run_cmd| {
                return runContainerLinuxImpl(allocator, run_cmd, stdout, stderr);
            },
            .exec => |exec_cmd| {
                return execContainerLinuxImpl(allocator, exec_cmd, stdout, stderr);
            },
        }
    }

    fn pullImageLinuxImpl(
        allocator: std.mem.Allocator,
        pull_cmd: isolazi.cli.PullCommand,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        try stdout.print("Pulling {s}...\n", .{pull_cmd.image});
        try stdout.flush();

        // Initialize image cache
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer cache.deinit();

        // Pull the image with progress reporting
        const progress_cb = struct {
            fn cb(stage: isolazi.image.PullStage, detail: []const u8) void {
                const stage_str = switch (stage) {
                    .cached => "Cached",
                    .authenticating => "Authenticating",
                    .fetching_manifest => "Fetching manifest",
                    .downloading_layer => "Downloading",
                    .layer_cached => "Layer cached",
                    .extracting => "Extracting",
                    .complete => "Complete",
                };
                std.debug.print("  {s}: {s}\n", .{ stage_str, detail });
            }
        }.cb;

        _ = isolazi.image.pullImage(allocator, pull_cmd.image, &cache, &progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        try stdout.print("Successfully pulled {s}\n", .{pull_cmd.image});
        try stdout.flush();
        return 0;
    }

    fn listImagesLinuxImpl(
        allocator: std.mem.Allocator,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer cache.deinit();

        const images = cache.listImages(allocator) catch |err| {
            try stderr.print("Error: Failed to list images: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer {
            for (images) |*img| {
                @constCast(img).deinit(allocator);
            }
            allocator.free(images);
        }

        try stdout.writeAll("REPOSITORY                          TAG       \n");
        try stdout.writeAll("--------------------------------------------\n");

        if (images.len == 0) {
            try stdout.writeAll("(no images)\n");
        } else {
            for (images) |img| {
                try stdout.print("{s}/{s}                  {s}\n", .{
                    img.registry,
                    img.repository,
                    img.tag,
                });
            }
        }

        // Print stats
        const stats = cache.getStats() catch |err| {
            try stderr.print("Warning: Could not get cache stats: {}\n", .{err});
            try stderr.flush();
            return 0;
        };

        try stdout.print("\nTotal: {d} images, {d} blobs, {d:.2} MB\n", .{
            images.len,
            stats.total_blobs,
            @as(f64, @floatFromInt(stats.total_size)) / 1024.0 / 1024.0,
        });

        try stdout.flush();
        return 0;
    }

    fn runContainerLinuxImpl(
        allocator: std.mem.Allocator,
        run_cmd: isolazi.cli.RunCommand,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        _ = stdout;

        // Check if running as root
        const uid = std.os.linux.getuid();
        if (uid != 0) {
            try stderr.writeAll("Error: Isolazi must be run as root.\n");
            try stderr.writeAll("Container namespaces require CAP_SYS_ADMIN privileges.\n");
            try stderr.writeAll("\nHint: Run with 'sudo isolazi run ...'\n");
            try stderr.flush();
            return 1;
        }

        // Determine rootfs path
        var rootfs_path: []const u8 = undefined;
        var container_id: ?[12]u8 = null;
        var cache_opt: ?isolazi.image.ImageCache = null;
        defer {
            if (cache_opt) |*c| {
                // Cleanup container if we created one
                if (container_id) |cid| {
                    c.removeContainer(&cid) catch {};
                }
                if (rootfs_path.ptr != run_cmd.rootfs.ptr) {
                    allocator.free(rootfs_path);
                }
                c.deinit();
            }
        }

        if (run_cmd.is_image) {
            // It's an OCI image reference - pull and extract
            var cache = isolazi.image.ImageCache.init(allocator) catch |err| {
                try stderr.print("Error: Failed to initialize image cache: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
            cache_opt = cache;

            // Pull image if needed
            const ref = isolazi.image.pullImage(allocator, run_cmd.rootfs, &cache, null) catch |err| {
                try stderr.print("Error: Failed to pull image '{s}': {}\n", .{ run_cmd.rootfs, err });
                try stderr.flush();
                return 1;
            };

            // Get manifest and layer digests
            const manifest_data = cache.readManifest(&ref) catch |err| {
                try stderr.print("Error: Failed to read manifest: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
            defer allocator.free(manifest_data);

            const parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
                try stderr.writeAll("Error: Invalid manifest format\n");
                try stderr.flush();
                return 1;
            };
            defer parsed.deinit();

            // Extract layer digests
            const layers = parsed.value.object.get("layers") orelse {
                try stderr.writeAll("Error: No layers in manifest\n");
                try stderr.flush();
                return 1;
            };

            var layer_digests: std.ArrayList([]const u8) = .empty;
            defer layer_digests.deinit(allocator);

            for (layers.array.items) |layer_obj| {
                if (layer_obj.object.get("digest")) |digest| {
                    try layer_digests.append(allocator, digest.string);
                }
            }

            // Generate container ID and extract layers
            container_id = isolazi.image.generateContainerId();
            rootfs_path = cache.prepareContainer(&container_id.?, layer_digests.items) catch |err| {
                try stderr.print("Error: Failed to prepare container: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
        } else {
            // It's a filesystem path
            rootfs_path = run_cmd.rootfs;

            if (!isolazi.fs.validateRootfs(rootfs_path)) {
                try stderr.print("Error: Invalid rootfs at '{s}'\n", .{rootfs_path});
                try stderr.writeAll("The rootfs must be a directory containing /bin or /usr/bin.\n");
                try stderr.flush();
                return 1;
            }
        }

        // Build configuration with resolved rootfs
        var modified_run_cmd = run_cmd;
        modified_run_cmd.rootfs = rootfs_path;

        // Check if this is a postgres image - auto-configure
        const is_postgres = std.mem.indexOf(u8, run_cmd.rootfs, "postgres") != null;

        // If no command specified, use entrypoint for known images
        if (modified_run_cmd.command.len == 0 or std.mem.eql(u8, modified_run_cmd.command, "/bin/sh")) {
            if (is_postgres) {
                modified_run_cmd.command = "docker-entrypoint.sh";
                // Args will be set after buildConfig
            }
        }

        var cfg = isolazi.cli.buildConfig(&modified_run_cmd) catch |err| {
            try stderr.print("Error: Failed to build configuration: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        // For postgres, add default arg "postgres" if entrypoint
        if (is_postgres and std.mem.eql(u8, modified_run_cmd.command, "docker-entrypoint.sh")) {
            cfg.addArg("postgres") catch {};
        }

        // For postgres, auto-set PGDATA if not provided
        if (is_postgres) {
            var has_pgdata = false;
            for (run_cmd.env_vars) |env| {
                if (std.mem.eql(u8, env.key, "PGDATA")) {
                    has_pgdata = true;
                    break;
                }
            }
            if (!has_pgdata) {
                // Find volume mount for /var/lib/postgresql
                for (run_cmd.volumes) |vol| {
                    if (std.mem.startsWith(u8, vol.container_path, "/var/lib/postgresql")) {
                        var buf: [256]u8 = undefined;
                        const pgdata = std.fmt.bufPrint(&buf, "PGDATA={s}/data", .{vol.container_path}) catch "PGDATA=/var/lib/postgresql/data";
                        cfg.addEnv(pgdata) catch {};
                        has_pgdata = true;
                        break;
                    }
                }
                if (!has_pgdata) {
                    cfg.addEnv("PGDATA=/var/lib/postgresql/data") catch {};
                }
            }
        }

        // Create and run the container
        // Expand 12-byte container_id to 32-byte for state tracking
        var cid_buf_short: [12]u8 = if (container_id) |cid| cid else [_]u8{ 'u', 'n', 'k', 'n', 'o', 'w', 'n', '0', '0', '0', '0', '0' };
        var cid_buf: [32]u8 = undefined;
        @memcpy(cid_buf[0..12], &cid_buf_short);
        // Pad with zeros
        @memset(cid_buf[12..], '0');

        // Register container with ContainerManager for state tracking
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Warning: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        // Build command string for state tracking
        var cmd_display: [256]u8 = undefined;
        const cmd_len = @min(run_cmd.command.len, 255);
        @memcpy(cmd_display[0..cmd_len], run_cmd.command[0..cmd_len]);

        // Register container and update to running
        _ = manager.createContainerWithId(&cid_buf, run_cmd.rootfs, cmd_display[0..cmd_len], null) catch {};
        manager.updateState(&cid_buf, .running, null, null) catch {};

        const result = isolazi.runtime.run(&cfg, allocator, &cid_buf_short) catch |err| {
            // Update state to stopped on error
            manager.updateState(&cid_buf, .stopped, null, 1) catch {};
            try stderr.print("Error: Container execution failed: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        // Update container state to stopped
        manager.updateState(&cid_buf, .stopped, null, result.exit_code) catch {};

        // Return the container's exit code
        if (result.signaled) {
            try stderr.print("Container killed by signal {}\n", .{result.signal});
            try stderr.flush();
        }

        return result.exit_code;
    }

    /// Execute a command in a running container on Linux using nsenter
    fn execContainerLinuxImpl(
        allocator: std.mem.Allocator,
        exec_cmd: isolazi.cli.ExecCommand,
        stdout: anytype,
        stderr: anytype,
    ) !u8 {
        _ = stdout;

        // Check if running as root
        const uid = std.os.linux.getuid();
        if (uid != 0) {
            try stderr.writeAll("Error: Isolazi exec must be run as root.\n");
            try stderr.writeAll("nsenter requires CAP_SYS_ADMIN privileges.\n");
            try stderr.writeAll("\nHint: Run with 'sudo isolazi exec ...'\n");
            try stderr.flush();
            return 1;
        }

        // Find the container
        var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
            try stderr.print("Error: Failed to initialize container manager: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer manager.deinit();

        const full_id = manager.findContainer(exec_cmd.container_id) catch {
            try stderr.print("Error: No such container: {s}\n", .{exec_cmd.container_id});
            try stderr.flush();
            return 1;
        };
        defer allocator.free(full_id);

        var info = manager.getContainer(full_id) catch {
            try stderr.print("Error: Failed to get container info\n", .{});
            try stderr.flush();
            return 1;
        };
        defer info.deinit();

        // Check container is running
        if (info.state != .running) {
            try stderr.print("Error: Container {s} is not running\n", .{info.shortId()});
            try stderr.flush();
            return 1;
        }

        const target_pid = info.pid orelse {
            try stderr.writeAll("Error: Container has no PID recorded\n");
            try stderr.flush();
            return 1;
        };

        // Build environment variables
        var env_list: std.ArrayList([]const u8) = .empty;
        defer env_list.deinit(allocator);

        for (exec_cmd.env_vars) |env| {
            var env_buf: [512]u8 = undefined;
            const env_str = std.fmt.bufPrint(&env_buf, "{s}={s}", .{ env.key, env.value }) catch continue;
            const duped = try allocator.dupe(u8, env_str);
            try env_list.append(allocator, duped);
        }
        defer {
            for (env_list.items) |item| {
                allocator.free(item);
            }
        }

        // Create exec configuration
        const exec_cfg = isolazi.runtime.ExecConfig{
            .target_pid = target_pid,
            .command = exec_cmd.command,
            .args = exec_cmd.args,
            .env = env_list.items,
            .cwd = exec_cmd.cwd,
            .user = exec_cmd.user,
            .namespaces = .{
                .mount = true,
                .uts = true,
                .ipc = true,
                .net = true,
                .pid = true,
                .user = false, // Usually skip user ns for exec
                .cgroup = true,
            },
        };

        // Execute in container
        const result = isolazi.runtime.execInContainer(allocator, exec_cfg) catch |err| {
            try stderr.print("Error: Failed to execute in container: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        if (result.signaled) {
            try stderr.print("Command killed by signal {}\n", .{result.signal});
            try stderr.flush();
        }

        return result.exit_code;
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

test "main imports compile" {
    // Just verify that the imports compile correctly
    _ = isolazi;
}
