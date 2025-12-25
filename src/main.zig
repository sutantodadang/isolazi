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

    const EnvPair = struct {
        key: []const u8,
        value: []const u8,
    };

    const VolumePair = struct {
        host_path: []const u8,
        container_path: []const u8,
        read_only: bool,
    };
};

/// Parse run command arguments (shared by all platforms)
fn parseRunOptions(allocator: std.mem.Allocator, args: []const []const u8) !RunOptions {
    var opts = RunOptions{};

    // Static buffers for env vars and volumes
    var env_buf: [64]RunOptions.EnvPair = undefined;
    var env_count: usize = 0;
    var vol_buf: [32]RunOptions.VolumePair = undefined;
    var vol_count: usize = 0;

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

            // Parse KEY=VALUE
            if (std.mem.indexOf(u8, env_str, "=")) |eq_pos| {
                if (env_count < env_buf.len) {
                    env_buf[env_count] = .{
                        .key = env_str[0..eq_pos],
                        .value = env_str[eq_pos + 1 ..],
                    };
                    env_count += 1;
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
        } else if (arg.len > 0 and arg[0] == '-') {
            // Skip unknown flags with values
            if (std.mem.eql(u8, arg, "--hostname") or std.mem.eql(u8, arg, "--cwd")) {
                arg_idx += 1; // Skip the value
            }
        } else if (!image_found) {
            opts.image_name = arg;
            image_found = true;
            // Everything after image is command + args
            if (arg_idx + 1 < args.len) {
                opts.command_args = args[arg_idx + 1 ..];
            }
            break;
        }
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
    }

    // Check if we have an image argument
    if (opts.image_name.len == 0) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi run [options] <image> [command...]\n");
        try stderr.writeAll("\nOptions:\n");
        try stderr.writeAll("  -d, --detach              Run in background\n");
        try stderr.writeAll("  -e, --env KEY=VALUE       Set environment variable\n");
        try stderr.writeAll("  -v, --volume SRC:DST[:ro] Mount a volume\n");
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
        // Default command
        try cmd_args.append(allocator, "/bin/sh");
    }

    // Build the command to run in WSL
    // We use unshare to create namespaces and chroot into the rootfs
    var wsl_cmd: std.ArrayList([]const u8) = .empty;
    defer wsl_cmd.deinit(allocator);

    try wsl_cmd.append(allocator, "wsl");
    try wsl_cmd.append(allocator, "-u");
    try wsl_cmd.append(allocator, "root");
    try wsl_cmd.append(allocator, "--");

    if (opts.detach_mode) {
        // In detach mode, use nohup and redirect output to /dev/null
        // Run the container in the background
        try wsl_cmd.append(allocator, "nohup");
    }

    // Set environment variables using env command
    if (opts.env_vars.len > 0) {
        try wsl_cmd.append(allocator, "env");
        for (opts.env_vars) |env| {
            const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
            try wsl_cmd.append(allocator, env_str);
        }
    }

    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");
    try wsl_cmd.append(allocator, "--mount-proc");

    // Handle volume mounts - use a script to mount before chroot
    if (opts.volumes.len > 0) {
        // Create a shell script that mounts volumes then runs chroot
        try wsl_cmd.append(allocator, "sh");
        try wsl_cmd.append(allocator, "-c");

        var script_buf: std.ArrayList(u8) = .empty;
        defer script_buf.deinit(allocator);

        // Mount each volume
        for (opts.volumes) |vol| {
            const wsl_host = windows.windowsToWslPath(allocator, vol.host_path) catch vol.host_path;
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

        // Add chroot command
        try script_buf.appendSlice(allocator, "exec chroot ");
        try script_buf.appendSlice(allocator, wsl_rootfs);
        try script_buf.append(allocator, ' ');
        for (cmd_args.items) |arg| {
            try script_buf.appendSlice(allocator, arg);
            try script_buf.append(allocator, ' ');
        }

        try wsl_cmd.append(allocator, script_buf.items);
    } else {
        try wsl_cmd.append(allocator, "chroot");
        try wsl_cmd.append(allocator, wsl_rootfs);

        // Add the command
        for (cmd_args.items) |arg| {
            try wsl_cmd.append(allocator, arg);
        }
    }

    if (opts.detach_mode) {
        // Redirect output and background the process
        try wsl_cmd.append(allocator, ">");
        try wsl_cmd.append(allocator, "/dev/null");
        try wsl_cmd.append(allocator, "2>&1");
        try wsl_cmd.append(allocator, "&");
    }

    if (opts.detach_mode) {
        // For detach mode, print container ID and return immediately
        try stdout.print("{s}\n", .{container_id});
        try stdout.flush();
    } else {
        try stdout.print("Starting container...\n", .{});
        try stdout.flush();
    }

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
        // Don't wait for the child in detach mode
        return 0;
    }

    const term = try child.wait();

    // Cleanup container (optional, could keep for debugging)
    // cache.removeContainer(&container_id) catch {};

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
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

        // Get command to run (default: /bin/sh)
        var cmd_args: std.ArrayList([]const u8) = .empty;
        defer cmd_args.deinit(allocator);

        if (opts.command_args.len > 0) {
            for (opts.command_args) |arg| {
                try cmd_args.append(allocator, arg);
            }
        } else {
            try cmd_args.append(allocator, "/bin/sh");
        }

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
        for (opts.env_vars) |e| {
            try env_pairs.append(allocator, .{ .key = e.key, .value = e.value });
        }

        // Convert volumes to virtualization format
        var vol_pairs: std.ArrayList(isolazi.macos.virtualization.VolumePair) = .empty;
        defer vol_pairs.deinit(allocator);
        for (opts.volumes) |v| {
            try vol_pairs.append(allocator, .{ .host_path = v.host_path, .container_path = v.container_path });
        }

        // Ensure VM assets are available (only needed for vfkit)
        const VMAssets = struct {
            kernel_path: []const u8,
            initramfs_path: []const u8,
        };
        var vm_assets: ?VMAssets = null;

        if (std.mem.eql(u8, hypervisor.?, "vfkit")) {
            const assets = isolazi.macos.virtualization.ensureVMAssets(allocator) catch {
                try stderr.writeAll("Error: Linux VM kernel not found.\n");
                try stderr.writeAll("\nTo setup the VM environment:\n");
                try stderr.writeAll("  1. Download a Linux kernel (vmlinuz) for your architecture\n");
                try stderr.writeAll("  2. Place it at: ~/Library/Application Support/isolazi/vm/vmlinuz\n");
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
                allocator.free(assets.initramfs_path);
            }
        }

        // Run in VM using appropriate hypervisor
        if (std.mem.eql(u8, hypervisor.?, "vfkit")) {
            return isolazi.macos.virtualization.runWithVfkit(
                allocator,
                vm_assets.?.kernel_path,
                rootfs_path,
                cmd_args.items,
                env_pairs.items,
                vol_pairs.items,
            ) catch |err| {
                try stderr.print("Error: Failed to run in VM: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
        } else {
            // Use Lima
            return isolazi.macos.virtualization.runWithLima(
                allocator,
                "", // Lima manages its own kernel
                rootfs_path,
                cmd_args.items,
                env_pairs.items,
                vol_pairs.items,
            ) catch |err| {
                try stderr.print("Error: Failed to run with Lima: {}\n", .{err});
                try stderr.flush();
                return 1;
            };
        }
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

        const cfg = isolazi.cli.buildConfig(&modified_run_cmd) catch |err| {
            try stderr.print("Error: Failed to build configuration: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        // Create and run the container
        const result = isolazi.runtime.run(&cfg) catch |err| {
            try stderr.print("Error: Container execution failed: {}\n", .{err});
            try stderr.flush();
            return 1;
        };

        // Return the container's exit code
        if (result.signaled) {
            try stderr.print("Container killed by signal {}\n", .{result.signal});
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
