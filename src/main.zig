//! Isolazi - Minimal Container Runtime
//!
//! Main entry point for the CLI application.
//!
//! Platform support:
//! - Linux: Native container execution using namespaces
//! - Windows: Delegates to WSL2 for container operations

const std = @import("std");
const builtin = @import("builtin");
const isolazi = @import("isolazi");

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
    } else {
        try stderr.writeAll("Error: Unsupported platform.\n");
        try stderr.writeAll("Isolazi supports Linux and Windows (via WSL2).\n");
        try stderr.flush();
        return 1;
    }
}

/// Run on Windows using WSL2 backend.
fn runOnWindows(
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
    if (!isolazi.windows.isWslAvailable(allocator)) {
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
            const wsl_path = isolazi.windows.windowsToWslPath(allocator, arg) catch |err| {
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
    const wsl_config = isolazi.windows.WslConfig{
        .distro = null, // Use default distro
        .isolazi_path = null, // Assume isolazi is in PATH
        .run_as_root = true, // Containers need root
    };

    return isolazi.windows.execInWsl(allocator, wsl_config, wsl_args.items) catch |err| {
        try stderr.print("Error executing in WSL: {}\n", .{err});
        try stderr.writeAll("\nMake sure:\n");
        try stderr.writeAll("  1. WSL2 is properly installed\n");
        try stderr.writeAll("  2. Isolazi is installed in your WSL distribution\n");
        try stderr.writeAll("  3. The rootfs path is accessible from WSL\n");
        try stderr.flush();
        return 1;
    };
}

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

/// Run container on Windows using WSL2 backend
fn runContainerWindows(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Parse flags
    var detach_mode = false;
    var image_idx: usize = 2;

    // Check for flags after "run"
    var arg_idx: usize = 2;
    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
            detach_mode = true;
        } else if (arg.len > 0 and arg[0] == '-') {
            // Unknown flag, skip for now
            continue;
        } else {
            // First non-flag argument is the image
            image_idx = arg_idx;
            break;
        }
    }

    // Check if we have an image argument
    if (image_idx >= args.len) {
        try stderr.writeAll("Error: Missing image name\n");
        try stderr.writeAll("Usage: isolazi run [-d|--detach] <image> [command...]\n");
        try stderr.flush();
        return 1;
    }

    const image_name = args[image_idx];

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
    if (!isolazi.windows.isWslAvailable(allocator)) {
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
    if (!detach_mode) {
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
    const wsl_rootfs = isolazi.windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
        try stderr.print("Error: Failed to convert path: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(wsl_rootfs);

    // Get command to run (default: /bin/sh)
    var cmd_args: std.ArrayList([]const u8) = .empty;
    defer cmd_args.deinit(allocator);

    if (args.len > image_idx + 1) {
        // User specified command
        for (args[image_idx + 1 ..]) |arg| {
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

    if (detach_mode) {
        // In detach mode, use nohup and redirect output to /dev/null
        // Run the container in the background
        try wsl_cmd.append(allocator, "nohup");
    }

    try wsl_cmd.append(allocator, "unshare");
    try wsl_cmd.append(allocator, "--mount");
    try wsl_cmd.append(allocator, "--uts");
    try wsl_cmd.append(allocator, "--ipc");
    try wsl_cmd.append(allocator, "--pid");
    try wsl_cmd.append(allocator, "--fork");
    try wsl_cmd.append(allocator, "--mount-proc");
    try wsl_cmd.append(allocator, "chroot");
    try wsl_cmd.append(allocator, wsl_rootfs);

    // Add the command
    for (cmd_args.items) |arg| {
        try wsl_cmd.append(allocator, arg);
    }

    if (detach_mode) {
        // Redirect output and background the process
        try wsl_cmd.append(allocator, ">");
        try wsl_cmd.append(allocator, "/dev/null");
        try wsl_cmd.append(allocator, "2>&1");
        try wsl_cmd.append(allocator, "&");
    }

    if (detach_mode) {
        // For detach mode, print container ID and return immediately
        try stdout.print("{s}\n", .{container_id});
        try stdout.flush();
    } else {
        try stdout.print("Starting container...\n", .{});
        try stdout.flush();
    }

    // Execute in WSL
    var child = std.process.Child.init(wsl_cmd.items, allocator);

    if (detach_mode) {
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

    if (detach_mode) {
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
    const wsl_rootfs = isolazi.windows.windowsToWslPath(allocator, rootfs_path) catch |err| {
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

        var ref = isolazi.image.pullImage(allocator, pull_cmd.image, &cache, &progress_cb) catch |err| {
            try stderr.print("Error: Failed to pull image: {}\n", .{err});
            try stderr.flush();
            return 1;
        };
        defer ref.deinit();

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
                @constCast(img).deinit();
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
                    img.tag orelse "latest",
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
        var ref_opt: ?isolazi.image.ImageReference = null;
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
            if (ref_opt) |*r| r.deinit();
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
            var ref = isolazi.image.pullImage(allocator, run_cmd.rootfs, &cache, null) catch |err| {
                try stderr.print("Error: Failed to pull image '{s}': {}\n", .{ run_cmd.rootfs, err });
                try stderr.flush();
                return 1;
            };
            ref_opt = ref;

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
