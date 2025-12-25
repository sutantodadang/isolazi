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

/// VM configuration options
pub const VMConfig = struct {
    /// Number of CPU cores (default: 2)
    cpu_count: u32 = 2,
    /// Memory size in bytes (default: 2GB)
    memory_size: u64 = 2 * 1024 * 1024 * 1024,
    /// Path to Linux kernel (vmlinuz)
    kernel_path: ?[]const u8 = null,
    /// Path to initramfs
    initramfs_path: ?[]const u8 = null,
    /// Kernel command line arguments
    kernel_cmdline: []const u8 = "console=hvc0",
    /// Path to root disk image (optional)
    disk_image_path: ?[]const u8 = null,
    /// Enable Rosetta for x86_64 translation (Apple Silicon only)
    enable_rosetta: bool = false,
    /// Share directories with the VM
    shared_directories: []const SharedDirectory = &.{},
    /// Network mode
    network_mode: NetworkMode = .nat,
};

/// Shared directory configuration for VirtioFS
pub const SharedDirectory = struct {
    /// Host path to share
    host_path: []const u8,
    /// Mount tag in the guest
    mount_tag: []const u8,
    /// Read-only mount
    read_only: bool = false,
};

/// Network configuration mode
pub const NetworkMode = enum {
    /// NAT networking (default)
    nat,
    /// Bridged networking (requires permission)
    bridged,
    /// No network
    none,
};

/// VM state
pub const VMState = enum {
    stopped,
    starting,
    running,
    pausing,
    paused,
    stopping,
    error_state,
};

/// Virtual Machine handle
pub const VirtualMachine = struct {
    allocator: std.mem.Allocator,
    config: VMConfig,
    state: VMState,
    /// Socket path for VM communication
    socket_path: ?[]const u8,
    /// PID of the VM process (when using helper tool)
    vm_pid: ?std.process.Child.Id,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: VMConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .state = .stopped,
            .socket_path = null,
            .vm_pid = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.socket_path) |path| {
            self.allocator.free(path);
        }
        self.* = undefined;
    }

    /// Start the virtual machine
    pub fn start(self: *Self) VirtualizationError!void {
        if (self.state != .stopped) {
            return VirtualizationError.VMStartFailed;
        }

        self.state = .starting;

        // Validate configuration
        if (self.config.kernel_path == null) {
            self.state = .error_state;
            return VirtualizationError.KernelNotFound;
        }

        // In a real implementation, this would use Objective-C runtime
        // to interact with Virtualization.framework. For now, we use
        // a helper tool approach similar to vfkit/lima.
        self.state = .running;
    }

    /// Stop the virtual machine
    pub fn stop(self: *Self) VirtualizationError!void {
        if (self.state != .running and self.state != .paused) {
            return VirtualizationError.VMStopFailed;
        }

        self.state = .stopping;

        // Send shutdown signal to VM
        if (self.vm_pid) |pid| {
            _ = std.posix.kill(pid, std.posix.SIG.TERM) catch {};
        }

        self.state = .stopped;
    }

    /// Execute a command in the VM
    pub fn exec(self: *Self, args: []const []const u8) VirtualizationError!u8 {
        if (self.state != .running) {
            return VirtualizationError.CommandFailed;
        }

        // In a full implementation, this would use vsock or SSH to
        // communicate with the guest. For now, we simulate success.
        _ = args;
        return 0;
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

/// Get the path to the Linux VM assets
pub fn getVMAssetsDir(allocator: std.mem.Allocator) ![]const u8 {
    const data_dir = try getDataDir(allocator);
    defer allocator.free(data_dir);
    return try std.fmt.allocPrint(allocator, "{s}/vm", .{data_dir});
}

/// Create a Linux VM configuration suitable for container execution.
/// This sets up a minimal Linux environment with VirtioFS for sharing
/// the container rootfs.
pub fn createLinuxVM(allocator: std.mem.Allocator, config: VMConfig) !VirtualMachine {
    // Validate that virtualization is available
    if (!isVirtualizationAvailable(allocator)) {
        return VirtualizationError.VirtualizationNotAvailable;
    }

    // Create VM with config
    return VirtualMachine.init(allocator, config);
}

/// Run a command inside a Linux VM.
/// This is the main entry point for macOS container execution.
///
/// The flow is:
/// 1. Start/reuse a Linux VM
/// 2. Share the container rootfs via VirtioFS
/// 3. Execute the container command using isolazi inside the VM
/// 4. Return the exit code
pub fn runInVM(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    command: []const []const u8,
    config: VMConfig,
) !u8 {
    // For a full implementation, we would:
    // 1. Check if a VM is already running (persistent VM approach)
    // 2. Start VM if needed
    // 3. Share rootfs via VirtioFS
    // 4. Execute command via vsock/SSH
    // 5. Return exit code

    // For now, we use a simpler approach similar to lima/colima:
    // Use a helper tool that manages the VM lifecycle

    var vm = try createLinuxVM(allocator, config);
    defer vm.deinit();

    // Share the rootfs directory
    const shared_dirs = [_]SharedDirectory{
        .{
            .host_path = rootfs_path,
            .mount_tag = "rootfs",
            .read_only = false,
        },
    };

    var vm_config = config;
    vm_config.shared_directories = &shared_dirs;

    try vm.start();
    defer vm.stop() catch {};

    return vm.exec(command);
}

/// Convert a macOS path to a format usable inside the VM.
/// For VirtioFS mounts, paths are typically mounted under /mnt/<tag>.
pub fn convertMacOSPath(
    allocator: std.mem.Allocator,
    _: []const u8, // host_path - reserved for future use
    mount_tag: []const u8,
) ![]const u8 {
    // VirtioFS mounts appear at /mnt/<tag> or /Volumes/<tag> in the guest
    return try std.fmt.allocPrint(allocator, "/mnt/{s}", .{mount_tag});
}

/// Download and setup the Linux VM assets if not present.
/// This downloads a minimal Linux kernel and initramfs.
pub fn ensureVMAssets(allocator: std.mem.Allocator) !struct {
    kernel_path: []const u8,
    initramfs_path: []const u8,
} {
    const assets_dir = try getVMAssetsDir(allocator);
    defer allocator.free(assets_dir);

    // Create assets directory if it doesn't exist
    std.fs.makeDirAbsolute(assets_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };

    const kernel_path = try std.fmt.allocPrint(allocator, "{s}/vmlinuz", .{assets_dir});
    const initramfs_path = try std.fmt.allocPrint(allocator, "{s}/initramfs", .{assets_dir});

    // Check if assets exist
    const kernel_exists = blk: {
        std.fs.accessAbsolute(kernel_path, .{}) catch break :blk false;
        break :blk true;
    };

    if (!kernel_exists) {
        // Assets need to be downloaded or built
        // In a full implementation, we would download pre-built assets
        // or guide the user to install them
        allocator.free(kernel_path);
        allocator.free(initramfs_path);
        return VirtualizationError.KernelNotFound;
    }

    return .{
        .kernel_path = kernel_path,
        .initramfs_path = initramfs_path,
    };
}

/// Create a helper script to manage VM lifecycle.
/// This can be used when direct Virtualization.framework access isn't available.
pub fn createVMHelperScript(allocator: std.mem.Allocator) ![]const u8 {
    const script_content =
        \\#!/bin/bash
        \\# Isolazi VM Helper for macOS
        \\# Uses vfkit or QEMU as the hypervisor backend
        \\
        \\set -e
        \\
        \\ISOLAZI_DIR="${HOME}/Library/Application Support/isolazi"
        \\VM_DIR="${ISOLAZI_DIR}/vm"
        \\SOCKET_PATH="${VM_DIR}/vm.sock"
        \\
        \\start_vm() {
        \\    local kernel="$1"
        \\    local initramfs="$2"
        \\    local rootfs="$3"
        \\    
        \\    # Check for vfkit (preferred on Apple Silicon)
        \\    if command -v vfkit &> /dev/null; then
        \\        vfkit \
        \\            --kernel "$kernel" \
        \\            --initrd "$initramfs" \
        \\            --kernel-cmdline "console=hvc0 root=/dev/vda" \
        \\            --cpus 2 \
        \\            --memory 2048 \
        \\            --virtio-fs "path=$rootfs,mount-tag=rootfs" \
        \\            --virtio-vsock "port=2222,socketURL=$SOCKET_PATH" &
        \\    elif command -v limactl &> /dev/null; then
        \\        # Fallback to Lima
        \\        limactl start isolazi 2>/dev/null || true
        \\        limactl shell isolazi -- \
        \\            sudo unshare --mount --uts --ipc --pid --fork --mount-proc \
        \\            chroot "$rootfs" "$@" &
        \\    else
        \\        echo "Error: No hypervisor found. Install vfkit or lima." >&2
        \\        exit 1
        \\    fi
        \\}
        \\
        \\stop_vm() {
        \\    # Send shutdown command via vsock or kill process
        \\    if [ -f "${VM_DIR}/vm.pid" ]; then
        \\        kill "$(cat ${VM_DIR}/vm.pid)" 2>/dev/null || true
        \\        rm -f "${VM_DIR}/vm.pid"
        \\    fi
        \\}
        \\
        \\case "$1" in
        \\    start)
        \\        start_vm "$2" "$3" "$4"
        \\        ;;
        \\    stop)
        \\        stop_vm
        \\        ;;
        \\    *)
        \\        echo "Usage: $0 {start|stop} [args...]"
        \\        exit 1
        \\        ;;
        \\esac
    ;

    const data_dir = try getDataDir(allocator);
    defer allocator.free(data_dir);

    const script_path = try std.fmt.allocPrint(allocator, "{s}/vm-helper.sh", .{data_dir});
    errdefer allocator.free(script_path);

    // Create directory if needed
    std.fs.makeDirAbsolute(data_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };

    // Write script
    const file = try std.fs.createFileAbsolute(script_path, .{});
    defer file.close();
    try file.writeAll(script_content);

    // Make executable (chmod +x)
    // On POSIX systems, we'd use fchmod here
    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "chmod", "+x", script_path },
    }) catch {};

    return script_path;
}

/// Check if a hypervisor backend is available (vfkit, lima)
pub fn findHypervisor(allocator: std.mem.Allocator) ?[]const u8 {
    // Check for vfkit first (native macOS, uses Virtualization.framework)
    const vfkit_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "which", "vfkit" },
    }) catch return null;

    defer allocator.free(vfkit_result.stdout);
    defer allocator.free(vfkit_result.stderr);

    if (vfkit_result.term.Exited == 0 and vfkit_result.stdout.len > 0) {
        return "vfkit";
    }

    // Check for lima (limactl)
    const lima_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "which", "limactl" },
    }) catch return null;

    defer allocator.free(lima_result.stdout);
    defer allocator.free(lima_result.stderr);

    if (lima_result.term.Exited == 0 and lima_result.stdout.len > 0) {
        return "lima";
    }

    return null;
}

/// Environment variable pair
pub const EnvPair = struct {
    key: []const u8,
    value: []const u8,
};

/// Volume mount pair
pub const VolumePair = struct {
    host_path: []const u8,
    container_path: []const u8,
};

/// Run using vfkit (Apple Virtualization.framework wrapper)
pub fn runWithVfkit(
    allocator: std.mem.Allocator,
    kernel_path: []const u8,
    rootfs_path: []const u8,
    command: []const []const u8,
    env_vars: []const EnvPair,
    volumes: []const VolumePair,
) !u8 {
    // Build vfkit command
    var vfkit_args: std.ArrayList([]const u8) = .empty;
    defer vfkit_args.deinit(allocator);

    try vfkit_args.append(allocator, "vfkit");
    try vfkit_args.append(allocator, "--kernel");
    try vfkit_args.append(allocator, kernel_path);
    try vfkit_args.append(allocator, "--cpus");
    try vfkit_args.append(allocator, "2");
    try vfkit_args.append(allocator, "--memory");
    try vfkit_args.append(allocator, "2048");

    // Add VirtioFS for rootfs sharing
    const virtfs_arg = try std.fmt.allocPrint(
        allocator,
        "path={s},mount-tag=rootfs",
        .{rootfs_path},
    );
    defer allocator.free(virtfs_arg);

    try vfkit_args.append(allocator, "--virtio-fs");
    try vfkit_args.append(allocator, virtfs_arg);

    // Add additional VirtioFS mounts for volumes
    var volume_allocs: std.ArrayList([]const u8) = .empty;
    defer {
        for (volume_allocs.items) |alloc| {
            allocator.free(alloc);
        }
        volume_allocs.deinit(allocator);
    }

    for (volumes, 0..) |vol, i| {
        const vol_arg = try std.fmt.allocPrint(
            allocator,
            "path={s},mount-tag=vol{d}",
            .{ vol.host_path, i },
        );
        try volume_allocs.append(allocator, vol_arg);
        try vfkit_args.append(allocator, "--virtio-fs");
        try vfkit_args.append(allocator, vol_arg);
    }

    // Build kernel cmdline with init command and env vars
    var cmdline_parts: std.ArrayList(u8) = .empty;
    defer cmdline_parts.deinit(allocator);

    try cmdline_parts.appendSlice(allocator, "console=hvc0 ");

    // Add environment variables to kernel cmdline
    for (env_vars) |env| {
        try cmdline_parts.appendSlice(allocator, env.key);
        try cmdline_parts.append(allocator, '=');
        try cmdline_parts.appendSlice(allocator, env.value);
        try cmdline_parts.append(allocator, ' ');
    }

    try cmdline_parts.appendSlice(allocator, "init=/sbin/init -- ");
    for (command) |arg| {
        try cmdline_parts.appendSlice(allocator, arg);
        try cmdline_parts.append(allocator, ' ');
    }

    try vfkit_args.append(allocator, "--kernel-cmdline");
    try vfkit_args.append(allocator, cmdline_parts.items);

    // Execute vfkit
    var child = std.process.Child.init(vfkit_args.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
}

/// Run using Lima (Linux virtual machines on macOS)
/// Lima provides a seamless Linux VM experience with automatic file sharing.
pub fn runWithLima(
    allocator: std.mem.Allocator,
    _: []const u8, // kernel_path - Lima manages its own kernel
    rootfs_path: []const u8,
    command: []const []const u8,
    env_vars: []const EnvPair,
    volumes: []const VolumePair,
) !u8 {
    // First, ensure Lima VM "isolazi" exists and is running
    // Try to start it (will succeed if already running)
    const start_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "start", "isolazi" },
    }) catch |err| {
        // If VM doesn't exist, we need to create it first
        if (err == error.FileNotFound) {
            return VirtualizationError.VMCreationFailed;
        }
        // Try to continue anyway - VM might already be running
    };

    if (start_result.term.Exited != 0) {
        // VM might not exist, try to create it
        _ = try createLimaInstance(allocator);
    }

    allocator.free(start_result.stdout);
    allocator.free(start_result.stderr);

    // Build the lima shell command
    // Lima automatically mounts the home directory, so we can access rootfs directly
    var lima_args: std.ArrayList([]const u8) = .empty;
    defer lima_args.deinit(allocator);

    try lima_args.append(allocator, "limactl");
    try lima_args.append(allocator, "shell");
    try lima_args.append(allocator, "isolazi");
    try lima_args.append(allocator, "--");
    try lima_args.append(allocator, "sudo");

    // Add environment variables using env command
    if (env_vars.len > 0) {
        try lima_args.append(allocator, "env");
        var env_allocs: std.ArrayList([]const u8) = .empty;
        defer {
            for (env_allocs.items) |alloc| {
                allocator.free(alloc);
            }
            env_allocs.deinit(allocator);
        }
        for (env_vars) |env| {
            const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
            try env_allocs.append(allocator, env_str);
            try lima_args.append(allocator, env_str);
        }
    }

    // Build a shell script to handle bind mounts for volumes
    if (volumes.len > 0) {
        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, "-c");

        // Build script that creates bind mounts then runs chroot
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(allocator);

        // Create bind mounts for each volume
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

        // Add the unshare and chroot command
        try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc chroot ");
        try script.appendSlice(allocator, rootfs_path);

        // Add the command
        for (command) |arg| {
            try script.append(allocator, ' ');
            try script.appendSlice(allocator, arg);
        }

        const script_str = try allocator.dupe(u8, script.items);
        defer allocator.free(script_str);
        try lima_args.append(allocator, script_str);
    } else {
        try lima_args.append(allocator, "unshare");
        try lima_args.append(allocator, "--mount");
        try lima_args.append(allocator, "--uts");
        try lima_args.append(allocator, "--ipc");
        try lima_args.append(allocator, "--pid");
        try lima_args.append(allocator, "--fork");
        try lima_args.append(allocator, "--mount-proc");
        try lima_args.append(allocator, "chroot");
        try lima_args.append(allocator, rootfs_path);

        // Add the command
        for (command) |arg| {
            try lima_args.append(allocator, arg);
        }
    }

    // Execute via Lima
    var child = std.process.Child.init(lima_args.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @truncate(128 +% sig),
        else => 1,
    };
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
        \\  - location: "/tmp/lima"
        \\    writable: true
        \\containerd:
        \\  system: false
        \\  user: false
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
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "limactl", "list", "--format={{.Status}}", "isolazi" },
    }) catch return false;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return false;
    }

    const status = std.mem.trim(u8, result.stdout, " \t\r\n");
    return std.mem.eql(u8, status, "Running");
}
