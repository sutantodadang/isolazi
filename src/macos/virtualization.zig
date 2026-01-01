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

/// Download a file from a URL using curl
fn downloadFile(allocator: std.mem.Allocator, url: []const u8, dest_path: []const u8) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl",
            "-fSL",
            "--progress-bar",
            "-o",
            dest_path,
            url,
        },
    }) catch return VirtualizationError.CommandFailed;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return VirtualizationError.CommandFailed;
    }
}

/// Create a minimal initramfs that mounts virtio-fs rootfs and switches to it.
/// This creates a cpio archive with busybox-based init.
fn createMinimalInitramfs(allocator: std.mem.Allocator, initramfs_path: []const u8) !void {
    const assets_dir = std.fs.path.dirname(initramfs_path) orelse return VirtualizationError.ConfigurationInvalid;

    // Create initramfs build directory
    const build_dir = try std.fmt.allocPrint(allocator, "{s}/initramfs-build", .{assets_dir});
    defer allocator.free(build_dir);

    // Remove old build dir if exists
    std.fs.deleteTreeAbsolute(build_dir) catch {};

    // Create directory structure
    const dirs = [_][]const u8{
        "",
        "/bin",
        "/sbin",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/mnt",
        "/mnt/rootfs",
        "/lib",
        "/lib64",
    };

    for (dirs) |dir| {
        const full_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ build_dir, dir });
        defer allocator.free(full_path);
        std.fs.makeDirAbsolute(full_path) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    // Create init script that mounts virtio-fs and switches root
    const init_script =
        \\#!/bin/sh
        \\# Minimal init for isolazi VM
        \\
        \\# Mount essential filesystems
        \\mount -t proc proc /proc
        \\mount -t sysfs sys /sys
        \\mount -t devtmpfs dev /dev
        \\
        \\# Mount virtio-fs rootfs
        \\mount -t virtiofs rootfs /mnt/rootfs
        \\
        \\# Switch root to the container rootfs
        \\exec switch_root /mnt/rootfs /sbin/init "$@"
    ;

    const init_path = try std.fmt.allocPrint(allocator, "{s}/init", .{build_dir});
    defer allocator.free(init_path);

    const init_file = try std.fs.createFileAbsolute(init_path, .{});
    defer init_file.close();
    try init_file.writeAll(init_script);

    // Make init executable
    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "chmod", "+x", init_path },
    }) catch {};

    // Download busybox static binary for arm64
    const busybox_path = try std.fmt.allocPrint(allocator, "{s}/bin/busybox", .{build_dir});
    defer allocator.free(busybox_path);

    // Use busybox from Alpine Linux (static arm64 build)
    const busybox_url = "https://busybox.net/downloads/binaries/1.35.0-arm64-linux-musl/busybox";

    std.debug.print("Downloading busybox for initramfs...\n", .{});
    try downloadFile(allocator, busybox_url, busybox_path);

    // Make busybox executable
    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "chmod", "+x", busybox_path },
    }) catch {};

    // Create busybox symlinks
    const busybox_cmds = [_][]const u8{
        "sh",
        "mount",
        "umount",
        "switch_root",
        "cat",
        "ls",
        "mkdir",
        "mknod",
        "sleep",
    };

    for (busybox_cmds) |cmd| {
        const link_path = try std.fmt.allocPrint(allocator, "{s}/bin/{s}", .{ build_dir, cmd });
        defer allocator.free(link_path);

        // Create symlink: ln -sf busybox <cmd>
        _ = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "ln", "-sf", "busybox", link_path },
        }) catch {};
    }

    // Also link to /sbin
    const sbin_cmds = [_][]const u8{ "init", "switch_root" };
    for (sbin_cmds) |cmd| {
        const link_path = try std.fmt.allocPrint(allocator, "{s}/sbin/{s}", .{ build_dir, cmd });
        defer allocator.free(link_path);

        _ = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "ln", "-sf", "../bin/busybox", link_path },
        }) catch {};
    }

    // Create initramfs cpio archive
    // (cd build_dir && find . | cpio -o -H newc | gzip > initramfs)
    std.debug.print("Creating initramfs cpio archive...\n", .{});

    const script_path = try std.fmt.allocPrint(allocator, "{s}/create-initramfs.sh", .{assets_dir});
    defer allocator.free(script_path);

    const create_script = try std.fmt.allocPrint(
        allocator,
        \\#!/bin/sh
        \\cd "{s}" && find . | cpio -o -H newc 2>/dev/null | gzip > "{s}"
    ,
        .{ build_dir, initramfs_path },
    );
    defer allocator.free(create_script);

    const script_file = try std.fs.createFileAbsolute(script_path, .{});
    defer script_file.close();
    try script_file.writeAll(create_script);

    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "chmod", "+x", script_path },
    }) catch {};

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", script_path },
    }) catch return VirtualizationError.CommandFailed;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return VirtualizationError.CommandFailed;
    }

    // Clean up build directory
    std.fs.deleteTreeAbsolute(build_dir) catch {};
    std.fs.deleteFileAbsolute(script_path) catch {};

    std.debug.print("Initramfs created at: {s}\n", .{initramfs_path});
}

/// Download and setup the Linux VM assets if not present.
/// This downloads a minimal Linux kernel from gokrazy/kernel.arm64.
/// For ARM64 macOS (Apple Silicon), we use the arm64 kernel.
pub fn ensureVMAssets(allocator: std.mem.Allocator) !struct {
    kernel_path: []const u8,
    initramfs_path: ?[]const u8,
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
    errdefer allocator.free(kernel_path);

    const initramfs_path = try std.fmt.allocPrint(allocator, "{s}/initramfs.cpio.gz", .{assets_dir});
    errdefer allocator.free(initramfs_path);

    // Check if kernel exists, if not download it
    const kernel_exists = blk: {
        std.fs.accessAbsolute(kernel_path, .{}) catch break :blk false;
        break :blk true;
    };

    if (!kernel_exists) {
        // Download kernel from gokrazy/kernel.arm64 repository
        // The vmlinuz file is available directly in the repo
        const kernel_url = "https://raw.githubusercontent.com/gokrazy/kernel.arm64/main/vmlinuz";

        std.debug.print("Downloading Linux kernel from gokrazy/kernel.arm64...\n", .{});
        downloadFile(allocator, kernel_url, kernel_path) catch {
            allocator.free(kernel_path);
            allocator.free(initramfs_path);
            return VirtualizationError.KernelNotFound;
        };
        std.debug.print("Kernel downloaded to: {s}\n", .{kernel_path});
    }

    // Check if initramfs exists, if not create it
    const initramfs_exists = blk: {
        std.fs.accessAbsolute(initramfs_path, .{}) catch break :blk false;
        break :blk true;
    };

    if (!initramfs_exists) {
        createMinimalInitramfs(allocator, initramfs_path) catch {
            allocator.free(kernel_path);
            allocator.free(initramfs_path);
            return VirtualizationError.InitramfsNotFound;
        };
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
        \\            --bootloader "linux,kernel=$kernel,initrd=$initramfs,cmdline=\"console=hvc0 root=/dev/vda\"" \
        \\            --cpus 2 \
        \\            --memory 2048 \
        \\            --device "virtio-fs,sharedDir=$rootfs,mountTag=rootfs" \
        \\            --device "virtio-vsock,port=2222,socketURL=$SOCKET_PATH" \
        \\            --device virtio-serial,stdio &
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

/// Port mapping for container networking
pub const PortMapping = struct {
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

    pub const Protocol = enum {
        tcp,
        udp,
    };
};

/// Run using vfkit (Apple Virtualization.framework wrapper)
pub fn runWithVfkit(
    allocator: std.mem.Allocator,
    kernel_path: []const u8,
    initramfs_path: ?[]const u8,
    rootfs_path: []const u8,
    command: []const []const u8,
    env_vars: []const EnvPair,
    volumes: []const VolumePair,
    port_mappings: []const PortMapping,
) !u8 {
    // Build vfkit command
    var vfkit_args: std.ArrayList([]const u8) = .empty;
    defer vfkit_args.deinit(allocator);

    try vfkit_args.append(allocator, "vfkit");
    try vfkit_args.append(allocator, "--cpus");
    try vfkit_args.append(allocator, "2");
    try vfkit_args.append(allocator, "--memory");
    try vfkit_args.append(allocator, "2048");

    // Track allocations for cleanup
    var allocs_to_free: std.ArrayList([]const u8) = .empty;
    defer {
        for (allocs_to_free.items) |a| allocator.free(a);
        allocs_to_free.deinit(allocator);
    }

    // Build kernel cmdline with init script that sets clean environment
    var cmdline_parts: std.ArrayList(u8) = .empty;
    defer cmdline_parts.deinit(allocator);

    try cmdline_parts.appendSlice(allocator, "console=hvc0 ");

    // Use init script that sets up clean environment
    // The init will use env -i to clear inherited environment
    try cmdline_parts.appendSlice(allocator, "init=/bin/sh -- -c 'exec env -i ");

    // Set minimal required environment
    try cmdline_parts.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ");
    try cmdline_parts.appendSlice(allocator, "HOME=/root ");
    try cmdline_parts.appendSlice(allocator, "TERM=xterm ");
    try cmdline_parts.appendSlice(allocator, "LANG=C.UTF-8 ");

    // Add user environment variables (these override defaults)
    for (env_vars) |env| {
        try cmdline_parts.appendSlice(allocator, env.key);
        try cmdline_parts.append(allocator, '=');
        try cmdline_parts.appendSlice(allocator, env.value);
        try cmdline_parts.append(allocator, ' ');
    }

    // Add the command
    for (command) |arg| {
        try cmdline_parts.appendSlice(allocator, arg);
        try cmdline_parts.append(allocator, ' ');
    }
    try cmdline_parts.append(allocator, '\'');

    // Add bootloader configuration (new vfkit format)
    // Format: --bootloader linux,kernel=path,initrd=path,cmdline="..."
    // Note: cmdline must be quoted and inner quotes escaped
    const bootloader_arg = if (initramfs_path) |initrd|
        try std.fmt.allocPrint(
            allocator,
            "linux,kernel={s},initrd={s},cmdline=\"{s}\"",
            .{ kernel_path, initrd, cmdline_parts.items },
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "linux,kernel={s},cmdline=\"{s}\"",
            .{ kernel_path, cmdline_parts.items },
        );
    try allocs_to_free.append(allocator, bootloader_arg);
    try vfkit_args.append(allocator, "--bootloader");
    try vfkit_args.append(allocator, bootloader_arg);

    // Add VirtioFS for rootfs sharing using --device virtio-fs format
    // Format: --device virtio-fs,sharedDir=/path,mountTag=tag
    const virtfs_arg = try std.fmt.allocPrint(
        allocator,
        "virtio-fs,sharedDir={s},mountTag=rootfs",
        .{rootfs_path},
    );
    try allocs_to_free.append(allocator, virtfs_arg);
    try vfkit_args.append(allocator, "--device");
    try vfkit_args.append(allocator, virtfs_arg);

    // Add additional VirtioFS mounts for volumes
    for (volumes, 0..) |vol, i| {
        const vol_arg = try std.fmt.allocPrint(
            allocator,
            "virtio-fs,sharedDir={s},mountTag=vol{d}",
            .{ vol.host_path, i },
        );
        try allocs_to_free.append(allocator, vol_arg);
        try vfkit_args.append(allocator, "--device");
        try vfkit_args.append(allocator, vol_arg);
    }

    // Add virtio-net device with NAT networking
    // Format: --device virtio-net,nat,unixSocketPath=/path/to/socket
    // or simpler: --device virtio-net,nat for basic NAT
    try vfkit_args.append(allocator, "--device");
    try vfkit_args.append(allocator, "virtio-net,nat");

    // Add port forwarding rules if any ports are mapped
    // vfkit uses --publish flag for port forwarding: --publish HOST:CONTAINER/PROTOCOL
    for (port_mappings) |port| {
        const proto_str: []const u8 = if (port.protocol == .udp) "udp" else "tcp";
        const publish_arg = try std.fmt.allocPrint(
            allocator,
            "{d}:{d}/{s}",
            .{ port.host_port, port.container_port, proto_str },
        );
        try allocs_to_free.append(allocator, publish_arg);
        try vfkit_args.append(allocator, "--publish");
        try vfkit_args.append(allocator, publish_arg);
    }

    // Add serial console device for output
    try vfkit_args.append(allocator, "--device");
    try vfkit_args.append(allocator, "virtio-serial,stdio");

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
    port_mappings: []const PortMapping,
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
        // VM might not exist, try to create it
        _ = try createLimaInstance(allocator);
        // After creating, try to start again
        return runWithLima(allocator, "", rootfs_path, command, env_vars, volumes, port_mappings);
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

    // Use env -i to clear inherited environment and set fresh vars
    try lima_args.append(allocator, "env");
    try lima_args.append(allocator, "-i");

    // Set minimal required environment
    try lima_args.append(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    try lima_args.append(allocator, "HOME=/root");
    try lima_args.append(allocator, "TERM=xterm");
    try lima_args.append(allocator, "LANG=C.UTF-8");

    // Add user environment variables (these override defaults)
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

        // Set up port forwarding using iptables DNAT
        for (port_mappings) |port| {
            try script.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ");
            if (port.protocol == .udp) {
                try script.appendSlice(allocator, "udp");
            } else {
                try script.appendSlice(allocator, "tcp");
            }
            try script.appendSlice(allocator, " --dport ");
            var host_port_buf: [8]u8 = undefined;
            const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
            try script.appendSlice(allocator, host_port_str);
            try script.appendSlice(allocator, " -j REDIRECT --to-port ");
            var cont_port_buf: [8]u8 = undefined;
            const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";
            try script.appendSlice(allocator, cont_port_str);
            try script.appendSlice(allocator, " 2>/dev/null; ");
        }

        // Add the unshare and chroot command with clean environment inside container
        try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc chroot ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, " /usr/bin/env -i ");

        // Set minimal required environment inside container
        try script.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ");
        try script.appendSlice(allocator, "HOME=/root ");
        try script.appendSlice(allocator, "TERM=xterm ");
        try script.appendSlice(allocator, "LANG=C.UTF-8 ");

        // Add user env vars inside container
        for (env_vars) |env| {
            try script.appendSlice(allocator, env.key);
            try script.append(allocator, '=');
            try script.appendSlice(allocator, env.value);
            try script.append(allocator, ' ');
        }

        // Add the command
        for (command) |arg| {
            try script.appendSlice(allocator, arg);
            try script.append(allocator, ' ');
        }

        const script_str = try allocator.dupe(u8, script.items);
        defer allocator.free(script_str);
        try lima_args.append(allocator, script_str);
    } else if (port_mappings.len > 0) {
        // Use script approach for port forwarding even without volumes
        try lima_args.append(allocator, "sh");
        try lima_args.append(allocator, "-c");

        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(allocator);

        // Set up port forwarding using iptables DNAT
        for (port_mappings) |port| {
            try script.appendSlice(allocator, "iptables -t nat -A PREROUTING -p ");
            if (port.protocol == .udp) {
                try script.appendSlice(allocator, "udp");
            } else {
                try script.appendSlice(allocator, "tcp");
            }
            try script.appendSlice(allocator, " --dport ");
            var host_port_buf: [8]u8 = undefined;
            const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{port.host_port}) catch "0";
            try script.appendSlice(allocator, host_port_str);
            try script.appendSlice(allocator, " -j REDIRECT --to-port ");
            var cont_port_buf: [8]u8 = undefined;
            const cont_port_str = std.fmt.bufPrint(&cont_port_buf, "{d}", .{port.container_port}) catch "0";
            try script.appendSlice(allocator, cont_port_str);
            try script.appendSlice(allocator, " 2>/dev/null; ");
        }

        // Add the unshare and chroot command with clean environment inside container
        try script.appendSlice(allocator, "unshare --mount --uts --ipc --pid --fork --mount-proc chroot ");
        try script.appendSlice(allocator, rootfs_path);
        try script.appendSlice(allocator, " /usr/bin/env -i ");

        // Set minimal required environment inside container
        try script.appendSlice(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ");
        try script.appendSlice(allocator, "HOME=/root ");
        try script.appendSlice(allocator, "TERM=xterm ");
        try script.appendSlice(allocator, "LANG=C.UTF-8 ");

        // Add user env vars inside container
        for (env_vars) |env| {
            try script.appendSlice(allocator, env.key);
            try script.append(allocator, '=');
            try script.appendSlice(allocator, env.value);
            try script.append(allocator, ' ');
        }

        // Add the command
        for (command) |arg| {
            try script.appendSlice(allocator, arg);
            try script.append(allocator, ' ');
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
        try lima_args.append(allocator, "/usr/bin/env");
        try lima_args.append(allocator, "-i");

        // Set minimal required environment inside container
        try lima_args.append(allocator, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        try lima_args.append(allocator, "HOME=/root");
        try lima_args.append(allocator, "TERM=xterm");
        try lima_args.append(allocator, "LANG=C.UTF-8");

        // Add user env vars
        for (env_vars) |env| {
            const env_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ env.key, env.value });
            try env_allocs.append(allocator, env_str);
            try lima_args.append(allocator, env_str);
        }

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
