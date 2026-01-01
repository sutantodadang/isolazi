//! Network namespace and container networking support.
//!
//! This module provides network isolation and connectivity for containers:
//! - veth (virtual ethernet) pair creation
//! - Bridge device management (isolazi0)
//! - IP address assignment for containers
//! - NAT/masquerade for outbound connectivity
//! - Port forwarding (DNAT) for inbound connections
//!
//! Network topology:
//! ```
//!                     Host                          Container
//!              ┌─────────────────┐           ┌─────────────────┐
//!              │                 │           │                 │
//!   eth0 ──────┤   isolazi0      ├───vethXXX─┤   eth0          │
//!              │   172.20.0.1    │           │   172.20.0.X    │
//!              │   (bridge)      │           │                 │
//!              └─────────────────┘           └─────────────────┘
//!                     │
//!              iptables NAT
//!              (MASQUERADE)
//! ```
//!
//! SECURITY NOTES:
//! - Requires CAP_NET_ADMIN for network namespace operations
//! - iptables rules require root or CAP_NET_ADMIN
//! - Bridge mode allows container-to-container communication
//! - NAT hides container IPs behind host IP

const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");

/// Network configuration constants
pub const NetworkConfig = struct {
    /// Bridge device name for container networking
    pub const BRIDGE_NAME = "isolazi0";

    /// Bridge IP address (gateway for containers)
    pub const BRIDGE_IP = "172.20.0.1";

    /// Bridge subnet in CIDR notation
    pub const BRIDGE_CIDR = "172.20.0.1/24";

    /// Subnet for container IP allocation
    pub const CONTAINER_SUBNET = "172.20.0.0/24";

    /// Starting IP for container allocation (172.20.0.2)
    pub const CONTAINER_IP_START: u8 = 2;

    /// Maximum containers (172.20.0.254)
    pub const CONTAINER_IP_MAX: u8 = 254;

    /// Default MTU for veth devices
    pub const DEFAULT_MTU: u16 = 1500;
};

/// A port mapping from host to container.
pub const PortMapping = struct {
    /// Host port to listen on
    host_port: u16,
    /// Container port to forward to
    container_port: u16,
    /// Protocol (tcp/udp)
    protocol: Protocol = .tcp,

    pub const Protocol = enum {
        tcp,
        udp,
    };

    /// Parse a port mapping string like "8080:80" or "8080:80/udp"
    pub fn parse(spec: []const u8) !PortMapping {
        // Check for protocol suffix
        var protocol: Protocol = .tcp;
        var port_spec = spec;

        if (std.mem.endsWith(u8, spec, "/udp")) {
            protocol = .udp;
            port_spec = spec[0 .. spec.len - 4];
        } else if (std.mem.endsWith(u8, spec, "/tcp")) {
            port_spec = spec[0 .. spec.len - 4];
        }

        // Parse host:container
        const colon_idx = std.mem.indexOf(u8, port_spec, ":") orelse return error.InvalidPortMapping;
        const host_str = port_spec[0..colon_idx];
        const container_str = port_spec[colon_idx + 1 ..];

        const host_port = std.fmt.parseInt(u16, host_str, 10) catch return error.InvalidPortNumber;
        const container_port = std.fmt.parseInt(u16, container_str, 10) catch return error.InvalidPortNumber;

        return PortMapping{
            .host_port = host_port,
            .container_port = container_port,
            .protocol = protocol,
        };
    }
};

/// Container network configuration.
pub const ContainerNetwork = struct {
    /// Container IP address (e.g., "172.20.0.2")
    ip_address: [16]u8 = std.mem.zeroes([16]u8),
    ip_len: usize = 0,

    /// veth interface name on host side (e.g., "veth_abc123")
    veth_host: [16]u8 = std.mem.zeroes([16]u8),
    veth_host_len: usize = 0,

    /// veth interface name on container side (e.g., "eth0")
    veth_container: [16]u8 = std.mem.zeroes([16]u8),
    veth_container_len: usize = 0,

    /// Port mappings
    port_mappings: [32]PortMapping = undefined,
    port_count: usize = 0,

    /// Whether network is active
    active: bool = false,

    /// Container ID (used for generating unique veth names)
    container_id: [12]u8 = std.mem.zeroes([12]u8),

    pub fn init(container_id: []const u8, ip_suffix: u8) ContainerNetwork {
        var net = ContainerNetwork{};

        // Set container ID (first 12 chars)
        const id_len = @min(container_id.len, 12);
        @memcpy(net.container_id[0..id_len], container_id[0..id_len]);

        // Generate IP address (172.20.0.X)
        const ip = std.fmt.bufPrint(&net.ip_address, "172.20.0.{d}", .{ip_suffix}) catch unreachable;
        net.ip_len = ip.len;

        // Generate veth names
        const veth_host = std.fmt.bufPrint(&net.veth_host, "veth_{s}", .{net.container_id[0..6]}) catch unreachable;
        net.veth_host_len = veth_host.len;

        const veth_cont = std.fmt.bufPrint(&net.veth_container, "eth0", .{}) catch unreachable;
        net.veth_container_len = veth_cont.len;

        return net;
    }

    pub fn getIp(self: *const ContainerNetwork) []const u8 {
        return self.ip_address[0..self.ip_len];
    }

    pub fn getVethHost(self: *const ContainerNetwork) []const u8 {
        return self.veth_host[0..self.veth_host_len];
    }

    pub fn getVethContainer(self: *const ContainerNetwork) []const u8 {
        return self.veth_container[0..self.veth_container_len];
    }

    pub fn addPortMapping(self: *ContainerNetwork, mapping: PortMapping) !void {
        if (self.port_count >= 32) return error.TooManyPortMappings;
        self.port_mappings[self.port_count] = mapping;
        self.port_count += 1;
    }
};

/// Network setup error types.
pub const NetworkError = error{
    BridgeCreationFailed,
    VethCreationFailed,
    IpAssignmentFailed,
    InterfaceUpFailed,
    IptablesError,
    CommandFailed,
    InvalidPortMapping,
    InvalidPortNumber,
    TooManyPortMappings,
    OutOfMemory,
    Unexpected,
};

/// Network manager for container networking.
/// Uses ip/iptables commands for network configuration (simpler than raw netlink).
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    bridge_initialized: bool = false,

    pub fn init(allocator: std.mem.Allocator) NetworkManager {
        return NetworkManager{
            .allocator = allocator,
            .bridge_initialized = false,
        };
    }

    /// Initialize the host bridge device (isolazi0).
    /// This is idempotent - safe to call multiple times.
    pub fn initBridge(self: *NetworkManager) NetworkError!void {
        if (self.bridge_initialized) return;

        // Check if bridge already exists
        const check_result = runCommand(self.allocator, &.{
            "ip", "link", "show", NetworkConfig.BRIDGE_NAME,
        }) catch |err| {
            if (err == error.CommandFailed) {
                // Bridge doesn't exist, create it
                try self.createBridge();
            } else {
                return NetworkError.BridgeCreationFailed;
            }
            self.bridge_initialized = true;
            return;
        };

        // Bridge exists, ensure it's up
        _ = check_result;
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", NetworkConfig.BRIDGE_NAME, "up",
        }) catch {};

        self.bridge_initialized = true;
    }

    fn createBridge(self: *NetworkManager) NetworkError!void {
        // Create bridge device
        _ = runCommand(self.allocator, &.{
            "ip", "link", "add", "name", NetworkConfig.BRIDGE_NAME, "type", "bridge",
        }) catch return NetworkError.BridgeCreationFailed;

        // Assign IP address
        _ = runCommand(self.allocator, &.{
            "ip", "addr", "add", NetworkConfig.BRIDGE_CIDR, "dev", NetworkConfig.BRIDGE_NAME,
        }) catch {
            // IP might already exist, try to continue
        };

        // Bring up the bridge
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", NetworkConfig.BRIDGE_NAME, "up",
        }) catch return NetworkError.InterfaceUpFailed;

        // Enable IP forwarding
        _ = runCommand(self.allocator, &.{
            "sysctl", "-w", "net.ipv4.ip_forward=1",
        }) catch {
            // Not fatal, might already be enabled
        };

        // Setup NAT for outbound traffic
        try self.setupNat();
    }

    /// Setup NAT/masquerade for container outbound connectivity.
    fn setupNat(self: *NetworkManager) NetworkError!void {
        // Add MASQUERADE rule for container subnet
        // iptables -t nat -A POSTROUTING -s 172.20.0.0/24 ! -o isolazi0 -j MASQUERADE
        _ = runCommand(self.allocator, &.{
            "iptables",
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            NetworkConfig.CONTAINER_SUBNET,
            "!",
            "-o",
            NetworkConfig.BRIDGE_NAME,
            "-j",
            "MASQUERADE",
        }) catch {
            // Rule doesn't exist, add it
            _ = runCommand(self.allocator, &.{
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                NetworkConfig.CONTAINER_SUBNET,
                "!",
                "-o",
                NetworkConfig.BRIDGE_NAME,
                "-j",
                "MASQUERADE",
            }) catch return NetworkError.IptablesError;
        };

        // Allow forwarding from bridge
        _ = runCommand(self.allocator, &.{
            "iptables", "-A", "FORWARD", "-i", NetworkConfig.BRIDGE_NAME, "-j", "ACCEPT",
        }) catch {};
        _ = runCommand(self.allocator, &.{
            "iptables", "-A", "FORWARD", "-o", NetworkConfig.BRIDGE_NAME, "-j", "ACCEPT",
        }) catch {};
    }

    /// Create a veth pair for a container.
    /// Returns the container-side interface name to move into the namespace.
    pub fn createVethPair(self: *NetworkManager, net_config: *ContainerNetwork) NetworkError!void {
        const veth_host = net_config.getVethHost();
        _ = net_config.getVethContainer(); // Will be updated with peer name

        // Create veth pair: ip link add veth_xxx type veth peer name eth0
        var host_buf: [32]u8 = undefined;
        const host_name = std.fmt.bufPrint(&host_buf, "{s}", .{veth_host}) catch unreachable;

        var cont_buf: [32]u8 = undefined;
        const cont_name = std.fmt.bufPrint(&cont_buf, "veth_{s}_c", .{net_config.container_id[0..6]}) catch unreachable;

        _ = runCommand(self.allocator, &.{
            "ip", "link", "add", host_name, "type", "veth", "peer", "name", cont_name,
        }) catch return NetworkError.VethCreationFailed;

        // Attach host-side veth to bridge
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", host_name, "master", NetworkConfig.BRIDGE_NAME,
        }) catch return NetworkError.VethCreationFailed;

        // Bring up host-side veth
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", host_name, "up",
        }) catch return NetworkError.InterfaceUpFailed;

        // Store the peer name temporarily in veth_container for moving into namespace
        @memset(&net_config.veth_container, 0);
        @memcpy(net_config.veth_container[0..cont_name.len], cont_name);
        net_config.veth_container_len = cont_name.len;
        net_config.active = true;
    }

    /// Move the container-side veth into a network namespace.
    /// Must be called from the parent after the child has created its net namespace.
    pub fn moveVethToNamespace(self: *NetworkManager, net_config: *const ContainerNetwork, pid: i32) NetworkError!void {
        var pid_buf: [16]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch unreachable;

        const veth_peer = net_config.getVethContainer();

        // Move the peer veth into the container's network namespace
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", veth_peer, "netns", pid_str,
        }) catch return NetworkError.VethCreationFailed;
    }

    /// Configure networking inside the container namespace.
    /// This must be called from within the container's network namespace.
    pub fn configureContainerNetwork(self: *NetworkManager, net_config: *ContainerNetwork) NetworkError!void {
        // Rename the interface to eth0
        const veth_peer = net_config.getVethContainer();
        if (!std.mem.eql(u8, veth_peer, "eth0")) {
            _ = runCommand(self.allocator, &.{
                "ip", "link", "set", veth_peer, "name", "eth0",
            }) catch {};
        }

        // Assign IP address to container interface
        var ip_cidr_buf: [24]u8 = undefined;
        const ip_cidr = std.fmt.bufPrint(&ip_cidr_buf, "{s}/24", .{net_config.getIp()}) catch unreachable;

        _ = runCommand(self.allocator, &.{
            "ip", "addr", "add", ip_cidr, "dev", "eth0",
        }) catch return NetworkError.IpAssignmentFailed;

        // Bring up loopback
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", "lo", "up",
        }) catch {};

        // Bring up eth0
        _ = runCommand(self.allocator, &.{
            "ip", "link", "set", "eth0", "up",
        }) catch return NetworkError.InterfaceUpFailed;

        // Add default route via bridge gateway
        _ = runCommand(self.allocator, &.{
            "ip", "route", "add", "default", "via", NetworkConfig.BRIDGE_IP,
        }) catch {
            // Route might already exist
        };

        // Update veth_container to reflect the renamed interface
        @memset(&net_config.veth_container, 0);
        @memcpy(net_config.veth_container[0..4], "eth0");
        net_config.veth_container_len = 4;
    }

    /// Setup port forwarding rules for a container.
    pub fn setupPortForwarding(self: *NetworkManager, net_config: *const ContainerNetwork) NetworkError!void {
        const container_ip = net_config.getIp();

        for (net_config.port_mappings[0..net_config.port_count]) |mapping| {
            var host_port_buf: [8]u8 = undefined;
            const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{mapping.host_port}) catch unreachable;

            var dest_buf: [32]u8 = undefined;
            const dest_str = std.fmt.bufPrint(&dest_buf, "{s}:{d}", .{ container_ip, mapping.container_port }) catch unreachable;

            const proto = if (mapping.protocol == .tcp) "tcp" else "udp";

            // DNAT rule: iptables -t nat -A PREROUTING -p tcp --dport HOST_PORT -j DNAT --to-destination CONTAINER_IP:CONTAINER_PORT
            _ = runCommand(self.allocator, &.{
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                proto,
                "--dport",
                host_port_str,
                "-j",
                "DNAT",
                "--to-destination",
                dest_str,
            }) catch return NetworkError.IptablesError;

            // Also add OUTPUT rule for localhost access
            _ = runCommand(self.allocator, &.{
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                host_port_str,
                "-j",
                "DNAT",
                "--to-destination",
                dest_str,
            }) catch {};
        }
    }

    /// Cleanup network resources for a container.
    pub fn cleanup(self: *NetworkManager, net_config: *const ContainerNetwork) void {
        if (!net_config.active) return;

        const veth_host = net_config.getVethHost();
        const container_ip = net_config.getIp();

        // Remove host-side veth (this also removes the peer)
        _ = runCommand(self.allocator, &.{
            "ip", "link", "del", veth_host,
        }) catch {};

        // Remove port forwarding rules
        for (net_config.port_mappings[0..net_config.port_count]) |mapping| {
            var host_port_buf: [8]u8 = undefined;
            const host_port_str = std.fmt.bufPrint(&host_port_buf, "{d}", .{mapping.host_port}) catch unreachable;

            var dest_buf: [32]u8 = undefined;
            const dest_str = std.fmt.bufPrint(&dest_buf, "{s}:{d}", .{ container_ip, mapping.container_port }) catch unreachable;

            const proto = if (mapping.protocol == .tcp) "tcp" else "udp";

            _ = runCommand(self.allocator, &.{
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                proto,
                "--dport",
                host_port_str,
                "-j",
                "DNAT",
                "--to-destination",
                dest_str,
            }) catch {};

            _ = runCommand(self.allocator, &.{
                "iptables",
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                host_port_str,
                "-j",
                "DNAT",
                "--to-destination",
                dest_str,
            }) catch {};
        }
    }

    /// Cleanup the bridge device (call on daemon shutdown).
    pub fn cleanupBridge(self: *NetworkManager) void {
        // Remove NAT rules
        _ = runCommand(self.allocator, &.{
            "iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            NetworkConfig.CONTAINER_SUBNET,
            "!",
            "-o",
            NetworkConfig.BRIDGE_NAME,
            "-j",
            "MASQUERADE",
        }) catch {};

        // Remove forwarding rules
        _ = runCommand(self.allocator, &.{
            "iptables", "-D", "FORWARD", "-i", NetworkConfig.BRIDGE_NAME, "-j", "ACCEPT",
        }) catch {};
        _ = runCommand(self.allocator, &.{
            "iptables", "-D", "FORWARD", "-o", NetworkConfig.BRIDGE_NAME, "-j", "ACCEPT",
        }) catch {};

        // Delete bridge device
        _ = runCommand(self.allocator, &.{
            "ip", "link", "del", NetworkConfig.BRIDGE_NAME,
        }) catch {};

        self.bridge_initialized = false;
    }
};

/// Simple IP address allocator for containers.
/// Tracks which IPs in the 172.20.0.0/24 range are in use.
pub const IpAllocator = struct {
    /// Bitmap of used IPs (bit N = IP 172.20.0.N is used)
    /// Bit 0 = network address (unused)
    /// Bit 1 = gateway (172.20.0.1)
    /// Bits 2-254 = container IPs
    /// Bit 255 = broadcast (unused)
    used: [256]bool = [_]bool{false} ** 256,

    pub fn init() IpAllocator {
        var alloc = IpAllocator{};
        // Reserve network address, gateway, and broadcast
        alloc.used[0] = true; // Network address
        alloc.used[1] = true; // Gateway (172.20.0.1)
        alloc.used[255] = true; // Broadcast
        return alloc;
    }

    /// Allocate the next available IP address.
    /// Returns the last octet (e.g., 2 for 172.20.0.2).
    pub fn allocate(self: *IpAllocator) ?u8 {
        for (NetworkConfig.CONTAINER_IP_START..NetworkConfig.CONTAINER_IP_MAX + 1) |i| {
            if (!self.used[i]) {
                self.used[i] = true;
                return @intCast(i);
            }
        }
        return null; // No IPs available
    }

    /// Release an IP address back to the pool.
    pub fn release(self: *IpAllocator, ip_suffix: u8) void {
        if (ip_suffix >= NetworkConfig.CONTAINER_IP_START and ip_suffix <= NetworkConfig.CONTAINER_IP_MAX) {
            self.used[ip_suffix] = false;
        }
    }

    /// Format a full IP address from the suffix.
    pub fn formatIp(suffix: u8, buf: *[16]u8) []const u8 {
        return std.fmt.bufPrint(buf, "172.20.0.{d}", .{suffix}) catch unreachable;
    }
};

/// Run a command and wait for completion.
/// Returns stdout on success, error on failure.
fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) ![]const u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // Read stdout
    var stdout_list: std.ArrayList(u8) = .empty;
    defer stdout_list.deinit(allocator);

    if (child.stdout) |stdout_file| {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = stdout_file.read(&buf) catch break;
            if (n == 0) break;
            try stdout_list.appendSlice(allocator, buf[0..n]);
        }
    }

    const result = try child.wait();

    if (result.Exited != 0) {
        return error.CommandFailed;
    }

    return try stdout_list.toOwnedSlice(allocator);
}

// =============================================================================
// High-level API for container network setup
// =============================================================================

/// Full network setup for a container.
/// Call from parent process after fork, before child enters net namespace.
pub fn setupContainerNetworkHost(
    allocator: std.mem.Allocator,
    container_id: []const u8,
    port_mappings: []const PortMapping,
    child_pid: i32,
) !ContainerNetwork {
    var net_mgr = NetworkManager.init(allocator);

    // Ensure bridge exists
    try net_mgr.initBridge();

    // Allocate IP
    var ip_alloc = IpAllocator.init();
    const ip_suffix = ip_alloc.allocate() orelse return error.OutOfMemory;

    // Create network config
    var net_config = ContainerNetwork.init(container_id, ip_suffix);

    // Add port mappings
    for (port_mappings) |mapping| {
        try net_config.addPortMapping(mapping);
    }

    // Create veth pair
    try net_mgr.createVethPair(&net_config);

    // Move container-side veth to namespace
    try net_mgr.moveVethToNamespace(&net_config, child_pid);

    // Setup port forwarding
    if (net_config.port_count > 0) {
        try net_mgr.setupPortForwarding(&net_config);
    }

    return net_config;
}

/// Configure network inside container namespace.
/// Call from child process after entering net namespace.
pub fn setupContainerNetworkContainer(allocator: std.mem.Allocator, net_config: *ContainerNetwork) !void {
    var net_mgr = NetworkManager.init(allocator);
    try net_mgr.configureContainerNetwork(net_config);
}

// =============================================================================
// Tests
// =============================================================================

test "PortMapping.parse basic" {
    const mapping = try PortMapping.parse("8080:80");
    try std.testing.expectEqual(@as(u16, 8080), mapping.host_port);
    try std.testing.expectEqual(@as(u16, 80), mapping.container_port);
    try std.testing.expectEqual(PortMapping.Protocol.tcp, mapping.protocol);
}

test "PortMapping.parse with protocol" {
    const udp_mapping = try PortMapping.parse("5353:53/udp");
    try std.testing.expectEqual(@as(u16, 5353), udp_mapping.host_port);
    try std.testing.expectEqual(@as(u16, 53), udp_mapping.container_port);
    try std.testing.expectEqual(PortMapping.Protocol.udp, udp_mapping.protocol);
}

test "ContainerNetwork.init" {
    const net = ContainerNetwork.init("abc123def456", 5);
    try std.testing.expectEqualStrings("172.20.0.5", net.getIp());
    try std.testing.expect(std.mem.startsWith(u8, net.getVethHost(), "veth_"));
}

test "IpAllocator basic allocation" {
    var alloc = IpAllocator.init();
    const ip1 = alloc.allocate();
    try std.testing.expectEqual(@as(?u8, 2), ip1);

    const ip2 = alloc.allocate();
    try std.testing.expectEqual(@as(?u8, 3), ip2);

    // Release ip1 and reallocate
    alloc.release(2);
    const ip3 = alloc.allocate();
    try std.testing.expectEqual(@as(?u8, 2), ip3);
}
