//! Container configuration structures.
//!
//! Inspired by OCI Runtime Specification but simplified for initial implementation.
//! See: https://github.com/opencontainers/runtime-spec
//!
//! Design decisions:
//! - No heap allocations in Config struct itself
//! - Fixed-size buffers for paths (PATH_MAX = 4096)
//! - Explicit defaults for all optional fields
//! - Validation at construction time

const std = @import("std");

/// Maximum path length (Linux PATH_MAX)
pub const PATH_MAX = 4096;

/// Maximum hostname length (Linux HOST_NAME_MAX)
pub const HOSTNAME_MAX = 64;

/// Maximum number of arguments
pub const MAX_ARGS = 64;

/// Maximum number of environment variables
pub const MAX_ENV = 128;

/// Maximum number of bind mounts
pub const MAX_MOUNTS = 32;

/// Maximum number of port mappings
pub const MAX_PORTS = 32;

/// Maximum number of UID/GID mappings for user namespace
pub const MAX_ID_MAPPINGS = 8;

/// A UID/GID mapping entry for user namespaces
/// Maps a range of IDs from parent namespace to child namespace
pub const IdMapping = struct {
    /// First ID in the child (container) namespace
    container_id: u32 = 0,
    /// First ID in the parent (host) namespace
    host_id: u32 = 0,
    /// Number of consecutive IDs to map
    count: u32 = 1,
    /// Is this mapping active?
    active: bool = false,

    /// Create a simple 1:1 mapping
    pub fn single(host_id: u32, container_id: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = 1,
            .active = true,
        };
    }

    /// Create a range mapping
    pub fn range(host_id: u32, container_id: u32, count: u32) IdMapping {
        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
            .active = true,
        };
    }

    /// Parse a mapping string like "0:1000:1" (container:host:count)
    pub fn parse(spec: []const u8) !IdMapping {
        var iter = std.mem.splitScalar(u8, spec, ':');

        const container_str = iter.next() orelse return error.InvalidIdMapping;
        const host_str = iter.next() orelse return error.InvalidIdMapping;
        const count_str = iter.next() orelse "1";

        const container_id = std.fmt.parseInt(u32, container_str, 10) catch
            return error.InvalidIdMapping;
        const host_id = std.fmt.parseInt(u32, host_str, 10) catch
            return error.InvalidIdMapping;
        const count = std.fmt.parseInt(u32, count_str, 10) catch
            return error.InvalidIdMapping;

        return IdMapping{
            .container_id = container_id,
            .host_id = host_id,
            .count = count,
            .active = true,
        };
    }
};

/// A port mapping specification (host:container).
pub const PortMapping = struct {
    /// Host port to listen on
    host_port: u16 = 0,
    /// Container port to forward to
    container_port: u16 = 0,
    /// Protocol (tcp/udp)
    protocol: Protocol = .tcp,
    /// Is this mapping active?
    active: bool = false,

    pub const Protocol = enum(u8) {
        tcp = 0,
        udp = 1,
    };

    /// Create a port mapping.
    pub fn init(host_port: u16, container_port: u16, protocol: Protocol) PortMapping {
        return PortMapping{
            .host_port = host_port,
            .container_port = container_port,
            .protocol = protocol,
            .active = true,
        };
    }

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

        return PortMapping.init(host_port, container_port, protocol);
    }
};

/// Namespace configuration flags.
pub const Namespaces = packed struct {
    pid: bool = true,
    mount: bool = true,
    uts: bool = true,
    ipc: bool = true,
    network: bool = true, // Network namespace with veth/bridge
    user: bool = false, // Not implemented yet
    cgroup: bool = false, // Not implemented yet

    /// Return the combined clone flags for namespace creation.
    pub fn toCloneFlags(self: Namespaces) u64 {
        const linux = @import("../linux/mod.zig");
        var flags: u64 = 0;
        if (self.pid) flags |= linux.CloneFlags.NEWPID;
        if (self.mount) flags |= linux.CloneFlags.NEWNS;
        if (self.uts) flags |= linux.CloneFlags.NEWUTS;
        if (self.ipc) flags |= linux.CloneFlags.NEWIPC;
        if (self.network) flags |= linux.CloneFlags.NEWNET;
        if (self.user) flags |= linux.CloneFlags.NEWUSER;
        if (self.cgroup) flags |= linux.CloneFlags.NEWCGROUP;
        return flags;
    }

    /// Default configuration with PID, mount, UTS, and IPC namespaces.
    pub const default = Namespaces{};

    /// Minimal configuration (mount only, for testing).
    pub const minimal = Namespaces{
        .pid = false,
        .mount = true,
        .uts = false,
        .ipc = false,
    };
};

/// A bind mount specification.
pub const Mount = struct {
    /// Source path on the host (null-terminated)
    source: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),
    /// Destination path in the container (null-terminated)
    destination: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),
    /// Mount options
    readonly: bool = false,
    /// Is this mount configured?
    active: bool = false,

    /// Create a mount specification.
    pub fn init(source: []const u8, destination: []const u8, readonly: bool) !Mount {
        if (source.len >= PATH_MAX or destination.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        var m = Mount{
            .readonly = readonly,
            .active = true,
        };
        @memcpy(m.source[0..source.len], source);
        @memcpy(m.destination[0..destination.len], destination);
        return m;
    }

    /// Get source as a null-terminated slice.
    pub fn getSource(self: *const Mount) [*:0]const u8 {
        return &self.source;
    }

    /// Get destination as a null-terminated slice.
    pub fn getDestination(self: *const Mount) [*:0]const u8 {
        return &self.destination;
    }
};

/// Container configuration.
///
/// This struct contains all the information needed to create and run a container.
/// It uses fixed-size buffers to avoid heap allocation.
pub const Config = struct {
    /// Path to the root filesystem
    rootfs: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Working directory inside the container
    cwd: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Hostname for the container
    hostname: [HOSTNAME_MAX:0]u8 = std.mem.zeroes([HOSTNAME_MAX:0]u8),

    /// Command to execute (path to executable)
    command: [PATH_MAX:0]u8 = std.mem.zeroes([PATH_MAX:0]u8),

    /// Arguments to the command (including argv[0])
    /// Each argument is a null-terminated string stored contiguously
    args: [MAX_ARGS][PATH_MAX:0]u8 = undefined,
    args_count: usize = 0,

    /// Environment variables (KEY=VALUE format)
    env: [MAX_ENV][PATH_MAX:0]u8 = undefined,
    env_count: usize = 0,

    /// Bind mounts
    mounts: [MAX_MOUNTS]Mount = std.mem.zeroes([MAX_MOUNTS]Mount),
    mounts_count: usize = 0,

    /// Port mappings (host:container)
    port_mappings: [MAX_PORTS]PortMapping = std.mem.zeroes([MAX_PORTS]PortMapping),
    port_count: usize = 0,

    /// Namespace configuration
    namespaces: Namespaces = Namespaces.default,

    /// Use pivot_root instead of chroot (more secure)
    use_pivot_root: bool = true,

    /// User namespace configuration for rootless containers
    /// UID mappings (container_id:host_id:count format)
    uid_mappings: [MAX_ID_MAPPINGS]IdMapping = std.mem.zeroes([MAX_ID_MAPPINGS]IdMapping),
    uid_map_count: usize = 0,

    /// GID mappings (container_id:host_id:count format)
    gid_mappings: [MAX_ID_MAPPINGS]IdMapping = std.mem.zeroes([MAX_ID_MAPPINGS]IdMapping),
    gid_map_count: usize = 0,

    /// Enable rootless mode (user namespace with current user mapped to root)
    rootless: bool = false,

    /// Initialize a new configuration with the given rootfs path.
    pub fn init(rootfs: []const u8) !Config {
        if (rootfs.len >= PATH_MAX) {
            return error.PathTooLong;
        }

        var config = Config{};

        // Set rootfs
        @memcpy(config.rootfs[0..rootfs.len], rootfs);

        // Default cwd is "/"
        config.cwd[0] = '/';

        // Default hostname
        const default_hostname = "container";
        @memcpy(config.hostname[0..default_hostname.len], default_hostname);

        // Initialize args array
        config.args = std.mem.zeroes([MAX_ARGS][PATH_MAX:0]u8);

        // Initialize env array with basic environment
        config.env = std.mem.zeroes([MAX_ENV][PATH_MAX:0]u8);
        try config.addEnv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        try config.addEnv("TERM=xterm");

        return config;
    }

    /// Set the command to execute.
    pub fn setCommand(self: *Config, cmd: []const u8) !void {
        if (cmd.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.command, 0);
        @memcpy(self.command[0..cmd.len], cmd);
    }

    /// Add an argument.
    pub fn addArg(self: *Config, arg: []const u8) !void {
        if (self.args_count >= MAX_ARGS) {
            return error.TooManyArguments;
        }
        if (arg.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.args[self.args_count], 0);
        @memcpy(self.args[self.args_count][0..arg.len], arg);
        self.args_count += 1;
    }

    /// Add an environment variable (KEY=VALUE format).
    pub fn addEnv(self: *Config, env: []const u8) !void {
        if (self.env_count >= MAX_ENV) {
            return error.TooManyEnvVars;
        }
        if (env.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.env[self.env_count], 0);
        @memcpy(self.env[self.env_count][0..env.len], env);
        self.env_count += 1;
    }

    /// Add a bind mount.
    pub fn addMount(self: *Config, source: []const u8, destination: []const u8, readonly: bool) !void {
        if (self.mounts_count >= MAX_MOUNTS) {
            return error.TooManyMounts;
        }
        self.mounts[self.mounts_count] = try Mount.init(source, destination, readonly);
        self.mounts_count += 1;
    }

    /// Add a port mapping.
    pub fn addPort(self: *Config, host_port: u16, container_port: u16, protocol: PortMapping.Protocol) !void {
        if (self.port_count >= MAX_PORTS) {
            return error.TooManyPorts;
        }
        self.port_mappings[self.port_count] = PortMapping.init(host_port, container_port, protocol);
        self.port_count += 1;
    }

    /// Add a port mapping from a spec string like "8080:80" or "8080:80/udp".
    pub fn addPortFromSpec(self: *Config, spec: []const u8) !void {
        const mapping = try PortMapping.parse(spec);
        if (self.port_count >= MAX_PORTS) {
            return error.TooManyPorts;
        }
        self.port_mappings[self.port_count] = mapping;
        self.port_count += 1;
    }

    /// Add a UID mapping for user namespace.
    pub fn addUidMapping(self: *Config, host_id: u32, container_id: u32, count: u32) !void {
        if (self.uid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.uid_mappings[self.uid_map_count] = IdMapping.range(host_id, container_id, count);
        self.uid_map_count += 1;
    }

    /// Add a UID mapping from a spec string like "0:1000:1" (container:host:count).
    pub fn addUidMappingFromSpec(self: *Config, spec: []const u8) !void {
        if (self.uid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.uid_mappings[self.uid_map_count] = try IdMapping.parse(spec);
        self.uid_map_count += 1;
    }

    /// Add a GID mapping for user namespace.
    pub fn addGidMapping(self: *Config, host_id: u32, container_id: u32, count: u32) !void {
        if (self.gid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.gid_mappings[self.gid_map_count] = IdMapping.range(host_id, container_id, count);
        self.gid_map_count += 1;
    }

    /// Add a GID mapping from a spec string like "0:1000:1" (container:host:count).
    pub fn addGidMappingFromSpec(self: *Config, spec: []const u8) !void {
        if (self.gid_map_count >= MAX_ID_MAPPINGS) {
            return error.TooManyIdMappings;
        }
        self.gid_mappings[self.gid_map_count] = try IdMapping.parse(spec);
        self.gid_map_count += 1;
    }

    /// Enable rootless mode with default mappings (current user -> root in container).
    pub fn enableRootless(self: *Config) void {
        self.rootless = true;
        self.namespaces.user = true;
        // Default mapping: current user to root (0) inside container
        // The actual UID/GID will be determined at runtime
        self.uid_map_count = 0;
        self.gid_map_count = 0;
    }

    /// Get active UID mappings.
    pub fn getUidMappings(self: *const Config) []const IdMapping {
        return self.uid_mappings[0..self.uid_map_count];
    }

    /// Get active GID mappings.
    pub fn getGidMappings(self: *const Config) []const IdMapping {
        return self.gid_mappings[0..self.gid_map_count];
    }

    /// Set the hostname.
    pub fn setHostname(self: *Config, name: []const u8) !void {
        if (name.len >= HOSTNAME_MAX) {
            return error.HostnameTooLong;
        }
        @memset(&self.hostname, 0);
        @memcpy(self.hostname[0..name.len], name);
    }

    /// Set the working directory.
    pub fn setCwd(self: *Config, path: []const u8) !void {
        if (path.len >= PATH_MAX) {
            return error.PathTooLong;
        }
        @memset(&self.cwd, 0);
        @memcpy(self.cwd[0..path.len], path);
    }

    /// Get rootfs path as null-terminated pointer.
    pub fn getRootfs(self: *const Config) [*:0]const u8 {
        return &self.rootfs;
    }

    /// Get cwd as null-terminated pointer.
    pub fn getCwd(self: *const Config) [*:0]const u8 {
        return &self.cwd;
    }

    /// Get hostname as a slice.
    pub fn getHostname(self: *const Config) []const u8 {
        return std.mem.sliceTo(&self.hostname, 0);
    }

    /// Get command as null-terminated pointer.
    pub fn getCommand(self: *const Config) [*:0]const u8 {
        return &self.command;
    }

    /// Build argv array for execve.
    /// Returns array of pointers suitable for execve.
    /// The array is null-terminated.
    pub fn buildArgv(self: *const Config, buf: *[MAX_ARGS + 1]?[*:0]const u8) [*:null]const ?[*:0]const u8 {
        var i: usize = 0;
        while (i < self.args_count) : (i += 1) {
            buf[i] = &self.args[i];
        }
        buf[i] = null;
        return @ptrCast(buf);
    }

    /// Build envp array for execve.
    /// Returns array of pointers suitable for execve.
    /// The array is null-terminated.
    pub fn buildEnvp(self: *const Config, buf: *[MAX_ENV + 1]?[*:0]const u8) [*:null]const ?[*:0]const u8 {
        var i: usize = 0;
        while (i < self.env_count) : (i += 1) {
            buf[i] = &self.env[i];
        }
        buf[i] = null;
        return @ptrCast(buf);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Config initialization" {
    const testing = std.testing;
    const config = try Config.init("/tmp/rootfs");

    // Check rootfs was set
    const rootfs = std.mem.sliceTo(&config.rootfs, 0);
    try testing.expectEqualStrings("/tmp/rootfs", rootfs);

    // Check default cwd
    const cwd = std.mem.sliceTo(&config.cwd, 0);
    try testing.expectEqualStrings("/", cwd);

    // Check default hostname
    try testing.expectEqualStrings("container", config.getHostname());

    // Check default namespaces
    try testing.expect(config.namespaces.pid);
    try testing.expect(config.namespaces.mount);
    try testing.expect(config.namespaces.uts);
    try testing.expect(config.namespaces.ipc);
    try testing.expect(config.namespaces.network); // Network is now enabled by default
}

test "Config add arguments" {
    const testing = std.testing;
    var config = try Config.init("/tmp/rootfs");
    try config.setCommand("/bin/sh");
    try config.addArg("/bin/sh");
    try config.addArg("-c");
    try config.addArg("echo hello");

    try testing.expectEqual(@as(usize, 3), config.args_count);

    const arg0 = std.mem.sliceTo(&config.args[0], 0);
    try testing.expectEqualStrings("/bin/sh", arg0);

    const arg1 = std.mem.sliceTo(&config.args[1], 0);
    try testing.expectEqualStrings("-c", arg1);
}

test "Config add mount" {
    const testing = std.testing;
    var config = try Config.init("/tmp/rootfs");
    try config.addMount("/host/data", "/data", true);

    try testing.expectEqual(@as(usize, 1), config.mounts_count);
    try testing.expect(config.mounts[0].active);
    try testing.expect(config.mounts[0].readonly);

    const src = std.mem.sliceTo(&config.mounts[0].source, 0);
    try testing.expectEqualStrings("/host/data", src);
}

test "Namespaces toCloneFlags" {
    const ns = Namespaces.default;
    const flags = ns.toCloneFlags();
    try std.testing.expect(flags != 0);
}
