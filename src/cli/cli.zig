//! Command-line interface for Isolazi container runtime.
//!
//! Provides argument parsing and command dispatch for:
//! - isolazi run <image|rootfs> <command> [args...]
//! - isolazi pull <image>
//! - isolazi images
//! - isolazi version
//! - isolazi help
//!
//! Design decisions:
//! - No external dependencies (pure Zig argument parsing)
//! - Minimal memory allocation (uses fixed buffers)
//! - Clear error messages for users
//! - Docker/Podman compatible image references

const std = @import("std");
const config_mod = @import("../config/mod.zig");
const runtime_mod = @import("../runtime/mod.zig");

const Config = config_mod.Config;

/// CLI version string
pub const VERSION = "0.1.0";

/// CLI error types
pub const CliError = error{
    NoCommand,
    UnknownCommand,
    MissingRootfs,
    MissingCommand,
    MissingImage,
    InvalidArgument,
    PathTooLong,
    TooManyArguments,
    TooManyEnvVars,
    TooManyMounts,
    TooManyPorts,
    HostnameTooLong,
    InvalidEnvVar,
    InvalidVolumeMount,
    InvalidPortMapping,
    InvalidMemoryLimit,
    InvalidCpuLimit,
    InvalidIoLimit,
    InvalidOomScoreAdj,
};

/// Maximum number of environment variables
pub const MAX_ENV_VARS = 64;
/// Maximum number of volume mounts
pub const MAX_VOLUMES = 32;
/// Maximum number of port mappings
pub const MAX_PORTS = 32;
/// Maximum number of UID/GID mappings
pub const MAX_ID_MAPPINGS = 8;

/// Environment variable
pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};

/// Volume mount
pub const VolumeMount = struct {
    host_path: []const u8,
    container_path: []const u8,
    read_only: bool = false,
};

/// Port mapping
pub const PortMap = struct {
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

    pub const Protocol = enum { tcp, udp };
};

/// UID/GID mapping for user namespaces
pub const IdMap = struct {
    container_id: u32,
    host_id: u32,
    count: u32 = 1,
};

/// Parsed command from CLI
pub const Command = union(enum) {
    run: RunCommand,
    pull: PullCommand,
    images: void,
    version: void,
    help: void,
};

/// Arguments for the 'run' command
pub const RunCommand = struct {
    rootfs: []const u8,
    command: []const u8,
    args: []const []const u8,
    hostname: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    use_chroot: bool = false, // Use chroot instead of pivot_root
    is_image: bool = false, // true if rootfs is an OCI image reference
    env_vars: []const EnvVar = &[_]EnvVar{},
    volumes: []const VolumeMount = &[_]VolumeMount{},
    ports: []const PortMap = &[_]PortMap{},
    detach: bool = false, // Run container in background
    rootless: bool = false, // Enable rootless mode (user namespace)
    uid_maps: []const IdMap = &[_]IdMap{}, // Custom UID mappings
    gid_maps: []const IdMap = &[_]IdMap{}, // Custom GID mappings

    // Resource limits
    memory_limit: ?[]const u8 = null, // e.g., "512m", "1g"
    memory_swap: ?[]const u8 = null, // Swap limit
    cpu_limit: ?[]const u8 = null, // e.g., "2", "0.5", "200%"
    cpu_quota: ?u64 = null, // CPU quota in microseconds
    cpu_period: ?u64 = null, // CPU period in microseconds
    cpu_weight: ?u32 = null, // CPU weight (1-10000)
    io_weight: ?u32 = null, // I/O weight (1-10000)
    oom_score_adj: ?i16 = null, // OOM score adjustment (-1000 to 1000)
    oom_kill_disable: bool = false, // Disable OOM killer
};

/// Arguments for the 'pull' command
pub const PullCommand = struct {
    image: []const u8,
};

/// Parse command-line arguments.
///
/// Expected format:
///   isolazi run [options] <image|rootfs> <command> [args...]
///   isolazi pull <image>
///   isolazi images
///   isolazi version
///   isolazi help
///
/// Options for 'run':
///   --hostname <name>    Set container hostname
///   --cwd <path>         Set working directory
///   --chroot             Use chroot instead of pivot_root
pub fn parse(args: []const []const u8) CliError!Command {
    if (args.len < 2) {
        return CliError.NoCommand;
    }

    // args[0] is the program name, args[1] is the command
    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
        return Command{ .version = {} };
    }

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        return Command{ .help = {} };
    }

    if (std.mem.eql(u8, cmd, "run")) {
        return parseRunCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "pull")) {
        return parsePullCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "images")) {
        return Command{ .images = {} };
    }

    return CliError.UnknownCommand;
}

/// Parse the 'run' subcommand arguments.
fn parseRunCommand(args: []const []const u8) CliError!Command {
    var run_cmd = RunCommand{
        .rootfs = undefined,
        .command = undefined,
        .args = &[_][]const u8{},
    };

    // Static arrays to store env vars, volumes, ports, and id maps (avoids allocation)
    var env_vars_buf: [MAX_ENV_VARS]EnvVar = undefined;
    var env_vars_count: usize = 0;
    var volumes_buf: [MAX_VOLUMES]VolumeMount = undefined;
    var volumes_count: usize = 0;
    var ports_buf: [MAX_PORTS]PortMap = undefined;
    var ports_count: usize = 0;
    var uid_maps_buf: [MAX_ID_MAPPINGS]IdMap = undefined;
    var uid_maps_count: usize = 0;
    var gid_maps_buf: [MAX_ID_MAPPINGS]IdMap = undefined;
    var gid_maps_count: usize = 0;

    var i: usize = 0;
    var positional_count: usize = 0;
    var command_args_start: usize = 0;

    // Parse options and positional arguments
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (arg.len > 0 and arg[0] == '-') {
            // Option
            if (std.mem.eql(u8, arg, "--hostname")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.hostname = args[i];
            } else if (std.mem.eql(u8, arg, "--cwd")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.cwd = args[i];
            } else if (std.mem.eql(u8, arg, "--chroot")) {
                run_cmd.use_chroot = true;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
                // Environment variable: -e KEY=VALUE
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (env_vars_count >= MAX_ENV_VARS) return CliError.TooManyEnvVars;

                const env_str = args[i];
                const env_var = parseEnvVar(env_str) orelse return CliError.InvalidEnvVar;
                env_vars_buf[env_vars_count] = env_var;
                env_vars_count += 1;
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--volume")) {
                // Volume mount: -v /host/path:/container/path[:ro]
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (volumes_count >= MAX_VOLUMES) return CliError.TooManyMounts;

                const vol_str = args[i];
                const volume = parseVolumeMount(vol_str) orelse return CliError.InvalidVolumeMount;
                volumes_buf[volumes_count] = volume;
                volumes_count += 1;
            } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "--publish")) {
                // Port mapping: -p host_port:container_port[/protocol]
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (ports_count >= MAX_PORTS) return CliError.TooManyPorts;

                const port_str = args[i];
                const port_map = parsePortMapping(port_str) orelse return CliError.InvalidPortMapping;
                ports_buf[ports_count] = port_map;
                ports_count += 1;
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
                // Detach mode
                run_cmd.detach = true;
            } else if (std.mem.eql(u8, arg, "--rootless") or std.mem.eql(u8, arg, "--userns")) {
                // Enable rootless mode (user namespace)
                run_cmd.rootless = true;
            } else if (std.mem.eql(u8, arg, "--uid-map") or std.mem.eql(u8, arg, "--uidmap")) {
                // UID mapping: --uid-map container:host:count
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (uid_maps_count >= MAX_ID_MAPPINGS) return CliError.InvalidArgument;

                const map_str = args[i];
                const uid_map = parseIdMap(map_str) orelse return CliError.InvalidArgument;
                uid_maps_buf[uid_maps_count] = uid_map;
                uid_maps_count += 1;
            } else if (std.mem.eql(u8, arg, "--gid-map") or std.mem.eql(u8, arg, "--gidmap")) {
                // GID mapping: --gid-map container:host:count
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (gid_maps_count >= MAX_ID_MAPPINGS) return CliError.InvalidArgument;

                const map_str = args[i];
                const gid_map = parseIdMap(map_str) orelse return CliError.InvalidArgument;
                gid_maps_buf[gid_maps_count] = gid_map;
                gid_maps_count += 1;
            } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--memory")) {
                // Memory limit: --memory 512m
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.memory_limit = args[i];
            } else if (std.mem.eql(u8, arg, "--memory-swap")) {
                // Memory swap limit: --memory-swap 1g
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.memory_swap = args[i];
            } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--cpus")) {
                // CPU limit: --cpus 2
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.cpu_limit = args[i];
            } else if (std.mem.eql(u8, arg, "--cpu-quota")) {
                // CPU quota: --cpu-quota 100000
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.cpu_quota = std.fmt.parseInt(u64, args[i], 10) catch return CliError.InvalidCpuLimit;
            } else if (std.mem.eql(u8, arg, "--cpu-period")) {
                // CPU period: --cpu-period 100000
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.cpu_period = std.fmt.parseInt(u64, args[i], 10) catch return CliError.InvalidCpuLimit;
            } else if (std.mem.eql(u8, arg, "--cpu-weight") or std.mem.eql(u8, arg, "--cpu-shares")) {
                // CPU weight: --cpu-weight 512
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.cpu_weight = std.fmt.parseInt(u32, args[i], 10) catch return CliError.InvalidCpuLimit;
            } else if (std.mem.eql(u8, arg, "--io-weight") or std.mem.eql(u8, arg, "--blkio-weight")) {
                // I/O weight: --io-weight 500
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                run_cmd.io_weight = std.fmt.parseInt(u32, args[i], 10) catch return CliError.InvalidIoLimit;
            } else if (std.mem.eql(u8, arg, "--oom-score-adj")) {
                // OOM score adjustment: --oom-score-adj -500
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const adj = std.fmt.parseInt(i16, args[i], 10) catch return CliError.InvalidOomScoreAdj;
                if (adj < -1000 or adj > 1000) return CliError.InvalidOomScoreAdj;
                run_cmd.oom_score_adj = adj;
            } else if (std.mem.eql(u8, arg, "--oom-kill-disable")) {
                // Disable OOM killer
                run_cmd.oom_kill_disable = true;
            } else {
                return CliError.InvalidArgument;
            }
        } else {
            // Positional argument
            if (positional_count == 0) {
                run_cmd.rootfs = arg;
                // Check if this looks like an OCI image reference
                run_cmd.is_image = isImageReference(arg);
            } else if (positional_count == 1) {
                run_cmd.command = arg;
                command_args_start = i;
            }
            positional_count += 1;
        }
    }

    // Store env vars, volumes, and ports in the command
    if (env_vars_count > 0) {
        run_cmd.env_vars = env_vars_buf[0..env_vars_count];
    }
    if (volumes_count > 0) {
        run_cmd.volumes = volumes_buf[0..volumes_count];
    }
    if (ports_count > 0) {
        run_cmd.ports = ports_buf[0..ports_count];
    }
    if (uid_maps_count > 0) {
        run_cmd.uid_maps = uid_maps_buf[0..uid_maps_count];
    }
    if (gid_maps_count > 0) {
        run_cmd.gid_maps = gid_maps_buf[0..gid_maps_count];
    }

    if (positional_count < 1) {
        return CliError.MissingRootfs;
    }
    if (positional_count < 2) {
        return CliError.MissingCommand;
    }

    // Set command args (including the command itself as argv[0])
    if (command_args_start < args.len) {
        run_cmd.args = args[command_args_start..];
    }

    return Command{ .run = run_cmd };
}

/// Parse a port mapping string "host_port:container_port[/protocol]"
fn parsePortMapping(s: []const u8) ?PortMap {
    // Check for protocol suffix
    var protocol: PortMap.Protocol = .tcp;
    var port_spec = s;

    if (std.mem.endsWith(u8, s, "/udp")) {
        protocol = .udp;
        port_spec = s[0 .. s.len - 4];
    } else if (std.mem.endsWith(u8, s, "/tcp")) {
        port_spec = s[0 .. s.len - 4];
    }

    // Parse host:container
    const colon_idx = std.mem.indexOf(u8, port_spec, ":") orelse return null;
    const host_str = port_spec[0..colon_idx];
    const container_str = port_spec[colon_idx + 1 ..];

    const host_port = std.fmt.parseInt(u16, host_str, 10) catch return null;
    const container_port = std.fmt.parseInt(u16, container_str, 10) catch return null;

    return PortMap{
        .host_port = host_port,
        .container_port = container_port,
        .protocol = protocol,
    };
}

/// Parse an ID mapping string "container:host[:count]"
fn parseIdMap(s: []const u8) ?IdMap {
    var iter = std.mem.splitScalar(u8, s, ':');

    const container_str = iter.next() orelse return null;
    const host_str = iter.next() orelse return null;
    const count_str = iter.next() orelse "1";

    const container_id = std.fmt.parseInt(u32, container_str, 10) catch return null;
    const host_id = std.fmt.parseInt(u32, host_str, 10) catch return null;
    const count = std.fmt.parseInt(u32, count_str, 10) catch return null;

    return IdMap{
        .container_id = container_id,
        .host_id = host_id,
        .count = count,
    };
}

/// Parse an environment variable string "KEY=VALUE"
fn parseEnvVar(s: []const u8) ?EnvVar {
    const eq_pos = std.mem.indexOf(u8, s, "=") orelse return null;
    if (eq_pos == 0) return null; // Empty key

    return EnvVar{
        .key = s[0..eq_pos],
        .value = s[eq_pos + 1 ..],
    };
}

/// Parse a volume mount string "/host/path:/container/path[:ro]"
fn parseVolumeMount(s: []const u8) ?VolumeMount {
    // Find the first colon (could be Windows drive letter)
    var colon_pos: usize = 0;

    // Handle Windows paths (C:\path)
    if (s.len >= 2 and s[1] == ':' and (s[0] >= 'A' and s[0] <= 'Z' or s[0] >= 'a' and s[0] <= 'z')) {
        // Windows path, skip first colon
        colon_pos = if (std.mem.indexOf(u8, s[2..], ":")) |pos| pos + 2 else return null;
    } else {
        colon_pos = std.mem.indexOf(u8, s, ":") orelse return null;
    }

    if (colon_pos == 0) return null; // Empty host path

    const host_path = s[0..colon_pos];
    const rest = s[colon_pos + 1 ..];

    // Check for read-only flag and container path
    var container_path: []const u8 = undefined;
    var read_only = false;

    if (std.mem.lastIndexOf(u8, rest, ":")) |last_colon| {
        const suffix = rest[last_colon + 1 ..];
        if (std.mem.eql(u8, suffix, "ro")) {
            read_only = true;
            container_path = rest[0..last_colon];
        } else if (std.mem.eql(u8, suffix, "rw")) {
            container_path = rest[0..last_colon];
        } else {
            // No valid suffix, use entire rest as container path
            container_path = rest;
        }
    } else {
        container_path = rest;
    }

    if (container_path.len == 0) return null;

    return VolumeMount{
        .host_path = host_path,
        .container_path = container_path,
        .read_only = read_only,
    };
}

/// Parse the 'pull' subcommand arguments.
fn parsePullCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) {
        return CliError.MissingImage;
    }

    return Command{ .pull = .{
        .image = args[0],
    } };
}

/// Check if a string looks like an OCI image reference rather than a file path.
/// Image references typically contain:
/// - A colon followed by a tag (e.g., alpine:3.18)
/// - A domain with dots (e.g., docker.io/library/alpine)
/// - Or no path separators at the start (e.g., alpine, ubuntu)
pub fn isImageReference(s: []const u8) bool {
    // If it starts with / or ./, it's a file path
    if (s.len > 0 and s[0] == '/') return false;
    if (s.len > 1 and s[0] == '.' and s[1] == '/') return false;

    // If it contains a colon (tag separator), likely an image
    if (std.mem.indexOf(u8, s, ":")) |_| return true;

    // If it contains a registry domain (has dots but not ../)
    if (std.mem.indexOf(u8, s, ".")) |dot_pos| {
        // Check if there's a slash after the dot (registry/repo format)
        if (std.mem.indexOf(u8, s[dot_pos..], "/")) |_| return true;
    }

    // If it's a simple name without path separators, treat as image
    // (e.g., "alpine", "ubuntu", "nginx")
    if (std.mem.indexOf(u8, s, "/") == null) {
        // Check if the directory exists - if not, treat as image
        std.fs.cwd().access(s, .{}) catch return true;
    }

    return false;
}

/// Build a Config from parsed CLI arguments.
pub fn buildConfig(run_cmd: *const RunCommand) !Config {
    var cfg = try Config.init(run_cmd.rootfs);

    // Set command
    try cfg.setCommand(run_cmd.command);

    // Set argv (including argv[0])
    for (run_cmd.args) |arg| {
        try cfg.addArg(arg);
    }

    // Set optional parameters
    if (run_cmd.hostname) |h| {
        try cfg.setHostname(h);
    }

    if (run_cmd.cwd) |c| {
        try cfg.setCwd(c);
    }

    // Copy environment variables
    for (run_cmd.env_vars) |env| {
        var buf: [4096]u8 = undefined;
        const env_str = std.fmt.bufPrint(&buf, "{s}={s}", .{ env.key, env.value }) catch continue;
        try cfg.addEnv(env_str);
    }

    // Copy volume mounts
    for (run_cmd.volumes) |vol| {
        try cfg.addMount(vol.host_path, vol.container_path, vol.read_only);
    }

    // Copy port mappings
    for (run_cmd.ports) |port| {
        const protocol: config_mod.PortMapping.Protocol = if (port.protocol == .tcp) .tcp else .udp;
        try cfg.addPort(port.host_port, port.container_port, protocol);
    }

    // Enable rootless mode if requested
    if (run_cmd.rootless) {
        cfg.enableRootless();
    }

    // Copy UID mappings
    for (run_cmd.uid_maps) |uid_map| {
        try cfg.addUidMapping(uid_map.host_id, uid_map.container_id, uid_map.count);
    }

    // Copy GID mappings
    for (run_cmd.gid_maps) |gid_map| {
        try cfg.addGidMapping(gid_map.host_id, gid_map.container_id, gid_map.count);
    }

    // If uid/gid maps provided but rootless not explicitly set, enable user namespace
    if (run_cmd.uid_maps.len > 0 or run_cmd.gid_maps.len > 0) {
        cfg.namespaces.user = true;
    }

    // Use chroot instead of pivot_root if requested
    cfg.use_pivot_root = !run_cmd.use_chroot;

    // Apply resource limits
    if (run_cmd.memory_limit) |mem| {
        cfg.setMemoryLimit(mem) catch return error.PathTooLong; // Reuse error type
    }

    if (run_cmd.memory_swap) |swap| {
        cfg.setSwapLimit(swap) catch return error.PathTooLong;
    }

    if (run_cmd.cpu_limit) |cpu| {
        cfg.setCpuLimit(cpu) catch return error.PathTooLong;
    }

    if (run_cmd.cpu_quota) |quota| {
        cfg.setCpuQuota(quota);
    }

    if (run_cmd.cpu_period) |period| {
        cfg.setCpuPeriod(period);
    }

    if (run_cmd.cpu_weight) |weight| {
        cfg.setCpuWeight(weight);
    }

    if (run_cmd.io_weight) |weight| {
        cfg.setIoWeight(weight);
    }

    if (run_cmd.oom_score_adj) |adj| {
        cfg.setOomScoreAdj(adj) catch {};
    }

    if (run_cmd.oom_kill_disable) {
        cfg.disableOomKiller();
    }

    return cfg;
}

/// Print help message.
pub fn printHelp(writer: anytype) !void {
    try writer.writeAll(
        \\Isolazi - Minimal Container Runtime
        \\
        \\USAGE:
        \\    isolazi <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    run [-d] <image> [command]       Run a command in a new container
        \\    create [--name NAME] <image>     Create a container without starting
        \\    start <container>                Start a stopped container
        \\    stop <container>                 Stop a running container
        \\    rm [-f] <container>              Remove a container
        \\    ps [-a]                          List containers
        \\    inspect <container>              Display container details
        \\    pull <image>                     Pull an image from a registry
        \\    images                           List cached images
        \\    prune                            Remove all stopped containers and unused images
        \\    version                          Print version information
        \\    help                             Print this help message
        \\
        \\OPTIONS for 'run':
        \\    -d, --detach              Run container in background
        \\    -e, --env KEY=VALUE       Set environment variable (can use comma: KEY1=V1,KEY2=V2)
        \\    -v, --volume SRC:DST[:ro] Mount a volume (can be repeated)
        \\    -p, --port HOST:CONTAINER Publish port (can be repeated)
        \\    --hostname <name>         Set the container hostname
        \\    --cwd <path>              Set the working directory
        \\    --rootless                Enable rootless mode (user namespace)
        \\    --uid-map C:H[:N]         Map container UID C to host UID H (N count, default 1)
        \\    --gid-map C:H[:N]         Map container GID C to host GID H (N count, default 1)
        \\
        \\RESOURCE LIMITS:
        \\    -m, --memory <limit>      Memory limit (e.g., 512m, 1g, 2048k)
        \\    --memory-swap <limit>     Swap limit (0 to disable, default: same as memory)
        \\    -c, --cpus <num>          Number of CPUs (e.g., 2, 0.5, 1.5)
        \\    --cpu-quota <usec>        CPU quota per period (microseconds)
        \\    --cpu-period <usec>       CPU period (default: 100000 = 100ms)
        \\    --cpu-weight <weight>     CPU weight for scheduling (1-10000, default: 100)
        \\    --io-weight <weight>      Block I/O weight (1-10000, default: 100)
        \\    --oom-score-adj <adj>     OOM score adjustment (-1000 to 1000)
        \\    --oom-kill-disable        Disable OOM killer (use with caution)
        \\
        \\OPTIONS for 'ps':
        \\    -a, --all            Show all containers (default: only running)
        \\
        \\OPTIONS for 'rm':
        \\    -f, --force          Force remove running container
        \\
        \\IMAGE REFERENCES:
        \\    alpine                          Short name (defaults to docker.io)
        \\    alpine:3.18                     With tag
        \\    docker.io/library/alpine:3.18  Full reference
        \\
        \\EXAMPLES:
        \\    isolazi pull alpine:3.18
        \\    isolazi run alpine /bin/sh
        \\    isolazi run -d alpine sleep 300
        \\    isolazi run -e DB_HOST=localhost -e DB_PORT=5432 postgres /bin/sh
        \\    isolazi run -v /data:/app/data -v /config:/etc/myapp:ro alpine /bin/sh
        \\    isolazi run postgres:16-alpine -d -p 5432:5432 -v /mydata:/var/lib/postgresql -e POSTGRES_PASSWORD=secret
        \\    isolazi run --rootless alpine /bin/sh
        \\    isolazi run --uid-map 0:1000:1 --gid-map 0:1000:1 alpine /bin/sh
        \\    isolazi run --memory 512m --cpus 2 alpine stress --vm 1 --vm-bytes 256M
        \\    isolazi run -m 1g --cpu-weight 200 --io-weight 500 alpine /bin/sh
        \\    isolazi create --name myapp alpine
        \\    isolazi start myapp
        \\    isolazi ps -a
        \\    isolazi stop myapp
        \\    isolazi prune
        \\    isolazi rm myapp
        \\
    );
}

/// Print version information.
pub fn printVersion(writer: anytype) !void {
    try writer.print("isolazi version {s}\n", .{VERSION});
}

/// Print an error message with usage hint.
pub fn printError(writer: anytype, err: CliError) !void {
    const msg = switch (err) {
        CliError.NoCommand => "No command specified",
        CliError.UnknownCommand => "Unknown command",
        CliError.MissingRootfs => "Missing image or rootfs path",
        CliError.MissingCommand => "Missing command to execute",
        CliError.MissingImage => "Missing image name",
        CliError.InvalidArgument => "Invalid argument",
        CliError.PathTooLong => "Path too long",
        CliError.TooManyArguments => "Too many arguments",
        CliError.TooManyEnvVars => "Too many environment variables (max 64)",
        CliError.TooManyMounts => "Too many bind mounts (max 32)",
        CliError.TooManyPorts => "Too many port mappings (max 32)",
        CliError.HostnameTooLong => "Hostname too long",
        CliError.InvalidEnvVar => "Invalid environment variable format (use KEY=VALUE)",
        CliError.InvalidVolumeMount => "Invalid volume mount format (use /host/path:/container/path[:ro])",
        CliError.InvalidPortMapping => "Invalid port mapping format (use HOST_PORT:CONTAINER_PORT[/tcp|udp])",
        CliError.InvalidMemoryLimit => "Invalid memory limit format (use e.g., 512m, 1g, 2048k)",
        CliError.InvalidCpuLimit => "Invalid CPU limit format (use e.g., 2, 0.5, 200% or microseconds)",
        CliError.InvalidIoLimit => "Invalid I/O limit format (use weight 1-10000)",
        CliError.InvalidOomScoreAdj => "Invalid OOM score adjustment (use -1000 to 1000)",
    };
    try writer.print("Error: {s}\n", .{msg});
    try writer.writeAll("Run 'isolazi help' for usage information.\n");
}

// =============================================================================
// Tests
// =============================================================================

test "parse version command" {
    const args = [_][]const u8{ "isolazi", "version" };
    const cmd = try parse(&args);
    try std.testing.expect(cmd == .version);
}

test "parse help command" {
    const args = [_][]const u8{ "isolazi", "help" };
    const cmd = try parse(&args);
    try std.testing.expect(cmd == .help);
}

test "parse run command" {
    const args = [_][]const u8{ "isolazi", "run", "/rootfs", "/bin/sh" };
    const cmd = try parse(&args);

    switch (cmd) {
        .run => |run_cmd| {
            try std.testing.expectEqualStrings("/rootfs", run_cmd.rootfs);
            try std.testing.expectEqualStrings("/bin/sh", run_cmd.command);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse run command with options" {
    const args = [_][]const u8{ "isolazi", "run", "--hostname", "test", "--cwd", "/app", "/rootfs", "/bin/sh" };
    const cmd = try parse(&args);

    switch (cmd) {
        .run => |run_cmd| {
            try std.testing.expectEqualStrings("/rootfs", run_cmd.rootfs);
            try std.testing.expectEqualStrings("/bin/sh", run_cmd.command);
            try std.testing.expectEqualStrings("test", run_cmd.hostname.?);
            try std.testing.expectEqualStrings("/app", run_cmd.cwd.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse pull command" {
    const args = [_][]const u8{ "isolazi", "pull", "alpine:3.18" };
    const cmd = try parse(&args);

    switch (cmd) {
        .pull => |pull_cmd| {
            try std.testing.expectEqualStrings("alpine:3.18", pull_cmd.image);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse images command" {
    const args = [_][]const u8{ "isolazi", "images" };
    const cmd = try parse(&args);
    try std.testing.expect(cmd == .images);
}

test "parse missing command returns error" {
    const args = [_][]const u8{"isolazi"};
    const result = parse(&args);
    try std.testing.expectError(CliError.NoCommand, result);
}

test "parse unknown command returns error" {
    const args = [_][]const u8{ "isolazi", "unknown" };
    const result = parse(&args);
    try std.testing.expectError(CliError.UnknownCommand, result);
}

test "isImageReference detects images" {
    // Image references
    try std.testing.expect(isImageReference("alpine:3.18"));
    try std.testing.expect(isImageReference("docker.io/library/alpine"));
    try std.testing.expect(isImageReference("ghcr.io/owner/repo:latest"));

    // File paths
    try std.testing.expect(!isImageReference("/path/to/rootfs"));
    try std.testing.expect(!isImageReference("./relative/path"));
}
