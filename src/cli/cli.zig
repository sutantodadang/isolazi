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
pub const VERSION = "0.2.4";

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
    MissingContainerId,
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
    exec: ExecCommand,
    logs: LogsCommand,
    prune: PruneCommand,
    ps: PsCommand,
    start: StartCommand,
    stop: StopCommand,
    rm: RmCommand,
    inspect: InspectCommand,
    create: CreateCommand,
    build: BuildCommand,
    images: void,
    version: void,
    help: void,
};

/// Arguments for the 'run' command
pub const RunCommand = struct {
    rootfs: []const u8,
    command: ?[]const u8 = null, // Optional - uses image default CMD if not specified
    args: []const []const u8,
    hostname: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    use_chroot: bool = false, // Use chroot instead of pivot_root
    is_image: bool = false, // true if rootfs is an OCI image reference
    env_vars: []const EnvVar = &[_]EnvVar{},
    volumes: []const VolumeMount = &[_]VolumeMount{},
    ports: []const PortMap = &[_]PortMap{},
    detach: bool = false, // Run container in background
    restart_policy: config_mod.Config.RestartPolicy = .no, // Restart policy
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

    // Seccomp security options
    seccomp_enabled: bool = true, // Enable seccomp filtering (default: true)
    seccomp_profile: SeccompProfile = .default_container, // Seccomp profile

    // AppArmor Linux Security Module options
    apparmor_enabled: bool = false, // Enable AppArmor profile
    apparmor_profile: ?[]const u8 = null, // AppArmor profile name (null = default "isolazi-default")
    apparmor_mode: AppArmorMode = .enforce, // AppArmor enforcement mode

    // SELinux Linux Security Module options
    selinux_enabled: bool = false, // Enable SELinux context
    selinux_context: ?[]const u8 = null, // Custom SELinux context string
    selinux_type: SELinuxType = .container_t, // SELinux type for container process
    selinux_mcs_category1: ?u16 = null, // MCS category 1 for container isolation
    selinux_mcs_category2: ?u16 = null, // MCS category 2 for container isolation

    pub const SeccompProfile = enum {
        disabled, // No seccomp filtering
        default_container, // Default container profile - blocks dangerous syscalls
        minimal, // Minimal profile - only blocks most critical syscalls
        strict, // Strict allowlist profile - blocks everything except explicitly allowed
    };

    pub const AppArmorMode = enum {
        unconfined, // No AppArmor restrictions
        complain, // Log violations but don't block
        enforce, // Block violations (default)
    };

    pub const SELinuxType = enum {
        container_t, // Standard container (restricted)
        spc_t, // Super-privileged container
        unconfined_t, // Unconfined (no SELinux restrictions)
        custom, // Custom context string provided
    };
};

/// Arguments for the 'pull' command
pub const PullCommand = struct {
    image: []const u8,
};

/// Arguments for the 'exec' command
/// Execute a command in a running container using nsenter
pub const ExecCommand = struct {
    container_id: []const u8,
    command: []const u8,
    args: []const []const u8,
    env_vars: []const EnvVar = &[_]EnvVar{},
    cwd: ?[]const u8 = null,
    interactive: bool = true, // -i, allocate pseudo-TTY
    tty: bool = true, // -t, keep STDIN open
    detach: bool = false, // -d, run in background
    user: ?[]const u8 = null, // -u, user to run as
};

/// Arguments for the 'logs' command
/// Display container stdout/stderr logs
pub const LogsCommand = struct {
    container_id: []const u8,
    follow: bool = false, // -f, --follow: follow log output
    timestamps: bool = false, // --timestamps: show timestamps
    tail: usize = 0, // --tail N: show last N lines (0 = all)
    stdout_only: bool = false, // --stdout: show only stdout
    stderr_only: bool = false, // --stderr: show only stderr
};

/// Arguments for the 'prune' command
/// Remove unused resources (containers/images)
pub const PruneCommand = struct {
    force: bool = false, // -f, --force: remove all containers (including running)
};

/// Arguments for the 'ps' command
pub const PsCommand = struct {
    all: bool = false, // -a, --all: show all containers
};

/// Arguments for the 'start' command
pub const StartCommand = struct {
    container_id: []const u8,
};

/// Arguments for the 'stop' command
pub const StopCommand = struct {
    container_id: []const u8,
};

/// Arguments for the 'rm' command
pub const RmCommand = struct {
    container_id: []const u8,
    force: bool = false, // -f, --force: force removal
};

/// Arguments for the 'inspect' command
pub const InspectCommand = struct {
    container_id: []const u8,
};

/// Arguments for the 'create' command (placeholder for now)
pub const CreateCommand = struct {
    image: []const u8,
    command: []const u8,
    args: []const []const u8,
    // Add other fields from RunCommand as needed
};

/// Arguments for the 'build' command
pub const BuildCommand = struct {
    context_path: []const u8,
    file: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    build_args: []const BuildArg = &[_]BuildArg{},
    no_cache: bool = false,
    quiet: bool = false,

    pub const BuildArg = struct {
        name: []const u8,
        value: []const u8,
    };
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

    if (std.mem.eql(u8, cmd, "exec")) {
        return parseExecCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "logs")) {
        return parseLogsCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "prune")) {
        return parsePruneCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "ps")) {
        return parsePsCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "start")) {
        return parseStartCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "stop")) {
        return parseStopCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "rm")) {
        return parseRmCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "inspect")) {
        return parseInspectCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "create")) {
        return parseCreateCommand(args[2..]);
    }

    if (std.mem.eql(u8, cmd, "build")) {
        return parseBuildCommand(args[2..]);
    }

    return CliError.UnknownCommand;
}

/// Parse the 'run' subcommand arguments.
fn parseRunCommand(args: []const []const u8) CliError!Command {
    var run_cmd = RunCommand{
        .rootfs = undefined,
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

        // Only check for flags BEFORE the image name (positional_count == 0)
        // After image name, everything is command arguments (including shell -c args)
        if (arg.len > 0 and arg[0] == '-' and positional_count == 0) {
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
            } else if (std.mem.eql(u8, arg, "--no-seccomp") or std.mem.eql(u8, arg, "--disable-seccomp")) {
                // Disable seccomp filtering
                run_cmd.seccomp_enabled = false;
                run_cmd.seccomp_profile = .disabled;
            } else if (std.mem.eql(u8, arg, "--seccomp")) {
                // Seccomp profile: --seccomp <profile>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const profile_str = args[i];
                if (std.mem.eql(u8, profile_str, "disabled") or std.mem.eql(u8, profile_str, "none")) {
                    run_cmd.seccomp_enabled = false;
                    run_cmd.seccomp_profile = .disabled;
                } else if (std.mem.eql(u8, profile_str, "default") or std.mem.eql(u8, profile_str, "default-container")) {
                    run_cmd.seccomp_profile = .default_container;
                } else if (std.mem.eql(u8, profile_str, "minimal")) {
                    run_cmd.seccomp_profile = .minimal;
                } else if (std.mem.eql(u8, profile_str, "strict")) {
                    run_cmd.seccomp_profile = .strict;
                } else {
                    return CliError.InvalidArgument;
                }
            } else if (std.mem.eql(u8, arg, "--apparmor")) {
                // AppArmor profile: --apparmor <profile-name>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const profile_str = args[i];
                if (std.mem.eql(u8, profile_str, "unconfined") or std.mem.eql(u8, profile_str, "disabled") or std.mem.eql(u8, profile_str, "none")) {
                    run_cmd.apparmor_enabled = false;
                    run_cmd.apparmor_mode = .unconfined;
                } else {
                    run_cmd.apparmor_enabled = true;
                    run_cmd.apparmor_profile = profile_str;
                    run_cmd.apparmor_mode = .enforce;
                }
            } else if (std.mem.eql(u8, arg, "--apparmor-mode")) {
                // AppArmor mode: --apparmor-mode <enforce|complain|unconfined>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const mode_str = args[i];
                if (std.mem.eql(u8, mode_str, "enforce") or std.mem.eql(u8, mode_str, "enforcing")) {
                    run_cmd.apparmor_mode = .enforce;
                } else if (std.mem.eql(u8, mode_str, "complain") or std.mem.eql(u8, mode_str, "permissive")) {
                    run_cmd.apparmor_mode = .complain;
                } else if (std.mem.eql(u8, mode_str, "unconfined") or std.mem.eql(u8, mode_str, "disabled")) {
                    run_cmd.apparmor_enabled = false;
                    run_cmd.apparmor_mode = .unconfined;
                } else {
                    return CliError.InvalidArgument;
                }
            } else if (std.mem.eql(u8, arg, "--no-apparmor") or std.mem.eql(u8, arg, "--disable-apparmor")) {
                // Disable AppArmor
                run_cmd.apparmor_enabled = false;
                run_cmd.apparmor_mode = .unconfined;
            } else if (std.mem.eql(u8, arg, "--security-opt")) {
                // Docker-compatible security option: --security-opt <option>
                // Supports: apparmor=<profile>, label=type:<type>, label=disable
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const opt_str = args[i];
                if (std.mem.startsWith(u8, opt_str, "apparmor=")) {
                    const profile = opt_str[9..];
                    if (std.mem.eql(u8, profile, "unconfined")) {
                        run_cmd.apparmor_enabled = false;
                        run_cmd.apparmor_mode = .unconfined;
                    } else {
                        run_cmd.apparmor_enabled = true;
                        run_cmd.apparmor_profile = profile;
                    }
                } else if (std.mem.startsWith(u8, opt_str, "label=type:")) {
                    // SELinux type: label=type:<type>
                    const type_str = opt_str[11..];
                    run_cmd.selinux_enabled = true;
                    if (std.mem.eql(u8, type_str, "container_t")) {
                        run_cmd.selinux_type = .container_t;
                    } else if (std.mem.eql(u8, type_str, "spc_t")) {
                        run_cmd.selinux_type = .spc_t;
                    } else if (std.mem.eql(u8, type_str, "unconfined_t")) {
                        run_cmd.selinux_type = .unconfined_t;
                    } else {
                        // Custom context
                        run_cmd.selinux_type = .custom;
                        run_cmd.selinux_context = type_str;
                    }
                } else if (std.mem.eql(u8, opt_str, "label=disable") or std.mem.eql(u8, opt_str, "label:disable")) {
                    // Disable SELinux
                    run_cmd.selinux_enabled = false;
                    run_cmd.selinux_type = .unconfined_t;
                } else if (std.mem.startsWith(u8, opt_str, "label=")) {
                    // Generic label - treat as SELinux context
                    run_cmd.selinux_enabled = true;
                    run_cmd.selinux_context = opt_str[6..];
                    run_cmd.selinux_type = .custom;
                }
            } else if (std.mem.eql(u8, arg, "--selinux") or std.mem.eql(u8, arg, "--selinux-context")) {
                // SELinux context: --selinux <context>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const context_str = args[i];
                if (std.mem.eql(u8, context_str, "unconfined") or std.mem.eql(u8, context_str, "disabled") or std.mem.eql(u8, context_str, "none")) {
                    run_cmd.selinux_enabled = false;
                    run_cmd.selinux_type = .unconfined_t;
                } else {
                    run_cmd.selinux_enabled = true;
                    run_cmd.selinux_context = context_str;
                    run_cmd.selinux_type = .custom;
                }
            } else if (std.mem.eql(u8, arg, "--selinux-type")) {
                // SELinux type: --selinux-type <container_t|spc_t|unconfined_t>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const type_str = args[i];
                run_cmd.selinux_enabled = true;
                if (std.mem.eql(u8, type_str, "container_t") or std.mem.eql(u8, type_str, "container")) {
                    run_cmd.selinux_type = .container_t;
                } else if (std.mem.eql(u8, type_str, "spc_t") or std.mem.eql(u8, type_str, "super-privileged")) {
                    run_cmd.selinux_type = .spc_t;
                } else if (std.mem.eql(u8, type_str, "unconfined_t") or std.mem.eql(u8, type_str, "unconfined")) {
                    run_cmd.selinux_enabled = false;
                    run_cmd.selinux_type = .unconfined_t;
                } else {
                    return CliError.InvalidArgument;
                }
            } else if (std.mem.eql(u8, arg, "--selinux-mcs")) {
                // SELinux MCS categories: --selinux-mcs <c1>,<c2>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const mcs_str = args[i];
                // Parse "c1,c2" format
                var iter = std.mem.splitScalar(u8, mcs_str, ',');
                const cat1_str = iter.next() orelse return CliError.InvalidArgument;
                const cat2_str = iter.next() orelse cat1_str;
                run_cmd.selinux_enabled = true;
                run_cmd.selinux_mcs_category1 = std.fmt.parseInt(u16, cat1_str, 10) catch return CliError.InvalidArgument;
                run_cmd.selinux_mcs_category2 = std.fmt.parseInt(u16, cat2_str, 10) catch return CliError.InvalidArgument;
            } else if (std.mem.eql(u8, arg, "--no-selinux") or std.mem.eql(u8, arg, "--disable-selinux")) {
                // Disable SELinux
                run_cmd.selinux_enabled = false;
                run_cmd.selinux_type = .unconfined_t;
            } else if (std.mem.eql(u8, arg, "--privileged")) {
                // Privileged container: disable all security features
                run_cmd.seccomp_enabled = false;
                run_cmd.seccomp_profile = .disabled;
                run_cmd.apparmor_enabled = false;
                run_cmd.apparmor_mode = .unconfined;
                run_cmd.selinux_enabled = false;
                run_cmd.selinux_type = .unconfined_t;
            } else if (std.mem.eql(u8, arg, "--restart")) {
                // Restart policy: --restart <policy>
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                const policy_str = args[i];
                if (config_mod.Config.RestartPolicy.fromString(policy_str)) |policy| {
                    run_cmd.restart_policy = policy;
                } else {
                    return CliError.InvalidArgument;
                }
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
    // Command is now optional - images with default CMD/ENTRYPOINT don't need one

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

/// Parse the 'exec' subcommand arguments.
/// Usage: isolazi exec [options] <container-id> <command> [args...]
fn parseExecCommand(args: []const []const u8) CliError!Command {
    var exec_cmd = ExecCommand{
        .container_id = undefined,
        .command = undefined,
        .args = &[_][]const u8{},
    };

    // Static arrays to store env vars (avoids allocation)
    var env_vars_buf: [MAX_ENV_VARS]EnvVar = undefined;
    var env_vars_count: usize = 0;

    var i: usize = 0;
    var positional_count: usize = 0;
    var command_args_start: usize = 0;

    // Parse options and positional arguments
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (arg.len > 0 and arg[0] == '-') {
            // Option
            if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
                exec_cmd.interactive = true;
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tty")) {
                exec_cmd.tty = true;
            } else if (std.mem.eql(u8, arg, "-it")) {
                // Common Docker shorthand
                exec_cmd.interactive = true;
                exec_cmd.tty = true;
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
                exec_cmd.detach = true;
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                exec_cmd.user = args[i];
            } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--workdir")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                exec_cmd.cwd = args[i];
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
                // Environment variable: -e KEY=VALUE
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (env_vars_count >= MAX_ENV_VARS) return CliError.TooManyEnvVars;

                const env_str = args[i];
                const env_var = parseEnvVar(env_str) orelse return CliError.InvalidEnvVar;
                env_vars_buf[env_vars_count] = env_var;
                env_vars_count += 1;
            } else {
                return CliError.InvalidArgument;
            }
        } else {
            // Positional argument
            if (positional_count == 0) {
                exec_cmd.container_id = arg;
            } else if (positional_count == 1) {
                exec_cmd.command = arg;
                command_args_start = i;
            }
            positional_count += 1;
        }
    }

    // Store env vars in the command
    if (env_vars_count > 0) {
        exec_cmd.env_vars = env_vars_buf[0..env_vars_count];
    }

    if (positional_count < 1) {
        return CliError.MissingContainerId;
    }
    if (positional_count < 2) {
        return CliError.MissingCommand;
    }

    // Set command args (including the command itself as argv[0])
    if (command_args_start < args.len) {
        exec_cmd.args = args[command_args_start..];
    }

    return Command{ .exec = exec_cmd };
}

/// Parse the 'logs' subcommand arguments.
fn parseLogsCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) {
        return CliError.MissingContainerId;
    }

    var logs_cmd = LogsCommand{
        .container_id = undefined,
    };

    var i: usize = 0;
    var container_found = false;

    // Parse options and positional arguments
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (arg.len > 0 and arg[0] == '-') {
            // Option
            if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--follow")) {
                logs_cmd.follow = true;
            } else if (std.mem.eql(u8, arg, "--timestamps") or std.mem.eql(u8, arg, "-t")) {
                logs_cmd.timestamps = true;
            } else if (std.mem.eql(u8, arg, "--tail") or std.mem.eql(u8, arg, "-n")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                logs_cmd.tail = std.fmt.parseInt(usize, args[i], 10) catch return CliError.InvalidArgument;
            } else if (std.mem.eql(u8, arg, "--stdout")) {
                logs_cmd.stdout_only = true;
            } else if (std.mem.eql(u8, arg, "--stderr")) {
                logs_cmd.stderr_only = true;
            } else {
                return CliError.InvalidArgument;
            }
        } else {
            // Positional argument (container ID)
            if (!container_found) {
                logs_cmd.container_id = arg;
                container_found = true;
            }
        }
    }

    if (!container_found) {
        return CliError.MissingContainerId;
    }

    return Command{ .logs = logs_cmd };
}

/// Parse the 'prune' subcommand arguments.
fn parsePruneCommand(args: []const []const u8) CliError!Command {
    var prune_cmd = PruneCommand{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            prune_cmd.force = true;
        } else {
            return CliError.InvalidArgument;
        }
    }

    return Command{ .prune = prune_cmd };
}

fn parsePsCommand(args: []const []const u8) CliError!Command {
    var cmd = PsCommand{};
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            cmd.all = true;
        }
    }
    return Command{ .ps = cmd };
}

fn parseStartCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) return CliError.MissingContainerId;
    return Command{ .start = .{ .container_id = args[0] } };
}

fn parseStopCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) return CliError.MissingContainerId;
    return Command{ .stop = .{ .container_id = args[0] } };
}

fn parseRmCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) return CliError.MissingContainerId;
    var cmd = RmCommand{ .container_id = undefined };
    var found_id = false;

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            cmd.force = true;
        } else if (!found_id) {
            cmd.container_id = arg;
            found_id = true;
        }
    }
    if (!found_id) return CliError.MissingContainerId;
    return Command{ .rm = cmd };
}

fn parseInspectCommand(args: []const []const u8) CliError!Command {
    if (args.len < 1) return CliError.MissingContainerId;
    return Command{ .inspect = .{ .container_id = args[0] } };
}

fn parseCreateCommand(args: []const []const u8) CliError!Command {
    // Basic implementation for now
    if (args.len < 2) return CliError.MissingImage;
    return Command{ .create = .{
        .image = args[0],
        .command = args[1],
        .args = if (args.len > 2) args[2..] else &[_][]const u8{},
    } };
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
    if (run_cmd.command) |cmd| {
        try cfg.setCommand(cmd);
    }

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
        // Ensure host path exists (create directory if missing)
        if (std.fs.cwd().access(vol.host_path, .{})) |_| {} else |err| switch (err) {
            error.FileNotFound => std.fs.cwd().makePath(vol.host_path) catch return err,
            else => return err,
        }
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
        \\    exec <container> <command>       Execute a command in a running container
        \\    logs [-f] <container>            Display container logs
        \\    create [--name NAME] <image>     Create a container without starting
        \\    start <container>                Start a stopped container
        \\    stop <container>                 Stop a running container
        \\    rm [-f] <container>              Remove a container
        \\    ps [-a]                          List containers
        \\    inspect <container>              Display container details
        \\    pull <image>                     Pull an image from a registry
        \\    images                           List cached images
        \\    prune [-f]                       Remove stopped containers and unused images
        \\    update                           Update isolazi to the latest version
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
        \\    --restart <policy>        Restart policy (no|always|on-failure|unless-stopped)
        \\
        \\OPTIONS for 'exec':
        \\    -i, --interactive         Keep STDIN open
        \\    -t, --tty                 Allocate a pseudo-TTY
        \\    -d, --detach              Run command in background
        \\    -e, --env KEY=VALUE       Set environment variable
        \\    -u, --user <user>         Run as specified user (name or UID)
        \\    -w, --workdir <path>      Working directory inside the container
        \\
        \\OPTIONS for 'logs':
        \\    -f, --follow              Follow log output (stream new logs)
        \\    -n, --tail <N>            Number of lines to show from the end
        \\    -t, --timestamps          Show timestamps with each line
        \\    --stdout                  Show only stdout logs
        \\    --stderr                  Show only stderr logs
        \\OPTIONS for 'prune':
        \\    -f, --force               Remove all containers (including running)
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
        \\SECURITY OPTIONS:
        \\    --seccomp <profile>       Seccomp profile (default: default-container)
        \\                              Profiles: default, minimal, strict, disabled
        \\    --no-seccomp              Disable seccomp filtering (same as --seccomp disabled)
        \\
        \\    --apparmor <profile>      AppArmor profile name (default: isolazi-default)
        \\    --apparmor-mode <mode>    AppArmor mode: enforce, complain, unconfined
        \\    --no-apparmor             Disable AppArmor enforcement
        \\
        \\    --selinux <context>       SELinux security context (full context string)
        \\    --selinux-type <type>     SELinux type: container_t, spc_t, unconfined_t
        \\    --selinux-mcs <c1>,<c2>   SELinux MCS categories for isolation (e.g., 100,200)
        \\    --no-selinux              Disable SELinux enforcement
        \\
        \\    --security-opt <opt>      Docker-compatible security options:
        \\                              apparmor=<profile>, label=type:<type>, label=disable
        \\
        \\    --privileged              Disable all security features (seccomp, AppArmor, SELinux)
        \\
        \\    Seccomp Profiles:
        \\      default-container       Blocks dangerous syscalls (mount, ptrace, kexec, etc.)
        \\      minimal                 Only blocks critical syscalls (kexec, reboot, modules)
        \\      strict                  Allowlist mode - only basic syscalls permitted
        \\      disabled                No syscall filtering (less secure)
        \\
        \\    AppArmor Modes:
        \\      enforce                 Block and log policy violations (default)
        \\      complain                Log violations but don't block (for debugging)
        \\      unconfined              No AppArmor restrictions
        \\
        \\    SELinux Types:
        \\      container_t             Standard container process (restricted, default)
        \\      spc_t                   Super-privileged container (less restricted)
        \\      unconfined_t            No SELinux restrictions
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
        \\    isolazi run --seccomp minimal alpine /bin/sh
        \\    isolazi run --no-seccomp alpine /bin/sh     # Less secure, for debugging
        \\    isolazi run --apparmor isolazi-default alpine /bin/sh
        \\    isolazi run --apparmor myprofile --apparmor-mode complain alpine /bin/sh
        \\    isolazi run --selinux-type container_t --selinux-mcs 100,200 alpine /bin/sh
        \\    isolazi run --security-opt apparmor=isolazi-default alpine /bin/sh
        \\    isolazi run --privileged alpine /bin/sh     # Disables all security features
        \\    isolazi create --name myapp alpine
        \\    isolazi start myapp
        \\    isolazi ps -a
        \\    isolazi stop myapp
        \\    isolazi prune
        \\    isolazi prune -f
        \\    isolazi rm myapp
        \\    isolazi exec mycontainer /bin/sh
        \\    isolazi exec -it mycontainer /bin/bash
        \\    isolazi exec -e MY_VAR=value mycontainer env
        \\    isolazi logs mycontainer
        \\    isolazi logs -f mycontainer
        \\    isolazi logs --tail 100 mycontainer
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
        CliError.MissingContainerId => "Missing container ID or name",
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

/// Maximum number of build arguments
const MAX_BUILD_ARGS = 32;

/// Parse the 'build' subcommand arguments.
/// Usage: isolazi build [options] <context>
fn parseBuildCommand(args: []const []const u8) CliError!Command {
    var build_cmd = BuildCommand{
        .context_path = ".",
    };

    var build_args_buf: [MAX_BUILD_ARGS]BuildCommand.BuildArg = undefined;
    var build_args_count: usize = 0;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (arg.len > 0 and arg[0] == '-') {
            if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                build_cmd.file = args[i];
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tag")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                build_cmd.tag = args[i];
            } else if (std.mem.eql(u8, arg, "--build-arg")) {
                i += 1;
                if (i >= args.len) return CliError.InvalidArgument;
                if (build_args_count >= MAX_BUILD_ARGS) return CliError.InvalidArgument;
                const arg_str = args[i];
                if (std.mem.indexOf(u8, arg_str, "=")) |eq_pos| {
                    build_args_buf[build_args_count] = .{
                        .name = arg_str[0..eq_pos],
                        .value = arg_str[eq_pos + 1 ..],
                    };
                    build_args_count += 1;
                }
            } else if (std.mem.eql(u8, arg, "--no-cache")) {
                build_cmd.no_cache = true;
            } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
                build_cmd.quiet = true;
            } else {
                return CliError.InvalidArgument;
            }
        } else {
            // Positional argument = context path
            build_cmd.context_path = arg;
        }
    }

    if (build_args_count > 0) {
        build_cmd.build_args = build_args_buf[0..build_args_count];
    }

    return Command{ .build = build_cmd };
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
