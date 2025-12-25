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
    HostnameTooLong,
    InvalidEnvVar,
    InvalidVolumeMount,
};

/// Maximum number of environment variables
pub const MAX_ENV_VARS = 64;
/// Maximum number of volume mounts
pub const MAX_VOLUMES = 32;

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

    // Static arrays to store env vars and volumes (avoids allocation)
    var env_vars_buf: [MAX_ENV_VARS]EnvVar = undefined;
    var env_vars_count: usize = 0;
    var volumes_buf: [MAX_VOLUMES]VolumeMount = undefined;
    var volumes_count: usize = 0;

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
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
                // Detach mode is handled at the main.zig level, just skip here
                continue;
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

    // Store env vars and volumes in the command
    if (env_vars_count > 0) {
        run_cmd.env_vars = env_vars_buf[0..env_vars_count];
    }
    if (volumes_count > 0) {
        run_cmd.volumes = volumes_buf[0..volumes_count];
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

    // Use chroot instead of pivot_root if requested
    cfg.use_pivot_root = !run_cmd.use_chroot;

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
        \\    version                          Print version information
        \\    help                             Print this help message
        \\
        \\OPTIONS for 'run':
        \\    -d, --detach              Run container in background
        \\    -e, --env KEY=VALUE       Set environment variable (can be repeated)
        \\    -v, --volume SRC:DST[:ro] Mount a volume (can be repeated)
        \\    --hostname <name>         Set the container hostname
        \\    --cwd <path>              Set the working directory
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
        \\    isolazi create --name myapp alpine
        \\    isolazi start myapp
        \\    isolazi ps -a
        \\    isolazi stop myapp
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
        CliError.HostnameTooLong => "Hostname too long",
        CliError.InvalidEnvVar => "Invalid environment variable format (use KEY=VALUE)",
        CliError.InvalidVolumeMount => "Invalid volume mount format (use /host/path:/container/path[:ro])",
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
