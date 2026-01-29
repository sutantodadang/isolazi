//! Run Command Handler
//!
//! Shared run command parsing and execution logic used by all platforms.
//! Contains RunOptions struct and parsing helpers extracted from main.zig.

const std = @import("std");
const isolazi = @import("../../root.zig");

/// Parsed options for run command (used by all platforms)
pub const RunOptions = struct {
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
    restart_policy: isolazi.Config.RestartPolicy = .no,

    pub const EnvPair = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const VolumePair = struct {
        host_path: []const u8,
        container_path: []const u8,
        read_only: bool,
    };

    pub const PortMapping = struct {
        host_port: u16,
        container_port: u16,
        protocol: Protocol = .tcp,

        pub const Protocol = enum {
            tcp,
            udp,
        };
    };

    pub const IdMapping = struct {
        container_id: u32,
        host_id: u32,
        count: u32 = 1,
    };

    pub const SeccompProfileOption = enum {
        disabled,
        default_container,
        minimal,
        strict,
    };

    /// Free allocated resources
    pub fn deinit(self: RunOptions, allocator: std.mem.Allocator) void {
        if (self.env_vars.len > 0) allocator.free(self.env_vars);
        if (self.volumes.len > 0) allocator.free(self.volumes);
        if (self.ports.len > 0) allocator.free(self.ports);
        if (self.uid_maps.len > 0) allocator.free(self.uid_maps);
        if (self.gid_maps.len > 0) allocator.free(self.gid_maps);
        if (self.command_args.len > 0) allocator.free(self.command_args);
    }
};

/// Parse run command arguments (shared by all platforms)
pub fn parseRunOptions(allocator: std.mem.Allocator, args: []const []const u8) !RunOptions {
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

    var arg_idx: usize = 2; // Skip program name and "run"
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
        } else if (std.mem.eql(u8, arg, "--restart")) {
            arg_idx += 1;
            if (arg_idx >= args.len) return error.MissingValue;
            const policy_str = args[arg_idx];
            if (isolazi.Config.RestartPolicy.fromString(policy_str)) |policy| {
                opts.restart_policy = policy;
            } else {
                return error.InvalidRestartPolicy;
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
        } else if (arg.len > 0 and arg[0] == '-' and !image_found) {
            // Only check for flags BEFORE the image name is found
            // After image name, everything is command arguments (including shell -c args)
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

/// Parse volume mount specification (/host:/container[:ro])
pub fn parseVolume(s: []const u8) ?RunOptions.VolumePair {
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

/// Parse port mapping (host_port:container_port[/protocol])
pub fn parsePort(s: []const u8) ?RunOptions.PortMapping {
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
pub fn parseIdMap(s: []const u8) ?RunOptions.IdMapping {
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

/// Quote an argument for shell if it contains special characters
pub fn quoteArg(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, arg: []const u8) !void {
    const needs_quoting = for (arg) |c| {
        if (c == ' ' or c == '\t' or c == '"' or c == '\'' or c == '$' or c == '`' or c == '\\' or c == '!' or c == '*' or c == '?' or c == '[' or c == ']' or c == '(' or c == ')' or c == '{' or c == '}' or c == '<' or c == '>' or c == '|' or c == '&' or c == ';' or c == '\n') break true;
    } else false;

    if (needs_quoting) {
        try buf.append(alloc, '\'');
        for (arg) |c| {
            if (c == '\'') {
                // Escape single quote: ' -> '\''
                try buf.appendSlice(alloc, "'\\''");
            } else {
                try buf.append(alloc, c);
            }
        }
        try buf.append(alloc, '\'');
    } else {
        try buf.appendSlice(alloc, arg);
    }
    try buf.append(alloc, ' ');
}

/// Print usage information for run command
pub fn printUsage(stderr: anytype) void {
    stderr.writeAll("Error: Missing image name\n") catch {};
    stderr.writeAll("Usage: isolazi run [options] <image> [command...]\n") catch {};
    stderr.writeAll("\nOptions:\n") catch {};
    stderr.writeAll("  -d, --detach              Run in background\n") catch {};
    stderr.writeAll("  -e, --env KEY=VALUE       Set environment variable\n") catch {};
    stderr.writeAll("  -v, --volume SRC:DST[:ro] Mount a volume\n") catch {};
    stderr.writeAll("  -p, --port HOST:CONTAINER Publish port\n") catch {};
    stderr.writeAll("  --rootless                Run in rootless mode\n") catch {};
    stderr.writeAll("  --seccomp <profile>       Seccomp profile (disabled|default|minimal|strict)\n") catch {};
    stderr.writeAll("  --restart <policy>        Restart policy (no|always|on-failure|unless-stopped)\n") catch {};
    stderr.flush() catch {};
}
