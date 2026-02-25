//! Compose command implementation
//!
//! Orchestrates multiple containers defined in a docker-compose.yml file.
//! Uses a minimal YAML parser to read the configuration and delegates
//! container management to the standard `isolazi run` and `remove` logic.
//! Supports: up, down, ps, logs, stop, restart, pull, config subcommands.

const std = @import("std");
const isolazi = @import("isolazi");
const yaml = @import("../yaml.zig");

pub const ComposeError = error{
    FileNotFound,
    InvalidFormat,
    ServiceExecutionFailed,
    ServiceRemovalFailed,
    DependencyCycle,
} || yaml.YamlError || std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

const MAX_SERVICES = 64;
const MAX_ENV_VARS = 128;
const MAX_PORTS = 32;
const MAX_VOLUMES = 32;
const MAX_DEPENDS = 32;

const ServiceConfig = struct {
    name: []const u8,
    image: ?[]const u8 = null,
    command: ?[]const u8 = null,
    command_list: []const []const u8 = &.{},
    ports: []const []const u8 = &.{},
    volumes: []const []const u8 = &.{},
    environment: []const []const u8 = &.{}, // KEY=VALUE format
    env_file: []const []const u8 = &.{},
    depends_on: []const []const u8 = &.{},
    restart: ?[]const u8 = null,
    working_dir: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    container_name: ?[]const u8 = null,
    privileged: bool = false,
    mem_limit: ?[]const u8 = null,
    cpus: ?[]const u8 = null,
};

pub fn run(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const command = isolazi.cli.parse(args) catch |err| {
        try isolazi.cli.printError(stderr, err);
        return 1;
    };

    const compose_cmd = switch (command) {
        .compose => |cmd| cmd,
        else => return 1,
    };

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const project_name = std.fs.path.basename(cwd);

    // Operations that don't need the compose file
    switch (compose_cmd.op) {
        .ps => return composePsOp(allocator, project_name, stdout, stderr),
        .logs => return composeLogsOp(allocator, project_name, compose_cmd, stdout, stderr),
        .stop => return composeStopOp(allocator, project_name, stdout, stderr),
        .restart => return composeRestartOp(allocator, project_name, stdout, stderr),
        .down => return composeDownOp(allocator, project_name, stdout, stderr),
        else => {},
    }

    // Operations that need the compose file: up, pull, config
    const file_content = std.fs.cwd().readFileAlloc(allocator, compose_cmd.file, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) {
            try stderr.print("Error: Compose file '{s}' not found\n", .{compose_cmd.file});
        } else {
            try stderr.print("Error: Failed to read '{s}': {}\n", .{ compose_cmd.file, err });
        }
        try stderr.flush();
        return 1;
    };
    defer allocator.free(file_content);

    var parser = yaml.Parser.init(allocator, file_content);
    var root_val = parser.parse() catch |err| {
        try stderr.print("Error: Failed to parse YAML: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer root_val.deinit(allocator);

    const root_map = root_val.asMap() orelse {
        try stderr.writeAll("Error: Invalid Compose file format (root must be a map)\n");
        try stderr.flush();
        return 1;
    };

    const services_val = root_map.get("services") orelse {
        try stderr.writeAll("Error: No 'services' defined in Compose file\n");
        try stderr.flush();
        return 1;
    };
    const services_map = services_val.asMap() orelse {
        try stderr.writeAll("Error: 'services' must be a map\n");
        try stderr.flush();
        return 1;
    };

    switch (compose_cmd.op) {
        .up => return composeUp(allocator, project_name, services_map, compose_cmd.detach, stdout, stderr),
        .pull => return composePull(allocator, services_map, stdout, stderr),
        .config => return composeConfig(allocator, services_map, stdout, stderr),
        else => unreachable,
    }
}

// ---------------------------------------------------------------------------
// Service Config Parsing
// ---------------------------------------------------------------------------

fn parseServiceConfig(
    arena: std.mem.Allocator,
    name: []const u8,
    def_map: std.StringArrayHashMapUnmanaged(yaml.Value),
) !ServiceConfig {
    var cfg = ServiceConfig{ .name = name };

    // image
    if (def_map.get("image")) |v| cfg.image = v.asString();

    // command (string or list)
    if (def_map.get("command")) |c| {
        if (c.asString()) |s| {
            cfg.command = s;
        } else if (c.asList()) |l| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (l.items) |item| {
                if (item.asString()) |s| try list.append(arena, s);
            }
            cfg.command_list = try list.toOwnedSlice(arena);
        }
    }

    // ports
    if (def_map.get("ports")) |v| {
        if (v.asList()) |l| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (l.items) |item| {
                if (item.asString()) |s| {
                    try list.append(arena, s);
                } else {
                    // integer port like 8080 → "8080:8080"
                    if (item == .integer) {
                        const port_str = try std.fmt.allocPrint(arena, "{d}:{d}", .{ item.integer, item.integer });
                        try list.append(arena, port_str);
                    }
                }
            }
            cfg.ports = try list.toOwnedSlice(arena);
        }
    }

    // volumes
    if (def_map.get("volumes")) |v| {
        if (v.asList()) |l| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (l.items) |item| {
                if (item.asString()) |s| try list.append(arena, s);
            }
            cfg.volumes = try list.toOwnedSlice(arena);
        }
    }

    // environment (list of KEY=VALUE or map)
    if (def_map.get("environment")) |v| {
        cfg.environment = try parseEnvironment(arena, v);
    }

    // env_file (string or list)
    if (def_map.get("env_file")) |v| {
        if (v.asString()) |s| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            try list.append(arena, s);
            cfg.env_file = try list.toOwnedSlice(arena);
        } else if (v.asList()) |l| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (l.items) |item| {
                if (item.asString()) |s| try list.append(arena, s);
            }
            cfg.env_file = try list.toOwnedSlice(arena);
        }
    }

    // depends_on (list or map)
    if (def_map.get("depends_on")) |v| {
        if (v.asList()) |l| {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (l.items) |item| {
                if (item.asString()) |s| try list.append(arena, s);
            }
            cfg.depends_on = try list.toOwnedSlice(arena);
        } else if (v.asMap()) |m| {
            // map form: extract keys only
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            var it = m.iterator();
            while (it.next()) |entry| {
                try list.append(arena, entry.key_ptr.*);
            }
            cfg.depends_on = try list.toOwnedSlice(arena);
        }
    }

    // restart
    if (def_map.get("restart")) |v| cfg.restart = v.asString();

    // working_dir
    if (def_map.get("working_dir")) |v| cfg.working_dir = v.asString();

    // hostname
    if (def_map.get("hostname")) |v| cfg.hostname = v.asString();

    // container_name
    if (def_map.get("container_name")) |v| cfg.container_name = v.asString();

    // privileged
    if (def_map.get("privileged")) |v| {
        if (v == .boolean) cfg.privileged = v.boolean;
    }

    // mem_limit (top-level or deploy.resources.limits.memory)
    if (def_map.get("mem_limit")) |v| {
        cfg.mem_limit = v.asString();
    } else if (def_map.get("deploy")) |deploy| {
        if (deploy.asMap()) |dm| {
            if (dm.get("resources")) |res| {
                if (res.asMap()) |rm| {
                    if (rm.get("limits")) |lim| {
                        if (lim.asMap()) |lm| {
                            if (lm.get("memory")) |mem| cfg.mem_limit = mem.asString();
                            if (lm.get("cpus")) |c| {
                                if (c.asString()) |s| {
                                    cfg.cpus = s;
                                } else if (c == .float) {
                                    cfg.cpus = try std.fmt.allocPrint(arena, "{d}", .{c.float});
                                } else if (c == .integer) {
                                    cfg.cpus = try std.fmt.allocPrint(arena, "{d}", .{c.integer});
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // cpus (top-level shorthand)
    if (def_map.get("cpus")) |v| {
        if (v.asString()) |s| {
            cfg.cpus = s;
        } else if (v == .float) {
            cfg.cpus = try std.fmt.allocPrint(arena, "{d}", .{v.float});
        } else if (v == .integer) {
            cfg.cpus = try std.fmt.allocPrint(arena, "{d}", .{v.integer});
        }
    }

    return cfg;
}

fn parseEnvironment(arena: std.mem.Allocator, v: yaml.Value) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;

    if (v.asList()) |l| {
        // list form: ["KEY=VALUE", ...]
        for (l.items) |item| {
            if (item.asString()) |s| try list.append(arena, s);
        }
    } else if (v.asMap()) |m| {
        // map form: { KEY: VALUE, ... }
        var it = m.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const val = entry.value_ptr.*;
            const val_str = try yamlValueToString(arena, val);
            const env_str = try std.fmt.allocPrint(arena, "{s}={s}", .{ key, val_str });
            try list.append(arena, env_str);
        }
    }

    return try list.toOwnedSlice(arena);
}

fn yamlValueToString(arena: std.mem.Allocator, val: yaml.Value) ![]const u8 {
    return switch (val) {
        .string => |s| s,
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(arena, "{d}", .{f}),
        .boolean => |b| if (b) "true" else "false",
        .null_value => "",
        else => "",
    };
}

// ---------------------------------------------------------------------------
// Environment Variable Substitution
// ---------------------------------------------------------------------------

fn substituteEnvVars(arena: std.mem.Allocator, value: []const u8) ![]const u8 {
    // Fast path: no $ at all
    if (std.mem.indexOfScalar(u8, value, '$') == null) {
        return try arena.dupe(u8, value);
    }

    var result: std.ArrayListUnmanaged(u8) = .empty;
    var i: usize = 0;

    while (i < value.len) {
        if (value[i] == '$') {
            if (i + 1 < value.len and value[i + 1] == '{') {
                // ${VAR} or ${VAR:-default}
                const end = std.mem.indexOfScalarPos(u8, value, i + 2, '}') orelse {
                    try result.append(arena, value[i]);
                    i += 1;
                    continue;
                };
                const inner = value[i + 2 .. end];
                if (std.mem.indexOf(u8, inner, ":-")) |sep| {
                    const var_name = inner[0..sep];
                    const default_val = inner[sep + 2 ..];
                    const env_val = getEnvVar(arena, var_name) catch default_val;
                    try result.appendSlice(arena, env_val);
                } else {
                    const env_val = getEnvVar(arena, inner) catch "";
                    try result.appendSlice(arena, env_val);
                }
                i = end + 1;
            } else if (i + 1 < value.len and (std.ascii.isAlphabetic(value[i + 1]) or value[i + 1] == '_')) {
                // $VAR
                var end = i + 1;
                while (end < value.len and (std.ascii.isAlphanumeric(value[end]) or value[end] == '_')) {
                    end += 1;
                }
                const var_name = value[i + 1 .. end];
                const env_val = getEnvVar(arena, var_name) catch "";
                try result.appendSlice(arena, env_val);
                i = end;
            } else {
                try result.append(arena, value[i]);
                i += 1;
            }
        } else {
            try result.append(arena, value[i]);
            i += 1;
        }
    }

    return try result.toOwnedSlice(arena);
}

fn getEnvVar(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    return std.process.getEnvVarOwned(arena, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return err,
        else => return err,
    };
}

// ---------------------------------------------------------------------------
// .env file loading
// ---------------------------------------------------------------------------

fn loadEnvFile(arena: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    const content = std.fs.cwd().readFileAlloc(arena, path, 1024 * 1024) catch {
        return &.{};
    };

    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        // Must contain '=' to be a valid env line
        if (std.mem.indexOfScalar(u8, trimmed, '=') != null) {
            try list.append(arena, trimmed);
        }
    }
    return try list.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Topological Sort (Kahn's Algorithm)
// ---------------------------------------------------------------------------

fn topologicalSort(
    arena: std.mem.Allocator,
    services: []const ServiceConfig,
) ![]const []const u8 {
    const n = services.len;

    // Build name → index map
    var name_idx = std.StringHashMap(usize).init(arena);
    for (services, 0..) |svc, i| {
        try name_idx.put(svc.name, i);
    }

    // Build in-degree array and adjacency list
    var in_degree = try arena.alloc(usize, n);
    @memset(in_degree, 0);

    // adjacency: for each service, list of services that depend on it
    var adj = try arena.alloc(std.ArrayListUnmanaged(usize), n);
    for (adj) |*a| {
        a.* = .empty;
    }

    for (services, 0..) |svc, i| {
        for (svc.depends_on) |dep| {
            if (name_idx.get(dep)) |dep_idx| {
                try adj[dep_idx].append(arena, i);
                in_degree[i] += 1;
            }
        }
    }

    // Kahn's algorithm
    var queue: std.ArrayListUnmanaged(usize) = .empty;
    for (0..n) |i| {
        if (in_degree[i] == 0) try queue.append(arena, i);
    }

    var order: std.ArrayListUnmanaged([]const u8) = .empty;
    var processed: usize = 0;

    while (queue.items.len > 0) {
        const idx = queue.orderedRemove(0);
        try order.append(arena, services[idx].name);
        processed += 1;

        for (adj[idx].items) |neighbor| {
            in_degree[neighbor] -= 1;
            if (in_degree[neighbor] == 0) {
                try queue.append(arena, neighbor);
            }
        }
    }

    if (processed != n) {
        return error.DependencyCycle;
    }

    return try order.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// compose up
// ---------------------------------------------------------------------------

fn composeUp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    services_map: std.StringArrayHashMapUnmanaged(yaml.Value),
    detach: bool,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Parse all service configs
    var configs: std.ArrayListUnmanaged(ServiceConfig) = .empty;
    var it = services_map.iterator();
    while (it.next()) |entry| {
        const svc_name = entry.key_ptr.*;
        const svc_def = entry.value_ptr.*;
        const def_map = svc_def.asMap() orelse {
            try stderr.print("Warning: Skipping invalid service definition '{s}'\n", .{svc_name});
            try stderr.flush();
            continue;
        };
        const cfg = try parseServiceConfig(a, svc_name, def_map);
        try configs.append(a, cfg);
    }

    // Topological sort
    const start_order = topologicalSort(a, configs.items) catch |err| {
        if (err == error.DependencyCycle) {
            try stderr.writeAll("Error: Circular dependency detected in depends_on\n");
            try stderr.flush();
            return 1;
        }
        return err;
    };

    const self_exe = try std.fs.selfExePathAlloc(a);

    try stdout.print("Starting project '{s}'...\n", .{project_name});
    try stdout.flush();

    // Build config lookup by name
    var cfg_map = std.StringHashMap(ServiceConfig).init(a);
    for (configs.items) |cfg| {
        try cfg_map.put(cfg.name, cfg);
    }

    for (start_order) |svc_name| {
        const cfg = cfg_map.get(svc_name) orelse continue;

        if (cfg.image == null) {
            if (services_map.get(svc_name)) |sv| {
                if (sv.asMap()) |dm| {
                    if (dm.get("build")) |_| {
                        try stderr.print("Warning: Service '{s}' has 'build' but 'isolazi compose' only supports 'image' for now.\n", .{svc_name});
                        try stderr.flush();
                        return 1;
                    }
                }
            }
            try stderr.print("Error: Service '{s}' missing 'image' field\n", .{svc_name});
            try stderr.flush();
            return 1;
        }

        try stdout.print("Creating service '{s}'...\n", .{svc_name});
        try stdout.flush();

        // Build run args
        var run_args: std.ArrayListUnmanaged([]const u8) = .empty;
        try run_args.append(a, self_exe);
        try run_args.append(a, "run");

        // Always detach in compose
        try run_args.append(a, "-d");

        // Environment from env_file
        for (cfg.env_file) |ef| {
            const env_entries = try loadEnvFile(a, ef);
            for (env_entries) |entry| {
                const substituted = try substituteEnvVars(a, entry);
                try run_args.append(a, "-e");
                try run_args.append(a, substituted);
            }
        }

        // Environment variables
        for (cfg.environment) |env| {
            const substituted = try substituteEnvVars(a, env);
            try run_args.append(a, "-e");
            try run_args.append(a, substituted);
        }

        // Compose tracking env vars
        try run_args.append(a, "-e");
        try run_args.append(a, try std.fmt.allocPrint(a, "ISOLAZI_COMPOSE_PROJECT={s}", .{project_name}));
        try run_args.append(a, "-e");
        try run_args.append(a, try std.fmt.allocPrint(a, "ISOLAZI_COMPOSE_SERVICE={s}", .{svc_name}));

        // Ports
        for (cfg.ports) |port| {
            try run_args.append(a, "-p");
            try run_args.append(a, port);
        }

        // Volumes
        for (cfg.volumes) |vol| {
            try run_args.append(a, "-v");
            try run_args.append(a, vol);
        }

        // Hostname
        if (cfg.hostname) |h| {
            try run_args.append(a, "--hostname");
            try run_args.append(a, h);
        }

        // Working directory
        if (cfg.working_dir) |w| {
            try run_args.append(a, "--cwd");
            try run_args.append(a, w);
        }

        // Restart policy
        if (cfg.restart) |r| {
            try run_args.append(a, "--restart");
            try run_args.append(a, r);
        }

        // Memory limit
        if (cfg.mem_limit) |m| {
            try run_args.append(a, "-m");
            try run_args.append(a, m);
        }

        // CPU limit
        if (cfg.cpus) |c| {
            try run_args.append(a, "--cpus");
            try run_args.append(a, c);
        }

        // Privileged
        if (cfg.privileged) {
            try run_args.append(a, "--privileged");
        }

        // Image (positional arg)
        try run_args.append(a, cfg.image.?);

        // Command args
        if (cfg.command) |cmd| {
            var cmd_iter = std.mem.tokenizeScalar(u8, cmd, ' ');
            while (cmd_iter.next()) |part| {
                try run_args.append(a, part);
            }
        } else {
            for (cfg.command_list) |part| {
                try run_args.append(a, part);
            }
        }

        // Execute
        var child = std.process.Child.init(run_args.items, a);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        const term = child.spawnAndWait() catch |err| {
            try stderr.print("Error: Failed to spawn service '{s}': {}\n", .{ svc_name, err });
            try stderr.flush();
            return 1;
        };

        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    try stderr.print("Error: Service '{s}' failed with exit code {d}\n", .{ svc_name, code });
                    try stderr.flush();
                    return 1;
                }
            },
            else => {
                try stderr.print("Error: Service '{s}' terminated abnormally\n", .{svc_name});
                try stderr.flush();
                return 1;
            },
        }
    }

    try stdout.writeAll("Project started successfully.\n");
    if (!detach) {
        try stdout.writeAll("(Attached mode not yet implemented, containers are running in background)\n");
    }
    try stdout.flush();

    return 0;
}

// ---------------------------------------------------------------------------
// compose down — stop and remove all project containers
// ---------------------------------------------------------------------------

fn composeDownOp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    try stdout.print("Stopping project '{s}'...\n", .{project_name});
    try stdout.flush();

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error initializing container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(true) catch |err| {
        try stderr.print("Error listing containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(containers);

    var count: usize = 0;
    for (containers) |*info| {
        defer info.deinit();

        var is_project = false;
        var service_name: []const u8 = "unknown";

        for (info.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_PROJECT")) {
                if (std.mem.eql(u8, env.value, project_name)) is_project = true;
            }
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_SERVICE")) {
                service_name = env.value;
            }
        }

        if (is_project) {
            try stdout.print("Removing service '{s}' ({s})...\n", .{ service_name, info.shortId() });
            try stdout.flush();
            manager.removeContainer(&info.id, true) catch |err| {
                try stderr.print("Error removing container {s}: {}\n", .{ info.shortId(), err });
                try stderr.flush();
            };
            count += 1;
        }
    }

    try stdout.print("Removed {d} containers.\n", .{count});
    try stdout.flush();
    return 0;
}

// ---------------------------------------------------------------------------
// compose ps — list project containers
// ---------------------------------------------------------------------------

fn composePsOp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error initializing container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(true) catch |err| {
        try stderr.print("Error listing containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(containers);

    // Header
    try stdout.print("{s:<14} {s:<20} {s:<15} {s:<12} {s}\n", .{
        "CONTAINER ID", "SERVICE", "IMAGE", "STATUS", "PORTS",
    });
    try stdout.flush();

    for (containers) |*info| {
        defer info.deinit();

        var is_project = false;
        var service_name: []const u8 = "";

        for (info.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_PROJECT")) {
                if (std.mem.eql(u8, env.value, project_name)) is_project = true;
            }
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_SERVICE")) {
                service_name = env.value;
            }
        }

        if (is_project) {
            // Format ports
            var ports_buf: [256]u8 = undefined;
            var ports_len: usize = 0;
            for (info.ports, 0..) |p, pi| {
                if (pi > 0 and ports_len < ports_buf.len - 2) {
                    ports_buf[ports_len] = ',';
                    ports_buf[ports_len + 1] = ' ';
                    ports_len += 2;
                }
                const written = std.fmt.bufPrint(ports_buf[ports_len..], "{d}:{d}", .{ p.host_port, p.container_port }) catch break;
                ports_len += written.len;
            }
            const ports_str = ports_buf[0..ports_len];

            try stdout.print("{s:<14} {s:<20} {s:<15} {s:<12} {s}\n", .{
                info.shortId(),
                service_name,
                info.image,
                info.state.toString(),
                ports_str,
            });
            try stdout.flush();
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// compose logs — show logs for project containers
// ---------------------------------------------------------------------------

fn composeLogsOp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    compose_cmd: isolazi.cli.ComposeCommand,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = stdout;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error initializing container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(true) catch |err| {
        try stderr.print("Error listing containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(containers);

    const self_exe = try std.fs.selfExePathAlloc(a);

    var found = false;
    for (containers) |*info| {
        defer info.deinit();

        var is_project = false;
        for (info.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_PROJECT")) {
                if (std.mem.eql(u8, env.value, project_name)) is_project = true;
            }
        }

        if (is_project) {
            found = true;
            var log_args: std.ArrayListUnmanaged([]const u8) = .empty;
            try log_args.append(a, self_exe);
            try log_args.append(a, "logs");

            if (compose_cmd.follow) {
                try log_args.append(a, "-f");
            }
            if (compose_cmd.tail > 0) {
                try log_args.append(a, "--tail");
                try log_args.append(a, try std.fmt.allocPrint(a, "{d}", .{compose_cmd.tail}));
            }

            try log_args.append(a, info.shortId());

            var child = std.process.Child.init(log_args.items, a);
            child.stdin_behavior = .Inherit;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;

            const term = child.spawnAndWait() catch |err| {
                try stderr.print("Error: Failed to get logs: {}\n", .{err});
                try stderr.flush();
                continue;
            };
            _ = term;
        }
    }

    if (!found) {
        try stderr.print("No containers found for project '{s}'\n", .{project_name});
        try stderr.flush();
    }

    return 0;
}

// ---------------------------------------------------------------------------
// compose stop — stop all project containers
// ---------------------------------------------------------------------------

fn composeStopOp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error initializing container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(false) catch |err| {
        try stderr.print("Error listing containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(containers);

    const self_exe = try std.fs.selfExePathAlloc(a);

    var count: usize = 0;
    for (containers) |*info| {
        defer info.deinit();

        var is_project = false;
        var service_name: []const u8 = "unknown";

        for (info.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_PROJECT")) {
                if (std.mem.eql(u8, env.value, project_name)) is_project = true;
            }
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_SERVICE")) {
                service_name = env.value;
            }
        }

        if (is_project) {
            try stdout.print("Stopping service '{s}' ({s})...\n", .{ service_name, info.shortId() });
            try stdout.flush();

            var stop_args = [_][]const u8{ self_exe, "stop", info.shortId() };
            var child = std.process.Child.init(&stop_args, a);
            child.stdin_behavior = .Inherit;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;

            const term = child.spawnAndWait() catch |err| {
                try stderr.print("Error stopping container {s}: {}\n", .{ info.shortId(), err });
                try stderr.flush();
                continue;
            };
            _ = term;
            count += 1;
        }
    }

    try stdout.print("Stopped {d} containers.\n", .{count});
    try stdout.flush();
    return 0;
}

// ---------------------------------------------------------------------------
// compose restart — restart all project containers
// ---------------------------------------------------------------------------

fn composeRestartOp(
    allocator: std.mem.Allocator,
    project_name: []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Stop first, then start
    const stop_result = try composeStopOp(allocator, project_name, stdout, stderr);
    if (stop_result != 0) return stop_result;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var manager = isolazi.container.ContainerManager.init(allocator) catch |err| {
        try stderr.print("Error initializing container manager: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer manager.deinit();

    const containers = manager.listContainers(true) catch |err| {
        try stderr.print("Error listing containers: {}\n", .{err});
        try stderr.flush();
        return 1;
    };
    defer allocator.free(containers);

    const self_exe = try std.fs.selfExePathAlloc(a);

    var count: usize = 0;
    for (containers) |*info| {
        defer info.deinit();

        var is_project = false;
        var service_name: []const u8 = "unknown";

        for (info.env_vars) |env| {
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_PROJECT")) {
                if (std.mem.eql(u8, env.value, project_name)) is_project = true;
            }
            if (std.mem.eql(u8, env.key, "ISOLAZI_COMPOSE_SERVICE")) {
                service_name = env.value;
            }
        }

        if (is_project) {
            try stdout.print("Starting service '{s}' ({s})...\n", .{ service_name, info.shortId() });
            try stdout.flush();

            var start_args = [_][]const u8{ self_exe, "start", info.shortId() };
            var child = std.process.Child.init(&start_args, a);
            child.stdin_behavior = .Inherit;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;

            const term = child.spawnAndWait() catch |err| {
                try stderr.print("Error starting container {s}: {}\n", .{ info.shortId(), err });
                try stderr.flush();
                continue;
            };
            _ = term;
            count += 1;
        }
    }

    try stdout.print("Restarted {d} containers.\n", .{count});
    try stdout.flush();
    return 0;
}

// ---------------------------------------------------------------------------
// compose pull — pull images for all services
// ---------------------------------------------------------------------------

fn composePull(
    allocator: std.mem.Allocator,
    services_map: std.StringArrayHashMapUnmanaged(yaml.Value),
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const self_exe = try std.fs.selfExePathAlloc(a);

    var it = services_map.iterator();
    while (it.next()) |entry| {
        const svc_name = entry.key_ptr.*;
        const svc_def = entry.value_ptr.*;
        const def_map = svc_def.asMap() orelse continue;

        const image = if (def_map.get("image")) |v| v.asString() else null;
        if (image) |img| {
            try stdout.print("Pulling image for service '{s}': {s}\n", .{ svc_name, img });
            try stdout.flush();

            var pull_args = [_][]const u8{ self_exe, "pull", img };
            var child = std.process.Child.init(&pull_args, a);
            child.stdin_behavior = .Inherit;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;

            const term = child.spawnAndWait() catch |err| {
                try stderr.print("Error pulling image '{s}': {}\n", .{ img, err });
                try stderr.flush();
                continue;
            };

            switch (term) {
                .Exited => |code| {
                    if (code != 0) {
                        try stderr.print("Warning: Failed to pull '{s}' (exit code {d})\n", .{ img, code });
                        try stderr.flush();
                    }
                },
                else => {
                    try stderr.print("Warning: Pull for '{s}' terminated abnormally\n", .{img});
                    try stderr.flush();
                },
            }
        }
    }

    try stdout.writeAll("Pull complete.\n");
    try stdout.flush();
    return 0;
}

// ---------------------------------------------------------------------------
// compose config — validate and display the parsed compose file
// ---------------------------------------------------------------------------

fn composeConfig(
    allocator: std.mem.Allocator,
    services_map: std.StringArrayHashMapUnmanaged(yaml.Value),
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try stdout.writeAll("services:\n");

    var it = services_map.iterator();
    while (it.next()) |entry| {
        const svc_name = entry.key_ptr.*;
        const svc_def = entry.value_ptr.*;
        const def_map = svc_def.asMap() orelse {
            try stderr.print("Warning: Skipping invalid service '{s}'\n", .{svc_name});
            try stderr.flush();
            continue;
        };

        const cfg = parseServiceConfig(a, svc_name, def_map) catch |err| {
            try stderr.print("Error parsing service '{s}': {}\n", .{ svc_name, err });
            try stderr.flush();
            continue;
        };

        try stdout.print("  {s}:\n", .{cfg.name});
        if (cfg.image) |img| try stdout.print("    image: {s}\n", .{img});
        if (cfg.command) |cmd| try stdout.print("    command: {s}\n", .{cmd});
        if (cfg.command_list.len > 0) {
            try stdout.writeAll("    command:\n");
            for (cfg.command_list) |part| {
                try stdout.print("      - {s}\n", .{part});
            }
        }
        if (cfg.ports.len > 0) {
            try stdout.writeAll("    ports:\n");
            for (cfg.ports) |p| try stdout.print("      - \"{s}\"\n", .{p});
        }
        if (cfg.volumes.len > 0) {
            try stdout.writeAll("    volumes:\n");
            for (cfg.volumes) |v| try stdout.print("      - {s}\n", .{v});
        }
        if (cfg.environment.len > 0) {
            try stdout.writeAll("    environment:\n");
            for (cfg.environment) |e| try stdout.print("      - {s}\n", .{e});
        }
        if (cfg.depends_on.len > 0) {
            try stdout.writeAll("    depends_on:\n");
            for (cfg.depends_on) |d| try stdout.print("      - {s}\n", .{d});
        }
        if (cfg.restart) |r| try stdout.print("    restart: {s}\n", .{r});
        if (cfg.working_dir) |w| try stdout.print("    working_dir: {s}\n", .{w});
        if (cfg.hostname) |h| try stdout.print("    hostname: {s}\n", .{h});
        if (cfg.container_name) |cn| try stdout.print("    container_name: {s}\n", .{cn});
        if (cfg.privileged) try stdout.writeAll("    privileged: true\n");
        if (cfg.mem_limit) |m| try stdout.print("    mem_limit: {s}\n", .{m});
        if (cfg.cpus) |c| try stdout.print("    cpus: {s}\n", .{c});
    }

    try stdout.flush();
    return 0;
}
