//! Container State Management
//!
//! Manages container lifecycle and state persistence.
//! Container states: created, running, stopped, removing

const std = @import("std");
const builtin = @import("builtin");
const config_mod = @import("../config/config.zig");

/// Container state enum
pub const ContainerState = enum {
    created,
    running,
    stopped,
    removing,

    pub fn toString(self: ContainerState) []const u8 {
        return switch (self) {
            .created => "created",
            .running => "running",
            .stopped => "stopped",
            .removing => "removing",
        };
    }

    pub fn fromString(s: []const u8) ?ContainerState {
        if (std.mem.eql(u8, s, "created")) return .created;
        if (std.mem.eql(u8, s, "running")) return .running;
        if (std.mem.eql(u8, s, "stopped")) return .stopped;
        if (std.mem.eql(u8, s, "removing")) return .removing;
        return null;
    }
};

/// Port mapping for container networking (persistent version for state.json)
pub const PortMapping = struct {
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

    pub const Protocol = enum {
        tcp,
        udp,

        pub fn toString(self: Protocol) []const u8 {
            return switch (self) {
                .tcp => "tcp",
                .udp => "udp",
            };
        }

        pub fn fromString(s: []const u8) Protocol {
            if (std.mem.eql(u8, s, "udp")) return .udp;
            return .tcp;
        }
    };
};

/// Volume mount for container (persistent version)
pub const VolumeMount = struct {
    host_path: []const u8,
    container_path: []const u8,
};

/// Environment variable pair (persistent version)
pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};

/// Container metadata stored on disk
pub const ContainerInfo = struct {
    id: [32]u8,
    image: []const u8,
    command: []const u8,
    state: ContainerState,
    created_at: i64,
    started_at: ?i64,
    finished_at: ?i64,
    pid: ?i32,
    exit_code: ?u8,
    name: ?[]const u8,

    restart_policy: config_mod.Config.RestartPolicy = .no,

    /// Working directory inside the container (from OCI config)
    workdir: []const u8 = "/",

    /// Persisted port mappings for container restart
    ports: []PortMapping = &[_]PortMapping{},
    /// Persisted volume mounts for container restart
    volumes: []VolumeMount = &[_]VolumeMount{},
    /// Persisted environment variables for container restart
    env_vars: []EnvVar = &[_]EnvVar{},

    allocator: std.mem.Allocator,

    pub fn deinit(self: *ContainerInfo) void {
        self.allocator.free(self.image);
        self.allocator.free(self.command);
        if (self.name) |n| self.allocator.free(n);
        if (!std.mem.eql(u8, self.workdir, "/")) self.allocator.free(self.workdir);
        // Free port mappings
        self.allocator.free(self.ports);
        // Free volume mounts (strings are slices into parsed JSON, freed with parse result)
        for (self.volumes) |v| {
            self.allocator.free(v.host_path);
            self.allocator.free(v.container_path);
        }
        self.allocator.free(self.volumes);
        // Free env vars
        for (self.env_vars) |e| {
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        }
        self.allocator.free(self.env_vars);
    }

    pub fn shortId(self: *const ContainerInfo) []const u8 {
        return self.id[0..12];
    }
};

/// Container state manager
pub const ContainerManager = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        // Get home directory
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => blk: {
                break :blk std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
                    return error.CacheNotInitialized;
                };
            },
            else => return error.CacheNotInitialized,
        };
        defer allocator.free(home);

        const base_path = try std.fmt.allocPrint(allocator, "{s}/.isolazi/containers", .{home});

        // Ensure directory exists
        std.fs.cwd().makePath(base_path) catch {};

        return Self{
            .allocator = allocator,
            .base_path = base_path,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.base_path);
    }

    /// Create a new container (does not start it)
    pub fn createContainer(
        self: *Self,
        image: []const u8,
        command: []const u8,
        name: ?[]const u8,
        restart_policy: config_mod.Config.RestartPolicy,
    ) ![32]u8 {

        // Generate container ID
        var container_id: [32]u8 = undefined;
        var id_buf: [16]u8 = undefined;
        std.crypto.random.bytes(&id_buf);
        const hex_chars = "0123456789abcdef";
        for (id_buf, 0..) |byte, i| {
            container_id[i * 2] = hex_chars[byte >> 4];
            container_id[i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        // Create container directory
        const container_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.base_path, container_id });
        defer self.allocator.free(container_dir);
        try std.fs.cwd().makePath(container_dir);

        // Write state file
        const state_path = try std.fmt.allocPrint(self.allocator, "{s}/state.json", .{container_dir});
        defer self.allocator.free(state_path);

        // Build name string
        var name_buf: [256]u8 = undefined;
        const name_str: []const u8 = if (name) |n|
            std.fmt.bufPrint(&name_buf, "\"{s}\"", .{n}) catch "null"
        else
            "null";

        var json_buf: [4096]u8 = undefined;
        const json = try std.fmt.bufPrint(&json_buf,
            \\{{
            \\  "id": "{s}",
            \\  "image": "{s}",
            \\  "command": "{s}",
            \\  "state": "created",
            \\  "created_at": {d},
            \\  "name": {s},
            \\  "restart_policy": "{s}"
            \\}}
        , .{
            container_id,
            image,
            command,
            std.time.timestamp(),
            name_str,
            restart_policy.toString(),
        });

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json);

        return container_id;
    }

    /// Create a new container with a pre-generated ID (does not start it)
    /// Now also persists ports, volumes, env_vars, and workdir for restart support
    pub fn createContainerWithId(
        self: *Self,
        container_id: *const [32]u8,
        image: []const u8,
        command: []const u8,
        name: ?[]const u8,
        restart_policy: config_mod.Config.RestartPolicy,
        ports: []const PortMapping,
        volumes: []const VolumeMount,
        env_vars: []const EnvVar,
        workdir: []const u8,
    ) !void {

        // Create container directory
        const container_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.base_path, container_id });
        defer self.allocator.free(container_dir);
        try std.fs.cwd().makePath(container_dir);

        // Write state file
        const state_path = try std.fmt.allocPrint(self.allocator, "{s}/state.json", .{container_dir});
        defer self.allocator.free(state_path);

        // Build JSON dynamically using ArrayList
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(self.allocator);

        try json.appendSlice(self.allocator, "{\n");
        try json.appendSlice(self.allocator, "  \"id\": \"");
        try json.appendSlice(self.allocator, container_id);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"image\": \"");
        try json.appendSlice(self.allocator, image);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"command\": \"");
        try json.appendSlice(self.allocator, command);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"state\": \"created\",\n");

        // created_at
        var time_buf: [32]u8 = undefined;
        const time_str = try std.fmt.bufPrint(&time_buf, "{d}", .{std.time.timestamp()});
        try json.appendSlice(self.allocator, "  \"created_at\": ");
        try json.appendSlice(self.allocator, time_str);
        try json.appendSlice(self.allocator, ",\n");

        // name
        try json.appendSlice(self.allocator, "  \"name\": ");
        if (name) |n| {
            try json.append(self.allocator, '"');
            try json.appendSlice(self.allocator, n);
            try json.append(self.allocator, '"');
        } else {
            try json.appendSlice(self.allocator, "null");
        }
        try json.appendSlice(self.allocator, ",\n");

        // restart_policy
        try json.appendSlice(self.allocator, "  \"restart_policy\": \"");
        try json.appendSlice(self.allocator, restart_policy.toString());
        try json.appendSlice(self.allocator, "\",\n");

        // workdir
        try json.appendSlice(self.allocator, "  \"workdir\": \"");
        try json.appendSlice(self.allocator, workdir);
        try json.appendSlice(self.allocator, "\",\n");

        // ports array
        try json.appendSlice(self.allocator, "  \"ports\": [");
        for (ports, 0..) |p, i| {
            if (i > 0) try json.append(self.allocator, ',');
            var port_buf: [128]u8 = undefined;
            const port_str = try std.fmt.bufPrint(&port_buf, "{{\"host_port\":{d},\"container_port\":{d},\"protocol\":\"{s}\"}}", .{ p.host_port, p.container_port, p.protocol.toString() });
            try json.appendSlice(self.allocator, port_str);
        }
        try json.appendSlice(self.allocator, "],\n");

        // volumes array
        try json.appendSlice(self.allocator, "  \"volumes\": [");
        for (volumes, 0..) |v, i| {
            if (i > 0) try json.append(self.allocator, ',');
            try json.appendSlice(self.allocator, "{\"host_path\":\"");
            try json.appendSlice(self.allocator, v.host_path);
            try json.appendSlice(self.allocator, "\",\"container_path\":\"");
            try json.appendSlice(self.allocator, v.container_path);
            try json.appendSlice(self.allocator, "\"}");
        }
        try json.appendSlice(self.allocator, "],\n");

        // env_vars array
        try json.appendSlice(self.allocator, "  \"env_vars\": [");
        for (env_vars, 0..) |e, i| {
            if (i > 0) try json.append(self.allocator, ',');
            try json.appendSlice(self.allocator, "{\"key\":\"");
            try json.appendSlice(self.allocator, e.key);
            try json.appendSlice(self.allocator, "\",\"value\":\"");
            try json.appendSlice(self.allocator, e.value);
            try json.appendSlice(self.allocator, "\"}");
        }
        try json.appendSlice(self.allocator, "]\n");

        try json.appendSlice(self.allocator, "}");

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json.items);
    }

    /// Update container state
    /// Preserves all existing fields (ports, volumes, env_vars) from the
    /// original state.json so that compose project tracking and restart
    /// metadata are not lost.
    pub fn updateState(
        self: *Self,
        container_id: []const u8,
        state: ContainerState,
        pid: ?i32,
        exit_code: ?u8,
    ) !void {
        const state_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/state.json",
            .{ self.base_path, container_id },
        );
        defer self.allocator.free(state_path);

        // Read existing state
        const existing = std.fs.cwd().readFileAlloc(self.allocator, state_path, 16384) catch {
            return error.ContainerNotFound;
        };
        defer self.allocator.free(existing);

        // Parse and update
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, existing, .{}) catch {
            return error.InvalidState;
        };
        defer parsed.deinit();

        const root = parsed.value.object;

        // Build updated JSON using dynamic buffer to accommodate ports/volumes/env_vars
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(self.allocator);

        const timestamp = std.time.timestamp();

        const id_str = root.get("id").?.string;
        const image_str = root.get("image").?.string;
        const cmd_str = root.get("command").?.string;
        const created_at = root.get("created_at").?.integer;
        const restart_policy_str = if (root.get("restart_policy")) |rp| rp.string else "no";
        const workdir_str = if (root.get("workdir")) |wd| wd.string else "/";

        try json.appendSlice(self.allocator, "{\n");
        try json.appendSlice(self.allocator, "  \"id\": \"");
        try json.appendSlice(self.allocator, id_str);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"image\": \"");
        try json.appendSlice(self.allocator, image_str);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"command\": \"");
        try json.appendSlice(self.allocator, cmd_str);
        try json.appendSlice(self.allocator, "\",\n");
        try json.appendSlice(self.allocator, "  \"state\": \"");
        try json.appendSlice(self.allocator, state.toString());
        try json.appendSlice(self.allocator, "\",\n");

        // created_at
        var time_buf: [32]u8 = undefined;
        const created_str = try std.fmt.bufPrint(&time_buf, "{d}", .{created_at});
        try json.appendSlice(self.allocator, "  \"created_at\": ");
        try json.appendSlice(self.allocator, created_str);
        try json.appendSlice(self.allocator, ",\n");

        // name
        try json.appendSlice(self.allocator, "  \"name\": ");
        if (root.get("name")) |n| {
            if (n == .string) {
                try json.append(self.allocator, '"');
                try json.appendSlice(self.allocator, n.string);
                try json.append(self.allocator, '"');
            } else {
                try json.appendSlice(self.allocator, "null");
            }
        } else {
            try json.appendSlice(self.allocator, "null");
        }
        try json.appendSlice(self.allocator, ",\n");

        // restart_policy
        try json.appendSlice(self.allocator, "  \"restart_policy\": \"");
        try json.appendSlice(self.allocator, restart_policy_str);
        try json.appendSlice(self.allocator, "\",\n");

        // workdir
        try json.appendSlice(self.allocator, "  \"workdir\": \"");
        try json.appendSlice(self.allocator, workdir_str);
        try json.appendSlice(self.allocator, "\"");

        // Timestamp fields
        switch (state) {
            .running => {
                var ts_buf: [32]u8 = undefined;
                const ts_str = try std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp});
                try json.appendSlice(self.allocator, ",\n  \"started_at\": ");
                try json.appendSlice(self.allocator, ts_str);
            },
            .stopped => {
                var ts_buf: [32]u8 = undefined;
                const ts_str = try std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp});
                try json.appendSlice(self.allocator, ",\n  \"finished_at\": ");
                try json.appendSlice(self.allocator, ts_str);
            },
            else => {},
        }

        // PID
        if (pid) |p| {
            var pid_buf: [32]u8 = undefined;
            const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{p});
            try json.appendSlice(self.allocator, ",\n  \"pid\": ");
            try json.appendSlice(self.allocator, pid_str);
        } else if (root.get("pid")) |existing_pid| {
            // Preserve existing PID if not overriding
            if (existing_pid == .integer) {
                var pid_buf: [32]u8 = undefined;
                const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{existing_pid.integer});
                try json.appendSlice(self.allocator, ",\n  \"pid\": ");
                try json.appendSlice(self.allocator, pid_str);
            }
        }

        // Exit code
        if (exit_code) |e| {
            var exit_buf: [32]u8 = undefined;
            const exit_str = try std.fmt.bufPrint(&exit_buf, "{d}", .{e});
            try json.appendSlice(self.allocator, ",\n  \"exit_code\": ");
            try json.appendSlice(self.allocator, exit_str);
        } else if (root.get("exit_code")) |existing_exit| {
            if (existing_exit == .integer) {
                var exit_buf: [32]u8 = undefined;
                const exit_str = try std.fmt.bufPrint(&exit_buf, "{d}", .{existing_exit.integer});
                try json.appendSlice(self.allocator, ",\n  \"exit_code\": ");
                try json.appendSlice(self.allocator, exit_str);
            }
        }

        // Preserve ports array
        if (root.get("ports")) |ports_val| {
            if (ports_val == .array) {
                try json.appendSlice(self.allocator, ",\n  \"ports\": [");
                for (ports_val.array.items, 0..) |item, i| {
                    if (i > 0) try json.append(self.allocator, ',');
                    const obj = item.object;
                    const hp: i64 = obj.get("host_port").?.integer;
                    const cp: i64 = obj.get("container_port").?.integer;
                    const proto = if (obj.get("protocol")) |p| p.string else "tcp";
                    var port_buf: [128]u8 = undefined;
                    const port_str = try std.fmt.bufPrint(&port_buf, "{{\"host_port\":{d},\"container_port\":{d},\"protocol\":\"{s}\"}}", .{ hp, cp, proto });
                    try json.appendSlice(self.allocator, port_str);
                }
                try json.append(self.allocator, ']');
            }
        }

        // Preserve volumes array
        if (root.get("volumes")) |vols_val| {
            if (vols_val == .array) {
                try json.appendSlice(self.allocator, ",\n  \"volumes\": [");
                for (vols_val.array.items, 0..) |item, i| {
                    if (i > 0) try json.append(self.allocator, ',');
                    const obj = item.object;
                    try json.appendSlice(self.allocator, "{\"host_path\":\"");
                    try json.appendSlice(self.allocator, obj.get("host_path").?.string);
                    try json.appendSlice(self.allocator, "\",\"container_path\":\"");
                    try json.appendSlice(self.allocator, obj.get("container_path").?.string);
                    try json.appendSlice(self.allocator, "\"}");
                }
                try json.append(self.allocator, ']');
            }
        }

        // Preserve env_vars array
        if (root.get("env_vars")) |envs_val| {
            if (envs_val == .array) {
                try json.appendSlice(self.allocator, ",\n  \"env_vars\": [");
                for (envs_val.array.items, 0..) |item, i| {
                    if (i > 0) try json.append(self.allocator, ',');
                    const obj = item.object;
                    try json.appendSlice(self.allocator, "{\"key\":\"");
                    try json.appendSlice(self.allocator, obj.get("key").?.string);
                    try json.appendSlice(self.allocator, "\",\"value\":\"");
                    try json.appendSlice(self.allocator, obj.get("value").?.string);
                    try json.appendSlice(self.allocator, "\"}");
                }
                try json.append(self.allocator, ']');
            }
        }

        try json.appendSlice(self.allocator, "\n}");

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json.items);
    }

    /// Get container info
    pub fn getContainer(self: *Self, container_id: []const u8) !ContainerInfo {
        const state_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/state.json",
            .{ self.base_path, container_id },
        );
        defer self.allocator.free(state_path);

        const data = std.fs.cwd().readFileAlloc(self.allocator, state_path, 8192) catch {
            return error.ContainerNotFound;
        };
        defer self.allocator.free(data);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch {
            return error.InvalidState;
        };
        defer parsed.deinit();

        const root = parsed.value.object;

        var id: [32]u8 = undefined;
        const id_str = root.get("id").?.string;
        @memcpy(&id, id_str[0..32]);

        const image_val = root.get("image").?.string;
        const cmd_val = root.get("command").?.string;
        var container_state = ContainerState.fromString(root.get("state").?.string) orelse .created;
        const restart_policy = if (root.get("restart_policy")) |rp| config_mod.Config.RestartPolicy.fromString(rp.string) orelse .no else .no;
        const pid_val = if (root.get("pid")) |v| if (v == .integer) @as(i32, @intCast(v.integer)) else null else null;

        // Liveness check for running containers
        if (container_state == .running) {
            var alive = false;

            // 1. Check host process if PID is available
            if (pid_val) |pid| {
                if (builtin.os.tag == .windows) {
                    // WSL check for Windows
                    alive = self.isPidAliveWSL(pid) catch false;
                } else {
                    // Unix check using kill(pid, 0)
                    std.posix.kill(pid, 0) catch |err| {
                        if (err != error.PermissionDenied) {
                            alive = false;
                        } else {
                            alive = true;
                        }
                    };
                }
            }

            // 2. Platform-specific backend check (fallback or primary)
            if (!alive) {
                if (builtin.os.tag == .windows) {
                    // On Windows, check WSL by container tag
                    alive = self.isContainerAliveWSLByTag(id_str) catch false;
                } else if (builtin.os.tag == .macos) {
                    // On macOS, containers run in Lima VM. Check if still alive there.
                    const macos = @import("../macos/virtualization.zig");
                    alive = macos.isContainerAliveInLima(self.allocator, id_str) catch false;
                }
            }

            if (!alive) {
                container_state = .stopped;
                // Persist corrected state to disk so it's not stale on next read
                self.updateState(id_str, .stopped, null, null) catch {};
            }
        }

        // Parse ports array
        var ports: std.ArrayList(PortMapping) = .empty;
        errdefer ports.deinit(self.allocator);
        if (root.get("ports")) |ports_val| {
            if (ports_val == .array) {
                for (ports_val.array.items) |item| {
                    const obj = item.object;
                    const host_port: u16 = @intCast(obj.get("host_port").?.integer);
                    const container_port: u16 = @intCast(obj.get("container_port").?.integer);
                    const proto_str = if (obj.get("protocol")) |p| p.string else "tcp";
                    try ports.append(self.allocator, .{
                        .host_port = host_port,
                        .container_port = container_port,
                        .protocol = PortMapping.Protocol.fromString(proto_str),
                    });
                }
            }
        }
        const ports_slice = try ports.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(ports_slice);

        // Parse volumes array
        var vols: std.ArrayList(VolumeMount) = .empty;
        errdefer {
            for (vols.items) |v| {
                self.allocator.free(v.host_path);
                self.allocator.free(v.container_path);
            }
            vols.deinit(self.allocator);
        }
        if (root.get("volumes")) |vols_val| {
            if (vols_val == .array) {
                for (vols_val.array.items) |item| {
                    const obj = item.object;
                    const hp = try self.allocator.dupe(u8, obj.get("host_path").?.string);
                    errdefer self.allocator.free(hp);
                    const cp = try self.allocator.dupe(u8, obj.get("container_path").?.string);
                    try vols.append(self.allocator, .{
                        .host_path = hp,
                        .container_path = cp,
                    });
                }
            }
        }
        const vols_slice = try vols.toOwnedSlice(self.allocator);
        errdefer {
            for (vols_slice) |v| {
                self.allocator.free(v.host_path);
                self.allocator.free(v.container_path);
            }
            self.allocator.free(vols_slice);
        }

        // Parse env_vars array
        var envs: std.ArrayList(EnvVar) = .empty;
        errdefer {
            for (envs.items) |e| {
                self.allocator.free(e.key);
                self.allocator.free(e.value);
            }
            envs.deinit(self.allocator);
        }
        if (root.get("env_vars")) |envs_val| {
            if (envs_val == .array) {
                for (envs_val.array.items) |item| {
                    const obj = item.object;
                    const key = try self.allocator.dupe(u8, obj.get("key").?.string);
                    errdefer self.allocator.free(key);
                    const value = try self.allocator.dupe(u8, obj.get("value").?.string);
                    try envs.append(self.allocator, .{
                        .key = key,
                        .value = value,
                    });
                }
            }
        }
        const envs_slice = try envs.toOwnedSlice(self.allocator);

        return ContainerInfo{
            .id = id,
            .image = try self.allocator.dupe(u8, image_val),
            .command = try self.allocator.dupe(u8, cmd_val),
            .state = container_state,
            .created_at = root.get("created_at").?.integer,
            .started_at = if (root.get("started_at")) |v| if (v == .integer) v.integer else null else null,
            .finished_at = if (root.get("finished_at")) |v| if (v == .integer) v.integer else null else null,
            .pid = pid_val,
            .exit_code = if (root.get("exit_code")) |v| if (v == .integer) @intCast(v.integer) else null else null,
            .name = if (root.get("name")) |v| if (v == .string) try self.allocator.dupe(u8, v.string) else null else null,
            .restart_policy = restart_policy,
            .workdir = if (root.get("workdir")) |wd| if (wd == .string and !std.mem.eql(u8, wd.string, "/")) try self.allocator.dupe(u8, wd.string) else "/" else "/",
            .ports = ports_slice,
            .volumes = vols_slice,
            .env_vars = envs_slice,
            .allocator = self.allocator,
        };
    }

    /// Helper to check if a PID is alive in WSL2
    fn isPidAliveWSL(self: *Self, pid: i32) !bool {
        const pid_str = try std.fmt.allocPrint(self.allocator, "{d}", .{pid});
        defer self.allocator.free(pid_str);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "ps", "-p", pid_str },
        }) catch return false;

        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        return result.term.Exited == 0;
    }

    /// Helper to check if a container is alive in WSL2 by tag
    /// Uses the pidfile at /tmp/isolazi/<id>/pid to check if the container's
    /// outer process (unshare) is still running. This is more reliable than
    /// /proc/*/environ grep which fails when services drop privileges (e.g.
    /// redis via gosu clears the environ, making ISOLAZI_ID invisible).
    fn isContainerAliveWSLByTag(self: *Self, container_id: []const u8) !bool {
        // Read the PID from the container's pidfile and check if it's alive
        // The pidfile contains the PID of the outer shell that exec'd into unshare.
        // If that process is alive, the container is running.
        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "PID=$(cat /tmp/isolazi/{s}/pid 2>/dev/null) && [ -n \"$PID\" ] && kill -0 $PID 2>/dev/null",
            .{container_id},
        );
        defer self.allocator.free(cmd);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", cmd },
        }) catch return false;
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        // kill -0 exits with 0 if process exists
        return result.term.Exited == 0;
    }

    /// List all containers
    pub fn listContainers(self: *Self, all: bool) ![]ContainerInfo {
        var containers: std.ArrayList(ContainerInfo) = .empty;
        errdefer {
            for (containers.items) |*c| c.deinit();
            containers.deinit(self.allocator);
        }

        var dir = std.fs.cwd().openDir(self.base_path, .{ .iterate = true }) catch {
            return containers.toOwnedSlice(self.allocator);
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name.len != 32) continue; // Container IDs are 32 hex chars

            const info = self.getContainer(entry.name) catch continue;

            // Filter by state if not showing all
            if (!all and info.state != .running) {
                var info_mut = info;
                info_mut.deinit();
                continue;
            }

            try containers.append(self.allocator, info);
        }

        return containers.toOwnedSlice(self.allocator);
    }

    /// Remove a container
    pub fn removeContainer(self: *Self, container_id: []const u8, force: bool) !void {
        // Check if container exists and get its state
        var info = self.getContainer(container_id) catch {
            return error.ContainerNotFound;
        };
        defer info.deinit();

        // Can't remove running container unless forced
        if (info.state == .running and !force) {
            return error.ContainerRunning;
        }

        // If forced, always try to kill WSL processes for this container
        // regardless of reported state (state can be stale)
        if (force) {
            self.forceKillWSLContainer(container_id);
        } else if (info.state == .running) {
            self.stopContainer(container_id) catch {};
        }

        // Remove container directory
        const container_dir = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.base_path, container_id },
        );
        defer self.allocator.free(container_dir);

        std.fs.cwd().deleteTree(container_dir) catch {};
    }

    /// Stop a running container
    pub fn stopContainer(self: *Self, container_id: []const u8) !void {
        var info = self.getContainer(container_id) catch {
            return error.ContainerNotFound;
        };
        defer info.deinit();

        if (info.state != .running) {
            return error.ContainerNotRunning;
        }

        if (builtin.os.tag == .windows) {
            // Try state.json PID first, then fall back to pidfile
            var pid_to_kill: ?i32 = info.pid;
            if (pid_to_kill == null) {
                // Read PID from WSL pidfile
                const pid_cmd = std.fmt.allocPrint(self.allocator, "cat /tmp/isolazi/{s}/pid 2>/dev/null", .{container_id}) catch "";
                defer if (pid_cmd.len > 0) self.allocator.free(pid_cmd);
                if (pid_cmd.len > 0) {
                    if (std.process.Child.run(.{
                        .allocator = self.allocator,
                        .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", pid_cmd },
                    })) |res| {
                        defer self.allocator.free(res.stdout);
                        defer self.allocator.free(res.stderr);
                        const trimmed = std.mem.trim(u8, res.stdout, &[_]u8{ ' ', '\n', '\r', '\t' });
                        pid_to_kill = std.fmt.parseInt(i32, trimmed, 10) catch null;
                    } else |_| {}
                }
            }
            if (pid_to_kill) |pid| {
                // Kill process tree: find descendants first, then kill all with SIGTERM
                const stop_cmd = std.fmt.allocPrint(
                    self.allocator,
                    "PID={d}; " ++
                        "L1=$(pgrep -P $PID 2>/dev/null); " ++
                        "L2=\"\"; for p in $L1; do L2=\"$L2 $(pgrep -P $p 2>/dev/null)\"; done; " ++
                        "L3=\"\"; for p in $L2; do L3=\"$L3 $(pgrep -P $p 2>/dev/null)\"; done; " ++
                        "kill -TERM $L3 $L2 $L1 $PID 2>/dev/null",
                    .{pid},
                ) catch "";
                defer if (stop_cmd.len > 0) self.allocator.free(stop_cmd);
                if (stop_cmd.len > 0) {
                    if (std.process.Child.run(.{
                        .allocator = self.allocator,
                        .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", stop_cmd },
                    })) |res| {
                        self.allocator.free(res.stdout);
                        self.allocator.free(res.stderr);
                    } else |_| {}
                }
            }
        } else if (builtin.os.tag == .macos) {
            // On macOS, kill the local proxy process AND the remote processes in VM
            if (info.pid) |pid| {
                _ = std.posix.kill(pid, std.posix.SIG.TERM) catch {};
            }
            // Also call pkill in VM to be sure
            const macos = @import("../macos/virtualization.zig");
            macos.stopInLima(self.allocator, container_id) catch {};

            // Refresh Lima port forwarding to release host port bindings
            macos.refreshLimaPortForwarding(self.allocator);
        } else {
            // On Linux, use kill syscall
            if (info.pid) |pid| {
                _ = std.posix.kill(pid, std.posix.SIG.TERM) catch {};
                // Also kill child processes with SIGTERM
                const kill_children = std.fmt.allocPrint(self.allocator, "pkill -TERM -P {d} 2>/dev/null", .{pid}) catch "";
                defer if (kill_children.len > 0) self.allocator.free(kill_children);
                if (kill_children.len > 0) {
                    if (std.process.Child.run(.{
                        .allocator = self.allocator,
                        .argv = &[_][]const u8{ "sh", "-c", kill_children },
                    })) |res| {
                        self.allocator.free(res.stdout);
                        self.allocator.free(res.stderr);
                    } else |_| {}
                }
            }
        }
        try self.updateState(container_id, .stopped, null, null);
    }

    /// Force-kill all WSL processes for a specific container.
    /// Uses procfs /proc/*/root scanning to find chrooted processes + pidfile for outer shell.
    fn forceKillWSLContainer(self: *Self, container_id: []const u8) void {
        if (builtin.os.tag == .windows) {
            // Write kill script to a temp file in WSL to avoid Windows command-line quoting issues
            const script_path = "/tmp/isolazi_kill_single.sh";
            const kill_script = std.fmt.allocPrint(
                self.allocator,
                "#!/bin/sh\n" ++
                    "PID=$(cat /tmp/isolazi/{s}/pid 2>/dev/null)\n" ++
                    "[ -n \"$PID\" ] && {{\n" ++
                    "ALL_PIDS=\"$PID\"\n" ++
                    "for c1 in $(pgrep -P $PID 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c1\"\n" ++
                    "for c2 in $(pgrep -P $c1 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c2\"\n" ++
                    "for c3 in $(pgrep -P $c2 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c3\"; done\n" ++
                    "done; done\n" ++
                    "kill -9 $ALL_PIDS 2>/dev/null\n" ++
                    "}}\n" ++
                    "umount -l /tmp/isolazi/{s}/merged 2>/dev/null\n" ++
                    "rm -rf /tmp/isolazi/{s} 2>/dev/null\n",
                .{ container_id, container_id, container_id },
            ) catch "";
            defer if (kill_script.len > 0) self.allocator.free(kill_script);
            if (kill_script.len == 0) return;
            // Write script to WSL filesystem via stdin pipe
            var write_cmd = [_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", "cat > " ++ script_path };
            var write_child = std.process.Child.init(&write_cmd, self.allocator);
            write_child.stdin_behavior = .Pipe;
            write_child.stdout_behavior = .Ignore;
            write_child.stderr_behavior = .Ignore;
            if (write_child.spawn()) {
                if (write_child.stdin) |*stdin| {
                    stdin.writeAll(kill_script) catch {};
                    stdin.close();
                    write_child.stdin = null;
                }
                _ = write_child.wait() catch {};
            } else |_| return;
            // Execute the kill script
            if (std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", script_path },
            })) |res| {
                self.allocator.free(res.stdout);
                self.allocator.free(res.stderr);
            } else |_| {}
        } else if (builtin.os.tag == .macos) {
            const macos = @import("../macos/virtualization.zig");
            macos.stopInLima(self.allocator, container_id) catch {};
            macos.refreshLimaPortForwarding(self.allocator);
        } else {
            // Linux: read PID from pidfile and kill process tree
            const linux_kill_cmd = std.fmt.allocPrint(
                self.allocator,
                "PID=$(cat /tmp/isolazi/{s}/pid 2>/dev/null); " ++
                    "[ -n \"$PID\" ] && {{ " ++
                    "ALL_PIDS=\"$PID\"; " ++
                    "for c1 in $(pgrep -P $PID 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c1\"; " ++
                    "for c2 in $(pgrep -P $c1 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c2\"; " ++
                    "for c3 in $(pgrep -P $c2 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c3\"; done; " ++
                    "done; done; " ++
                    "kill -9 $ALL_PIDS 2>/dev/null; " ++
                    "}}",
                .{container_id},
            ) catch return;
            defer self.allocator.free(linux_kill_cmd);
            if (std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "sh", "-c", linux_kill_cmd },
            })) |res| {
                self.allocator.free(res.stdout);
                self.allocator.free(res.stderr);
            } else |_| {}
        }
    }

    /// Kill ALL isolazi container processes and clean up overlay mounts.
    /// Uses pidfile-based process tree scanning to find all container processes.
    /// No dependency on state.json — works even with stale/missing state.
    fn killAllWSLContainers(self: *Self) void {
        if (builtin.os.tag == .windows) {
            // Write kill script to a temp file in WSL to avoid Windows command-line quoting issues
            const script_path = "/tmp/isolazi_kill_all.sh";
            const kill_script =
                "#!/bin/sh\n" ++
                "ALL_PIDS=''\n" ++
                "for f in /tmp/isolazi/*/pid; do\n" ++
                "  PID=$(cat \"$f\" 2>/dev/null)\n" ++
                "  [ -n \"$PID\" ] && {\n" ++
                "    ALL_PIDS=\"$ALL_PIDS $PID\"\n" ++
                "    for c1 in $(pgrep -P $PID 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c1\"\n" ++
                "      for c2 in $(pgrep -P $c1 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c2\"\n" ++
                "        for c3 in $(pgrep -P $c2 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c3\"; done\n" ++
                "      done\n" ++
                "    done\n" ++
                "  }\n" ++
                "done\n" ++
                "[ -n \"$ALL_PIDS\" ] && kill -9 $ALL_PIDS 2>/dev/null\n" ++
                "for d in /tmp/isolazi/*/merged; do umount -l \"$d\" 2>/dev/null; done\n" ++
                "rm -rf /tmp/isolazi 2>/dev/null\n";
            // Write script to WSL filesystem via stdin pipe
            var write_cmd2 = [_][]const u8{ "wsl", "-u", "root", "--", "sh", "-c", "cat > " ++ script_path };
            var write_child = std.process.Child.init(&write_cmd2, self.allocator);
            write_child.stdin_behavior = .Pipe;
            write_child.stdout_behavior = .Ignore;
            write_child.stderr_behavior = .Ignore;
            if (write_child.spawn()) {
                if (write_child.stdin) |*stdin| {
                    stdin.writeAll(kill_script) catch {};
                    stdin.close();
                    write_child.stdin = null;
                }
                _ = write_child.wait() catch {};
            } else |_| return;
            // Execute the kill script
            if (std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "wsl", "-u", "root", "--", "sh", script_path },
            })) |res| {
                self.allocator.free(res.stdout);
                self.allocator.free(res.stderr);
            } else |_| {}
        } else if (builtin.os.tag == .macos) {
            const macos = @import("../macos/virtualization.zig");
            macos.stopLimaInstance(self.allocator) catch {};
            macos.refreshLimaPortForwarding(self.allocator);
        } else {
            // Linux: iterate pidfiles and kill all process trees
            if (std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "sh", "-c", "ALL_PIDS=''; " ++
                    "for f in /tmp/isolazi/*/pid; do " ++
                    "PID=$(cat \"$f\" 2>/dev/null); " ++
                    "[ -n \"$PID\" ] && { " ++
                    "ALL_PIDS=\"$ALL_PIDS $PID\"; " ++
                    "for c1 in $(pgrep -P $PID 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c1\"; " ++
                    "for c2 in $(pgrep -P $c1 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c2\"; " ++
                    "for c3 in $(pgrep -P $c2 2>/dev/null); do ALL_PIDS=\"$ALL_PIDS $c3\"; done; " ++
                    "done; done; }; done; " ++
                    "[ -n \"$ALL_PIDS\" ] && kill -9 $ALL_PIDS 2>/dev/null; " ++
                    "for d in /tmp/isolazi/*/merged; do umount -l \"$d\" 2>/dev/null; done; " ++
                    "rm -rf /tmp/isolazi 2>/dev/null" },
            })) |res| {
                self.allocator.free(res.stdout);
                self.allocator.free(res.stderr);
            } else |_| {}
        }
    }

    /// Prune containers.
    /// - When force is false: remove only non-running containers.
    /// - When force is true: remove all containers (running will be stopped first).
    pub fn pruneContainers(self: *Self, force: bool) !u64 {
        // When force-pruning, kill ALL isolazi processes first
        // This catches orphan processes whose state might be stale
        if (force) {
            self.killAllWSLContainers();
        }

        var removed: u64 = 0;

        var dir = std.fs.cwd().openDir(self.base_path, .{ .iterate = true }) catch {
            return removed;
        };
        defer dir.close();

        // Collect container IDs to remove (can't modify while iterating)
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer {
            for (to_remove.items) |id| {
                self.allocator.free(id);
            }
            to_remove.deinit(self.allocator);
        }

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name.len != 32) continue;

            const info = self.getContainer(entry.name) catch continue;
            defer {
                var info_mut = info;
                info_mut.deinit();
            }

            // Only prune non-running containers unless forced
            if (force or info.state != .running) {
                try to_remove.append(self.allocator, try self.allocator.dupe(u8, entry.name));
            }
        }

        // Now remove them
        for (to_remove.items) |container_id| {
            self.removeContainer(container_id, force) catch continue;
            removed += 1;
        }

        return removed;
    }

    /// Find container by ID prefix or name
    pub fn findContainer(self: *Self, query: []const u8) ![]const u8 {
        var dir = std.fs.cwd().openDir(self.base_path, .{ .iterate = true }) catch {
            return error.ContainerNotFound;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name.len != 32) continue;

            // Check if ID starts with query
            if (std.mem.startsWith(u8, entry.name, query)) {
                return try self.allocator.dupe(u8, entry.name);
            }

            // Check name
            const info = self.getContainer(entry.name) catch continue;
            defer {
                var info_mut = info;
                info_mut.deinit();
            }
            if (info.name) |name| {
                if (std.mem.eql(u8, name, query)) {
                    return try self.allocator.dupe(u8, entry.name);
                }
            }
        }

        return error.ContainerNotFound;
    }
};
