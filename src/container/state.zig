//! Container State Management
//!
//! Manages container lifecycle and state persistence.
//! Container states: created, running, stopped, removing

const std = @import("std");
const builtin = @import("builtin");

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

    allocator: std.mem.Allocator,

    pub fn deinit(self: *ContainerInfo) void {
        self.allocator.free(self.image);
        self.allocator.free(self.command);
        if (self.name) |n| self.allocator.free(n);
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
            \\  "name": {s}
            \\}}
        , .{
            container_id,
            image,
            command,
            std.time.timestamp(),
            name_str,
        });

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json);

        return container_id;
    }

    /// Create a new container with a pre-generated ID (does not start it)
    pub fn createContainerWithId(
        self: *Self,
        container_id: *const [32]u8,
        image: []const u8,
        command: []const u8,
        name: ?[]const u8,
    ) !void {
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
            \\  "state": "running",
            \\  "created_at": {d},
            \\  "started_at": {d},
            \\  "name": {s}
            \\}}
        , .{
            container_id,
            image,
            command,
            std.time.timestamp(),
            std.time.timestamp(),
            name_str,
        });

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json);
    }

    /// Update container state
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
        const existing = std.fs.cwd().readFileAlloc(self.allocator, state_path, 8192) catch {
            return error.ContainerNotFound;
        };
        defer self.allocator.free(existing);

        // Parse and update
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, existing, .{}) catch {
            return error.InvalidState;
        };
        defer parsed.deinit();

        const root = parsed.value.object;

        // Build updated JSON
        var json_buf: [4096]u8 = undefined;
        const timestamp = std.time.timestamp();

        const time_field = switch (state) {
            .running => "started_at",
            .stopped => "finished_at",
            else => "",
        };

        var time_line: []const u8 = "";
        var time_buf: [64]u8 = undefined;
        if (time_field.len > 0) {
            time_line = try std.fmt.bufPrint(&time_buf, ",\n  \"{s}\": {d}", .{ time_field, timestamp });
        }

        var pid_line: []const u8 = "";
        var pid_buf: [32]u8 = undefined;
        if (pid) |p| {
            pid_line = try std.fmt.bufPrint(&pid_buf, ",\n  \"pid\": {d}", .{p});
        }

        var exit_line: []const u8 = "";
        var exit_buf: [32]u8 = undefined;
        if (exit_code) |e| {
            exit_line = try std.fmt.bufPrint(&exit_buf, ",\n  \"exit_code\": {d}", .{e});
        }

        const id_str = root.get("id").?.string;
        const image_str = root.get("image").?.string;
        const cmd_str = root.get("command").?.string;
        const created_at = root.get("created_at").?.integer;

        var name_str: []const u8 = "null";
        var name_buf: [256]u8 = undefined;
        if (root.get("name")) |n| {
            if (n != .null) {
                name_str = try std.fmt.bufPrint(&name_buf, "\"{s}\"", .{n.string});
            }
        }

        const json = try std.fmt.bufPrint(&json_buf,
            \\{{
            \\  "id": "{s}",
            \\  "image": "{s}",
            \\  "command": "{s}",
            \\  "state": "{s}",
            \\  "created_at": {d},
            \\  "name": {s}{s}{s}{s}
            \\}}
        , .{
            id_str,
            image_str,
            cmd_str,
            state.toString(),
            created_at,
            name_str,
            time_line,
            pid_line,
            exit_line,
        });

        const file = try std.fs.cwd().createFile(state_path, .{});
        defer file.close();
        try file.writeAll(json);
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

        return ContainerInfo{
            .id = id,
            .image = try self.allocator.dupe(u8, root.get("image").?.string),
            .command = try self.allocator.dupe(u8, root.get("command").?.string),
            .state = ContainerState.fromString(root.get("state").?.string) orelse .created,
            .created_at = root.get("created_at").?.integer,
            .started_at = if (root.get("started_at")) |v| if (v == .integer) v.integer else null else null,
            .finished_at = if (root.get("finished_at")) |v| if (v == .integer) v.integer else null else null,
            .pid = if (root.get("pid")) |v| if (v == .integer) @intCast(v.integer) else null else null,
            .exit_code = if (root.get("exit_code")) |v| if (v == .integer) @intCast(v.integer) else null else null,
            .name = if (root.get("name")) |v| if (v == .string) try self.allocator.dupe(u8, v.string) else null else null,
            .allocator = self.allocator,
        };
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

        // If running and forced, try to stop first
        if (info.state == .running and force) {
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

        // On Windows, we need to kill through WSL
        if (builtin.os.tag == .windows) {
            if (info.pid) |pid| {
                // Try to kill the process via WSL
                var child = std.process.Child.init(&.{
                    "wsl",                                                 "-u", "root", "--", "kill", "-TERM",
                    try std.fmt.allocPrint(self.allocator, "{d}", .{pid}),
                }, self.allocator);
                child.spawn() catch {};
                _ = child.wait() catch {};
            }
        } else {
            // On Linux, use kill syscall
            if (info.pid) |pid| {
                _ = std.posix.kill(pid, std.posix.SIG.TERM) catch {};
            }
        }

        try self.updateState(container_id, .stopped, null, null);
    }

    /// Prune all non-running containers
    pub fn pruneContainers(self: *Self) !u64 {
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

            // Only prune non-running containers
            if (info.state != .running) {
                try to_remove.append(self.allocator, try self.allocator.dupe(u8, entry.name));
            }
        }

        // Now remove them
        for (to_remove.items) |container_id| {
            self.removeContainer(container_id, true) catch continue;
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
