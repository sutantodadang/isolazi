//! Cgroup v2 Resource Management for Container Isolation
//!
//! This module provides cgroup v2 integration for:
//! - Memory limits (memory.max, memory.high, memory.swap.max)
//! - CPU limits (cpu.max for quota/period, cpu.weight)
//! - I/O bandwidth limits (io.max for device-specific limits, io.weight)
//! - OOM killer configuration (memory.oom.group, memory.oom.kill)
//!
//! Cgroup v2 unified hierarchy:
//! ```
//! /sys/fs/cgroup/
//! └── isolazi/
//!     └── <container_id>/
//!         ├── cgroup.procs          # PIDs in this cgroup
//!         ├── cgroup.controllers    # Available controllers
//!         ├── cgroup.subtree_control # Enabled controllers for children
//!         ├── memory.max            # Memory limit (bytes or "max")
//!         ├── memory.high           # Memory high watermark
//!         ├── memory.swap.max       # Swap limit
//!         ├── memory.oom.group      # OOM behavior for group
//!         ├── cpu.max               # CPU quota (quota period)
//!         ├── cpu.weight            # CPU weight (1-10000, default 100)
//!         ├── io.max                # I/O limits per device
//!         └── io.weight             # I/O weight (1-10000, default 100)
//! ```
//!
//! SECURITY: Requires appropriate permissions to write to cgroup filesystem.
//! Rootless containers may need user namespace + cgroup namespace delegation.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config/config.zig");

/// Config resource limits type (from config module)
pub const ConfigResourceLimits = config.ResourceLimits;

/// Cgroup v2 error types
pub const CgroupError = error{
    CgroupNotMounted,
    CgroupNotV2,
    PermissionDenied,
    CgroupCreateFailed,
    CgroupWriteFailed,
    CgroupRemoveFailed,
    InvalidMemoryLimit,
    InvalidCpuLimit,
    InvalidIoLimit,
    ContainerNotFound,
    ControllerNotAvailable,
    OutOfMemory,
};

/// Memory limit configuration
pub const MemoryLimit = struct {
    /// Hard memory limit in bytes (0 = unlimited)
    max: u64 = 0,
    /// High watermark - triggers memory pressure at this level (0 = disabled)
    high: u64 = 0,
    /// Swap limit in bytes (0 = same as memory max, max_int = unlimited)
    swap_max: u64 = 0,
    /// Enable swap (if false, swap_max is set to 0)
    swap_enabled: bool = true,

    /// Parse a memory string like "512m", "1g", "1024k", "1073741824"
    pub fn parse(s: []const u8) !u64 {
        if (s.len == 0) return 0;

        // Check for suffix
        const last = s[s.len - 1];
        var multiplier: u64 = 1;
        var num_str = s;

        if (last == 'k' or last == 'K') {
            multiplier = 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 'm' or last == 'M') {
            multiplier = 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 'g' or last == 'G') {
            multiplier = 1024 * 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        } else if (last == 't' or last == 'T') {
            multiplier = 1024 * 1024 * 1024 * 1024;
            num_str = s[0 .. s.len - 1];
        }

        const value = std.fmt.parseInt(u64, num_str, 10) catch
            return CgroupError.InvalidMemoryLimit;

        // Check for overflow
        if (value > std.math.maxInt(u64) / multiplier) {
            return CgroupError.InvalidMemoryLimit;
        }

        return value * multiplier;
    }

    /// Format memory value for human display
    pub fn format(bytes: u64, buf: []u8) []const u8 {
        if (bytes == 0) {
            return std.fmt.bufPrint(buf, "unlimited", .{}) catch "unlimited";
        } else if (bytes >= 1024 * 1024 * 1024 and bytes % (1024 * 1024 * 1024) == 0) {
            return std.fmt.bufPrint(buf, "{d}G", .{bytes / (1024 * 1024 * 1024)}) catch "?";
        } else if (bytes >= 1024 * 1024 and bytes % (1024 * 1024) == 0) {
            return std.fmt.bufPrint(buf, "{d}M", .{bytes / (1024 * 1024)}) catch "?";
        } else if (bytes >= 1024 and bytes % 1024 == 0) {
            return std.fmt.bufPrint(buf, "{d}K", .{bytes / 1024}) catch "?";
        } else {
            return std.fmt.bufPrint(buf, "{d}", .{bytes}) catch "?";
        }
    }
};

/// CPU limit configuration
pub const CpuLimit = struct {
    /// CPU quota in microseconds per period (0 = unlimited)
    /// E.g., 100000 with period 100000 = 1 CPU
    quota: u64 = 0,
    /// CPU period in microseconds (default 100ms = 100000)
    period: u64 = 100000,
    /// CPU weight for scheduling (1-10000, default 100)
    /// Higher weight = more CPU time relative to other cgroups
    weight: u32 = 100,

    /// Parse a CPU specification like "2" (cores), "0.5", "200%", "150000" (quota)
    pub fn parseSpec(s: []const u8) !CpuLimit {
        var result = CpuLimit{};

        if (std.mem.endsWith(u8, s, "%")) {
            // Percentage of one CPU
            const percent_str = s[0 .. s.len - 1];
            const percent = std.fmt.parseFloat(f64, percent_str) catch
                return CgroupError.InvalidCpuLimit;
            // 100% = 100000 quota per 100000 period
            result.quota = @intFromFloat(percent * 1000);
            result.period = 100000;
        } else if (std.mem.indexOf(u8, s, ".")) |_| {
            // Fractional cores (e.g., "1.5" = 1.5 CPUs)
            const cores = std.fmt.parseFloat(f64, s) catch
                return CgroupError.InvalidCpuLimit;
            result.quota = @intFromFloat(cores * 100000);
            result.period = 100000;
        } else {
            // Integer cores or direct quota value
            const value = std.fmt.parseInt(u64, s, 10) catch
                return CgroupError.InvalidCpuLimit;
            if (value <= 128) {
                // Treat as number of cores
                result.quota = value * 100000;
                result.period = 100000;
            } else {
                // Treat as raw quota value in microseconds
                result.quota = value;
                result.period = 100000;
            }
        }

        return result;
    }
};

/// I/O limit configuration
pub const IoLimit = struct {
    /// I/O weight for scheduling (1-10000, default 100)
    weight: u32 = 100,
    /// Device-specific limits (major:minor format -> limits)
    /// Each entry: "MAJ:MIN rbps=X wbps=Y riops=Z wiops=W"
    device_limits: [MAX_IO_DEVICES]DeviceIoLimit = std.mem.zeroes([MAX_IO_DEVICES]DeviceIoLimit),
    device_count: usize = 0,

    pub const MAX_IO_DEVICES = 8;

    /// Device I/O limit entry
    pub const DeviceIoLimit = struct {
        /// Device major number
        major: u32 = 0,
        /// Device minor number
        minor: u32 = 0,
        /// Read bytes per second limit (0 = unlimited)
        rbps: u64 = 0,
        /// Write bytes per second limit (0 = unlimited)
        wbps: u64 = 0,
        /// Read I/O operations per second (0 = unlimited)
        riops: u64 = 0,
        /// Write I/O operations per second (0 = unlimited)
        wiops: u64 = 0,
        /// Is this entry active?
        active: bool = false,
    };

    /// Parse an I/O limit specification like "8:0 rbps=10485760 wbps=10485760"
    pub fn parseDeviceLimit(s: []const u8) !DeviceIoLimit {
        var result = DeviceIoLimit{};

        var parts = std.mem.splitScalar(u8, s, ' ');
        const device_str = parts.next() orelse return CgroupError.InvalidIoLimit;

        // Parse device major:minor
        var dev_parts = std.mem.splitScalar(u8, device_str, ':');
        const major_str = dev_parts.next() orelse return CgroupError.InvalidIoLimit;
        const minor_str = dev_parts.next() orelse return CgroupError.InvalidIoLimit;

        result.major = std.fmt.parseInt(u32, major_str, 10) catch
            return CgroupError.InvalidIoLimit;
        result.minor = std.fmt.parseInt(u32, minor_str, 10) catch
            return CgroupError.InvalidIoLimit;

        // Parse key=value pairs
        while (parts.next()) |part| {
            var kv = std.mem.splitScalar(u8, part, '=');
            const key = kv.next() orelse continue;
            const value_str = kv.next() orelse continue;
            const value = MemoryLimit.parse(value_str) catch continue;

            if (std.mem.eql(u8, key, "rbps")) {
                result.rbps = value;
            } else if (std.mem.eql(u8, key, "wbps")) {
                result.wbps = value;
            } else if (std.mem.eql(u8, key, "riops")) {
                result.riops = std.fmt.parseInt(u64, value_str, 10) catch continue;
            } else if (std.mem.eql(u8, key, "wiops")) {
                result.wiops = std.fmt.parseInt(u64, value_str, 10) catch continue;
            }
        }

        result.active = true;
        return result;
    }
};

/// OOM killer configuration
pub const OomConfig = struct {
    /// Disable OOM killer for this cgroup (processes will hang if OOM)
    /// WARNING: Can cause system hangs - use with caution
    disable_oom_kill: bool = false,
    /// OOM score adjustment (-1000 to 1000)
    /// Lower = less likely to be killed, -1000 = never kill
    oom_score_adj: i16 = 0,
    /// Enable OOM kill for the entire cgroup (cgroup v2)
    /// When true, all processes in cgroup are killed on OOM
    oom_group: bool = false,

    /// Parse OOM score adjustment string
    pub fn parseOomScoreAdj(s: []const u8) !i16 {
        const value = std.fmt.parseInt(i16, s, 10) catch
            return CgroupError.InvalidMemoryLimit;
        if (value < -1000 or value > 1000) {
            return CgroupError.InvalidMemoryLimit;
        }
        return value;
    }
};

/// Complete resource limits configuration
pub const ResourceLimits = struct {
    /// Memory limits
    memory: MemoryLimit = .{},
    /// CPU limits
    cpu: CpuLimit = .{},
    /// I/O limits
    io: IoLimit = .{},
    /// OOM configuration
    oom: OomConfig = .{},
    /// Enable cgroup namespace (CLONE_NEWCGROUP)
    cgroup_namespace: bool = false,
    /// Are any limits configured?
    pub fn hasLimits(self: *const ResourceLimits) bool {
        return self.memory.max > 0 or
            self.memory.high > 0 or
            self.cpu.quota > 0 or
            self.cpu.weight != 100 or
            self.io.weight != 100 or
            self.io.device_count > 0 or
            self.oom.disable_oom_kill or
            self.oom.oom_score_adj != 0 or
            self.oom.oom_group;
    }
};

/// Cgroup manager for container resource control
pub const CgroupManager = struct {
    allocator: std.mem.Allocator,
    /// Base path for isolazi cgroups (/sys/fs/cgroup/isolazi)
    base_path: []const u8,
    /// Path to the cgroup for a specific container
    container_path: ?[]const u8,

    const Self = @This();
    const CGROUP_ROOT = "/sys/fs/cgroup";
    const ISOLAZI_CGROUP = "isolazi";

    pub fn init(allocator: std.mem.Allocator) !Self {
        // Verify cgroup v2 is available
        if (!isCgroupV2Available()) {
            return CgroupError.CgroupNotV2;
        }

        const base_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ CGROUP_ROOT, ISOLAZI_CGROUP });

        // Ensure base isolazi cgroup exists
        std.fs.cwd().makePath(base_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                allocator.free(base_path);
                return CgroupError.CgroupCreateFailed;
            }
        };

        // Enable controllers for subtree
        enableSubtreeControllers(allocator) catch {
            // Non-fatal - some controllers may not be available
        };

        return Self{
            .allocator = allocator,
            .base_path = base_path,
            .container_path = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.container_path) |path| {
            self.allocator.free(path);
        }
        self.allocator.free(self.base_path);
    }

    /// Create a cgroup for a container
    pub fn createCgroup(self: *Self, container_id: []const u8) !void {
        const cgroup_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.base_path, container_id },
        );

        std.fs.cwd().makePath(cgroup_path) catch |err| {
            self.allocator.free(cgroup_path);
            if (err == error.AccessDenied) {
                return CgroupError.PermissionDenied;
            }
            return CgroupError.CgroupCreateFailed;
        };

        // Enable controllers for this cgroup's children
        self.enableControllersForPath(cgroup_path) catch {
            // Non-fatal - continue without some controllers
        };

        if (self.container_path) |old_path| {
            self.allocator.free(old_path);
        }
        self.container_path = cgroup_path;
    }

    /// Add a process to the container's cgroup
    pub fn addProcess(self: *Self, pid: std.os.linux.pid_t) !void {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        const procs_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/cgroup.procs",
            .{cgroup_path},
        );
        defer self.allocator.free(procs_path);

        try writeValue(procs_path, "{d}", .{pid});
    }

    /// Apply memory limits to the container's cgroup
    pub fn applyMemoryLimits(self: *Self, limits: *const MemoryLimit) !void {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        // Set memory.max (hard limit)
        if (limits.max > 0) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/memory.max",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "{d}", .{limits.max});
        }

        // Set memory.high (soft limit / pressure trigger)
        if (limits.high > 0) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/memory.high",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "{d}", .{limits.high});
        }

        // Set memory.swap.max
        if (!limits.swap_enabled) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/memory.swap.max",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "0", .{});
        } else if (limits.swap_max > 0) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/memory.swap.max",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "{d}", .{limits.swap_max});
        }
    }

    /// Apply CPU limits to the container's cgroup
    pub fn applyCpuLimits(self: *Self, limits: *const CpuLimit) !void {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        // Set cpu.max (quota period format: "$MAX $PERIOD")
        if (limits.quota > 0) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/cpu.max",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "{d} {d}", .{ limits.quota, limits.period });
        }

        // Set cpu.weight
        if (limits.weight != 100) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/cpu.weight",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "{d}", .{limits.weight});
        }
    }

    /// Apply I/O limits to the container's cgroup
    pub fn applyIoLimits(self: *Self, limits: *const IoLimit) !void {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        // Set io.weight
        if (limits.weight != 100) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/io.weight",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "default {d}", .{limits.weight});
        }

        // Set io.max for each device
        if (limits.device_count > 0) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/io.max",
                .{cgroup_path},
            );
            defer self.allocator.free(path);

            // io.max format: "MAJ:MIN rbps=X wbps=Y riops=Z wiops=W"
            for (limits.device_limits[0..limits.device_count]) |dev| {
                if (!dev.active) continue;

                var buf: [256]u8 = undefined;
                var len: usize = 0;

                // Start with device
                len += (std.fmt.bufPrint(buf[len..], "{d}:{d}", .{ dev.major, dev.minor }) catch continue).len;

                // Add limits that are set
                if (dev.rbps > 0) {
                    len += (std.fmt.bufPrint(buf[len..], " rbps={d}", .{dev.rbps}) catch continue).len;
                }
                if (dev.wbps > 0) {
                    len += (std.fmt.bufPrint(buf[len..], " wbps={d}", .{dev.wbps}) catch continue).len;
                }
                if (dev.riops > 0) {
                    len += (std.fmt.bufPrint(buf[len..], " riops={d}", .{dev.riops}) catch continue).len;
                }
                if (dev.wiops > 0) {
                    len += (std.fmt.bufPrint(buf[len..], " wiops={d}", .{dev.wiops}) catch continue).len;
                }

                // Write to file (append mode for multiple devices)
                const file = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch continue;
                defer file.close();
                _ = file.write(buf[0..len]) catch continue;
            }
        }
    }

    /// Apply OOM configuration to the container's cgroup
    pub fn applyOomConfig(self: *Self, oom_config: *const OomConfig, pid: std.os.linux.pid_t) !void {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        // Set memory.oom.group (cgroup v2 specific)
        if (oom_config.oom_group) {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/memory.oom.group",
                .{cgroup_path},
            );
            defer self.allocator.free(path);
            try writeValue(path, "1", .{});
        }

        // Set OOM score adjustment via /proc (per-process, not cgroup)
        if (oom_config.oom_score_adj != 0) {
            const oom_adj_path = try std.fmt.allocPrint(
                self.allocator,
                "/proc/{d}/oom_score_adj",
                .{pid},
            );
            defer self.allocator.free(oom_adj_path);
            writeValue(oom_adj_path, "{d}", .{oom_config.oom_score_adj}) catch {
                // May fail if PID doesn't exist yet or no permission
            };
        }
    }

    /// Apply all resource limits from internal types
    pub fn applyLimits(self: *Self, limits: *const ResourceLimits, pid: std.os.linux.pid_t) !void {
        if (limits.memory.max > 0 or limits.memory.high > 0) {
            self.applyMemoryLimits(&limits.memory) catch |err| {
                std.debug.print("Warning: Failed to apply memory limits: {}\n", .{err});
            };
        }

        if (limits.cpu.quota > 0 or limits.cpu.weight != 100) {
            self.applyCpuLimits(&limits.cpu) catch |err| {
                std.debug.print("Warning: Failed to apply CPU limits: {}\n", .{err});
            };
        }

        if (limits.io.weight != 100 or limits.io.device_count > 0) {
            self.applyIoLimits(&limits.io) catch |err| {
                std.debug.print("Warning: Failed to apply I/O limits: {}\n", .{err});
            };
        }

        self.applyOomConfig(&limits.oom, pid) catch |err| {
            std.debug.print("Warning: Failed to apply OOM config: {}\n", .{err});
        };
    }

    /// Apply resource limits from config module types
    /// Converts config.ResourceLimits to internal types and applies them
    pub fn applyConfigLimits(self: *Self, cfg_limits: *const ConfigResourceLimits, pid: std.os.linux.pid_t) !void {
        // Convert and apply memory limits
        if (cfg_limits.memory.max > 0 or cfg_limits.memory.high > 0) {
            var mem_limit = MemoryLimit{
                .max = cfg_limits.memory.max,
                .high = cfg_limits.memory.high,
                .swap_max = cfg_limits.memory.swap_max,
            };
            self.applyMemoryLimits(&mem_limit) catch |err| {
                std.debug.print("Warning: Failed to apply memory limits: {}\n", .{err});
            };
        }

        // Convert and apply CPU limits
        if (cfg_limits.cpu.quota > 0 or cfg_limits.cpu.weight != 100) {
            var cpu_limit = CpuLimit{
                .quota = cfg_limits.cpu.quota,
                .period = cfg_limits.cpu.period,
                .weight = cfg_limits.cpu.weight,
            };
            self.applyCpuLimits(&cpu_limit) catch |err| {
                std.debug.print("Warning: Failed to apply CPU limits: {}\n", .{err});
            };
        }

        // Convert and apply I/O limits
        if (cfg_limits.io.weight != 100 or cfg_limits.io.device_count > 0) {
            var io_limit = IoLimit{
                .weight = cfg_limits.io.weight,
                .device_count = cfg_limits.io.device_count,
            };
            // Copy device limits
            for (0..cfg_limits.io.device_count) |i| {
                const src = cfg_limits.io.device_limits[i];
                io_limit.device_limits[i] = IoLimit.DeviceIoLimit{
                    .major = src.major,
                    .minor = src.minor,
                    .rbps = src.rbps,
                    .wbps = src.wbps,
                    .riops = src.riops,
                    .wiops = src.wiops,
                    .active = src.active,
                };
            }
            self.applyIoLimits(&io_limit) catch |err| {
                std.debug.print("Warning: Failed to apply I/O limits: {}\n", .{err});
            };
        }

        // Convert and apply OOM config
        var oom_cfg = OomConfig{
            .disable_oom_kill = cfg_limits.oom.disable_oom_kill,
            .oom_score_adj = cfg_limits.oom.oom_score_adj,
            .oom_group = cfg_limits.oom.oom_group,
        };
        self.applyOomConfig(&oom_cfg, pid) catch |err| {
            std.debug.print("Warning: Failed to apply OOM config: {}\n", .{err});
        };
    }

    /// Remove the container's cgroup
    pub fn removeCgroup(self: *Self) !void {
        const cgroup_path = self.container_path orelse return;

        // Try to remove the cgroup directory
        // This will fail if processes are still in it
        std.fs.cwd().deleteDir(cgroup_path) catch |err| {
            if (err != error.DirNotEmpty and err != error.FileNotFound) {
                return CgroupError.CgroupRemoveFailed;
            }
        };

        self.allocator.free(cgroup_path);
        self.container_path = null;
    }

    /// Enable controllers for a specific cgroup path
    fn enableControllersForPath(self: *Self, cgroup_path: []const u8) !void {
        const subtree_control_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/cgroup.subtree_control",
            .{cgroup_path},
        );
        defer self.allocator.free(subtree_control_path);

        // Enable memory, cpu, and io controllers
        writeValue(subtree_control_path, "+memory +cpu +io", .{}) catch {
            // May fail if controllers aren't available
        };
    }

    /// Get current memory usage for the container
    pub fn getMemoryUsage(self: *Self) !u64 {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/memory.current",
            .{cgroup_path},
        );
        defer self.allocator.free(path);

        return readU64Value(path);
    }

    /// Get current CPU usage statistics
    pub fn getCpuStats(self: *Self) !CpuStats {
        const cgroup_path = self.container_path orelse return CgroupError.ContainerNotFound;

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/cpu.stat",
            .{cgroup_path},
        );
        defer self.allocator.free(path);

        var stats = CpuStats{};

        const file = std.fs.cwd().openFile(path, .{}) catch return stats;
        defer file.close();

        var buf: [1024]u8 = undefined;
        const n = file.read(&buf) catch return stats;
        const content = buf[0..n];

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            var parts = std.mem.splitScalar(u8, line, ' ');
            const key = parts.next() orelse continue;
            const value_str = parts.next() orelse continue;
            const value = std.fmt.parseInt(u64, value_str, 10) catch continue;

            if (std.mem.eql(u8, key, "usage_usec")) {
                stats.usage_usec = value;
            } else if (std.mem.eql(u8, key, "user_usec")) {
                stats.user_usec = value;
            } else if (std.mem.eql(u8, key, "system_usec")) {
                stats.system_usec = value;
            } else if (std.mem.eql(u8, key, "nr_periods")) {
                stats.nr_periods = value;
            } else if (std.mem.eql(u8, key, "nr_throttled")) {
                stats.nr_throttled = value;
            } else if (std.mem.eql(u8, key, "throttled_usec")) {
                stats.throttled_usec = value;
            }
        }

        return stats;
    }
};

/// CPU statistics from cgroup
pub const CpuStats = struct {
    /// Total CPU time used (microseconds)
    usage_usec: u64 = 0,
    /// User CPU time (microseconds)
    user_usec: u64 = 0,
    /// System CPU time (microseconds)
    system_usec: u64 = 0,
    /// Number of enforcement periods
    nr_periods: u64 = 0,
    /// Number of times throttled
    nr_throttled: u64 = 0,
    /// Total throttled time (microseconds)
    throttled_usec: u64 = 0,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if cgroup v2 is available (unified hierarchy)
pub fn isCgroupV2Available() bool {
    // Check if /sys/fs/cgroup/cgroup.controllers exists (cgroup v2 marker)
    const marker_path = "/sys/fs/cgroup/cgroup.controllers";
    std.fs.cwd().access(marker_path, .{}) catch return false;
    return true;
}

/// Enable controllers in the root cgroup for delegation
fn enableSubtreeControllers(allocator: std.mem.Allocator) !void {
    // First, enable in root cgroup
    const root_subtree = "/sys/fs/cgroup/cgroup.subtree_control";
    writeValue(root_subtree, "+memory +cpu +io +pids", .{}) catch {};

    // Then enable in isolazi cgroup
    const isolazi_subtree = try std.fmt.allocPrint(
        allocator,
        "/sys/fs/cgroup/{s}/cgroup.subtree_control",
        .{CgroupManager.ISOLAZI_CGROUP},
    );
    defer allocator.free(isolazi_subtree);

    writeValue(isolazi_subtree, "+memory +cpu +io +pids", .{}) catch {};
}

/// Write a formatted value to a cgroup file
fn writeValue(path: []const u8, comptime fmt: []const u8, args: anytype) !void {
    const file = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch |err| {
        if (err == error.AccessDenied) {
            return CgroupError.PermissionDenied;
        }
        return CgroupError.CgroupWriteFailed;
    };
    defer file.close();

    var buf: [256]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, fmt, args) catch return CgroupError.CgroupWriteFailed;
    _ = file.write(str) catch return CgroupError.CgroupWriteFailed;
}

/// Read a u64 value from a cgroup file
fn readU64Value(path: []const u8) !u64 {
    const file = std.fs.cwd().openFile(path, .{}) catch return CgroupError.CgroupWriteFailed;
    defer file.close();

    var buf: [64]u8 = undefined;
    const n = file.read(&buf) catch return CgroupError.CgroupWriteFailed;
    const content = std.mem.trim(u8, buf[0..n], " \t\r\n");

    return std.fmt.parseInt(u64, content, 10) catch CgroupError.CgroupWriteFailed;
}

/// High-level function to set up cgroup for a container
/// Accepts config.ResourceLimits and converts to internal types
pub fn setupContainerCgroup(
    allocator: std.mem.Allocator,
    container_id: []const u8,
    cfg_limits: *const ConfigResourceLimits,
    pid: std.os.linux.pid_t,
) !*CgroupManager {
    var manager = try allocator.create(CgroupManager);
    errdefer allocator.destroy(manager);

    manager.* = try CgroupManager.init(allocator);
    errdefer manager.deinit();

    try manager.createCgroup(container_id);
    try manager.addProcess(pid);
    try manager.applyConfigLimits(cfg_limits, pid);

    return manager;
}

/// Clean up cgroup resources for a container
pub fn cleanupContainerCgroup(allocator: std.mem.Allocator, manager: *CgroupManager) void {
    manager.removeCgroup() catch {};
    manager.deinit();
    allocator.destroy(manager);
}

// =============================================================================
// Tests
// =============================================================================

test "MemoryLimit.parse" {
    const testing = std.testing;

    try testing.expectEqual(@as(u64, 1024), try MemoryLimit.parse("1k"));
    try testing.expectEqual(@as(u64, 1024), try MemoryLimit.parse("1K"));
    try testing.expectEqual(@as(u64, 512 * 1024 * 1024), try MemoryLimit.parse("512m"));
    try testing.expectEqual(@as(u64, 512 * 1024 * 1024), try MemoryLimit.parse("512M"));
    try testing.expectEqual(@as(u64, 2 * 1024 * 1024 * 1024), try MemoryLimit.parse("2g"));
    try testing.expectEqual(@as(u64, 1073741824), try MemoryLimit.parse("1073741824"));
}

test "CpuLimit.parseSpec" {
    const testing = std.testing;

    // 2 CPUs = 200000 quota
    const two_cpus = try CpuLimit.parseSpec("2");
    try testing.expectEqual(@as(u64, 200000), two_cpus.quota);

    // 50% = 50000 quota
    const half_cpu = try CpuLimit.parseSpec("50%");
    try testing.expectEqual(@as(u64, 50000), half_cpu.quota);

    // 1.5 CPUs = 150000 quota
    const one_half = try CpuLimit.parseSpec("1.5");
    try testing.expectEqual(@as(u64, 150000), one_half.quota);
}

test "ResourceLimits.hasLimits" {
    const testing = std.testing;

    var limits = ResourceLimits{};
    try testing.expect(!limits.hasLimits());

    limits.memory.max = 512 * 1024 * 1024;
    try testing.expect(limits.hasLimits());
}
