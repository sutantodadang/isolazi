//! Memory & CPU Overhead Benchmark
//!
//! Measures the resource overhead of running idle containers:
//! - Memory consumption (RSS, virtual memory)
//! - CPU usage when idle
//! - File descriptor count
//! - Process count
//!
//! This benchmark helps understand the "cost" of running containers
//! and is important for capacity planning and density optimization.

const std = @import("std");
const builtin = @import("builtin");

const container_bench = @import("container_bench.zig");
const BenchmarkResult = container_bench.BenchmarkResult;
const BenchmarkConfig = container_bench.BenchmarkConfig;

/// Memory usage statistics
pub const MemoryStats = struct {
    /// Resident Set Size in bytes
    rss_bytes: u64 = 0,
    /// Virtual memory size in bytes
    vms_bytes: u64 = 0,
    /// Shared memory in bytes
    shared_bytes: u64 = 0,
    /// Data + stack size in bytes
    data_bytes: u64 = 0,
    /// Peak RSS (high water mark) in bytes
    peak_rss_bytes: u64 = 0,

    /// Print formatted memory stats
    pub fn print(self: MemoryStats, writer: anytype) !void {
        try writer.print("\n┌─────────────────────────────────────────────────────────────────┐\n", .{});
        try writer.print("│ Memory Usage Statistics                                          │\n", .{});
        try writer.print("├─────────────────────────────────────────────────────────────────┤\n", .{});
        try writer.print("│ RSS:          {d: >44} KB │\n", .{self.rss_bytes / 1024});
        try writer.print("│ Virtual:      {d: >44} KB │\n", .{self.vms_bytes / 1024});
        try writer.print("│ Shared:       {d: >44} KB │\n", .{self.shared_bytes / 1024});
        try writer.print("│ Data+Stack:   {d: >44} KB │\n", .{self.data_bytes / 1024});
        try writer.print("│ Peak RSS:     {d: >44} KB │\n", .{self.peak_rss_bytes / 1024});
        try writer.print("└─────────────────────────────────────────────────────────────────┘\n", .{});
    }

    /// Get difference between two memory states
    pub fn diff(self: MemoryStats, baseline: MemoryStats) MemoryStats {
        return .{
            .rss_bytes = if (self.rss_bytes > baseline.rss_bytes)
                self.rss_bytes - baseline.rss_bytes
            else
                0,
            .vms_bytes = if (self.vms_bytes > baseline.vms_bytes)
                self.vms_bytes - baseline.vms_bytes
            else
                0,
            .shared_bytes = if (self.shared_bytes > baseline.shared_bytes)
                self.shared_bytes - baseline.shared_bytes
            else
                0,
            .data_bytes = if (self.data_bytes > baseline.data_bytes)
                self.data_bytes - baseline.data_bytes
            else
                0,
            .peak_rss_bytes = if (self.peak_rss_bytes > baseline.peak_rss_bytes)
                self.peak_rss_bytes - baseline.peak_rss_bytes
            else
                0,
        };
    }
};

/// CPU usage statistics
pub const CpuStats = struct {
    /// User mode CPU time in nanoseconds
    user_ns: u64 = 0,
    /// System mode CPU time in nanoseconds
    system_ns: u64 = 0,
    /// Total CPU time (user + system) in nanoseconds
    total_ns: u64 = 0,
    /// CPU usage percentage (0.0 - 100.0)
    usage_percent: f64 = 0.0,

    /// Print formatted CPU stats
    pub fn print(self: CpuStats, writer: anytype) !void {
        try writer.print("\n┌─────────────────────────────────────────────────────────────────┐\n", .{});
        try writer.print("│ CPU Usage Statistics                                             │\n", .{});
        try writer.print("├─────────────────────────────────────────────────────────────────┤\n", .{});
        try writer.print("│ User time:    {d: >44} ms │\n", .{self.user_ns / 1_000_000});
        try writer.print("│ System time:  {d: >44} ms │\n", .{self.system_ns / 1_000_000});
        try writer.print("│ Total time:   {d: >44} ms │\n", .{self.total_ns / 1_000_000});
        try writer.print("│ Usage:        {d: >43.2}%  │\n", .{self.usage_percent});
        try writer.print("└─────────────────────────────────────────────────────────────────┘\n", .{});
    }

    /// Get difference between two CPU states
    pub fn diff(self: CpuStats, baseline: CpuStats) CpuStats {
        return .{
            .user_ns = if (self.user_ns > baseline.user_ns)
                self.user_ns - baseline.user_ns
            else
                0,
            .system_ns = if (self.system_ns > baseline.system_ns)
                self.system_ns - baseline.system_ns
            else
                0,
            .total_ns = if (self.total_ns > baseline.total_ns)
                self.total_ns - baseline.total_ns
            else
                0,
            .usage_percent = self.usage_percent,
        };
    }
};

/// Resource overhead measurement
pub const OverheadStats = struct {
    /// Memory statistics
    memory: MemoryStats = .{},
    /// CPU statistics
    cpu: CpuStats = .{},
    /// Number of file descriptors
    fd_count: u64 = 0,
    /// Number of threads
    thread_count: u64 = 0,
    /// Measurement duration in nanoseconds
    duration_ns: u64 = 0,

    /// Print formatted overhead stats
    pub fn print(self: OverheadStats, writer: anytype) !void {
        try writer.print("\n╔═══════════════════════════════════════════════════════════════════╗\n", .{});
        try writer.print("║              Container Overhead Report                            ║\n", .{});
        try writer.print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});

        try self.memory.print(writer);
        try self.cpu.print(writer);

        try writer.print("\n┌─────────────────────────────────────────────────────────────────┐\n", .{});
        try writer.print("│ Other Resources                                                  │\n", .{});
        try writer.print("├─────────────────────────────────────────────────────────────────┤\n", .{});
        try writer.print("│ File descriptors: {d: >40}     │\n", .{self.fd_count});
        try writer.print("│ Threads:          {d: >40}     │\n", .{self.thread_count});
        try writer.print("│ Duration:         {d: >36} ms     │\n", .{self.duration_ns / 1_000_000});
        try writer.print("└─────────────────────────────────────────────────────────────────┘\n", .{});
    }

    /// Export as JSON
    pub fn toJson(self: OverheadStats, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayListUnmanaged(u8) = .{};
        const writer = list.writer(allocator);

        try writer.print(
            \\{{
            \\  "memory": {{
            \\    "rss_bytes": {d},
            \\    "vms_bytes": {d},
            \\    "shared_bytes": {d},
            \\    "data_bytes": {d},
            \\    "peak_rss_bytes": {d},
            \\    "rss_kb": {d},
            \\    "rss_mb": {d:.2}
            \\  }},
            \\  "cpu": {{
            \\    "user_ns": {d},
            \\    "system_ns": {d},
            \\    "total_ns": {d},
            \\    "usage_percent": {d:.2}
            \\  }},
            \\  "fd_count": {d},
            \\  "thread_count": {d},
            \\  "duration_ns": {d},
            \\  "duration_ms": {d:.2}
            \\}}
        , .{
            self.memory.rss_bytes,
            self.memory.vms_bytes,
            self.memory.shared_bytes,
            self.memory.data_bytes,
            self.memory.peak_rss_bytes,
            self.memory.rss_bytes / 1024,
            @as(f64, @floatFromInt(self.memory.rss_bytes)) / (1024.0 * 1024.0),
            self.cpu.user_ns,
            self.cpu.system_ns,
            self.cpu.total_ns,
            self.cpu.usage_percent,
            self.fd_count,
            self.thread_count,
            self.duration_ns,
            @as(f64, @floatFromInt(self.duration_ns)) / 1_000_000.0,
        });

        return list.toOwnedSlice(allocator);
    }
};

/// Read memory statistics for a process
pub fn getProcessMemoryStats(pid: ?std.posix.pid_t) MemoryStats {
    // Only available on Linux
    if (builtin.os.tag != .linux) {
        return .{};
    }

    const target_pid = pid orelse std.os.linux.getpid();
    var stats = MemoryStats{};

    // Read /proc/[pid]/statm for memory info
    var path_buf: [64]u8 = undefined;
    const statm_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/statm", .{target_pid}) catch return stats;

    const statm_file = std.fs.openFileAbsolute(statm_path, .{}) catch return stats;
    defer statm_file.close();

    var buf: [256]u8 = undefined;
    const bytes_read = statm_file.read(&buf) catch return stats;
    const content = buf[0..bytes_read];

    // statm format: size resident shared text lib data dt (all in pages)
    var iter = std.mem.tokenizeScalar(u8, content, ' ');
    const page_size: u64 = 4096; // Usually 4KB pages

    // Total program size
    if (iter.next()) |size_str| {
        if (std.fmt.parseInt(u64, size_str, 10)) |pages| {
            stats.vms_bytes = pages * page_size;
        } else |_| {}
    }

    // Resident set size
    if (iter.next()) |rss_str| {
        if (std.fmt.parseInt(u64, rss_str, 10)) |pages| {
            stats.rss_bytes = pages * page_size;
        } else |_| {}
    }

    // Shared pages
    if (iter.next()) |shared_str| {
        if (std.fmt.parseInt(u64, shared_str, 10)) |pages| {
            stats.shared_bytes = pages * page_size;
        } else |_| {}
    }

    // Skip text
    _ = iter.next();
    // Skip lib
    _ = iter.next();

    // Data + stack
    if (iter.next()) |data_str| {
        if (std.fmt.parseInt(u64, data_str, 10)) |pages| {
            stats.data_bytes = pages * page_size;
        } else |_| {}
    }

    // Read /proc/[pid]/status for peak RSS
    const status_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{target_pid}) catch return stats;

    const status_file = std.fs.openFileAbsolute(status_path, .{}) catch return stats;
    defer status_file.close();

    var status_buf: [4096]u8 = undefined;
    const status_read = status_file.read(&status_buf) catch return stats;
    const status_content = status_buf[0..status_read];

    var lines = std.mem.tokenizeScalar(u8, status_content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "VmHWM:")) {
            // High water mark (peak RSS)
            var parts = std.mem.tokenizeScalar(u8, line, '\t');
            _ = parts.next(); // Skip label
            if (parts.next()) |value_str| {
                const trimmed = std.mem.trim(u8, value_str, " kB");
                if (std.fmt.parseInt(u64, trimmed, 10)) |kb| {
                    stats.peak_rss_bytes = kb * 1024;
                } else |_| {}
            }
        }
    }

    return stats;
}

/// Read CPU statistics for a process
pub fn getProcessCpuStats(pid: ?std.posix.pid_t) CpuStats {
    // Only available on Linux
    if (builtin.os.tag != .linux) {
        return .{};
    }

    const target_pid = pid orelse std.os.linux.getpid();
    var stats = CpuStats{};

    // Read /proc/[pid]/stat for CPU times
    var path_buf: [64]u8 = undefined;
    const stat_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/stat", .{target_pid}) catch return stats;

    const stat_file = std.fs.openFileAbsolute(stat_path, .{}) catch return stats;
    defer stat_file.close();

    var buf: [1024]u8 = undefined;
    const bytes_read = stat_file.read(&buf) catch return stats;
    const content = buf[0..bytes_read];

    // Find end of comm field (enclosed in parentheses)
    const comm_end = std.mem.lastIndexOf(u8, content, ")") orelse return stats;
    if (comm_end + 2 >= content.len) return stats;

    var iter = std.mem.tokenizeScalar(u8, content[comm_end + 2 ..], ' ');

    // Skip to utime (field 14) and stime (field 15)
    // Fields after comm: state, ppid, pgrp, session, tty_nr, tpgid, flags,
    //                   minflt, cminflt, majflt, cmajflt, utime, stime
    for (0..11) |_| {
        _ = iter.next();
    }

    const clock_ticks_per_sec: u64 = 100; // Usually 100 Hz (sysconf(_SC_CLK_TCK))

    // utime (user mode jiffies)
    if (iter.next()) |utime_str| {
        if (std.fmt.parseInt(u64, utime_str, 10)) |jiffies| {
            stats.user_ns = (jiffies * 1_000_000_000) / clock_ticks_per_sec;
        } else |_| {}
    }

    // stime (kernel mode jiffies)
    if (iter.next()) |stime_str| {
        if (std.fmt.parseInt(u64, stime_str, 10)) |jiffies| {
            stats.system_ns = (jiffies * 1_000_000_000) / clock_ticks_per_sec;
        } else |_| {}
    }

    stats.total_ns = stats.user_ns + stats.system_ns;

    return stats;
}

/// Count open file descriptors for a process
pub fn getProcessFdCount(pid: ?std.posix.pid_t) u64 {
    // Only available on Linux
    if (builtin.os.tag != .linux) {
        return 0;
    }

    const target_pid = pid orelse std.os.linux.getpid();

    var path_buf: [64]u8 = undefined;
    const fd_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/fd", .{target_pid}) catch return 0;

    var dir = std.fs.openDirAbsolute(fd_path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var count: u64 = 0;
    var iter = dir.iterate();
    while (iter.next() catch null) |_| {
        count += 1;
    }

    return count;
}

/// Count threads for a process
pub fn getProcessThreadCount(pid: ?std.posix.pid_t) u64 {
    // Only available on Linux
    if (builtin.os.tag != .linux) {
        return 0;
    }

    const target_pid = pid orelse std.os.linux.getpid();

    var path_buf: [64]u8 = undefined;
    const task_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/task", .{target_pid}) catch return 0;

    var dir = std.fs.openDirAbsolute(task_path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var count: u64 = 0;
    var iter = dir.iterate();
    while (iter.next() catch null) |_| {
        count += 1;
    }

    return count;
}

/// Measure overhead for an idle container over a duration
pub fn measureIdleOverhead(
    allocator: std.mem.Allocator,
    container_pid: std.posix.pid_t,
    duration_ms: u64,
) OverheadStats {
    _ = allocator;

    var stats = OverheadStats{};

    // Record start time and initial CPU stats
    const start_time = std.time.nanoTimestamp();
    const start_cpu = getProcessCpuStats(container_pid);

    // Sleep for the measurement duration
    std.time.sleep(duration_ms * 1_000_000);

    // Record end time and final stats
    const end_time = std.time.nanoTimestamp();
    const end_cpu = getProcessCpuStats(container_pid);

    stats.duration_ns = @intCast(end_time - start_time);

    // Memory stats (current snapshot)
    stats.memory = getProcessMemoryStats(container_pid);

    // CPU stats (delta during measurement period)
    stats.cpu = end_cpu.diff(start_cpu);

    // Calculate CPU usage percentage
    if (stats.duration_ns > 0) {
        stats.cpu.usage_percent = @as(f64, @floatFromInt(stats.cpu.total_ns)) /
            @as(f64, @floatFromInt(stats.duration_ns)) * 100.0;
    }

    // Other resources
    stats.fd_count = getProcessFdCount(container_pid);
    stats.thread_count = getProcessThreadCount(container_pid);

    return stats;
}

/// Benchmark configuration for overhead measurement
pub const OverheadBenchConfig = struct {
    /// Path to rootfs directory
    rootfs_path: []const u8,
    /// Command to run (should be a sleep or idle process)
    command: []const u8 = "/bin/sleep",
    /// Arguments for command
    args: []const []const u8 = &.{"infinity"},
    /// Duration to measure idle overhead (milliseconds)
    measure_duration_ms: u64 = 5000,
    /// Number of sample measurements
    samples: u32 = 3,
};

/// Aggregate overhead results
pub const OverheadBenchResult = struct {
    /// Individual samples
    samples: []const OverheadStats,
    /// Average memory RSS
    avg_rss_bytes: u64,
    /// Average CPU usage percentage
    avg_cpu_percent: f64,
    /// Average file descriptors
    avg_fd_count: u64,

    pub fn calculate(samples: []const OverheadStats) OverheadBenchResult {
        if (samples.len == 0) {
            return .{
                .samples = samples,
                .avg_rss_bytes = 0,
                .avg_cpu_percent = 0,
                .avg_fd_count = 0,
            };
        }

        var total_rss: u64 = 0;
        var total_cpu: f64 = 0;
        var total_fd: u64 = 0;

        for (samples) |s| {
            total_rss += s.memory.rss_bytes;
            total_cpu += s.cpu.usage_percent;
            total_fd += s.fd_count;
        }

        const n: u64 = samples.len;
        return .{
            .samples = samples,
            .avg_rss_bytes = total_rss / n,
            .avg_cpu_percent = total_cpu / @as(f64, @floatFromInt(n)),
            .avg_fd_count = total_fd / n,
        };
    }

    pub fn print(self: OverheadBenchResult, writer: anytype) !void {
        try writer.print("\n╔═══════════════════════════════════════════════════════════════════╗\n", .{});
        try writer.print("║           Idle Container Overhead Summary                         ║\n", .{});
        try writer.print("╠═══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Samples:           {d: >44}  ║\n", .{self.samples.len});
        try writer.print("║ Average RSS:       {d: >40} KB  ║\n", .{self.avg_rss_bytes / 1024});
        try writer.print("║ Average RSS:       {d: >40.2} MB  ║\n", .{@as(f64, @floatFromInt(self.avg_rss_bytes)) / (1024.0 * 1024.0)});
        try writer.print("║ Average CPU:       {d: >41.4}%  ║\n", .{self.avg_cpu_percent});
        try writer.print("║ Average FDs:       {d: >44}  ║\n", .{self.avg_fd_count});
        try writer.print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    }
};

// =============================================================================
// Unit Tests
// =============================================================================

test "MemoryStats.diff" {
    const baseline = MemoryStats{
        .rss_bytes = 1000,
        .vms_bytes = 2000,
        .shared_bytes = 500,
        .data_bytes = 300,
        .peak_rss_bytes = 1500,
    };

    const current = MemoryStats{
        .rss_bytes = 1500,
        .vms_bytes = 2500,
        .shared_bytes = 600,
        .data_bytes = 400,
        .peak_rss_bytes = 2000,
    };

    const diff = current.diff(baseline);

    try std.testing.expectEqual(@as(u64, 500), diff.rss_bytes);
    try std.testing.expectEqual(@as(u64, 500), diff.vms_bytes);
    try std.testing.expectEqual(@as(u64, 100), diff.shared_bytes);
}

test "CpuStats.diff" {
    const baseline = CpuStats{
        .user_ns = 1_000_000,
        .system_ns = 500_000,
        .total_ns = 1_500_000,
    };

    const current = CpuStats{
        .user_ns = 2_000_000,
        .system_ns = 700_000,
        .total_ns = 2_700_000,
    };

    const diff = current.diff(baseline);

    try std.testing.expectEqual(@as(u64, 1_000_000), diff.user_ns);
    try std.testing.expectEqual(@as(u64, 200_000), diff.system_ns);
    try std.testing.expectEqual(@as(u64, 1_200_000), diff.total_ns);
}

test "OverheadStats.toJson" {
    const allocator = std.testing.allocator;

    const stats = OverheadStats{
        .memory = .{
            .rss_bytes = 1024 * 1024,
            .vms_bytes = 2048 * 1024,
        },
        .cpu = .{
            .user_ns = 1_000_000,
            .system_ns = 500_000,
            .total_ns = 1_500_000,
            .usage_percent = 0.15,
        },
        .fd_count = 10,
        .thread_count = 1,
        .duration_ns = 1_000_000_000,
    };

    const json = try stats.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"rss_bytes\": 1048576") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fd_count\": 10") != null);
}

test "OverheadBenchResult.calculate" {
    const samples = [_]OverheadStats{
        .{
            .memory = .{ .rss_bytes = 1000 },
            .cpu = .{ .usage_percent = 0.1 },
            .fd_count = 10,
        },
        .{
            .memory = .{ .rss_bytes = 2000 },
            .cpu = .{ .usage_percent = 0.2 },
            .fd_count = 12,
        },
        .{
            .memory = .{ .rss_bytes = 1500 },
            .cpu = .{ .usage_percent = 0.15 },
            .fd_count = 11,
        },
    };

    const result = OverheadBenchResult.calculate(&samples);

    try std.testing.expectEqual(@as(u64, 1500), result.avg_rss_bytes);
    try std.testing.expectEqual(@as(u64, 11), result.avg_fd_count);
}
