//! Container Startup Benchmark
//!
//! Measures cold container start time, which includes:
//! - Namespace creation (clone/unshare)
//! - Filesystem setup (pivot_root/chroot, mounts)
//! - Network configuration (if enabled)
//! - Cgroup setup (if enabled)
//! - Process execution until first instruction
//!
//! This benchmark is critical for understanding container latency
//! in serverless/FaaS workloads where cold starts impact user experience.

const std = @import("std");
const builtin = @import("builtin");

/// Benchmark result statistics
pub const BenchmarkResult = struct {
    /// Name of the benchmark
    name: []const u8,
    /// Number of iterations
    iterations: u64,
    /// Minimum time in nanoseconds
    min_ns: u64,
    /// Maximum time in nanoseconds
    max_ns: u64,
    /// Mean time in nanoseconds
    mean_ns: u64,
    /// Median time in nanoseconds
    median_ns: u64,
    /// Standard deviation in nanoseconds
    stddev_ns: u64,
    /// 95th percentile in nanoseconds
    p95_ns: u64,
    /// 99th percentile in nanoseconds
    p99_ns: u64,
    /// Total time in nanoseconds
    total_ns: u64,

    /// Print formatted benchmark result
    pub fn print(self: BenchmarkResult, writer: anytype) !void {
        try writer.print("\n╔══════════════════════════════════════════════════════════════════╗\n", .{});
        try writer.print("║ Benchmark: {s: <53} ║\n", .{self.name});
        try writer.print("╠══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Iterations: {d: >52} ║\n", .{self.iterations});
        try writer.print("║ Min:        {d: >48} ns ║\n", .{self.min_ns});
        try writer.print("║ Max:        {d: >48} ns ║\n", .{self.max_ns});
        try writer.print("║ Mean:       {d: >48} ns ║\n", .{self.mean_ns});
        try writer.print("║ Median:     {d: >48} ns ║\n", .{self.median_ns});
        try writer.print("║ Stddev:     {d: >48} ns ║\n", .{self.stddev_ns});
        try writer.print("║ P95:        {d: >48} ns ║\n", .{self.p95_ns});
        try writer.print("║ P99:        {d: >48} ns ║\n", .{self.p99_ns});
        try writer.print("╠══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Mean (ms):  {d: >48.3} ║\n", .{@as(f64, @floatFromInt(self.mean_ns)) / 1_000_000.0});
        try writer.print("║ Mean (μs):  {d: >48.3} ║\n", .{@as(f64, @floatFromInt(self.mean_ns)) / 1_000.0});
        try writer.print("╚══════════════════════════════════════════════════════════════════╝\n", .{});
    }

    /// Export as JSON
    pub fn toJson(self: BenchmarkResult, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayListUnmanaged(u8) = .{};
        const writer = list.writer(allocator);

        try writer.print(
            \\{{
            \\  "name": "{s}",
            \\  "iterations": {d},
            \\  "min_ns": {d},
            \\  "max_ns": {d},
            \\  "mean_ns": {d},
            \\  "median_ns": {d},
            \\  "stddev_ns": {d},
            \\  "p95_ns": {d},
            \\  "p99_ns": {d},
            \\  "total_ns": {d},
            \\  "mean_ms": {d:.3},
            \\  "mean_us": {d:.3}
            \\}}
        , .{
            self.name,
            self.iterations,
            self.min_ns,
            self.max_ns,
            self.mean_ns,
            self.median_ns,
            self.stddev_ns,
            self.p95_ns,
            self.p99_ns,
            self.total_ns,
            @as(f64, @floatFromInt(self.mean_ns)) / 1_000_000.0,
            @as(f64, @floatFromInt(self.mean_ns)) / 1_000.0,
        });

        return list.toOwnedSlice(allocator);
    }
};

/// Benchmark runner configuration
pub const BenchmarkConfig = struct {
    /// Number of warmup iterations (not measured)
    warmup_iterations: u32 = 3,
    /// Number of measured iterations
    iterations: u32 = 10,
    /// Whether to print progress
    verbose: bool = true,
    /// Output format
    output_format: enum { text, json } = .text,
};

/// Generic benchmark runner
pub const BenchmarkRunner = struct {
    allocator: std.mem.Allocator,
    config: BenchmarkConfig,
    samples: std.ArrayListUnmanaged(u64),

    pub fn init(allocator: std.mem.Allocator, bench_config: BenchmarkConfig) BenchmarkRunner {
        return .{
            .allocator = allocator,
            .config = bench_config,
            .samples = .{},
        };
    }

    pub fn deinit(self: *BenchmarkRunner) void {
        self.samples.deinit(self.allocator);
    }

    /// Run a benchmark function and collect statistics
    pub fn run(
        self: *BenchmarkRunner,
        name: []const u8,
        comptime bench_fn: fn (*BenchmarkRunner) anyerror!void,
    ) !BenchmarkResult {
        self.samples.clearRetainingCapacity();
        try self.samples.ensureTotalCapacity(self.allocator, self.config.iterations);

        var stdout_buffer: [4096]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        // Warmup iterations
        if (self.config.verbose) {
            try stdout.print("Running warmup ({d} iterations)...\n", .{self.config.warmup_iterations});
        }

        for (0..self.config.warmup_iterations) |_| {
            _ = try bench_fn(self);
        }

        // Measured iterations
        if (self.config.verbose) {
            try stdout.print("Running benchmark '{s}' ({d} iterations)...\n", .{ name, self.config.iterations });
        }

        for (0..self.config.iterations) |i| {
            const start = std.time.nanoTimestamp();
            try bench_fn(self);
            const end = std.time.nanoTimestamp();

            const elapsed: u64 = @intCast(end - start);
            try self.samples.append(self.allocator, elapsed);

            if (self.config.verbose and (i + 1) % 5 == 0) {
                try stdout.print("  Progress: {d}/{d} iterations\n", .{ i + 1, self.config.iterations });
            }
        }

        // Calculate statistics
        return self.calculateStats(name);
    }

    fn calculateStats(self: *BenchmarkRunner, name: []const u8) BenchmarkResult {
        const samples = self.samples.items;

        if (samples.len == 0) {
            return BenchmarkResult{
                .name = name,
                .iterations = 0,
                .min_ns = 0,
                .max_ns = 0,
                .mean_ns = 0,
                .median_ns = 0,
                .stddev_ns = 0,
                .p95_ns = 0,
                .p99_ns = 0,
                .total_ns = 0,
            };
        }

        // Sort for percentiles
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));

        // Calculate min, max, total
        var min_ns: u64 = std.math.maxInt(u64);
        var max_ns: u64 = 0;
        var total_ns: u64 = 0;

        for (samples) |s| {
            min_ns = @min(min_ns, s);
            max_ns = @max(max_ns, s);
            total_ns += s;
        }

        const n = samples.len;
        const mean_ns = total_ns / n;

        // Median
        const median_ns = if (n % 2 == 0)
            (samples[n / 2 - 1] + samples[n / 2]) / 2
        else
            samples[n / 2];

        // Standard deviation
        var variance_sum: u128 = 0;
        for (samples) |s| {
            const diff: i128 = @as(i128, @intCast(s)) - @as(i128, @intCast(mean_ns));
            variance_sum += @intCast(@abs(diff * diff));
        }
        const variance = variance_sum / n;
        const stddev_ns: u64 = @intCast(std.math.sqrt(variance));

        // Percentiles
        const p95_idx = (n * 95) / 100;
        const p99_idx = (n * 99) / 100;

        return BenchmarkResult{
            .name = name,
            .iterations = n,
            .min_ns = min_ns,
            .max_ns = max_ns,
            .mean_ns = mean_ns,
            .median_ns = median_ns,
            .stddev_ns = stddev_ns,
            .p95_ns = samples[@min(p95_idx, n - 1)],
            .p99_ns = samples[@min(p99_idx, n - 1)],
            .total_ns = total_ns,
        };
    }
};

/// Cold container start benchmark configuration
pub const ContainerStartBenchConfig = struct {
    /// Path to rootfs directory
    rootfs_path: []const u8,
    /// Command to run in container (should exit quickly)
    command: []const u8 = "/bin/true",
    /// Enable network namespace
    enable_network: bool = false,
    /// Enable user namespace (rootless)
    enable_userns: bool = false,
    /// Enable cgroup limits
    enable_cgroup: bool = false,
    /// Memory limit (if cgroup enabled)
    memory_limit: u64 = 0,
    /// CPU quota (if cgroup enabled)
    cpu_quota: u64 = 0,
};

/// Run cold container start benchmark
/// Measures time from container configuration to process exit
/// Uses external isolazi binary for accurate measurement
pub fn benchmarkColdContainerStart(
    allocator: std.mem.Allocator,
    bench_config: BenchmarkConfig,
    container_config: ContainerStartBenchConfig,
) !BenchmarkResult {
    // Only run on Linux
    if (builtin.os.tag != .linux) {
        std.debug.print("Container start benchmark only available on Linux\n", .{});
        return BenchmarkResult{
            .name = "cold_container_start",
            .iterations = 0,
            .min_ns = 0,
            .max_ns = 0,
            .mean_ns = 0,
            .median_ns = 0,
            .stddev_ns = 0,
            .p95_ns = 0,
            .p99_ns = 0,
            .total_ns = 0,
        };
    }

    var runner = BenchmarkRunner.init(allocator, bench_config);
    defer runner.deinit();

    // Store config for benchmark function
    const Context = struct {
        var config_ref: ContainerStartBenchConfig = undefined;
        var alloc_ref: std.mem.Allocator = undefined;

        fn bench(r: *BenchmarkRunner) anyerror!void {
            _ = r;
            // Run isolazi container via command line
            // This provides accurate end-to-end timing
            const result = std.process.Child.run(.{
                .allocator = alloc_ref,
                .argv = &[_][]const u8{
                    "isolazi",
                    "run",
                    "--rootfs",
                    config_ref.rootfs_path,
                    "--",
                    config_ref.command,
                },
            }) catch |err| {
                std.debug.print("Failed to run container: {}\n", .{err});
                return err;
            };
            defer alloc_ref.free(result.stdout);
            defer alloc_ref.free(result.stderr);

            if (result.term.Exited != 0) {
                std.debug.print("Container exited with code: {d}\n", .{result.term.Exited});
            }
        }
    };

    Context.config_ref = container_config;
    Context.alloc_ref = allocator;

    return runner.run("cold_container_start", Context.bench);
}

/// Benchmark configuration presets
pub const BenchmarkPresets = struct {
    /// Quick benchmark for CI/CD
    pub const quick = BenchmarkConfig{
        .warmup_iterations = 1,
        .iterations = 5,
        .verbose = true,
    };

    /// Standard benchmark for development
    pub const standard = BenchmarkConfig{
        .warmup_iterations = 3,
        .iterations = 20,
        .verbose = true,
    };

    /// Thorough benchmark for releases
    pub const thorough = BenchmarkConfig{
        .warmup_iterations = 5,
        .iterations = 100,
        .verbose = true,
    };
};

// =============================================================================
// Unit Tests
// =============================================================================

test "BenchmarkResult.toJson" {
    const allocator = std.testing.allocator;

    const result = BenchmarkResult{
        .name = "test_bench",
        .iterations = 10,
        .min_ns = 1000,
        .max_ns = 5000,
        .mean_ns = 2500,
        .median_ns = 2400,
        .stddev_ns = 500,
        .p95_ns = 4500,
        .p99_ns = 4900,
        .total_ns = 25000,
    };

    const json = try result.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\": \"test_bench\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"iterations\": 10") != null);
}

test "BenchmarkRunner statistics calculation" {
    const allocator = std.testing.allocator;

    var runner = BenchmarkRunner.init(allocator, .{
        .warmup_iterations = 0,
        .iterations = 5,
        .verbose = false,
    });
    defer runner.deinit();

    // Manually add samples
    try runner.samples.append(100);
    try runner.samples.append(200);
    try runner.samples.append(300);
    try runner.samples.append(400);
    try runner.samples.append(500);

    const stats = runner.calculateStats("test");

    try std.testing.expectEqual(@as(u64, 5), stats.iterations);
    try std.testing.expectEqual(@as(u64, 100), stats.min_ns);
    try std.testing.expectEqual(@as(u64, 500), stats.max_ns);
    try std.testing.expectEqual(@as(u64, 300), stats.mean_ns); // (100+200+300+400+500)/5
    try std.testing.expectEqual(@as(u64, 300), stats.median_ns); // middle value
    try std.testing.expectEqual(@as(u64, 1500), stats.total_ns);
}
