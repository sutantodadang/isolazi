//! Benchmark Runner
//!
//! Command-line tool for running isolazi benchmarks.
//! Supports running individual benchmarks or the full suite.
//!
//! Usage:
//!   zig-out/bin/isolazi-bench [options] <benchmark>
//!
//! Benchmarks:
//!   all              - Run all benchmarks
//!   container-start  - Cold container start time
//!   overhead         - Memory & CPU overhead for idle container
//!   layer            - Layer extraction speed
//!
//! Options:
//!   --iterations <n>  - Number of benchmark iterations (default: 10)
//!   --warmup <n>      - Number of warmup iterations (default: 3)
//!   --output <file>   - Write JSON results to file
//!   --rootfs <path>   - Path to rootfs for container benchmarks
//!   --layer <path>    - Path to layer file for extraction benchmark
//!   --verbose         - Enable verbose output
//!   --help            - Show this help message

const std = @import("std");
const builtin = @import("builtin");

const container_bench = @import("container_bench.zig");
const overhead_bench = @import("overhead_bench.zig");
const layer_bench = @import("layer_bench.zig");

const BenchmarkResult = container_bench.BenchmarkResult;
const BenchmarkConfig = container_bench.BenchmarkConfig;
const BenchmarkPresets = container_bench.BenchmarkPresets;

/// Command line options
const Options = struct {
    benchmark: []const u8 = "all",
    iterations: u32 = 10,
    warmup: u32 = 3,
    output_file: ?[]const u8 = null,
    rootfs_path: ?[]const u8 = null,
    layer_path: ?[]const u8 = null,
    verbose: bool = true,
    show_help: bool = false,
};

fn printUsage(writer: anytype) !void {
    try writer.print(
        \\
        \\isolazi-bench - Benchmark suite for isolazi container runtime
        \\
        \\USAGE:
        \\    isolazi-bench [OPTIONS] <BENCHMARK>
        \\
        \\BENCHMARKS:
        \\    all              Run all available benchmarks
        \\    container-start  Measure cold container startup time
        \\    overhead         Measure memory & CPU overhead for idle containers
        \\    layer            Measure OCI layer extraction speed
        \\
        \\OPTIONS:
        \\    -i, --iterations <N>   Number of benchmark iterations (default: 10)
        \\    -w, --warmup <N>       Number of warmup iterations (default: 3)
        \\    -o, --output <FILE>    Write JSON results to file
        \\    -r, --rootfs <PATH>    Path to rootfs directory (required for container benchmarks)
        \\    -l, --layer <PATH>     Path to layer file (required for layer benchmark)
        \\    -v, --verbose          Enable verbose output
        \\    -h, --help             Show this help message
        \\
        \\EXAMPLES:
        \\    # Run all benchmarks
        \\    isolazi-bench all --rootfs /path/to/rootfs --layer /path/to/layer.tar.gz
        \\
        \\    # Run container start benchmark with 20 iterations
        \\    isolazi-bench container-start --rootfs /path/to/rootfs -i 20
        \\
        \\    # Run layer extraction benchmark and save results
        \\    isolazi-bench layer --layer /path/to/layer.tar.gz -o results.json
        \\
        \\NOTES:
        \\    - Container benchmarks require Linux with namespace support
        \\    - Root privileges may be required for some benchmarks
        \\    - Results are affected by system load; run on idle system for accuracy
        \\
        \\
    , .{});
}

fn parseArgs(allocator: std.mem.Allocator) !Options {
    var opts = Options{};

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip(); // Skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            opts.show_help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            opts.verbose = true;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--iterations")) {
            if (args.next()) |val| {
                opts.iterations = std.fmt.parseInt(u32, val, 10) catch 10;
            }
        } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--warmup")) {
            if (args.next()) |val| {
                opts.warmup = std.fmt.parseInt(u32, val, 10) catch 3;
            }
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            opts.output_file = args.next();
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--rootfs")) {
            opts.rootfs_path = args.next();
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--layer")) {
            opts.layer_path = args.next();
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            opts.benchmark = arg;
        }
    }

    return opts;
}

/// All benchmark results aggregated
const AllResults = struct {
    container_start: ?BenchmarkResult = null,
    layer_extraction: ?layer_bench.LayerExtractionBenchResult = null,
    timestamp: i64 = 0,
    system_info: SystemInfo = .{},

    const SystemInfo = struct {
        os: []const u8 = "unknown",
        arch: []const u8 = "unknown",
        cpu_count: u32 = 0,
    };

    pub fn toJson(self: AllResults, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayListUnmanaged(u8) = .{};
        const writer = list.writer(allocator);

        try writer.print("{{", .{});
        try writer.print("\n  \"timestamp\": {d},", .{self.timestamp});
        try writer.print("\n  \"system\": {{", .{});
        try writer.print("\n    \"os\": \"{s}\",", .{self.system_info.os});
        try writer.print("\n    \"arch\": \"{s}\",", .{self.system_info.arch});
        try writer.print("\n    \"cpu_count\": {d}", .{self.system_info.cpu_count});
        try writer.print("\n  }},", .{});

        try writer.print("\n  \"benchmarks\": {{", .{});

        var has_prev = false;

        if (self.container_start) |cs| {
            if (has_prev) try writer.print(",", .{});
            try writer.print("\n    \"container_start\": {{", .{});
            try writer.print("\n      \"iterations\": {d},", .{cs.iterations});
            try writer.print("\n      \"min_ns\": {d},", .{cs.min_ns});
            try writer.print("\n      \"max_ns\": {d},", .{cs.max_ns});
            try writer.print("\n      \"mean_ns\": {d},", .{cs.mean_ns});
            try writer.print("\n      \"median_ns\": {d},", .{cs.median_ns});
            try writer.print("\n      \"stddev_ns\": {d},", .{cs.stddev_ns});
            try writer.print("\n      \"p95_ns\": {d},", .{cs.p95_ns});
            try writer.print("\n      \"p99_ns\": {d},", .{cs.p99_ns});
            try writer.print("\n      \"mean_ms\": {d:.3}", .{@as(f64, @floatFromInt(cs.mean_ns)) / 1_000_000.0});
            try writer.print("\n    }}", .{});
            has_prev = true;
        }

        if (self.layer_extraction) |le| {
            if (has_prev) try writer.print(",", .{});
            try writer.print("\n    \"layer_extraction\": {{", .{});
            try writer.print("\n      \"iterations\": {d},", .{le.samples.len});
            try writer.print("\n      \"compressed_size_bytes\": {d},", .{le.compressed_size});
            try writer.print("\n      \"extracted_size_bytes\": {d},", .{le.extracted_size});
            try writer.print("\n      \"min_time_ns\": {d},", .{le.min_time_ns});
            try writer.print("\n      \"max_time_ns\": {d},", .{le.max_time_ns});
            try writer.print("\n      \"mean_time_ns\": {d},", .{le.mean_time_ns});
            try writer.print("\n      \"mean_time_ms\": {d:.2},", .{@as(f64, @floatFromInt(le.mean_time_ns)) / 1_000_000.0});
            try writer.print("\n      \"avg_throughput_compressed_mbps\": {d:.2},", .{le.avg_throughput_compressed_mbps});
            try writer.print("\n      \"avg_throughput_extracted_mbps\": {d:.2}", .{le.avg_throughput_extracted_mbps});
            try writer.print("\n    }}", .{});
        }
        try writer.print("\n  }}", .{});
        try writer.print("\n}}\n", .{});

        return list.toOwnedSlice(allocator);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get stdout writer using Zig 0.15+ API
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const opts = try parseArgs(allocator);

    if (opts.show_help) {
        try printUsage(stdout);
        try stdout.flush();
        return;
    }

    // Print banner
    try stdout.print(
        \\
        \\╔═══════════════════════════════════════════════════════════════════╗
        \\║                    isolazi Benchmark Suite                        ║
        \\║                                                                   ║
        \\║  Measuring container performance metrics                          ║
        \\╚═══════════════════════════════════════════════════════════════════╝
        \\
        \\
    , .{});

    var results = AllResults{
        .timestamp = std.time.timestamp(),
        .system_info = .{
            .os = @tagName(builtin.os.tag),
            .arch = @tagName(builtin.cpu.arch),
            .cpu_count = @as(u32, @intCast(std.Thread.getCpuCount() catch 1)),
        },
    };

    const bench_config = BenchmarkConfig{
        .warmup_iterations = opts.warmup,
        .iterations = opts.iterations,
        .verbose = opts.verbose,
    };

    // Run requested benchmarks
    const run_all = std.mem.eql(u8, opts.benchmark, "all");

    // Container start benchmark
    if (run_all or std.mem.eql(u8, opts.benchmark, "container-start")) {
        if (opts.rootfs_path) |rootfs| {
            try stdout.print("\n=== Running Container Start Benchmark ===\n", .{});

            const container_config = container_bench.ContainerStartBenchConfig{
                .rootfs_path = rootfs,
                .command = "/bin/true",
                .enable_network = false,
                .enable_userns = false,
                .enable_cgroup = false,
            };

            if (builtin.os.tag == .linux) {
                results.container_start = container_bench.benchmarkColdContainerStart(
                    allocator,
                    bench_config,
                    container_config,
                ) catch |err| blk: {
                    try stdout.print("Container start benchmark failed: {}\n", .{err});
                    break :blk null;
                };

                if (results.container_start) |cs| {
                    try cs.print(stdout);
                }
            } else {
                try stdout.print("Container start benchmark only available on Linux\n", .{});
            }
        } else if (!run_all) {
            try stdout.print("Error: --rootfs required for container-start benchmark\n", .{});
            return;
        }
    }

    // Layer extraction benchmark
    if (run_all or std.mem.eql(u8, opts.benchmark, "layer")) {
        if (opts.layer_path) |layer_path| {
            try stdout.print("\n=== Running Layer Extraction Benchmark ===\n", .{});

            const layer_config = layer_bench.LayerBenchConfig{
                .layer_path = layer_path,
                .target_dir = "/tmp/isolazi-bench-extract",
                .clean_before_extract = true,
                .iterations = opts.iterations,
                .warmup_iterations = opts.warmup,
            };

            results.layer_extraction = layer_bench.benchmarkLayerExtraction(
                allocator,
                layer_config,
            ) catch |err| blk: {
                try stdout.print("Layer extraction benchmark failed: {}\n", .{err});
                break :blk null;
            };

            if (results.layer_extraction) |le| {
                try le.print(stdout);
            }
        } else if (!run_all) {
            try stdout.print("Error: --layer required for layer benchmark\n", .{});
            return;
        }
    }

    // Overhead benchmark info
    if (run_all or std.mem.eql(u8, opts.benchmark, "overhead")) {
        try stdout.print("\n=== Overhead Benchmark ===\n", .{});
        try stdout.print("Note: Overhead benchmark requires a running container.\n", .{});
        try stdout.print("Use the overhead_bench module programmatically with a container PID.\n", .{});
        try stdout.print("Example:\n", .{});
        try stdout.print("  const stats = overhead_bench.measureIdleOverhead(allocator, container_pid, 5000);\n", .{});
    }

    // Write JSON output if requested
    if (opts.output_file) |output_path| {
        const json = try results.toJson(allocator);
        defer allocator.free(json);

        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();
        try file.writeAll(json);

        try stdout.print("\nResults written to: {s}\n", .{output_path});
    }

    // Print summary
    try stdout.print(
        \\
        \\╔═══════════════════════════════════════════════════════════════════╗
        \\║                     Benchmark Complete                            ║
        \\╚═══════════════════════════════════════════════════════════════════╝
        \\
        \\
    , .{});
    try stdout.flush();
}
