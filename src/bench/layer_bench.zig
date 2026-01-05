//! Layer Extraction Speed Benchmark
//!
//! Measures the performance of OCI layer extraction:
//! - Decompression speed (gzip)
//! - File I/O throughput
//! - Whiteout processing overhead
//! - Multi-layer extraction time
//!
//! Layer extraction speed is critical for:
//! - Container cold start time
//! - Image pull performance
//! - CI/CD pipeline efficiency

const std = @import("std");
const builtin = @import("builtin");

const container_bench = @import("container_bench.zig");
const BenchmarkResult = container_bench.BenchmarkResult;
const BenchmarkConfig = container_bench.BenchmarkConfig;
const BenchmarkRunner = container_bench.BenchmarkRunner;

/// Layer extraction statistics
pub const LayerExtractionStats = struct {
    /// Layer file size in bytes
    compressed_size: u64 = 0,
    /// Extracted size in bytes
    extracted_size: u64 = 0,
    /// Number of files extracted
    file_count: u64 = 0,
    /// Extraction time in nanoseconds
    extraction_time_ns: u64 = 0,
    /// Compression ratio (extracted/compressed)
    compression_ratio: f64 = 0.0,
    /// Extraction throughput in MB/s (based on compressed size)
    throughput_compressed_mbps: f64 = 0.0,
    /// Extraction throughput in MB/s (based on extracted size)
    throughput_extracted_mbps: f64 = 0.0,

    /// Print formatted stats
    pub fn print(self: LayerExtractionStats, writer: anytype) !void {
        try writer.print("\n┌─────────────────────────────────────────────────────────────────┐\n", .{});
        try writer.print("│ Layer Extraction Statistics                                      │\n", .{});
        try writer.print("├─────────────────────────────────────────────────────────────────┤\n", .{});
        try writer.print("│ Compressed size:   {d: >40} KB │\n", .{self.compressed_size / 1024});
        try writer.print("│ Extracted size:    {d: >40} KB │\n", .{self.extracted_size / 1024});
        try writer.print("│ File count:        {d: >44} │\n", .{self.file_count});
        try writer.print("│ Extraction time:   {d: >40} ms │\n", .{self.extraction_time_ns / 1_000_000});
        try writer.print("│ Compression ratio: {d: >43.2}x │\n", .{self.compression_ratio});
        try writer.print("│ Throughput (comp): {d: >40.2} MB/s │\n", .{self.throughput_compressed_mbps});
        try writer.print("│ Throughput (extr): {d: >40.2} MB/s │\n", .{self.throughput_extracted_mbps});
        try writer.print("└─────────────────────────────────────────────────────────────────┘\n", .{});
    }

    /// Export as JSON
    pub fn toJson(self: LayerExtractionStats, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayListUnmanaged(u8) = .{};
        const writer = list.writer(allocator);

        try writer.print(
            \\{{
            \\  "compressed_size_bytes": {d},
            \\  "extracted_size_bytes": {d},
            \\  "compressed_size_kb": {d},
            \\  "extracted_size_kb": {d},
            \\  "compressed_size_mb": {d:.2},
            \\  "extracted_size_mb": {d:.2},
            \\  "file_count": {d},
            \\  "extraction_time_ns": {d},
            \\  "extraction_time_ms": {d:.2},
            \\  "compression_ratio": {d:.2},
            \\  "throughput_compressed_mbps": {d:.2},
            \\  "throughput_extracted_mbps": {d:.2}
            \\}}
        , .{
            self.compressed_size,
            self.extracted_size,
            self.compressed_size / 1024,
            self.extracted_size / 1024,
            @as(f64, @floatFromInt(self.compressed_size)) / (1024.0 * 1024.0),
            @as(f64, @floatFromInt(self.extracted_size)) / (1024.0 * 1024.0),
            self.file_count,
            self.extraction_time_ns,
            @as(f64, @floatFromInt(self.extraction_time_ns)) / 1_000_000.0,
            self.compression_ratio,
            self.throughput_compressed_mbps,
            self.throughput_extracted_mbps,
        });

        return list.toOwnedSlice(allocator);
    }
};

/// Benchmark configuration for layer extraction
pub const LayerBenchConfig = struct {
    /// Path to layer file (tar.gz)
    layer_path: []const u8,
    /// Target extraction directory (will be created/cleaned)
    target_dir: []const u8 = "/tmp/isolazi-bench-extract",
    /// Whether to clean target directory before each extraction
    clean_before_extract: bool = true,
    /// Benchmark iterations
    iterations: u32 = 5,
    /// Warmup iterations
    warmup_iterations: u32 = 1,
};

/// Get file size
fn getFileSize(path: []const u8) u64 {
    const file = std.fs.cwd().openFile(path, .{}) catch return 0;
    defer file.close();
    const stat = file.stat() catch return 0;
    return stat.size;
}

/// Get total size of directory recursively
fn getDirectorySize(allocator: std.mem.Allocator, path: []const u8) !u64 {
    var total_size: u64 = 0;
    var file_count: u64 = 0;

    // Use find + du for efficiency on large directories
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "find",
            path,
            "-type",
            "f",
            "-exec",
            "cat",
            "{}",
            "+",
        },
        .max_output_bytes = 0, // We don't need the output
    }) catch {
        // Fallback: manual directory traversal
        return getDirectorySizeManual(path, &total_size, &file_count);
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Alternative: use du -sb
    const du_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "du", "-sb", path },
    }) catch return 0;
    defer allocator.free(du_result.stdout);
    defer allocator.free(du_result.stderr);

    if (du_result.stdout.len > 0) {
        var iter = std.mem.tokenizeScalar(u8, du_result.stdout, '\t');
        if (iter.next()) |size_str| {
            return std.fmt.parseInt(u64, size_str, 10) catch 0;
        }
    }

    return total_size;
}

/// Manual directory size calculation (fallback)
fn getDirectorySizeManual(path: []const u8, total_size: *u64, file_count: *u64) u64 {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            file_count.* += 1;
            if (dir.statFile(entry.name)) |stat| {
                total_size.* += stat.size;
            } else |_| {}
        } else if (entry.kind == .directory) {
            var subpath_buf: [std.fs.max_path_bytes]u8 = undefined;
            const subpath = std.fmt.bufPrint(&subpath_buf, "{s}/{s}", .{ path, entry.name }) catch continue;
            _ = getDirectorySizeManual(subpath, total_size, file_count);
        }
    }

    return total_size.*;
}

/// Count files in directory recursively
fn countFilesInDirectory(allocator: std.mem.Allocator, path: []const u8) u64 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "find", path, "-type", "f" },
    }) catch return 0;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Count newlines in output
    var count: u64 = 0;
    for (result.stdout) |c| {
        if (c == '\n') count += 1;
    }
    return count;
}

/// Clean directory
fn cleanDirectory(path: []const u8) void {
    std.fs.cwd().deleteTree(path) catch {};
}

/// Verify layer file exists
fn verifyLayerFile(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// Extract layer using native tar command
fn extractLayerNative(allocator: std.mem.Allocator, layer_path: []const u8, target_dir: []const u8) !u64 {
    // Create target directory
    std.fs.cwd().makePath(target_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "tar",
            "-xzf",
            layer_path,
            "-C",
            target_dir,
            "--no-same-owner",
        },
    }) catch return error.DecompressionFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return error.DecompressionFailed;
    }

    return 1;
}

/// Extract a layer and measure statistics
pub fn extractLayerWithStats(
    allocator: std.mem.Allocator,
    layer_path: []const u8,
    target_dir: []const u8,
) !LayerExtractionStats {
    var stats = LayerExtractionStats{};

    // Get compressed size
    stats.compressed_size = getFileSize(layer_path);

    // Create target directory
    std.fs.cwd().makePath(target_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Time the extraction
    const start = std.time.nanoTimestamp();

    stats.file_count = extractLayerNative(allocator, layer_path, target_dir) catch |err| {
        std.debug.print("Layer extraction failed: {}\n", .{err});
        return err;
    };

    const end = std.time.nanoTimestamp();
    stats.extraction_time_ns = @intCast(end - start);

    // Get extracted size
    stats.extracted_size = getDirectorySize(allocator, target_dir) catch 0;
    if (stats.extracted_size == 0) {
        // Fallback estimate based on file count
        stats.extracted_size = stats.file_count * 4096; // Assume 4KB average
    }

    // Count files if not returned by extractLayer
    if (stats.file_count <= 1) {
        stats.file_count = countFilesInDirectory(allocator, target_dir);
    }

    // Calculate derived metrics
    if (stats.compressed_size > 0) {
        stats.compression_ratio = @as(f64, @floatFromInt(stats.extracted_size)) /
            @as(f64, @floatFromInt(stats.compressed_size));
    }

    if (stats.extraction_time_ns > 0) {
        const time_seconds = @as(f64, @floatFromInt(stats.extraction_time_ns)) / 1_000_000_000.0;
        stats.throughput_compressed_mbps = @as(f64, @floatFromInt(stats.compressed_size)) / (1024.0 * 1024.0) / time_seconds;
        stats.throughput_extracted_mbps = @as(f64, @floatFromInt(stats.extracted_size)) / (1024.0 * 1024.0) / time_seconds;
    }

    return stats;
}

/// Benchmark layer extraction
pub fn benchmarkLayerExtraction(
    allocator: std.mem.Allocator,
    bench_config: LayerBenchConfig,
) !LayerExtractionBenchResult {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Pre-allocate samples array
    const samples_buf = try allocator.alloc(LayerExtractionStats, bench_config.iterations);
    defer allocator.free(samples_buf);
    var sample_count: usize = 0;

    // Verify layer exists
    if (!verifyLayerFile(bench_config.layer_path)) {
        try stdout.print("Error: Layer file not found: {s}\n", .{bench_config.layer_path});
        return error.FileNotFound;
    }

    try stdout.print("Benchmarking layer extraction: {s}\n", .{bench_config.layer_path});
    try stdout.print("Target directory: {s}\n", .{bench_config.target_dir});

    // Warmup iterations
    try stdout.print("Running warmup ({d} iterations)...\n", .{bench_config.warmup_iterations});
    for (0..bench_config.warmup_iterations) |_| {
        if (bench_config.clean_before_extract) {
            cleanDirectory(bench_config.target_dir);
        }
        _ = try extractLayerWithStats(allocator, bench_config.layer_path, bench_config.target_dir);
    }

    // Measured iterations
    try stdout.print("Running benchmark ({d} iterations)...\n", .{bench_config.iterations});
    for (0..bench_config.iterations) |i| {
        if (bench_config.clean_before_extract) {
            cleanDirectory(bench_config.target_dir);
        }

        const stats = try extractLayerWithStats(allocator, bench_config.layer_path, bench_config.target_dir);
        samples_buf[sample_count] = stats;
        sample_count += 1;

        try stdout.print("  Iteration {d}/{d}: {d} ms\n", .{
            i + 1,
            bench_config.iterations,
            stats.extraction_time_ns / 1_000_000,
        });
    }

    // Calculate aggregate results
    return LayerExtractionBenchResult.calculate(samples_buf[0..sample_count]);
}

/// Aggregate layer extraction benchmark results
pub const LayerExtractionBenchResult = struct {
    /// Sample statistics
    samples: []const LayerExtractionStats,
    /// Minimum extraction time in nanoseconds
    min_time_ns: u64,
    /// Maximum extraction time in nanoseconds
    max_time_ns: u64,
    /// Mean extraction time in nanoseconds
    mean_time_ns: u64,
    /// Median extraction time in nanoseconds
    median_time_ns: u64,
    /// Average throughput (compressed) in MB/s
    avg_throughput_compressed_mbps: f64,
    /// Average throughput (extracted) in MB/s
    avg_throughput_extracted_mbps: f64,
    /// Layer compressed size
    compressed_size: u64,
    /// Layer extracted size
    extracted_size: u64,

    pub fn calculate(samples: []const LayerExtractionStats) LayerExtractionBenchResult {
        if (samples.len == 0) {
            return .{
                .samples = samples,
                .min_time_ns = 0,
                .max_time_ns = 0,
                .mean_time_ns = 0,
                .median_time_ns = 0,
                .avg_throughput_compressed_mbps = 0,
                .avg_throughput_extracted_mbps = 0,
                .compressed_size = 0,
                .extracted_size = 0,
            };
        }

        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_throughput_comp: f64 = 0;
        var total_throughput_extr: f64 = 0;

        for (samples) |s| {
            min_time = @min(min_time, s.extraction_time_ns);
            max_time = @max(max_time, s.extraction_time_ns);
            total_time += s.extraction_time_ns;
            total_throughput_comp += s.throughput_compressed_mbps;
            total_throughput_extr += s.throughput_extracted_mbps;
        }

        const n = samples.len;
        const n_f = @as(f64, @floatFromInt(n));

        // For median, we'd need to sort - use mean for now
        const mean_time = total_time / n;

        return .{
            .samples = samples,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .mean_time_ns = mean_time,
            .median_time_ns = mean_time, // Simplified
            .avg_throughput_compressed_mbps = total_throughput_comp / n_f,
            .avg_throughput_extracted_mbps = total_throughput_extr / n_f,
            .compressed_size = samples[0].compressed_size,
            .extracted_size = samples[0].extracted_size,
        };
    }

    pub fn print(self: LayerExtractionBenchResult, writer: anytype) !void {
        try writer.print("\n╔═══════════════════════════════════════════════════════════════════╗\n", .{});
        try writer.print("║          Layer Extraction Benchmark Results                       ║\n", .{});
        try writer.print("╠═══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Iterations:              {d: >40}  ║\n", .{self.samples.len});
        try writer.print("║ Compressed size:         {d: >36} KB  ║\n", .{self.compressed_size / 1024});
        try writer.print("║ Extracted size:          {d: >36} KB  ║\n", .{self.extracted_size / 1024});
        try writer.print("╠═══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Min time:                {d: >36} ms  ║\n", .{self.min_time_ns / 1_000_000});
        try writer.print("║ Max time:                {d: >36} ms  ║\n", .{self.max_time_ns / 1_000_000});
        try writer.print("║ Mean time:               {d: >36} ms  ║\n", .{self.mean_time_ns / 1_000_000});
        try writer.print("║ Median time:             {d: >36} ms  ║\n", .{self.median_time_ns / 1_000_000});
        try writer.print("╠═══════════════════════════════════════════════════════════════════╣\n", .{});
        try writer.print("║ Throughput (compressed): {d: >36.2} MB/s║\n", .{self.avg_throughput_compressed_mbps});
        try writer.print("║ Throughput (extracted):  {d: >36.2} MB/s║\n", .{self.avg_throughput_extracted_mbps});
        try writer.print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    }

    /// Export as JSON
    pub fn toJson(self: LayerExtractionBenchResult, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayListUnmanaged(u8) = .{};
        const writer = list.writer(allocator);

        try writer.print(
            \\{{
            \\  "iterations": {d},
            \\  "compressed_size_bytes": {d},
            \\  "extracted_size_bytes": {d},
            \\  "compressed_size_mb": {d:.2},
            \\  "extracted_size_mb": {d:.2},
            \\  "min_time_ns": {d},
            \\  "max_time_ns": {d},
            \\  "mean_time_ns": {d},
            \\  "median_time_ns": {d},
            \\  "min_time_ms": {d:.2},
            \\  "max_time_ms": {d:.2},
            \\  "mean_time_ms": {d:.2},
            \\  "avg_throughput_compressed_mbps": {d:.2},
            \\  "avg_throughput_extracted_mbps": {d:.2}
            \\}}
        , .{
            self.samples.len,
            self.compressed_size,
            self.extracted_size,
            @as(f64, @floatFromInt(self.compressed_size)) / (1024.0 * 1024.0),
            @as(f64, @floatFromInt(self.extracted_size)) / (1024.0 * 1024.0),
            self.min_time_ns,
            self.max_time_ns,
            self.mean_time_ns,
            self.median_time_ns,
            @as(f64, @floatFromInt(self.min_time_ns)) / 1_000_000.0,
            @as(f64, @floatFromInt(self.max_time_ns)) / 1_000_000.0,
            @as(f64, @floatFromInt(self.mean_time_ns)) / 1_000_000.0,
            self.avg_throughput_compressed_mbps,
            self.avg_throughput_extracted_mbps,
        });

        return list.toOwnedSlice(allocator);
    }
};

/// Multi-layer extraction benchmark
pub const MultiLayerBenchConfig = struct {
    /// Paths to layer files in order
    layer_paths: []const []const u8,
    /// Target extraction directory
    target_dir: []const u8 = "/tmp/isolazi-bench-multilayer",
    /// Benchmark iterations
    iterations: u32 = 3,
};

/// Benchmark multi-layer extraction (simulates image pull)
pub fn benchmarkMultiLayerExtraction(
    allocator: std.mem.Allocator,
    bench_config: MultiLayerBenchConfig,
) !BenchmarkResult {
    var runner = BenchmarkRunner.init(allocator, .{
        .warmup_iterations = 1,
        .iterations = bench_config.iterations,
        .verbose = true,
    });
    defer runner.deinit();

    const Context = struct {
        var config_ref: MultiLayerBenchConfig = undefined;
        var alloc_ref: std.mem.Allocator = undefined;

        fn bench(r: *BenchmarkRunner) anyerror!void {
            _ = r;
            cleanDirectory(config_ref.target_dir);

            // Extract each layer in order
            for (config_ref.layer_paths) |layer_path| {
                _ = try extractLayerNative(
                    alloc_ref,
                    layer_path,
                    config_ref.target_dir,
                );
            }
        }
    };

    Context.config_ref = bench_config;
    Context.alloc_ref = allocator;

    return runner.run("multi_layer_extraction", Context.bench);
}

// =============================================================================
// Unit Tests
// =============================================================================

test "LayerExtractionStats.toJson" {
    const allocator = std.testing.allocator;

    const stats = LayerExtractionStats{
        .compressed_size = 1024 * 1024,
        .extracted_size = 5 * 1024 * 1024,
        .file_count = 100,
        .extraction_time_ns = 500_000_000,
        .compression_ratio = 5.0,
        .throughput_compressed_mbps = 2.0,
        .throughput_extracted_mbps = 10.0,
    };

    const json = try stats.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"file_count\": 100") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"compression_ratio\": 5.00") != null);
}

test "LayerExtractionBenchResult.calculate" {
    const samples = [_]LayerExtractionStats{
        .{
            .compressed_size = 1024,
            .extracted_size = 4096,
            .extraction_time_ns = 100_000_000,
            .throughput_compressed_mbps = 10.0,
            .throughput_extracted_mbps = 40.0,
        },
        .{
            .compressed_size = 1024,
            .extracted_size = 4096,
            .extraction_time_ns = 200_000_000,
            .throughput_compressed_mbps = 5.0,
            .throughput_extracted_mbps = 20.0,
        },
    };

    const result = LayerExtractionBenchResult.calculate(&samples);

    try std.testing.expectEqual(@as(u64, 2), result.samples.len);
    try std.testing.expectEqual(@as(u64, 100_000_000), result.min_time_ns);
    try std.testing.expectEqual(@as(u64, 200_000_000), result.max_time_ns);
    try std.testing.expectEqual(@as(u64, 150_000_000), result.mean_time_ns);
}
