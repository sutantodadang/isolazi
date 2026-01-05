# isolazi Benchmark Suite

This document describes the benchmark suite for measuring isolazi container runtime performance.

## Overview

The benchmark suite measures three critical performance metrics:

1. **Cold Container Start Time** - Time from container creation to first process instruction
2. **Memory & CPU Overhead** - Resource consumption of idle containers
3. **Layer Extraction Speed** - OCI image layer decompression performance

## Quick Start

### Build Benchmarks

```bash
# Build the benchmark executable
zig build

# The benchmark tool will be at zig-out/bin/isolazi-bench
```

### Run All Benchmarks

```bash
# Run all benchmarks (requires rootfs and layer file)
./zig-out/bin/isolazi-bench all \
    --rootfs /path/to/rootfs \
    --layer /path/to/layer.tar.gz \
    --output results.json
```

### Run Individual Benchmarks

```bash
# Cold container start time
./zig-out/bin/isolazi-bench container-start --rootfs /path/to/rootfs

# Layer extraction speed
./zig-out/bin/isolazi-bench layer --layer /path/to/layer.tar.gz

# Memory & CPU overhead (requires running container)
./zig-out/bin/isolazi-bench overhead
```

## Benchmark Details

### 1. Cold Container Start Time

**What it measures:** The time from when a container is created until the first instruction of the container process executes.

**Components measured:**
- Namespace creation (user, mount, PID, network, UTS, IPC, cgroup)
- Filesystem setup (pivot_root/chroot)
- Mount operations (proc, dev, sys, tmpfs)
- Network configuration (if enabled)
- Cgroup setup (if enabled)
- Process execution setup

**Why it matters:**
- Critical for serverless/FaaS workloads where cold starts impact latency
- Affects container orchestration efficiency
- Determines minimum scheduling granularity

**Expected results:**
| Configuration | Typical Time |
|--------------|--------------|
| Minimal (no network) | 10-50ms |
| With network namespace | 50-150ms |
| With cgroup limits | 20-80ms |
| Full isolation | 100-300ms |

**Usage:**
```bash
./zig-out/bin/isolazi-bench container-start \
    --rootfs /path/to/alpine-rootfs \
    --iterations 20 \
    --warmup 5
```

**Programmatic API:**
```zig
const container_bench = @import("bench").container_bench;

const config = container_bench.ContainerStartBenchConfig{
    .rootfs_path = "/path/to/rootfs",
    .command = "/bin/true",
    .enable_network = false,
    .enable_userns = false,
    .enable_cgroup = true,
};

const result = try container_bench.benchmarkColdContainerStart(
    allocator,
    container_bench.BenchmarkPresets.standard,
    config,
);

try result.print(stdout);
```

### 2. Memory & CPU Overhead

**What it measures:** Resource consumption of an idle container over time.

**Metrics captured:**
- **Memory:**
  - RSS (Resident Set Size) - Physical memory used
  - Virtual memory size
  - Shared memory
  - Peak RSS (high water mark)
- **CPU:**
  - User mode time
  - System mode time
  - CPU usage percentage
- **Other:**
  - File descriptor count
  - Thread count

**Why it matters:**
- Determines container density (containers per host)
- Affects capacity planning
- Identifies memory leaks
- Important for resource billing in cloud environments

**Expected results:**
| Metric | Typical Value |
|--------|---------------|
| Idle RSS | 500KB - 2MB |
| File descriptors | 5-15 |
| CPU usage (idle) | < 0.1% |
| Thread count | 1-3 |

**Programmatic API:**
```zig
const overhead_bench = @import("bench").overhead_bench;

// Measure overhead for an existing container process
const stats = overhead_bench.measureIdleOverhead(
    allocator,
    container_pid,  // PID of container's init process
    5000,           // Measurement duration in milliseconds
);

try stats.print(stdout);

// Get detailed memory stats
const mem_stats = overhead_bench.getProcessMemoryStats(container_pid);
std.debug.print("RSS: {} KB\n", .{mem_stats.rss_bytes / 1024});

// Get CPU stats
const cpu_stats = overhead_bench.getProcessCpuStats(container_pid);
std.debug.print("CPU: {d:.2}%\n", .{cpu_stats.usage_percent});
```

### 3. Layer Extraction Speed

**What it measures:** Performance of extracting OCI image layers (tar.gz archives).

**Metrics captured:**
- Compressed layer size
- Extracted size
- File count
- Extraction time
- Compression ratio
- Throughput (MB/s for both compressed and extracted data)

**Why it matters:**
- Affects image pull time
- Impacts cold start when layers aren't cached
- Important for CI/CD pipelines
- Determines cache effectiveness

**Expected results:**
| Layer Size | Typical Throughput |
|------------|-------------------|
| < 10MB | 100-500 MB/s |
| 10-100MB | 50-200 MB/s |
| > 100MB | 30-100 MB/s |

**Usage:**
```bash
./zig-out/bin/isolazi-bench layer \
    --layer /path/to/layer.tar.gz \
    --iterations 10 \
    --output layer-results.json
```

**Programmatic API:**
```zig
const layer_bench = @import("bench").layer_bench;

// Single layer benchmark
const config = layer_bench.LayerBenchConfig{
    .layer_path = "/path/to/layer.tar.gz",
    .target_dir = "/tmp/extract-bench",
    .clean_before_extract = true,
    .iterations = 10,
    .warmup_iterations = 2,
};

const result = try layer_bench.benchmarkLayerExtraction(allocator, config);
try result.print(stdout);

// Multi-layer benchmark (simulates full image extraction)
const multi_config = layer_bench.MultiLayerBenchConfig{
    .layer_paths = &[_][]const u8{
        "/path/to/base-layer.tar.gz",
        "/path/to/app-layer.tar.gz",
        "/path/to/config-layer.tar.gz",
    },
    .target_dir = "/tmp/multilayer-bench",
    .iterations = 5,
};

const multi_result = try layer_bench.benchmarkMultiLayerExtraction(allocator, multi_config);
try multi_result.print(stdout);
```

## Command Line Reference

```
isolazi-bench [OPTIONS] <BENCHMARK>

BENCHMARKS:
    all              Run all available benchmarks
    container-start  Measure cold container startup time
    overhead         Measure memory & CPU overhead for idle containers
    layer            Measure OCI layer extraction speed

OPTIONS:
    -i, --iterations <N>   Number of benchmark iterations (default: 10)
    -w, --warmup <N>       Number of warmup iterations (default: 3)
    -o, --output <FILE>    Write JSON results to file
    -r, --rootfs <PATH>    Path to rootfs directory
    -l, --layer <PATH>     Path to layer file (tar.gz)
    -v, --verbose          Enable verbose output
    -h, --help             Show help message
```

## Output Formats

### Console Output

```
╔══════════════════════════════════════════════════════════════════╗
║ Benchmark: cold_container_start                                  ║
╠══════════════════════════════════════════════════════════════════╣
║ Iterations:                                                   20 ║
║ Min:                                                    12345678 ns ║
║ Max:                                                    98765432 ns ║
║ Mean:                                                   45678901 ns ║
║ Median:                                                 43210987 ns ║
║ Stddev:                                                  5678901 ns ║
║ P95:                                                    87654321 ns ║
║ P99:                                                    95432198 ns ║
╠══════════════════════════════════════════════════════════════════╣
║ Mean (ms):                                                 45.68 ║
║ Mean (μs):                                              45678.90 ║
╚══════════════════════════════════════════════════════════════════╝
```

### JSON Output

```json
{
  "timestamp": 1736000000,
  "system": {
    "os": "linux",
    "arch": "x86_64",
    "cpu_count": 8
  },
  "benchmarks": {
    "container_start": {
      "iterations": 20,
      "min_ns": 12345678,
      "max_ns": 98765432,
      "mean_ns": 45678901,
      "median_ns": 43210987,
      "stddev_ns": 5678901,
      "p95_ns": 87654321,
      "p99_ns": 95432198,
      "mean_ms": 45.679
    },
    "layer_extraction": {
      "iterations": 10,
      "compressed_size_bytes": 5242880,
      "extracted_size_bytes": 26214400,
      "min_time_ns": 45000000,
      "max_time_ns": 85000000,
      "mean_time_ns": 62000000,
      "mean_time_ms": 62.00,
      "avg_throughput_compressed_mbps": 84.68,
      "avg_throughput_extracted_mbps": 423.39
    }
  }
}
```

## Benchmark Configuration Presets

The benchmark module provides three presets for different use cases:

```zig
const BenchmarkPresets = struct {
    // Quick benchmark for CI/CD (5 iterations, 1 warmup)
    pub const quick = BenchmarkConfig{...};
    
    // Standard benchmark for development (20 iterations, 3 warmup)
    pub const standard = BenchmarkConfig{...};
    
    // Thorough benchmark for releases (100 iterations, 5 warmup)
    pub const thorough = BenchmarkConfig{...};
};
```

## Best Practices

### For Accurate Results

1. **Isolate the system:**
   - Stop unnecessary services
   - Use a dedicated benchmark machine if possible
   - Avoid running during system updates

2. **Warm up caches:**
   - Use warmup iterations to prime filesystem caches
   - Run benchmarks multiple times

3. **Use consistent configuration:**
   - Document kernel version and configuration
   - Note CPU frequency scaling settings
   - Record memory and swap configuration

4. **Statistical significance:**
   - Run enough iterations (minimum 10, preferably 20+)
   - Look at percentiles (P95, P99), not just mean
   - Check standard deviation for consistency

### Comparing Results

When comparing benchmark results:

1. **Same hardware** - Results vary significantly by CPU and storage
2. **Same OS/kernel** - Namespace and cgroup performance varies
3. **Same rootfs** - Different base images have different overhead
4. **Same state** - Cold vs warm cache affects results

## Interpreting Results

### Container Start Time

| Result | Interpretation |
|--------|----------------|
| < 50ms | Excellent - suitable for FaaS |
| 50-100ms | Good - acceptable for most workloads |
| 100-200ms | Fair - may need optimization |
| > 200ms | Poor - investigate bottlenecks |

### Memory Overhead

| Result | Interpretation |
|--------|----------------|
| < 1MB RSS | Excellent - high density possible |
| 1-5MB RSS | Good - normal for most runtimes |
| 5-20MB RSS | Fair - check for leaks |
| > 20MB RSS | Poor - likely memory leak or bloat |

### Layer Extraction

| Result | Interpretation |
|--------|----------------|
| > 200 MB/s | Excellent - SSD/NVMe performance |
| 100-200 MB/s | Good - typical SSD |
| 50-100 MB/s | Fair - HDD or slow storage |
| < 50 MB/s | Poor - check I/O bottleneck |

## Running Tests

```bash
# Run all benchmark unit tests
zig build test

# Run only benchmark module tests
zig test src/bench/mod.zig
```

## Troubleshooting

### "Permission denied" errors
- Container benchmarks require root or appropriate capabilities
- Use user namespaces for rootless benchmarking

### Inconsistent results
- Check for CPU frequency scaling (set to performance mode)
- Ensure no background processes are competing for resources
- Increase iteration count

### "Layer extraction failed"
- Verify the layer file is a valid tar.gz archive
- Check available disk space in target directory
- Ensure tar command is available in PATH

## Contributing

When adding new benchmarks:

1. Create a new file in `src/bench/` following the pattern of existing benchmarks
2. Export from `mod.zig`
3. Add to `bench_main.zig` if CLI access is needed
4. Update this documentation
5. Include unit tests for statistics calculations
