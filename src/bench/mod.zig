//! Benchmark Module
//!
//! This module provides benchmark tests for measuring isolazi performance:
//! - Cold container start time
//! - Memory & CPU overhead for idle containers
//! - Layer extraction speed

pub const container_bench = @import("container_bench.zig");
pub const layer_bench = @import("layer_bench.zig");
pub const overhead_bench = @import("overhead_bench.zig");

// Re-export benchmark runner
pub const BenchmarkRunner = container_bench.BenchmarkRunner;
pub const BenchmarkResult = container_bench.BenchmarkResult;
