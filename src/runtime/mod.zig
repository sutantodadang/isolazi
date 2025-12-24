//! Container runtime module.
//!
//! Provides the core container execution engine:
//! - Process forking and isolation
//! - Namespace setup
//! - Container lifecycle management

pub const container = @import("container.zig");

pub const Runtime = container.Runtime;
pub const RuntimeError = container.RuntimeError;
pub const RunResult = container.RunResult;
pub const run = container.run;
