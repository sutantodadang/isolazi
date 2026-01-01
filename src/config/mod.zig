//! Container configuration module.
//!
//! Provides structures for defining container specifications:
//! - Rootfs path
//! - Command and arguments
//! - Environment variables
//! - Namespace configuration
//! - Bind mounts

pub const config = @import("config.zig");

pub const Config = config.Config;
pub const Namespaces = config.Namespaces;
pub const Mount = config.Mount;
pub const PortMapping = config.PortMapping;

pub const PATH_MAX = config.PATH_MAX;
pub const MAX_ARGS = config.MAX_ARGS;
pub const MAX_ENV = config.MAX_ENV;
pub const MAX_MOUNTS = config.MAX_MOUNTS;
pub const MAX_PORTS = config.MAX_PORTS;
