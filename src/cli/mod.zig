//! CLI module for Isolazi container runtime.
//!
//! Provides command-line argument parsing and command dispatch.

pub const cli = @import("cli.zig");

pub const VERSION = cli.VERSION;
pub const Command = cli.Command;
pub const RunCommand = cli.RunCommand;
pub const CliError = cli.CliError;

pub const parse = cli.parse;
pub const buildConfig = cli.buildConfig;
pub const printHelp = cli.printHelp;
pub const printVersion = cli.printVersion;
pub const printError = cli.printError;
