//! CLI module for Isolazi container runtime.
//!
//! Provides command-line argument parsing and command dispatch.

pub const cli = @import("cli.zig");
pub const commands = @import("commands/mod.zig");

pub const VERSION = cli.VERSION;
pub const Command = cli.Command;
pub const RunCommand = cli.RunCommand;
pub const PullCommand = cli.PullCommand;
pub const ExecCommand = cli.ExecCommand;
pub const LogsCommand = cli.LogsCommand;
pub const PruneCommand = cli.PruneCommand;
pub const StartCommand = cli.StartCommand;
pub const StopCommand = cli.StopCommand;
pub const RmCommand = cli.RmCommand;
pub const InspectCommand = cli.InspectCommand;
pub const PsCommand = cli.PsCommand;
pub const CreateCommand = cli.CreateCommand;
pub const CliError = cli.CliError;

pub const parse = cli.parse;
pub const buildConfig = cli.buildConfig;
pub const printHelp = cli.printHelp;
pub const printVersion = cli.printVersion;
pub const printError = cli.printError;
