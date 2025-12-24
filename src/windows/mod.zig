//! Windows platform support for Isolazi.
//!
//! On Windows, Isolazi uses WSL2 (Windows Subsystem for Linux) as the backend
//! for container operations. This is similar to how Podman and Docker Desktop
//! work on Windows.
//!
//! The Windows CLI is a thin client that:
//! 1. Parses command-line arguments
//! 2. Converts Windows paths to WSL paths
//! 3. Invokes the Linux version through WSL
//! 4. Returns the exit code

pub const wsl = @import("wsl.zig");

pub const WslError = wsl.WslError;
pub const WslConfig = wsl.WslConfig;

pub const isWslAvailable = wsl.isWslAvailable;
pub const listDistros = wsl.listDistros;
pub const execInWsl = wsl.execInWsl;
pub const runThroughWsl = wsl.runThroughWsl;
pub const windowsToWslPath = wsl.windowsToWslPath;
pub const wslToWindowsPath = wsl.wslToWindowsPath;
