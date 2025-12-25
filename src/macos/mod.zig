//! macOS platform support for Isolazi.
//!
//! On macOS, Isolazi uses Apple's Virtualization.framework to run Linux VMs.
//! This is similar to how Docker Desktop and Podman work on macOS.
//!
//! Architecture:
//! ```
//! macOS Host                           Linux VM (Apple Virtualization)
//! ──────────                           ─────────────────────────────────
//!
//! isolazi ──────────────────────────► VM: isolazi run ...
//!     │                                    │
//!     │ (Virtualization.framework)         │ (native Linux execution)
//!     │                                    │
//!     └── VZVirtualMachine ◄───────────────┘
//! ```
//!
//! Requirements:
//! - macOS 12.0 (Monterey) or later
//! - Apple Silicon (M1/M2) or Intel Mac with virtualization support
//! - Linux kernel and initramfs for the VM

pub const virtualization = @import("virtualization.zig");

pub const VirtualizationError = virtualization.VirtualizationError;
pub const VMConfig = virtualization.VMConfig;
pub const VirtualMachine = virtualization.VirtualMachine;

pub const isVirtualizationAvailable = virtualization.isVirtualizationAvailable;
pub const createLinuxVM = virtualization.createLinuxVM;
pub const runInVM = virtualization.runInVM;
pub const convertMacOSPath = virtualization.convertMacOSPath;
