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
//! Resource Limits:
//! Resource limits (--memory, --cpus, etc.) are passed through to the
//! Linux VM where they are applied using cgroup v2. The VM itself is
//! configured with appropriate CPU/memory limits.
//!
//! Requirements:
//! - macOS 12.0 (Monterey) or later
//! - Apple Silicon (M1/M2) or Intel Mac with virtualization support
//! - Linux kernel and initramfs for the VM

pub const virtualization = @import("virtualization.zig");

pub const VirtualizationError = virtualization.VirtualizationError;
pub const VMConfig = virtualization.VMConfig;
pub const VirtualMachine = virtualization.VirtualMachine;
pub const ResourceLimitsConfig = virtualization.ResourceLimitsConfig;

pub const isVirtualizationAvailable = virtualization.isVirtualizationAvailable;
pub const createLinuxVM = virtualization.createLinuxVM;
pub const runInVM = virtualization.runInVM;
pub const convertMacOSPath = virtualization.convertMacOSPath;
pub const runWithLima = virtualization.runWithLima;
pub const runWithLimaEx = virtualization.runWithLimaEx;
