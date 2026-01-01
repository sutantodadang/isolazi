//! Seccomp-BPF syscall filtering for container security.
//!
//! This module provides syscall filtering to block dangerous syscalls inside containers.
//! Seccomp (Secure Computing Mode) is a Linux kernel feature that restricts the system
//! calls a process can make.
//!
//! Key concepts:
//! - SeccompAction: What to do when a syscall matches a rule (kill, errno, allow, etc.)
//! - SeccompRule: A rule matching a syscall to an action
//! - SeccompProfile: A complete seccomp policy with multiple rules
//! - Default deny list: Commonly blocked syscalls for container security
//!
//! Default blocked syscalls (similar to Docker/Podman defaults):
//! - mount/umount: Prevent filesystem manipulation
//! - ptrace: Prevent process debugging/tracing
//! - kexec_load: Prevent kernel replacement
//! - reboot: Prevent system reboot
//! - swapon/swapoff: Prevent swap manipulation
//! - pivot_root: Prevent root filesystem changes (outside init)
//! - acct: Prevent process accounting manipulation
//! - settimeofday/adjtimex: Prevent time manipulation
//! - sethostname/setdomainname: Prevent hostname changes (outside UTS ns)
//! - init_module/finit_module/delete_module: Prevent kernel module loading
//! - create_module: Prevent kernel module creation
//! - lookup_dcookie: Prevent profiling information leak
//! - perf_event_open: Prevent performance monitoring
//! - bpf: Prevent BPF program loading (except our own seccomp)
//! - userfaultfd: Prevent memory manipulation
//! - keyctl: Prevent kernel keyring manipulation
//! - add_key/request_key: Prevent key management
//! - mbind/move_pages/migrate_pages: Prevent NUMA manipulation
//! - ioperm/iopl: Prevent I/O port access
//! - open_by_handle_at: Prevent filesystem escape
//! - clock_settime/clock_adjtime: Prevent clock manipulation
//! - personality: Prevent execution domain changes (some dangerous flags)
//! - setns: Prevent namespace switching (controlled)
//! - unshare: Prevent namespace creation (controlled)
//!
//! SECURITY: Seccomp filters are inherited by child processes and cannot be removed.
//! Once installed, they provide a strong security boundary.
//!
//! PLATFORM: This module is Linux-only. Windows and macOS pass seccomp config
//! to their Linux backend (WSL2 or Lima/vfkit VM).

const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");

/// Seccomp-related error types
pub const SeccompError = error{
    /// Seccomp not supported on this kernel
    SeccompNotSupported,
    /// Failed to install seccomp filter
    FilterInstallFailed,
    /// Invalid filter configuration
    InvalidFilter,
    /// Too many rules in filter
    TooManyRules,
    /// Permission denied (need CAP_SYS_ADMIN or no_new_privs)
    PermissionDenied,
    /// Out of memory
    OutOfMemory,
    /// Syscall number not found
    UnknownSyscall,
};

/// Seccomp filter return actions.
/// These define what happens when a syscall matches a rule.
pub const SeccompAction = enum(u32) {
    /// Kill the process immediately (SECCOMP_RET_KILL_PROCESS)
    kill_process = 0x80000000,

    /// Kill the thread (SECCOMP_RET_KILL_THREAD)
    kill_thread = 0x00000000,

    /// Send SIGSYS signal (for debugging/logging, SECCOMP_RET_TRAP)
    trap = 0x00030000,

    /// Return an errno value (SECCOMP_RET_ERRNO | errno)
    /// The errno is OR'd with this value
    errno_base = 0x00050000,

    /// Trace the syscall (SECCOMP_RET_TRACE | data)
    trace = 0x7ff00000,

    /// Log the syscall but allow it (SECCOMP_RET_LOG)
    log = 0x7ffc0000,

    /// Allow the syscall (SECCOMP_RET_ALLOW)
    allow = 0x7fff0000,

    /// Helper to create errno action with specific errno value
    pub fn withErrno(errno: u16) u32 {
        return @intFromEnum(SeccompAction.errno_base) | @as(u32, errno);
    }
};

/// Syscall numbers for x86_64 Linux.
/// These are the syscalls we commonly want to filter.
pub const Syscall = enum(u32) {
    // Filesystem manipulation
    mount = 165,
    umount2 = 166,
    pivot_root = 155,

    // Process debugging
    ptrace = 101,

    // Kernel/system manipulation
    kexec_load = 246,
    kexec_file_load = 320,
    reboot = 169,
    swapon = 167,
    swapoff = 168,
    acct = 163,

    // Time manipulation
    settimeofday = 164,
    adjtimex = 159,
    clock_settime = 227,
    clock_adjtime = 305,

    // Hostname manipulation
    sethostname = 170,
    setdomainname = 171,

    // Kernel module manipulation
    init_module = 175,
    finit_module = 313,
    delete_module = 176,
    create_module = 174, // Deprecated but still exists

    // Profiling/debugging
    lookup_dcookie = 212,
    perf_event_open = 298,
    bpf = 321,

    // Memory manipulation
    userfaultfd = 323,
    mbind = 237,
    move_pages = 279,
    migrate_pages = 256,

    // Key management
    keyctl = 250,
    add_key = 248,
    request_key = 249,

    // I/O port access
    ioperm = 173,
    iopl = 172,

    // Filesystem escape
    open_by_handle_at = 304,

    // Personality/execution domain (partially restricted)
    personality = 135,

    // Namespace manipulation (controlled via rules)
    setns = 308,
    unshare = 272,

    // Privileged operations
    quotactl = 179,
    nfsservctl = 180, // Removed in newer kernels but keep for compatibility
    bdflush = 134, // Deprecated

    // Misc dangerous
    vhangup = 153,
    sysfs = 139, // Deprecated
    _sysctl = 156, // Deprecated

    _,

    /// Get syscall number for the current architecture
    pub fn number(self: Syscall) u32 {
        return @intFromEnum(self);
    }
};

/// Comparison operators for seccomp argument filtering
pub const SeccompOp = enum(u8) {
    /// Not equal
    ne = 0,
    /// Less than
    lt = 1,
    /// Less than or equal
    le = 2,
    /// Equal
    eq = 3,
    /// Greater than or equal
    ge = 4,
    /// Greater than
    gt = 5,
    /// Masked equal (arg & mask == value)
    masked_eq = 6,
};

/// A seccomp argument comparison for conditional filtering.
/// Allows rules like "block personality() with specific flags"
pub const SeccompArg = struct {
    /// Argument index (0-5)
    arg_index: u3,
    /// Comparison operator
    op: SeccompOp,
    /// Value to compare against
    value: u64,
    /// Mask for masked_eq operation
    mask: u64 = 0xFFFFFFFFFFFFFFFF,
    /// Is this comparison active?
    active: bool = false,

    /// Create an equality comparison
    pub fn eq(arg_index: u3, value: u64) SeccompArg {
        return SeccompArg{
            .arg_index = arg_index,
            .op = .eq,
            .value = value,
            .active = true,
        };
    }

    /// Create a masked equality comparison
    pub fn maskedEq(arg_index: u3, mask: u64, value: u64) SeccompArg {
        return SeccompArg{
            .arg_index = arg_index,
            .op = .masked_eq,
            .value = value,
            .mask = mask,
            .active = true,
        };
    }

    /// Create a not-equal comparison
    pub fn ne(arg_index: u3, value: u64) SeccompArg {
        return SeccompArg{
            .arg_index = arg_index,
            .op = .ne,
            .value = value,
            .active = true,
        };
    }
};

/// Maximum number of argument comparisons per rule
pub const MAX_ARGS_PER_RULE: usize = 6;

/// Maximum number of seccomp rules
pub const MAX_SECCOMP_RULES: usize = 256;

/// A seccomp rule matching a syscall to an action.
/// Rules can optionally filter by argument values.
pub const SeccompRule = struct {
    /// The syscall to match
    syscall: Syscall,
    /// Action to take when matched
    action: SeccompAction,
    /// Optional argument comparisons (all must match)
    args: [MAX_ARGS_PER_RULE]SeccompArg = std.mem.zeroes([MAX_ARGS_PER_RULE]SeccompArg),
    /// Number of active argument comparisons
    args_count: usize = 0,
    /// Is this rule active?
    active: bool = false,
    /// Human-readable description
    description: [128]u8 = std.mem.zeroes([128]u8),

    /// Create a simple block rule (kill process on syscall)
    pub fn block(syscall: Syscall) SeccompRule {
        return SeccompRule{
            .syscall = syscall,
            .action = .kill_process,
            .active = true,
        };
    }

    /// Create a simple allow rule
    pub fn allow(syscall: Syscall) SeccompRule {
        return SeccompRule{
            .syscall = syscall,
            .action = .allow,
            .active = true,
        };
    }

    /// Create a rule that returns errno
    pub fn denyWithErrno(syscall: Syscall, errno: u16) SeccompRule {
        return SeccompRule{
            .syscall = syscall,
            .action = @enumFromInt(SeccompAction.withErrno(errno)),
            .active = true,
        };
    }

    /// Create a rule that traps (sends SIGSYS)
    pub fn trap(syscall: Syscall) SeccompRule {
        return SeccompRule{
            .syscall = syscall,
            .action = .trap,
            .active = true,
        };
    }

    /// Create a rule that logs but allows
    pub fn logOnly(syscall: Syscall) SeccompRule {
        return SeccompRule{
            .syscall = syscall,
            .action = .log,
            .active = true,
        };
    }

    /// Add an argument comparison to this rule
    pub fn withArg(self: *SeccompRule, arg: SeccompArg) *SeccompRule {
        if (self.args_count < MAX_ARGS_PER_RULE) {
            self.args[self.args_count] = arg;
            self.args_count += 1;
        }
        return self;
    }

    /// Set description for debugging/logging
    pub fn withDescription(self: *SeccompRule, desc: []const u8) *SeccompRule {
        const len = @min(desc.len, self.description.len - 1);
        @memcpy(self.description[0..len], desc[0..len]);
        return self;
    }
};

/// Seccomp profile - a complete set of rules.
pub const SeccompProfile = struct {
    /// Rules in this profile
    rules: [MAX_SECCOMP_RULES]SeccompRule = std.mem.zeroes([MAX_SECCOMP_RULES]SeccompRule),
    /// Number of active rules
    rules_count: usize = 0,
    /// Default action for unmatched syscalls
    default_action: SeccompAction = .allow,
    /// Name of this profile
    name: [64]u8 = std.mem.zeroes([64]u8),

    /// Create an empty profile
    pub fn init() SeccompProfile {
        return SeccompProfile{};
    }

    /// Create the default container security profile.
    /// This blocks dangerous syscalls commonly restricted in containers.
    pub fn defaultContainerProfile() SeccompProfile {
        var profile = SeccompProfile{};

        // Set profile name
        const name = "default-container";
        @memcpy(profile.name[0..name.len], name);

        // Block filesystem manipulation
        profile.addRule(SeccompRule.block(.mount));
        profile.addRule(SeccompRule.block(.umount2));
        profile.addRule(SeccompRule.block(.pivot_root));

        // Block process debugging
        profile.addRule(SeccompRule.block(.ptrace));

        // Block kernel/system manipulation
        profile.addRule(SeccompRule.block(.kexec_load));
        profile.addRule(SeccompRule.block(.kexec_file_load));
        profile.addRule(SeccompRule.block(.reboot));
        profile.addRule(SeccompRule.block(.swapon));
        profile.addRule(SeccompRule.block(.swapoff));
        profile.addRule(SeccompRule.block(.acct));

        // Block time manipulation
        profile.addRule(SeccompRule.block(.settimeofday));
        profile.addRule(SeccompRule.block(.adjtimex));
        profile.addRule(SeccompRule.block(.clock_settime));
        profile.addRule(SeccompRule.block(.clock_adjtime));

        // Block hostname manipulation (UTS namespace should handle this, but belt-and-suspenders)
        profile.addRule(SeccompRule.block(.sethostname));
        profile.addRule(SeccompRule.block(.setdomainname));

        // Block kernel module manipulation
        profile.addRule(SeccompRule.block(.init_module));
        profile.addRule(SeccompRule.block(.finit_module));
        profile.addRule(SeccompRule.block(.delete_module));
        profile.addRule(SeccompRule.block(.create_module));

        // Block profiling/debugging
        profile.addRule(SeccompRule.block(.lookup_dcookie));
        profile.addRule(SeccompRule.block(.perf_event_open));
        profile.addRule(SeccompRule.block(.bpf));

        // Block dangerous memory manipulation
        profile.addRule(SeccompRule.block(.userfaultfd));
        profile.addRule(SeccompRule.block(.mbind));
        profile.addRule(SeccompRule.block(.move_pages));
        profile.addRule(SeccompRule.block(.migrate_pages));

        // Block key management
        profile.addRule(SeccompRule.block(.keyctl));
        profile.addRule(SeccompRule.block(.add_key));
        profile.addRule(SeccompRule.block(.request_key));

        // Block I/O port access
        profile.addRule(SeccompRule.block(.ioperm));
        profile.addRule(SeccompRule.block(.iopl));

        // Block filesystem escape
        profile.addRule(SeccompRule.block(.open_by_handle_at));

        // Block namespace manipulation (containers shouldn't create nested namespaces)
        profile.addRule(SeccompRule.block(.setns));
        profile.addRule(SeccompRule.block(.unshare));

        // Block misc dangerous syscalls
        profile.addRule(SeccompRule.block(.quotactl));
        profile.addRule(SeccompRule.block(.vhangup));
        profile.addRule(SeccompRule.block(.sysfs));
        profile.addRule(SeccompRule.block(._sysctl));

        return profile;
    }

    /// Create a minimal security profile that only blocks the most dangerous syscalls.
    pub fn minimalProfile() SeccompProfile {
        var profile = SeccompProfile{};

        const name = "minimal";
        @memcpy(profile.name[0..name.len], name);

        // Only block the most critical syscalls
        profile.addRule(SeccompRule.block(.kexec_load));
        profile.addRule(SeccompRule.block(.kexec_file_load));
        profile.addRule(SeccompRule.block(.reboot));
        profile.addRule(SeccompRule.block(.init_module));
        profile.addRule(SeccompRule.block(.finit_module));
        profile.addRule(SeccompRule.block(.delete_module));

        return profile;
    }

    /// Create an allowlist profile - block everything except explicitly allowed syscalls.
    /// This is the most secure but requires careful configuration.
    pub fn allowlistProfile() SeccompProfile {
        var profile = SeccompProfile{};

        const name = "allowlist";
        @memcpy(profile.name[0..name.len], name);

        // Default deny all
        profile.default_action = .kill_process;

        // Basic syscalls needed for any program to run
        const allowed_syscalls = [_]Syscall{
            // File operations
            @enumFromInt(0), // read
            @enumFromInt(1), // write
            @enumFromInt(2), // open
            @enumFromInt(3), // close
            @enumFromInt(4), // stat
            @enumFromInt(5), // fstat
            @enumFromInt(6), // lstat
            @enumFromInt(9), // mmap
            @enumFromInt(10), // mprotect
            @enumFromInt(11), // munmap
            @enumFromInt(12), // brk
            @enumFromInt(16), // ioctl
            @enumFromInt(17), // pread64
            @enumFromInt(18), // pwrite64
            @enumFromInt(19), // readv
            @enumFromInt(20), // writev
            @enumFromInt(21), // access
            @enumFromInt(22), // pipe
            @enumFromInt(32), // dup
            @enumFromInt(33), // dup2
            @enumFromInt(39), // getpid
            @enumFromInt(57), // fork
            @enumFromInt(58), // vfork
            @enumFromInt(59), // execve
            @enumFromInt(60), // exit
            @enumFromInt(61), // wait4
            @enumFromInt(62), // kill
            @enumFromInt(63), // uname
            @enumFromInt(79), // getcwd
            @enumFromInt(80), // chdir
            @enumFromInt(89), // readlink
            @enumFromInt(102), // getuid
            @enumFromInt(104), // getgid
            @enumFromInt(107), // geteuid
            @enumFromInt(108), // getegid
            @enumFromInt(110), // getppid
            @enumFromInt(231), // exit_group
            @enumFromInt(257), // openat
            @enumFromInt(262), // newfstatat
        };

        for (allowed_syscalls) |syscall| {
            profile.addRule(SeccompRule.allow(syscall));
        }

        return profile;
    }

    /// Add a rule to the profile
    pub fn addRule(self: *SeccompProfile, rule: SeccompRule) void {
        if (self.rules_count < MAX_SECCOMP_RULES) {
            self.rules[self.rules_count] = rule;
            self.rules[self.rules_count].active = true;
            self.rules_count += 1;
        }
    }

    /// Remove rules for a specific syscall
    pub fn removeRulesFor(self: *SeccompProfile, syscall: Syscall) void {
        for (&self.rules) |*rule| {
            if (rule.active and rule.syscall == syscall) {
                rule.active = false;
            }
        }
    }

    /// Check if a syscall is blocked by this profile
    pub fn isBlocked(self: *const SeccompProfile, syscall: Syscall) bool {
        for (self.rules[0..self.rules_count]) |rule| {
            if (rule.active and rule.syscall == syscall) {
                return switch (rule.action) {
                    .kill_process, .kill_thread, .trap => true,
                    .allow, .log => false,
                    else => {
                        // Check if it's an errno action
                        const action_val = @intFromEnum(rule.action);
                        return (action_val & 0xFFFF0000) == @intFromEnum(SeccompAction.errno_base);
                    },
                };
            }
        }
        // Check default action
        return switch (self.default_action) {
            .kill_process, .kill_thread, .trap => true,
            else => false,
        };
    }

    /// Get the profile name as a slice
    pub fn getName(self: *const SeccompProfile) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..len];
    }
};

/// Seccomp configuration for container setup
pub const SeccompConfig = struct {
    /// Is seccomp enabled?
    enabled: bool = true,
    /// The active profile
    profile: SeccompProfile = SeccompProfile.defaultContainerProfile(),
    /// Log blocked syscalls (via SECCOMP_RET_LOG or SECCOMP_RET_TRAP)
    log_blocked: bool = false,
    /// Use SECCOMP_RET_ERRNO instead of kill for blocked syscalls
    errno_instead_of_kill: bool = false,
    /// Errno to return when blocking (default: EPERM = 1)
    errno_value: u16 = 1,

    /// Create default seccomp configuration
    pub fn default_config() SeccompConfig {
        return SeccompConfig{};
    }

    /// Create disabled seccomp configuration
    pub fn disabled() SeccompConfig {
        return SeccompConfig{
            .enabled = false,
        };
    }

    /// Create minimal seccomp configuration
    pub fn minimal() SeccompConfig {
        return SeccompConfig{
            .profile = SeccompProfile.minimalProfile(),
        };
    }

    /// Check if this config has any effect
    pub fn hasFilter(self: *const SeccompConfig) bool {
        return self.enabled and self.profile.rules_count > 0;
    }
};

// ============================================================================
// BPF Filter Generation and Installation
// ============================================================================

/// BPF instruction for seccomp filter
const BpfInsn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// BPF program structure for seccomp
const BpfProg = extern struct {
    len: c_ushort,
    filter: [*]const BpfInsn,
};

/// Seccomp data structure passed to BPF filter
const SeccompData = extern struct {
    /// Syscall number
    nr: c_int,
    /// CPU architecture (AUDIT_ARCH_*)
    arch: u32,
    /// Instruction pointer at time of syscall
    instruction_pointer: u64,
    /// Syscall arguments
    args: [6]u64,
};

// BPF instruction macros
const BPF_LD = 0x00;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JMP = 0x05;
const BPF_JEQ = 0x10;
const BPF_JGE = 0x30;
const BPF_JGT = 0x20;
const BPF_JSET = 0x40;
const BPF_K = 0x00;
const BPF_RET = 0x06;

/// Architecture audit value for x86_64
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
/// Architecture audit value for aarch64
const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

/// Get the current architecture audit value
fn getArchValue() u32 {
    return switch (builtin.cpu.arch) {
        .x86_64 => AUDIT_ARCH_X86_64,
        .aarch64 => AUDIT_ARCH_AARCH64,
        else => AUDIT_ARCH_X86_64, // Default fallback
    };
}

/// Offset of the architecture field in seccomp_data
const SECCOMP_DATA_ARCH_OFFSET = @offsetOf(SeccompData, "arch");
/// Offset of the syscall number field in seccomp_data
const SECCOMP_DATA_NR_OFFSET = @offsetOf(SeccompData, "nr");
/// Offset of the args field in seccomp_data
const SECCOMP_DATA_ARGS_OFFSET = @offsetOf(SeccompData, "args");

/// BPF instruction helpers
fn bpfStmt(code: u16, k: u32) BpfInsn {
    return BpfInsn{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) BpfInsn {
    return BpfInsn{ .code = code, .jt = jt, .jf = jf, .k = k };
}

/// Maximum BPF instructions we can generate
const MAX_BPF_INSNS: usize = 512;

/// Generate BPF filter from seccomp profile.
/// Returns the number of instructions generated.
fn generateBpfFilter(
    profile: *const SeccompProfile,
    config: *const SeccompConfig,
    insns: *[MAX_BPF_INSNS]BpfInsn,
) SeccompError!usize {
    var idx: usize = 0;

    // Step 1: Validate architecture
    // Load architecture
    insns[idx] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET);
    idx += 1;

    // Jump if architecture matches, else kill
    insns[idx] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, getArchValue(), 1, 0);
    idx += 1;

    // Kill on architecture mismatch
    insns[idx] = bpfStmt(BPF_RET | BPF_K, @intFromEnum(SeccompAction.kill_process));
    idx += 1;

    // Step 2: Load syscall number
    insns[idx] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET);
    idx += 1;

    // Step 3: Generate rules
    // We generate a sequence of: if (syscall == X) then action
    // The jump targets need to be calculated based on remaining instructions

    // First pass: count how many rules we have
    var active_rules: usize = 0;
    for (profile.rules[0..profile.rules_count]) |rule| {
        if (rule.active) active_rules += 1;
    }

    // For each rule, we need 2 instructions: compare and action
    // But we skip the action if we want to fall through to next rule
    var rules_processed: usize = 0;
    for (profile.rules[0..profile.rules_count]) |rule| {
        if (!rule.active) continue;

        if (idx + 3 >= MAX_BPF_INSNS) {
            return SeccompError.TooManyRules;
        }

        // Calculate jump offset to skip the action (go to next rule)
        // If this matches, execute action (jt=0), else skip to next (jf=1)
        insns[idx] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, rule.syscall.number(), 0, 1);
        idx += 1;

        // Action to take
        var action_value: u32 = @intFromEnum(rule.action);

        // Override to errno if config says so
        if (config.errno_instead_of_kill) {
            if (rule.action == .kill_process or rule.action == .kill_thread) {
                action_value = SeccompAction.withErrno(config.errno_value);
            }
        }

        // Override to log if config says so
        if (config.log_blocked) {
            if (rule.action == .kill_process or rule.action == .kill_thread) {
                action_value = @intFromEnum(SeccompAction.log);
            }
        }

        insns[idx] = bpfStmt(BPF_RET | BPF_K, action_value);
        idx += 1;

        rules_processed += 1;
    }

    // Step 4: Default action for unmatched syscalls
    insns[idx] = bpfStmt(BPF_RET | BPF_K, @intFromEnum(profile.default_action));
    idx += 1;

    return idx;
}

// Seccomp operation constants
const SECCOMP_SET_MODE_FILTER = 1;
const SECCOMP_FILTER_FLAG_TSYNC = 1;

/// Install seccomp filter using prctl or seccomp syscall.
///
/// IMPORTANT: Before calling this:
/// 1. Set PR_SET_NO_NEW_PRIVS to allow filter installation without CAP_SYS_ADMIN
/// 2. Drop all capabilities you don't need
///
/// Once installed, the filter cannot be removed and is inherited by children.
pub fn installSeccompFilter(config: *const SeccompConfig) SeccompError!void {
    if (!config.enabled) return;
    if (config.profile.rules_count == 0) return;

    // Generate BPF filter
    var insns: [MAX_BPF_INSNS]BpfInsn = undefined;
    const insn_count = try generateBpfFilter(&config.profile, config, &insns);

    // Create BPF program structure
    const prog = BpfProg{
        .len = @intCast(insn_count),
        .filter = &insns,
    };

    // First, set no_new_privs (required for unprivileged seccomp)
    // PR_SET_NO_NEW_PRIVS = 38
    const PR_SET_NO_NEW_PRIVS: usize = 38;
    const nnp_result = linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (nnp_result != 0) {
        // This shouldn't fail unless we're in a weird state
        std.debug.print("Warning: Failed to set no_new_privs\n", .{});
    }

    // Install the seccomp filter
    // seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog)
    const seccomp_result = linux.syscall3(
        .seccomp,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_TSYNC, // Sync across all threads
        @intFromPtr(&prog),
    );

    if (seccomp_result > std.math.maxInt(usize) - 4096) {
        const errno_val: u16 = @truncate(0 -% seccomp_result);
        const err = linux.E.init(errno_val);
        return switch (err) {
            .PERM, .ACCES => SeccompError.PermissionDenied,
            .INVAL => SeccompError.InvalidFilter,
            .NOMEM => SeccompError.OutOfMemory,
            .NOSYS => SeccompError.SeccompNotSupported,
            else => SeccompError.FilterInstallFailed,
        };
    }
}

/// Check if seccomp is supported on this system
pub fn isSeccompSupported() bool {
    // Try to query seccomp status
    // PR_GET_SECCOMP = 21
    const result = linux.prctl(.GET_SECCOMP, 0, 0, 0, 0);
    // Returns 0 if seccomp is disabled, 1 if prctl mode, 2 if filter mode
    // Returns -EINVAL if not supported
    if (result > std.math.maxInt(usize) - 4096) {
        return false;
    }
    return true;
}

/// Apply seccomp filter as part of container initialization.
/// This should be called after namespaces are set up but before execve.
///
/// SECURITY: This is the final step before exec - once applied, the container
/// process and all its children are restricted.
pub fn applySeccompFilter(config: *const SeccompConfig) SeccompError!void {
    if (!config.enabled) {
        return;
    }

    // Log what we're doing
    if (config.profile.rules_count > 0) {
        std.debug.print("Applying seccomp filter: {s} ({d} rules)\n", .{
            config.profile.getName(),
            config.profile.rules_count,
        });
    }

    try installSeccompFilter(config);
}

// ============================================================================
// Tests
// ============================================================================

test "SeccompRule creation" {
    const rule = SeccompRule.block(.mount);
    try std.testing.expect(rule.active);
    try std.testing.expectEqual(Syscall.mount, rule.syscall);
    try std.testing.expectEqual(SeccompAction.kill_process, rule.action);
}

test "SeccompProfile default" {
    const profile = SeccompProfile.defaultContainerProfile();
    try std.testing.expect(profile.rules_count > 0);
    try std.testing.expect(profile.isBlocked(.mount));
    try std.testing.expect(profile.isBlocked(.ptrace));
    try std.testing.expect(profile.isBlocked(.kexec_load));
}

test "SeccompConfig default" {
    const config = SeccompConfig.default_config();
    try std.testing.expect(config.enabled);
    try std.testing.expect(config.hasFilter());
}

test "BPF filter generation" {
    const profile = SeccompProfile.defaultContainerProfile();
    const config = SeccompConfig.default_config();
    var insns: [MAX_BPF_INSNS]BpfInsn = undefined;

    const count = try generateBpfFilter(&profile, &config, &insns);
    try std.testing.expect(count > 0);
    try std.testing.expect(count < MAX_BPF_INSNS);
}
