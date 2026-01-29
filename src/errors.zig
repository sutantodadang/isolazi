//! Structured Error Handling for Isolazi
//!
//! Provides application-wide error codes and rich error context
//! for consistent error reporting across all platforms.

const std = @import("std");

/// Application-wide error codes for consistent exit status
pub const ErrorCode = enum(u8) {
    // General errors (0-9)
    success = 0,
    unknown_error = 1,
    invalid_arguments = 2,
    missing_argument = 3,

    // Image errors (10-19)
    image_not_found = 10,
    image_pull_failed = 11,
    image_cache_error = 12,
    invalid_image_reference = 13,
    registry_auth_failed = 14,

    // Container errors (20-29)
    container_not_found = 20,
    container_not_running = 21,
    container_already_running = 22,
    container_create_failed = 23,
    container_start_failed = 24,
    container_stop_failed = 25,
    container_exec_failed = 26,

    // Permission errors (30-39)
    permission_denied = 30,
    root_required = 31,

    // Network errors (40-49)
    network_error = 40,
    port_in_use = 41,
    dns_resolution_failed = 42,

    // I/O errors (50-59)
    io_error = 50,
    file_not_found = 51,
    directory_not_found = 52,

    // Platform errors (60-69)
    wsl_not_available = 60,
    wsl_execution_failed = 61,
    lima_not_available = 62,
    lima_execution_failed = 63,
    virtualization_unavailable = 64,

    // Resource errors (70-79)
    out_of_memory = 70,
    resource_limit_exceeded = 71,

    pub fn toExitCode(self: ErrorCode) u8 {
        return @intFromEnum(self);
    }

    pub fn description(self: ErrorCode) []const u8 {
        return switch (self) {
            .success => "Success",
            .unknown_error => "Unknown error occurred",
            .invalid_arguments => "Invalid arguments provided",
            .missing_argument => "Required argument missing",
            .image_not_found => "Image not found",
            .image_pull_failed => "Failed to pull image",
            .image_cache_error => "Image cache error",
            .invalid_image_reference => "Invalid image reference",
            .registry_auth_failed => "Registry authentication failed",
            .container_not_found => "Container not found",
            .container_not_running => "Container is not running",
            .container_already_running => "Container is already running",
            .container_create_failed => "Failed to create container",
            .container_start_failed => "Failed to start container",
            .container_stop_failed => "Failed to stop container",
            .container_exec_failed => "Failed to execute in container",
            .permission_denied => "Permission denied",
            .root_required => "Root privileges required",
            .network_error => "Network error",
            .port_in_use => "Port already in use",
            .dns_resolution_failed => "DNS resolution failed",
            .io_error => "I/O error",
            .file_not_found => "File not found",
            .directory_not_found => "Directory not found",
            .wsl_not_available => "WSL2 is not available",
            .wsl_execution_failed => "WSL execution failed",
            .lima_not_available => "Lima is not available",
            .lima_execution_failed => "Lima execution failed",
            .virtualization_unavailable => "Virtualization is not available",
            .out_of_memory => "Out of memory",
            .resource_limit_exceeded => "Resource limit exceeded",
        };
    }
};

/// Rich error context for detailed error reporting
pub const AppError = struct {
    code: ErrorCode,
    message: []const u8,
    cause: ?anyerror = null,
    hint: ?[]const u8 = null,

    const Self = @This();

    /// Create a new AppError with just a code
    pub fn init(code: ErrorCode) Self {
        return .{
            .code = code,
            .message = code.description(),
        };
    }

    /// Create a new AppError with a custom message
    pub fn withMessage(code: ErrorCode, message: []const u8) Self {
        return .{
            .code = code,
            .message = message,
        };
    }

    /// Create a new AppError wrapping another error
    pub fn wrap(code: ErrorCode, message: []const u8, cause: anyerror) Self {
        return .{
            .code = code,
            .message = message,
            .cause = cause,
        };
    }

    /// Add a helpful hint to the error
    pub fn withHint(self: Self, hint: []const u8) Self {
        var copy = self;
        copy.hint = hint;
        return copy;
    }

    /// Format the error for display to the user
    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("Error: {s}\n", .{self.message});
        if (self.cause) |c| {
            try writer.print("  Caused by: {}\n", .{c});
        }
        if (self.hint) |h| {
            try writer.print("\nHint: {s}\n", .{h});
        }
    }

    /// Get the exit code for this error
    pub fn exitCode(self: Self) u8 {
        return self.code.toExitCode();
    }
};

/// Result type for command execution
pub fn CommandResult(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: AppError,

        const Self = @This();

        pub fn success(value: T) Self {
            return .{ .ok = value };
        }

        pub fn failure(err: AppError) Self {
            return .{ .err = err };
        }

        pub fn isOk(self: Self) bool {
            return self == .ok;
        }

        pub fn unwrap(self: Self) T {
            return switch (self) {
                .ok => |v| v,
                .err => unreachable,
            };
        }

        pub fn unwrapErr(self: Self) AppError {
            return switch (self) {
                .ok => unreachable,
                .err => |e| e,
            };
        }
    };
}

/// Exit code result for commands that just return a status
pub const ExitResult = CommandResult(u8);

// ============================================================================
// Tests
// ============================================================================

test "ErrorCode toExitCode" {
    try std.testing.expectEqual(@as(u8, 0), ErrorCode.success.toExitCode());
    try std.testing.expectEqual(@as(u8, 10), ErrorCode.image_not_found.toExitCode());
    try std.testing.expectEqual(@as(u8, 60), ErrorCode.wsl_not_available.toExitCode());
}

test "AppError creation" {
    const err = AppError.init(.container_not_found);
    try std.testing.expectEqual(ErrorCode.container_not_found, err.code);
    try std.testing.expectEqualStrings("Container not found", err.message);
}

test "AppError with custom message" {
    const err = AppError.withMessage(.image_not_found, "alpine:latest not in cache");
    try std.testing.expectEqual(ErrorCode.image_not_found, err.code);
    try std.testing.expectEqualStrings("alpine:latest not in cache", err.message);
}

test "AppError wrap" {
    const err = AppError.wrap(.network_error, "Failed to connect to registry", error.ConnectionRefused);
    try std.testing.expectEqual(ErrorCode.network_error, err.code);
    try std.testing.expect(err.cause != null);
}

test "AppError with hint" {
    const err = AppError.init(.root_required).withHint("Run with 'sudo isolazi run ...'");
    try std.testing.expect(err.hint != null);
    try std.testing.expectEqualStrings("Run with 'sudo isolazi run ...'", err.hint.?);
}

test "ExitResult success" {
    const result = ExitResult.success(0);
    try std.testing.expect(result.isOk());
    try std.testing.expectEqual(@as(u8, 0), result.unwrap());
}

test "ExitResult failure" {
    const result = ExitResult.failure(AppError.init(.permission_denied));
    try std.testing.expect(!result.isOk());
    try std.testing.expectEqual(ErrorCode.permission_denied, result.unwrapErr().code);
}
