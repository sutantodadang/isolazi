//! Container Logging Module
//!
//! Captures and manages stdout/stderr logs for containers.
//! Log files are stored at: ~/.isolazi/containers/<container-id>/stdout.log and stderr.log
//!
//! Features:
//! - Read container logs (stdout/stderr combined or separate)
//! - Follow mode for streaming new log entries
//! - Tail mode to show last N lines
//! - Log file rotation support
//!
//! Design decisions:
//! - Logs are stored as plain text files for simplicity
//! - Each container has separate stdout.log and stderr.log files
//! - Follow mode uses polling with configurable interval
//! - Max log file size with rotation (optional)

const std = @import("std");
const builtin = @import("builtin");

/// Log stream type
pub const LogStream = enum {
    stdout,
    stderr,
    both,

    pub fn toString(self: LogStream) []const u8 {
        return switch (self) {
            .stdout => "stdout",
            .stderr => "stderr",
            .both => "both",
        };
    }
};

/// Log entry with timestamp and stream info
pub const LogEntry = struct {
    timestamp: i64,
    stream: LogStream,
    message: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *LogEntry) void {
        self.allocator.free(self.message);
    }
};

/// Options for reading logs
pub const LogOptions = struct {
    /// Follow mode - stream new log entries
    follow: bool = false,
    /// Show timestamps with each line
    timestamps: bool = false,
    /// Number of lines to show from the end (0 = all)
    tail: usize = 0,
    /// Which streams to show
    stream: LogStream = .both,
    /// Poll interval in milliseconds for follow mode
    poll_interval_ms: u64 = 100,
    /// Since timestamp (only show logs after this time)
    since: ?i64 = null,
    /// Until timestamp (only show logs before this time)
    until: ?i64 = null,
};

/// Container log manager
pub const ContainerLogs = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,
    container_id: []const u8,

    const Self = @This();

    /// Initialize log manager for a container
    pub fn init(allocator: std.mem.Allocator, container_id: []const u8) !Self {
        // Get home directory
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => blk: {
                break :blk std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
                    return error.HomeNotFound;
                };
            },
            else => return error.HomeNotFound,
        };
        defer allocator.free(home);

        const base_path = try std.fmt.allocPrint(allocator, "{s}/.isolazi/containers/{s}", .{ home, container_id });

        return Self{
            .allocator = allocator,
            .base_path = base_path,
            .container_id = try allocator.dupe(u8, container_id),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.base_path);
        self.allocator.free(self.container_id);
    }

    /// Get the path to the stdout log file
    pub fn getStdoutPath(self: *Self) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "{s}/stdout.log", .{self.base_path});
    }

    /// Get the path to the stderr log file
    pub fn getStderrPath(self: *Self) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "{s}/stderr.log", .{self.base_path});
    }

    /// Ensure log directory exists
    pub fn ensureLogDir(self: *Self) !void {
        std.fs.cwd().makePath(self.base_path) catch {};
    }

    /// Read logs from a specific stream
    pub fn readStream(self: *Self, stream: LogStream) ![]const u8 {
        const path = switch (stream) {
            .stdout => try self.getStdoutPath(),
            .stderr => try self.getStderrPath(),
            .both => {
                // For both, concatenate stdout and stderr
                const stdout_content = self.readStream(.stdout) catch "";
                defer if (stdout_content.len > 0) self.allocator.free(stdout_content);

                const stderr_content = self.readStream(.stderr) catch "";
                defer if (stderr_content.len > 0) self.allocator.free(stderr_content);

                if (stdout_content.len == 0 and stderr_content.len == 0) {
                    return try self.allocator.dupe(u8, "");
                }

                // Combine with stream prefixes
                var result: std.ArrayList(u8) = .empty;
                defer result.deinit(self.allocator);

                if (stdout_content.len > 0) {
                    try result.appendSlice(self.allocator, stdout_content);
                }
                if (stderr_content.len > 0) {
                    try result.appendSlice(self.allocator, stderr_content);
                }

                return try result.toOwnedSlice(self.allocator);
            },
        };
        defer self.allocator.free(path);

        // Read the file
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                return try self.allocator.dupe(u8, "");
            }
            return err;
        };
        defer file.close();

        const stat = try file.stat();
        const size = stat.size;

        if (size == 0) {
            return try self.allocator.dupe(u8, "");
        }

        // Limit max read size to prevent OOM (100MB)
        const max_size: usize = 100 * 1024 * 1024;
        const read_size: usize = @min(size, max_size);

        const content = try self.allocator.alloc(u8, read_size);
        errdefer self.allocator.free(content);

        const bytes_read = try file.readAll(content);
        if (bytes_read < read_size) {
            return self.allocator.realloc(content, bytes_read);
        }

        return content;
    }

    /// Read logs and output to writer (supports follow mode)
    pub fn streamLogs(
        self: *Self,
        writer: anytype,
        options: LogOptions,
    ) !void {
        // Determine which files to read
        const read_stdout = options.stream == .stdout or options.stream == .both;
        const read_stderr = options.stream == .stderr or options.stream == .both;

        // Get file paths
        var stdout_path: ?[]const u8 = null;
        var stderr_path: ?[]const u8 = null;
        defer {
            if (stdout_path) |p| self.allocator.free(p);
            if (stderr_path) |p| self.allocator.free(p);
        }

        if (read_stdout) {
            stdout_path = try self.getStdoutPath();
        }
        if (read_stderr) {
            stderr_path = try self.getStderrPath();
        }

        // Track file positions for follow mode
        var stdout_pos: u64 = 0;
        var stderr_pos: u64 = 0;

        // If tail is specified, calculate starting position
        if (options.tail > 0 and !options.follow) {
            if (stdout_path) |path| {
                stdout_pos = self.getLastNLinesOffset(path, options.tail) catch 0;
            }
            if (stderr_path) |path| {
                stderr_pos = self.getLastNLinesOffset(path, options.tail) catch 0;
            }
        }

        // Initial read
        if (stdout_path) |path| {
            try self.readAndOutputFile(path, &stdout_pos, writer, "stdout", options.timestamps);
        }
        if (stderr_path) |path| {
            try self.readAndOutputFile(path, &stderr_pos, writer, "stderr", options.timestamps);
        }

        // Follow mode - continuously poll for new data
        if (options.follow) {
            while (true) {
                // Sleep before next poll
                std.Thread.sleep(options.poll_interval_ms * std.time.ns_per_ms);

                var had_output = false;

                if (stdout_path) |path| {
                    const before_pos = stdout_pos;
                    try self.readAndOutputFile(path, &stdout_pos, writer, "stdout", options.timestamps);
                    if (stdout_pos > before_pos) had_output = true;
                }
                if (stderr_path) |path| {
                    const before_pos = stderr_pos;
                    try self.readAndOutputFile(path, &stderr_pos, writer, "stderr", options.timestamps);
                    if (stderr_pos > before_pos) had_output = true;
                }

                // Flush if we had output
                if (had_output) {
                    writer.flush() catch {};
                }
            }
        }
    }

    /// Calculate file offset for last N lines
    fn getLastNLinesOffset(self: *Self, path: []const u8, n: usize) !u64 {
        _ = self;

        const file = std.fs.cwd().openFile(path, .{}) catch {
            return 0;
        };
        defer file.close();

        const stat = try file.stat();
        const size = stat.size;

        if (size == 0) return 0;

        // Read from end to find N newlines
        const chunk_size: usize = 4096;
        var lines_found: usize = 0;
        var offset: u64 = size;

        var buf: [4096]u8 = undefined;

        while (offset > 0 and lines_found < n + 1) {
            const read_start = if (offset > chunk_size) offset - chunk_size else 0;
            const read_len: usize = @intCast(offset - read_start);

            try file.seekTo(read_start);
            const bytes_read = try file.read(buf[0..read_len]);

            // Count newlines from end
            var i: usize = bytes_read;
            while (i > 0) : (i -= 1) {
                if (buf[i - 1] == '\n') {
                    lines_found += 1;
                    if (lines_found >= n + 1) {
                        return read_start + i;
                    }
                }
            }

            offset = read_start;
        }

        return 0;
    }

    /// Read file from position and output to writer
    fn readAndOutputFile(
        self: *Self,
        path: []const u8,
        position: *u64,
        writer: anytype,
        stream_name: []const u8,
        show_timestamps: bool,
    ) !void {
        _ = self;
        _ = stream_name;

        const file = std.fs.cwd().openFile(path, .{}) catch {
            return; // File doesn't exist yet
        };
        defer file.close();

        const stat = try file.stat();
        const size = stat.size;

        // Nothing new to read
        if (size <= position.*) {
            return;
        }

        try file.seekTo(position.*);

        var buf: [8192]u8 = undefined;
        while (true) {
            const bytes_read = file.read(&buf) catch break;
            if (bytes_read == 0) break;

            // Output with optional timestamp prefix
            if (show_timestamps) {
                const timestamp = std.time.timestamp();
                // Simple ISO-like timestamp
                try writer.print("[{d}] ", .{timestamp});
            }

            try writer.writeAll(buf[0..bytes_read]);
            position.* += bytes_read;
        }
    }

    /// Append data to stdout log
    pub fn appendStdout(self: *Self, data: []const u8) !void {
        try self.ensureLogDir();
        const path = try self.getStdoutPath();
        defer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{
            .truncate = false,
        });
        defer file.close();

        try file.seekFromEnd(0);
        try file.writeAll(data);
    }

    /// Append data to stderr log
    pub fn appendStderr(self: *Self, data: []const u8) !void {
        try self.ensureLogDir();
        const path = try self.getStderrPath();
        defer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{
            .truncate = false,
        });
        defer file.close();

        try file.seekFromEnd(0);
        try file.writeAll(data);
    }

    /// Clear all logs for this container
    pub fn clear(self: *Self) !void {
        const stdout_path = try self.getStdoutPath();
        defer self.allocator.free(stdout_path);
        std.fs.cwd().deleteFile(stdout_path) catch {};

        const stderr_path = try self.getStderrPath();
        defer self.allocator.free(stderr_path);
        std.fs.cwd().deleteFile(stderr_path) catch {};
    }

    /// Get log file sizes
    pub const LogStats = struct {
        stdout_size: u64,
        stderr_size: u64,
    };

    pub fn getStats(self: *Self) !LogStats {
        var stats = LogStats{
            .stdout_size = 0,
            .stderr_size = 0,
        };

        const stdout_path = try self.getStdoutPath();
        defer self.allocator.free(stdout_path);

        if (std.fs.cwd().openFile(stdout_path, .{})) |file| {
            defer file.close();
            const st = try file.stat();
            stats.stdout_size = st.size;
        } else |_| {}

        const stderr_path = try self.getStderrPath();
        defer self.allocator.free(stderr_path);

        if (std.fs.cwd().openFile(stderr_path, .{})) |file| {
            defer file.close();
            const st = try file.stat();
            stats.stderr_size = st.size;
        } else |_| {}

        return stats;
    }
};

/// Create log files for a new container and return file descriptors
/// Returns stdout_fd and stderr_fd for use with process spawning
pub fn createLogFiles(allocator: std.mem.Allocator, container_id: []const u8) !struct {
    stdout_path: []const u8,
    stderr_path: []const u8,
} {
    var logs = try ContainerLogs.init(allocator, container_id);
    defer logs.deinit();

    try logs.ensureLogDir();

    const stdout_path = try logs.getStdoutPath();
    errdefer allocator.free(stdout_path);

    const stderr_path = try logs.getStderrPath();
    errdefer allocator.free(stderr_path);

    // Create empty log files
    {
        const file = try std.fs.cwd().createFile(stdout_path, .{});
        file.close();
    }
    {
        const file = try std.fs.cwd().createFile(stderr_path, .{});
        file.close();
    }

    return .{
        .stdout_path = stdout_path,
        .stderr_path = stderr_path,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "ContainerLogs initialization" {
    const allocator = std.testing.allocator;

    // Use a test container ID
    var logs = ContainerLogs.init(allocator, "test1234567890ab") catch {
        // Skip test if HOME not set
        return;
    };
    defer logs.deinit();

    // Verify paths are constructed correctly
    const stdout_path = try logs.getStdoutPath();
    defer allocator.free(stdout_path);

    try std.testing.expect(std.mem.endsWith(u8, stdout_path, "/stdout.log"));
}
