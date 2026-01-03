//! OCI Registry Client
//!
//! Implements the OCI Distribution Specification for pulling images:
//! https://github.com/opencontainers/distribution-spec
//!
//! Uses curl as a subprocess for HTTP requests (more portable)
//!
//! Workflow:
//! 1. GET /v2/ - Check registry supports v2 API
//! 2. GET /v2/<repo>/manifests/<tag> - Get image manifest
//! 3. GET /v2/<repo>/blobs/<digest> - Download each layer
//!
//! Authentication:
//! - Anonymous access for public images
//! - Bearer token auth (Docker Hub style)
//! - Basic auth (private registries)

const std = @import("std");
const builtin = @import("builtin");
const reference = @import("reference.zig");

const ImageReference = reference.ImageReference;

/// OCI Media Types
pub const MediaType = struct {
    /// Docker manifest v2 schema 2
    pub const DOCKER_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json";
    /// Docker manifest list (multi-arch)
    pub const DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
    /// OCI image manifest
    pub const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
    /// OCI image index (multi-arch)
    pub const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
    /// Docker layer (gzipped tar)
    pub const DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    /// OCI layer (gzipped tar)
    pub const OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip";
};

/// Registry client errors
pub const RegistryError = error{
    ConnectionFailed,
    Unauthorized,
    NotFound,
    RateLimited,
    ServerError,
    InvalidResponse,
    CurlNotFound,
    OutOfMemory,
    NetworkError,
};

/// Registry client for OCI image operations
pub const RegistryClient = struct {
    allocator: std.mem.Allocator,
    auth_token: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .auth_token = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.auth_token) |token| {
            self.allocator.free(token);
        }
    }

    /// Run curl and get stdout
    fn runCurl(self: *Self, args: []const []const u8) ![]u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);

        // Use curl.exe on Windows to avoid PowerShell alias
        const curl_cmd = if (builtin.os.tag == .windows) "curl.exe" else "curl";
        try argv.append(self.allocator, curl_cmd);
        try argv.append(self.allocator, "-sL"); // silent, follow redirects

        for (args) |arg| {
            try argv.append(self.allocator, arg);
        }

        var child = std.process.Child.init(argv.items, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const stdout_file = child.stdout orelse return RegistryError.NetworkError;

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        var chunk_buf: [8192]u8 = undefined;
        while (true) {
            const n = stdout_file.read(&chunk_buf) catch break;
            if (n == 0) break;
            try result.appendSlice(self.allocator, chunk_buf[0..n]);
        }

        const term = child.wait() catch return RegistryError.NetworkError;
        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    return RegistryError.NetworkError;
                }
            },
            else => return RegistryError.NetworkError,
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Authenticate with Docker Hub (get bearer token)
    pub fn authenticateDockerHub(self: *Self, repository: []const u8) !void {
        // Handle official images - add library/ prefix
        var repo_buf: [512]u8 = undefined;
        const auth_repo = if (!std.mem.containsAtLeast(u8, repository, 1, "/"))
            try std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository})
        else
            repository;

        var url_buf: [1024]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{s}:pull",
            .{auth_repo},
        );

        const body = try self.runCurl(&[_][]const u8{url});
        defer self.allocator.free(body);

        // Parse JSON to extract token
        const parsed = std.json.parseFromSlice(
            struct { token: []const u8 },
            self.allocator,
            body,
            .{ .ignore_unknown_fields = true },
        ) catch return RegistryError.InvalidResponse;
        defer parsed.deinit();

        // Store token
        if (self.auth_token) |old| {
            self.allocator.free(old);
        }
        self.auth_token = try self.allocator.dupe(u8, parsed.value.token);
    }

    /// Fetch image manifest as raw JSON
    pub fn getManifest(self: *Self, repository: []const u8, tag: []const u8) ![]u8 {
        // Handle Docker Hub - add library/ prefix for official images
        var repo_buf: [512]u8 = undefined;
        const api_repo = if (!std.mem.containsAtLeast(u8, repository, 1, "/"))
            try std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository})
        else
            repository;

        // Build manifest URL (larger buffer to accommodate sha256 digests)
        var url_buf: [4096]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/manifests/{s}",
            .{ api_repo, tag },
        );

        // Build curl args
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        try args.append(self.allocator, "-H");
        try args.append(self.allocator, "Accept: " ++ MediaType.DOCKER_MANIFEST_V2);

        // Store auth_header to free later
        var auth_header: ?[]const u8 = null;
        defer if (auth_header) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            try args.append(self.allocator, "-H");
            auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{token});
            try args.append(self.allocator, auth_header.?);
        }

        try args.append(self.allocator, url);

        return self.runCurl(args.items);
    }

    /// Download a blob (layer or config) to memory
    pub fn downloadBlob(
        self: *Self,
        repository: []const u8,
        digest: []const u8,
    ) ![]u8 {
        // Handle Docker Hub - add library/ prefix for official images
        var repo_buf: [512]u8 = undefined;
        const api_repo = if (!std.mem.containsAtLeast(u8, repository, 1, "/"))
            try std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository})
        else
            repository;

        // Build blob URL
        var url_buf: [2048]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/blobs/{s}",
            .{ api_repo, digest },
        );

        // Build curl args
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        // Store auth_header to free later
        var auth_header: ?[]const u8 = null;
        defer if (auth_header) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            try args.append(self.allocator, "-H");
            auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{token});
            try args.append(self.allocator, auth_header.?);
        }

        try args.append(self.allocator, url);

        return self.runCurl(args.items);
    }

    /// Download a blob (layer or config) directly to a file for better memory efficiency
    pub fn downloadBlobToFile(
        self: *Self,
        repository: []const u8,
        digest: []const u8,
        dest_path: []const u8,
    ) !void {
        // Handle Docker Hub - add library/ prefix for official images
        var repo_buf: [512]u8 = undefined;
        const api_repo = if (!std.mem.containsAtLeast(u8, repository, 1, "/"))
            try std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository})
        else
            repository;

        // Build blob URL
        var url_buf: [2048]u8 = undefined;
        const url = try std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/blobs/{s}",
            .{ api_repo, digest },
        );

        // Build curl args
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        try args.append(self.allocator, "-o");
        try args.append(self.allocator, dest_path);

        // Store auth_header to free later
        var auth_header: ?[]const u8 = null;
        defer if (auth_header) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            try args.append(self.allocator, "-H");
            auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{token});
            try args.append(self.allocator, auth_header.?);
        }

        try args.append(self.allocator, url);

        const result = try self.runCurl(args.items);
        self.allocator.free(result);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "RegistryClient initialization" {
    var client = RegistryClient.init(std.testing.allocator);
    defer client.deinit();
    try std.testing.expect(client.auth_token == null);
}
