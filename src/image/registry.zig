//! OCI Registry Client
//!
//! Implements the OCI Distribution Specification for pulling images:
//! https://github.com/opencontainers/distribution-spec
//!
//! Uses Zig's native std.http.Client for HTTP requests (no external dependencies)
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
    OutOfMemory,
    NetworkError,
    TlsError,
    FileError,
    RedirectError,
};

/// Registry client for OCI image operations using native Zig HTTP
pub const RegistryClient = struct {
    allocator: std.mem.Allocator,
    auth_token: ?[]const u8,
    http_client: std.http.Client,

    const Self = @This();

    /// Buffer size for redirect handling
    const REDIRECT_BUFFER_SIZE = 8 * 1024;

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .auth_token = null,
            .http_client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.auth_token) |token| {
            self.allocator.free(token);
        }
        self.http_client.deinit();
    }

    /// Perform an HTTP GET request using fetch API and return the response body
    fn httpGet(
        self: *Self,
        url: []const u8,
        extra_headers: []const std.http.Header,
    ) ![]u8 {
        const parsed_uri = std.Uri.parse(url) catch return RegistryError.InvalidResponse;

        var redirect_buffer: [REDIRECT_BUFFER_SIZE]u8 = undefined;
        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try body.ensureUnusedCapacity(1024);

        const result = self.http_client.fetch(.{
            .location = .{ .uri = parsed_uri },
            .method = .GET,
            .redirect_buffer = &redirect_buffer,
            .response_writer = &body.writer,
            .extra_headers = extra_headers,
        }) catch return RegistryError.NetworkError;

        // Check status code
        switch (result.status) {
            .ok => {},
            .unauthorized => return RegistryError.Unauthorized,
            .not_found => return RegistryError.NotFound,
            .too_many_requests => return RegistryError.RateLimited,
            else => {
                if (@intFromEnum(result.status) >= 500) {
                    return RegistryError.ServerError;
                }
                return RegistryError.NetworkError;
            },
        }

        return body.toOwnedSlice() catch return RegistryError.OutOfMemory;
    }

    /// Download a file via HTTP GET and write directly to disk
    /// Handles Docker Hub's redirect to CDN by making two requests:
    /// 1. First request with auth to get redirect URL
    /// 2. Second request without auth to download from CDN
    /// Uses a fresh HTTP client to avoid thread safety issues
    /// Includes retry logic for transient network failures
    fn httpDownloadToFile(
        self: *Self,
        url: []const u8,
        dest_path: []const u8,
        auth_headers: []const std.http.Header,
    ) !void {
        const max_retries: u32 = 3;
        var attempt: u32 = 0;

        while (attempt < max_retries) : (attempt += 1) {
            if (attempt > 0) {
                // Brief delay before retry (exponential backoff: 100ms, 200ms, 400ms)
                std.Thread.sleep(100 * std.time.ns_per_ms * (@as(u64, 1) << @intCast(attempt - 1)));
            }

            const result = self.httpDownloadToFileOnce(url, dest_path, auth_headers);
            if (result) |_| {
                return; // Success
            } else |err| {
                // Only retry on network errors, not auth/notfound/etc
                if (err != RegistryError.NetworkError) {
                    return err;
                }
                // On last attempt, return the error
                if (attempt == max_retries - 1) {
                    return err;
                }
                // Otherwise, retry
            }
        }
    }

    /// Single attempt to download a file (called by httpDownloadToFile with retries)
    fn httpDownloadToFileOnce(
        self: *Self,
        url: []const u8,
        dest_path: []const u8,
        auth_headers: []const std.http.Header,
    ) !void {
        const parsed_uri = std.Uri.parse(url) catch return RegistryError.InvalidResponse;

        // Use a fresh HTTP client for downloads to avoid thread conflicts
        var download_client = std.http.Client{ .allocator = self.allocator };
        defer download_client.deinit();

        // First request with auth - don't follow redirects automatically
        var redirect_buffer: [REDIRECT_BUFFER_SIZE]u8 = undefined;

        var req = download_client.request(.GET, parsed_uri, .{
            .extra_headers = auth_headers,
            .redirect_behavior = .unhandled,
        }) catch return RegistryError.NetworkError;
        defer req.deinit();

        req.sendBodiless() catch return RegistryError.NetworkError;
        var response = req.receiveHead(&redirect_buffer) catch return RegistryError.NetworkError;

        // Check status code
        switch (response.head.status) {
            .ok => {
                // No redirect, download directly using body reader
                const file = std.fs.cwd().createFile(dest_path, .{}) catch return RegistryError.FileError;
                defer file.close();

                var transfer_buf: [16 * 1024]u8 = undefined;
                const body_reader = response.reader(&transfer_buf);

                // Stream the body to file
                var write_buf: [16 * 1024]u8 = undefined;
                var file_writer = file.writer(&write_buf);
                _ = body_reader.streamRemaining(&file_writer.interface) catch return RegistryError.NetworkError;
            },
            .temporary_redirect, .moved_permanently, .found, .see_other => {
                // Got a redirect - extract Location header and follow without auth
                const redirect_url = response.head.location orelse return RegistryError.NetworkError;

                // Second request without auth headers (CDN doesn't need them)
                const redirect_uri = std.Uri.parse(redirect_url) catch return RegistryError.InvalidResponse;

                var body: std.Io.Writer.Allocating = .init(self.allocator);
                defer body.deinit();
                try body.ensureUnusedCapacity(64 * 1024);

                // Use the same download_client for the redirect request
                const result2 = download_client.fetch(.{
                    .location = .{ .uri = redirect_uri },
                    .method = .GET,
                    .redirect_buffer = &redirect_buffer,
                    .response_writer = &body.writer,
                    .extra_headers = &.{}, // No auth for CDN
                }) catch return RegistryError.NetworkError;

                if (result2.status != .ok) {
                    return RegistryError.NetworkError;
                }

                const file = std.fs.cwd().createFile(dest_path, .{}) catch return RegistryError.FileError;
                defer file.close();
                const data = body.toOwnedSlice() catch return RegistryError.OutOfMemory;
                defer self.allocator.free(data);
                file.writeAll(data) catch return RegistryError.FileError;
            },
            .unauthorized => return RegistryError.Unauthorized,
            .not_found => return RegistryError.NotFound,
            .too_many_requests => return RegistryError.RateLimited,
            else => {
                if (@intFromEnum(response.head.status) >= 500) {
                    return RegistryError.ServerError;
                }
                return RegistryError.NetworkError;
            },
        }
    }

    /// Authenticate with Docker Hub (get bearer token)
    pub fn authenticateDockerHub(self: *Self, repository: []const u8) !void {
        // Handle official images - add library/ prefix
        var repo_buf: [512]u8 = undefined;
        const auth_repo = if (!std.mem.containsAtLeast(u8, repository, 1, "/"))
            std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository}) catch return RegistryError.OutOfMemory
        else
            repository;

        var url_buf: [1024]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{s}:pull",
            .{auth_repo},
        ) catch return RegistryError.OutOfMemory;

        const body = try self.httpGet(url, &.{});
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
            std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository}) catch return RegistryError.OutOfMemory
        else
            repository;

        // Build manifest URL (larger buffer to accommodate sha256 digests)
        var url_buf: [4096]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/manifests/{s}",
            .{ api_repo, tag },
        ) catch return RegistryError.OutOfMemory;

        // Build headers
        var headers_buf: [2]std.http.Header = undefined;
        var header_count: usize = 0;

        // Accept header for manifest type
        headers_buf[header_count] = .{
            .name = "Accept",
            .value = MediaType.DOCKER_MANIFEST_V2,
        };
        header_count += 1;

        // Authorization header if we have a token
        var auth_header_value: ?[]const u8 = null;
        defer if (auth_header_value) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            auth_header_value = std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token}) catch return RegistryError.OutOfMemory;
            headers_buf[header_count] = .{
                .name = "Authorization",
                .value = auth_header_value.?,
            };
            header_count += 1;
        }

        return self.httpGet(url, headers_buf[0..header_count]);
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
            std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository}) catch return RegistryError.OutOfMemory
        else
            repository;

        // Build blob URL
        var url_buf: [2048]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/blobs/{s}",
            .{ api_repo, digest },
        ) catch return RegistryError.OutOfMemory;

        // Build headers
        var headers_buf: [1]std.http.Header = undefined;
        var header_count: usize = 0;

        // Authorization header if we have a token
        var auth_header_value: ?[]const u8 = null;
        defer if (auth_header_value) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            auth_header_value = std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token}) catch return RegistryError.OutOfMemory;
            headers_buf[header_count] = .{
                .name = "Authorization",
                .value = auth_header_value.?,
            };
            header_count += 1;
        }

        return self.httpGet(url, headers_buf[0..header_count]);
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
            std.fmt.bufPrint(&repo_buf, "library/{s}", .{repository}) catch return RegistryError.OutOfMemory
        else
            repository;

        // Build blob URL
        var url_buf: [2048]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "https://registry-1.docker.io/v2/{s}/blobs/{s}",
            .{ api_repo, digest },
        ) catch return RegistryError.OutOfMemory;

        // Build headers
        var headers_buf: [1]std.http.Header = undefined;
        var header_count: usize = 0;

        // Authorization header if we have a token
        var auth_header_value: ?[]const u8 = null;
        defer if (auth_header_value) |h| self.allocator.free(h);

        if (self.auth_token) |token| {
            auth_header_value = std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token}) catch return RegistryError.OutOfMemory;
            headers_buf[header_count] = .{
                .name = "Authorization",
                .value = auth_header_value.?,
            };
            header_count += 1;
        }

        try self.httpDownloadToFile(url, dest_path, headers_buf[0..header_count]);
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
