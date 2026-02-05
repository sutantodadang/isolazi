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

/// Download progress information passed to progress callback
pub const DownloadProgress = struct {
    /// Bytes downloaded so far
    bytes_downloaded: u64,
    /// Total bytes to download (0 if unknown)
    total_bytes: u64,
    /// Current download speed in bytes per second
    bytes_per_second: u64,
    /// Layer digest being downloaded
    digest: []const u8,
    /// Layer index (1-based)
    layer_index: usize,
    /// Total number of layers
    total_layers: usize,

    /// Get download progress as percentage (0-100)
    pub fn percentComplete(self: DownloadProgress) u8 {
        if (self.total_bytes == 0) return 0;
        return @intCast(@min(100, (self.bytes_downloaded * 100) / self.total_bytes));
    }

    /// Format bytes as human-readable string (e.g., "1.5 MB")
    pub fn formatBytes(bytes: u64, buf: []u8) []const u8 {
        const units = [_][]const u8{ "B", "KB", "MB", "GB" };
        var size: f64 = @floatFromInt(bytes);
        var unit_idx: usize = 0;

        while (size >= 1024 and unit_idx < units.len - 1) {
            size /= 1024;
            unit_idx += 1;
        }

        return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ size, units[unit_idx] }) catch "?";
    }
};

/// Progress callback function type
pub const ProgressCallback = *const fn (progress: DownloadProgress) void;

/// Registry client for OCI image operations using native Zig HTTP
pub const RegistryClient = struct {
    allocator: std.mem.Allocator,
    auth_token: ?[]const u8,
    http_client: std.http.Client,

    const Self = @This();

    /// Buffer size for redirect handling
    const REDIRECT_BUFFER_SIZE = 8 * 1024;

    pub fn init(allocator: std.mem.Allocator) !Self {
        var client = std.http.Client{ .allocator = allocator };
        try client.ca_bundle.rescan(allocator);
        return Self{
            .allocator = allocator,
            .auth_token = null,
            .http_client = client,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.auth_token) |token| {
            self.allocator.free(token);
        }
        self.http_client.deinit();
    }

    /// Perform an HTTP GET request using fetch API and return the response body
    /// Optimized for speed with connection reuse and minimal allocations
    fn httpGet(
        self: *Self,
        url: []const u8,
        extra_headers: []const std.http.Header,
    ) ![]u8 {
        const parsed_uri = std.Uri.parse(url) catch return RegistryError.InvalidResponse;

        var redirect_buffer: [REDIRECT_BUFFER_SIZE]u8 = undefined;

        // Pre-allocate larger initial capacity for faster response handling
        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try body.ensureUnusedCapacity(16 * 1024); // 16KB initial capacity

        const result = self.http_client.fetch(.{
            .location = .{ .uri = parsed_uri },
            .method = .GET,
            .redirect_buffer = &redirect_buffer,
            .response_writer = &body.writer,
            .extra_headers = extra_headers,
            .keep_alive = true, // Enable connection reuse
        }) catch |err| {
            std.debug.print("Network error during fetch: {s}\n", .{@errorName(err)});
            return RegistryError.NetworkError;
        };

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

    /// Download progress context for tracking progress across redirects
    pub const DownloadContext = struct {
        progress_callback: ?ProgressCallback = null,
        digest: []const u8 = "",
        layer_index: usize = 0,
        total_layers: usize = 0,
    };

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
        return self.httpDownloadToFileWithProgress(url, dest_path, auth_headers, .{});
    }

    /// Download a file with progress reporting
    fn httpDownloadToFileWithProgress(
        self: *Self,
        url: []const u8,
        dest_path: []const u8,
        auth_headers: []const std.http.Header,
        ctx: DownloadContext,
    ) !void {
        const max_retries: u32 = 3;
        var attempt: u32 = 0;

        while (attempt < max_retries) : (attempt += 1) {
            if (attempt > 0) {
                // Brief delay before retry (exponential backoff: 100ms, 200ms, 400ms)
                std.Thread.sleep(100 * std.time.ns_per_ms * (@as(u64, 1) << @intCast(attempt - 1)));
            }

            const result = self.httpDownloadToFileOnce(url, dest_path, auth_headers, ctx);
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
        ctx: DownloadContext,
    ) !void {
        const parsed_uri = std.Uri.parse(url) catch return RegistryError.InvalidResponse;

        // Use a fresh HTTP client for downloads to avoid thread conflicts
        var download_client = std.http.Client{ .allocator = self.allocator };
        defer download_client.deinit();
        try download_client.ca_bundle.rescan(self.allocator);

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
                // No redirect, download directly using body reader with progress
                try self.downloadWithProgress(&response, dest_path, ctx);
            },
            .temporary_redirect, .moved_permanently, .found, .see_other => {
                // Got a redirect - extract Location header and follow without auth
                const redirect_url = response.head.location orelse return RegistryError.NetworkError;

                // Second request without auth headers (CDN doesn't need them)
                const redirect_uri = std.Uri.parse(redirect_url) catch return RegistryError.InvalidResponse;

                var req2 = download_client.request(.GET, redirect_uri, .{
                    .extra_headers = &.{}, // No auth for CDN
                    .redirect_behavior = .unhandled,
                }) catch return RegistryError.NetworkError;
                defer req2.deinit();

                req2.sendBodiless() catch return RegistryError.NetworkError;
                var response2 = req2.receiveHead(&redirect_buffer) catch return RegistryError.NetworkError;

                if (response2.head.status != .ok) {
                    return RegistryError.NetworkError;
                }

                try self.downloadWithProgress(&response2, dest_path, ctx);
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

    /// Download response body to file with progress reporting
    /// Uses streaming approach for maximum throughput while reporting progress
    fn downloadWithProgress(
        self: *Self,
        response: anytype,
        dest_path: []const u8,
        ctx: DownloadContext,
    ) !void {
        _ = self;
        const file = std.fs.cwd().createFile(dest_path, .{}) catch return RegistryError.FileError;
        defer file.close();

        // Get content length if available
        const content_length: u64 = if (response.head.content_length) |len| len else 0;

        // Use large transfer buffer for optimal network throughput (1MB)
        const BUFFER_SIZE = 1024 * 1024;
        var transfer_buf: [BUFFER_SIZE]u8 = undefined;
        var body_reader = response.reader(&transfer_buf);

        // Progress tracking state
        var bytes_downloaded: u64 = 0;
        var last_progress_time: i128 = std.time.nanoTimestamp();
        var last_bytes_for_speed: u64 = 0;
        var current_speed: u64 = 0;

        // Buffer for reading chunks directly
        var chunk_buf: [256 * 1024]u8 = undefined;

        // Read and write directly without buffered writer
        while (true) {
            // Check if we've received all expected content before trying to read more
            if (content_length > 0 and bytes_downloaded >= content_length) {
                break;
            }

            // Calculate how much we should try to read
            const max_to_read = if (content_length > 0)
                @min(chunk_buf.len, content_length - bytes_downloaded)
            else
                chunk_buf.len;

            if (max_to_read == 0) {
                break;
            }

            // Read a chunk from the body
            const bytes_read = body_reader.readSliceShort(chunk_buf[0..max_to_read]) catch |err| {
                // Handle end of stream - this is normal completion
                if (err == error.EndOfStream) {
                    break;
                }
                // If we've already downloaded all expected content, this is fine
                if (content_length > 0 and bytes_downloaded >= content_length) {
                    break;
                }
                return RegistryError.NetworkError;
            };

            if (bytes_read == 0) {
                // End of data
                break;
            }

            // Write directly to file (unbuffered for reliability)
            file.writeAll(chunk_buf[0..bytes_read]) catch return RegistryError.FileError;
            bytes_downloaded += bytes_read;

            // Report progress every 250ms to reduce overhead
            const now: i128 = std.time.nanoTimestamp();
            const elapsed_ns: i128 = now - last_progress_time;
            const threshold: i128 = 250 * std.time.ns_per_ms;
            if (elapsed_ns >= threshold) {
                // Calculate speed
                if (elapsed_ns > 0) {
                    const bytes_since_last = bytes_downloaded - last_bytes_for_speed;
                    const ns_per_s: i128 = std.time.ns_per_s;
                    current_speed = @intCast(@divFloor(bytes_since_last * ns_per_s, @as(u64, @intCast(elapsed_ns))));
                    last_bytes_for_speed = bytes_downloaded;
                    last_progress_time = now;
                }

                if (ctx.progress_callback) |callback| {
                    callback(.{
                        .bytes_downloaded = bytes_downloaded,
                        .total_bytes = content_length,
                        .bytes_per_second = current_speed,
                        .digest = ctx.digest,
                        .layer_index = ctx.layer_index,
                        .total_layers = ctx.total_layers,
                    });
                }
            }
        }

        // Final progress report
        if (ctx.progress_callback) |callback| {
            callback(.{
                .bytes_downloaded = bytes_downloaded,
                .total_bytes = if (content_length > 0) content_length else bytes_downloaded,
                .bytes_per_second = current_speed,
                .digest = ctx.digest,
                .layer_index = ctx.layer_index,
                .total_layers = ctx.total_layers,
            });
        }
    }

    /// Authenticate with Docker Hub (get bearer token)
    /// Optimized with faster JSON parsing
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

        // Fast token extraction - find "token":" and extract value
        // This is faster than full JSON parsing for simple token extraction
        const token = extractTokenFast(body) orelse {
            // Fallback to full JSON parsing
            const parsed = std.json.parseFromSlice(
                struct { token: []const u8 },
                self.allocator,
                body,
                .{ .ignore_unknown_fields = true },
            ) catch return RegistryError.InvalidResponse;
            defer parsed.deinit();

            if (self.auth_token) |old| {
                self.allocator.free(old);
            }
            self.auth_token = try self.allocator.dupe(u8, parsed.value.token);
            return;
        };

        // Store token
        if (self.auth_token) |old| {
            self.allocator.free(old);
        }
        self.auth_token = try self.allocator.dupe(u8, token);
    }

    /// Fast token extraction without full JSON parsing
    fn extractTokenFast(body: []const u8) ?[]const u8 {
        // Look for "token":" pattern
        const needle = "\"token\":\"";
        const start_idx = std.mem.indexOf(u8, body, needle) orelse return null;
        const token_start = start_idx + needle.len;

        // Find the closing quote
        const remaining = body[token_start..];
        const end_idx = std.mem.indexOf(u8, remaining, "\"") orelse return null;

        return remaining[0..end_idx];
    }

    /// Authenticate and fetch manifest in optimized sequence
    /// Returns the manifest data
    pub fn authenticateAndGetManifest(
        self: *Self,
        repository: []const u8,
        tag: []const u8,
    ) ![]u8 {
        // Authenticate first (required for Docker Hub)
        try self.authenticateDockerHub(repository);
        // Then get manifest using the same connection pool
        return self.getManifest(repository, tag);
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
        try self.downloadBlobToFileWithProgress(repository, digest, dest_path, null, 0, 0);
    }

    /// Download a blob with progress reporting
    pub fn downloadBlobToFileWithProgress(
        self: *Self,
        repository: []const u8,
        digest: []const u8,
        dest_path: []const u8,
        progress_callback: ?ProgressCallback,
        layer_index: usize,
        total_layers: usize,
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

        try self.httpDownloadToFileWithProgress(url, dest_path, headers_buf[0..header_count], .{
            .progress_callback = progress_callback,
            .digest = digest,
            .layer_index = layer_index,
            .total_layers = total_layers,
        });
    }
};

// =============================================================================
// Tests
// =============================================================================

test "RegistryClient initialization" {
    var client = try RegistryClient.init(std.testing.allocator);
    defer client.deinit();
    try std.testing.expect(client.auth_token == null);
}
