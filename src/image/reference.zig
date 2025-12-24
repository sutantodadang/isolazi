//! OCI Image Reference Parser
//!
//! Parses image references in Docker/OCI format:
//! - alpine                     -> docker.io/library/alpine:latest
//! - alpine:3.18                -> docker.io/library/alpine:3.18
//! - nginx:latest               -> docker.io/library/nginx:latest
//! - myuser/myimage:v1          -> docker.io/myuser/myimage:v1
//! - ghcr.io/owner/repo:tag     -> ghcr.io/owner/repo:tag
//! - localhost:5000/img:tag     -> localhost:5000/img:tag
//!
//! OCI Image Reference Spec: https://github.com/opencontainers/distribution-spec

const std = @import("std");

/// Maximum lengths for reference components
pub const MAX_REGISTRY_LEN = 256;
pub const MAX_REPOSITORY_LEN = 256;
pub const MAX_TAG_LEN = 128;
pub const MAX_DIGEST_LEN = 128;

/// Default registry when none specified
pub const DEFAULT_REGISTRY = "docker.io";
/// Default namespace for official images on Docker Hub
pub const DEFAULT_NAMESPACE = "library";
/// Default tag when none specified
pub const DEFAULT_TAG = "latest";

/// Parsed OCI image reference
pub const ImageReference = struct {
    /// Registry hostname (e.g., "docker.io", "ghcr.io")
    registry: []const u8,
    /// Repository path (e.g., "library/alpine", "myuser/myimage")
    repository: []const u8,
    /// Tag (e.g., "latest", "3.18", "v1.0.0")
    tag: ?[]const u8,
    /// Digest (e.g., "sha256:abc123...")
    digest: ?[]const u8,

    /// Format the reference as a full string
    pub fn format(
        self: ImageReference,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try writer.print("{s}/{s}", .{ self.registry, self.repository });
        if (self.digest) |d| {
            try writer.print("@{s}", .{d});
        } else if (self.tag) |t| {
            try writer.print(":{s}", .{t});
        }
    }

    /// Get a unique identifier for caching (registry/repo:tag or registry/repo@digest)
    pub fn cacheKey(self: ImageReference, buf: []u8) ![]const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        try writer.print("{s}/{s}", .{ self.registry, self.repository });
        if (self.digest) |d| {
            try writer.print("@{s}", .{d});
        } else if (self.tag) |t| {
            try writer.print(":{s}", .{t});
        } else {
            try writer.print(":{s}", .{DEFAULT_TAG});
        }

        return stream.getWritten();
    }

    /// Get the effective tag (returns DEFAULT_TAG if no tag or digest)
    pub fn effectiveTag(self: ImageReference) []const u8 {
        return self.tag orelse DEFAULT_TAG;
    }

    /// Check if this reference uses a digest
    pub fn hasDigest(self: ImageReference) bool {
        return self.digest != null;
    }
};

pub const ParseError = error{
    InvalidReference,
    RegistryTooLong,
    RepositoryTooLong,
    TagTooLong,
    DigestTooLong,
    EmptyReference,
    InvalidDigestFormat,
};

/// Parse an image reference string.
///
/// Supported formats:
/// - "alpine" -> docker.io/library/alpine:latest
/// - "alpine:3.18" -> docker.io/library/alpine:3.18
/// - "user/image:tag" -> docker.io/user/image:tag
/// - "registry.io/user/image:tag" -> registry.io/user/image:tag
/// - "image@sha256:..." -> docker.io/library/image@sha256:...
pub fn parse(reference: []const u8) ParseError!ImageReference {
    if (reference.len == 0) {
        return ParseError.EmptyReference;
    }

    var registry: []const u8 = DEFAULT_REGISTRY;
    var repository: []const u8 = undefined;
    var tag: ?[]const u8 = null;
    var digest: ?[]const u8 = null;

    var remaining = reference;

    // Check for digest (@sha256:...)
    if (std.mem.indexOf(u8, remaining, "@")) |digest_pos| {
        digest = remaining[digest_pos + 1 ..];
        remaining = remaining[0..digest_pos];

        // Validate digest format (should start with algorithm:)
        if (!std.mem.startsWith(u8, digest.?, "sha256:") and
            !std.mem.startsWith(u8, digest.?, "sha512:"))
        {
            return ParseError.InvalidDigestFormat;
        }

        if (digest.?.len > MAX_DIGEST_LEN) {
            return ParseError.DigestTooLong;
        }
    }

    // Check for tag (:tag) - only if no digest
    if (digest == null) {
        // Find the last colon that's not part of a port number
        // A port would be after a registry (contains dot or localhost)
        if (findTagColon(remaining)) |tag_pos| {
            tag = remaining[tag_pos + 1 ..];
            remaining = remaining[0..tag_pos];

            if (tag.?.len > MAX_TAG_LEN) {
                return ParseError.TagTooLong;
            }
        }
    }

    // Now parse registry and repository
    // A reference has a registry if:
    // 1. It contains a dot (.) before the first slash
    // 2. It contains a colon (:) before the first slash (port)
    // 3. It starts with "localhost"

    if (std.mem.indexOf(u8, remaining, "/")) |slash_pos| {
        const first_part = remaining[0..slash_pos];

        if (isRegistry(first_part)) {
            registry = first_part;
            repository = remaining[slash_pos + 1 ..];
        } else {
            // No explicit registry, use default
            repository = remaining;
        }
    } else {
        // No slash, just an image name
        repository = remaining;
    }

    // Validate lengths
    if (registry.len > MAX_REGISTRY_LEN) {
        return ParseError.RegistryTooLong;
    }
    if (repository.len > MAX_REPOSITORY_LEN) {
        return ParseError.RepositoryTooLong;
    }

    // Add "library/" prefix for Docker Hub official images
    if (std.mem.eql(u8, registry, DEFAULT_REGISTRY)) {
        if (std.mem.indexOf(u8, repository, "/") == null) {
            // Single-name image on Docker Hub needs library/ prefix
            // This will be handled by the caller when constructing URLs
        }
    }

    return ImageReference{
        .registry = registry,
        .repository = repository,
        .tag = tag,
        .digest = digest,
    };
}

/// Check if a string looks like a registry hostname
fn isRegistry(s: []const u8) bool {
    // Contains a dot (docker.io, ghcr.io, etc.)
    if (std.mem.indexOf(u8, s, ".") != null) return true;

    // Contains a colon (localhost:5000)
    if (std.mem.indexOf(u8, s, ":") != null) return true;

    // Is "localhost"
    if (std.mem.eql(u8, s, "localhost")) return true;

    return false;
}

/// Find the position of the tag colon (not a port colon)
fn findTagColon(s: []const u8) ?usize {
    // Walk backwards to find the last colon
    var i: usize = s.len;
    while (i > 0) {
        i -= 1;
        if (s[i] == ':') {
            // Check if this is after a slash (tag) or before (port)
            // If there's a slash after this colon, it's a port
            const after_colon = s[i + 1 ..];
            if (std.mem.indexOf(u8, after_colon, "/") == null) {
                // Check if the part before looks like a port (all digits)
                const is_port = blk: {
                    for (after_colon) |c| {
                        if (!std.ascii.isDigit(c)) break :blk false;
                    }
                    break :blk after_colon.len > 0;
                };

                // If after_colon is all digits and there's something that looks
                // like a registry before, it might be a port
                if (is_port and i > 0) {
                    const before_colon = s[0..i];
                    // If before colon has no slash and looks like hostname, it's a port
                    if (std.mem.indexOf(u8, before_colon, "/") == null and
                        (std.mem.indexOf(u8, before_colon, ".") != null or
                            std.mem.eql(u8, before_colon, "localhost")))
                    {
                        continue; // This is a port, keep looking
                    }
                }

                return i;
            }
        }
    }
    return null;
}

/// Get the full repository path for API calls
/// For Docker Hub, adds "library/" prefix to official images
pub fn getApiRepository(ref: ImageReference, buf: []u8) ![]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    if (std.mem.eql(u8, ref.registry, DEFAULT_REGISTRY)) {
        // Docker Hub: add library/ prefix for official images
        if (std.mem.indexOf(u8, ref.repository, "/") == null) {
            try writer.print("{s}/{s}", .{ DEFAULT_NAMESPACE, ref.repository });
            return stream.getWritten();
        }
    }

    try writer.writeAll(ref.repository);
    return stream.getWritten();
}

// =============================================================================
// Tests
// =============================================================================

test "parse simple image name" {
    const ref = try parse("alpine");
    try std.testing.expectEqualStrings("docker.io", ref.registry);
    try std.testing.expectEqualStrings("alpine", ref.repository);
    try std.testing.expectEqual(@as(?[]const u8, null), ref.tag);
}

test "parse image with tag" {
    const ref = try parse("alpine:3.18");
    try std.testing.expectEqualStrings("docker.io", ref.registry);
    try std.testing.expectEqualStrings("alpine", ref.repository);
    try std.testing.expectEqualStrings("3.18", ref.tag.?);
}

test "parse image with user" {
    const ref = try parse("myuser/myimage:v1");
    try std.testing.expectEqualStrings("docker.io", ref.registry);
    try std.testing.expectEqualStrings("myuser/myimage", ref.repository);
    try std.testing.expectEqualStrings("v1", ref.tag.?);
}

test "parse full registry path" {
    const ref = try parse("ghcr.io/owner/repo:latest");
    try std.testing.expectEqualStrings("ghcr.io", ref.registry);
    try std.testing.expectEqualStrings("owner/repo", ref.repository);
    try std.testing.expectEqualStrings("latest", ref.tag.?);
}

test "parse localhost registry with port" {
    const ref = try parse("localhost:5000/myimage:test");
    try std.testing.expectEqualStrings("localhost:5000", ref.registry);
    try std.testing.expectEqualStrings("myimage", ref.repository);
    try std.testing.expectEqualStrings("test", ref.tag.?);
}

test "parse image with digest" {
    const ref = try parse("alpine@sha256:abc123def456");
    try std.testing.expectEqualStrings("docker.io", ref.registry);
    try std.testing.expectEqualStrings("alpine", ref.repository);
    try std.testing.expectEqual(@as(?[]const u8, null), ref.tag);
    try std.testing.expectEqualStrings("sha256:abc123def456", ref.digest.?);
}

test "getApiRepository adds library prefix" {
    const ref = try parse("alpine:latest");
    var buf: [512]u8 = undefined;
    const repo = try getApiRepository(ref, &buf);
    try std.testing.expectEqualStrings("library/alpine", repo);
}

test "getApiRepository preserves user namespace" {
    const ref = try parse("myuser/myimage:latest");
    var buf: [512]u8 = undefined;
    const repo = try getApiRepository(ref, &buf);
    try std.testing.expectEqualStrings("myuser/myimage", repo);
}
