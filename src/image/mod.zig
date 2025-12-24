//! OCI Image Module
//!
//! This module provides functionality for working with OCI container images:
//! - Image reference parsing (registry/repository:tag@digest)
//! - Registry client for pulling images from Docker Hub and other registries
//! - Layer extraction for creating container rootfs
//! - Local image cache management
//!
//! Usage:
//! ```zig
//! const image = @import("image/mod.zig");
//!
//! // Parse an image reference
//! var ref = try image.ImageReference.parse(allocator, "alpine:3.18");
//! defer ref.deinit();
//!
//! // Initialize cache
//! var cache = try image.ImageCache.init(allocator);
//! defer cache.deinit();
//!
//! // Pull image if not cached
//! if (!try cache.hasImage(&ref)) {
//!     var client = try image.RegistryClient.init(allocator, ref.registry);
//!     defer client.deinit();
//!     // ... pull manifest and layers
//! }
//! ```

pub const reference = @import("reference.zig");
pub const registry = @import("registry.zig");
pub const layer = @import("layer.zig");
pub const cache = @import("cache.zig");

// Re-export main types for convenience
pub const ImageReference = reference.ImageReference;
pub const RegistryClient = registry.RegistryClient;
pub const ImageCache = cache.ImageCache;
pub const CachedImage = cache.CachedImage;
pub const CacheStats = cache.CacheStats;

// Re-export key functions
pub const extractLayer = layer.extractLayer;
pub const extractLayers = layer.extractLayers;
pub const verifyLayer = layer.verifyLayer;
pub const generateContainerId = cache.generateContainerId;

/// High-level function to pull an image and prepare it for running
pub fn pullImage(
    allocator: std.mem.Allocator,
    image_str: []const u8,
    img_cache: *ImageCache,
    progress_callback: ?*const fn (stage: PullStage, detail: []const u8) void,
) !ImageReference {
    // Parse the image reference
    const ref = reference.parse(image_str) catch return error.InvalidReference;

    // Check if already cached
    if (try img_cache.hasImage(&ref)) {
        if (progress_callback) |cb| {
            cb(.cached, "Image already in cache");
        }
        return ref;
    }

    // Initialize registry client
    var client = RegistryClient.init(allocator);
    defer client.deinit();

    // Report progress
    if (progress_callback) |cb| {
        cb(.authenticating, ref.registry);
    }

    // For Docker Hub, authenticate first
    if (std.mem.eql(u8, ref.registry, "docker.io") or
        std.mem.eql(u8, ref.registry, "registry-1.docker.io"))
    {
        try client.authenticateDockerHub(ref.repository);
    }

    // Fetch manifest
    if (progress_callback) |cb| {
        cb(.fetching_manifest, ref.repository);
    }

    const effective_tag = ref.tag orelse "latest";
    var manifest_data = try client.getManifest(ref.repository, effective_tag);
    defer allocator.free(manifest_data);

    // Parse manifest
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
        return error.InvalidManifest;
    };
    defer parsed.deinit();

    var root = parsed.value;

    // Check if this is a manifest list (multi-arch)
    const media_type = root.object.get("mediaType");
    if (media_type) |mt| {
        const mt_str = mt.string;
        // If it's a manifest list/index, get the amd64/linux manifest
        if (std.mem.containsAtLeast(u8, mt_str, 1, "manifest.list") or
            std.mem.containsAtLeast(u8, mt_str, 1, "image.index"))
        {
            const manifests = root.object.get("manifests") orelse return error.InvalidManifest;

            // Find amd64/linux manifest
            var selected_digest: ?[]const u8 = null;
            for (manifests.array.items) |m| {
                const platform = m.object.get("platform") orelse continue;
                const arch = platform.object.get("architecture") orelse continue;
                const os = platform.object.get("os") orelse continue;

                if (std.mem.eql(u8, arch.string, "amd64") and
                    std.mem.eql(u8, os.string, "linux"))
                {
                    // Check if it's not an attestation manifest
                    const annotations = m.object.get("annotations");
                    if (annotations) |ann| {
                        if (ann.object.get("vnd.docker.reference.type")) |ref_type| {
                            if (std.mem.eql(u8, ref_type.string, "attestation-manifest")) {
                                continue;
                            }
                        }
                    }

                    const digest_val = m.object.get("digest") orelse continue;
                    selected_digest = digest_val.string;
                    break;
                }
            }

            if (selected_digest == null) {
                return error.InvalidManifest;
            }

            // Copy the digest before freeing parsed data
            const digest_copy = try allocator.dupe(u8, selected_digest.?);
            defer allocator.free(digest_copy);

            // Clean up old manifest data
            parsed.deinit();
            allocator.free(manifest_data);

            // Fetch the platform-specific manifest using the digest
            manifest_data = try client.getManifest(ref.repository, digest_copy);
            parsed = std.json.parseFromSlice(std.json.Value, allocator, manifest_data, .{}) catch {
                return error.InvalidManifest;
            };
            root = parsed.value;
        }
    }

    // Store manifest in cache
    try img_cache.storeManifest(&ref, manifest_data);

    // Get layers from the manifest
    const layers = root.object.get("layers") orelse return error.InvalidManifest;

    // Download each layer
    for (layers.array.items, 0..) |layer_obj, i| {
        const digest = layer_obj.object.get("digest") orelse continue;
        const digest_str = digest.string;

        // Check if blob already cached
        if (try img_cache.hasBlob(digest_str)) {
            if (progress_callback) |cb| {
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "Layer {d}/{d} (cached)", .{ i + 1, layers.array.items.len }) catch "Layer cached";
                cb(.layer_cached, msg);
            }
            continue;
        }

        // Report progress
        if (progress_callback) |cb| {
            var buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "Layer {d}/{d}: {s}", .{ i + 1, layers.array.items.len, digest_str[0..@min(19, digest_str.len)] }) catch "Downloading layer";
            cb(.downloading_layer, msg);
        }

        // Download blob
        const blob_data = try client.downloadBlob(ref.repository, digest_str);
        defer allocator.free(blob_data);

        // Store in cache
        try img_cache.storeBlob(digest_str, blob_data);
    }

    if (progress_callback) |cb| {
        cb(.complete, "Image pulled successfully");
    }

    return ref;
}

/// Pull progress stages
pub const PullStage = enum {
    cached,
    authenticating,
    fetching_manifest,
    downloading_layer,
    layer_cached,
    extracting,
    complete,
};

const std = @import("std");

// =============================================================================
// Tests
// =============================================================================

test "module exports are accessible" {
    // Just verify the exports compile
    _ = ImageReference;
    _ = RegistryClient;
    _ = ImageCache;
    _ = extractLayer;
}
