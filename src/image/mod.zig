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

const std = @import("std");
const builtin = @import("builtin");

pub const reference = @import("reference.zig");
pub const registry = @import("registry.zig");
pub const layer = @import("layer.zig");
pub const cache = @import("cache.zig");
pub const isolazifile = @import("isolazifile.zig");
pub const builder = @import("builder.zig");
pub const executor = @import("executor.zig");

// Re-export main types for convenience
pub const ImageReference = reference.ImageReference;
pub const RegistryClient = registry.RegistryClient;
pub const ImageCache = cache.ImageCache;
pub const CachedImage = cache.CachedImage;
pub const CacheStats = cache.CacheStats;
pub const DownloadProgress = registry.DownloadProgress;
pub const DownloadProgressCallback = registry.ProgressCallback;

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
    download_progress_callback: ?DownloadProgressCallback,
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

    const effective_tag = ref.tag orelse "latest";
    var manifest_data: []u8 = undefined;

    // For Docker Hub, use optimized combined auth+manifest fetch
    if (std.mem.eql(u8, ref.registry, "docker.io") or
        std.mem.eql(u8, ref.registry, "registry-1.docker.io"))
    {
        // Combined auth + manifest fetch for speed
        if (progress_callback) |cb| {
            cb(.fetching_manifest, ref.repository);
        }
        manifest_data = try client.authenticateAndGetManifest(ref.repository, effective_tag);
    } else {
        // Non-Docker Hub: just fetch manifest
        if (progress_callback) |cb| {
            cb(.fetching_manifest, ref.repository);
        }
        manifest_data = try client.getManifest(ref.repository, effective_tag);
    }
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

            // Find manifest matching host architecture
            var selected_digest: ?[]const u8 = null;
            const host_arch = switch (builtin.cpu.arch) {
                .x86_64 => "amd64",
                .aarch64 => "arm64",
                else => "amd64", // Fallback to amd64
            };

            for (manifests.array.items) |m| {
                const platform = m.object.get("platform") orelse continue;
                const arch = platform.object.get("architecture") orelse continue;
                const os = platform.object.get("os") orelse continue;

                if (std.mem.eql(u8, arch.string, host_arch) and
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

    // List of layers to download
    const LayerDownloadItem = struct {
        digest: []const u8,
        index: usize,
    };
    var to_download: std.ArrayList(LayerDownloadItem) = .empty;
    defer to_download.deinit(allocator);

    for (layers.array.items, 0..) |layer_obj, i| {
        const digest = layer_obj.object.get("digest") orelse continue;
        const digest_str = digest.string;

        if (try img_cache.hasBlob(digest_str)) {
            if (progress_callback) |cb| {
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "Layer {d}/{d} (cached)", .{ i + 1, layers.array.items.len }) catch "Layer cached";
                cb(.layer_cached, msg);
            }
            continue;
        }

        try to_download.append(allocator, .{ .digest = try allocator.dupe(u8, digest_str), .index = i });
    }
    defer {
        for (to_download.items) |item| allocator.free(item.digest);
    }

    if (to_download.items.len > 0) {
        // Parallel download logic - using WSL ext4 filesystem for better I/O
        const ThreadData = struct {
            client: *RegistryClient,
            img_cache: *ImageCache,
            repository: []const u8,
            digest: []const u8,
            index: usize,
            total: usize,
            progress_callback: ?*const fn (stage: PullStage, detail: []const u8) void,
            download_progress_callback: ?DownloadProgressCallback,
            mutex: *std.Thread.Mutex,
            err: *?anyerror,
        };

        const downloader = struct {
            fn run(data: ThreadData) void {
                const final_path = data.img_cache.getBlobPath(data.digest) catch |e| {
                    data.mutex.lock();
                    data.err.* = e;
                    data.mutex.unlock();
                    return;
                };
                defer data.client.allocator.free(final_path);

                const tmp_path = std.fmt.allocPrint(data.client.allocator, "{s}.tmp", .{final_path}) catch return;
                defer data.client.allocator.free(tmp_path);

                {
                    data.mutex.lock();
                    if (data.progress_callback) |cb| {
                        var buf: [128]u8 = undefined;
                        const msg = std.fmt.bufPrint(&buf, "Layer {d}/{d}: {s} (downloading)", .{ data.index + 1, data.total, data.digest[0..@min(12, data.digest.len)] }) catch "Downloading layer";
                        cb(.downloading_layer, msg);
                    }
                    data.mutex.unlock();
                }

                data.client.downloadBlobToFileWithProgress(
                    data.repository,
                    data.digest,
                    tmp_path,
                    data.download_progress_callback,
                    data.index + 1,
                    data.total,
                ) catch |e| {
                    data.mutex.lock();
                    data.err.* = e;
                    data.mutex.unlock();
                    return;
                };

                // Atomic rename
                std.fs.renameAbsolute(tmp_path, final_path) catch |e| {
                    data.mutex.lock();
                    data.err.* = e;
                    data.mutex.unlock();
                    return;
                };

                data.mutex.lock();
                if (data.progress_callback) |cb| {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "Layer {d}/{d}: {s} (complete)", .{ data.index + 1, data.total, data.digest[0..@min(12, data.digest.len)] }) catch "Downloaded layer";
                    cb(.downloading_layer, msg);
                }
                data.mutex.unlock();
            }
        };

        var download_mutex = std.Thread.Mutex{};
        var download_err: ?anyerror = null;
        var threads: std.ArrayList(std.Thread) = .empty;
        defer threads.deinit(allocator);

        for (to_download.items) |item| {
            const t = try std.Thread.spawn(.{}, downloader.run, .{ThreadData{
                .client = &client,
                .img_cache = img_cache,
                .repository = ref.repository,
                .digest = item.digest,
                .index = item.index,
                .total = layers.array.items.len,
                .progress_callback = progress_callback,
                .download_progress_callback = download_progress_callback,
                .mutex = &download_mutex,
                .err = &download_err,
            }});
            try threads.append(allocator, t);
        }

        for (threads.items) |t| {
            t.join();
        }

        if (download_err) |e| return e;
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
    downloading_progress,
    layer_cached,
    extracting,
    complete,
};

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
