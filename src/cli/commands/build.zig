//! Build Command Handler
//!
//! Implements the `isolazi build` command for creating container images
//! from Isolazifile/Dockerfile specifications.
//!
//! Usage:
//!   isolazi build [OPTIONS] <CONTEXT>
//!
//! Options:
//!   -f, --file <path>     Isolazifile path (default: Isolazifile or Dockerfile)
//!   -t, --tag <name>      Image tag (e.g., myimage:latest)
//!   --build-arg <K=V>     Build argument
//!   --no-cache            Force rebuild all layers
//!   -q, --quiet           Suppress build output

const std = @import("std");
// Import image module directly for builder types
const image_mod = @import("../../image/mod.zig");
// Import cli module for BuildCommand type (re-export for convenience)
const cli = @import("../cli.zig");

/// Re-export BuildCommand from cli for convenience
pub const BuildCommand = cli.BuildCommand;

/// Default progress callback that prints stages to stderr
pub fn defaultProgressCallback(stage: image_mod.builder.BuildStage, detail: []const u8) void {
    const stage_str = switch (stage) {
        .parsing => "Parsing",
        .pulling_base => "Pulling base",
        .building_layer => "Building",
        .copying_files => "Copying",
        .committing => "Committing",
        .complete => "Complete",
    };
    std.debug.print("  {s}: {s}\n", .{ stage_str, detail });
}

/// Build an image
///
/// Main entry point for the build command.
/// Returns 0 on success, 1 on error.
pub fn buildImage(
    allocator: std.mem.Allocator,
    cmd: cli.BuildCommand,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Validate context path
    if (cmd.context_path.len == 0) {
        stderr.writeAll("Error: Missing build context\n") catch {};
        stderr.writeAll("Usage: isolazi build [OPTIONS] <CONTEXT>\n") catch {};
        stderr.flush() catch {};
        return 1;
    }

    // Check context exists
    std.fs.cwd().access(cmd.context_path, .{}) catch {
        stderr.print("Error: Build context not found: {s}\n", .{cmd.context_path}) catch {};
        stderr.flush() catch {};
        return 1;
    };

    stdout.print("Building image from {s}...\n", .{cmd.context_path}) catch {};
    stdout.flush() catch {};

    // Initialize image cache
    var img_cache = image_mod.ImageCache.init(allocator) catch |err| {
        stderr.print("Error: Failed to initialize image cache: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer img_cache.deinit();

    // Initialize builder
    var builder = image_mod.builder.Builder.init(allocator, &img_cache);
    defer builder.deinit();

    // Set progress callback if not quiet
    if (!cmd.quiet) {
        builder.setProgressCallback(&defaultProgressCallback);
    }

    // Convert build args from CLI type to builder type
    var build_args: std.ArrayList(image_mod.builder.BuildArg) = .empty;
    defer build_args.deinit(allocator);

    for (cmd.build_args) |arg| {
        build_args.append(allocator, image_mod.builder.BuildArg{
            .name = arg.name,
            .value = arg.value,
        }) catch {
            stderr.writeAll("Error: Out of memory\n") catch {};
            stderr.flush() catch {};
            return 1;
        };
    }

    // Build options
    const options = image_mod.builder.BuildOptions{
        .context_path = cmd.context_path,
        .file_path = cmd.file,
        .tag = cmd.tag,
        .build_args = build_args.items,
        .no_cache = cmd.no_cache,
        .quiet = cmd.quiet,
    };

    // Execute build
    var result = builder.build(options) catch |err| {
        stderr.print("Error: Build failed: {}\n", .{err}) catch {};
        stderr.flush() catch {};
        return 1;
    };
    defer result.deinit();

    // Print success
    stdout.print("\nSuccessfully built {s}\n", .{result.image_id[0..@min(12, result.image_id.len)]}) catch {};

    if (cmd.tag) |tag| {
        stdout.print("Successfully tagged {s}\n", .{tag}) catch {};
    }

    stdout.print("Layers: {d}, Build time: {d}ms\n", .{ result.layers_count, result.duration_ms }) catch {};
    stdout.flush() catch {};

    return 0;
}

/// Parse build command from arguments
///
/// args should be the full argv starting from "build"
pub fn parseFromArgs(allocator: std.mem.Allocator, args: []const []const u8) !BuildCommand {
    var cmd = BuildCommand{
        .context_path = ".",
    };

    var build_args = std.ArrayList(BuildCommand.BuildArg).init(allocator);
    errdefer build_args.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cmd.file = args[i];
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tag")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cmd.tag = args[i];
        } else if (std.mem.eql(u8, arg, "--build-arg")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            const arg_str = args[i];
            if (std.mem.indexOf(u8, arg_str, "=")) |eq_pos| {
                try build_args.append(.{
                    .name = arg_str[0..eq_pos],
                    .value = arg_str[eq_pos + 1 ..],
                });
            }
        } else if (std.mem.eql(u8, arg, "--no-cache")) {
            cmd.no_cache = true;
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            cmd.quiet = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            // Positional argument = context path
            cmd.context_path = arg;
        }
    }

    if (build_args.items.len > 0) {
        cmd.build_args = try build_args.toOwnedSlice();
    }

    return cmd;
}

/// Build from command-line args
///
/// Parses args and calls buildImage.
/// args should be the full argv (including program name).
pub fn buildFromArgs(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) u8 {
    // Skip program name and "build" command
    const build_args = if (args.len > 2) args[2..] else &[_][]const u8{};

    const cmd = parseFromArgs(allocator, build_args) catch |err| {
        stderr.print("Error: Invalid arguments: {}\n", .{err}) catch {};
        stderr.writeAll("Usage: isolazi build [OPTIONS] <CONTEXT>\n") catch {};
        stderr.flush() catch {};
        return 1;
    };

    return buildImage(allocator, cmd, stdout, stderr);
}

// =============================================================================
// Tests
// =============================================================================

test "parseFromArgs basic" {
    const allocator = std.testing.allocator;

    const args = &[_][]const u8{ "-t", "myimage:latest", "." };
    const cmd = try parseFromArgs(allocator, args);

    try std.testing.expectEqualStrings(".", cmd.context_path);
    try std.testing.expectEqualStrings("myimage:latest", cmd.tag.?);
}

test "parseFromArgs with file" {
    const allocator = std.testing.allocator;

    const args = &[_][]const u8{ "-f", "Dockerfile.dev", "-t", "test:dev", "./src" };
    const cmd = try parseFromArgs(allocator, args);

    try std.testing.expectEqualStrings("./src", cmd.context_path);
    try std.testing.expectEqualStrings("Dockerfile.dev", cmd.file.?);
    try std.testing.expectEqualStrings("test:dev", cmd.tag.?);
}

test "parseFromArgs with no-cache" {
    const allocator = std.testing.allocator;

    const args = &[_][]const u8{ "--no-cache", "." };
    const cmd = try parseFromArgs(allocator, args);

    try std.testing.expect(cmd.no_cache);
}
