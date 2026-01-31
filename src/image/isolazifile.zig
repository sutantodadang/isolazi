//! Isolazifile/Dockerfile Parser
//!
//! Parses Isolazifile (or Dockerfile) build instructions to create container images.
//! Supports standard Dockerfile syntax including:
//! - FROM: Base image specification
//! - RUN: Execute commands during build
//! - COPY/ADD: Copy files into image
//! - ENV: Set environment variables
//! - WORKDIR: Set working directory
//! - EXPOSE: Document exposed ports
//! - CMD/ENTRYPOINT: Default command configuration
//! - ARG: Build-time variables
//! - LABEL: Image metadata

const std = @import("std");

/// Build argument (--build-arg)
pub const BuildArg = struct {
    name: []const u8,
    value: ?[]const u8,
};

/// FROM instruction
pub const FromInstruction = struct {
    image: []const u8,
    tag: ?[]const u8 = null,
    digest: ?[]const u8 = null,
    as_name: ?[]const u8 = null, // For multi-stage builds: FROM alpine AS builder

    /// Get full image reference
    pub fn getReference(self: FromInstruction, allocator: std.mem.Allocator) ![]const u8 {
        if (self.digest) |d| {
            return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.image, d });
        } else if (self.tag) |t| {
            return std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.image, t });
        } else {
            return std.fmt.allocPrint(allocator, "{s}:latest", .{self.image});
        }
    }
};

/// RUN instruction
pub const RunInstruction = struct {
    /// Shell form: RUN command arg1 arg2
    /// Exec form: RUN ["executable", "param1", "param2"]
    command: []const u8,
    is_exec_form: bool = false,
    exec_args: []const []const u8 = &[_][]const u8{},
};

/// COPY instruction
pub const CopyInstruction = struct {
    sources: []const []const u8,
    destination: []const u8,
    from_stage: ?[]const u8 = null, // --from=builder
    chown: ?[]const u8 = null, // --chown=user:group
    chmod: ?[]const u8 = null, // --chmod=755
};

/// ADD instruction (like COPY but with URL and tar extraction support)
pub const AddInstruction = struct {
    sources: []const []const u8,
    destination: []const u8,
    chown: ?[]const u8 = null,
    chmod: ?[]const u8 = null,
};

/// ENV instruction
pub const EnvInstruction = struct {
    /// Key-value pairs
    vars: []const EnvVar,

    pub const EnvVar = struct {
        key: []const u8,
        value: []const u8,
    };
};

/// WORKDIR instruction
pub const WorkdirInstruction = struct {
    path: []const u8,
};

/// EXPOSE instruction
pub const ExposeInstruction = struct {
    ports: []const PortSpec,

    pub const PortSpec = struct {
        port: u16,
        protocol: Protocol = .tcp,

        pub const Protocol = enum {
            tcp,
            udp,
        };
    };
};

/// CMD instruction
pub const CmdInstruction = struct {
    /// Exec form: CMD ["executable","param1","param2"]
    /// Shell form: CMD command param1 param2
    command: []const u8,
    is_exec_form: bool = false,
    exec_args: []const []const u8 = &[_][]const u8{},
};

/// ENTRYPOINT instruction
pub const EntrypointInstruction = struct {
    /// Exec form: ENTRYPOINT ["executable", "param1", "param2"]
    /// Shell form: ENTRYPOINT command param1 param2
    command: []const u8,
    is_exec_form: bool = false,
    exec_args: []const []const u8 = &[_][]const u8{},
};

/// ARG instruction
pub const ArgInstruction = struct {
    name: []const u8,
    default_value: ?[]const u8 = null,
};

/// LABEL instruction
pub const LabelInstruction = struct {
    labels: []const Label,

    pub const Label = struct {
        key: []const u8,
        value: []const u8,
    };
};

/// USER instruction
pub const UserInstruction = struct {
    user: []const u8,
    group: ?[]const u8 = null,
};

/// VOLUME instruction
pub const VolumeInstruction = struct {
    paths: []const []const u8,
};

/// Instruction types
pub const Instruction = union(enum) {
    from: FromInstruction,
    run: RunInstruction,
    copy: CopyInstruction,
    add: AddInstruction,
    env: EnvInstruction,
    workdir: WorkdirInstruction,
    expose: ExposeInstruction,
    cmd: CmdInstruction,
    entrypoint: EntrypointInstruction,
    arg: ArgInstruction,
    label: LabelInstruction,
    user: UserInstruction,
    volume: VolumeInstruction,
};

/// Parsed Isolazifile
pub const Isolazifile = struct {
    allocator: std.mem.Allocator,
    instructions: []const Instruction,
    args: std.StringHashMap([]const u8),

    const Self = @This();

    /// Get the base image (first FROM instruction)
    pub fn getBaseImage(self: *const Self) ?FromInstruction {
        for (self.instructions) |inst| {
            if (inst == .from) {
                return inst.from;
            }
        }
        return null;
    }

    /// Get all build stages (for multi-stage builds)
    pub fn getStages(self: *const Self, allocator: std.mem.Allocator) ![]const []const u8 {
        var stages: std.ArrayList([]const u8) = .empty;
        for (self.instructions) |inst| {
            if (inst == .from) {
                if (inst.from.as_name) |name| {
                    try stages.append(name);
                }
            }
        }
        return stages.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *Self) void {
        // Free allocated strings
        for (self.instructions) |inst| {
            switch (inst) {
                .from => |f| {
                    self.allocator.free(f.image);
                    if (f.tag) |t| self.allocator.free(t);
                    if (f.digest) |d| self.allocator.free(d);
                    if (f.as_name) |n| self.allocator.free(n);
                },
                .run => |r| {
                    self.allocator.free(r.command);
                    for (r.exec_args) |arg| {
                        self.allocator.free(arg);
                    }
                    if (r.exec_args.len > 0) self.allocator.free(r.exec_args);
                },
                .copy => |c| {
                    for (c.sources) |src| self.allocator.free(src);
                    self.allocator.free(c.sources);
                    self.allocator.free(c.destination);
                    if (c.from_stage) |f| self.allocator.free(f);
                    if (c.chown) |o| self.allocator.free(o);
                    if (c.chmod) |m| self.allocator.free(m);
                },
                .add => |a| {
                    for (a.sources) |src| self.allocator.free(src);
                    self.allocator.free(a.sources);
                    self.allocator.free(a.destination);
                    if (a.chown) |o| self.allocator.free(o);
                    if (a.chmod) |m| self.allocator.free(m);
                },
                .env => |e| {
                    for (e.vars) |v| {
                        self.allocator.free(v.key);
                        self.allocator.free(v.value);
                    }
                    self.allocator.free(e.vars);
                },
                .workdir => |w| self.allocator.free(w.path),
                .expose => |ex| self.allocator.free(ex.ports),
                .cmd => |c| {
                    // In exec form, command points to exec_args[0], so only free exec_args
                    // In shell form, only command is allocated
                    if (c.is_exec_form) {
                        for (c.exec_args) |arg| self.allocator.free(arg);
                        if (c.exec_args.len > 0) self.allocator.free(c.exec_args);
                    } else {
                        self.allocator.free(c.command);
                    }
                },
                .entrypoint => |e| {
                    // In exec form, command points to exec_args[0], so only free exec_args
                    // In shell form, only command is allocated
                    if (e.is_exec_form) {
                        for (e.exec_args) |arg| self.allocator.free(arg);
                        if (e.exec_args.len > 0) self.allocator.free(e.exec_args);
                    } else {
                        self.allocator.free(e.command);
                    }
                },
                .arg => |a| {
                    self.allocator.free(a.name);
                    if (a.default_value) |v| self.allocator.free(v);
                },
                .label => |l| {
                    for (l.labels) |lb| {
                        self.allocator.free(lb.key);
                        self.allocator.free(lb.value);
                    }
                    self.allocator.free(l.labels);
                },
                .user => |u| {
                    self.allocator.free(u.user);
                    if (u.group) |g| self.allocator.free(g);
                },
                .volume => |v| {
                    for (v.paths) |p| self.allocator.free(p);
                    self.allocator.free(v.paths);
                },
            }
        }
        self.allocator.free(self.instructions);

        var args_iter = self.args.iterator();
        while (args_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.args.deinit();
    }
};

/// Parser error types
pub const ParseError = error{
    InvalidInstruction,
    MissingArgument,
    InvalidSyntax,
    UnterminatedString,
    InvalidJsonArray,
    NoFromInstruction,
    OutOfMemory,
    FileNotFound,
    AccessDenied,
    IoError,
};

/// Parse Isolazifile content
pub fn parse(allocator: std.mem.Allocator, content: []const u8) ParseError!Isolazifile {
    var instructions: std.ArrayList(Instruction) = .empty;
    errdefer {
        for (instructions.items) |_| {
            // Cleanup on error would go here
        }
        instructions.deinit(allocator);
    }

    var args = std.StringHashMap([]const u8).init(allocator);
    errdefer args.deinit();

    // Process line by line
    var lines = std.mem.splitScalar(u8, content, '\n');
    var current_line: std.ArrayList(u8) = .empty;
    defer current_line.deinit(allocator);

    while (lines.next()) |raw_line| {
        // Trim carriage return for Windows compatibility
        var line = std.mem.trimRight(u8, raw_line, "\r");
        line = std.mem.trim(u8, line, " \t");

        // Skip empty lines and comments
        if (line.len == 0 or line[0] == '#') continue;

        // Handle line continuation (backslash at end)
        if (line.len > 0 and line[line.len - 1] == '\\') {
            current_line.appendSlice(allocator, line[0 .. line.len - 1]) catch return ParseError.OutOfMemory;
            current_line.append(allocator, ' ') catch return ParseError.OutOfMemory;
            continue;
        }

        // Complete the line
        current_line.appendSlice(allocator, line) catch return ParseError.OutOfMemory;

        // Parse the instruction
        const full_line = current_line.items;
        if (full_line.len > 0) {
            const inst = try parseInstruction(allocator, full_line, &args);
            if (inst) |i| {
                instructions.append(allocator, i) catch return ParseError.OutOfMemory;
            }
        }

        current_line.clearRetainingCapacity();
    }

    // Validate: must have at least one FROM instruction
    var has_from = false;
    for (instructions.items) |inst| {
        if (inst == .from) {
            has_from = true;
            break;
        }
    }
    if (!has_from) return ParseError.NoFromInstruction;

    return Isolazifile{
        .allocator = allocator,
        .instructions = instructions.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
        .args = args,
    };
}

/// Parse a file
pub fn parseFile(allocator: std.mem.Allocator, path: []const u8) ParseError!Isolazifile {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound => ParseError.FileNotFound,
            error.AccessDenied => ParseError.AccessDenied,
            else => ParseError.IoError,
        };
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch {
        return ParseError.IoError;
    };
    defer allocator.free(content);

    return parse(allocator, content);
}

/// Parse a single instruction line
fn parseInstruction(
    allocator: std.mem.Allocator,
    line: []const u8,
    args: *std.StringHashMap([]const u8),
) ParseError!?Instruction {
    // Find instruction name
    var iter = std.mem.tokenizeAny(u8, line, " \t");
    const instruction_name = iter.next() orelse return null;
    const rest = iter.rest();

    // Substitute ARG values in the rest
    const substituted = try substituteArgs(allocator, rest, args);
    defer if (substituted.ptr != rest.ptr) allocator.free(substituted);

    // Parse based on instruction type (case-insensitive)
    if (std.ascii.eqlIgnoreCase(instruction_name, "FROM")) {
        return Instruction{ .from = try parseFrom(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "RUN")) {
        return Instruction{ .run = try parseRun(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "COPY")) {
        return Instruction{ .copy = try parseCopy(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "ADD")) {
        return Instruction{ .add = try parseAdd(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "ENV")) {
        return Instruction{ .env = try parseEnv(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "WORKDIR")) {
        return Instruction{ .workdir = try parseWorkdir(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "EXPOSE")) {
        return Instruction{ .expose = try parseExpose(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "CMD")) {
        return Instruction{ .cmd = try parseCmd(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "ENTRYPOINT")) {
        return Instruction{ .entrypoint = try parseEntrypoint(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "ARG")) {
        const arg_inst = try parseArg(allocator, substituted);
        // Store ARG for substitution
        const key = allocator.dupe(u8, arg_inst.name) catch return ParseError.OutOfMemory;
        const value = if (arg_inst.default_value) |v|
            allocator.dupe(u8, v) catch return ParseError.OutOfMemory
        else
            allocator.dupe(u8, "") catch return ParseError.OutOfMemory;
        args.put(key, value) catch return ParseError.OutOfMemory;
        return Instruction{ .arg = arg_inst };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "LABEL")) {
        return Instruction{ .label = try parseLabel(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "USER")) {
        return Instruction{ .user = try parseUser(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "VOLUME")) {
        return Instruction{ .volume = try parseVolume(allocator, substituted) };
    } else if (std.ascii.eqlIgnoreCase(instruction_name, "MAINTAINER")) {
        // Deprecated, convert to LABEL
        var labels = allocator.alloc(LabelInstruction.Label, 1) catch return ParseError.OutOfMemory;
        labels[0] = .{
            .key = allocator.dupe(u8, "maintainer") catch return ParseError.OutOfMemory,
            .value = allocator.dupe(u8, std.mem.trim(u8, substituted, " \t\"")) catch return ParseError.OutOfMemory,
        };
        return Instruction{ .label = .{ .labels = labels } };
    }

    // Unknown instruction - skip (could also error)
    return null;
}

/// Substitute ${ARG_NAME} and $ARG_NAME in text
fn substituteArgs(
    allocator: std.mem.Allocator,
    text: []const u8,
    args: *std.StringHashMap([]const u8),
) ParseError![]const u8 {
    if (args.count() == 0 or std.mem.indexOf(u8, text, "$") == null) {
        return text;
    }

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '$') {
            if (i + 1 < text.len and text[i + 1] == '{') {
                // ${VAR_NAME} form
                const end = std.mem.indexOfScalarPos(u8, text, i + 2, '}') orelse {
                    result.append(allocator, text[i]) catch return ParseError.OutOfMemory;
                    i += 1;
                    continue;
                };
                const var_name = text[i + 2 .. end];
                if (args.get(var_name)) |value| {
                    result.appendSlice(allocator, value) catch return ParseError.OutOfMemory;
                }
                i = end + 1;
            } else if (i + 1 < text.len and (std.ascii.isAlphabetic(text[i + 1]) or text[i + 1] == '_')) {
                // $VAR_NAME form
                var end = i + 1;
                while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or text[end] == '_')) {
                    end += 1;
                }
                const var_name = text[i + 1 .. end];
                if (args.get(var_name)) |value| {
                    result.appendSlice(allocator, value) catch return ParseError.OutOfMemory;
                }
                i = end;
            } else {
                result.append(allocator, text[i]) catch return ParseError.OutOfMemory;
                i += 1;
            }
        } else {
            result.append(allocator, text[i]) catch return ParseError.OutOfMemory;
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator) catch return ParseError.OutOfMemory;
}

/// Parse FROM instruction
fn parseFrom(allocator: std.mem.Allocator, text: []const u8) ParseError!FromInstruction {
    var trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    var result = FromInstruction{
        .image = undefined,
    };

    // Check for AS clause (multi-stage)
    if (std.ascii.indexOfIgnoreCase(trimmed, " as ")) |as_pos| {
        result.as_name = allocator.dupe(u8, std.mem.trim(u8, trimmed[as_pos + 4 ..], " \t")) catch return ParseError.OutOfMemory;
        trimmed = trimmed[0..as_pos];
    }

    // Parse image reference
    if (std.mem.indexOf(u8, trimmed, "@")) |digest_pos| {
        result.image = allocator.dupe(u8, trimmed[0..digest_pos]) catch return ParseError.OutOfMemory;
        result.digest = allocator.dupe(u8, trimmed[digest_pos + 1 ..]) catch return ParseError.OutOfMemory;
    } else if (std.mem.lastIndexOf(u8, trimmed, ":")) |tag_pos| {
        result.image = allocator.dupe(u8, trimmed[0..tag_pos]) catch return ParseError.OutOfMemory;
        result.tag = allocator.dupe(u8, trimmed[tag_pos + 1 ..]) catch return ParseError.OutOfMemory;
    } else {
        result.image = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory;
    }

    return result;
}

/// Parse RUN instruction
fn parseRun(allocator: std.mem.Allocator, text: []const u8) ParseError!RunInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    // Check for exec form: ["cmd", "arg1", "arg2"]
    if (trimmed[0] == '[') {
        const args = try parseJsonArray(allocator, trimmed);
        if (args.len == 0) return ParseError.MissingArgument;
        return RunInstruction{
            .command = args[0],
            .is_exec_form = true,
            .exec_args = args,
        };
    }

    // Shell form
    return RunInstruction{
        .command = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
        .is_exec_form = false,
    };
}

/// Parse COPY instruction
fn parseCopy(allocator: std.mem.Allocator, text: []const u8) ParseError!CopyInstruction {
    var trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    var result = CopyInstruction{
        .sources = undefined,
        .destination = undefined,
    };

    // Parse options (--from, --chown, --chmod)
    while (trimmed.len > 0 and std.mem.startsWith(u8, trimmed, "--")) {
        const space_pos = std.mem.indexOfAny(u8, trimmed, " \t") orelse break;
        const option = trimmed[0..space_pos];

        if (std.mem.startsWith(u8, option, "--from=")) {
            result.from_stage = allocator.dupe(u8, option[7..]) catch return ParseError.OutOfMemory;
        } else if (std.mem.startsWith(u8, option, "--chown=")) {
            result.chown = allocator.dupe(u8, option[8..]) catch return ParseError.OutOfMemory;
        } else if (std.mem.startsWith(u8, option, "--chmod=")) {
            result.chmod = allocator.dupe(u8, option[8..]) catch return ParseError.OutOfMemory;
        }

        trimmed = std.mem.trim(u8, trimmed[space_pos..], " \t");
    }

    // Parse sources and destination
    var sources: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (sources.items) |s| allocator.free(s);
        sources.deinit(allocator);
    }

    var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
    var last: ?[]const u8 = null;

    while (iter.next()) |part| {
        if (last) |l| {
            sources.append(allocator, allocator.dupe(u8, l) catch return ParseError.OutOfMemory) catch return ParseError.OutOfMemory;
        }
        last = part;
    }

    if (last) |l| {
        result.destination = allocator.dupe(u8, l) catch return ParseError.OutOfMemory;
    } else {
        return ParseError.MissingArgument;
    }

    if (sources.items.len == 0) {
        return ParseError.MissingArgument;
    }

    result.sources = sources.toOwnedSlice(allocator) catch return ParseError.OutOfMemory;
    return result;
}

/// Parse ADD instruction
fn parseAdd(allocator: std.mem.Allocator, text: []const u8) ParseError!AddInstruction {
    const copy_inst = try parseCopy(allocator, text);
    return AddInstruction{
        .sources = copy_inst.sources,
        .destination = copy_inst.destination,
        .chown = copy_inst.chown,
        .chmod = copy_inst.chmod,
    };
}

/// Parse ENV instruction
fn parseEnv(allocator: std.mem.Allocator, text: []const u8) ParseError!EnvInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    var vars: std.ArrayList(EnvInstruction.EnvVar) = .empty;
    errdefer {
        for (vars.items) |v| {
            allocator.free(v.key);
            allocator.free(v.value);
        }
        vars.deinit(allocator);
    }

    // Check for new format: ENV KEY=VALUE KEY2=VALUE2
    if (std.mem.indexOf(u8, trimmed, "=")) |_| {
        var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
        while (iter.next()) |pair| {
            if (std.mem.indexOf(u8, pair, "=")) |eq_pos| {
                const key = allocator.dupe(u8, pair[0..eq_pos]) catch return ParseError.OutOfMemory;
                const value = allocator.dupe(u8, pair[eq_pos + 1 ..]) catch return ParseError.OutOfMemory;
                vars.append(allocator, .{ .key = key, .value = value }) catch return ParseError.OutOfMemory;
            }
        }
    } else {
        // Old format: ENV KEY VALUE
        var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
        const key = iter.next() orelse return ParseError.MissingArgument;
        const value = iter.rest();
        vars.append(allocator, .{
            .key = allocator.dupe(u8, key) catch return ParseError.OutOfMemory,
            .value = allocator.dupe(u8, value) catch return ParseError.OutOfMemory,
        }) catch return ParseError.OutOfMemory;
    }

    return EnvInstruction{
        .vars = vars.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
    };
}

/// Parse WORKDIR instruction
fn parseWorkdir(allocator: std.mem.Allocator, text: []const u8) ParseError!WorkdirInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    return WorkdirInstruction{
        .path = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
    };
}

/// Parse EXPOSE instruction
fn parseExpose(allocator: std.mem.Allocator, text: []const u8) ParseError!ExposeInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    var ports: std.ArrayList(ExposeInstruction.PortSpec) = .empty;
    errdefer ports.deinit(allocator);

    var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
    while (iter.next()) |port_spec| {
        var port_str = port_spec;
        var protocol: ExposeInstruction.PortSpec.Protocol = .tcp;

        if (std.mem.indexOf(u8, port_spec, "/")) |slash_pos| {
            port_str = port_spec[0..slash_pos];
            const proto_str = port_spec[slash_pos + 1 ..];
            if (std.ascii.eqlIgnoreCase(proto_str, "udp")) {
                protocol = .udp;
            }
        }

        const port = std.fmt.parseInt(u16, port_str, 10) catch continue;
        ports.append(allocator, .{ .port = port, .protocol = protocol }) catch return ParseError.OutOfMemory;
    }

    return ExposeInstruction{
        .ports = ports.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
    };
}

/// Parse CMD instruction
fn parseCmd(allocator: std.mem.Allocator, text: []const u8) ParseError!CmdInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    // Check for exec form
    if (trimmed[0] == '[') {
        const args = try parseJsonArray(allocator, trimmed);
        if (args.len == 0) return ParseError.MissingArgument;
        return CmdInstruction{
            .command = args[0],
            .is_exec_form = true,
            .exec_args = args,
        };
    }

    // Shell form
    return CmdInstruction{
        .command = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
        .is_exec_form = false,
    };
}

/// Parse ENTRYPOINT instruction
fn parseEntrypoint(allocator: std.mem.Allocator, text: []const u8) ParseError!EntrypointInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    // Check for exec form
    if (trimmed[0] == '[') {
        const args = try parseJsonArray(allocator, trimmed);
        if (args.len == 0) return ParseError.MissingArgument;
        return EntrypointInstruction{
            .command = args[0],
            .is_exec_form = true,
            .exec_args = args,
        };
    }

    // Shell form
    return EntrypointInstruction{
        .command = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
        .is_exec_form = false,
    };
}

/// Parse ARG instruction
fn parseArg(allocator: std.mem.Allocator, text: []const u8) ParseError!ArgInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
        return ArgInstruction{
            .name = allocator.dupe(u8, trimmed[0..eq_pos]) catch return ParseError.OutOfMemory,
            .default_value = allocator.dupe(u8, trimmed[eq_pos + 1 ..]) catch return ParseError.OutOfMemory,
        };
    }

    return ArgInstruction{
        .name = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
        .default_value = null,
    };
}

/// Parse LABEL instruction
fn parseLabel(allocator: std.mem.Allocator, text: []const u8) ParseError!LabelInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    var labels: std.ArrayList(LabelInstruction.Label) = .empty;
    errdefer {
        for (labels.items) |l| {
            allocator.free(l.key);
            allocator.free(l.value);
        }
        labels.deinit(allocator);
    }

    // Parse KEY=VALUE or KEY="VALUE" pairs
    var i: usize = 0;
    while (i < trimmed.len) {
        // Skip whitespace
        while (i < trimmed.len and (trimmed[i] == ' ' or trimmed[i] == '\t')) i += 1;
        if (i >= trimmed.len) break;

        // Find key
        const key_start = i;
        while (i < trimmed.len and trimmed[i] != '=' and trimmed[i] != ' ') i += 1;
        if (i >= trimmed.len or trimmed[i] != '=') break;

        const key = trimmed[key_start..i];
        i += 1; // Skip '='

        // Find value (may be quoted)
        var value: []const u8 = undefined;
        if (i < trimmed.len and trimmed[i] == '"') {
            i += 1; // Skip opening quote
            const value_start = i;
            while (i < trimmed.len and trimmed[i] != '"') i += 1;
            value = trimmed[value_start..i];
            if (i < trimmed.len) i += 1; // Skip closing quote
        } else {
            const value_start = i;
            while (i < trimmed.len and trimmed[i] != ' ' and trimmed[i] != '\t') i += 1;
            value = trimmed[value_start..i];
        }

        labels.append(allocator, .{
            .key = allocator.dupe(u8, key) catch return ParseError.OutOfMemory,
            .value = allocator.dupe(u8, value) catch return ParseError.OutOfMemory,
        }) catch return ParseError.OutOfMemory;
    }

    return LabelInstruction{
        .labels = labels.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
    };
}

/// Parse USER instruction
fn parseUser(allocator: std.mem.Allocator, text: []const u8) ParseError!UserInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
        return UserInstruction{
            .user = allocator.dupe(u8, trimmed[0..colon_pos]) catch return ParseError.OutOfMemory,
            .group = allocator.dupe(u8, trimmed[colon_pos + 1 ..]) catch return ParseError.OutOfMemory,
        };
    }

    return UserInstruction{
        .user = allocator.dupe(u8, trimmed) catch return ParseError.OutOfMemory,
        .group = null,
    };
}

/// Parse VOLUME instruction
fn parseVolume(allocator: std.mem.Allocator, text: []const u8) ParseError!VolumeInstruction {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return ParseError.MissingArgument;

    // Check for JSON array format
    if (trimmed[0] == '[') {
        return VolumeInstruction{
            .paths = try parseJsonArray(allocator, trimmed),
        };
    }

    // Space-separated paths
    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }

    var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
    while (iter.next()) |path| {
        paths.append(allocator, allocator.dupe(u8, path) catch return ParseError.OutOfMemory) catch return ParseError.OutOfMemory;
    }

    return VolumeInstruction{
        .paths = paths.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
    };
}

/// Parse JSON array ["item1", "item2", ...]
fn parseJsonArray(allocator: std.mem.Allocator, text: []const u8) ParseError![]const []const u8 {
    var items: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }

    // Find content between [ and ]
    const start = std.mem.indexOf(u8, text, "[") orelse return ParseError.InvalidJsonArray;
    const end = std.mem.lastIndexOf(u8, text, "]") orelse return ParseError.InvalidJsonArray;

    if (end <= start) return ParseError.InvalidJsonArray;

    const content = text[start + 1 .. end];
    var i: usize = 0;

    while (i < content.len) {
        // Skip whitespace and commas
        while (i < content.len and (content[i] == ' ' or content[i] == '\t' or content[i] == ',' or content[i] == '\n' or content[i] == '\r')) i += 1;
        if (i >= content.len) break;

        if (content[i] == '"') {
            i += 1; // Skip opening quote
            const item_start = i;

            // Find closing quote (handle escapes)
            while (i < content.len) {
                if (content[i] == '\\' and i + 1 < content.len) {
                    i += 2; // Skip escaped character
                } else if (content[i] == '"') {
                    break;
                } else {
                    i += 1;
                }
            }

            if (i >= content.len) return ParseError.UnterminatedString;

            const item = content[item_start..i];
            items.append(allocator, allocator.dupe(u8, item) catch return ParseError.OutOfMemory) catch return ParseError.OutOfMemory;
            i += 1; // Skip closing quote
        } else {
            // Unquoted item
            const item_start = i;
            while (i < content.len and content[i] != ',' and content[i] != ']') i += 1;
            const item = std.mem.trim(u8, content[item_start..i], " \t\n\r");
            if (item.len > 0) {
                items.append(allocator, allocator.dupe(u8, item) catch return ParseError.OutOfMemory) catch return ParseError.OutOfMemory;
            }
        }
    }

    return items.toOwnedSlice(allocator) catch return ParseError.OutOfMemory;
}

// =============================================================================
// Tests
// =============================================================================

test "parse FROM instruction" {
    const allocator = std.testing.allocator;

    const content = "FROM alpine:3.18";
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    try std.testing.expectEqual(@as(usize, 1), isolazifile.instructions.len);
    const from = isolazifile.instructions[0].from;
    try std.testing.expectEqualStrings("alpine", from.image);
    try std.testing.expectEqualStrings("3.18", from.tag.?);
}

test "parse FROM with AS" {
    const allocator = std.testing.allocator;

    const content = "FROM golang:1.21 AS builder";
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    const from = isolazifile.instructions[0].from;
    try std.testing.expectEqualStrings("golang", from.image);
    try std.testing.expectEqualStrings("1.21", from.tag.?);
    try std.testing.expectEqualStrings("builder", from.as_name.?);
}

test "parse RUN shell form" {
    const allocator = std.testing.allocator;

    const content =
        \\FROM alpine
        \\RUN apk add --no-cache curl
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    try std.testing.expectEqual(@as(usize, 2), isolazifile.instructions.len);
    const run = isolazifile.instructions[1].run;
    try std.testing.expectEqualStrings("apk add --no-cache curl", run.command);
    try std.testing.expect(!run.is_exec_form);
}

test "parse RUN exec form" {
    const allocator = std.testing.allocator;

    const content =
        \\FROM alpine
        \\RUN ["echo", "hello", "world"]
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    const run = isolazifile.instructions[1].run;
    try std.testing.expect(run.is_exec_form);
    try std.testing.expectEqual(@as(usize, 3), run.exec_args.len);
    try std.testing.expectEqualStrings("echo", run.exec_args[0]);
    try std.testing.expectEqualStrings("hello", run.exec_args[1]);
    try std.testing.expectEqualStrings("world", run.exec_args[2]);
}

test "parse COPY instruction" {
    const allocator = std.testing.allocator;

    const content =
        \\FROM alpine
        \\COPY src/ /app/src/
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    const copy = isolazifile.instructions[1].copy;
    try std.testing.expectEqual(@as(usize, 1), copy.sources.len);
    try std.testing.expectEqualStrings("src/", copy.sources[0]);
    try std.testing.expectEqualStrings("/app/src/", copy.destination);
}

test "parse ENV instruction" {
    const allocator = std.testing.allocator;

    const content =
        \\FROM alpine
        \\ENV PATH=/usr/local/bin:$PATH DEBUG=1
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    const env = isolazifile.instructions[1].env;
    try std.testing.expectEqual(@as(usize, 2), env.vars.len);
    try std.testing.expectEqualStrings("PATH", env.vars[0].key);
    try std.testing.expectEqualStrings("DEBUG", env.vars[1].key);
    try std.testing.expectEqualStrings("1", env.vars[1].value);
}

test "parse line continuation" {
    const allocator = std.testing.allocator;

    const content =
        \\FROM alpine
        \\RUN apk add \
        \\    curl \
        \\    wget
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    const run = isolazifile.instructions[1].run;
    try std.testing.expect(std.mem.indexOf(u8, run.command, "curl") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.command, "wget") != null);
}

test "parse comments" {
    const allocator = std.testing.allocator;

    const content =
        \\# This is a comment
        \\FROM alpine
        \\# Another comment
        \\RUN echo hello
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    try std.testing.expectEqual(@as(usize, 2), isolazifile.instructions.len);
}

test "parse ARG substitution" {
    const allocator = std.testing.allocator;

    const content =
        \\ARG VERSION=1.0
        \\FROM alpine
        \\LABEL version=${VERSION}
    ;
    var isolazifile = try parse(allocator, content);
    defer isolazifile.deinit();

    // ARG instruction should be parsed
    try std.testing.expectEqual(@as(usize, 3), isolazifile.instructions.len);
    const arg = isolazifile.instructions[0].arg;
    try std.testing.expectEqualStrings("VERSION", arg.name);
    try std.testing.expectEqualStrings("1.0", arg.default_value.?);
}

test "no FROM instruction fails" {
    const allocator = std.testing.allocator;

    const content = "RUN echo hello";
    const result = parse(allocator, content);
    try std.testing.expectError(ParseError.NoFromInstruction, result);
}
