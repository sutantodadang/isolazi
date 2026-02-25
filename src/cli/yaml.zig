//! Minimal YAML parser for docker-compose.yml support.
//!
//! This parser is NOT a full YAML 1.2 implementation. It supports:
//! - Maps (key: value)
//! - Lists ( - item)
//! - Strings (unquoted, single-quoted, double-quoted)
//! - Indentation-based nesting
//!
//! It is designed specifically to parse typical docker-compose.yml files
//! used with Isolazi.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const YamlError = error{
    InvalidCharacter,
    InvalidIndentation,
    UnexpectedToken,
    OutOfMemory,
    KeyMissing,
    ValueMissing,
    InvalidListStart,
};

pub const ParseError = YamlError || Allocator.Error;

/// Represents a value in the YAML document
pub const Value = union(enum) {
    null_value: void,
    boolean: bool,
    integer: i64,
    float: f64,
    string: []const u8,
    list: std.ArrayListUnmanaged(Value),
    map: std.StringArrayHashMapUnmanaged(Value),

    pub fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .list => |*list| {
                for (list.items) |*item| {
                    item.deinit(allocator);
                }
                list.deinit(allocator);
            },
            .map => |*map| {
                var it = map.iterator();
                while (it.next()) |entry| {
                    var val = entry.value_ptr;
                    val.deinit(allocator);
                }
                map.deinit(allocator);
            },
            else => {},
        }
    }

    pub fn asString(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn asMap(self: Value) ?std.StringArrayHashMapUnmanaged(Value) {
        return switch (self) {
            .map => |m| m,
            else => null,
        };
    }

    pub fn asList(self: Value) ?std.ArrayListUnmanaged(Value) {
        return switch (self) {
            .list => |l| l,
            else => null,
        };
    }
};

pub const Parser = struct {
    allocator: Allocator,
    source: []const u8,
    pos: usize = 0,
    line: usize = 1,
    col: usize = 0,

    pub fn init(allocator: Allocator, source: []const u8) Parser {
        return .{
            .allocator = allocator,
            .source = source,
        };
    }

    pub fn parse(self: *Parser) ParseError!Value {
        return self.parseBlock(0);
    }

    fn peek(self: *Parser) ?u8 {
        if (self.pos >= self.source.len) return null;
        return self.source[self.pos];
    }

    fn advance(self: *Parser) void {
        if (self.pos < self.source.len) {
            if (self.source[self.pos] == '\n') {
                self.line += 1;
                self.col = 0;
            } else {
                self.col += 1;
            }
            self.pos += 1;
        }
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.peek()) |c| {
            if (c == ' ' or c == '\t') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skipCommentAndNewlines(self: *Parser) void {
        while (self.peek()) |c| {
            if (c == '#') {
                // Skip until newline
                while (self.peek()) |nc| {
                    if (nc == '\n') break;
                    self.advance();
                }
            } else if (c == '\n' or c == '\r') {
                self.advance();
            } else {
                break;
            }
        }
    }

    // Check current indentation level (col number of next non-whitespace char)
    // Does not advance parser state
    fn currentIndent(self: *Parser) !usize {
        var p = self.pos;
        var col = self.col;

        // If we are at newline, move to next line start
        while (p < self.source.len and (self.source[p] == '\n' or self.source[p] == '\r')) {
            if (self.source[p] == '\n') col = 0;
            p += 1;
        }

        var indent: usize = 0;
        while (p < self.source.len) {
            const c = self.source[p];
            if (c == ' ') {
                indent += 1;
                p += 1;
            } else if (c == '\t') {
                // YAML does not allow tabs for indentation
                return YamlError.InvalidIndentation;
            } else if (c == '#') {
                // Comment line, skip it and continue to next line
                while (p < self.source.len and self.source[p] != '\n') p += 1;
                if (p < self.source.len and self.source[p] == '\n') {
                    col = 0;
                    p += 1;
                    indent = 0;
                    continue;
                }
                break;
            } else if (c == '\n' or c == '\r') {
                // Empty line
                col = 0;
                p += 1;
                indent = 0;
                continue;
            } else {
                break;
            }
        }

        if (p >= self.source.len) return 0; // End of file

        return indent;
    }

    // Parse a generic block at a minimum indentation level
    fn parseBlock(self: *Parser, min_indent: usize) ParseError!Value {
        self.skipCommentAndNewlines();

        // Check indentation of the first item
        const indent = try self.currentIndent();
        if (indent < min_indent) {
            // Block ended
            return Value{ .null_value = {} };
        }

        // Look ahead to see if it's a list or map
        // We need to actually consume indentation now
        try self.consumeIndent(indent);

        if (self.peek() == '-') {
            // It's a list
            return self.parseList(indent);
        } else {
            // It's probably a map (or scalar if key: value is just value)
            // But top-level JSON-like scalars are rare in compose files except as values
            // Let's try to parse as map
            return self.parseMap(indent);
        }
    }

    fn consumeIndent(self: *Parser, indent: usize) !void {
        // Skip newlines/comments until we find real content
        while (true) {
            // Consume newlines
            while (self.peek()) |c| {
                if (c == '\n' or c == '\r') {
                    self.advance();
                    self.col = 0;
                } else {
                    break;
                }
            }

            // Consume spaces up to indent
            var current: usize = 0;
            while (current < indent) {
                if (self.peek()) |c| {
                    if (c == ' ') {
                        self.advance();
                        current += 1;
                    } else if (c == '\n') {
                        // Empty line within block, restart
                        current = 0;
                        self.advance(); // consume newline
                        self.col = 0;
                    } else {
                        // Found content before indent reached?
                        // If it's a comment, skip line
                        if (c == '#') {
                            while (self.peek()) |cc| {
                                if (cc == '\n') break;
                                self.advance();
                            }
                            current = 0; // restart for next line
                            // Loop will continue and consume newline
                        } else {
                            // Unexpected dedent or content?
                            // This might be end of block if we are checking parent.
                            // But here we rely on call to currentIndent() before calling consumeIndent
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            if (current == indent) {
                // Check if it's a comment line
                if (self.peek() == '#') {
                    while (self.peek()) |c| {
                        if (c == '\n') break;
                        self.advance();
                    }
                    // loop again to consume newline
                } else {
                    // Found indentation
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn parseList(self: *Parser, indent: usize) ParseError!Value {
        var list: std.ArrayListUnmanaged(Value) = .empty;
        errdefer list.deinit(self.allocator);

        while (true) {
            // Expect '-'
            if (self.peek() != '-') break;
            self.advance(); // Skip '-'

            // Allow space after '-'
            if (self.peek() == ' ') self.advance();

            // Parse item value
            // Item can be a scalar or a complex object (map/list)

            // If newline follows immediately, it's a block item (map or list)
            // If text follows, it might be scalar or inline map

            var item_indent = try self.currentIndent();
            var item_val: Value = undefined;

            // Check if it's a block or scalar
            // Complex heuristic: if it looks like "key: value", it's a one-item map
            // If it is just "value", it's a string
            // If it is newline, we recurse parseBlock with higher indent

            // Simplification for Docker Compose:
            // services:
            //   - name: foo
            // ports:
            //   - "80:80"

            // Read until newline to check content
            const line_content = self.peekLine();
            if (std.mem.indexOf(u8, line_content, ":") != null) {
                // Should parse as map?
                // Exception: strings with colons like "80:80"
                // If it's quoted, it's a string.
                // If the key part has no spaces and value exists, map.

                // Let's reuse parseValue.
                // But wait, list items in YAML are tricky.
                // - item
                // - key: value

                // We'll parse as scalar first. If it consumes the whole line and has no colon, it's string.
                // If it finds a key: value structure on the same line, parseMapEntry?

                if (line_content.len == 0) {
                    // Block content on next line
                    item_indent = try self.currentIndent();
                    item_val = try self.parseBlock(item_indent);
                } else {
                    // Inline content
                    // Try to parse as scalar string first
                    // If it looks like a map key (key:), it's an inline map

                    // Optimization: For Docker Compose, list items are usually strings (ports, vols)
                    // or maps (if complex).

                    // Try parsing inline value
                    item_val = try self.parseValue();
                }
            } else {
                // Scalar string
                item_val = try self.parseValue();
            }

            try list.append(self.allocator, item_val);

            // Check next item
            const next_indent = try self.currentIndent();
            if (next_indent != indent) break;

            try self.consumeIndent(indent);
            if (self.peek() != '-') break;
        }

        return Value{ .list = list };
    }

    fn parseMap(self: *Parser, indent: usize) ParseError!Value {
        var map: std.StringArrayHashMapUnmanaged(Value) = .empty;
        errdefer map.deinit(self.allocator);

        while (true) {
            if (self.peek() == null) break;
            // Read key
            const key = try self.parseKey();

            // Expect ':'
            self.skipWhitespace();
            if (self.peek() != ':') {
                return YamlError.UnexpectedToken;
            }
            self.advance();

            // Read value
            // Value can be scalar on same line, or block on next line
            self.skipWhitespace(); // Spaces after colon

            var val: Value = undefined;
            if (self.peek() == '\n' or self.peek() == '\r') {
                // Block value on next line?
                const next_indent = try self.currentIndent();
                if (next_indent > indent) {
                    val = try self.parseBlock(next_indent);
                } else {
                    // Empty value (null)
                    val = Value{ .null_value = {} };
                }
            } else {
                // Inline value
                val = try self.parseValue();
            }

            try map.put(self.allocator, key, val);

            // Check next key
            // Must have same indent
            const next_indent = try self.currentIndent();
            if (next_indent != indent) break;

            try self.consumeIndent(indent);
        }

        return Value{ .map = map };
    }

    // Parse key: unquoted string usually
    fn parseKey(self: *Parser) ![]const u8 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (c == ':' or c == '\n') break;
            self.advance();
        }
        return std.mem.trim(u8, self.source[start..self.pos], " ");
    }

    // Parse flow-style list [a, b, c]
    fn parseFlowList(self: *Parser) ParseError!Value {
        self.advance(); // Skip [
        var list: std.ArrayListUnmanaged(Value) = .empty;
        errdefer list.deinit(self.allocator);

        while (true) {
            self.skipWhitespace();
            if (self.peek() == ']') {
                self.advance();
                break;
            }

            const val = try self.parseValue();
            try list.append(self.allocator, val);

            self.skipWhitespace();
            if (self.peek() == ',') {
                self.advance();
            } else if (self.peek() != ']') {
                return ParseError.UnexpectedToken;
            }
        }
        return Value{ .list = list };
    }

    // Parse scalar value: string, number, bool
    // For now, treat mostly as strings, maybe simple type inference
    fn parseValue(self: *Parser) ParseError!Value {
        self.skipWhitespace();

        if (self.peek() == '[') {
            return self.parseFlowList();
        }

        const start = self.pos;

        if (self.peek() == '"') {
            // Quoted string
            self.advance();
            const str_start = self.pos;
            while (self.peek()) |c| {
                if (c == '"' and self.source[self.pos - 1] != '\\') break;
                self.advance();
            }
            const res = self.source[str_start..self.pos];
            if (self.peek() == '"') self.advance();
            return Value{ .string = res };
        } else if (self.peek() == '\'') {
            // Single quoted string
            self.advance();
            const str_start = self.pos;
            while (self.peek()) |c| {
                if (c == '\'') break;
                self.advance();
            }
            const res = self.source[str_start..self.pos];
            if (self.peek() == '\'') self.advance();
            return Value{ .string = res };
        }

        // Unquoted value until newline or comment
        while (self.peek()) |c| {
            if (c == '\n' or c == '#') break;
            self.advance();
        }
        const raw = std.mem.trim(u8, self.source[start..self.pos], " ");

        // Basic type inference
        if (std.mem.eql(u8, raw, "true") or std.mem.eql(u8, raw, "yes")) {
            return Value{ .boolean = true };
        }
        if (std.mem.eql(u8, raw, "false") or std.mem.eql(u8, raw, "no")) {
            return Value{ .boolean = false };
        }
        // TODO: integer/float parsing

        return Value{ .string = raw };
    }

    fn peekLine(self: *Parser) []const u8 {
        const start = self.pos;
        var p = start;
        while (p < self.source.len) {
            if (self.source[p] == '\n') break;
            p += 1;
        }
        return self.source[start..p];
    }
};

test "parse simple map" {
    const src =
        \\version: '3'
        \\services:
        \\  web:
        \\    image: nginx
    ;

    var parser = Parser.init(std.testing.allocator, src);
    var val = try parser.parse();
    defer val.deinit();

    const root = val.asMap().?;
    try std.testing.expectEqualStrings("3", root.get("version").?.asString().?);

    const services = root.get("services").?.asMap().?;
    const web = services.get("web").?.asMap().?;
    try std.testing.expectEqualStrings("nginx", web.get("image").?.asString().?);
}
