const std = @import("std");
const utf8encrypt = @import("utf8encrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("UTF-8 Length-Preserving Encryption Demo\n", .{});
    std.debug.print("========================================\n\n", .{});

    // Generate a random key
    const key: [16]u8 = @splat(0x2B);

    // Initialize cipher
    var cipher = try utf8encrypt.Utf8Cipher.init(allocator, &key);
    defer cipher.deinit();

    // Test with various UTF-8 strings
    const test_strings = [_][]const u8{
        "Hello, World!",
        "Héllo 世界",
        "🌍 emoji test 🚀",
        "Café résumé naïve",
    };

    for (test_strings) |plaintext| {
        std.debug.print("Plaintext:  {s} ({d} bytes)\n", .{ plaintext, plaintext.len });

        const ciphertext = try cipher.encrypt(plaintext, "demo");
        defer allocator.free(ciphertext);

        std.debug.print("Ciphertext: {s} ({d} bytes)\n", .{ ciphertext, ciphertext.len });

        const decrypted = try cipher.decrypt(ciphertext, "demo");
        defer allocator.free(decrypted);

        const match = std.mem.eql(u8, plaintext, decrypted);
        std.debug.print("Decrypted:  {s} (match: {s})\n\n", .{ decrypted, if (match) "✓" else "✗" });
    }
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
