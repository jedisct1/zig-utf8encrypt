const std = @import("std");
const utf8encrypt = @import("utf8encrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("UTF-8 Length-Preserving Encryption Demo\n", .{});
    std.debug.print("=======================================\n\n", .{});

    // Generate a random key
    const key: [16]u8 = @splat(0x2B);

    // Test with various UTF-8 strings
    const test_strings = [_][]const u8{
        "Hello, World!",
        "Héllo 世界",
        "🌍 emoji test 🚀",
        "Café résumé naïve",
    };

    // Test with boundary space avoidance enabled
    std.debug.print("=== With Boundary Space Avoidance ===\n\n", .{});
    {
        var cipher = try utf8encrypt.Utf8Cipher.init(allocator, &key, true);
        defer cipher.deinit();

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

    // Test without boundary space avoidance
    std.debug.print("\n=== Without Boundary Space Avoidance ===\n\n", .{});
    {
        var cipher = try utf8encrypt.Utf8Cipher.init(allocator, &key, false);
        defer cipher.deinit();

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
}
