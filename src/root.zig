//! UTF-8 Format-Preserving Encryption with Class Permutation
//!
//! This library provides format-preserving encryption for UTF-8 text, ensuring that:
//! - Output is valid UTF-8
//! - Byte length is exactly preserved (input_len == output_len)
//! - Each code point stays within its UTF-8 byte-length class (1-4 bytes)
//! - Character class sequence is permuted based on key and content
//!
//! Uses the FAST cipher with radix-256 encoding for format-preserving encryption
//! with content-dependent class permutations to hide structural information.
//!
//! ## Use Cases
//!
//! This library is ideal for encrypting UTF-8 text in length-constrained environments:
//!
//! - **Social Network Posts**: Encrypt messages while respecting character/byte limits
//! - **Database Fields**: Encrypt VARCHAR/TEXT fields without changing column size requirements
//! - **Filesystem**: Encrypt filenames that must be valid UTF-8 with byte length restrictions
//! - **Protocol Messages**: Encrypt fixed-length UTF-8 fields in network protocols
//! - **Legacy Systems**: Encrypt data for systems that validate UTF-8 and enforce byte limits
//! - **Confidential text**: Encrypt text while hiding language/encoding patterns
//! - **Obfuscated messages**: Hide whether text contains ASCII, Unicode, emojis, etc.
//! - **Research/experimentation**: Explore format-preserving encryption techniques

const std = @import("std");
const fast = @import("fast");
const Allocator = std.mem.Allocator;

/// Errors that can occur during UTF-8 encryption/decryption
pub const Utf8EncryptError = error{
    /// Input is not valid UTF-8
    InvalidUtf8,
    /// Code point is a surrogate (U+D800-U+DFFF), invalid in UTF-8
    SurrogateCodepoint,
    /// Code point is beyond Unicode range (>U+10FFFF)
    CodepointTooLarge,
    /// Memory allocation failed
    OutOfMemory,
    /// FAST cipher error
    CipherError,
    /// Cannot encode surrogate half in UTF-8
    Utf8CannotEncodeSurrogateHalf,
    /// Tweak string is too long to format into buffer
    TweakBufferOverflow,
};

/// UTF-8 byte-length classes
/// Each Unicode code point belongs to one of 4 classes based on its UTF-8 byte length
pub const Utf8Class = enum(u2) {
    /// 1-byte UTF-8: U+0000 - U+007F (ASCII, control chars < 32 not encrypted, 96 encrypted values)
    class1 = 0,
    /// 2-byte UTF-8: U+0080 - U+07FF (1,920 values)
    class2 = 1,
    /// 3-byte UTF-8: U+0800 - U+FFFF minus surrogates (61,440 values)
    class3 = 2,
    /// 4-byte UTF-8: U+10000 - U+10FFFF (1,048,576 values)
    class4 = 3,

    /// Determine the UTF-8 class for a given code point
    pub fn fromCodepoint(cp: u21) Utf8EncryptError!Utf8Class {
        if (cp < 0x80) return .class1;
        if (cp < 0x800) return .class2;
        if (cp < 0x10000) {
            // Check for surrogates
            if (std.unicode.isSurrogateCodepoint(cp)) {
                return error.SurrogateCodepoint;
            }
            return .class3;
        }
        if (cp <= 0x10FFFF) return .class4;
        return error.CodepointTooLarge;
    }
};

/// FAST cipher uses base-256 encoding (radix 256) for all classes
pub const RADIX: u32 = 256;

/// Word lengths for each class (number of base-256 digits needed)
/// Note: FAST requires word_length >= 2
pub const WORD_LEN_CLASS1: u32 = 2; // 256^2 = 65536 > 128 (minimum is 2)
pub const WORD_LEN_CLASS2: u32 = 2; // 256^2 = 65536 > 1920
pub const WORD_LEN_CLASS3: u32 = 2; // 256^2 = 65536 > 63488
pub const WORD_LEN_CLASS4: u32 = 3; // 256^3 = 16777216 > 1048576

/// Number of S-boxes for FAST cipher
pub const SBOX_COUNT: u32 = fast.SBOX_POOL_SIZE;

/// Domain sizes for each UTF-8 class
pub const DOMAIN_SIZE_CLASS1: u32 = 96; // U+0020 - U+007F (printable ASCII, control chars are not encrypted)
pub const DOMAIN_SIZE_CLASS2: u32 = 1920; // U+0080 - U+07FF
pub const DOMAIN_SIZE_CLASS3: u32 = 61440; // U+0800 - U+FFFF (excluding surrogates)
pub const DOMAIN_SIZE_CLASS4: u32 = 1048576; // U+10000 - U+10FFFF

/// Buffer sizes for encryption/decryption
pub const IV_SIZE: usize = 16; // Initialization vector size in bytes
pub const TWEAK_BUFFER_SIZE: usize = 1024; // Maximum tweak string buffer size
pub const PREV_CIPHERTEXT_BUFFER_SIZE: usize = 16; // Buffer for previous ciphertext bytes (IV size)
pub const SEED_SIZE: usize = 32; // Seed size for Fisher-Yates shuffle (256 bits)

/// Context-separation prefixes for TurboSHAKE128 (all 8 bytes for domain separation)
pub const SHAKE_PREFIX_IV: []const u8 = "utf8e-iv"; // IV generation from tweak
pub const SHAKE_PREFIX_SEED_DERIVE: []const u8 = "utf8e-sd"; // Seed derivation from key+codepoints
pub const SHAKE_PREFIX_PERMUTATION: []const u8 = "utf8e-pr"; // Permutation generation from seed
pub const SHAKE_PREFIX_CLASS1: []const u8 = "utf8e-c1"; // Class1 permutation from tweak

/// Context type (all classes use same radix)
const CtxType = fast.Context(RADIX, SBOX_COUNT);

/// Generate a Fisher-Yates permutation of size N using the given seed
fn fisherYatesShuffle(comptime N: usize, seed: *const [SEED_SIZE]u8, perm: *[N]u8) void {
    for (0..N) |i| {
        perm[i] = @intCast(i);
    }

    var prng = std.Random.ChaCha.init(seed.*);
    const random = prng.random();

    var i: usize = N - 1;
    while (i > 0) : (i -= 1) {
        const j = random.intRangeAtMost(usize, 0, i);
        std.mem.swap(u8, &perm[i], &perm[j]);
    }
}

/// Generate inverse permutation
fn invertPermutation(comptime N: usize, perm: *const [N]u8, inv: *[N]u8) void {
    for (0..N) |i| {
        const val = perm[i];
        inv[val] = @intCast(i);
    }
}

/// Derive a seed from key and sorted codepoints
/// Sorts the codepoints, serializes them, and hashes with key using TurboSHAKE128
fn deriveSeedFromCodepoints(key: *const [16]u8, codepoints: []const u21, allocator: Allocator) ![SEED_SIZE]u8 {
    // Create a copy and sort it
    const sorted = try allocator.dupe(u21, codepoints);
    defer allocator.free(sorted);
    std.mem.sort(u21, sorted, {}, std.sort.asc(u21));

    // Serialize codepoints as 4-byte little-endian integers
    const cp_bytes = try allocator.alloc(u8, sorted.len * 4);
    defer allocator.free(cp_bytes);
    for (sorted, 0..) |cp, i| {
        std.mem.writeInt(u32, cp_bytes[i * 4 ..][0..4], @as(u32, cp), .little);
    }

    // Hash key + sorted codepoints with TurboSHAKE128
    var seed: [SEED_SIZE]u8 = undefined;
    const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
    var shake = TurboShake.init(.{});
    shake.update(SHAKE_PREFIX_SEED_DERIVE);
    shake.update(key);
    shake.update(cp_bytes);
    shake.squeeze(&seed);

    return seed;
}

/// Generate a permutation using Fisher-Yates with TurboSHAKE128 as PRNG
fn generatePermutationFromSeed(seed: *const [SEED_SIZE]u8, n: usize, allocator: Allocator) ![]usize {
    const perm = try allocator.alloc(usize, n);
    errdefer allocator.free(perm);

    // Initialize to identity permutation
    for (0..n) |i| {
        perm[i] = i;
    }

    // Fisher-Yates shuffle using TurboSHAKE128 as PRNG
    const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
    var shake = TurboShake.init(.{});
    shake.update(SHAKE_PREFIX_PERMUTATION);
    shake.update(seed);

    for (0..n) |i| {
        // Generate random j in [i, n-1]
        var rand_bytes: [8]u8 = undefined;
        shake.squeeze(&rand_bytes);
        const rand_val = std.mem.readInt(u64, &rand_bytes, .little);
        const j = i + (rand_val % (n - i));

        // Swap perm[i] and perm[j]
        std.mem.swap(usize, &perm[i], &perm[j]);
    }

    return perm;
}

/// Invert a dynamically-sized permutation
fn invertPermutationDynamic(perm: []const usize, allocator: Allocator) ![]usize {
    const inv = try allocator.alloc(usize, perm.len);
    errdefer allocator.free(inv);

    for (perm, 0..) |p, i| {
        inv[p] = i;
    }

    return inv;
}

/// Helper to initialize a FAST context with given word length
fn initFastContext(
    allocator: Allocator,
    word_len: u32,
    key: *const [16]u8,
) !*CtxType {
    const params = try fast.calculateRecommendedParams(RADIX, word_len, 128);
    return fast.init(RADIX, SBOX_COUNT, allocator, &params, key) catch {
        return error.CipherError;
    };
}

/// Generic cycle walking for format-preserving encryption
/// Encrypts/decrypts an index using FAST cipher with cycle walking
fn cycleWalk(
    comptime N: usize,
    ctx: *CtxType,
    idx: u32,
    max_value: u32,
    tweak: []const u8,
    encrypt_mode: bool,
) Utf8EncryptError!u32 {
    // Determine the integer type based on byte count
    const IntType = switch (N) {
        2 => u16,
        3 => u24,
        else => @compileError("Unsupported byte count for cycleWalk"),
    };

    // Compute max iterations based on expected cycle walking rounds
    // Expected iterations = (256^N) / max_value
    // Use 10x that as a safety margin
    comptime var space_size: u64 = 1;
    comptime {
        var i: usize = 0;
        while (i < N) : (i += 1) {
            space_size *= 256;
        }
    }
    const expected_iterations = @divTrunc(space_size, max_value);
    const max_iterations = @max(100, expected_iterations * 10);

    var current_idx = idx;
    var iterations: usize = 0;

    while (iterations < max_iterations) : (iterations += 1) {
        var input: [N]u8 = undefined;
        var output: [N]u8 = undefined;

        const value: IntType = @intCast(current_idx);
        std.mem.writeInt(IntType, &input, value, .little);

        if (encrypt_mode) {
            fast.encrypt(RADIX, SBOX_COUNT, ctx, tweak, &input, &output) catch {
                return error.CipherError;
            };
        } else {
            fast.decrypt(RADIX, SBOX_COUNT, ctx, tweak, &input, &output) catch {
                return error.CipherError;
            };
        }

        current_idx = std.mem.readInt(IntType, &output, .little);
        if (current_idx < max_value) {
            return current_idx;
        }
    }

    return error.CipherError;
}

/// Map code point to domain index for Class 1 (printable ASCII)
/// Domain: U+0020 - U+007F (control characters < 32 are not encrypted)
fn cpToIndexClass1(cp: u21) u32 {
    std.debug.assert(cp >= 32 and cp < 0x80);
    return @as(u32, cp - 32);
}

/// Map domain index back to code point for Class 1
fn indexToCpClass1(idx: u32) u21 {
    std.debug.assert(idx < DOMAIN_SIZE_CLASS1);
    return @as(u21, @intCast(idx + 32));
}

/// Map code point to domain index for Class 2
/// Domain: U+0080 - U+07FF
fn cpToIndexClass2(cp: u21) u32 {
    std.debug.assert(cp >= 0x80 and cp < 0x800);
    return @as(u32, cp - 0x80);
}

/// Map domain index back to code point for Class 2
fn indexToCpClass2(idx: u32) u21 {
    std.debug.assert(idx < DOMAIN_SIZE_CLASS2);
    return @as(u21, @intCast(idx + 0x80));
}

/// Map code point to domain index for Class 3
/// Domain: U+0800 - U+FFFF, excluding surrogates U+D800 - U+DFFF
fn cpToIndexClass3(cp: u21) u32 {
    std.debug.assert(cp >= 0x800 and cp < 0x10000);
    std.debug.assert(!(cp >= 0xD800 and cp <= 0xDFFF)); // No surrogates

    if (cp < 0xD800) {
        return @as(u32, cp - 0x800); // 0x800..0xD7FF -> 0..53247
    } else {
        return @as(u32, cp - 0xE000 + 53248); // 0xE000..0xFFFF -> 53248..61439
    }
}

/// Map domain index back to code point for Class 3
fn indexToCpClass3(idx: u32) u21 {
    std.debug.assert(idx < DOMAIN_SIZE_CLASS3); // 53248 + 8192

    if (idx < 53248) {
        return @as(u21, @intCast(idx + 0x800)); // -> 0x800..0xD7FF
    } else {
        return @as(u21, @intCast(idx - 53248 + 0xE000)); // -> 0xE000..0xFFFF
    }
}

/// Map code point to domain index for Class 4
/// Domain: U+10000 - U+10FFFF
fn cpToIndexClass4(cp: u21) u32 {
    std.debug.assert(cp >= 0x10000 and cp <= 0x10FFFF);
    return @as(u32, cp - 0x10000);
}

/// Map domain index back to code point for Class 4
fn indexToCpClass4(idx: u32) u21 {
    std.debug.assert(idx < DOMAIN_SIZE_CLASS4);
    return @as(u21, @intCast(idx + 0x10000));
}

/// Main UTF-8 cipher context
/// Holds FAST cipher contexts for all 4 UTF-8 byte-length classes
pub const Utf8Cipher = struct {
    const Self = @This();

    // FAST contexts for each class (all use radix 256, differ by word_length in params)
    ctx1: *CtxType, // word_length=2
    ctx2: *CtxType, // word_length=2
    ctx3: *CtxType, // word_length=2
    ctx4: *CtxType, // word_length=3

    key: [16]u8, // Store key for seed derivation

    allocator: Allocator,

    /// Initialize UTF-8 cipher with a 16-byte master key
    pub fn init(allocator: Allocator, key: *const [16]u8) !Self {
        // Initialize FAST contexts for each class
        const ctx1 = try initFastContext(allocator, WORD_LEN_CLASS1, key);
        errdefer {
            ctx1.deinit();
            allocator.destroy(ctx1);
        }

        const ctx2 = try initFastContext(allocator, WORD_LEN_CLASS2, key);
        errdefer {
            ctx2.deinit();
            allocator.destroy(ctx2);
        }

        const ctx3 = try initFastContext(allocator, WORD_LEN_CLASS3, key);
        errdefer {
            ctx3.deinit();
            allocator.destroy(ctx3);
        }

        const ctx4 = try initFastContext(allocator, WORD_LEN_CLASS4, key);
        errdefer {
            ctx4.deinit();
            allocator.destroy(ctx4);
        }

        return .{
            .ctx1 = ctx1,
            .ctx2 = ctx2,
            .ctx3 = ctx3,
            .ctx4 = ctx4,
            .key = key.*,
            .allocator = allocator,
        };
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        self.ctx1.deinit();
        self.allocator.destroy(self.ctx1);

        self.ctx2.deinit();
        self.allocator.destroy(self.ctx2);

        self.ctx3.deinit();
        self.allocator.destroy(self.ctx3);

        self.ctx4.deinit();
        self.allocator.destroy(self.ctx4);
    }

    /// Encrypt a single code point using the appropriate FAST context
    fn encryptCodepoint(
        self: *Self,
        cp: u21,
        tweak: []const u8,
        is_boundary: bool,
    ) Utf8EncryptError!u21 {
        const class = try Utf8Class.fromCodepoint(cp);

        switch (class) {
            .class1 => {
                // Control characters (code < 32) are not encrypted
                if (cp < 32) {
                    return cp;
                }

                const idx = cpToIndexClass1(cp);
                // For class1, generate a tweak-dependent permutation with seed
                var seed: [SEED_SIZE]u8 = undefined;
                const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
                var shake = TurboShake.init(.{});
                shake.update(SHAKE_PREFIX_CLASS1);
                shake.update(tweak);
                shake.squeeze(&seed);

                var perm: [DOMAIN_SIZE_CLASS1]u8 = undefined;
                fisherYatesShuffle(DOMAIN_SIZE_CLASS1, &seed, &perm);

                var encrypted_idx = perm[idx];

                // If boundary position and result is space (index 0), apply LUT again
                if (is_boundary and encrypted_idx == 0) {
                    encrypted_idx = perm[0];
                }

                return indexToCpClass1(encrypted_idx);
            },
            .class2 => {
                const idx = cpToIndexClass2(cp);
                const encrypted_idx = try cycleWalk(2, self.ctx2, idx, DOMAIN_SIZE_CLASS2, tweak, true);
                return indexToCpClass2(encrypted_idx);
            },
            .class3 => {
                const idx = cpToIndexClass3(cp);
                const encrypted_idx = try cycleWalk(2, self.ctx3, idx, DOMAIN_SIZE_CLASS3, tweak, true);
                return indexToCpClass3(encrypted_idx);
            },
            .class4 => {
                const idx = cpToIndexClass4(cp);
                const encrypted_idx = try cycleWalk(3, self.ctx4, idx, DOMAIN_SIZE_CLASS4, tweak, true);
                return indexToCpClass4(encrypted_idx);
            },
        }
    }

    /// Decrypt a single code point using the appropriate FAST context
    fn decryptCodepoint(
        self: *Self,
        cp: u21,
        tweak: []const u8,
        is_boundary: bool,
    ) Utf8EncryptError!u21 {
        const class = try Utf8Class.fromCodepoint(cp);

        switch (class) {
            .class1 => {
                // Control characters (code < 32) are not encrypted
                if (cp < 32) {
                    return cp;
                }

                const idx = cpToIndexClass1(cp);
                // For class1, generate same tweak-dependent permutation with seed
                var seed: [SEED_SIZE]u8 = undefined;
                const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
                var shake = TurboShake.init(.{});
                shake.update(SHAKE_PREFIX_CLASS1);
                shake.update(tweak);
                shake.squeeze(&seed);

                var perm: [DOMAIN_SIZE_CLASS1]u8 = undefined;
                fisherYatesShuffle(DOMAIN_SIZE_CLASS1, &seed, &perm);

                var inv_perm: [DOMAIN_SIZE_CLASS1]u8 = undefined;
                invertPermutation(DOMAIN_SIZE_CLASS1, &perm, &inv_perm);

                var decrypted_idx = inv_perm[idx];

                // If boundary position and result is space (index 0), apply inverse LUT again
                if (is_boundary and decrypted_idx == 0) {
                    decrypted_idx = inv_perm[0];
                }

                return indexToCpClass1(decrypted_idx);
            },
            .class2 => {
                const idx = cpToIndexClass2(cp);
                const decrypted_idx = try cycleWalk(2, self.ctx2, idx, DOMAIN_SIZE_CLASS2, tweak, false);
                return indexToCpClass2(decrypted_idx);
            },
            .class3 => {
                const idx = cpToIndexClass3(cp);
                const decrypted_idx = try cycleWalk(2, self.ctx3, idx, DOMAIN_SIZE_CLASS3, tweak, false);
                return indexToCpClass3(decrypted_idx);
            },
            .class4 => {
                const idx = cpToIndexClass4(cp);
                const decrypted_idx = try cycleWalk(3, self.ctx4, idx, DOMAIN_SIZE_CLASS4, tweak, false);
                return indexToCpClass4(decrypted_idx);
            },
        }
    }

    /// Encrypt UTF-8 text with chaining mode and content-dependent permutation
    /// Each codepoint's tweak incorporates the previous ciphertext bytes
    /// The order of codepoints is then shuffled based on sorted encrypted values
    /// Returns allocated ciphertext with same byte length as plaintext
    pub fn encrypt(
        self: *Self,
        plaintext: []const u8,
        tweak: []const u8,
    ) Utf8EncryptError![]u8 {
        // Validate UTF-8
        if (!std.unicode.utf8ValidateSlice(plaintext)) {
            return error.InvalidUtf8;
        }

        // Step 1: Decode all plaintext codepoints
        var plaintext_cps = std.ArrayList(u21){};
        defer plaintext_cps.deinit(self.allocator);

        var view = std.unicode.Utf8View.initUnchecked(plaintext);
        var it = view.iterator();
        while (it.nextCodepoint()) |cp| {
            try plaintext_cps.append(self.allocator, cp);
        }

        // Handle empty input
        if (plaintext_cps.items.len == 0) {
            return try self.allocator.alloc(u8, 0);
        }

        // Step 2: Encrypt each codepoint with chaining
        const encrypted_cps = try self.allocator.alloc(u21, plaintext_cps.items.len);
        defer self.allocator.free(encrypted_cps);

        // Generate IV from base tweak using TurboSHAKE128
        var iv: [IV_SIZE]u8 = undefined;
        const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
        var shake = TurboShake.init(.{});
        shake.update(SHAKE_PREFIX_IV);
        shake.update(tweak);
        shake.squeeze(&iv);

        var prev_ciphertext_bytes: [PREV_CIPHERTEXT_BUFFER_SIZE]u8 = undefined;
        var prev_len: usize = iv.len;

        // Use IV as "previous" for first codepoint
        @memcpy(prev_ciphertext_bytes[0..iv.len], &iv);

        for (plaintext_cps.items, 0..) |cp, pos| {
            // Create chained tweak: base_tweak:pos:N:chain:<binary_prev_bytes>
            var tweak_buf: [TWEAK_BUFFER_SIZE]u8 = undefined;
            var tweak_pos: usize = 0;

            // Append base tweak
            @memcpy(tweak_buf[tweak_pos..][0..tweak.len], tweak);
            tweak_pos += tweak.len;

            // Append ":pos:"
            const pos_prefix = ":pos:";
            @memcpy(tweak_buf[tweak_pos..][0..pos_prefix.len], pos_prefix);
            tweak_pos += pos_prefix.len;

            // Append position as decimal string
            const pos_str = std.fmt.bufPrint(tweak_buf[tweak_pos..], "{d}", .{pos}) catch {
                return error.TweakBufferOverflow;
            };
            tweak_pos += pos_str.len;

            // Append ":chain:"
            const chain_prefix = ":chain:";
            @memcpy(tweak_buf[tweak_pos..][0..chain_prefix.len], chain_prefix);
            tweak_pos += chain_prefix.len;

            // Append previous ciphertext bytes (binary, not hex-encoded)
            if (tweak_pos + prev_len > TWEAK_BUFFER_SIZE) {
                return error.TweakBufferOverflow;
            }
            @memcpy(tweak_buf[tweak_pos..][0..prev_len], prev_ciphertext_bytes[0..prev_len]);
            tweak_pos += prev_len;

            const chained_tweak = tweak_buf[0..tweak_pos];

            // Check if this is a boundary position (first or last)
            const is_boundary = (pos == 0 or pos == plaintext_cps.items.len - 1);

            // Encrypt code point with chained tweak
            encrypted_cps[pos] = try self.encryptCodepoint(cp, chained_tweak, is_boundary);

            // Encode encrypted codepoint to get ciphertext bytes for chaining
            var temp_encoded: [4]u8 = undefined;
            const len = try std.unicode.utf8Encode(encrypted_cps[pos], &temp_encoded);
            @memcpy(prev_ciphertext_bytes[0..len], temp_encoded[0..len]);
            prev_len = len;
        }

        // Step 3: Derive permutation from sorted encrypted codepoints
        const seed = try deriveSeedFromCodepoints(&self.key, encrypted_cps, self.allocator);
        const perm = try generatePermutationFromSeed(&seed, encrypted_cps.len, self.allocator);
        defer self.allocator.free(perm);

        // Step 4: Apply permutation to shuffle encrypted codepoints
        const shuffled_cps = try self.allocator.alloc(u21, encrypted_cps.len);
        defer self.allocator.free(shuffled_cps);
        for (0..encrypted_cps.len) |i| {
            shuffled_cps[i] = encrypted_cps[perm[i]];
        }

        // Step 5: Encode shuffled codepoints to UTF-8
        const output = try self.allocator.alloc(u8, plaintext.len);
        errdefer self.allocator.free(output);

        var output_pos: usize = 0;
        for (shuffled_cps) |cp| {
            const len = try std.unicode.utf8Encode(cp, output[output_pos..]);
            output_pos += len;
        }

        std.debug.assert(output_pos == plaintext.len);
        return output;
    }

    /// Decrypt UTF-8 ciphertext with chaining mode and content-dependent permutation
    /// First unshuffles based on sorted ciphertext, then decrypts with chaining
    /// Returns allocated plaintext with same byte length as ciphertext
    pub fn decrypt(
        self: *Self,
        ciphertext: []const u8,
        tweak: []const u8,
    ) Utf8EncryptError![]u8 {
        // Validate UTF-8
        if (!std.unicode.utf8ValidateSlice(ciphertext)) {
            return error.InvalidUtf8;
        }

        // Step 1: Decode all shuffled ciphertext codepoints
        var shuffled_cps = std.ArrayList(u21){};
        defer shuffled_cps.deinit(self.allocator);

        var view = std.unicode.Utf8View.initUnchecked(ciphertext);
        var it = view.iterator();
        while (it.nextCodepoint()) |cp| {
            try shuffled_cps.append(self.allocator, cp);
        }

        // Handle empty input
        if (shuffled_cps.items.len == 0) {
            return try self.allocator.alloc(u8, 0);
        }

        // Step 2: Derive same permutation from sorted codepoints
        const seed = try deriveSeedFromCodepoints(&self.key, shuffled_cps.items, self.allocator);
        const perm = try generatePermutationFromSeed(&seed, shuffled_cps.items.len, self.allocator);
        defer self.allocator.free(perm);

        // Step 3: Invert permutation
        const inv_perm = try invertPermutationDynamic(perm, self.allocator);
        defer self.allocator.free(inv_perm);

        // Step 4: Unshuffle to restore original encrypted order
        const encrypted_cps = try self.allocator.alloc(u21, shuffled_cps.items.len);
        defer self.allocator.free(encrypted_cps);
        for (0..shuffled_cps.items.len) |i| {
            encrypted_cps[i] = shuffled_cps.items[inv_perm[i]];
        }

        // Step 5: Decrypt with chaining (must use original encrypted order)
        const plaintext_cps = try self.allocator.alloc(u21, encrypted_cps.len);
        defer self.allocator.free(plaintext_cps);

        // Generate same IV from base tweak using TurboSHAKE128
        var iv: [IV_SIZE]u8 = undefined;
        const TurboShake = std.crypto.hash.sha3.TurboShake128(null);
        var shake = TurboShake.init(.{});
        shake.update(SHAKE_PREFIX_IV);
        shake.update(tweak);
        shake.squeeze(&iv);

        var prev_ciphertext_bytes: [PREV_CIPHERTEXT_BUFFER_SIZE]u8 = undefined;
        var prev_len: usize = iv.len;

        // Use IV as "previous" for first codepoint
        @memcpy(prev_ciphertext_bytes[0..iv.len], &iv);

        for (encrypted_cps, 0..) |cp, pos| {
            // Create same chained tweak as encryption
            var tweak_buf: [TWEAK_BUFFER_SIZE]u8 = undefined;
            var tweak_pos: usize = 0;

            // Append base tweak
            @memcpy(tweak_buf[tweak_pos..][0..tweak.len], tweak);
            tweak_pos += tweak.len;

            // Append ":pos:"
            const pos_prefix = ":pos:";
            @memcpy(tweak_buf[tweak_pos..][0..pos_prefix.len], pos_prefix);
            tweak_pos += pos_prefix.len;

            // Append position as decimal string
            const pos_str = std.fmt.bufPrint(tweak_buf[tweak_pos..], "{d}", .{pos}) catch {
                return error.TweakBufferOverflow;
            };
            tweak_pos += pos_str.len;

            // Append ":chain:"
            const chain_prefix = ":chain:";
            @memcpy(tweak_buf[tweak_pos..][0..chain_prefix.len], chain_prefix);
            tweak_pos += chain_prefix.len;

            // Append previous ciphertext bytes (binary, not hex-encoded)
            if (tweak_pos + prev_len > TWEAK_BUFFER_SIZE) {
                return error.TweakBufferOverflow;
            }
            @memcpy(tweak_buf[tweak_pos..][0..prev_len], prev_ciphertext_bytes[0..prev_len]);
            tweak_pos += prev_len;

            const chained_tweak = tweak_buf[0..tweak_pos];

            // Check if this is a boundary position (first or last)
            const is_boundary = (pos == 0 or pos == encrypted_cps.len - 1);

            // Decrypt code point with chained tweak
            plaintext_cps[pos] = try self.decryptCodepoint(cp, chained_tweak, is_boundary);

            // Encode encrypted codepoint to get ciphertext bytes for chaining
            var temp_encoded: [4]u8 = undefined;
            const len = try std.unicode.utf8Encode(cp, &temp_encoded);
            @memcpy(prev_ciphertext_bytes[0..len], temp_encoded[0..len]);
            prev_len = len;
        }

        // Step 6: Encode plaintext codepoints to UTF-8
        const output = try self.allocator.alloc(u8, ciphertext.len);
        errdefer self.allocator.free(output);

        var output_pos: usize = 0;
        for (plaintext_cps) |cp| {
            const len = try std.unicode.utf8Encode(cp, output[output_pos..]);
            output_pos += len;
        }

        std.debug.assert(output_pos == ciphertext.len);
        return output;
    }
};

// Tests
test "class detection" {
    try std.testing.expectEqual(Utf8Class.class1, try Utf8Class.fromCodepoint(0x00)); // NULL
    try std.testing.expectEqual(Utf8Class.class1, try Utf8Class.fromCodepoint(0x7F)); // DEL
    try std.testing.expectEqual(Utf8Class.class2, try Utf8Class.fromCodepoint(0x80));
    try std.testing.expectEqual(Utf8Class.class2, try Utf8Class.fromCodepoint(0x7FF));
    try std.testing.expectEqual(Utf8Class.class3, try Utf8Class.fromCodepoint(0x800));
    try std.testing.expectEqual(Utf8Class.class3, try Utf8Class.fromCodepoint(0xD7FF)); // Before surrogates
    try std.testing.expectEqual(Utf8Class.class3, try Utf8Class.fromCodepoint(0xE000)); // After surrogates
    try std.testing.expectEqual(Utf8Class.class3, try Utf8Class.fromCodepoint(0xFFFF));
    try std.testing.expectEqual(Utf8Class.class4, try Utf8Class.fromCodepoint(0x10000));
    try std.testing.expectEqual(Utf8Class.class4, try Utf8Class.fromCodepoint(0x10FFFF));

    // Test surrogate rejection
    try std.testing.expectError(error.SurrogateCodepoint, Utf8Class.fromCodepoint(0xD800));
    try std.testing.expectError(error.SurrogateCodepoint, Utf8Class.fromCodepoint(0xDFFF));
}

test "code point mapping roundtrip" {
    // Class 1
    try std.testing.expectEqual(@as(u21, 0x41), indexToCpClass1(cpToIndexClass1(0x41))); // 'A'

    // Class 2
    try std.testing.expectEqual(@as(u21, 0xFF), indexToCpClass2(cpToIndexClass2(0xFF))); // ÿ
    try std.testing.expectEqual(@as(u21, 0x7FF), indexToCpClass2(cpToIndexClass2(0x7FF)));

    // Class 3
    try std.testing.expectEqual(@as(u21, 0x800), indexToCpClass3(cpToIndexClass3(0x800)));
    try std.testing.expectEqual(@as(u21, 0xD7FF), indexToCpClass3(cpToIndexClass3(0xD7FF)));
    try std.testing.expectEqual(@as(u21, 0xE000), indexToCpClass3(cpToIndexClass3(0xE000)));
    try std.testing.expectEqual(@as(u21, 0xFFFF), indexToCpClass3(cpToIndexClass3(0xFFFF)));

    // Class 4
    try std.testing.expectEqual(@as(u21, 0x10000), indexToCpClass4(cpToIndexClass4(0x10000)));
    try std.testing.expectEqual(@as(u21, 0x10FFFF), indexToCpClass4(cpToIndexClass4(0x10FFFF)));
}

test "encryption roundtrip ASCII" {
    const allocator = std.testing.allocator;

    const key: [16]u8 = @splat(0x2B);
    var cipher = try Utf8Cipher.init(allocator, &key);
    defer cipher.deinit();

    const plaintext = "Hello, World!";
    const tweak = "test";

    const ciphertext = try cipher.encrypt(plaintext, tweak);
    defer allocator.free(ciphertext);

    // Verify byte length preserved
    try std.testing.expectEqual(plaintext.len, ciphertext.len);

    // Verify valid UTF-8
    try std.testing.expect(std.unicode.utf8ValidateSlice(ciphertext));

    // Decrypt and verify
    const decrypted = try cipher.decrypt(ciphertext, tweak);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "encryption roundtrip multi-byte UTF-8" {
    const allocator = std.testing.allocator;

    const key: [16]u8 = @splat(0x2B);
    var cipher = try Utf8Cipher.init(allocator, &key);
    defer cipher.deinit();

    const plaintext = "Héllo 世界 🌍";
    const tweak = "test";

    const ciphertext = try cipher.encrypt(plaintext, tweak);
    defer allocator.free(ciphertext);

    // Verify byte length preserved
    try std.testing.expectEqual(plaintext.len, ciphertext.len);

    // Verify valid UTF-8
    try std.testing.expect(std.unicode.utf8ValidateSlice(ciphertext));

    // Decrypt and verify
    const decrypted = try cipher.decrypt(ciphertext, tweak);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "tweak buffer overflow error" {
    const allocator = std.testing.allocator;

    const key: [16]u8 = @splat(0x2B);
    var cipher = try Utf8Cipher.init(allocator, &key);
    defer cipher.deinit();

    const plaintext = "Hello";

    // Create a very long tweak that will overflow the buffer when combined with chaining info
    // TWEAK_BUFFER_SIZE is 1024, so a tweak of 1000 bytes should overflow when formatted
    const long_tweak: [1000]u8 = @splat('A');

    // Should return TweakBufferOverflow error
    const result = cipher.encrypt(plaintext, &long_tweak);
    try std.testing.expectError(error.TweakBufferOverflow, result);
}

test "boundary space avoidance" {
    const allocator = std.testing.allocator;

    // Test with many different keys and tweaks to ensure boundary positions
    // never contain spaces in the ciphertext (for class 1 characters)
    var key_byte: u8 = 0;
    while (key_byte < 50) : (key_byte += 1) {
        const key: [16]u8 = @splat(key_byte);
        var cipher = try Utf8Cipher.init(allocator, &key);
        defer cipher.deinit();

        const test_cases = [_][]const u8{
            "Hello World",
            "Test message",
            "A",
            "AB",
            "ABC",
            "x",
            "xy",
            "xyz",
        };

        for (test_cases) |plaintext| {
            const ciphertext = try cipher.encrypt(plaintext, "test-tweak");
            defer allocator.free(ciphertext);

            // Check that ciphertext is valid UTF-8
            try std.testing.expect(std.unicode.utf8ValidateSlice(ciphertext));

            // Check first and last characters
            var view = std.unicode.Utf8View.initUnchecked(ciphertext);
            var it = view.iterator();

            // Get first codepoint
            const first_cp = it.nextCodepoint() orelse continue;

            // Check if first character is class 1 (ASCII)
            const first_class = try Utf8Class.fromCodepoint(first_cp);
            if (first_class == .class1) {
                // First character should not be a space (0x20)
                try std.testing.expect(first_cp != 0x20);
            }

            // Get last codepoint
            var last_cp: u21 = first_cp;
            while (it.nextCodepoint()) |cp| {
                last_cp = cp;
            }

            // Check if last character is class 1 (ASCII)
            const last_class = try Utf8Class.fromCodepoint(last_cp);
            if (last_class == .class1) {
                // Last character should not be a space (0x20)
                try std.testing.expect(last_cp != 0x20);
            }

            // Verify decryption works correctly
            const decrypted = try cipher.decrypt(ciphertext, "test-tweak");
            defer allocator.free(decrypted);

            try std.testing.expectEqualStrings(plaintext, decrypted);
        }
    }
}
