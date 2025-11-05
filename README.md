# utf8encrypt

A Zig library for UTF-8 length-preserving encryption that encrypts UTF-8 text while preserving valid UTF-8 encoding and exact byte length.

> ⚠️ EXPERIMENTAL: This library is highly experimental. Do not use in production systems or for protecting sensitive data.

## Features

- Valid UTF-8 Output: Encrypted text is guaranteed to be valid UTF-8
- Byte-Length Preservation: Output has identical byte count as input
- Class Preservation: Each code point stays within its UTF-8 byte-length class (1-4 bytes)
- Control Character Passthrough: ASCII control characters (codes 0-31) are preserved unchanged for structural integrity
- Content-Dependent Permutation: Character class sequence is shuffled based on key and content to hide structural patterns

## Quick Start

```zig
const std = @import("std");
const utf8encrypt = @import("utf8encrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize cipher with 16-byte key
    const key = [_]u8{0x2B}  16;
    var cipher = try utf8encrypt.Utf8Cipher.init(allocator, &key);
    defer cipher.deinit();

    // Encrypt UTF-8 text
    const plaintext = "Hello, World!";
    const tweak = "context:record123:field:name";
    const ciphertext = try cipher.encrypt(plaintext, tweak);
    defer allocator.free(ciphertext);

    std.debug.print("Plaintext:  {s} ({d} bytes)\n", .{ plaintext, plaintext.len });
    std.debug.print("Ciphertext: {s} ({d} bytes)\n", .{ ciphertext, ciphertext.len });

    // Decrypt
    const decrypted = try cipher.decrypt(ciphertext, tweak);
    defer allocator.free(decrypted);

    std.debug.print("Match: {}\n", .{std.mem.eql(u8, plaintext, decrypted)});
}
```

## How It Works

### UTF-8 Byte-Length Classes

The library divides Unicode code points into 4 classes based on UTF-8 byte length:

| Class | Code Point Range   | UTF-8 Bytes | Domain Size | Encryption Method                          |
| ----- | ------------------ | ----------- | ----------- | ------------------------------------------ |
| 1     | U+0000 - U+007F    | 1 byte      | 96          | Fisher-Yates permutation (tweak-dependent) |
| 2     | U+0080 - U+07FF    | 2 bytes     | 1,920       | FAST cipher + cycle walking                |
| 3     | U+0800 - U+FFFF    | 3 bytes     | 61,440      | FAST cipher + cycle walking                |
| 4     | U+10000 - U+10FFFF | 4 bytes     | 1,048,576   | FAST cipher + cycle walking                |

Class 1 control characters (U+0000 - U+001F, codes 0-31) are not encrypted and pass through unchanged. Only printable ASCII (U+0020 - U+007F, codes 32-127) are encrypted.

Class 3 excludes surrogates U+D800 - U+DFFF (invalid in UTF-8)

### Encryption Process

1. Code Point Classification: Each code point is classified into one of the 4 byte-length classes
2. Control Character Passthrough: Class 1 control characters (codes 0-31) are preserved unchanged
3. Domain Mapping: Code points are mapped to domain indices (0..N-1) within their class
4. Format-Preserving Encryption:
   - Class 1 (printable ASCII): Uses Fisher-Yates shuffle with 256-bit seed from TurboSHAKE128
   - Classes 2-4: Uses FAST cipher with cycle walking until result falls within valid domain
5. Chaining: Position-dependent tweaks incorporate previous ciphertext bytes (CBC-like mode)
   - Note: Control characters participate in chaining even though they're not encrypted
6. Content-Dependent Permutation: The order of encrypted code points is shuffled based on:
   - Sorted encrypted code points (for deterministic permutation derivation)
   - Encryption key (for key-dependent permutation)
   - Fisher-Yates shuffle with TurboSHAKE128 as PRNG
7. UTF-8 Encoding: Shuffled encrypted code points are encoded back to UTF-8

This process ensures that:

- Each code point remains within its original byte-length class
- Control characters (newlines, tabs, etc.) are preserved for structural integrity
- Total byte length is preserved
- The sequence of character classes is permuted to hide structural patterns

### Chaining Mode

The library uses a CBC-like chaining mode:

- IV Generation: `IV = TurboSHAKE128(base_tweak)[0..16]`
- Chained Tweaks: `tweak_i = base_tweak || ":pos:" || i || ":chain:" || C_{i-1}` (binary concatenation)
- Identical plaintexts at different positions produce different ciphertexts

## Use Cases

This library is ideal for encrypting UTF-8 text in length-constrained environments:

- Social Network Posts: Encrypt messages while respecting character/byte limits (Twitter, Mastodon, etc.)
- Database Fields: Encrypt VARCHAR/TEXT fields without changing column size requirements
- Filesystem: Encrypt filenames that must be valid UTF-8 and have byte length restrictions
- Protocol Messages: Encrypt fixed-length UTF-8 fields in network protocols
- Legacy Systems: Encrypt data for systems that validate UTF-8 and enforce byte limits

## Security Considerations

### Cryptographic Properties

- Deterministic Encryption: Same plaintext + key + tweak always produces same ciphertext (by design for format-preserving encryption)
- Primitives:
  - Classes 2-4: Use FAST cipher (format-preserving encryption algorithm)
  - Class 1: Uses ChaCha PRNG with 256-bit seeds derived from TurboSHAKE128

### Limitations

- Not IND-CPA Secure: Not probabilistic; not suitable for high-security applications requiring IND-CPA security
- Control Characters Unencrypted: ASCII control characters (codes 0-31 like newlines, tabs, etc.) pass through unencrypted
- Frequency Preservation: Character frequency within each class is preserved (susceptible to frequency analysis within each class)
- Structural Obfuscation: While the sequence of character classes is permuted to hide patterns, the multiset of classes remains the same (e.g., input with 2 ASCII + 1 emoji will produce output with 2 ASCII + 1 emoji, but in different positions)
- No Authentication: Provides confidentiality only; no integrity or authentication guarantees

## Performance

### Encryption Speed by Class

Performance varies by UTF-8 class due to different encryption methods:

- Class 1 (ASCII): ~25% slower than pre-computed tables (Fisher-Yates per code point)
- Class 2: ~34 average cycle-walking iterations
- Class 3: ~1.03 average cycle-walking iterations
- Class 4: ~16 average cycle-walking iterations

## Sample Output

Here are examples showing actual input text and encrypted output:

### ASCII Text

```
Plaintext:  Hello, World! (13 bytes)
Ciphertext: L;ba>{AeiWr (13 bytes)
```

The encrypted text maintains the exact byte length and remains valid UTF-8, but the content is transformed.

### Multi-Byte UTF-8 (Latin + Chinese)

```
Plaintext:  Héllo 世界 (13 bytes)
Ciphertext: LȦ.O@䧵 (13 bytes)
```

Characters from different UTF-8 classes are encrypted while preserving their byte-length classes. The Chinese characters (3 bytes each) remain 3-byte UTF-8 characters in the output. Note that the order of character classes may be permuted in the encrypted output.

### Emoji (4-Byte UTF-8)

```
Plaintext:  🌍 emoji test 🚀 (20 bytes)
Ciphertext: 񃻸RhufBh]E񄃂 (20 bytes)
```

Emojis are 4-byte UTF-8 sequences that encrypt to other 4-byte UTF-8 sequences, maintaining the byte structure. The permutation may reorder ASCII and emoji characters while preserving the total byte count.

### Accented Characters

```
Plaintext:  Café résumé naïve (21 bytes)
Ciphertext: ~Ԟtݛ]0و>tM¸+ (21 bytes)
```

Latin characters with diacritics (é, ï) are 2-byte UTF-8 sequences that encrypt to other 2-byte sequences. Each character stays within its byte-length class, but the class sequence may be reordered.

Note: The encrypted output shown above is deterministic for a given key and tweak. Different keys, tweaks, or positions will produce different ciphertexts.

## Examples

### Basic Encryption/Decryption

```zig
const cipher = try Utf8Cipher.init(allocator, &key);
defer cipher.deinit();

const ciphertext = try cipher.encrypt("Hello, World!", "myapp:user123:field:message");
defer allocator.free(ciphertext);

const plaintext = try cipher.decrypt(ciphertext, "myapp:user123:field:message");
defer allocator.free(plaintext);
```

### Unique Tweaks for Different Contexts

```zig
// Different tweaks for different contexts prevent cross-context attacks
const email_encrypted = try cipher.encrypt(user_email, "app:users:email");
defer allocator.free(email_encrypted);

const phone_encrypted = try cipher.encrypt(user_phone, "app:users:phone");
defer allocator.free(phone_encrypted);
```

### Multi-Byte UTF-8

```zig
const multilingual = "Hello 世界 مرحبا";
const encrypted = try cipher.encrypt(multilingual, "demo");
defer allocator.free(encrypted);

// Byte length preserved
std.debug.assert(encrypted.len == multilingual.len);

// Valid UTF-8 preserved
std.debug.assert(std.unicode.utf8ValidateSlice(encrypted));
```

### Class Sequence Permutation Demo

```zig
// Example showing how class sequences are permuted
const plaintext = "AB世";  // Classes: [ASCII, ASCII, 3-byte]
const ciphertext = try cipher.encrypt(plaintext, "test");
defer allocator.free(ciphertext);

// Ciphertext has SAME multiset of classes but DIFFERENT order
// For example, might produce: [3-byte, ASCII, ASCII]
// Total byte length: 5 bytes (unchanged)
// Each character stayed in its class (ASCII→ASCII, 3-byte→3-byte)
// But the ORDER was permuted based on content and key
```
