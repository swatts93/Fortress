# Changelog

## [2.0.1] — Code Audit Fixes

This release addresses issues found in a code review pass across all three
implementations. **The `.fortress` binary format is unchanged** — files
encrypted with 2.0.0 remain fully compatible.

### Security

- **Constant-time comparisons (iOS + Android).** Key-commitment checks, trap-code
  verification, and footer/HMAC authentication tags previously used ordinary
  equality (`==` / `contentEquals`), which can leak information through timing.
  All now use constant-time comparison:
  - iOS: new `FortressKeyDerivation.constantTimeEquals` (XOR-accumulate over all bytes).
  - Android: new `FortressKeyDerivation.constantTimeEquals` wrapping
    `MessageDigest.isEqual`.
  - Python reference already used `hmac.compare_digest`; unchanged.

- **No plaintext to disk during message decryption (iOS).** Message parsing
  previously wrote the encrypted buffer to a temporary file via a `FileHandle`
  convenience initializer. Replaced with an in-memory `ByteReader` protocol and
  `DataByteReader`, so decrypted message material never touches persistent storage.

### Correctness

- **Android minSdk compatibility.** Replaced single-argument `readNBytes(int)`
  calls (which require API 33+) with `skipFully`/`readExactly` helpers built on
  `readFully`, restoring compatibility with the declared `minSdk = 28`.

- **Android `SecureRandom.nextBytes` misuse.** `scrambleRealData` called a
  non-existent three-argument `nextBytes(buf, 0, 64)` overload that would not
  compile. Rewritten to fill a correctly sized buffer.

- **Android `scrambleRealData` rewrite.** The duress data-wipe routine opened the
  file three times and computed offsets fragilely (one pass did no useful work).
  Rewritten to a single parse pass with an explicit, verified header-offset
  constant (key commitment at byte 111, salt at byte 35 — both confirmed against
  the serialized layout).

### Code quality

- **Cleaner XOR combine (iOS).** Phase-1/phase-2 key XOR now uses a `zip` idiom
  instead of an index loop.

- **Added top-level suite README and this changelog.**

---

## [2.0.0] — Traps & Duress

- Added trap sequence: 1–5 ordered codes; a wrong entry overwrites the header
  salt, nonce seed, and key commitment, destroying the file.
- Added duress mode: a secondary password decrypts decoy data and silently
  overwrites the real data section.
- Doubled the cascade from 3 layers to 6 (two independent passes).
- Upgraded KDF to a triple chain: Argon2id → scrypt → HKDF-SHA512.
- Added key commitment (SHA3-512) and dual-hash-family authentication.
- Shipped native iOS (Swift) and Android (Kotlin) apps.

## [1.0.0] — Initial release

- 3-layer cascade (Camellia → ChaCha20 → AES).
- Argon2id key derivation.
- ML-KEM-1024 post-quantum hybrid mode.
- Streaming support for large files.
- Python library + CLI.
