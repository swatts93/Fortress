# Changelog

## [2.0.3] — Second-Pass Audit: iOS/Android Timing Fix + CLI Robustness

### Security

- **Duress timing oracle also present on iOS and Android.** The same
  conditional-derivation pattern fixed in 2.0.2 for the Python reference existed
  identically in `FortressAPI.swift` and `FortressFileAPI.kt` (both ports
  intentionally mirror the reference's control flow). Applied the same fix:
  both keysets are now always derived when duress is enabled, on all three
  platforms. Not independently compiled/tested here (no Xcode/Android SDK in
  this environment) — reviewed by hand for correctness; recommend running the
  existing iOS/Android test targets before the next release.

### Correctness

- **Three CLI commands crashed with a raw Python traceback on bad input.**
  `decrypt`, `info`, and `msg-dec` all read a file/token header before entering
  their `try`/`except` blocks, so a corrupted, truncated, or non-Fortress input
  raised an unhandled `ValueError` instead of the clean `FAILED:`/`Error:`
  message the rest of the CLI uses. All three now wrap the header read and
  report failures consistently.

- **`chunk_size <= 0` raised a bare `ZeroDivisionError`/`struct.error`.**
  `encrypt_file` now validates `chunk_size` is a positive integer up front and
  raises a clear `ValueError`. (Investigated whether this could cause an
  infinite loop/DoS — it can't: the division/struct-pack failures both occur
  before any chunk-writing loop runs. It was a poor error message, not a hang.)
  Added regression tests for both the zero and negative cases.

## [2.0.2] — Duress Timing Side-Channel Fix

### Security

- **Duress-mode timing oracle (Python reference, all platforms share the same
  control flow).** `decrypt_file` derived the duress keyset only after the real
  password's key commitment failed to match, so entering the real password cost
  one Argon2id/scrypt pass while entering the duress password or any wrong
  password cost two. Measured on a `standard`-level file, this was a ~2x wall-clock
  difference (~1.4s vs ~2.8s) — enough for a coercion adversary (THREAT_MODEL.md
  A5) to confirm from response latency alone that a handed-over password was the
  genuine one, before ever inspecting the decrypted output. This undermined the
  duress deniability goal (G6). Fixed by always deriving both keysets when duress
  is enabled, regardless of which one (if any) matches, so response time no longer
  depends on which password was supplied. Added a regression test
  (`test_duress_enabled_always_derives_both_keysets`) that asserts both KDF calls
  always occur. No file-format or on-disk byte change; existing `.fortress` files
  are unaffected.

### Correctness

- **CLI crashed on non-UTF-8 Windows consoles.** The banner, progress bar, and
  status lines use box-drawing and emoji characters (`╔`, `█`, `⛫`, `⚠`, `☠`).
  On a default Windows console (`cp1252`), writing them raised
  `UnicodeEncodeError` and killed the process before any command — including
  `--help` — could run. `fortress/cli.py`'s `main()` now reconfigures
  `stdout`/`stderr` to UTF-8 with `errors="replace"` on entry, so output
  degrades gracefully instead of crashing.

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
