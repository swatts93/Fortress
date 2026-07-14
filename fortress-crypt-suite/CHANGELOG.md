# Changelog

## [2.0.4] — Independent Audit: Header-Forgery and Plaintext-Leak Fixes

An independent audit pass (see `AUDIT_FINDINGS.md`, FC-01 through FC-06) found
and this release fixes six issues in the Python reference core. All fixes
verified with the audit's own regression tests (`test_header_forgery.py`)
plus the full existing suite (69 passed against the shipping build, 59
against the audit fork).

### Security

- **FC-01 (CRITICAL) — forged trap section could destroy any file with zero
  password knowledge.** `decrypt_file()` used to read `trap_count` /
  `trap_salt` / `trap_hashes` off the *unauthenticated* header and act on
  them (including the destructive scramble on mismatch) before ever checking
  the header HMAC. An attacker with one moment of write access to the
  ciphertext could inject a fake trap requirement into a file that never had
  one; the owner's very next ordinary decrypt attempt would demand codes they
  never set, and any attempt to comply destroyed the file permanently — even
  with the correct real password. Fixed: trap fields are now only trusted
  once `verify_header()` has confirmed the header is authentic using the real
  password's `header_auth_key`, which is only possible when the real
  password was supplied. This also means trap enforcement now specifically
  targets its actual purpose ("you have the real password but not the trap
  sequence") rather than gating every decrypt attempt regardless of which
  password will be used.

- **FC-02 (CRITICAL) — forged duress section could destroy real data with
  zero password knowledge.** `_decrypt_duress()` never authenticated the
  header at all (it structurally can't — the header HMAC needs the real
  password, which a duress-password holder never has by design). Because the
  duress commitment check is entirely self-consistent (computed from inputs
  the caller freely chooses), anyone could pick their own password and
  duress salt/nonce, derive a matching commitment locally, splice it into any
  file's header, and trigger the destructive real-data wipe using a password
  only they knew. There is no cryptographic fix that preserves pure
  duress-password-only unlock (verifying authenticity requires the real
  password; anything checkable with just the duress password is equally
  forgeable by an attacker with no relation to either password — this was
  checked exhaustively, see the fix's docstring). Given that, the automatic
  wipe is now level-gated: **standard/high** security levels no longer
  destroy real data automatically on a duress match (call the new
  `destroy_real_data_after_duress()` explicitly if you want it); **paranoid/
  fortress** keep the original automatic, silent behavior. This is a
  deliberate, documented tradeoff, not a complete fix — see AUDIT_FINDINGS.md
  FC-02 and THREAT_MODEL.md for the residual risk at paranoid/fortress
  levels. `decrypt_file()` also takes an explicit
  `destroy_real_on_duress: Optional[bool]` override (and the CLI's `decrypt`
  gets `--destroy-real-on-duress`/`--no-destroy-real-on-duress`) so a caller
  can force either behavior regardless of the file's security level, rather
  than being limited to the level-based default.

- **FC-03 (HIGH) — unverified plaintext could survive a failed decrypt.**
  `_decrypt_real()`/`_decrypt_duress()` wrote decrypted plaintext directly to
  the output path chunk-by-chunk, before the footer chain was checked. A
  truncated or tampered ciphertext (missing footer, missing trailing chunk)
  raised an error but left correctly-decrypted plaintext sitting on disk with
  no cleanup and no warning — a direct contradiction of SPECIFICATION.md's
  own Security Claim #2 ("detected before plaintext is released"). Fixed:
  both functions now decrypt to a temp file and only atomically rename it
  into place (`os.replace`) after full footer verification succeeds; the
  temp file is removed on every exception path.

- **FC-04 (documentation) — `FortressKeys.wipe()` doesn't actually wipe
  memory in CPython.** `bytes` is immutable, so reassigning fields drops
  references without overwriting the original key buffers. Already out of
  scope under the project's own threat model (endpoint compromise, A6), but
  the name/usage pattern implied a guarantee it doesn't deliver. Fixed the
  docstring to say so explicitly rather than changing the (out-of-scope)
  behavior.

- **FC-06 (LOW) — `chmod(0o600)` on the ML-KEM secret-key file is a silent
  no-op on Windows.** POSIX mode bits don't map to NTFS ACLs. Added an
  `icacls`-based restriction (strip inherited ACEs, grant only the current
  user) on Windows; unchanged `chmod` elsewhere.

### Packaging

- **FC-05 (LOW) — license metadata contradicted the actual license.** All
  three `pyproject.toml` files declared `license = {text = "MIT"}` while
  every source header, the top-level `LICENSE`, and `licensing/` establish
  AGPL-3.0-or-later with a commercial dual-licensing program. Corrected to
  `license = {text = "AGPL-3.0-or-later"}`.

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
