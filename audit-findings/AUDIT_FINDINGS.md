# Fortress Crypt — Independent Audit Findings Log

Scope: `core-python` / `core-python-audit` (the normative reference implementation,
per SPECIFICATION.md §0 — "iOS and Android are ports and MUST match its byte-level
behavior"). Android/iOS ports are out of scope per project owner's direction.
Windows and Linux both run this same Python core via the `fortress` CLI, so every
finding here applies identically to both target platforms.

Status legend: OPEN (confirmed, unfixed) / FIXED (patched + regression test added
and passing) / MITIGATED (residual risk documented, not cryptographically closed) /
WONTFIX (documented, accepted risk).

All PoCs referenced below were executed against `audit-package/core-python`
(shipping/destructive build) or `audit-package/core-python-audit` (non-destructive
fork) in a scratch directory outside the repo. None of the destructive PoCs were
run against real user data.

All fixes described here landed on `main` in commit `c3c501c` (2026-07-14). See
`REGISTER.md` in this folder for the at-a-glance table.

---

## FC-01 — CRITICAL — Trap-check reads unauthenticated header fields before any password/HMAC verification → zero-cost forged trap injection permanently destroys any file

**File:** `fortress/api.py`, `decrypt_file()`, `verify_trap_sequence()`
**Also present in:** shipping `core-python` and both `audit-package` copies (identical files)

`decrypt_file()` called `read_header_raw(f)` (format.py) to get `raw_header` — this
function performs **zero HMAC verification**, it just parses bytes off disk. That
raw, unauthenticated header was used directly to decide whether trap codes are
required and, if supplied, to run `verify_trap_sequence()`, which on any mismatch
calls `scramble_header()` — an unconditional, irreversible overwrite of the
header's real `salt`, `nonce_seed`, and `key_commitment` at fixed absolute offsets.

Because `trap_count` / `trap_salt` / `trap_hashes` were read and acted on **before**
`verify_header()` was ever called, an attacker with one moment of write access to
the ciphertext file could:

1. Parse the existing header (public operation, no secrets needed).
2. Re-serialize it with `trap_count=1`, `trap_salt=<anything>`,
   `trap_hashes=[<anything>]` — literally arbitrary bytes, no KDF, no hashing
   tied to a real code.
3. Splice the new header + the **original** (now-mismatching, but never checked
   at this stage) header HMAC + the untouched rest of the file back together.

The owner's very next ordinary decrypt attempt (no code changes needed on their
side) would see "This file requires 1 trap code(s)" — something they never
configured. If they made *any* attempt to comply (a guess, a support-ticket
suggestion, an automated retry with a placeholder), the mismatch fired
`scramble_header()` and the file was permanently unrecoverable, **even with the
correct real password**, and the attacker never needed to know it.

### Proof of concept (verified, output below)

```
[victim] encrypted, NO traps configured at all
[attacker] injected a fake trap_count=1 with a random, unsatisfiable trap_hash.
[attacker] did ZERO KDF/crypto computation. did not touch key_commitment or any ciphertext.

=== Owner's FIRST decrypt attempt (no trap_codes, as always) ===
raised: ValueError - This file requires 1 trap code(s). Provide them via trap_codes parameter.

=== Owner, confused, tries to comply and supplies SOME guess ===
raised: TrapTriggered - Trap code #1 INCORRECT. FILE HAS BEEN PERMANENTLY DESTROYED.

=== AFTERMATH: does the owner's REAL password still work at all? ===
Owner's real password now FAILS PERMANENTLY: ValueError - This file requires 1 trap code(s)...
```

This was the single most severe and least effortful finding in the audit: no
cryptography broken, no password guessed, and the trigger condition (owner
makes one attempt to comply with a prompt they don't understand) highly likely
in practice, not a contrived edge case.

**Root cause:** header authenticity was checked far too late in the control flow.
Anything read via `read_header_raw()` and acted upon before `verify_header()` runs
is an attacker-controlled input.

### Status: FIXED (2026-07-14, commit `c3c501c`)

`decrypt_file()` now always derives `real_keys` and attempts `verify_header()`
with them *before* looking at `trap_count`/`trap_salt`/`trap_hashes`. The
destructive branch of `verify_trap_sequence()` (shipping: `scramble_header()`;
audit fork: raising `TrapVerificationError` from unauthenticated data) is now
only reached once the header is proven authentic — which requires the entered
password to genuinely be the real one, since the header is only ever signed
with the real `header_auth_key`. If the header verifies but the trap check
still fails, an untampered file with a genuinely wrong trap code still
destroys as originally designed. If the entered password is not real (wrong
guess, or a legitimate duress password) or the header fails verification, no
destructive action fires — the caller sees a plain rejection instead.

Trade-off, accepted: if a file has both traps and duress configured, and
someone who knows only the (legitimate) duress password enters wrong/no trap
codes, the trap section no longer destroys the header on that attempt
(previously it did). Intentional — the alternative was leaving the zero-cost
forgery open.

Regression test: `audit-package/tests/test_header_forgery.py::test_trap_injection_cannot_be_forged`.

---

## FC-02 — CRITICAL — Duress-decrypt path never authenticates the header → forged, self-consistent duress section triggers unauthenticated permanent destruction of real data

**File:** `fortress/api.py`, `_decrypt_duress()` (comment acknowledged the gap:
"We can't verify the main header HMAC with duress keys... so we skip header
auth for duress mode.")

Unlike `_decrypt_real()` (which calls `verify_header()`), `_decrypt_duress()`
never authenticated the header. Every duress-related field — `duress_enabled`,
`duress_salt`, `duress_nonce_seed`, `duress_key_commitment`, `duress_data_size`,
`duress_chunk_count` — was unauthenticated on this path. Because the commitment
check is self-consistent by construction (`commitment = SHA3-512(keys derived
from salt + nonce_seed + password)`), an attacker who never learns any real or
duress password could:

1. Choose an arbitrary password of their own.
2. Choose arbitrary `duress_salt` / `duress_nonce_seed`.
3. Run Fortress's own public, deterministic KDF locally to get a matching
   `duress_key_commitment`.
4. Splice `(duress_enabled=1, duress_salt, duress_nonce_seed,
   duress_key_commitment, duress_data_size=0, duress_chunk_count=0)` into
   *any* file's header (even one that never had duress configured).
5. Patch 32 bytes at the position where the "0-chunk duress footer" is
   expected, to a value only they can precompute (a function of their own
   derived `footer_auth_key`).
6. Call `decrypt_file()` with their own chosen password.

This was accepted as valid "duress" entry and triggered
`scramble_real_data_section()`, which unconditionally overwrote the real
`key_commitment` — permanently destroying real-password recoverability.

### Proof of concept (verified, output below)

```
[victim] encrypted file, real password only, duress NOT configured
[attacker] attacker does NOT know: 'the-owners-real-password'
[attacker] decrypt_file(password=attacker's own chosen password) SUCCEEDED:
    {'chunks': 0, 'mode': 'decrypted', 'verified': True, 'duress': True}

Owner's real password decrypt now FAILS: ValueError - KEY COMMITMENT MISMATCH - wrong password
```

**Why the FC-01 fix technique does not transfer here:** FC-01's fix works
because the *legitimate, intended* trigger for trap destruction always
coincides with the real password being used. Gating on header authenticity
(which requires the real password) costs nothing in the legitimate case.
Duress is the opposite by definition: its legitimate trigger is *precisely*
the case where the real password is *not* being used, so header authenticity
can never be true on a genuine duress decrypt. Every symmetric-crypto scheme
considered (a second HMAC keyed by a duress-derived sub-key, an
envelope-wrapped shared secret, a canary AEAD block) reduces to "attacker
computes the public deterministic function themselves with self-chosen
inputs," because none of it depends on anything the attacker doesn't already
control. The only secret anywhere in this system unavailable to an attacker
with no password knowledge is the real password itself — and the duress
branch cannot depend on that without collapsing into "only the real password
can trigger duress," which defeats the point of a duress password.

**Conclusion:** this cannot be closed as a pure implementation bug in the
current (v2) format/trust model. There is no cryptographic fix that preserves
pure duress-password-only unlock.

### Status: MITIGATED — product-level decision made by the project owner (2026-07-14, commit `c3c501c`)

Given no cryptographic fix exists, the automatic real-data wipe is now
level-gated: **standard/high** security levels no longer destroy real data
automatically on a duress match; **paranoid/fortress** keep the original
automatic, silent behavior (an accepted residual risk at those levels,
documented in THREAT_MODEL.md §5). A new `destroy_real_data_after_duress()`
function lets standard/high callers opt into the wipe explicitly. `decrypt_file()`
additionally takes an explicit `destroy_real_on_duress: Optional[bool]`
override (and the CLI a matching `--destroy-real-on-duress` /
`--no-destroy-real-on-duress` flag) so a caller can force either behavior
regardless of the file's security level.

This does not make forged duress sections cryptographically detectable — an
attacker who forges a duress section against a paranoid/fortress-level file,
or who explicitly requests the wipe via the override on any level, can still
complete the destructive attack demonstrated in the PoC. This is a real,
documented residual limitation, not a resolved finding — see THREAT_MODEL.md
§5 for the precise, current claim.

Regression tests: `audit-package/tests/test_header_forgery.py::test_duress_section_cannot_be_forged`,
plus `audit-package/tests/test_traps_duress.py::test_duress_standard_level_does_not_auto_wipe_real`,
`test_duress_paranoid_level_auto_wipes_real`,
`test_destroy_real_data_after_duress_explicit_opt_in`,
`test_destroy_real_on_duress_override_forces_wipe_at_standard_level`,
`test_destroy_real_on_duress_override_prevents_wipe_at_paranoid_level`.

---

## FC-03 — HIGH — Plaintext was written to disk (and left there, uncleaned, in some failure modes) before the footer integrity check ran

**File:** `fortress/api.py`, `_decrypt_real()`, `_decrypt_duress()`

Both functions decrypted and wrote plaintext chunk-by-chunk *inside* the loop,
then checked the footer chain (`read_footer()` + `_footer_hmac()` comparison)
**after** all writes were flushed and the output file closed. The footer chain
only requires ciphertext (not plaintext), so it could have been verified
first — it just wasn't.

Two distinct failure paths existed and only one had cleanup:

- Footer bytes present but wrong value → caught, `os.unlink(output_path)` ran.
- Footer bytes **missing** (`read_footer()` raises `"Missing footer HMAC"`) or a
  trailing chunk missing entirely (`"Unexpected EOF at chunk N"`) → raised
  before/outside the unlink logic — **no cleanup at all.**

### Proof of concept (verified, output below — 3-chunk file, last chunk +
footer truncated off)

```
decrypt_file raised (expected): ValueError Unexpected EOF at chunk 2

OUTPUT FILE LEFT ON DISK: ...secret2.out size: 1200
chunk-0 marker present: True
chunk-1 marker present: True
chunk-2 marker present (should be MISSING, it was truncated): False
```

Two full chunks of correctly-decrypted plaintext were left permanently on disk
after a *reported failure*, with no indication to the user that anything was
written. This directly contradicted SPECIFICATION.md's Security Claim #2 ("any
modification of ciphertext, header, or chunk order is detected **before
plaintext is released**").

### Status: FIXED (2026-07-14, commit `c3c501c`)

Both functions now decrypt to a temp file (`<output>.fortress-tmp`) and only
atomically rename it into place (`os.replace`) once the footer chain has
fully verified; the temp file is removed on every exception path (`except
BaseException`), not just the "footer value mismatch" case.

Regression test: `audit-package/tests/test_header_forgery.py::test_truncated_file_leaves_no_plaintext_on_disk`.

---

## FC-04 — MEDIUM — `FortressKeys.wipe()` does not actually wipe key material in CPython

**File:** `fortress/keys.py`

`wipe()` reassigns each dataclass field to a new zero-filled `bytes` object.
`bytes` is immutable in CPython; the *original* key material returned by
`hash_secret_raw` / `HKDF.derive()` / `Scrypt.derive()` is a separate object
that this call does not touch — only one reference to it is dropped. This
provides no real protection against memory disclosure.

Explicitly out of scope under the project's own threat model (A6, endpoint
compromise, THREAT_MODEL.md §4) — so this isn't a violation of a stated
guarantee. It's flagged because the function's name and its use in `finally:`
blocks throughout `api.py` implies a security property it does not deliver.

### Status: FIXED — documentation (2026-07-14, commit `c3c501c`)

`wipe()`'s docstring now states explicitly that this is best-effort reference-
dropping, not a memory-safety guarantee, and explains why (CPython `bytes`
immutability) and what a real fix would require (mutable `bytearray` buffers
plus OS-level protections). Behavior unchanged — this is a scope decision, not
a functional gap, since real memory-safety guarantees are out of scope.

---

## FC-05 — LOW — Package license metadata contradicted actual license

**Files:** `fortress-crypt-suite/core-python/pyproject.toml`,
`audit-package/core-python/pyproject.toml`, `audit-package/core-python-audit/pyproject.toml`

All three declared `license = {text = "MIT"}`. Every source file header, the
top-level `LICENSE` (full AGPLv3 text), and the entire `licensing/` directory
(CLA, dual-licensing docs) establish AGPL-3.0-or-later with a commercial
dual-licensing program. `pip show fortress-crypt` / PyPI metadata would tell
installers "MIT", misrepresenting real copyleft obligations.

### Status: FIXED (2026-07-14, commit `c3c501c`)

All three corrected to `license = {text = "AGPL-3.0-or-later"}`.

---

## FC-06 — LOW — `pq.save_keypair`'s `chmod(0o600)` was a silent no-op on Windows

**File:** `fortress/pq.py`

POSIX mode bits don't map onto NTFS ACLs; on Windows the `try/except OSError`
either did nothing or silently "succeeded" without actually restricting other
local accounts from reading the ML-KEM-1024 secret-key JSON file. Not
exploitable without local access already, but worth fixing since Windows is a
primary target platform.

### Status: FIXED (2026-07-14, commit `c3c501c`)

Added `_restrict_to_current_user()`: on Windows, uses `icacls` to strip
inherited ACEs and grant Full Control only to the current user; unchanged
`chmod(0o600)` elsewhere. No regression test (platform ACL behavior isn't
practical to assert in the existing pytest suite without a Windows-specific
ACL-reading test) — verified manually that the `icacls` invocation succeeds
and restricts access as expected.

---

## Findings NOT filed (checked, found to be already correctly handled or already documented by the project's own spec)

- Footer using prefix-keyed SHA3-256 instead of HMAC/KMAC — SPEC §7.3 already
  flags this; the sponge-construction argument against length-extension holds.
- XOR KDF combiner non-independence — SPEC §4 already flags this correctly.
- AEAD layers not binding chunk index as associated data — SPEC §5.4 flags this;
  verified that per-chunk nonce derivation from `(nonce_seed, chunk_idx, pass)`
  already defeats naive splicing/reordering across chunks or files at the AEAD
  layer (different position → different nonce → tag fails) — the *actual* gap
  this note was fishing for turned out to be FC-03 (truncation succeeds because
  verification is deferred past the point plaintext is released), which was
  filed separately with a working PoC.
- Key commitment excludes `padding_key`/`nonce_seed` — reviewed per
  THREAT_MODEL.md §7 Q4; `nonce_seed` is public/random and independent of
  password, its exclusion does not create a practical partitioning oracle given
  the commitment already binds all cipher/MAC keys derived from `master`.
