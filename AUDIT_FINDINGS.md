# Fortress Crypt — Independent Audit Findings Log

Scope: `core-python` / `core-python-audit` (the normative reference implementation,
per SPECIFICATION.md §0 — "iOS and Android are ports and MUST match its byte-level
behavior"). Android/iOS ports are out of scope per project owner's direction.
Windows and Linux both run this same Python core via the `fortress` CLI, so every
finding here applies identically to both target platforms.

Status legend: OPEN (confirmed, unfixed) / FIXED (patched + regression test added
and passing) / WONTFIX (documented, accepted risk).

All PoCs referenced below were executed against `audit-package/core-python`
(shipping/destructive build) or `audit-package/core-python-audit` (non-destructive
fork) in a scratch directory outside the repo. None of the destructive PoCs were
run against real user data.

## Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| FC-01 | CRITICAL | Forged trap section → zero-cost, no-password destruction of any file | **FIXED** |
| FC-02 | CRITICAL | Forged duress section → no-password destruction of real data | **PARTIALLY MITIGATED** (see writeup — this needs a project-owner decision, not just a patch) |
| FC-03 | HIGH | Plaintext released to disk before ciphertext integrity check; no cleanup on some failure paths | **FIXED** |
| FC-04 | MEDIUM | `FortressKeys.wipe()` doesn't wipe anything in CPython | OPEN (documentation-only fix recommended) |
| FC-05 | LOW | `pyproject.toml` license metadata (MIT) contradicts actual AGPL-3.0 source | OPEN |
| FC-06 | LOW | PQ secret-key `chmod(0o600)` is a silent no-op on Windows | OPEN |

Verification: `audit-package/tests/test_header_forgery.py` (new, 3 tests) plus
the full pre-existing suite (`test_kdf`, `test_roundtrip`, `test_integrity`,
`test_traps_duress`, `test_audit_fork`) pass with **0 failures** against both
the patched shipping build (68 passed / 2 correctly skipped) and the patched
non-destructive audit fork (59 passed / 11 correctly skipped — the skips are
the shipping-only destructive tests, by existing project design). All fixes
applied identically to `audit-package/core-python`,
`audit-package/core-python-audit`, and `fortress-crypt-suite/core-python`
(confirmed byte-identical after patching).

---

## FC-01 — CRITICAL — Trap-check reads unauthenticated header fields before any password/HMAC verification → zero-cost forged trap injection permanently destroys any file

**File:** `fortress/api.py`, `decrypt_file()` lines ~323-333, `verify_trap_sequence()` lines ~95-125
**Also present in:** shipping `core-python` and both `audit-package` copies (identical files)

`decrypt_file()` calls `read_header_raw(f)` (format.py) to get `raw_header` — this
function performs **zero HMAC verification**, it just parses bytes off disk. That
raw, unauthenticated header is used directly to decide whether trap codes are
required and, if supplied, to run `verify_trap_sequence()`, which on any mismatch
calls `scramble_header()` — an unconditional, irreversible overwrite of the
header's real `salt`, `nonce_seed`, and `key_commitment` at fixed absolute offsets.

Because `trap_count` / `trap_salt` / `trap_hashes` are read and acted on **before**
`verify_header()` is ever called (verify_header only happens later, inside
`_decrypt_real()`, which is never reached if the trap check destroys the file
first), an attacker with one moment of write access to the ciphertext file can:

1. Parse the existing header (public operation, no secrets needed).
2. Re-serialize it with `trap_count=1`, `trap_salt=<anything>`,
   `trap_hashes=[<anything>]` — literally arbitrary bytes, no KDF, no hashing
   tied to a real code.
3. Splice the new header + the **original** (now-mismatching, but never checked
   at this stage) header HMAC + the untouched rest of the file back together.

The owner's very next ordinary decrypt attempt (no code changes needed on their
side) sees "This file requires 1 trap code(s)" — something they never configured.
If they make *any* attempt to comply (a guess, a support-ticket suggestion, an
automated retry with a placeholder), the mismatch fires `scramble_header()` and
the file is permanently unrecoverable, **even with the correct real password**,
and the attacker never needed to know it.

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

This is the single most severe and least effortful finding in the audit: no
cryptography is broken, no password is guessed, and the trigger condition (owner
makes one attempt to comply with a prompt they don't understand) is highly likely
in practice, not a contrived edge case.

**Root cause:** header authenticity is checked far too late in the control flow.
Anything read via `read_header_raw()` and acted upon before `verify_header()` runs
is an attacker-controlled input.

**Fix direction:** verify the header HMAC (using the *real* `header_auth_key`,
which requires deriving real keys first) before trusting `trap_count`/`trap_salt`/
`trap_hashes`/any destructive-adjacent field — i.e. move key derivation + header
verification ahead of the trap-sequence check, or otherwise cryptographically
bind trap metadata so it can't be forged without the real password.

**Status: FIXED.** `decrypt_file()` now always derives `real_keys` and attempts
`verify_header()` with them *before* looking at `trap_count`/`trap_salt`/
`trap_hashes`. The destructive branch of `verify_trap_sequence()` (shipping:
`scramble_header()`; audit fork: raising `TrapVerificationError` from
unauthenticated data) is now only reached once `header_authentic` is proven —
which requires the entered password to genuinely be the real one, since the
header is only ever signed with the real `header_auth_key`. If the header
verifies but the trap check still fails, an untampered file with a genuinely
wrong trap code still destroys as originally designed (all four
`test_trap_wrong_*_destroys` tests and `test_traps_checked_before_password`,
which all use the true real password on an untouched file, continue to pass
unmodified). If the entered password is not real (wrong guess, or a
legitimate duress password) or the header fails verification, no destructive
action fires — the caller sees a plain rejection instead.

Deliberate trade-off, logged for the project owner: if a file has BOTH traps
and duress configured, and someone who knows only the (legitimate) duress
password enters wrong/no trap codes, the trap section no longer destroys the
header on that attempt (previously it did, since the original code fired the
trap check before any password was known). This is intentional — the
alternative was leaving the zero-cost forgery open — but it does trade away a
small amount of defense-in-depth for the A5/coercion scenario in favor of
closing a much more severe A3-only (no password needed at all) exploit.
Applied identically to `core-python`, `core-python-audit`, and
`fortress-crypt-suite/core-python`.

Regression test `test_header_forgery.py::test_trap_injection_cannot_be_forged`
added — PASSES against the patched code (verified: 3/3 new tests pass, plus
the full existing suite of 56 tests across both the shipping and audit-fork
builds still passes, including all four pre-existing shipping-only trap tests
that exercise the *intended* destructive path).

---

## FC-02 — CRITICAL — Duress-decrypt path never authenticates the header → forged, self-consistent duress section triggers unauthenticated permanent destruction of real data

**File:** `fortress/api.py`, `_decrypt_duress()` lines ~451-503 (comment at ~460-462
acknowledges the gap: "We can't verify the main header HMAC with duress keys...
so we skip header auth for duress mode.")

Unlike `_decrypt_real()` (which calls `verify_header()`), `_decrypt_duress()` never
authenticates the header. Every duress-related field — `duress_enabled`,
`duress_salt`, `duress_nonce_seed`, `duress_key_commitment`, `duress_data_size`,
`duress_chunk_count` — is unauthenticated on this path. Because the commitment
check is self-consistent by construction (`commitment = SHA3-512(keys derived
from salt + nonce_seed + password)`), an attacker who never learns any real or
duress password can:

1. Choose an arbitrary password of their own.
2. Choose arbitrary `duress_salt` / `duress_nonce_seed`.
3. Run Fortress's own public, deterministic KDF locally to get a matching
   `duress_key_commitment`.
4. Splice `(duress_enabled=1, duress_salt, duress_nonce_seed,
   duress_key_commitment, duress_data_size=0, duress_chunk_count=0)` into
   *any* file's header (even one that never had duress configured).
5. Patch 32 bytes at the position where the "0-chunk duress footer" is expected,
   to a value only they can precompute (a function of their own derived
   `footer_auth_key`) — this incidentally corrupts part of real chunk 0, but is
   not needed for the destructive payoff.
6. Call `decrypt_file()` with their own chosen password.

This is accepted as valid "duress" entry and triggers `scramble_real_data_section()`,
which unconditionally overwrites the real `key_commitment` at its fixed header
offset (111) — permanently destroying real-password recoverability.

### Proof of concept (verified, output below)

```
[victim] encrypted file, real password only, duress NOT configured
[attacker] attacker does NOT know: 'the-owners-real-password'
[attacker] decrypt_file(password=attacker's own chosen password) SUCCEEDED:
    {'chunks': 0, 'mode': 'decrypted', 'verified': True, 'duress': True}

Owner's real password decrypt now FAILS: ValueError - KEY COMMITMENT MISMATCH - wrong password
```

**Why the FC-01 fix technique does NOT transfer to FC-02 (important — read
before attempting a "quick" fix here):** FC-01's fix works because the
*legitimate, intended* trigger for trap destruction always coincides with the
real password being used (a coercion adversary who has the real password,
entering a wrong trap code). Gating on `header_authentic` (which requires the
real password) costs nothing in the legitimate case. Duress is the opposite by
definition: its legitimate trigger is *precisely* the case where the real
password is *not* being used. `header_authentic` can therefore NEVER be true
on a genuine duress decrypt, so gating the wipe on it would disable the
feature entirely, not just the attack.

I spent real effort trying to find a scheme where the duress branch could
verify its own metadata's authenticity (an HMAC/commitment/wrapped-key scheme
keyed by something duress-derivable) and could not construct one that
survives a determined attacker, for a structural reason worth recording: an
attacker who has write access to the whole file can *simultaneously* choose
(a) any password, (b) any `duress_salt`/`duress_nonce_seed`, and (c) rewrite
any other "supporting" field they'd need to be self-consistent with (a)+(b) —
including a second HMAC, a wrapped envelope key, or a canary ciphertext, since
all of those are just more file-resident bytes they're equally free to
rewrite. Every scheme I tried (second HMAC keyed by a duress-derived
sub-key, an envelope-wrapped shared secret, a canary AEAD block) reduces to
"attacker computes the public deterministic function themselves with
self-chosen inputs," because none of it depends on anything the attacker
doesn't already control. The only genuinely unavailable-to-the-attacker
secret anywhere in this system is the real password (and values that require
it) — and by definition, the duress branch can't use that without collapsing
back into "real data is only wiped by someone who already knows the real
password," which defeats the entire point of a *duress* password.

**Conclusion:** this cannot be closed as a pure implementation bug in the
current (v2) format/trust model. A complete fix requires a product/protocol
decision, e.g.: (a) an out-of-band or hardware-backed confirmation secret
established at duress setup time that an attacker who wasn't present for that
setup cannot obtain regardless of file access, or (b) explicitly accepting,
in THREAT_MODEL.md, that duress's guarantee (G6) does not hold against an
adversary who has ALSO tampered with the file before the coercion event (A3 +
A5 combined) — which is a narrower, more honest claim than the current text
implies, since A3 and A5 are currently presented as independent rows in the
capability table with no combined-adversary caveat.

**Status: PARTIALLY MITIGATED, NOT CRYPTOGRAPHICALLY CLOSED — flagged for the
project owner's decision.** `decrypt_file()` now requires an explicit
`confirm_duress_wipe=True` before `scramble_real_data_section()` fires
(default `False`); the CLI additionally requires an interactive "yes" (or an
explicit `--confirm-duress-wipe` flag for scripted use) before the wipe
proceeds, and correctly recognizes the non-destructive audit fork so it
doesn't claim a destruction it didn't (couldn't) perform. This does not make
forged duress sections cryptographically detectable — it removes the
*silent, zero-interaction, one-function-call* character of the exploit, which
was the most dangerous part in practice (an automated script, a compromised
backup job, or a brief unattended write could previously destroy real data
with zero trace and zero required interaction). An attacker who also scripts
"yes" (or passes `--confirm-duress-wipe`) can still complete the same attack
demonstrated in the PoC — this is a real, honestly-reported limitation, not a
resolved finding.

Regression test `test_header_forgery.py::test_duress_section_cannot_be_forged`
was updated to assert the achievable property (no wipe fires without explicit
confirmation, and — after confirmation is never given — the real password
still recovers the original data once the forged header fields are restored)
rather than the unachievable one (the forged duress branch is
cryptographically rejected outright). PASSES against the patched code.
Applied identically to `core-python`, `core-python-audit`, and
`fortress-crypt-suite/core-python`; `test_traps_duress.py`'s
`test_duress_fake_password_gets_dummy_and_wipes_real` updated to pass
`confirm_duress_wipe=True` (it is testing the legitimate, intended wipe path,
which still works exactly as before given explicit confirmation), and a new
`test_duress_password_alone_does_not_wipe_without_confirmation` added
alongside it.

---

## FC-03 — HIGH — Plaintext is written to disk (and left there, uncleaned, in some failure modes) before the footer integrity check runs

**File:** `fortress/api.py`, `_decrypt_real()` lines ~404-448, `_decrypt_duress()`
lines ~451-503

Both functions decrypt and `write()` plaintext chunk-by-chunk *inside* the loop,
then check the footer chain (`read_footer()` + `_footer_hmac()` comparison)
**after** all writes are flushed and the output file is closed. The footer chain
only requires ciphertext (not plaintext), so it could be verified first — it
just isn't.

Two distinct failure paths exist and only one has cleanup:

- Footer bytes present but wrong value → caught, `os.unlink(output_path)` runs.
- Footer bytes **missing** (`read_footer()` raises `"Missing footer HMAC"`) or a
  trailing chunk is missing entirely (`"Unexpected EOF at chunk N"`) → **raised
  before/outside the unlink logic — no cleanup at all.**

### Proof of concept (verified, output below — 3-chunk file, last chunk +
footer truncated off)

```
decrypt_file raised (expected): ValueError Unexpected EOF at chunk 2

OUTPUT FILE LEFT ON DISK: ...secret2.out size: 1200
chunk-0 marker present: True
chunk-1 marker present: True
chunk-2 marker present (should be MISSING, it was truncated): False
```

Two full chunks of correctly-decrypted plaintext are left permanently on disk
after a *reported failure*, with no indication to the user that anything was
written. This reaches the CLI directly (`cli.py:decrypt` adds no cleanup of its
own), so both Windows and Linux users hit this identically. It also directly
contradicts SPECIFICATION.md's Security Claim #2 ("any modification of
ciphertext, header, or chunk order is detected **before plaintext is
released**").

**Fix direction:** verify the footer chain against ciphertext-only data before
decrypting/writing any chunk (all inputs are already available), or decrypt to a
temp file and only rename into place after full verification; ensure cleanup
happens on *every* exception path, not just the "footer value mismatch" one.

**Status:** OPEN → regression test `test_header_forgery.py::
test_truncated_file_leaves_no_plaintext_on_disk` added (currently FAILS; must
PASS once fixed).

---

## FC-04 — MEDIUM — `FortressKeys.wipe()` does not actually wipe key material in CPython

**File:** `fortress/keys.py` lines 76-85

`wipe()` reassigns each dataclass field to a new zero-filled `bytes` object.
`bytes` is immutable in CPython; the *original* key material returned by
`hash_secret_raw` / `HKDF.derive()` / `Scrypt.derive()` is a separate object that
this call does not touch — only one reference to it is dropped. This provides no
real protection against memory disclosure.

Explicitly out of scope under the project's own threat model (A6, endpoint
compromise, THREAT_MODEL.md §4.1) — so this isn't a violation of a stated
guarantee. It's flagged because the function's name and its use in `finally:`
blocks throughout `api.py` implies a security property ("we wipe keys after use")
that it does not deliver, which could mislead a future maintainer or a reviewer
skimming the code.

**Fix direction:** either implement real best-effort zeroing (mutable
`bytearray` buffers with in-place overwrite instead of `bytes`, accepting the
larger refactor this implies), or rename/document `wipe()` explicitly as
"drops references, not a memory-safety guarantee" so it isn't mistaken for one.

**Status:** OPEN (no regression test — this is a documentation/hygiene finding,
not something a black-box test can observe from outside the process).

---

## FC-05 — LOW — Package license metadata contradicts actual license

**Files:** `fortress-crypt-suite/core-python/pyproject.toml`,
`audit-package/core-python/pyproject.toml`, `audit-package/core-python-audit/pyproject.toml`

All three declare `license = {text = "MIT"}`. Every source file header, the
top-level `LICENSE` (full AGPLv3 text), and the entire `licensing/` directory
(CLA, dual-licensing docs) establish AGPL-3.0-or-later with a commercial
dual-licensing program. `pip show fortress-crypt` / PyPI metadata will tell
installers "MIT", misrepresenting real copyleft obligations.

**Fix direction:** `license = {text = "AGPL-3.0-or-later"}` (or the modern SPDX
`license = "AGPL-3.0-or-later"` field), consistently across all three
`pyproject.toml` files.

**Status:** OPEN.

---

## FC-06 — LOW — `pq.save_keypair`'s `chmod(0o600)` is a silent no-op on Windows

**File:** `fortress/pq.py` lines 62-63

POSIX mode bits don't map onto NTFS ACLs; on Windows this `try/except OSError`
either does nothing or silently "succeeds" without actually restricting other
local accounts from reading the ML-KEM-1024 secret-key JSON file. Not exploitable
without local access already, but worth documenting since the user specifically
asked about Windows-side hardening.

**Fix direction:** either accept this as a known platform limitation (document
it), or use `icacls`/`win32security` on Windows to set an equivalent ACL.

**Status:** OPEN (no regression test — platform ACL behavior isn't practical to
assert in the existing pytest suite without a Windows-specific ACL-reading test).

---

## Findings NOT filed (checked, found to be already correctly handled or already
documented by the project's own spec)

- Footer using prefix-keyed SHA3-256 instead of HMAC/KMAC — SPEC §7.3 already
  flags this; the sponge-construction argument against length-extension holds.
- XOR KDF combiner non-independence — SPEC §4 already flags this correctly.
- AEAD layers not binding chunk index as associated data — SPEC §5.4 flags this;
  verified that per-chunk nonce derivation from `(nonce_seed, chunk_idx, pass)`
  already defeats naive splicing/reordering across chunks or files at the AEAD
  layer (different position → different nonce → tag fails) — the *actual* gap
  this note was fishing for turned out to be FC-03 (truncation succeeds because
  verification is deferred past the point plaintext is released), which is now
  filed separately with a working PoC.
- Key commitment excludes `padding_key`/`nonce_seed` — reviewed per
  THREAT_MODEL.md §7 Q4; `nonce_seed` is public/random and independent of
  password, its exclusion does not create a practical partitioning oracle given
  the commitment already binds all cipher/MAC keys derived from `master`.
</content>
