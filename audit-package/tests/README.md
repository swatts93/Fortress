# Fortress Crypt — Test Suite

A reviewer-oriented test suite for the Fortress cryptographic core. It is
organized so an auditor can quickly see what is asserted and run it against
either the shipping build or the non-destructive audit fork.

## Layout

| File | What it locks down |
|------|--------------------|
| `test_kdf.py` | KDF determinism, sub-key separation, commitment construction, nonce/padding derivation, trap hashing. Deterministic (pinned salt/nonce). |
| `test_roundtrip.py` | Encrypt→decrypt correctness across sizes (0 B … multi-chunk), chunk boundaries, security levels, Unicode passwords, messages. |
| `test_integrity.py` | Negative tests: wrong password, bit-flips in header/body, truncation, bad magic, and **byte-offset verification** of the header layout. |
| `test_traps_duress.py` | Shipping (destructive) trap + duress behavior. |
| `test_audit_fork.py` | Proves the fork's crypto core is **byte-identical** to shipping, and that the fork is genuinely non-destructive. |

## Running

Install exactly one core, then run the suite:

```bash
# Shipping build
pip install -e core-python
pytest tests/ -q            # runs everything except fork-only tests (auto-skipped)

# Audit fork (non-destructive)
pip install -e core-python-audit
pytest tests/ -q            # fork-only tests now run
```

The byte-identity tests (`test_keys_module_byte_identical`, etc.) compare source
files on disk and require both `core-python/` and `core-python-audit/` to be
present — which they are in this package.

Because both packages expose the top-level module name `fortress`, only one can
be imported at a time. The fork-behavior tests detect the active package and skip
if the shipping build is installed instead.

## What is NOT covered (by design)

- **Full-ciphertext known-answer vectors.** Padding content is fresh random per
  chunk (SPEC §5.2), so the complete ciphertext is not byte-reproducible. The KDF
  and header layout ARE deterministic and are locked by KATs here.
- **The C/Swift/Kotlin ports.** These tests target the Python reference. The ports
  are expected to produce interoperable files; cross-language interop vectors are
  a recommended follow-up (see SPEC §11).
- **Timing measurements.** Constant-time comparison is used in the code; empirical
  timing verification is left to the paid audit.

## Runtime note

`test_kdf` and any test at `standard` level runs real Argon2id + scrypt
(128 MB each). The full suite takes ~90 s. For faster iteration, run a subset:

```bash
pytest tests/test_integrity.py -q      # fast, no heavy KDF in most cases
```
