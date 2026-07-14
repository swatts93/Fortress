# Audit Findings Register

Tracks every finding from the independent audit of the Fortress Crypt Python
core (`core-python` / `core-python-audit`), when each was addressed, and where.
Full technical detail (root cause, PoC, fix rationale) is in `AUDIT_FINDINGS.md`
in this folder.

| ID | Severity | Title | Status | Date Addressed | Fix Commit |
|----|----------|-------|--------|-----------------|------------|
| FC-01 | CRITICAL | Forged trap section → zero-cost, no-password destruction of any file | FIXED | 2026-07-14 | `c3c501c` |
| FC-02 | CRITICAL | Forged duress section → no-password destruction of real data | MITIGATED (no cryptographic fix exists; level-gated + explicit toggle, residual risk documented) | 2026-07-14 | `c3c501c` |
| FC-03 | HIGH | Plaintext released to disk before ciphertext integrity check; no cleanup on some failure paths | FIXED | 2026-07-14 | `c3c501c` |
| FC-04 | MEDIUM | `FortressKeys.wipe()` doesn't wipe anything in CPython | FIXED (documentation — behavior was already out of scope per THREAT_MODEL.md A6) | 2026-07-14 | `c3c501c` |
| FC-05 | LOW | `pyproject.toml` license metadata (MIT) contradicted actual AGPL-3.0 source | FIXED | 2026-07-14 | `c3c501c` |
| FC-06 | LOW | PQ secret-key `chmod(0o600)` was a silent no-op on Windows | FIXED | 2026-07-14 | `c3c501c` |

## Verification

All fixes verified against:
- The audit's own regression suite: `audit-package/tests/test_header_forgery.py`
  (previously failing against the vulnerable code, now passing).
- The full existing test suite: 71 passed / 2 skipped against the shipping
  build, 59 passed / 14 skipped against the non-destructive audit fork.
- GitHub Actions CI (`.github/workflows/tests.yml`), ubuntu-latest and
  windows-latest × Python 3.11/3.12, all green on commit `c3c501c`.

## Provenance note

An independent review session also produced its own analysis and fix attempt
for FC-01/FC-02/FC-03 on a separate git worktree/branch (`worktree-crypto-audit`,
commit `965b9c4`), using a different design for FC-02 (`confirm_duress_wipe`
flag requiring explicit confirmation on every duress decrypt, rather than the
level-gated default + override that shipped). That branch was never merged;
the fixes on `main` (`c3c501c`) reflect the project owner's explicit direction
for FC-02 specifically. The branch and its commit remain in the repository's
history (not deleted) for reference even though its working-tree checkout was
removed.
