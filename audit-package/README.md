# Fortress Crypt — Audit Package

This package is the pre-audit preparation bundle for Fortress Crypt. It exists to
make a third-party cryptographic review as cheap and effective as possible: an
auditor should spend their time *finding* problems, not *reconstructing intent*.

It contains the three things worth doing before paying for an audit:

1. **A formal specification** — the exact construction, byte layout, and security
   claims (`docs/SPECIFICATION.md`).
2. **An explicit threat model** — what is and isn't defended, and the assumptions
   each guarantee rests on (`docs/THREAT_MODEL.md`).
3. **A reviewable, well-tested state** — a comprehensive test suite with locked
   deterministic vectors (`tests/`), plus a **non-destructive audit fork** of the
   core so the crypto can be reviewed without the shipping build's
   file-destruction behavior (`core-python-audit/`).

## Contents

```
audit-package/
├── README.md                    ← this file
├── docs/
│   ├── SPECIFICATION.md         ← normative construction + byte layout + claims
│   └── THREAT_MODEL.md          ← adversary model, guarantees, out-of-scope
├── core-python/                 ← shipping reference build (destructive features)
├── core-python-audit/           ← non-destructive fork (identical crypto core)
│   └── README-AUDIT-FORK.md     ← what differs and why
├── tests/
│   ├── README.md                ← how to run, what's covered
│   ├── test_kdf.py              ← KDF determinism + known-answer tests
│   ├── test_roundtrip.py        ← correctness across sizes/levels/messages
│   ├── test_integrity.py        ← negative/tamper/offset tests
│   ├── test_traps_duress.py     ← shipping destructive behavior
│   ├── test_audit_fork.py       ← byte-identity + non-destructive proofs
│   ├── test_vectors.py          ← locks the deterministic vectors
│   └── vectors/kdf_vectors.json ← cross-implementation KDF vectors
└── pytest.ini
```

## Quick start for a reviewer

```bash
# Review the crypto without destructive side effects:
pip install pytest pycryptodome cryptography argon2-cffi
pip install -e core-python-audit
pytest tests/ -q

# Read, in order:
#   docs/THREAT_MODEL.md   (what we claim)
#   docs/SPECIFICATION.md  (how we build it — note the ⚠ Review notes)
#   core-python-audit/fortress/{keys,engine,format,api}.py
```

## Known limitations, stated up front

The specification's §12 lists the seven design points most likely to draw a
finding — including the prefix-keyed SHA3 footer, the XOR KDF combiner, and the
bounded padding-length leak. These are documented deliberately so the audit
starts from the known edge and pushes outward.

## Status

All 52 functional tests pass against the shipping build; the KDF vectors are
locked; the audit fork's crypto core is proven byte-identical to shipping and its
non-destructive behavior is verified. This has **not** yet had a third-party
cryptographic audit — that is what this package is meant to enable.
