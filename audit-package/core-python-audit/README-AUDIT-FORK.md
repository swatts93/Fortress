# Fortress Crypt — Audit Fork (non-destructive)

This is a **fork of the shipping Fortress core**, created specifically so the
cryptographic construction can be reviewed without the in-place file-destruction
behavior that the shipping build performs.

## Why a fork instead of a flag?

The project owner's requirement is that audit-readiness must **not** weaken the
shipping product. The shipping build's trap and duress features are *supposed* to
destroy data — that is their entire purpose. But that same destructive, file-
mutating behavior:

1. makes the crypto core hard to unit-test in isolation (every wrong-password
   path has irreversible side effects), and
2. is exactly the kind of thing a reviewer wants *removed* so they can reason
   about confidentiality/integrity without also reasoning about file I/O.

So rather than adding a "safe mode" toggle to the shipping code (which risks a
production build accidentally running in non-destructive mode), the destructive
behavior is removed in a separate fork. The shipping build is unchanged.

## What differs

| Behavior | Shipping (`core-python`) | This fork |
|----------|--------------------------|-----------|
| Wrong trap code | Overwrites header, destroys file | Raises `TrapVerificationError`, file untouched |
| Duress password | Decrypts decoy, **wipes real data** | Decrypts decoy, **preserves real data**, returns `audit_fork_real_data_preserved: True` |
| Any decrypt path | May mutate the input file | **Never** mutates the input file |

## What is identical

The cryptographic core is **byte-for-byte identical** to the shipping build:

- `fortress/keys.py` — KDF chain, sub-key derivation, key commitment, trap hashing
- `fortress/engine.py` — the 6-layer double cascade
- `fortress/format.py` `_serialize` — header byte layout

This is enforced by `tests/test_audit_fork.py::test_keys_module_byte_identical`
and friends, which fail if the cores ever drift apart. A file produced by either
build decrypts under the other.

## Install

Because both builds expose the module name `fortress`, install only one at a
time in a given environment:

```bash
pip install -e core-python-audit    # this fork
# or
pip install -e core-python          # shipping build
```

## Intended use

Hand `core-python-audit/` + `docs/SPECIFICATION.md` + `docs/THREAT_MODEL.md` to a
reviewer. They can analyze the full confidentiality/integrity story here without
destructive side effects, then separately review the ~40 lines of destructive I/O
(`scramble_header`, `scramble_real_data_section` in the shipping `format.py`, and
their call sites in the shipping `api.py`) that this fork removes.
