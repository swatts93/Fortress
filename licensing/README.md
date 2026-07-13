# Fortress Crypt — Licensing Kit

This folder contains everything needed to license Fortress Crypt under a
**dual-licensing** model: **AGPL-3.0 for the public**, with the copyright holder
retaining the right to sell **separate commercial licenses**. It lets outside
contributors improve the project while you keep ownership and a commercial path.

## What's here

| File | Purpose |
|------|---------|
| `LICENSE` | The verbatim GNU AGPL-3.0 text (the public license). |
| `CONTRIBUTING.md` | How to contribute; explains the CLA and security ground rules. |
| `CLA.md` | The Contributor License Agreement contributors accept. |
| `CLA-signatures.md` | Ledger where contributors record agreement. |
| `HEADERS.md` | Per-file license header text for each language. |
| `apply_headers.py` | Script that inserts those headers across the codebase. |
| `DUAL-LICENSING.md` | How the AGPL + commercial model works, and how to run it. |

## Why AGPL-3.0 (not MIT/GPL)

- **You keep ownership regardless.** A license grants permission; it does not
  transfer copyright. You remain the owner.
- **Copyleft keeps improvements open.** Anyone can modify Fortress Crypt, but
  derivatives must also be AGPL-3.0 — nobody can quietly fold it into a closed
  product.
- **AGPL closes the SaaS gap.** Plain GPL only triggers on *distribution*. AGPL
  also triggers when the software is offered as a **network service**, which
  matters for encryption tooling that could be run as a hosted service. A provider
  must offer their modified source to network users.
- **It enables dual licensing.** Because you hold the copyright (and gather
  contributor rights via the CLA), you can *also* sell commercial licenses to
  parties who don't want the copyleft obligations. This is the MongoDB / Qt model.

## Setup checklist

1. **Add `LICENSE` to the repository root.** One copy at the top level covers the
   whole project.
2. **Apply source headers:**
   ```bash
   python3 apply_headers.py --root /path/to/fortress-crypt --year 2025
   ```
   Re-run any time; it's idempotent. Add `--check` in CI to enforce headers.
3. **Add `CONTRIBUTING.md`, `CLA.md`, and `CLA-signatures.md`** to the repo root.
4. **Fill in your contact address** in the project README so people can reach you
   about commercial licensing.
5. **Have counsel review** `CLA.md` and your commercial license terms before you
   accept outside contributions or sell a commercial license.
6. **(Optional) Register your copyright.** You own it automatically on creation,
   but registration (e.g., with the U.S. Copyright Office) strengthens your ability
   to enforce it and to claim statutory damages.

## A note on the pre-existing "MIT" mentions

Earlier drafts of the project README and `pyproject.toml` said "MIT". Switching to
AGPL-3.0 is your choice to make as the copyright holder for all your own code.
Update those references (README badges, `pyproject.toml` `license` field, package
metadata) to `AGPL-3.0-or-later` so they're consistent with the new `LICENSE`.
Note the third-party libraries you depend on keep their own licenses — AGPL applies
to *your* code, not to, say, pyca/cryptography.
