# Contributing to Fortress Crypt

Thanks for your interest in improving Fortress Crypt. This document explains how
contributions work here, and — importantly — the licensing arrangement, because
it is a little different from a typical open-source project.

## TL;DR

- The project is licensed **AGPL-3.0** to the public.
- The original author, **Steve Watts / The Lion's Kingdom IT Solutions, LLC**
  ("the Maintainer"), retains copyright ownership of the project as a whole.
- To contribute, you sign a **Contributor License Agreement (CLA)** that lets the
  Maintainer keep offering the project under both AGPL-3.0 *and* separate
  commercial licenses.
- You keep the copyright to your own contribution. You are not signing it away —
  you are granting the Maintainer a broad license to use it (see below).

If that is agreeable, read on. If not, that is completely fine — you are still
free to fork the project under AGPL-3.0 and develop your fork independently, as
the license permits.

---

## Why a CLA?

Fortress Crypt uses a **dual-licensing** model:

1. **AGPL-3.0** for everyone. Anyone may use, study, modify, and redistribute the
   software, provided their derivative works are also AGPL-3.0 and — critically
   for a network-deployed tool — provided network users are offered the source.
2. **Commercial licenses**, sold by the Maintainer, for organizations that want
   to use Fortress Crypt without the AGPL's copyleft obligations.

For the Maintainer to be able to offer option (2), the Maintainer must hold
sufficient rights to *all* the code — including contributions from others. If a
contribution were only available under AGPL-3.0, the Maintainer could not include
it in a commercially licensed build. The CLA solves this: it grants the
Maintainer the rights needed to relicense contributions, **without** taking your
copyright away from you.

This is the same model used by MongoDB, Qt, SugarCRM, and many other projects.

---

## What the CLA actually says (plain-English summary)

The authoritative document is `CLA.md`. In plain terms, by signing you agree that:

1. **You keep your copyright.** You grant the Maintainer a perpetual, worldwide,
   royalty-free, irrevocable license to use, reproduce, modify, sublicense, and
   relicense your contribution — including under commercial terms. You are *not*
   assigning ownership.
2. **You have the right to contribute it.** The work is yours, or you have
   permission to submit it, and it does not knowingly infringe anyone else's
   rights. If your employer has rights to your work, you have their permission.
3. **You grant a patent license** for any patents you hold that your contribution
   would otherwise infringe, so the project can use your code freely.
4. **No warranty.** You provide the contribution "as is."

Signing the CLA does **not** obligate the Maintainer to include your
contribution, and does not create an employment or partnership relationship.

---

## How to contribute

1. **Open an issue first** for anything non-trivial, so we can agree on the
   approach before you invest time. For a cryptographic project, design changes
   especially need discussion before code.
2. **Sign the CLA.** Add your name to `CLA-signatures.md` in your pull request, in
   the format shown at the bottom of that file. Submitting the PR with that line
   added constitutes your agreement to `CLA.md`.
3. **Follow the security ground rules** (below).
4. **Include tests.** New behavior needs tests; changes to the crypto core must
   keep the existing test suite and vectors passing (`pytest tests/`).
5. **Open a pull request** with a clear description of what changed and why.

---

## Security ground rules (non-negotiable)

Because this is encryption software, some contribution types get extra scrutiny
or are declined outright:

- **Do not invent new cryptographic primitives or modes.** Improvements should use
  standard, vetted primitives. Novel ciphers, homemade KDFs, or "clever" tweaks to
  the cascade will be declined regardless of quality.
- **Do not change the file format or KDF labels without a version bump.** The
  deterministic vectors in `tests/vectors/` exist to catch this. If you
  intentionally change them, bump `FORMAT_VERSION` and document the migration.
- **No weakening of the constant-time comparisons** or other side-channel
  mitigations.
- **Changes to the destructive features** (trap/duress) must preserve the
  separation that keeps the audit fork reviewable.
- Cryptographic design changes should ideally reference peer-reviewed sources or
  come with analysis. "Trust me" is not sufficient for this domain.

Everyday contributions — bug fixes, docs, tests, performance, portability, UI,
build tooling — are very welcome and reviewed normally.

---

## What if I don't want to sign the CLA?

Then don't. The AGPL-3.0 gives you the right to fork and modify Fortress Crypt on
your own terms (within the AGPL). You simply can't have your changes merged into
the Maintainer's official, dual-licensed distribution without the CLA. No hard
feelings — that is how copyleft is supposed to work.

---

## Questions

Open an issue, or contact the Maintainer at the address listed in the project
README. For anything touching the commercial license, contact the Maintainer
directly rather than opening a public issue.
