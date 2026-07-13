# Dual Licensing — How It Works

Fortress Crypt is offered under **two** licenses simultaneously. The user chooses
which one they operate under.

```
                    ┌─────────────────────────────┐
                    │   Fortress Crypt source     │
                    │   (you hold the copyright)  │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                          ▼
   ┌──────────────────────┐                 ┌──────────────────────────┐
   │  AGPL-3.0 (public)   │                 │  Commercial license      │
   │  Free to use/modify  │                 │  You sell this           │
   │  BUT derivatives &    │                 │  No copyleft obligation  │
   │  network use must be  │                 │  Terms you set           │
   │  open-sourced         │                 │  (support, warranty…)    │
   └──────────────────────┘                 └──────────────────────────┘
```

## Who picks which

- **Hobbyists, researchers, open-source projects** → take the **AGPL-3.0** path
  for free. They must keep their derivatives open and, if they run it as a network
  service, offer source to their users.
- **A company that wants to embed Fortress Crypt in a closed-source product, or
  run it as a service without publishing their changes** → the AGPL forbids that,
  so they come to **you** and buy a **commercial license** that waives the copyleft
  terms.

This is exactly why the AGPL (rather than MIT/BSD) is the engine of the model: the
stronger the copyleft, the more valuable the commercial exception you're selling.

## Why you can do this and others can't

You can offer commercial licenses because you **own the copyright** to the whole
work. Someone who merely received the code under AGPL-3.0 cannot — the AGPL grant
they got doesn't include the right to relicense. The one risk to this position is
**outside contributions**: if you merged someone else's AGPL-only code, you
couldn't relicense *that part* commercially. The **CLA** (`CLA.md`) solves this by
having every contributor grant you relicensing rights while keeping their own
copyright.

So the two pillars of the model are:

1. **You own your original code.** (Automatic on creation.)
2. **Contributors grant you relicensing rights via the CLA.** (Required before
   merging outside contributions.)

Keep both intact and the commercial path stays open.

## Running the commercial side (practical notes)

- **You set the terms.** A commercial license is a private contract. Common terms:
  per-seat or per-deployment fee, included support/SLA, an actual warranty (the
  AGPL disclaims all warranty), indemnification, and a defined scope of use.
- **Keep a clean contribution trail.** The signed CLAs are what let you prove you
  can relicense. Keep `CLA-signatures.md` and the PRs that reference it.
- **Version your commercial license** and record which software version each
  customer licensed.
- **Get counsel to draft the actual commercial agreement.** The AGPL `LICENSE` and
  the `CLA.md` are standard templates; a commercial license that you *sell* should
  be drafted or reviewed by an IP/commercial attorney for your jurisdiction. This
  is the one piece worth paying for.

## What the AGPL does NOT let you do

- It does not let you stop someone from forking the public AGPL version and
  competing with an open-source fork. Copyleft cuts both ways.
- It does not force existing AGPL users to pay — they can stay on AGPL forever, as
  long as they honor its terms.
- It does not cover trademark. Your project **name** and any logo are protected
  separately (trademark), not by the software license. If brand control matters,
  consider a trademark policy and, potentially, registration.

## Trademark tie-in

The AGPL governs the *code*. It does **not** grant anyone the right to use the
"Fortress Crypt" name or your heraldic logo to market their fork. You can (and for
brand control, should) reserve those separately — a short `TRADEMARK.md` stating
that the name and marks are not licensed under the AGPL and require permission is a
common, low-cost step. Ask counsel whether registration is worth it for your goals.
