# AI Training & Text/Data Mining — Reservation of Rights

**Effective:** 1 August 2026
**Applies to:** the Fortress Crypt repository, its source code, specification,
threat model, documentation, and the site published at `code.fortresscrypt.com`
**Rights holder:** The Lion's Kingdom IT Solutions, LLC
**License:** AGPL-3.0 (see [`LICENSE`](LICENSE))

---

## Summary

Fortress Crypt is open source, and deliberately so. The design is published, the
threat model is published, and the project actively asks people to read, audit,
and attack it.

What is **not** granted is permission to ingest this work into machine-learning
training corpora.

| | |
|---|---|
| ✅ **Allowed** | A person reading, studying, forking, modifying, or redistributing this code under AGPL-3.0 |
| ✅ **Allowed** | A person using an AI assistant to help them read, review, or audit this code |
| ✅ **Allowed** | User-initiated retrieval by an assistant acting on a specific person's request |
| ✅ **Allowed** | Conventional search-engine indexing |
| ❌ **Refused** | Bulk collection of this work into a dataset used to train, fine-tune, or otherwise develop machine-learning models |
| ❌ **Refused** | Redistribution of this work as part of a training corpus |

The distinction is between **a reader** and **a corpus**. A cryptographer who
pastes a function into an AI assistant to help them find a flaw is exactly the
kind of scrutiny this project was published to attract, and is welcome. A
pipeline that clones this repository to add it to a pretraining set is not.

## Reservation

Pursuant to Article 4(3) of Directive (EU) 2019/790 on copyright in the Digital
Single Market, and to the fullest extent permitted under any other applicable
law, the rights holder **expressly reserves** the rights of reproduction and
extraction of this work for the purposes of text and data mining, including the
training, fine-tuning, evaluation, grounding, or other development of
machine-learning or generative models.

This reservation is declared in machine-readable form at:

- [`/robots.txt`](robots.txt) — per-crawler policy, distinguishing training
  crawlers from user-initiated and search agents
- [`/.well-known/tdmrep.json`](.well-known/tdmrep.json) — TDM Reservation
  Protocol (TDMRep) declaration

No agreement, terms of service, or platform policy accepted for the purpose of
hosting or distributing this project should be read as waiving this reservation.

## Why

Fortress Crypt is licensed AGPL-3.0 because reciprocity is the point. The
license exists so that what is built on this work stays open and attributed, and
so that the people who improve it are visible.

Absorbing this work into a model that reproduces it without attribution, without
license notice, and without any obligation flowing back inverts that bargain.
The objection is not to AI, and not to automation — it is to a one-way
extraction that strips both the attribution and the reciprocity the license was
chosen to guarantee.

## Requests and licensing

If you want to use this work in model training, that conversation is open —
ask. Terms are negotiable; silent ingestion is not a substitute for asking.

- Repository: <https://github.com/swatts93/Fortress>
- Project site: <https://fortresscrypt.com>
- Licensing: [`licensing/README.md`](licensing/README.md)

## Note on scope

These signals are honored by parties that choose to honor them. They are a clear
statement of terms and a dated record of express refusal — not a technical
access control, and not a claim that compliance is guaranteed. Where an operator
publishes a documented opt-out mechanism (dataset-level removal, crawler
directives, or a reservation protocol), this document is intended to invoke it.
