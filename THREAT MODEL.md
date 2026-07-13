# Fortress Crypt — Threat Model

**Version:** 2.0.1
**Companion to:** SPECIFICATION.md

This document states what Fortress Crypt is designed to defend against, what it is
explicitly *not* designed to defend against, and the assumptions each guarantee
depends on. An auditor should read this before the specification: a construction
can only be "correct" relative to a threat model.

---

## 1. Assets

| Asset | Sensitivity |
|-------|-------------|
| File plaintext (disk images, documents, media) | Primary — must stay confidential |
| The master password | Critical — root of all key material |
| The duress password + decoy | The decoy is intentionally disclosable |
| Metadata: file sizes, timestamps, that a file *is* a Fortress file | Low — not hidden |
| Existence of a real (non-decoy) payload of a given size | **Not** protected (see §5) |

---

## 2. Adversary capabilities considered

The design is evaluated against adversaries with increasing capability:

### A1 — Passive ciphertext holder
Has the encrypted file(s) and the header. No access to the device, password, or
runtime. **Example:** stolen backup, seized cloud storage, intercepted transfer.

### A2 — Offline brute-forcer
A1 plus large offline compute (GPU/ASIC clusters) attempting to guess the password.

### A3 — Tampering adversary
A1 plus the ability to modify ciphertext before it reaches the legitimate
recipient, hoping to cause incorrect decryption, chunk reordering, or a forgery
that still "decrypts."

### A4 — Future quantum adversary
A2 with a large-scale quantum computer (Shor/Grover). Relevant to the key-exchange
step and to symmetric key sizes.

### A5 — Coercion adversary
Physically compels the holder to reveal a password (the "$5 wrench" / border-search
scenario). The holder may reveal the *duress* password instead.

### A6 — Endpoint adversary (OUT OF SCOPE — see §4)
Has code execution on the device during encryption/decryption: keyloggers, memory
scrapers, malicious OS, evil-maid firmware.

---

## 3. Guarantees and the assumptions they rest on

| # | Guarantee | Holds against | Depends on |
|---|-----------|---------------|------------|
| G1 | Plaintext confidentiality | A1, A2 | ≥1 of {AES-256, ChaCha20, Camellia-256} secure AND ≥1 of {Argon2id, scrypt} secure AND password has adequate entropy AND CSPRNG sound |
| G2 | Brute-force cost | A2 | Memory-hard parameters as configured (256 MB–4 GB/guess); password entropy |
| G3 | Tamper-evidence | A3 | Collision/forgery resistance of GCM, Poly1305, HMAC-SHA512, SHA3; header HMAC; footer chain |
| G4 | PQ confidentiality of key exchange (hybrid mode) | A4 | ML-KEM-1024 (FIPS 203); classical fallback if broken |
| G5 | Symmetric PQ margin | A4 | 256-bit keys → ~128-bit post-Grover; considered adequate |
| G6 | Coercion decoy | A5 | Adversary lacks a prior byte-image of the file; accepts decoy as sole content (see §5) |
| G7 | Key commitment | A1, A3 | SHA3-512; constant-time comparison |

**Entropy caveat (applies to G1, G2):** all password-based guarantees are void if
the password is weak. A 6-character password is breakable regardless of KDF cost.
The system cannot and does not compensate for low-entropy passwords beyond raising
the per-guess cost.

---

## 4. Explicitly OUT OF SCOPE

The following are **not** defended against, by design. An auditor should not treat
these as findings against the construction; they are stated limits.

1. **Endpoint compromise (A6).** If the OS, hardware, or app is compromised at
   runtime, the password and plaintext are exposed regardless of any file-format
   property. Fortress assumes a trusted endpoint during operations.

2. **Weak passwords.** No guarantee survives a guessable password.

3. **Rubber-hose against the *real* password.** If the holder reveals the real
   password (not the duress one), all content is exposed. Duress (G6) is the only
   mitigation and is partial (§5).

4. **Traffic/metadata analysis.** That a file is a Fortress file (magic bytes),
   its approximate size, and its timestamps are visible. Padding hides per-chunk
   length only within a 256–4096 B window.

5. **Denial of service / data-loss from the destructive features.** Trap and
   duress are *designed* to destroy data. A user who forgets a trap code, or who is
   coerced into the duress password and later wants the real data back, has
   permanently lost it. This is intended behavior, not a vulnerability — but it is
   a serious operational hazard and is the reason the audit fork (SPECIFICATION §10)
   exists for reviewing the crypto without it.

6. **Side channels in the underlying cipher libraries.** Fortress uses
   constant-time comparison for its own tag/commitment checks, but does not
   independently guarantee constant-time behavior of AES/ChaCha/Camellia beyond
   what the platform libraries provide (AES-NI, etc.).

7. **Multi-user / key-sharing / forward secrecy.** There is no ratchet, no key
   rotation, no forward secrecy. A compromised password compromises every file
   encrypted under it, past and future.

---

## 5. Duress: precise deniability claim

Duress is frequently over-claimed by similar tools, so its exact property is
stated carefully:

**What duress DOES provide:** after the duress password is used, the file's real
data section and real key commitment are overwritten with random bytes. The file
then decrypts *only* to the decoy under the duress password, and the real password
no longer recovers anything. An adversary who obtains the file *only after*
duress activation sees a file consistent with having held just the decoy.

**What duress does NOT provide:**
- It does **not** hide that a region of a given size was overwritten. The random
  block occupies the same length the real ciphertext did, so the *existence of
  ~N bytes of former payload* is inferable from file size vs. decoy size.
- It does **not** protect against an adversary who captured a byte-image of the
  file *before* duress activation (they can still attack the original real
  section offline).
- It is **not** a hidden-volume scheme (à la VeraCrypt) where the very existence
  of a second volume is cryptographically deniable. Fortress's duress is a
  *destroy-on-decoy* mechanism, not a *coexist-and-deny* one.

An auditor evaluating G6 should evaluate it against exactly this claim, not the
stronger hidden-volume claim.

---

## 6. Trust assumptions summary

Fortress's guarantees hold only if all of the following are true:

- The endpoint is trusted during encryption and decryption.
- The CSPRNG is sound on the platform.
- The password has adequate entropy and is not otherwise disclosed.
- The underlying vetted libraries (pyca/cryptography, PyCryptodome, argon2,
  BouncyCastle, OpenSSL, CryptoKit, ML-KEM) are correct.
- For duress deniability (G6), no prior byte-image of the file exists in the
  adversary's hands.

If any assumption fails, the corresponding guarantee is void. This is normal for
any encryption system; it is stated explicitly so the audit scope is unambiguous.

---

## 7. Prioritized questions for a paid auditor

To get the most value per dollar, we would ask an auditor to focus on, in order:

1. The footer keyed-hash construction (SPEC §7.3) — is prefix-keyed SHA3-256
   acceptable, or must it become HMAC-SHA3/KMAC?
2. Chunk-ordering / truncation resistance (SPEC §5.4) — is the footer chain +
   `original_size` sufficient given the AEAD layers don't bind the index?
3. The KDF combiner (SPEC §4) — does XOR of non-independent operands weaken any
   stated claim?
4. Key-commitment completeness — does committing to the 10 listed sub-keys (but
   not `padding_key` or `nonce_seed`) admit any partitioning-oracle edge case?
5. The duress deniability claim (§5) — is it correctly bounded, and is the
   single-pass wipe offset computation correct in all header configurations?
6. Constant-time coverage — are there remaining data-dependent branches on secret
   material outside the comparisons already hardened?
