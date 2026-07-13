# Fortress Crypt — Cryptographic Specification

**Version:** 2.0.1
**Format version:** 2
**Status:** Draft for third-party review
**Reference implementation:** `core-python/` (this is the normative implementation; iOS and Android are ports and MUST match its byte-level behavior)

---

## 0. How to read this document

This document specifies the Fortress Crypt construction precisely enough for an
independent cryptographer to (a) reproduce the byte layout of an encrypted file,
(b) reason about the security claims, and (c) identify weaknesses. Where the
design makes an unconventional choice, it is called out explicitly in a
**⚠ Review note** so a reviewer does not have to discover it by reading code.

Notation:
- `‖` denotes byte concatenation.
- `LE16/LE32/LE64` denote unsigned little-endian integers of 2/4/8 bytes.
- `random(n)` denotes `n` bytes from a cryptographically secure RNG
  (`os.urandom` in Python, `SecRandomCopyBytes` on iOS, `SecureRandom` on Android).
- All multi-byte integers in the file format are little-endian.

---

## 1. Cryptographic primitives

| Role | Primitive | Parameters | Library |
|------|-----------|-----------|---------|
| Block cipher (inner) | Camellia-256 | CBC mode, PKCS#7 pad | pyca/cryptography; BouncyCastle; OpenSSL |
| AEAD (middle) | ChaCha20-Poly1305 | 96-bit nonce, 128-bit tag | PyCryptodome; javax.crypto; CryptoKit |
| AEAD (outer) | AES-256 | GCM, 96-bit nonce, 128-bit tag | PyCryptodome; javax.crypto; CryptoKit |
| Inner-layer MAC | HMAC-SHA-512 | 64-byte tag | stdlib hmac; javax.crypto; CryptoKit |
| KDF phase 1 | Argon2id | see §3 | argon2-cffi; argon2kt; libargon2 |
| KDF phase 2 | scrypt | see §3 | pyca/cryptography; BouncyCastle; OpenSSL |
| KDF phase 3 | HKDF-SHA-512 | RFC 5869 | pyca/cryptography; custom; CryptoKit |
| Header MAC | HMAC-SHA-256 | 32-byte tag | stdlib hmac; javax.crypto; CryptoKit |
| Footer integrity | keyed SHA3-256 | see §7.3 | hashlib; BouncyCastle; OpenSSL |
| Key commitment | SHA3-512 | 64-byte output | hashlib; BouncyCastle; OpenSSL |
| Trap-code hash | SHA3-256 | 32-byte output | hashlib; BouncyCastle; OpenSSL |
| PQ KEM (optional) | ML-KEM-1024 | FIPS 203 | pqcrypto / liboqs |

All keys are 256 bits unless stated otherwise.

---

## 2. High-level structure

A Fortress file consists of a **header**, an optional **duress data section**, and
a **real data section**. Plaintext is split into fixed-size chunks (default
1 MiB = 1,048,576 bytes). Each chunk is independently encrypted through a
**double cascade** of six cipher layers and authenticated by twelve tags.

```
plaintext
  → split into chunks of CHUNK_SIZE
  → per chunk: prepend anti-forensic padding, then
       Pass 1: Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM   (key set 1)
       Pass 2: Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM   (key set 2)
  → concatenate length-prefixed encrypted chunks
  → append footer integrity tag
```

Decryption reverses each cascade and verifies all twelve authentication tags per
chunk; any failure aborts.

---

## 3. Security levels

Each level fixes the two memory-hard KDF cost parameters. They are stored in the
header so decryption uses the parameters the file was created with (not a local
default).

| Level | Argon2id (t, m KiB, p) | scrypt (N, r, p) | Approx. combined memory |
|-------|------------------------|------------------|-------------------------|
| standard | 4, 131072, 4 | 2¹⁷, 8, 1 | ~256 MB |
| high | 6, 524288, 4 | 2¹⁹, 8, 1 | ~1 GB |
| paranoid (default) | 10, 1048576, 8 | 2²⁰, 8, 2 | ~2 GB |
| fortress | 14, 2097152, 8 | 2²¹, 8, 2 | ~4 GB |

⚠ **Review note:** scrypt N is stored in the header as an LE32. For the
`fortress` level N = 2²¹ = 2,097,152, which fits in 32 bits. Any future level
with N ≥ 2³² would overflow the field. Flagged as a format limit.

---

## 4. Key derivation

Inputs: `password` (UTF-8 bytes), `salt` (32 bytes, §6), `nonce_seed`
(32 bytes), the level parameters, and an optional `kem_shared_secret`
(32 bytes, only in hybrid mode).

```
phase1 = Argon2id(password, salt, t, m, p, outlen=64)

if hybrid:
    phase1 = HKDF-SHA512(ikm = phase1 ‖ kem_shared_secret,
                         salt = salt,
                         info = "fortress-hybrid-pre-scrypt-v2",
                         L = 64)

scrypt_salt = SHA3-256("fortress-scrypt-salt-v2" ‖ salt)
phase2 = scrypt(phase1, scrypt_salt, N, r, p, outlen=64)

combined = phase1 XOR phase2            # 64 bytes
master   = HKDF-SHA512(combined, salt, "fortress-master-key-v2", L=64)
```

From `master`, eleven 32-byte sub-keys are derived by HKDF-SHA512 with distinct
`info` labels:

```
p1_aes      = HKDF(master, salt, "fortress-p1-aes256gcm-v2")
p1_chacha   = HKDF(master, salt, "fortress-p1-chacha20poly1305-v2")
p1_camellia = HKDF(master, salt, "fortress-p1-camellia256cbc-v2")
p1_hmac     = HKDF(master, salt, "fortress-p1-hmac-sha512-v2")
p2_aes      = HKDF(master, salt, "fortress-p2-aes256gcm-v2")
p2_chacha   = HKDF(master, salt, "fortress-p2-chacha20poly1305-v2")
p2_camellia = HKDF(master, salt, "fortress-p2-camellia256cbc-v2")
p2_hmac     = HKDF(master, salt, "fortress-p2-hmac-sha512-v2")
header_auth = HKDF(master, salt, "fortress-header-auth-sha256-v2")
footer_auth = HKDF(master, salt, "fortress-footer-auth-sha3-256-v2")
padding     = HKDF(master, salt, "fortress-padding-key-v2")
```

**Rationale for XOR-combining two memory-hard functions:** if a structural
weakness is found in Argon2id *or* scrypt individually, `master` still depends on
the other. Both must be simultaneously broken to recover `master` without the
password.

⚠ **Review note (XOR combiner):** XOR is used as a combiner for two KDF outputs
that are both derived from the *same* `phase1`. Because `phase2 = scrypt(phase1)`,
the two operands are not independent; XOR here provides a "fail-safe if one
primitive is weak" property, not the "combiner of independent secrets" property.
A reviewer should confirm this matches the intended claim (§9) and consider
whether a concatenation-then-HKDF would be preferable. The subsequent HKDF over
`combined` means the combiner is not relied upon for uniformity.

---

## 5. Per-chunk encryption

### 5.1 Nonce and IV derivation

For chunk index `i` (LE64) and cascade pass `π ∈ {1,2}` (LE32):

```
ctx = LE64(i) ‖ LE32(π)
aes_nonce   = HKDF(nonce_seed, ctx, "fortress-aes-nonce",   L=12)
chacha_nonce= HKDF(nonce_seed, ctx, "fortress-chacha-nonce",L=12)
camellia_iv = HKDF(nonce_seed, ctx, "fortress-camellia-iv", L=16)
```

Because `(i, π)` is unique for every (chunk, pass) pair and `nonce_seed` is unique
per file, no (key, nonce) pair is ever reused, satisfying the GCM/ChaCha20
nonce-uniqueness requirement.

⚠ **Review note (nonce collision across passes):** pass 1 and pass 2 use
*different keys* (`p1_*` vs `p2_*`) and *different nonces* (π differs), so even
without key separation the nonces would not collide. Reviewer should confirm both
protections are actually independent.

### 5.2 Anti-forensic padding

```
pad_len   = 256 + ( LE32(HKDF(padding_key, LE64(i), "fortress-pad-len", L=4)) mod (4096-256+1) )
padding   = random(pad_len)
padded_pt = LE16(pad_len) ‖ padding ‖ plaintext_chunk
```

`pad_len` is deterministic given the key (so decryption can strip it) but
unpredictable to an attacker. The padding *content* is random.

⚠ **Review note:** padding hides exact chunk plaintext length only up to a
256–4096 byte window; the encrypted chunk length still leaks plaintext length
modulo that window. This is a deliberate, documented limitation, not full length
hiding.

### 5.3 One cascade pass

Given `data` and a key set (aes, chacha, camellia, hmac) plus derived nonces:

```
# Layer 1: Camellia-256-CBC then Encrypt-then-MAC with HMAC-SHA512
padded    = PKCS7(data)                       # to 16-byte boundary
cam_ct    = Camellia-256-CBC(camellia_key, camellia_iv, padded)
auth      = LE64(i) ‖ LE32(π) ‖ camellia_iv ‖ cam_ct
hmac_tag  = HMAC-SHA512(hmac_key, auth)       # 64 bytes
layer1    = cam_ct ‖ hmac_tag

# Layer 2: ChaCha20-Poly1305
ct2, tag2 = ChaCha20Poly1305(chacha_key, chacha_nonce, layer1)
layer2    = ct2 ‖ tag2                         # tag2 is 16 bytes

# Layer 3: AES-256-GCM
ct3, tag3 = AES256GCM(aes_key, aes_nonce, layer2)
layer3    = ct3 ‖ tag3                         # tag3 is 16 bytes
```

### 5.4 Double cascade (full chunk)

```
after_p1 = cascade(padded_pt, key set 1, π=1)
after_p2 = cascade(after_p1,  key set 2, π=2)
encrypted_chunk = after_p2
```

Decryption reverses pass 2 then pass 1; within each pass it verifies GCM, then
Poly1305, then HMAC-SHA512 before removing PKCS#7 padding. Twelve authentication
checks total per chunk (2 passes × [GCM + Poly1305 + HMAC]). Any failure raises
and aborts.

⚠ **Review note (no associated data binding chunk index into AEAD):** the AES-GCM
and ChaCha20-Poly1305 layers do not pass the chunk index as AEAD associated data;
chunk-index binding is provided only by (a) the nonce derivation and (b) the
inner HMAC-SHA512 `auth` string. A reviewer should confirm a chunk-reordering or
truncation attack is prevented by the footer chain (§7.3) plus `original_size`
(§7.1), since individual chunks are not internally ordered by the AEAD layers.

---

## 6. Randomness and uniqueness requirements

Per file, freshly generated: `salt` (32B), `nonce_seed` (32B), and — if enabled —
`trap_salt` (32B), `duress_salt` (32B), `duress_nonce_seed` (32B). Padding content
per chunk is fresh random. The security of GCM/ChaCha20 depends on `nonce_seed`
being unique per file; reuse of a `(salt, nonce_seed)` pair across two different
plaintexts under the same password would be catastrophic (nonce reuse). Implementations
MUST use a CSPRNG.

---

## 7. File format (byte-exact)

### 7.1 Header (before HMAC)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | ASCII `FORTRESS` |
| 8 | 2 | version | LE16 = 2 |
| 10 | 1 | mode | 0=password, 1=pq-only, 2=hybrid |
| 11 | 4 | argon2_time | LE32 |
| 15 | 4 | argon2_memory | LE32 (KiB) |
| 19 | 4 | argon2_parallelism | LE32 |
| 23 | 4 | scrypt_N | LE32 |
| 27 | 4 | scrypt_r | LE32 |
| 31 | 4 | scrypt_p | LE32 |
| 35 | 32 | salt | |
| 67 | 32 | nonce_seed | |
| 99 | 8 | original_size | LE64 (real plaintext length) |
| 107 | 4 | chunk_size | LE32 |
| 111 | 64 | key_commitment | SHA3-512 (§7.2) |
| 175 | 4 | kem_ct_len | LE32 |
| 179 | kem_ct_len | kem_ciphertext | present iff hybrid |
| … | 1 | trap_count | 0–5 |
| … | 32 | trap_salt | |
| … | 32×trap_count | trap_hashes | each SHA3-256 |
| … | 1 | duress_enabled | 0/1 |
| … | 32 | duress_salt | |
| … | 32 | duress_nonce_seed | |
| … | 64 | duress_key_commitment | |
| … | 8 | duress_data_size | LE64 |
| … | 4 | duress_chunk_count | LE32 |

Immediately after the serialized header:

| Size | Field |
|-----:|-------|
| 32 | header HMAC = HMAC-SHA256(header_auth_key, serialized_header) |

The fixed prefix (offsets 0–178, before any KEM ciphertext) is **179 bytes**;
`key_commitment` begins at offset **111** and `salt` at offset **35**. These
constants are used by the destructive routines (§8) and are verified by test
`test_header_offsets`.

### 7.2 Key commitment

```
key_commitment = SHA3-512( "fortress-key-commitment-v2"
                           ‖ p1_aes ‖ p1_chacha ‖ p1_camellia ‖ p1_hmac
                           ‖ p2_aes ‖ p2_chacha ‖ p2_camellia ‖ p2_hmac
                           ‖ header_auth ‖ footer_auth )
```

On decryption the derived commitment is compared (constant-time) against the
stored value. A mismatch means wrong password (or, in the duress case, the entered
password is checked against `duress_key_commitment` next). This binds the
ciphertext to exactly one key set and prevents key-substitution / partitioning
oracle behavior at the AEAD layer.

### 7.3 Footer integrity tag

```
footer = SHA3-256( "fortress-footer-chain-v2" ‖ footer_auth_key
                   ‖ for each chunk ct: ( LE32(len(ct)) ‖ ct ) )
```

Computed over every encrypted chunk of a section, in order, with length prefixes.
This binds chunk count and order and prevents truncation/reordering of the chunk
stream. Separate footers are written for the duress section and the real section.

⚠ **Review note (keyed hash vs HMAC):** the footer uses a **prefix-keyed SHA3-256**
(`SHA3-256(label ‖ key ‖ data)`), not HMAC. SHA-3 is not vulnerable to
length-extension, so the classic reason to prefer HMAC does not apply, and the
per-message data is length-prefixed. Nonetheless this is a non-standard MAC
construction. A reviewer should decide whether to require migration to
`HMAC-SHA3-256` or `KMAC256` for defense-in-depth. This is the single most likely
"finding" in the current design and is called out deliberately.

---

## 8. Trap sequence and duress (destructive features)

These features intentionally destroy data and are the reason for the **audit
fork** (§10).

### 8.1 Trap codes

Up to 5 ordered codes. For position `k` (0-based) and code string `c`:

```
trap_hash[k] = SHA3-256( trap_salt ‖ LE32(k) ‖ UTF8(c) )
```

On decryption, if `trap_count > 0`, the caller must supply exactly `trap_count`
codes. Each is verified constant-time against `trap_hash[k]`. **On any mismatch,
wrong count, or wrong order**, the implementation overwrites the header's `salt`
(offset 35, 32B), `nonce_seed` (offset 67, 32B), and `key_commitment`
(offset 111, 64B) with fresh random bytes and `fsync`s. The file is then
cryptographically unrecoverable even with the correct password.

### 8.2 Duress password

At encryption time the caller may supply a `duress_password` and decoy
`duress_data`. A second, independent key set is derived from `duress_password`
with `duress_salt`/`duress_nonce_seed`; the decoy is encrypted with the same
double cascade and written as the duress section, and `duress_key_commitment` is
stored.

On decryption the entered password is checked (constant-time) first against
`key_commitment` (real) and, if that fails and duress is enabled, against
`duress_key_commitment`. If it matches duress: the decoy is decrypted and
returned **and then the real data section plus the real `key_commitment` are
overwritten with random bytes** (single-pass offset computation, §7.1 constants).
The result is indistinguishable from a file that only ever held the decoy.

⚠ **Review note (threat model dependency):** duress security assumes the adversary
cannot observe the file *before* duress activation (e.g., no prior byte-level
backup) and cannot distinguish "file with wiped real section" from "file that
never had one." The random-overwritten region is the same size as the original
real section, so its *length* still reveals that some data of that size existed.
Full deniability (hidden-volume style) is **not** claimed; see THREAT_MODEL.md.

⚠ **Review note (auditability):** because these routines mutate the input file in
place, the core cryptographic functions are entangled with destructive file I/O.
This complicates formal review and unit isolation. The **audit fork** (§10)
removes the destructive behavior so the pure crypto core can be reviewed in
isolation, without changing the shipping product.

---

## 9. Security claims

The design intends to provide:

1. **Confidentiality of file contents** against an adversary without the password,
   even given the full ciphertext and header, assuming at least one of
   {AES-256, ChaCha20, Camellia-256} and at least one of {Argon2id, scrypt}
   remains secure.
2. **Integrity / tamper-evidence**: any modification of ciphertext, header, or
   chunk order is detected before plaintext is released, via twelve per-chunk
   AEAD/HMAC checks, the header HMAC, and the footer chain.
3. **Password-guessing resistance** proportional to the configured memory-hard
   cost (256 MB – 4 GB per guess).
4. **Post-quantum confidentiality** (hybrid mode only) of the key-exchange step
   via ML-KEM-1024, retaining classical security if ML-KEM is broken.
5. **Key commitment**: a ciphertext decrypts under exactly one key set.

The design does **not** claim:

- Formal proof of security (there is none; this is a construction, not a theorem).
- Plausible-deniability / hidden-volume properties (duress hides content, not the
  existence of prior data of a given size).
- Protection against a compromised endpoint (keylogger, memory scraper, malicious
  OS) — see THREAT_MODEL.md.
- Resistance to side channels beyond the constant-time tag/commitment comparisons
  noted in the code (no claim of constant-time cipher primitives beyond what the
  underlying libraries provide).

---

## 10. Audit fork

Per the project owner's instruction — *do not weaken the shipping product for
audit-readiness; fork instead* — a reduced variant lives in
`core-python-audit/`. It is **byte-compatible for the non-destructive path** and
differs only as follows:

| Aspect | Shipping (`core-python`) | Audit fork (`core-python-audit`) |
|--------|--------------------------|----------------------------------|
| Trap wrong-code behavior | Overwrites header, destroys file | Raises `TrapVerificationError`, file untouched |
| Duress password behavior | Decrypts decoy, wipes real data | Decrypts decoy, **leaves real data intact**; returns a flag |
| File mutation on decrypt | Yes (destructive paths) | Never mutates input |
| Crypto core (KDF, cascade, format, commitment, footer) | — | **Identical** |

This lets a reviewer analyze the cryptographic core with zero destructive side
effects, then separately review the ~40 lines of destructive I/O that the fork
removes. Both share the same test vectors (§11) for the crypto core.

---

## 11. Test vectors and determinism

Full-ciphertext test vectors are **not** byte-reproducible because padding content
is random per chunk. To enable deterministic vectors, the test suite pins `salt`,
`nonce_seed`, and monkeypatches padding to zero-content of the derived length, and
asserts:

- **KDF determinism**: fixed (password, salt) → fixed 11 sub-keys and commitment.
- **Round-trip**: `decrypt(encrypt(x)) == x` across sizes and levels.
- **Cross-implementation**: the same header, given identical pinned inputs,
  serializes to identical bytes (offsets test).
- **Negative**: wrong password, bit-flip in each region, truncation, reordering,
  wrong trap code/order, duress path.

See `tests/` and `tests/vectors/`.

---

## 12. Known limitations (summary for reviewers)

1. Footer uses prefix-keyed SHA3-256, not HMAC/KMAC (§7.3).
2. XOR combiner operands are not independent (§4).
3. AEAD layers do not bind chunk index as associated data (§5.4).
4. Padding hides length only within a 256–4096 B window (§5.2).
5. scrypt_N field is LE32 (§3).
6. Duress hides content, not the existence of prior data of a given size (§8.2).
7. No formal proof; relies on the security of standard primitives and the
   defense-in-depth cascade argument.

These are stated up front so a paid audit spends its time on discovery, not on
rediscovering what the authors already know.
