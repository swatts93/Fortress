# Fortress Crypt

A 6-layer double-cascade encryption system with post-quantum key derivation, trap sequences, and duress protection. Available as a Python library/CLI, an iOS app, and an Android app — all sharing a single interoperable file format.

---

## What's in this package

```
fortress-crypt-suite/
├── core-python/          Reference implementation (library + CLI)
├── ios/                  Native iOS app (Swift + SwiftUI)
├── android/              Native Android app (Kotlin + Jetpack Compose)
├── branding/             Logo suite (SVG + showcase)
├── README.md             This file
└── CHANGELOG.md          Version history and audit fixes
```

A `.fortress` file encrypted on any one platform decrypts on all three.

---

## The encryption design

### Cipher cascade (6 layers)
Every chunk passes through two independent cascades:

```
Pass 1:  Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM   (key set 1)
Pass 2:  Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM   (key set 2)
```

An attacker must break all three cipher families, twice, with independent keys. All 12 authentication tags per chunk must verify or decryption halts.

### Key derivation (triple chain)
```
password → Argon2id → scrypt → HKDF-SHA512 → master key → 12 sub-keys
```
Two independent memory-hard functions (Argon2id and scrypt) are XOR-combined, so a weakness in either alone does not compromise the master key. Optional ML-KEM-1024 shared secret can be mixed in for post-quantum hybrid mode.

### Security features
| Feature | Purpose |
|---------|---------|
| Key commitment (SHA3-512) | Prevents key-switching attacks |
| Dual hash families | SHA-2 (header) + SHA-3 (footer) authentication |
| Anti-forensic padding | Random padding per chunk hides content patterns |
| Trap sequence | Ordered codes; a wrong entry destroys the file header (only ever enforced once the real password has authenticated the header — see CHANGELOG 2.0.4 FC-01) |
| Duress mode | A secondary password decrypts decoy data. At `paranoid`/`fortress` levels this also wipes the real data automatically; at `standard`/`high` it does not by default (call `destroy_real_data_after_duress()` explicitly) — see CHANGELOG 2.0.4 FC-02 |
| Constant-time comparison | All authentication checks resist timing side-channels |

### Security levels
| Level | Argon2id | scrypt | Combined memory |
|-------|----------|--------|-----------------|
| standard | 128 MB | ~128 MB | ~256 MB |
| high | 512 MB | ~512 MB | ~1 GB |
| paranoid | 1 GB | ~1 GB | ~2 GB (default) |
| fortress | 2 GB | ~2 GB | ~4 GB |

---

## Quick start (Python)

```bash
cd core-python
pip install -e ".[pq]"

fortress encrypt secret.pdf --level paranoid
fortress decrypt secret.pdf.fortress
```

See `core-python/README.md` for the full API and CLI reference.

## Building the apps

- **iOS**: open `ios/` in Xcode, follow `ios/BUILD_INSTRUCTIONS.md` (requires OpenSSL + libargon2 via SPM/CocoaPods).
- **Android**: open `android/` in Android Studio and run. All crypto is provided by Bouncy Castle + argon2kt — no native compilation needed.

---

## A note on the design philosophy

This system layers well-vetted, standardized primitives (AES, ChaCha20, Camellia, Argon2id, scrypt, ML-KEM) rather than inventing new cryptography. The strength comes from cascading independent, peer-reviewed algorithms so that no single break compromises the data. This is the same principle behind cascade encryption in tools like VeraCrypt.

It has **not** undergone formal third-party cryptographic audit. For protecting real high-value data against sophisticated adversaries, use established, audited tools (VeraCrypt, age, LUKS). Treat Fortress as a serious engineering project and a defense-in-depth design study.

## License
MIT
