# FORTRESS v2 — 6-Layer Double-Cascade Encryption

**Post-quantum hybrid encryption with triple-chained KDF, trap sequences, duress dead man's switch, anti-forensic padding, and dual hash-family authentication.**

---

## What's New in v2

### Trap Sequence (Pitfalls)
Set 1–5 sequential codes during encryption. During decryption, they must be entered **in the exact correct order** before the password is even prompted. **Get any code wrong → the file header is permanently overwritten with random data. No second chances. No recovery. Ever.**

### Duress Mode (Dead Man's Switch)
Set a secondary "duress" password during encryption along with dummy data. If someone forces you to decrypt:
1. Enter the duress password
2. Dummy data decrypts normally (looks legit)
3. Real data is **silently and permanently wiped** from the file
4. The file now looks like it only ever contained the dummy data

---

## Architecture

```
PASSWORD ──► Argon2id (2GB) ──► scrypt (2GB) ──► HKDF-SHA512
                                                      │
                [+ ML-KEM-1024 shared secret]         │
                                                 MASTER KEY
                                                 ┌────┴────┐
                                            KEY SET 1   KEY SET 2
                                                 │         │
                  ╔══════════════════════════════════════════╗
                  ║       DOUBLE CASCADE (per chunk)         ║
                  ║  Pass 1: Camellia→ChaCha→AES (set 1)    ║
                  ║  Pass 2: Camellia→ChaCha→AES (set 2)    ║
                  ║  = 6 layers, 12 auth checks              ║
                  ╚══════════════════════════════════════════╝
```

## Quick Start

```bash
pip install pycryptodome cryptography argon2-cffi click pqcrypto
cd fortress-crypt && pip install -e ".[pq]"
```

### Basic Encryption

```python
from fortress import encrypt_file, decrypt_file

encrypt_file("secret.img", "secret.fortress", password="strong-password")
decrypt_file("secret.fortress", "secret.img", password="strong-password")
```

### With Trap Codes (Pitfall Sequence)

```python
# Set 3 ordered trap codes — wrong order = file destroyed
encrypt_file("data.bin", "data.fortress",
    password="real-password",
    trap_codes=["alpha", "bravo", "charlie"])

# Must enter ALL codes in CORRECT ORDER, then password
decrypt_file("data.fortress", "data.bin",
    password="real-password",
    trap_codes=["alpha", "bravo", "charlie"])

# Wrong code at ANY position → TrapTriggered exception + file destroyed
```

### With Duress Mode (Dead Man's Switch)

```python
# Encrypt with real password + duress password + dummy data
encrypt_file("classified.bin", "classified.fortress",
    password="real-password",
    duress_password="give-them-this-one",
    duress_data=b"Nothing sensitive here, just my notes.")

# Real password → real data
decrypt_file("classified.fortress", "output.bin", password="real-password")
# → output.bin contains real data

# Duress password → dummy data + REAL DATA PERMANENTLY DESTROYED
decrypt_file("classified.fortress", "output.bin", password="give-them-this-one")
# → output.bin contains "Nothing sensitive here..."
# → real data wiped from .fortress file forever
```

### Combined: Traps + Duress + Post-Quantum

```python
from fortress import encrypt_file, decrypt_file
from fortress.pq import generate_keypair

pk, sk = generate_keypair()

encrypt_file("ultimate.bin", "ultimate.fortress",
    password="real-password",
    pq_public_key=pk,
    security_level="paranoid",
    trap_codes=["gate1", "gate2", "gate3"],
    duress_password="fake-password",
    duress_data=b"My cat photo collection metadata")

# Full decryption requires:
# 1. Correct trap codes in correct order (wrong = destroyed)
# 2. Real password (duress password = dummy data + destroy real)
# 3. PQ secret key
decrypt_file("ultimate.fortress", "ultimate.bin",
    password="real-password",
    pq_secret_key=sk,
    trap_codes=["gate1", "gate2", "gate3"])
```

### CLI

```bash
# Encrypt with 3 trap codes + duress mode
fortress encrypt secret.img --traps 3 --duress --duress-file dummy.txt --level paranoid

# Decrypt (prompts for trap codes first, then password)
fortress decrypt secret.img.fortress

# Messages with traps
fortress msg-enc "classified" --traps 2
fortress msg-dec "FORTRESS:..."

# Post-quantum keypair
fortress keygen --name mykey
fortress encrypt data.bin --pq-key mykey.pub.json --traps 2 --duress
```

## Security Levels

| Level | Argon2id | scrypt | Total KDF RAM | Use Case |
|---|---|---|---|---|
| `standard` | 128MB | ~128MB | ~256 MB | Quick ops, messages |
| `high` | 512MB | ~512MB | ~1 GB | Sensitive files |
| `paranoid` | 1GB | ~1GB | ~2 GB | **Default.** High-value |
| `fortress` | 2GB | ~2GB | ~4 GB | Nation-state threat |

## Threat Model Summary

| Threat | Protection |
|---|---|
| Brute force | Triple-chained KDF (up to 4GB per guess) |
| Quantum computers | ML-KEM-1024 (NIST Level 5) |
| Single cipher break | 3 independent cipher families × 2 passes |
| Coerced decryption | Duress password → dummy data + destroy real |
| Sequential brute force | Trap codes → wrong attempt destroys file |
| Traffic analysis | Anti-forensic random padding per chunk |
| Key switching attacks | SHA3-512 key commitment |
| Hash family compromise | SHA-2 (header) + SHA-3 (footer) dual auth |
| Memory dumps | Best-effort key wiping after use |

## Dependencies

| Package | Purpose | Required |
|---|---|---|
| `pycryptodome` | AES-256-GCM, ChaCha20-Poly1305 | Yes |
| `cryptography` | Camellia-256-CBC, HKDF, scrypt | Yes |
| `argon2-cffi` | Argon2id password hashing | Yes |
| `click` | CLI interface | Yes |
| `pqcrypto` | ML-KEM-1024 post-quantum KEM | Optional |

## License

MIT
