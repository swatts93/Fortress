# Fortress Crypt — 6-layer cascade encryption system
# Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing without the AGPL's copyleft obligations,
# contact the Maintainer (see README).

"""
Fortress Key Derivation — v2 with Trap + Duress support

Triple-chained: Argon2id → scrypt → HKDF-SHA512
Derives dual key sets for double cascade, plus duress keys.
"""

import os
import struct
import hashlib
from dataclasses import dataclass
from typing import Optional, List

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

ARGON2_PRESETS = {
    "standard": {"time_cost": 4,  "memory_cost": 131072,  "parallelism": 4},
    "high":     {"time_cost": 6,  "memory_cost": 524288,  "parallelism": 4},
    "paranoid": {"time_cost": 10, "memory_cost": 1048576, "parallelism": 8},
    "fortress": {"time_cost": 14, "memory_cost": 2097152, "parallelism": 8},
}
SCRYPT_PRESETS = {
    "standard": {"n": 2**17, "r": 8, "p": 1},
    "high":     {"n": 2**19, "r": 8, "p": 1},
    "paranoid": {"n": 2**20, "r": 8, "p": 2},
    "fortress": {"n": 2**21, "r": 8, "p": 2},
}

SALT_SIZE = 32
MASTER_KEY_SIZE = 64
DERIVED_KEY_SIZE = 32
NONCE_SEED_SIZE = 32
TRAP_HASH_SIZE = 32
TRAP_SALT_SIZE = 32
MAX_TRAPS = 5


@dataclass
class FortressKeys:
    p1_aes_key: bytes
    p1_chacha_key: bytes
    p1_camellia_key: bytes
    p1_hmac_key: bytes
    p2_aes_key: bytes
    p2_chacha_key: bytes
    p2_camellia_key: bytes
    p2_hmac_key: bytes
    header_auth_key: bytes
    footer_auth_key: bytes
    padding_key: bytes
    nonce_seed: bytes
    commitment: bytes

    def wipe(self):
        for field_name in [
            'p1_aes_key', 'p1_chacha_key', 'p1_camellia_key', 'p1_hmac_key',
            'p2_aes_key', 'p2_chacha_key', 'p2_camellia_key', 'p2_hmac_key',
            'header_auth_key', 'footer_auth_key', 'padding_key', 'nonce_seed',
        ]:
            try:
                object.__setattr__(self, field_name, bytes(DERIVED_KEY_SIZE))
            except Exception:
                pass


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def generate_nonce_seed() -> bytes:
    return os.urandom(NONCE_SEED_SIZE)


def _argon2id(password: bytes, salt: bytes, time_cost: int,
              memory_cost: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=time_cost, memory_cost=memory_cost,
        parallelism=parallelism, hash_len=MASTER_KEY_SIZE, type=Type.ID,
    )

def _scrypt(key_material: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=MASTER_KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(key_material)

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = DERIVED_KEY_SIZE) -> bytes:
    return HKDF(
        algorithm=hashes.SHA512(), length=length, salt=salt, info=info,
    ).derive(ikm)

def _key_commitment(keys_material: bytes) -> bytes:
    return hashlib.sha3_512(b"fortress-key-commitment-v2" + keys_material).digest()


def derive_keys(
    password: str, salt: bytes, nonce_seed: bytes,
    time_cost: int = 4, memory_cost: int = 131072, parallelism: int = 4,
    scrypt_n: int = 2**17, scrypt_r: int = 8, scrypt_p: int = 1,
    kem_shared_secret: Optional[bytes] = None,
) -> FortressKeys:
    pw = password.encode("utf-8") if isinstance(password, str) else password

    phase1 = _argon2id(pw, salt, time_cost, memory_cost, parallelism)
    if kem_shared_secret is not None:
        phase1 = _hkdf(phase1 + kem_shared_secret, salt,
                        b"fortress-hybrid-pre-scrypt-v2", MASTER_KEY_SIZE)

    scrypt_salt = hashlib.sha3_256(b"fortress-scrypt-salt-v2" + salt).digest()
    phase2 = _scrypt(phase1, scrypt_salt, n=scrypt_n, r=scrypt_r, p=scrypt_p)

    combined = bytes(a ^ b for a, b in zip(phase1, phase2))
    master = _hkdf(combined, salt, b"fortress-master-key-v2", MASTER_KEY_SIZE)

    p1a = _hkdf(master, salt, b"fortress-p1-aes256gcm-v2")
    p1c = _hkdf(master, salt, b"fortress-p1-chacha20poly1305-v2")
    p1m = _hkdf(master, salt, b"fortress-p1-camellia256cbc-v2")
    p1h = _hkdf(master, salt, b"fortress-p1-hmac-sha512-v2")
    p2a = _hkdf(master, salt, b"fortress-p2-aes256gcm-v2")
    p2c = _hkdf(master, salt, b"fortress-p2-chacha20poly1305-v2")
    p2m = _hkdf(master, salt, b"fortress-p2-camellia256cbc-v2")
    p2h = _hkdf(master, salt, b"fortress-p2-hmac-sha512-v2")
    hdr = _hkdf(master, salt, b"fortress-header-auth-sha256-v2")
    ftr = _hkdf(master, salt, b"fortress-footer-auth-sha3-256-v2")
    pad = _hkdf(master, salt, b"fortress-padding-key-v2")
    commitment = _key_commitment(p1a + p1c + p1m + p1h + p2a + p2c + p2m + p2h + hdr + ftr)

    return FortressKeys(
        p1_aes_key=p1a, p1_chacha_key=p1c, p1_camellia_key=p1m, p1_hmac_key=p1h,
        p2_aes_key=p2a, p2_chacha_key=p2c, p2_camellia_key=p2m, p2_hmac_key=p2h,
        header_auth_key=hdr, footer_auth_key=ftr, padding_key=pad,
        nonce_seed=nonce_seed, commitment=commitment,
    )


def derive_chunk_nonces(nonce_seed: bytes, chunk_index: int, cascade_pass: int) -> tuple:
    ctx = struct.pack("<QI", chunk_index, cascade_pass)
    aes_nonce = _hkdf(nonce_seed, ctx, b"fortress-aes-nonce", length=12)
    chacha_nonce = _hkdf(nonce_seed, ctx, b"fortress-chacha-nonce", length=12)
    camellia_iv = _hkdf(nonce_seed, ctx, b"fortress-camellia-iv", length=16)
    return aes_nonce, chacha_nonce, camellia_iv


def derive_padding_length(padding_key: bytes, chunk_index: int,
                          min_pad: int = 256, max_pad: int = 4096) -> int:
    ctx = struct.pack("<Q", chunk_index)
    raw = _hkdf(padding_key, ctx, b"fortress-pad-len", length=4)
    return min_pad + (struct.unpack("<I", raw)[0] % (max_pad - min_pad + 1))


# ═══════════════════════════════════════════════════════════════
#  TRAP SEQUENCE
# ═══════════════════════════════════════════════════════════════

def generate_trap_salt() -> bytes:
    return os.urandom(TRAP_SALT_SIZE)


def hash_trap_code(trap_salt: bytes, index: int, code: str) -> bytes:
    """Hash a single trap code with its position index (order-sensitive)."""
    data = trap_salt + struct.pack("<I", index) + code.encode("utf-8")
    return hashlib.sha3_256(data).digest()


def generate_trap_hashes(trap_salt: bytes, codes: List[str]) -> List[bytes]:
    """Generate ordered hashes for a sequence of trap codes."""
    if len(codes) > MAX_TRAPS:
        raise ValueError(f"Maximum {MAX_TRAPS} trap codes allowed")
    return [hash_trap_code(trap_salt, i, code) for i, code in enumerate(codes)]


def verify_trap_code(trap_salt: bytes, index: int, code: str,
                     expected_hash: bytes) -> bool:
    """Verify a single trap code at a specific position."""
    import hmac as hmac_mod
    computed = hash_trap_code(trap_salt, index, code)
    return hmac_mod.compare_digest(computed, expected_hash)
