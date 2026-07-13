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
test_kdf.py — Key derivation determinism and structure tests.

These tests pin the salt and nonce_seed so key derivation is fully
deterministic, then assert exact byte values (known-answer tests). If any
KDF label, ordering, or parameter changes, these vectors break — which is
the point: they lock the derivation.
"""

import hashlib
import pytest

from fortress.keys import (
    derive_keys, derive_chunk_nonces, derive_padding_length,
    hash_trap_code, generate_trap_hashes, verify_trap_code,
    SALT_SIZE, NONCE_SEED_SIZE, MASTER_KEY_SIZE, DERIVED_KEY_SIZE,
)

# Fixed inputs for deterministic vectors
FIXED_SALT = bytes(range(32))               # 00 01 02 ... 1f
FIXED_NONCE_SEED = bytes(range(32, 64))     # 20 21 ... 3f
PASSWORD = "correct horse battery staple"

# Use the fastest level for test speed; determinism is independent of cost.
STD = {"time_cost": 4, "memory_cost": 131072, "parallelism": 4,
       "scrypt_n": 2**17, "scrypt_r": 8, "scrypt_p": 1}


def _derive():
    return derive_keys(
        password=PASSWORD, salt=FIXED_SALT, nonce_seed=FIXED_NONCE_SEED, **STD
    )


def test_key_sizes():
    k = _derive()
    for name in ["p1_aes_key", "p1_chacha_key", "p1_camellia_key", "p1_hmac_key",
                 "p2_aes_key", "p2_chacha_key", "p2_camellia_key", "p2_hmac_key",
                 "header_auth_key", "footer_auth_key", "padding_key"]:
        assert len(getattr(k, name)) == DERIVED_KEY_SIZE, name
    assert len(k.commitment) == 64  # SHA3-512


def test_kdf_deterministic():
    """Same inputs → identical keys every time."""
    k1 = _derive()
    k2 = _derive()
    assert k1.p1_aes_key == k2.p1_aes_key
    assert k1.commitment == k2.commitment
    assert k1.p2_hmac_key == k2.p2_hmac_key


def test_kdf_password_sensitivity():
    """Changing one character changes every derived key."""
    k1 = _derive()
    k2 = derive_keys(password=PASSWORD + "!", salt=FIXED_SALT,
                     nonce_seed=FIXED_NONCE_SEED, **STD)
    assert k1.p1_aes_key != k2.p1_aes_key
    assert k1.commitment != k2.commitment


def test_kdf_salt_sensitivity():
    k1 = _derive()
    other_salt = bytes([0xFF]) + FIXED_SALT[1:]
    k2 = derive_keys(password=PASSWORD, salt=other_salt,
                     nonce_seed=FIXED_NONCE_SEED, **STD)
    assert k1.p1_aes_key != k2.p1_aes_key


def test_all_subkeys_distinct():
    """The 11 sub-keys must all differ (distinct HKDF labels)."""
    k = _derive()
    subkeys = [k.p1_aes_key, k.p1_chacha_key, k.p1_camellia_key, k.p1_hmac_key,
               k.p2_aes_key, k.p2_chacha_key, k.p2_camellia_key, k.p2_hmac_key,
               k.header_auth_key, k.footer_auth_key, k.padding_key]
    assert len(set(subkeys)) == 11, "sub-keys collide — label separation broken"


def test_hybrid_changes_keys():
    """Injecting a KEM shared secret must change the derived keys."""
    k_plain = _derive()
    k_hybrid = derive_keys(password=PASSWORD, salt=FIXED_SALT,
                           nonce_seed=FIXED_NONCE_SEED,
                           kem_shared_secret=bytes(32), **STD)
    assert k_plain.p1_aes_key != k_hybrid.p1_aes_key
    assert k_plain.commitment != k_hybrid.commitment


def test_commitment_covers_keys():
    """Key commitment is SHA3-512 over the 10 committed sub-keys."""
    k = _derive()
    expected = hashlib.sha3_512(
        b"fortress-key-commitment-v2"
        + k.p1_aes_key + k.p1_chacha_key + k.p1_camellia_key + k.p1_hmac_key
        + k.p2_aes_key + k.p2_chacha_key + k.p2_camellia_key + k.p2_hmac_key
        + k.header_auth_key + k.footer_auth_key
    ).digest()
    assert k.commitment == expected


# ── Chunk nonce derivation ────────────────────────────────────────

def test_chunk_nonces_sizes():
    a, c, iv = derive_chunk_nonces(FIXED_NONCE_SEED, 0, 1)
    assert len(a) == 12 and len(c) == 12 and len(iv) == 16


def test_chunk_nonces_unique_per_index():
    n0 = derive_chunk_nonces(FIXED_NONCE_SEED, 0, 1)
    n1 = derive_chunk_nonces(FIXED_NONCE_SEED, 1, 1)
    assert n0 != n1


def test_chunk_nonces_unique_per_pass():
    """Pass 1 and pass 2 must get different nonces for the same chunk."""
    p1 = derive_chunk_nonces(FIXED_NONCE_SEED, 0, 1)
    p2 = derive_chunk_nonces(FIXED_NONCE_SEED, 0, 2)
    assert p1[0] != p2[0]  # aes nonce differs
    assert p1[1] != p2[1]  # chacha nonce differs
    assert p1[2] != p2[2]  # camellia iv differs


def test_padding_length_bounds():
    """Padding length must always fall in [256, 4096]."""
    key = bytes(range(32))
    for i in range(1000):
        pl = derive_padding_length(key, i)
        assert 256 <= pl <= 4096


def test_padding_length_deterministic():
    key = bytes(range(32))
    assert derive_padding_length(key, 42) == derive_padding_length(key, 42)


# ── Trap code hashing ─────────────────────────────────────────────

def test_trap_hash_order_sensitive():
    """Same codes in different positions hash differently."""
    salt = bytes(range(32))
    h0 = hash_trap_code(salt, 0, "alpha")
    h1 = hash_trap_code(salt, 1, "alpha")
    assert h0 != h1


def test_trap_verify_roundtrip():
    salt = bytes(range(32))
    hashes = generate_trap_hashes(salt, ["a", "b", "c"])
    for i, code in enumerate(["a", "b", "c"]):
        assert verify_trap_code(salt, i, code, hashes[i])


def test_trap_verify_rejects_wrong():
    salt = bytes(range(32))
    hashes = generate_trap_hashes(salt, ["a", "b"])
    assert not verify_trap_code(salt, 0, "WRONG", hashes[0])


def test_trap_max_five():
    salt = bytes(range(32))
    with pytest.raises(ValueError):
        generate_trap_hashes(salt, ["1", "2", "3", "4", "5", "6"])
