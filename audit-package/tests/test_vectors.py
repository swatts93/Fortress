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
test_vectors.py — Locks the deterministic KDF vectors in tests/vectors/kdf_vectors.json.

If any KDF label, ordering, parameter, or primitive changes, these assertions
break. A conforming port (Swift/Kotlin) can load the same JSON and verify it
produces identical output, giving cross-implementation assurance.
"""

import json
import os
import pytest

from fortress.keys import (
    derive_keys, derive_chunk_nonces, derive_padding_length, hash_trap_code,
)

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors", "kdf_vectors.json")


@pytest.fixture(scope="module")
def vectors():
    if not os.path.exists(VECTORS):
        pytest.skip("kdf_vectors.json not present")
    with open(VECTORS) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def keys(vectors):
    inp = vectors["inputs"]
    return derive_keys(
        password=inp["password_utf8"],
        salt=bytes.fromhex(inp["salt_hex"]),
        nonce_seed=bytes.fromhex(inp["nonce_seed_hex"]),
        time_cost=inp["argon2id"]["time_cost"],
        memory_cost=inp["argon2id"]["memory_cost_kib"],
        parallelism=inp["argon2id"]["parallelism"],
        scrypt_n=inp["scrypt"]["N"],
        scrypt_r=inp["scrypt"]["r"],
        scrypt_p=inp["scrypt"]["p"],
    )


def test_derived_keys_match_vectors(vectors, keys):
    dk = vectors["derived_keys_hex"]
    assert keys.p1_aes_key.hex() == dk["p1_aes"]
    assert keys.p1_chacha_key.hex() == dk["p1_chacha"]
    assert keys.p1_camellia_key.hex() == dk["p1_camellia"]
    assert keys.p1_hmac_key.hex() == dk["p1_hmac"]
    assert keys.p2_aes_key.hex() == dk["p2_aes"]
    assert keys.p2_chacha_key.hex() == dk["p2_chacha"]
    assert keys.p2_camellia_key.hex() == dk["p2_camellia"]
    assert keys.p2_hmac_key.hex() == dk["p2_hmac"]
    assert keys.header_auth_key.hex() == dk["header_auth"]
    assert keys.footer_auth_key.hex() == dk["footer_auth"]
    assert keys.padding_key.hex() == dk["padding"]


def test_commitment_matches_vector(vectors, keys):
    assert keys.commitment.hex() == vectors["key_commitment_hex"]


def test_chunk_nonces_match_vectors(vectors, keys):
    nonce_seed = bytes.fromhex(vectors["inputs"]["nonce_seed_hex"])
    n0 = derive_chunk_nonces(nonce_seed, 0, 1)
    cn = vectors["chunk_nonces"]["chunk0_pass1"]
    assert n0[0].hex() == cn["aes"]
    assert n0[1].hex() == cn["chacha"]
    assert n0[2].hex() == cn["camellia_iv"]


def test_padding_lengths_match_vectors(vectors, keys):
    for idx_str, expected in vectors["padding_lengths"].items():
        assert derive_padding_length(keys.padding_key, int(idx_str)) == expected


def test_trap_hashes_match_vectors(vectors):
    th = vectors["trap_hash_examples"]
    salt = bytes.fromhex(th["salt_hex"])
    assert hash_trap_code(salt, 0, "alpha").hex() == th["index0_alpha"]
    assert hash_trap_code(salt, 1, "alpha").hex() == th["index1_alpha"]
