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
Fortress Double-Cascade Encryption Engine — 6 LAYERS

  PASS 1: plaintext+padding → Camellia-256-CBC+HMAC → ChaCha20 → AES-256-GCM
  PASS 2: pass1_output      → Camellia-256-CBC+HMAC → ChaCha20 → AES-256-GCM
"""

import os
import struct
import hmac as hmac_mod
import hashlib

from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

from .keys import FortressKeys, derive_chunk_nonces, derive_padding_length

DEFAULT_CHUNK_SIZE = 1048576
GCM_TAG = 16
POLY1305_TAG = 16
HMAC512_TAG = 64


def _camellia_encrypt(pt, key, hmac_key, iv, chunk_idx, pass_num):
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(pt) + padder.finalize()
    enc = Cipher(algorithms.Camellia(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    auth = struct.pack("<QI", chunk_idx, pass_num) + iv + ct
    tag = hmac_mod.new(hmac_key, auth, hashlib.sha512).digest()
    return ct + tag

def _camellia_decrypt(data, key, hmac_key, iv, chunk_idx, pass_num):
    ct, tag = data[:-HMAC512_TAG], data[-HMAC512_TAG:]
    auth = struct.pack("<QI", chunk_idx, pass_num) + iv + ct
    expected = hmac_mod.new(hmac_key, auth, hashlib.sha512).digest()
    if not hmac_mod.compare_digest(tag, expected):
        raise ValueError(f"Camellia HMAC FAILED [chunk={chunk_idx}, pass={pass_num}]")
    dec = Cipher(algorithms.Camellia(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def _chacha_encrypt(pt, key, nonce):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct + tag

def _chacha_decrypt(data, key, nonce, chunk_idx, pass_num):
    ct, tag = data[:-POLY1305_TAG], data[-POLY1305_TAG:]
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        raise ValueError(f"ChaCha20 auth FAILED [chunk={chunk_idx}, pass={pass_num}]")

def _aes_encrypt(pt, key, nonce):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct + tag

def _aes_decrypt(data, key, nonce, chunk_idx, pass_num):
    ct, tag = data[:-GCM_TAG], data[-GCM_TAG:]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        raise ValueError(f"AES-256-GCM auth FAILED [chunk={chunk_idx}, pass={pass_num}]")


def _cascade_encrypt(data, aes_key, chacha_key, camellia_key, hmac_key,
                     nonce_seed, chunk_idx, pass_num):
    aes_n, chacha_n, cam_iv = derive_chunk_nonces(nonce_seed, chunk_idx, pass_num)
    l1 = _camellia_encrypt(data, camellia_key, hmac_key, cam_iv, chunk_idx, pass_num)
    l2 = _chacha_encrypt(l1, chacha_key, chacha_n)
    l3 = _aes_encrypt(l2, aes_key, aes_n)
    return l3

def _cascade_decrypt(data, aes_key, chacha_key, camellia_key, hmac_key,
                     nonce_seed, chunk_idx, pass_num):
    aes_n, chacha_n, cam_iv = derive_chunk_nonces(nonce_seed, chunk_idx, pass_num)
    l2 = _aes_decrypt(data, aes_key, aes_n, chunk_idx, pass_num)
    l1 = _chacha_decrypt(l2, chacha_key, chacha_n, chunk_idx, pass_num)
    return _camellia_decrypt(l1, camellia_key, hmac_key, cam_iv, chunk_idx, pass_num)


def encrypt_chunk(plaintext: bytes, keys: FortressKeys, chunk_index: int) -> bytes:
    pad_len = derive_padding_length(keys.padding_key, chunk_index)
    padding = os.urandom(pad_len)
    padded_pt = struct.pack("<H", pad_len) + padding + plaintext

    after_p1 = _cascade_encrypt(
        padded_pt, keys.p1_aes_key, keys.p1_chacha_key,
        keys.p1_camellia_key, keys.p1_hmac_key,
        keys.nonce_seed, chunk_index, pass_num=1,
    )
    after_p2 = _cascade_encrypt(
        after_p1, keys.p2_aes_key, keys.p2_chacha_key,
        keys.p2_camellia_key, keys.p2_hmac_key,
        keys.nonce_seed, chunk_index, pass_num=2,
    )
    return after_p2


def decrypt_chunk(encrypted: bytes, keys: FortressKeys, chunk_index: int) -> bytes:
    after_p1 = _cascade_decrypt(
        encrypted, keys.p2_aes_key, keys.p2_chacha_key,
        keys.p2_camellia_key, keys.p2_hmac_key,
        keys.nonce_seed, chunk_index, pass_num=2,
    )
    padded_pt = _cascade_decrypt(
        after_p1, keys.p1_aes_key, keys.p1_chacha_key,
        keys.p1_camellia_key, keys.p1_hmac_key,
        keys.nonce_seed, chunk_index, pass_num=1,
    )
    pad_len = struct.unpack("<H", padded_pt[:2])[0]
    return padded_pt[2 + pad_len:]
