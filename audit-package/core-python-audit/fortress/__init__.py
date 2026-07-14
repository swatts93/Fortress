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
FORTRESS v2 — AUDIT FORK (non-destructive)

Byte-compatible cryptographic core with the destructive behaviors removed so the
crypto can be reviewed in isolation. See docs/SPECIFICATION.md section 10.

  KDF:     Argon2id -> scrypt -> HKDF-SHA512
  Cipher:  [Camellia-256 -> ChaCha20 -> AES-256] x 2 (6 layers)
  PQ:      ML-KEM-1024 (NIST FIPS 203)
  Auth:    HMAC-SHA512 + Poly1305 + GHASH + keyed-SHA3-256

Differences from the shipping build:
  - Wrong trap code raises TrapVerificationError; the file is NOT modified.
  - Duress password decrypts the decoy but the real data is NOT wiped.
  - No decrypt path ever mutates the input file.

The crypto core (keys.py, engine.py, format.py serialization, commitments,
footer) is IDENTICAL to the shipping build and shares the same test vectors.
"""

__version__ = "2.0.1-audit"

from .api import (
    encrypt_file, decrypt_file,
    encrypt_message, decrypt_message,
    verify_trap_sequence, TrapTriggered, TrapVerificationError,
    destroy_real_data_after_duress,
)
from .pq import generate_keypair, save_keypair, load_public_key, load_secret_key

__all__ = [
    "encrypt_file", "decrypt_file",
    "encrypt_message", "decrypt_message",
    "verify_trap_sequence", "TrapTriggered", "TrapVerificationError",
    "destroy_real_data_after_duress",
    "generate_keypair", "save_keypair", "load_public_key", "load_secret_key",
]
