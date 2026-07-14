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
FORTRESS v2 — 6-Layer Double-Cascade Encryption with Traps & Duress

  KDF:     Argon2id → scrypt → HKDF-SHA512
  Cipher:  [Camellia-256 → ChaCha20 → AES-256] × 2 (6 layers)
  PQ:      ML-KEM-1024 (NIST FIPS 203)
  Auth:    HMAC-SHA512 + Poly1305 + GHASH + SHA3-256
  Traps:   Sequential codes — wrong order destroys file
  Duress:  Dead man's switch — fake password decrypts dummy data. At
           paranoid/fortress security levels this also automatically wipes
           the real data; at standard/high it does not (that automatic wipe
           can never be cryptographically tied to the real password, so it's
           opt-in there — call destroy_real_data_after_duress() explicitly).
           See AUDIT_FINDINGS.md FC-02.
"""

__version__ = "2.0.0"

from .api import (
    encrypt_file, decrypt_file,
    encrypt_message, decrypt_message,
    verify_trap_sequence, TrapTriggered,
    destroy_real_data_after_duress,
)
from .pq import generate_keypair, save_keypair, load_public_key, load_secret_key

__all__ = [
    "encrypt_file", "decrypt_file",
    "encrypt_message", "decrypt_message",
    "verify_trap_sequence", "TrapTriggered",
    "destroy_real_data_after_duress",
    "generate_keypair", "save_keypair", "load_public_key", "load_secret_key",
]
