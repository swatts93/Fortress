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

"""Fortress Post-Quantum — ML-KEM-1024 (NIST FIPS 203, Level 5)"""

import os, json, base64
from pathlib import Path
from typing import Tuple

try:
    from pqcrypto.kem.ml_kem_1024 import (
        generate_keypair as _keygen, encrypt as _encaps, decrypt as _decaps,
        PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE,
    )
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False
    PUBLIC_KEY_SIZE = SECRET_KEY_SIZE = CIPHERTEXT_SIZE = 0

KEM_ALGORITHM = "ML-KEM-1024"

def is_available(): return PQ_AVAILABLE

def generate_keypair() -> Tuple[bytes, bytes]:
    if not PQ_AVAILABLE: raise RuntimeError("pqcrypto not installed")
    return _keygen()

def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    if not PQ_AVAILABLE: raise RuntimeError("pqcrypto not installed")
    return _encaps(public_key)

def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    if not PQ_AVAILABLE: raise RuntimeError("pqcrypto not installed")
    return _decaps(secret_key, ciphertext)

def save_keypair(pk, sk, directory, name="fortress"):
    d = Path(directory); d.mkdir(parents=True, exist_ok=True)
    pub_path, sec_path = d / f"{name}.pub.json", d / f"{name}.sec.json"
    with open(pub_path, "w") as f:
        json.dump({"algorithm": KEM_ALGORITHM, "type": "public",
                    "key": base64.b64encode(pk).decode(), "size": len(pk)}, f, indent=2)
    with open(sec_path, "w") as f:
        json.dump({"algorithm": KEM_ALGORITHM, "type": "secret",
                    "key": base64.b64encode(sk).decode(), "size": len(sk),
                    "warning": "KEEP SECRET."}, f, indent=2)
    try: os.chmod(sec_path, 0o600)
    except OSError: pass
    return str(pub_path), str(sec_path)

def load_public_key(path):
    with open(path) as f: data = json.load(f)
    if data.get("type") != "public": raise ValueError("Not a public key")
    return base64.b64decode(data["key"])

def load_secret_key(path):
    with open(path) as f: data = json.load(f)
    if data.get("type") != "secret": raise ValueError("Not a secret key")
    return base64.b64decode(data["key"])
