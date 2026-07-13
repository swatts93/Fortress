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
Fortress Binary File Format v2

Adds trap sequence and duress (dead man's switch) sections.

  ┌──────────────────────────────────────────────────────────────┐
  │ HEADER                                                       │
  │   Core fields (magic, version, mode, KDF params, etc.)       │
  │   Trap section (trap_count, trap_salt, trap_hashes)          │
  │   Duress section (duress salt, nonce, commitment, data size) │
  │   Real key commitment                                        │
  │   Header HMAC-SHA256                                         │
  ├──────────────────────────────────────────────────────────────┤
  │ DURESS ENCRYPTED DATA (if duress enabled)                    │
  │   [4B len][encrypted_chunk] × M                              │
  │   DURESS FOOTER HMAC (32B)                                   │
  ├──────────────────────────────────────────────────────────────┤
  │ REAL ENCRYPTED DATA                                          │
  │   [4B len][encrypted_chunk] × N                              │
  │   REAL FOOTER HMAC (32B)                                     │
  └──────────────────────────────────────────────────────────────┘

On duress password entry:
  1. Duress data decrypts normally
  2. Real data section overwritten with os.urandom()
  3. Real key commitment overwritten
  4. File rewritten to appear duress-only

On wrong trap code entry:
  1. Header salt, nonce_seed, all commitments overwritten with random
  2. File permanently unrecoverable
"""

import struct
import os
import hmac as hmac_mod
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, BinaryIO

MAGIC = b"FORTRESS"
FORMAT_VERSION = 2

MODE_PASSWORD = 0
MODE_PQ_ONLY = 1
MODE_HYBRID = 2

HEADER_HMAC_SIZE = 32
FOOTER_HMAC_SIZE = 32
KEY_COMMITMENT_SIZE = 64
TRAP_HASH_SIZE = 32
TRAP_SALT_SIZE = 32


@dataclass
class FortressHeader:
    version: int
    mode: int
    argon2_time: int
    argon2_memory: int
    argon2_parallelism: int
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    salt: bytes
    nonce_seed: bytes
    original_size: int
    chunk_size: int
    key_commitment: bytes
    kem_ciphertext: Optional[bytes]

    # Trap sequence
    trap_count: int = 0
    trap_salt: bytes = b"\x00" * TRAP_SALT_SIZE
    trap_hashes: List[bytes] = field(default_factory=list)

    # Duress (dead man's switch)
    duress_enabled: int = 0
    duress_salt: bytes = b"\x00" * 32
    duress_nonce_seed: bytes = b"\x00" * 32
    duress_key_commitment: bytes = b"\x00" * KEY_COMMITMENT_SIZE
    duress_data_size: int = 0
    duress_chunk_count: int = 0

    @property
    def total_chunks(self) -> int:
        if self.original_size == 0:
            return 0
        n = self.original_size // self.chunk_size
        if self.original_size % self.chunk_size > 0:
            n += 1
        return n


def _serialize(h: FortressHeader) -> bytes:
    buf = bytearray()
    buf.extend(MAGIC)
    buf.extend(struct.pack("<H", h.version))
    buf.extend(struct.pack("B", h.mode))
    buf.extend(struct.pack("<I", h.argon2_time))
    buf.extend(struct.pack("<I", h.argon2_memory))
    buf.extend(struct.pack("<I", h.argon2_parallelism))
    buf.extend(struct.pack("<I", h.scrypt_n))
    buf.extend(struct.pack("<I", h.scrypt_r))
    buf.extend(struct.pack("<I", h.scrypt_p))
    buf.extend(h.salt)
    buf.extend(h.nonce_seed)
    buf.extend(struct.pack("<Q", h.original_size))
    buf.extend(struct.pack("<I", h.chunk_size))
    buf.extend(h.key_commitment)
    kem = h.kem_ciphertext or b""
    buf.extend(struct.pack("<I", len(kem)))
    buf.extend(kem)

    # Trap section
    buf.extend(struct.pack("B", h.trap_count))
    buf.extend(h.trap_salt)
    for th in h.trap_hashes:
        buf.extend(th)

    # Duress section
    buf.extend(struct.pack("B", h.duress_enabled))
    buf.extend(h.duress_salt)
    buf.extend(h.duress_nonce_seed)
    buf.extend(h.duress_key_commitment)
    buf.extend(struct.pack("<Q", h.duress_data_size))
    buf.extend(struct.pack("<I", h.duress_chunk_count))

    return bytes(buf)


def write_header(f: BinaryIO, h: FortressHeader, auth_key: bytes) -> None:
    raw = _serialize(h)
    f.write(raw)
    mac = hmac_mod.new(auth_key, raw, hashlib.sha256).digest()
    f.write(mac)


def _parse_header_bytes(f: BinaryIO) -> tuple:
    """Parse header fields, return (header, raw_bytes_before_hmac, stored_hmac)."""
    start = f.tell()

    # Read fixed part (same as v1 but with version bump)
    fixed_size = 8 + 2 + 1 + (4*3) + (4*3) + 32 + 32 + 8 + 4 + 64 + 4
    fixed = f.read(fixed_size)
    if len(fixed) < fixed_size:
        raise ValueError("Not a valid Fortress file (too short)")
    if fixed[:8] != MAGIC:
        raise ValueError("Not a Fortress file (bad magic)")

    off = 8
    version = struct.unpack_from("<H", fixed, off)[0]; off += 2
    if version not in (1, 2):
        raise ValueError(f"Unsupported version: {version}")
    mode = fixed[off]; off += 1
    a_time = struct.unpack_from("<I", fixed, off)[0]; off += 4
    a_mem = struct.unpack_from("<I", fixed, off)[0]; off += 4
    a_par = struct.unpack_from("<I", fixed, off)[0]; off += 4
    s_n = struct.unpack_from("<I", fixed, off)[0]; off += 4
    s_r = struct.unpack_from("<I", fixed, off)[0]; off += 4
    s_p = struct.unpack_from("<I", fixed, off)[0]; off += 4
    salt = fixed[off:off+32]; off += 32
    nseed = fixed[off:off+32]; off += 32
    orig = struct.unpack_from("<Q", fixed, off)[0]; off += 8
    csz = struct.unpack_from("<I", fixed, off)[0]; off += 4
    commit = fixed[off:off+64]; off += 64
    kem_len = struct.unpack_from("<I", fixed, off)[0]; off += 4

    kem_ct = None
    if kem_len > 0:
        kem_ct = f.read(kem_len)

    # Trap section (v2+)
    trap_count = 0
    trap_salt = b"\x00" * TRAP_SALT_SIZE
    trap_hashes = []
    duress_enabled = 0
    duress_salt = b"\x00" * 32
    duress_nonce_seed = b"\x00" * 32
    duress_key_commitment = b"\x00" * KEY_COMMITMENT_SIZE
    duress_data_size = 0
    duress_chunk_count = 0

    if version >= 2:
        trap_byte = f.read(1)
        trap_count = trap_byte[0]
        trap_salt = f.read(TRAP_SALT_SIZE)
        trap_hashes = []
        for _ in range(trap_count):
            trap_hashes.append(f.read(TRAP_HASH_SIZE))

        # Duress section
        duress_byte = f.read(1)
        duress_enabled = duress_byte[0]
        duress_salt = f.read(32)
        duress_nonce_seed = f.read(32)
        duress_key_commitment = f.read(KEY_COMMITMENT_SIZE)
        duress_data_size = struct.unpack("<Q", f.read(8))[0]
        duress_chunk_count = struct.unpack("<I", f.read(4))[0]

    stored_hmac = f.read(HEADER_HMAC_SIZE)

    header = FortressHeader(
        version=version, mode=mode,
        argon2_time=a_time, argon2_memory=a_mem, argon2_parallelism=a_par,
        scrypt_n=s_n, scrypt_r=s_r, scrypt_p=s_p,
        salt=salt, nonce_seed=nseed,
        original_size=orig, chunk_size=csz,
        key_commitment=commit, kem_ciphertext=kem_ct,
        trap_count=trap_count, trap_salt=trap_salt, trap_hashes=trap_hashes,
        duress_enabled=duress_enabled,
        duress_salt=duress_salt, duress_nonce_seed=duress_nonce_seed,
        duress_key_commitment=duress_key_commitment,
        duress_data_size=duress_data_size,
        duress_chunk_count=duress_chunk_count,
    )

    return header, stored_hmac


def read_header_raw(f: BinaryIO) -> FortressHeader:
    header, _ = _parse_header_bytes(f)
    return header


def verify_header(f: BinaryIO, auth_key: bytes) -> FortressHeader:
    start = f.tell()
    f.seek(start)
    header, stored_hmac = _parse_header_bytes(f)
    end_pos = f.tell()

    raw = _serialize(header)
    expected = hmac_mod.new(auth_key, raw, hashlib.sha256).digest()

    if not hmac_mod.compare_digest(stored_hmac, expected):
        raise ValueError(
            "HEADER AUTHENTICATION FAILED. "
            "Wrong password, corrupted file, or tampering detected."
        )

    return header


def write_chunk(f: BinaryIO, encrypted_data: bytes) -> None:
    f.write(struct.pack("<I", len(encrypted_data)))
    f.write(encrypted_data)


def read_chunk(f: BinaryIO) -> Optional[bytes]:
    len_bytes = f.read(4)
    if len(len_bytes) < 4:
        return None
    chunk_len = struct.unpack("<I", len_bytes)[0]
    data = f.read(chunk_len)
    if len(data) < chunk_len:
        raise ValueError("Truncated chunk data")
    return data


def write_footer(f: BinaryIO, chain_hmac: bytes) -> None:
    f.write(chain_hmac)

def read_footer(f: BinaryIO) -> bytes:
    mac = f.read(FOOTER_HMAC_SIZE)
    if len(mac) < FOOTER_HMAC_SIZE:
        raise ValueError("Missing footer HMAC")
    return mac


# ═══════════════════════════════════════════════════════════════
#  SCRAMBLE OPERATIONS (destructive — no recovery possible)
# ═══════════════════════════════════════════════════════════════

def scramble_header(filepath: str) -> None:
    """
    DESTRUCTIVE: Overwrite critical header fields with random data.

    Destroys: salt, nonce_seed, key_commitment, trap_hashes,
    duress commitments. File becomes permanently unrecoverable.
    """
    with open(filepath, "r+b") as f:
        # Read header to find field offsets
        header = read_header_raw(f)
        f.seek(0)

        # Re-read to get the raw layout
        # Skip magic(8) + version(2) + mode(1) + argon2(12) + scrypt(12) = 35
        f.seek(35)

        # Overwrite salt (32 bytes)
        f.write(os.urandom(32))
        # Overwrite nonce_seed (32 bytes)
        f.write(os.urandom(32))
        # Skip original_size(8) + chunk_size(4) = 12
        f.seek(12, 1)
        # Overwrite key_commitment (64 bytes)
        f.write(os.urandom(64))

        f.flush()
        os.fsync(f.fileno())


def scramble_real_data_section(filepath: str, header: FortressHeader) -> None:
    """
    DESTRUCTIVE: Overwrite the real data section with random bytes.

    Used during duress password activation to destroy the actual data
    while keeping the duress (dummy) data intact.
    """
    with open(filepath, "r+b") as f:
        # Calculate where real data starts (after header + duress section)
        # Re-read to find exact position
        f.seek(0)
        _parse_header_bytes(f)  # advances past header + HMAC
        data_start = f.tell()

        # Skip duress chunks
        for _ in range(header.duress_chunk_count):
            len_bytes = f.read(4)
            if len(len_bytes) < 4:
                break
            chunk_len = struct.unpack("<I", len_bytes)[0]
            f.seek(chunk_len, 1)

        # Skip duress footer
        f.seek(FOOTER_HMAC_SIZE, 1)

        # Now at start of real data — overwrite everything until end of real data
        real_start = f.tell()

        # Read to find total real section size
        real_size = 0
        for _ in range(header.total_chunks):
            len_bytes = f.read(4)
            if len(len_bytes) < 4:
                break
            chunk_len = struct.unpack("<I", len_bytes)[0]
            real_size += 4 + chunk_len
            f.seek(chunk_len, 1)
        real_size += FOOTER_HMAC_SIZE  # include real footer

        # Overwrite with random data
        f.seek(real_start)
        remaining = real_size
        while remaining > 0:
            block = min(remaining, 1048576)  # 1MB at a time
            f.write(os.urandom(block))
            remaining -= block

        # Also overwrite real key commitment in header
        f.seek(35 + 32 + 32 + 8 + 4)  # offset to key_commitment
        f.write(os.urandom(64))

        f.flush()
        os.fsync(f.fileno())
