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
Fortress High-Level API v2

New features:
  - Trap sequence: ordered codes that must be entered correctly or file is destroyed
  - Duress mode: secondary password decrypts dummy data and silently wipes real data

Usage:
    # With trap codes
    encrypt_file("data.bin", "data.fortress", password="real",
                 trap_codes=["alpha", "bravo", "charlie"])

    # With duress password + dummy data
    encrypt_file("data.bin", "data.fortress", password="real",
                 duress_password="fake", duress_data=b"nothing important here")

    # Decryption — enter trap codes first, then password
    # Wrong trap code → file destroyed. Duress password → dummy data + real data wiped.
"""

import os
import hashlib
import hmac as hmac_mod
import base64
import struct
import io
from typing import Optional, Callable, List

from .keys import (
    FortressKeys, derive_keys, generate_salt, generate_nonce_seed,
    ARGON2_PRESETS, SCRYPT_PRESETS,
    generate_trap_salt, generate_trap_hashes, verify_trap_code,
)
from .engine import encrypt_chunk, decrypt_chunk, DEFAULT_CHUNK_SIZE
from .format import (
    FortressHeader, write_header, read_header_raw, verify_header,
    write_chunk, read_chunk, write_footer, read_footer,
    scramble_header, scramble_real_data_section,
    MODE_PASSWORD, MODE_HYBRID, FORMAT_VERSION,
)
from . import pq

ProgressCallback = Optional[Callable[[int, int, str], None]]


class TrapVerificationError(Exception):
    """AUDIT FORK: raised when a trap code is wrong. File is NOT modified."""
    pass


class TrapTriggered(Exception):
    """Raised when a trap code is wrong — file has been scrambled."""
    pass


class DuressActivated(Exception):
    """Raised internally when duress password detected — not exposed to caller."""
    pass


def _get_kdf_params(level: str) -> dict:
    a = ARGON2_PRESETS.get(level)
    s = SCRYPT_PRESETS.get(level)
    if a is None or s is None:
        raise ValueError(f"Unknown security level '{level}'")
    return {
        "time_cost": a["time_cost"], "memory_cost": a["memory_cost"],
        "parallelism": a["parallelism"],
        "scrypt_n": s["n"], "scrypt_r": s["r"], "scrypt_p": s["p"],
    }


def _footer_hmac(key: bytes, *chunks_data) -> bytes:
    h = hashlib.sha3_256(b"fortress-footer-chain-v2" + key)
    for ct in chunks_data:
        h.update(struct.pack("<I", len(ct)))
        h.update(ct)
    return h.digest()


def verify_trap_sequence(
    filepath: str,
    header: FortressHeader,
    codes: List[str],
) -> bool:
    """
    AUDIT FORK — NON-DESTRUCTIVE.

    Verify trap codes in order. A wrong code raises TrapVerificationError but
    DOES NOT modify the file. This variant exists so the cryptographic core can
    be reviewed without the in-place file destruction that the shipping build
    performs. See docs/SPECIFICATION.md §10.

    Returns True if all codes valid (or no traps set).
    Raises TrapVerificationError if any code is wrong. File is never touched.
    """
    if header.trap_count == 0:
        return True

    if len(codes) != header.trap_count:
        raise TrapVerificationError(
            f"Wrong number of trap codes (expected {header.trap_count}). "
            "[audit fork: file NOT modified]"
        )

    for i, code in enumerate(codes):
        if not verify_trap_code(header.trap_salt, i, code, header.trap_hashes[i]):
            raise TrapVerificationError(
                f"Trap code #{i+1} INCORRECT. [audit fork: file NOT modified]"
            )

    return True


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    pq_public_key: Optional[bytes] = None,
    security_level: str = "paranoid",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: ProgressCallback = None,
    trap_codes: Optional[List[str]] = None,
    duress_password: Optional[str] = None,
    duress_data: Optional[bytes] = None,
    duress_data_path: Optional[str] = None,
) -> dict:
    """
    Encrypt a file with 6-layer cascade, optional traps and duress.

    Args:
        trap_codes:       List of 1-5 ordered codes (pitfall sequence)
        duress_password:  Dead man's switch password
        duress_data:      Dummy data bytes (or use duress_data_path)
        duress_data_path: Path to dummy data file
    """
    if not password:
        raise ValueError("Password required")

    params = _get_kdf_params(security_level)
    file_size = os.path.getsize(input_path)
    salt = generate_salt()
    nonce_seed = generate_nonce_seed()

    # PQ key exchange
    kem_ct, kem_ss = None, None
    mode = MODE_PASSWORD
    if pq_public_key is not None:
        mode = MODE_HYBRID
        kem_ct, kem_ss = pq.encapsulate(pq_public_key)

    # Trap setup
    trap_count = 0
    trap_salt = b"\x00" * 32
    trap_hashes = []
    if trap_codes:
        if len(trap_codes) > 5:
            raise ValueError("Maximum 5 trap codes")
        trap_count = len(trap_codes)
        trap_salt = generate_trap_salt()
        trap_hashes = generate_trap_hashes(trap_salt, trap_codes)

    # Duress setup
    duress_enabled = 0
    d_salt = b"\x00" * 32
    d_nonce_seed = b"\x00" * 32
    d_commitment = b"\x00" * 64
    d_data_size = 0
    d_chunk_count = 0
    d_keys = None
    dummy_data = None

    if duress_password is not None:
        if duress_data is None and duress_data_path is not None:
            with open(duress_data_path, "rb") as f:
                dummy_data = f.read()
        elif duress_data is not None:
            dummy_data = duress_data
        else:
            raise ValueError("duress_password requires duress_data or duress_data_path")

        duress_enabled = 1
        d_salt = generate_salt()
        d_nonce_seed = generate_nonce_seed()

        if progress:
            progress(0, 0, "Deriving duress keys...")

        d_keys = derive_keys(
            password=duress_password, salt=d_salt, nonce_seed=d_nonce_seed,
            **params, kem_shared_secret=kem_ss,
        )
        d_commitment = d_keys.commitment
        d_data_size = len(dummy_data)
        d_chunk_count = max(1, (len(dummy_data) + chunk_size - 1) // chunk_size)
        if len(dummy_data) == 0:
            d_chunk_count = 0

    # Derive real keys
    if progress:
        progress(0, 0, "Deriving real keys (Argon2id → scrypt → HKDF)...")

    keys = derive_keys(
        password=password, salt=salt, nonce_seed=nonce_seed,
        **params, kem_shared_secret=kem_ss,
    )

    try:
        header = FortressHeader(
            version=FORMAT_VERSION, mode=mode,
            argon2_time=params["time_cost"], argon2_memory=params["memory_cost"],
            argon2_parallelism=params["parallelism"],
            scrypt_n=params["scrypt_n"], scrypt_r=params["scrypt_r"],
            scrypt_p=params["scrypt_p"],
            salt=salt, nonce_seed=nonce_seed,
            original_size=file_size, chunk_size=chunk_size,
            key_commitment=keys.commitment, kem_ciphertext=kem_ct,
            trap_count=trap_count, trap_salt=trap_salt, trap_hashes=trap_hashes,
            duress_enabled=duress_enabled,
            duress_salt=d_salt, duress_nonce_seed=d_nonce_seed,
            duress_key_commitment=d_commitment,
            duress_data_size=d_data_size,
            duress_chunk_count=d_chunk_count,
        )

        total_chunks = header.total_chunks
        real_chunk_cts = []

        with open(output_path, "wb") as out_f:
            # Use REAL keys for header auth (duress password can't validate header
            # — it uses its own verification via key commitment matching)
            write_header(out_f, header, keys.header_auth_key)

            # Write duress encrypted chunks (if duress mode)
            duress_chunk_cts = []
            if duress_enabled and d_keys and dummy_data is not None:
                if progress:
                    progress(0, 0, "Encrypting duress layer...")

                d_offset = 0
                d_idx = 0
                while d_offset < len(dummy_data):
                    chunk_data = dummy_data[d_offset:d_offset + chunk_size]
                    ct = encrypt_chunk(chunk_data, d_keys, d_idx)
                    write_chunk(out_f, ct)
                    duress_chunk_cts.append(ct)
                    d_offset += chunk_size
                    d_idx += 1

                # Duress footer
                d_footer = _footer_hmac(d_keys.footer_auth_key, *duress_chunk_cts)
                write_footer(out_f, d_footer)

            # Write real encrypted chunks
            with open(input_path, "rb") as in_f:
                chunk_idx = 0
                while True:
                    raw = in_f.read(chunk_size)
                    if not raw:
                        break
                    if progress:
                        progress(chunk_idx, total_chunks, "Encrypting real data...")
                    ct = encrypt_chunk(raw, keys, chunk_idx)
                    write_chunk(out_f, ct)
                    real_chunk_cts.append(ct)
                    chunk_idx += 1

            # Real footer
            real_footer = _footer_hmac(keys.footer_auth_key, *real_chunk_cts)
            write_footer(out_f, real_footer)

        if progress:
            progress(total_chunks, total_chunks, "Done")

        out_size = os.path.getsize(output_path)
        return {
            "input_size": file_size, "output_size": out_size,
            "overhead": out_size - file_size, "chunks": chunk_idx if total_chunks > 0 else 0,
            "mode": "hybrid-pq" if mode == MODE_HYBRID else "password",
            "security_level": security_level, "layers": 6,
            "traps_set": trap_count, "duress_enabled": duress_enabled == 1,
        }
    finally:
        keys.wipe()
        if d_keys:
            d_keys.wipe()


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    pq_secret_key: Optional[bytes] = None,
    progress: ProgressCallback = None,
    trap_codes: Optional[List[str]] = None,
) -> dict:
    """
    Decrypt a .fortress file.

    Trap codes (if set) are verified FIRST. Wrong code = file destroyed.
    Then password is checked against both real and duress commitments:
      - Real password → decrypts real data normally
      - Duress password → decrypts dummy data, DESTROYS real data
    """
    if not password:
        raise ValueError("Password required")

    with open(input_path, "rb") as f:
        raw_header = read_header_raw(f)

    # ── Step 1: Verify trap sequence (destructive on failure) ──
    if raw_header.trap_count > 0:
        if trap_codes is None:
            raise ValueError(
                f"This file requires {raw_header.trap_count} trap code(s). "
                "Provide them via trap_codes parameter."
            )
        verify_trap_sequence(input_path, raw_header, trap_codes)

    # ── Step 2: PQ decapsulation ──
    kem_ss = None
    if raw_header.mode == MODE_HYBRID:
        if pq_secret_key is None:
            raise ValueError("Hybrid PQ mode — secret key required")
        kem_ss = pq.decapsulate(pq_secret_key, raw_header.kem_ciphertext)

    # ── Step 3: Derive keys and check which password was used ──
    if progress:
        progress(0, 0, "Deriving keys (Argon2id → scrypt → HKDF)...")

    # Try as real password first
    real_keys = derive_keys(
        password=password, salt=raw_header.salt, nonce_seed=raw_header.nonce_seed,
        time_cost=raw_header.argon2_time, memory_cost=raw_header.argon2_memory,
        parallelism=raw_header.argon2_parallelism,
        scrypt_n=raw_header.scrypt_n, scrypt_r=raw_header.scrypt_r,
        scrypt_p=raw_header.scrypt_p, kem_shared_secret=kem_ss,
    )

    is_real = hmac_mod.compare_digest(real_keys.commitment, raw_header.key_commitment)

    # Always derive the duress keys too when duress is configured, even if the
    # real password already matched. Deriving them only on a real-password
    # mismatch makes the real password ~2x faster to verify than any other
    # guess (one KDF pass vs. two), letting a coercion adversary confirm a
    # handed-over password is the genuine one from wall-clock timing alone —
    # defeating the duress deniability goal (G6, THREAT_MODEL.md §5).
    duress_keys = None
    duress_match = False
    if raw_header.duress_enabled:
        if progress:
            progress(0, 0, "Verifying credentials...")

        duress_keys = derive_keys(
            password=password, salt=raw_header.duress_salt,
            nonce_seed=raw_header.duress_nonce_seed,
            time_cost=raw_header.argon2_time, memory_cost=raw_header.argon2_memory,
            parallelism=raw_header.argon2_parallelism,
            scrypt_n=raw_header.scrypt_n, scrypt_r=raw_header.scrypt_r,
            scrypt_p=raw_header.scrypt_p, kem_shared_secret=kem_ss,
        )
        duress_match = hmac_mod.compare_digest(
            duress_keys.commitment, raw_header.duress_key_commitment)

    is_duress = (not is_real) and duress_match

    if not is_real and not is_duress:
        real_keys.wipe()
        if duress_keys:
            duress_keys.wipe()
        raise ValueError("KEY COMMITMENT MISMATCH — wrong password")

    # ── Step 4: Decrypt appropriate section ──
    try:
        if is_duress:
            return _decrypt_duress(
                input_path, output_path, raw_header, duress_keys, progress,
            )
        else:
            return _decrypt_real(
                input_path, output_path, raw_header, real_keys, progress,
            )
    finally:
        real_keys.wipe()
        if duress_keys:
            duress_keys.wipe()


def _decrypt_real(filepath, output_path, header, keys, progress):
    """Normal decryption of real data."""
    with open(filepath, "rb") as f:
        f.seek(0)
        verified = verify_header(f, keys.header_auth_key)

        # Skip duress section if present
        if header.duress_enabled:
            for _ in range(header.duress_chunk_count):
                ct = read_chunk(f)
            f.read(32)  # duress footer

        # Decrypt real chunks
        total = header.total_chunks
        chunk_cts = []
        bytes_written = 0

        with open(output_path, "wb") as out_f:
            for i in range(total):
                if progress:
                    progress(i, total, "Decrypting...")
                ct = read_chunk(f)
                if ct is None:
                    raise ValueError(f"Unexpected EOF at chunk {i}")
                chunk_cts.append(ct)
                pt = decrypt_chunk(ct, keys, i)
                remaining = header.original_size - bytes_written
                out_f.write(pt[:remaining])
                bytes_written += min(len(pt), remaining)

        # Verify footer
        stored = read_footer(f)
        expected = _footer_hmac(keys.footer_auth_key, *chunk_cts)
        if not hmac_mod.compare_digest(stored, expected):
            try: os.unlink(output_path)
            except OSError: pass
            raise ValueError("FOOTER AUTH FAILED — file tampered")

    if progress:
        progress(total, total, "Done")

    return {
        "original_size": header.original_size, "bytes_written": bytes_written,
        "chunks": total, "mode": "real", "verified": True, "duress": False,
    }


def _decrypt_duress(filepath, output_path, header, duress_keys, progress):
    """
    Duress decryption: output dummy data, then DESTROY real data.

    The caller sees normal decryption output. The real data is silently
    and permanently wiped from the file afterward.
    """
    with open(filepath, "rb") as f:
        f.seek(0)
        # We can't verify the main header HMAC with duress keys (it was
        # signed with real keys), so we skip header auth for duress mode.
        # The duress key commitment match already proves the password is valid.
        _parse_past_header(f, header)

        # Decrypt duress chunks
        duress_cts = []
        bytes_written = 0

        with open(output_path, "wb") as out_f:
            for i in range(header.duress_chunk_count):
                if progress:
                    progress(i, header.duress_chunk_count, "Decrypting...")
                ct = read_chunk(f)
                if ct is None:
                    raise ValueError(f"Unexpected EOF at duress chunk {i}")
                duress_cts.append(ct)
                pt = decrypt_chunk(ct, duress_keys, i)
                remaining = header.duress_data_size - bytes_written
                out_f.write(pt[:remaining])
                bytes_written += min(len(pt), remaining)

        # Verify duress footer
        stored = read_footer(f)
        expected = _footer_hmac(duress_keys.footer_auth_key, *duress_cts)
        if not hmac_mod.compare_digest(stored, expected):
            try: os.unlink(output_path)
            except OSError: pass
            raise ValueError("DURESS FOOTER AUTH FAILED")

    # ══ AUDIT FORK: real data is NOT destroyed ══
    # The shipping build calls scramble_real_data_section(filepath, header) here.
    # In the audit fork the input file is left completely intact so the crypto
    # core can be reviewed without destructive I/O. See SPECIFICATION.md §10.
    if progress:
        progress(header.duress_chunk_count, header.duress_chunk_count, "Done")

    return {
        "original_size": header.duress_data_size, "bytes_written": bytes_written,
        "chunks": header.duress_chunk_count, "mode": "decrypted",
        "verified": True, "duress": True,
        "audit_fork_real_data_preserved": True,
    }


def _parse_past_header(f, header):
    """Advance file position past the header + HMAC."""
    from .format import _parse_header_bytes
    f.seek(0)
    _parse_header_bytes(f)


# ═══════════════════════════════════════════════════════════════
#  MESSAGE ENCRYPTION
# ═══════════════════════════════════════════════════════════════

def encrypt_message(message: str, password: str,
                    pq_public_key=None, security_level="standard",
                    trap_codes=None) -> str:
    msg_bytes = message.encode("utf-8")
    buf = io.BytesIO()

    params = _get_kdf_params(security_level)
    salt = generate_salt()
    nonce_seed = generate_nonce_seed()

    kem_ct, kem_ss = None, None
    mode = MODE_PASSWORD
    if pq_public_key is not None:
        mode = MODE_HYBRID
        kem_ct, kem_ss = pq.encapsulate(pq_public_key)

    trap_count = 0
    trap_salt = b"\x00" * 32
    trap_hashes = []
    if trap_codes:
        trap_count = len(trap_codes)
        trap_salt = generate_trap_salt()
        trap_hashes = generate_trap_hashes(trap_salt, trap_codes)

    keys = derive_keys(password=password, salt=salt, nonce_seed=nonce_seed,
                        **params, kem_shared_secret=kem_ss)
    try:
        header = FortressHeader(
            version=FORMAT_VERSION, mode=mode,
            argon2_time=params["time_cost"], argon2_memory=params["memory_cost"],
            argon2_parallelism=params["parallelism"],
            scrypt_n=params["scrypt_n"], scrypt_r=params["scrypt_r"],
            scrypt_p=params["scrypt_p"],
            salt=salt, nonce_seed=nonce_seed,
            original_size=len(msg_bytes), chunk_size=len(msg_bytes) + 8192,
            key_commitment=keys.commitment, kem_ciphertext=kem_ct,
            trap_count=trap_count, trap_salt=trap_salt, trap_hashes=trap_hashes,
        )
        write_header(buf, header, keys.header_auth_key)
        ct = encrypt_chunk(msg_bytes, keys, 0)
        write_chunk(buf, ct)
        write_footer(buf, _footer_hmac(keys.footer_auth_key, ct))
    finally:
        keys.wipe()

    return "FORTRESS:" + base64.urlsafe_b64encode(buf.getvalue()).decode()


def decrypt_message(token: str, password: str, pq_secret_key=None,
                    trap_codes=None) -> str:
    if not token.startswith("FORTRESS:"):
        raise ValueError("Not a Fortress message")

    raw = base64.urlsafe_b64decode(token[9:])
    buf = io.BytesIO(raw)
    header = read_header_raw(buf)

    # Trap verification (for messages, we can't scramble in-memory,
    # so we just reject)
    if header.trap_count > 0:
        if trap_codes is None or len(trap_codes) != header.trap_count:
            raise ValueError(f"Message requires {header.trap_count} trap code(s)")
        from .keys import verify_trap_code
        for i, code in enumerate(trap_codes):
            if not verify_trap_code(header.trap_salt, i, code, header.trap_hashes[i]):
                raise ValueError(f"Trap code #{i+1} INCORRECT — message access denied")

    kem_ss = None
    if header.mode == MODE_HYBRID:
        if pq_secret_key is None:
            raise ValueError("Hybrid PQ mode — secret key required")
        kem_ss = pq.decapsulate(pq_secret_key, header.kem_ciphertext)

    keys = derive_keys(password=password, salt=header.salt, nonce_seed=header.nonce_seed,
                        time_cost=header.argon2_time, memory_cost=header.argon2_memory,
                        parallelism=header.argon2_parallelism,
                        scrypt_n=header.scrypt_n, scrypt_r=header.scrypt_r,
                        scrypt_p=header.scrypt_p, kem_shared_secret=kem_ss)
    try:
        if not hmac_mod.compare_digest(keys.commitment, header.key_commitment):
            raise ValueError("KEY COMMITMENT MISMATCH — wrong password")
        buf.seek(0)
        verify_header(buf, keys.header_auth_key)
        ct = read_chunk(buf)
        pt = decrypt_chunk(ct, keys, 0)
        stored = read_footer(buf)
        expected = _footer_hmac(keys.footer_auth_key, ct)
        if not hmac_mod.compare_digest(stored, expected):
            raise ValueError("FOOTER AUTH FAILED")
        return pt[:header.original_size].decode("utf-8")
    finally:
        keys.wipe()
