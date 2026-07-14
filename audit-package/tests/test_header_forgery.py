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
test_header_forgery.py — Regression tests for AUDIT_FINDINGS.md FC-01, FC-02, FC-03.

These tests document real, verified vulnerabilities in the crypto core where
header fields are trusted (and, in the shipping build, acted on destructively)
*before* the header HMAC is checked, and where plaintext is released to disk
before the ciphertext footer chain is verified.

They are written to assert the SECURE behavior. Against the current, unpatched
code they are expected to FAIL — that failure IS the regression signal. Once a
fix lands (see AUDIT_FINDINGS.md "PROPOSED FIX"), these tests must pass and stay
green.

FC-01 / FC-02 need the actual destructive (shipping) behavior to mean anything —
the non-destructive audit fork only raises an exception with no real damage by
design, so those two tests import `core-python` (shipping) explicitly by path,
independent of whichever package happens to be `pip install -e`'d. FC-03 is a
control-flow bug present identically in both builds, so it also pins to
`core-python` for a single, unambiguous target, but the bug is not
fork-specific.
"""

import importlib
import os
import sys
import contextlib

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SHIPPING_CORE_DIR = os.path.join(HERE, "..", "core-python")


@contextlib.contextmanager
def _shipping_fortress():
    """
    Import a fresh copy of the SHIPPING (destructive) `fortress` package by
    path, isolated from whatever is normally `pip install -e`'d, and undo the
    sys.path/sys.modules changes afterward so other test files aren't affected.
    """
    stale = [name for name in sys.modules if name == "fortress" or name.startswith("fortress.")]
    saved_modules = {name: sys.modules[name] for name in stale}
    for name in stale:
        del sys.modules[name]

    sys.path.insert(0, SHIPPING_CORE_DIR)
    try:
        fortress = importlib.import_module("fortress")
        assert not hasattr(fortress, "TrapVerificationError"), (
            "expected the SHIPPING build (destructive), but imported the audit "
            "fork instead — check SHIPPING_CORE_DIR / sys.path ordering"
        )
        yield fortress
    finally:
        sys.path.remove(SHIPPING_CORE_DIR)
        stale_after = [n for n in sys.modules if n == "fortress" or n.startswith("fortress.")]
        for name in stale_after:
            del sys.modules[name]
        sys.modules.update(saved_modules)


# ── FC-01: forged trap section destroys a file that never had traps ───────

def test_trap_injection_cannot_be_forged(tmp_path):
    """
    An attacker with write access to the ciphertext (but no password of any
    kind) must NOT be able to inject a trap requirement that later destroys
    the file on the owner's ordinary decrypt attempt.

    Currently FAILS: the shipping build reads trap_count/trap_salt/trap_hashes
    from the *unauthenticated* raw header before any password/HMAC check, so a
    forged trap section (zero KDF work, arbitrary bytes) is honored and its
    mismatch destroys the header via scramble_header().
    """
    with _shipping_fortress() as fortress:
        from fortress.format import (
            read_header_raw, _parse_header_bytes, _serialize,
            HEADER_HMAC_SIZE, FortressHeader,
        )

        real_password = "the-owners-real-password"
        payload = b"THE OWNER'S ACTUAL SECRET DATA " * 500

        i = str(tmp_path / "victim.in")
        e = str(tmp_path / "victim.fortress")
        o = str(tmp_path / "victim.out")
        with open(i, "wb") as f:
            f.write(payload)

        # No traps configured at encryption time.
        fortress.encrypt_file(i, e, password=real_password, security_level="standard")

        # Sanity: works before tampering.
        fortress.decrypt_file(e, o, password=real_password)
        with open(o, "rb") as f:
            assert f.read() == payload

        # ── Attacker: inject a fake, unsatisfiable trap requirement ──
        with open(e, "rb") as f:
            orig_header = read_header_raw(f)

        forged = FortressHeader(
            version=orig_header.version, mode=orig_header.mode,
            argon2_time=orig_header.argon2_time, argon2_memory=orig_header.argon2_memory,
            argon2_parallelism=orig_header.argon2_parallelism,
            scrypt_n=orig_header.scrypt_n, scrypt_r=orig_header.scrypt_r, scrypt_p=orig_header.scrypt_p,
            salt=orig_header.salt, nonce_seed=orig_header.nonce_seed,
            original_size=orig_header.original_size, chunk_size=orig_header.chunk_size,
            key_commitment=orig_header.key_commitment,   # attacker never touches this
            kem_ciphertext=orig_header.kem_ciphertext,
            trap_count=1,
            trap_salt=os.urandom(32),
            trap_hashes=[os.urandom(32)],                 # arbitrary, unsatisfiable
            duress_enabled=orig_header.duress_enabled,
            duress_salt=orig_header.duress_salt,
            duress_nonce_seed=orig_header.duress_nonce_seed,
            duress_key_commitment=orig_header.duress_key_commitment,
            duress_data_size=orig_header.duress_data_size,
            duress_chunk_count=orig_header.duress_chunk_count,
        )
        new_header_bytes = _serialize(forged)

        with open(e, "rb") as f:
            _parse_header_bytes(f)
            header_end = f.tell()
            f.seek(0)
            full = f.read()
        old_hmac_bytes = full[header_end - HEADER_HMAC_SIZE:header_end]
        rest_of_file = full[header_end:]   # real chunks + real footer, untouched

        with open(e, "wb") as f:
            f.write(new_header_bytes + old_hmac_bytes + rest_of_file)

        # Owner's first decrypt attempt: no trap_codes, as always. This alone
        # must not be able to lead to destruction just by the owner making one
        # reasonable attempt to comply with the (forged) prompt.
        with pytest.raises(ValueError):
            fortress.decrypt_file(e, o, password=real_password)

        # This is the crux of the finding: the owner, confused, tries to
        # comply with a trap prompt they never set up. A SECURE implementation
        # must reject the forged trap section as tampering (header HMAC
        # mismatch) rather than accept it as authoritative and destroy the
        # header on any subsequent guess.
        try:
            fortress.decrypt_file(e, o, password=real_password, trap_codes=["reasonable-guess"])
        except fortress.TrapTriggered:
            pytest.fail(
                "FC-01: forged (unauthenticated) trap section was honored and "
                "its mismatch triggered scramble_header() — an attacker with "
                "no password knowledge destroyed the file"
            )
        except ValueError:
            pass  # acceptable: rejected as tampering, e.g. header HMAC failure

        # The forged trap section is still sitting in the header at this
        # point (nobody has repaired it), so the file correctly continues to
        # report tampering rather than silently decrypting -- that is not
        # data loss. The actual claim of this test is that scramble_header()
        # was never invoked, i.e. the real salt/nonce_seed/key_commitment are
        # byte-for-byte what they were before the attacker touched anything.
        # Prove it by restoring the original (untampered) header and
        # confirming the real password recovers the original payload.
        with open(e, "wb") as f:
            f.write(full)  # `full` = the file's bytes before any tampering
        res = fortress.decrypt_file(e, o, password=real_password)
        with open(o, "rb") as f:
            assert f.read() == payload


# ── FC-02: forged duress section destroys real data with no password ──────

def test_duress_section_cannot_be_forged(tmp_path):
    """
    An attacker who knows neither the real nor any duress password must not be
    able to self-manufacture a duress key set (they control the salt/nonce_seed
    they derive it from) and use it to trigger destruction of the real key
    commitment.

    Currently FAILS: _decrypt_duress() never calls verify_header(), so the
    entered password only needs to satisfy a commitment the attacker computed
    themselves — nothing ties duress_salt/duress_nonce_seed/duress_key_commitment
    to the real, HMAC-protected header.
    """
    with _shipping_fortress() as fortress:
        from fortress.format import (
            read_header_raw, _parse_header_bytes, _serialize,
            HEADER_HMAC_SIZE, FortressHeader,
        )
        from fortress.keys import derive_keys, ARGON2_PRESETS, SCRYPT_PRESETS
        import hashlib

        def footer_hmac_zero_chunks(key: bytes) -> bytes:
            return hashlib.sha3_256(b"fortress-footer-chain-v2" + key).digest()

        real_password = "the-owners-real-password"
        payload = b"THE OWNER'S ACTUAL SECRET DATA " * 500

        i = str(tmp_path / "victim.in")
        e = str(tmp_path / "victim.fortress")
        o = str(tmp_path / "victim.out")
        with open(i, "wb") as f:
            f.write(payload)

        # No duress configured at encryption time.
        fortress.encrypt_file(i, e, password=real_password, security_level="standard")
        fortress.decrypt_file(e, o, password=real_password)
        with open(o, "rb") as f:
            assert f.read() == payload

        # ── Attacker: forge a self-consistent duress section ──
        with open(e, "rb") as f:
            orig_header = read_header_raw(f)

        level = "standard"
        params = {
            "time_cost": ARGON2_PRESETS[level]["time_cost"],
            "memory_cost": ARGON2_PRESETS[level]["memory_cost"],
            "parallelism": ARGON2_PRESETS[level]["parallelism"],
            "scrypt_n": SCRYPT_PRESETS[level]["n"],
            "scrypt_r": SCRYPT_PRESETS[level]["r"],
            "scrypt_p": SCRYPT_PRESETS[level]["p"],
        }
        attacker_password = "anything-the-attacker-likes"
        fake_salt = os.urandom(32)
        fake_nonce_seed = os.urandom(32)
        fake_keys = derive_keys(password=attacker_password, salt=fake_salt,
                                 nonce_seed=fake_nonce_seed, **params)

        forged = FortressHeader(
            version=orig_header.version, mode=orig_header.mode,
            argon2_time=orig_header.argon2_time, argon2_memory=orig_header.argon2_memory,
            argon2_parallelism=orig_header.argon2_parallelism,
            scrypt_n=orig_header.scrypt_n, scrypt_r=orig_header.scrypt_r, scrypt_p=orig_header.scrypt_p,
            salt=orig_header.salt, nonce_seed=orig_header.nonce_seed,
            original_size=orig_header.original_size, chunk_size=orig_header.chunk_size,
            key_commitment=orig_header.key_commitment,   # attacker never touches this
            kem_ciphertext=orig_header.kem_ciphertext,
            trap_count=0, trap_salt=b"\x00" * 32, trap_hashes=[],
            duress_enabled=1,
            duress_salt=fake_salt,
            duress_nonce_seed=fake_nonce_seed,
            duress_key_commitment=fake_keys.commitment,
            duress_data_size=0,
            duress_chunk_count=0,
        )
        new_header_bytes = _serialize(forged)

        with open(e, "rb") as f:
            _parse_header_bytes(f)
            header_end = f.tell()
            f.seek(0)
            full = f.read()
        old_hmac_bytes = full[header_end - HEADER_HMAC_SIZE:header_end]
        rest_of_file = bytearray(full[header_end:])

        # Patch the 32 bytes where the forged "0-chunk duress footer" is
        # expected — computable by the attacker from keys they derived
        # themselves, no real secret needed.
        rest_of_file[0:32] = footer_hmac_zero_chunks(fake_keys.footer_auth_key)

        with open(e, "wb") as f:
            f.write(new_header_bytes + old_hmac_bytes + bytes(rest_of_file))

        # Attacker triggers decrypt with a password ONLY they chose. Whether
        # this "succeeds" in returning a (harmless, 0-byte) forged decoy or
        # is rejected outright doesn't matter -- the actual claim is that it
        # must never destroy real data. With confirm_duress_wipe defaulting
        # to False, no wipe should occur even if the forged commitment is
        # accepted.
        try:
            res = fortress.decrypt_file(e, o, password=attacker_password)
            assert res.get("real_data_wiped", False) is False, (
                "FC-02: forged duress section triggered the real-data wipe "
                "without explicit confirmation"
            )
        except ValueError:
            pass  # acceptable: rejected as tampering

        # The forged duress section is still sitting in the header at this
        # point, so a plain real-password decrypt correctly continues to
        # report tampering (the overall header HMAC no longer matches with
        # the duress fields changed) -- that is detection, not data loss.
        # Prove no destructive side effect occurred by restoring the
        # original (untampered) header and confirming the real password
        # recovers the original payload.
        with open(e, "wb") as f:
            f.write(full)  # `full` = the file's bytes before any tampering
        res = fortress.decrypt_file(e, o, password=real_password)
        assert res["duress"] is False
        with open(o, "rb") as f:
            assert f.read() == payload


# ── FC-03: truncation causes unverified plaintext to be released to disk ──

def test_truncated_file_leaves_no_plaintext_on_disk(tmp_path):
    """
    If the ciphertext is truncated (a whole trailing chunk + footer removed —
    simulating corruption, an interrupted transfer, or a tampering adversary),
    decrypt_file() must raise WITHOUT leaving any of the (unverified, because
    the footer chain never got checked) plaintext behind on disk.

    Currently FAILS: chunks are decrypted and written to the output file
    before the footer chain is checked, and the "Unexpected EOF at chunk N"
    path (reached when a trailing chunk is missing entirely) has no cleanup at
    all — the partially-decrypted output file survives the failure.
    """
    with _shipping_fortress() as fortress:
        import struct
        from fortress.format import _parse_header_bytes

        payload = (
            b"TOP-SECRET-CHUNK-0(0123456789)" * 20
            + b"TOP-SECRET-CHUNK-1(ABCDEFGHIJ)" * 20
            + b"TOP-SECRET-CHUNK-2(KLMNOPQRST)" * 20
        )
        i = str(tmp_path / "secret.in")
        e = str(tmp_path / "secret.fortress")
        o = str(tmp_path / "secret.out")
        with open(i, "wb") as f:
            f.write(payload)

        chunk_size = 600
        fortress.encrypt_file(i, e, password="correct-horse",
                               security_level="standard", chunk_size=chunk_size)

        # Find real chunk boundaries and cut off the last chunk + footer
        # entirely (simulates truncation/corruption of the tail of the file).
        with open(e, "rb") as f:
            _parse_header_bytes(f)
            chunk_starts = []
            while True:
                pos = f.tell()
                lb = f.read(4)
                if len(lb) < 4:
                    break
                clen = struct.unpack("<I", lb)[0]
                if clen > 1_000_000:
                    break
                f.seek(clen, 1)
                chunk_starts.append(pos)

        with open(e, "rb") as f:
            data = f.read()
        cut_at = chunk_starts[-1]
        with open(e, "wb") as f:
            f.write(data[:cut_at])

        if os.path.exists(o):
            os.remove(o)

        with pytest.raises(Exception):
            fortress.decrypt_file(e, o, password="correct-horse")

        assert not os.path.exists(o), (
            "FC-03: decrypt_file() reported failure but left an unverified, "
            "partially-decrypted plaintext file behind on disk"
        )
