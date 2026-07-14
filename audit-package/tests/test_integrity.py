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
test_integrity.py — Negative tests: wrong password, tampering, truncation,
header offset verification. These are the tests that matter most for an audit:
they assert the system FAILS correctly.
"""

import os
import struct
import pytest

from fortress import encrypt_file, decrypt_file
from fortress.format import read_header_raw, _serialize, FortressHeader


@pytest.fixture
def make_file(tmp_path):
    def _make(name, data=b"sensitive payload data " * 100, **kw):
        i = str(tmp_path / f"{name}.in")
        e = str(tmp_path / f"{name}.fortress")
        o = str(tmp_path / f"{name}.out")
        with open(i, "wb") as f:
            f.write(data)
        encrypt_file(i, e, password="pw", security_level="standard", **kw)
        return i, e, o, data
    return _make


def test_wrong_password(make_file):
    _, e, o, _ = make_file("wp")
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="wrongpassword")


def test_zero_chunk_size_rejected(tmp_path):
    i = str(tmp_path / "z.in")
    e = str(tmp_path / "z.fortress")
    with open(i, "wb") as f:
        f.write(b"data")
    with pytest.raises(ValueError):
        encrypt_file(i, e, password="pw", security_level="standard", chunk_size=0)


def test_negative_chunk_size_rejected(tmp_path):
    i = str(tmp_path / "n.in")
    e = str(tmp_path / "n.fortress")
    with open(i, "wb") as f:
        f.write(b"data")
    with pytest.raises(ValueError):
        encrypt_file(i, e, password="pw", security_level="standard", chunk_size=-1)


def test_bitflip_in_chunk_body(make_file):
    _, e, o, _ = make_file("flip")
    with open(e, "r+b") as f:
        f.seek(-60, 2)  # inside real chunk / footer region
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 0xFF]))
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="pw")


def test_bitflip_in_header(make_file):
    _, e, o, _ = make_file("hflip")
    with open(e, "r+b") as f:
        f.seek(40)  # inside salt region
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 0xFF]))
    # Corrupting salt → wrong keys → commitment mismatch (or header HMAC fail)
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="pw")


def test_truncation(make_file):
    _, e, o, _ = make_file("trunc")
    size = os.path.getsize(e)
    with open(e, "r+b") as f:
        f.truncate(size - 40)  # chop the footer / last chunk
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="pw")


def test_truncate_to_header_only(make_file):
    _, e, o, _ = make_file("hdronly")
    with open(e, "r+b") as f:
        f.truncate(179)  # just the fixed header prefix
    with pytest.raises(Exception):
        decrypt_file(e, o, password="pw")


def test_empty_file_not_fortress(tmp_path):
    e = str(tmp_path / "empty.fortress")
    o = str(tmp_path / "empty.out")
    with open(e, "wb") as f:
        f.write(b"")
    with pytest.raises(Exception):
        decrypt_file(e, o, password="pw")


def test_wrong_magic(tmp_path):
    e = str(tmp_path / "bad.fortress")
    o = str(tmp_path / "bad.out")
    with open(e, "wb") as f:
        f.write(b"NOTFORTS" + b"\x00" * 200)
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="pw")


# ── Header offset verification (locks the format layout) ──────────

def test_header_offsets():
    """
    Verify the byte offsets the destructive routines depend on.
    salt @ 35, nonce_seed @ 67, original_size @ 99, chunk_size @ 107,
    key_commitment @ 111, fixed prefix (pre-KEM) = 179 bytes.
    """
    h = FortressHeader(
        version=2, mode=0,
        argon2_time=4, argon2_memory=131072, argon2_parallelism=4,
        scrypt_n=2**17, scrypt_r=8, scrypt_p=1,
        salt=bytes([0xAA]) * 32,
        nonce_seed=bytes([0xBB]) * 32,
        original_size=0, chunk_size=1048576,
        key_commitment=bytes([0xCC]) * 64,
        kem_ciphertext=None,
    )
    raw = _serialize(h)

    # Magic
    assert raw[0:8] == b"FORTRESS"
    # Version at 8
    assert struct.unpack("<H", raw[8:10])[0] == 2
    # Mode at 10
    assert raw[10] == 0
    # salt at 35
    assert raw[35:67] == bytes([0xAA]) * 32
    # nonce_seed at 67
    assert raw[67:99] == bytes([0xBB]) * 32
    # original_size at 99
    assert struct.unpack("<Q", raw[99:107])[0] == 0
    # chunk_size at 107
    assert struct.unpack("<I", raw[107:111])[0] == 1048576
    # key_commitment at 111
    assert raw[111:175] == bytes([0xCC]) * 64
    # kem_ct_len at 175 == 0
    assert struct.unpack("<I", raw[175:179])[0] == 0


def test_header_params_survive_roundtrip(make_file):
    """The KDF params in the header must match what was used to encrypt."""
    _, e, o, _ = make_file("params")
    with open(e, "rb") as f:
        h = read_header_raw(f)
    assert h.argon2_time == 4
    assert h.argon2_memory == 131072
    assert h.scrypt_n == 2**17
    assert h.version == 2


# ── Duress timing side-channel ─────────────────────────────────────

def test_duress_enabled_always_derives_both_keysets(make_file, monkeypatch):
    """
    Regression test: decrypt_file must derive the duress keyset every time
    duress is enabled, regardless of whether the real password matches
    first. Deriving it only on a real-password mismatch means the real
    password is verified with one KDF pass while every other guess costs
    two, creating a timing side channel that reveals whether a handed-over
    password is the genuine one purely from response latency — undermining
    the duress deniability goal (THREAT_MODEL.md G6/A5).
    """
    import fortress.api as api_module

    _, e, o, _ = make_file("timing", duress_password="fakepw", duress_data=b"decoy")

    real_derive = api_module.derive_keys
    calls = []

    def counting_derive(*args, **kwargs):
        calls.append(kwargs.get("salt"))
        return real_derive(*args, **kwargs)

    monkeypatch.setattr(api_module, "derive_keys", counting_derive)

    calls.clear()
    decrypt_file(e, o, password="pw")  # real password — must still cost 2 KDFs
    assert len(calls) == 2, (
        "real-password decrypt only ran the real KDF, skipping the duress "
        "derivation — reintroduces the timing oracle"
    )

    calls.clear()
    decrypt_file(e, o + "2", password="fakepw")  # duress password
    assert len(calls) == 2

    calls.clear()
    with pytest.raises(ValueError):
        decrypt_file(e, o + "3", password="neither")
    assert len(calls) == 2
