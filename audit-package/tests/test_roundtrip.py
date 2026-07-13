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
test_roundtrip.py — Encrypt→decrypt correctness across sizes, levels, chunking.
"""

import os
import pytest

from fortress import encrypt_file, decrypt_file, encrypt_message, decrypt_message


@pytest.fixture
def tmp(tmp_path):
    def paths(name):
        return (str(tmp_path / f"{name}.in"),
                str(tmp_path / f"{name}.fortress"),
                str(tmp_path / f"{name}.out"))
    return paths


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000, 65536])
def test_roundtrip_small_sizes(tmp, size):
    i, e, o = tmp(f"s{size}")
    data = os.urandom(size)
    with open(i, "wb") as f:
        f.write(data)
    encrypt_file(i, e, password="pw", security_level="standard")
    decrypt_file(e, o, password="pw")
    with open(o, "rb") as f:
        assert f.read() == data


@pytest.mark.parametrize("chunk_size", [1024, 4096, 65536])
def test_roundtrip_multichunk(tmp, chunk_size):
    i, e, o = tmp(f"c{chunk_size}")
    # 3.5 chunks worth of data
    data = os.urandom(chunk_size * 3 + chunk_size // 2)
    with open(i, "wb") as f:
        f.write(data)
    r = encrypt_file(i, e, password="pw", security_level="standard",
                     chunk_size=chunk_size)
    assert r["chunks"] == 4
    decrypt_file(e, o, password="pw")
    with open(o, "rb") as f:
        assert f.read() == data


def test_roundtrip_exact_chunk_boundary(tmp):
    i, e, o = tmp("boundary")
    data = os.urandom(4096 * 2)  # exactly 2 chunks
    with open(i, "wb") as f:
        f.write(data)
    r = encrypt_file(i, e, password="pw", security_level="standard",
                     chunk_size=4096)
    assert r["chunks"] == 2
    decrypt_file(e, o, password="pw")
    with open(o, "rb") as f:
        assert f.read() == data


@pytest.mark.parametrize("level", ["standard"])  # only standard for CI speed
def test_roundtrip_levels(tmp, level):
    i, e, o = tmp(f"lvl{level}")
    data = os.urandom(50000)
    with open(i, "wb") as f:
        f.write(data)
    encrypt_file(i, e, password="pw", security_level=level)
    decrypt_file(e, o, password="pw")
    with open(o, "rb") as f:
        assert f.read() == data


def test_unicode_password(tmp):
    i, e, o = tmp("uni")
    data = b"payload"
    with open(i, "wb") as f:
        f.write(data)
    pw = "пароль🔐密码"
    encrypt_file(i, e, password=pw, security_level="standard")
    decrypt_file(e, o, password=pw)
    with open(o, "rb") as f:
        assert f.read() == data


# ── Messages ──────────────────────────────────────────────────────

def test_message_roundtrip():
    tok = encrypt_message("hello world", password="pw", security_level="standard")
    assert tok.startswith("FORTRESS:")
    assert decrypt_message(tok, password="pw") == "hello world"


def test_message_unicode():
    msg = "日本語 + emoji 🔐 + ελληνικά"
    tok = encrypt_message(msg, password="pw", security_level="standard")
    assert decrypt_message(tok, password="pw") == msg


def test_message_empty():
    tok = encrypt_message("", password="pw", security_level="standard")
    assert decrypt_message(tok, password="pw") == ""


def test_message_wrong_password():
    tok = encrypt_message("secret", password="right", security_level="standard")
    with pytest.raises(ValueError):
        decrypt_message(tok, password="wrong")
