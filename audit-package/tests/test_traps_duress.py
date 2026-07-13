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
test_traps_duress.py — Trap sequence and duress (destructive) behavior.

These test the SHIPPING behavior where wrong trap codes destroy the file and
the duress password wipes the real data. The audit fork (test_audit_fork.py)
tests the non-destructive variant.
"""

import os
import pytest

from fortress import encrypt_file, decrypt_file, TrapTriggered


def _is_audit_fork():
    """The audit fork exposes TrapVerificationError; the shipping build does not."""
    try:
        from fortress import TrapVerificationError  # noqa: F401
        return True
    except ImportError:
        return False


# These tests assert the SHIPPING build's destructive behavior. When the audit
# fork is installed they are skipped (the fork is non-destructive by design and
# has its own tests in test_audit_fork.py).
pytestmark = pytest.mark.skipif(
    _is_audit_fork(),
    reason="destructive-behavior tests target the shipping build; "
           "audit fork is non-destructive (see test_audit_fork.py)",
)


@pytest.fixture
def paths(tmp_path):
    def _p(name):
        return (str(tmp_path / f"{name}.in"),
                str(tmp_path / f"{name}.fortress"),
                str(tmp_path / f"{name}.out"))
    return _p


# ── Trap sequence ─────────────────────────────────────────────────

def test_trap_correct_sequence(paths):
    i, e, o = paths("t_ok")
    data = b"guarded secret"
    with open(i, "wb") as f:
        f.write(data)
    r = encrypt_file(i, e, password="pw", security_level="standard",
                     trap_codes=["alpha", "bravo", "charlie"])
    assert r["traps_set"] == 3
    decrypt_file(e, o, password="pw", trap_codes=["alpha", "bravo", "charlie"])
    with open(o, "rb") as f:
        assert f.read() == data


def test_trap_wrong_code_destroys(paths):
    i, e, o = paths("t_wrong")
    with open(i, "wb") as f:
        f.write(b"data")
    encrypt_file(i, e, password="pw", security_level="standard",
                 trap_codes=["one", "two"])
    with pytest.raises(TrapTriggered):
        decrypt_file(e, o, password="pw", trap_codes=["WRONG", "two"])
    # File must now be unrecoverable even with correct codes
    with pytest.raises((TrapTriggered, ValueError)):
        decrypt_file(e, o, password="pw", trap_codes=["one", "two"])


def test_trap_wrong_order_destroys(paths):
    i, e, o = paths("t_order")
    with open(i, "wb") as f:
        f.write(b"data")
    encrypt_file(i, e, password="pw", security_level="standard",
                 trap_codes=["first", "second"])
    with pytest.raises(TrapTriggered):
        decrypt_file(e, o, password="pw", trap_codes=["second", "first"])


def test_trap_wrong_count_destroys(paths):
    i, e, o = paths("t_count")
    with open(i, "wb") as f:
        f.write(b"data")
    encrypt_file(i, e, password="pw", security_level="standard",
                 trap_codes=["x", "y", "z"])
    with pytest.raises(TrapTriggered):
        decrypt_file(e, o, password="pw", trap_codes=["x", "y"])


# ── Duress ────────────────────────────────────────────────────────

def test_duress_real_password_gets_real(paths):
    i, e, o = paths("d_real")
    real = os.urandom(40000)
    dummy = b"grocery list: eggs, milk"
    with open(i, "wb") as f:
        f.write(real)
    r = encrypt_file(i, e, password="realpw", security_level="standard",
                     duress_password="fakepw", duress_data=dummy)
    assert r["duress_enabled"] is True
    res = decrypt_file(e, o, password="realpw")
    assert res["duress"] is False
    with open(o, "rb") as f:
        assert f.read() == real


def test_duress_fake_password_gets_dummy_and_wipes_real(paths):
    i, e, o = paths("d_fake")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw")
    assert res["duress"] is True
    with open(o, "rb") as f:
        assert f.read() == dummy
    # Real data must now be destroyed
    with pytest.raises(ValueError):
        decrypt_file(e, o + "2", password="realpw")


def test_duress_multichunk_dummy(paths):
    i, e, o = paths("d_multi")
    real = os.urandom(30000)
    dummy = os.urandom(70000)  # multiple chunks
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=dummy,
                 chunk_size=4096)
    decrypt_file(e, o, password="fakepw")
    with open(o, "rb") as f:
        assert f.read() == dummy


def test_duress_wrong_password_rejected(paths):
    i, e, o = paths("d_neither")
    with open(i, "wb") as f:
        f.write(b"data")
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=b"decoy")
    with pytest.raises(ValueError):
        decrypt_file(e, o, password="neither_password")


# ── Combined ──────────────────────────────────────────────────────

def test_traps_plus_duress(paths):
    i, e, o = paths("combo")
    real = b"top secret real"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 trap_codes=["gate"], duress_password="fakepw",
                 duress_data=b"decoy content")
    # Correct trap + real password
    decrypt_file(e, o, password="realpw", trap_codes=["gate"])
    with open(o, "rb") as f:
        assert f.read() == real


def test_traps_checked_before_password(paths):
    """Wrong trap must destroy file before the password is even evaluated."""
    i, e, o = paths("combo2")
    with open(i, "wb") as f:
        f.write(b"real")
    encrypt_file(i, e, password="realpw", security_level="standard",
                 trap_codes=["pin"], duress_password="fakepw",
                 duress_data=b"decoy")
    with pytest.raises(TrapTriggered):
        decrypt_file(e, o, password="realpw", trap_codes=["WRONG"])
