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

from fortress import encrypt_file, decrypt_file, TrapTriggered, destroy_real_data_after_duress


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


def test_duress_standard_level_does_not_auto_wipe_real(paths):
    """
    AUDIT_FINDINGS.md FC-02: the automatic real-data wipe on duress match can
    never be cryptographically tied to the real password (a duress-password
    holder never has the header_auth_key needed to authenticate the header),
    so for standard/high levels it's no longer automatic — real data must
    survive a duress decrypt unless the caller explicitly opts in.
    """
    i, e, o = paths("d_fake")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw")
    assert res["duress"] is True
    assert res["real_data_destroyed"] is False
    with open(o, "rb") as f:
        assert f.read() == dummy
    # Real data must still be recoverable — no automatic wipe at this level
    res2 = decrypt_file(e, o + "2", password="realpw")
    assert res2["duress"] is False
    with open(o + "2", "rb") as f:
        assert f.read() == real


def test_duress_paranoid_level_auto_wipes_real(paths):
    """paranoid/fortress levels keep the original automatic, silent wipe."""
    i, e, o = paths("d_paranoid")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="paranoid",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw")
    assert res["duress"] is True
    assert res["real_data_destroyed"] is True
    with open(o, "rb") as f:
        assert f.read() == dummy
    # Real data must now be destroyed
    with pytest.raises(ValueError):
        decrypt_file(e, o + "2", password="realpw")


def test_destroy_real_data_after_duress_explicit_opt_in(paths):
    """standard/high callers can still get the wipe by asking for it explicitly."""
    i, e, o = paths("d_optin")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw")
    assert res["real_data_destroyed"] is False

    destroy_real_data_after_duress(e)

    with pytest.raises(ValueError):
        decrypt_file(e, o + "2", password="realpw")


def test_destroy_real_on_duress_override_forces_wipe_at_standard_level(paths):
    """destroy_real_on_duress=True forces the wipe even at standard/high."""
    i, e, o = paths("d_force_on")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw", destroy_real_on_duress=True)
    assert res["real_data_destroyed"] is True
    with pytest.raises(ValueError):
        decrypt_file(e, o + "2", password="realpw")


def test_destroy_real_on_duress_override_prevents_wipe_at_paranoid_level(paths):
    """destroy_real_on_duress=False suppresses the wipe even at paranoid/fortress."""
    i, e, o = paths("d_force_off")
    real = os.urandom(40000)
    dummy = b"nothing to see here"
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="paranoid",
                 duress_password="fakepw", duress_data=dummy)
    res = decrypt_file(e, o, password="fakepw", destroy_real_on_duress=False)
    assert res["real_data_destroyed"] is False
    res2 = decrypt_file(e, o + "2", password="realpw")
    assert res2["duress"] is False
    with open(o + "2", "rb") as f:
        assert f.read() == real


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
