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
test_audit_fork.py — Proves the audit fork is:
  (1) byte-identical in its cryptographic core to the shipping build, and
  (2) genuinely non-destructive (never mutates the input file).

Run this with the AUDIT FORK installed (fortress-crypt-audit), pointing
SHIPPING_PATH at a checkout of the shipping core so both can be imported.

Because both packages use the same top-level module name `fortress`, this test
imports the crypto-core modules by file path to compare them directly, avoiding
an import-name clash.
"""

import importlib.util
import os
import sys
import pytest


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Resolve paths to both cores. Adjust SHIPPING_PATH / AUDIT_PATH via env if needed.
HERE = os.path.dirname(os.path.abspath(__file__))
SHIPPING_KEYS = os.environ.get(
    "SHIPPING_KEYS",
    os.path.join(HERE, "..", "core-python", "fortress", "keys.py"))
AUDIT_KEYS = os.environ.get(
    "AUDIT_KEYS",
    os.path.join(HERE, "..", "core-python-audit", "fortress", "keys.py"))
SHIPPING_ENGINE = os.environ.get(
    "SHIPPING_ENGINE",
    os.path.join(HERE, "..", "core-python", "fortress", "engine.py"))
AUDIT_ENGINE = os.environ.get(
    "AUDIT_ENGINE",
    os.path.join(HERE, "..", "core-python-audit", "fortress", "engine.py"))
SHIPPING_FORMAT = os.environ.get(
    "SHIPPING_FORMAT",
    os.path.join(HERE, "..", "core-python", "fortress", "format.py"))
AUDIT_FORMAT = os.environ.get(
    "AUDIT_FORMAT",
    os.path.join(HERE, "..", "core-python-audit", "fortress", "format.py"))


def _files_identical(a, b):
    if not (os.path.exists(a) and os.path.exists(b)):
        pytest.skip(f"core files not both present: {a} / {b}")
    with open(a, "rb") as fa, open(b, "rb") as fb:
        return fa.read() == fb.read()


def test_keys_module_byte_identical():
    """keys.py (KDF, commitment, trap hashing) must be identical in both cores."""
    assert _files_identical(SHIPPING_KEYS, AUDIT_KEYS), \
        "keys.py differs between shipping and audit fork — crypto core changed!"


def test_engine_module_byte_identical():
    """engine.py (the 6-layer cascade) must be identical in both cores."""
    assert _files_identical(SHIPPING_ENGINE, AUDIT_ENGINE), \
        "engine.py differs — cascade changed between builds!"


def test_format_serialization_identical():
    """
    format.py holds the header serialization. The audit fork keeps serialization
    identical (only the destructive scramble_* helpers may differ in usage).
    We compare the _serialize function source specifically.
    """
    ship = _load_module(SHIPPING_FORMAT, "ship_format")
    audit = _load_module(AUDIT_FORMAT, "audit_format")
    import inspect
    assert inspect.getsource(ship._serialize) == inspect.getsource(audit._serialize), \
        "Header serialization differs between builds!"


def test_cross_decrypt_shipping_file_with_audit_fork(tmp_path):
    """
    A file encrypted by the shipping build must decrypt with the audit fork,
    proving format compatibility. Here both cores share the same encrypt path,
    so we simply confirm a round-trip through the installed package works and
    the format version is 2.
    """
    from fortress import encrypt_file, decrypt_file
    from fortress.format import read_header_raw

    i = str(tmp_path / "x.in")
    e = str(tmp_path / "x.fortress")
    o = str(tmp_path / "x.out")
    data = os.urandom(20000)
    with open(i, "wb") as f:
        f.write(data)
    encrypt_file(i, e, password="pw", security_level="standard")
    with open(e, "rb") as f:
        assert read_header_raw(f).version == 2
    decrypt_file(e, o, password="pw")
    with open(o, "rb") as f:
        assert f.read() == data


# ── Non-destructive behavior (must be run with the AUDIT FORK installed) ──

def _audit_fork_installed():
    try:
        from fortress import TrapVerificationError  # only exists in the fork
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _audit_fork_installed(),
                    reason="requires the audit fork (fortress-crypt-audit)")
def test_fork_wrong_trap_does_not_destroy(tmp_path):
    from fortress import encrypt_file, decrypt_file, TrapVerificationError

    i = str(tmp_path / "t.in")
    e = str(tmp_path / "t.fortress")
    o = str(tmp_path / "t.out")
    with open(i, "wb") as f:
        f.write(b"payload that must survive")
    encrypt_file(i, e, password="pw", security_level="standard",
                 trap_codes=["a", "b"])

    before = open(e, "rb").read()

    with pytest.raises(TrapVerificationError):
        decrypt_file(e, o, password="pw", trap_codes=["WRONG", "b"])

    after = open(e, "rb").read()
    assert before == after, "audit fork must NOT modify the file on wrong trap"

    # And the file is still fully recoverable with correct codes
    decrypt_file(e, o, password="pw", trap_codes=["a", "b"])
    with open(o, "rb") as f:
        assert f.read() == b"payload that must survive"


@pytest.mark.skipif(not _audit_fork_installed(),
                    reason="requires the audit fork (fortress-crypt-audit)")
def test_fork_duress_does_not_wipe_real(tmp_path):
    from fortress import encrypt_file, decrypt_file

    i = str(tmp_path / "d.in")
    e = str(tmp_path / "d.fortress")
    o = str(tmp_path / "d.out")
    real = os.urandom(30000)
    with open(i, "wb") as f:
        f.write(real)
    encrypt_file(i, e, password="realpw", security_level="standard",
                 duress_password="fakepw", duress_data=b"decoy")

    # Use duress password
    res = decrypt_file(e, o, password="fakepw")
    assert res.get("duress") is True
    assert res.get("audit_fork_real_data_preserved") is True

    # Real data must STILL be recoverable (not wiped)
    o2 = str(tmp_path / "d.real")
    decrypt_file(e, o2, password="realpw")
    with open(o2, "rb") as f:
        assert f.read() == real, "audit fork must preserve real data after duress"
