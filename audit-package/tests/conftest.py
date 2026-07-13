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
conftest.py — shared pytest configuration for the Fortress test suite.

Package selection
-----------------
Most tests (test_kdf, test_roundtrip, test_integrity, test_traps_duress) run
against whichever `fortress` package is installed. Install ONE of:

    pip install -e core-python          # shipping build (destructive)
    pip install -e core-python-audit    # audit fork (non-destructive)

Then run:  pytest tests/

The fork-specific tests in test_audit_fork.py auto-skip unless the audit fork is
the active package (detected by the presence of TrapVerificationError).

To run the byte-identity tests you need BOTH cores present on disk (they compare
files by path, no import needed); this is the default layout of this package.
"""

import pytest
