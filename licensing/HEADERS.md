# Source File License Headers

Add the appropriate notice to the top of every source file. The FSF recommends a
per-file notice so the license travels with the code even if a single file is
copied out of the project. Replace `2025` with the current year on new files;
keep the original year on existing files and add new years as a range if edited
across years (e.g., `2025–2026`).

Below are ready-to-paste headers per language. The `apply_headers.py` script in
this folder can insert the Python/Kotlin/Swift/C variants automatically.

---

## Python (`.py`)

```python
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
```

## Swift (`.swift`), Kotlin (`.kt`), C (`.c` / `.h`), and other C-style files

```
//
//  Fortress Crypt — 6-layer cascade encryption system
//  Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//  For commercial licensing without the AGPL's copyleft obligations,
//  contact the Maintainer (see README).
//
```

## Short SPDX form (optional, for brevity on small files)

If you prefer a compact notice, this single-line SPDX tag is machine-readable and
widely recognized. It complements — but does not replace — the full LICENSE file:

```
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
```

(Use `//` instead of `#` for Swift/Kotlin/C.)

---

## The "or-later" choice

The headers above say **"either version 3 of the License, or (at your option) any
later version"** — this is `AGPL-3.0-or-later`. It lets the project adopt a future
AGPL version if the FSF publishes one. If you want to pin strictly to version 3,
use `AGPL-3.0-only` and remove the "or (at your option) any later version" clause.
`-or-later` is the more common and generally recommended choice.
