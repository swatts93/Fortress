#!/usr/bin/env python3
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
apply_headers.py — Insert AGPL-3.0 license headers into source files.

Usage:
    python3 apply_headers.py --root /path/to/fortress-crypt-suite [--year 2025] [--dry-run]
    python3 apply_headers.py --root . --check     # exit 1 if any file is missing a header

Handles .py, .swift, .kt, .c, .h. Skips files that already contain a Fortress
copyright line (idempotent — safe to run repeatedly). Preserves Python shebang
lines and existing coding declarations by inserting the header after them.
"""

import argparse
import os
import sys

AUTHOR = "Steve Watts, The Lion's Kingdom IT Solutions, LLC"
PROJECT = "Fortress Crypt — 6-layer cascade encryption system"
MARKER = "Fortress Crypt"  # presence of this in the first ~20 lines = already headered

HASH_LANGS = {".py"}
SLASH_LANGS = {".swift", ".kt", ".c", ".h"}


def hash_header(year: str) -> str:
    return (
        f"# {PROJECT}\n"
        f"# Copyright (C) {year} {AUTHOR}\n"
        f"#\n"
        f"# This program is free software: you can redistribute it and/or modify\n"
        f"# it under the terms of the GNU Affero General Public License as published\n"
        f"# by the Free Software Foundation, either version 3 of the License, or\n"
        f"# (at your option) any later version.\n"
        f"#\n"
        f"# This program is distributed in the hope that it will be useful,\n"
        f"# but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        f"# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
        f"# GNU Affero General Public License for more details.\n"
        f"#\n"
        f"# You should have received a copy of the GNU Affero General Public License\n"
        f"# along with this program.  If not, see <https://www.gnu.org/licenses/>.\n"
        f"#\n"
        f"# For commercial licensing without the AGPL's copyleft obligations,\n"
        f"# contact the Maintainer (see README).\n\n"
    )


def slash_header(year: str) -> str:
    return (
        f"//\n"
        f"//  {PROJECT}\n"
        f"//  Copyright (C) {year} {AUTHOR}\n"
        f"//\n"
        f"//  This program is free software: you can redistribute it and/or modify\n"
        f"//  it under the terms of the GNU Affero General Public License as published\n"
        f"//  by the Free Software Foundation, either version 3 of the License, or\n"
        f"//  (at your option) any later version.\n"
        f"//\n"
        f"//  This program is distributed in the hope that it will be useful,\n"
        f"//  but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        f"//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
        f"//  GNU Affero General Public License for more details.\n"
        f"//\n"
        f"//  You should have received a copy of the GNU Affero General Public License\n"
        f"//  along with this program.  If not, see <https://www.gnu.org/licenses/>.\n"
        f"//\n"
        f"//  For commercial licensing without the AGPL's copyleft obligations,\n"
        f"//  contact the Maintainer (see README).\n"
        f"//\n\n"
    )


def already_headered(text: str) -> bool:
    head = "\n".join(text.splitlines()[:20])
    return MARKER in head and "GNU Affero" in head


def insert_header(path: str, year: str, dry_run: bool) -> bool:
    """Returns True if a header was (or would be) added."""
    ext = os.path.splitext(path)[1]
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    if already_headered(text):
        return False

    if ext in HASH_LANGS:
        header = hash_header(year)
        # Preserve shebang and coding lines at the very top
        lines = text.splitlines(keepends=True)
        prefix = ""
        idx = 0
        while idx < len(lines) and (
            lines[idx].startswith("#!") or "coding:" in lines[idx] or "coding=" in lines[idx]
        ):
            prefix += lines[idx]
            idx += 1
        new_text = prefix + header + "".join(lines[idx:])
    elif ext in SLASH_LANGS:
        new_text = slash_header(year) + text
    else:
        return False

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_text)
    return True


def iter_source_files(root: str):
    skip_dirs = {".git", "__pycache__", "build", ".gradle", ".idea",
                 "node_modules", ".pytest_cache", "DerivedData"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext in HASH_LANGS or ext in SLASH_LANGS:
                yield os.path.join(dirpath, fn)


def main():
    ap = argparse.ArgumentParser(description="Apply AGPL-3.0 headers to source files.")
    ap.add_argument("--root", required=True, help="Project root to process")
    ap.add_argument("--year", default="2025", help="Copyright year (default 2025)")
    ap.add_argument("--dry-run", action="store_true", help="Show what would change")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if any file lacks a header (for CI); no changes made")
    args = ap.parse_args()

    missing = []
    changed = []
    for path in iter_source_files(args.root):
        if args.check:
            with open(path, "r", encoding="utf-8") as f:
                if not already_headered(f.read()):
                    missing.append(path)
            continue
        if insert_header(path, args.year, args.dry_run):
            changed.append(path)

    if args.check:
        if missing:
            print("Files missing license header:")
            for p in missing:
                print(f"  {p}")
            sys.exit(1)
        print("All source files have a license header.")
        return

    verb = "Would add" if args.dry_run else "Added"
    for p in changed:
        print(f"  {verb} header: {p}")
    print(f"\n{verb} headers to {len(changed)} file(s).")


if __name__ == "__main__":
    main()
