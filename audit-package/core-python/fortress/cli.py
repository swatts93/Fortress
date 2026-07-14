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

"""Fortress CLI v2 — with trap sequence and duress mode."""

import sys, os, time, getpass
import click
from .api import (
    encrypt_file, decrypt_file, encrypt_message, decrypt_message,
    TrapTriggered,
)
from . import pq


def _progress(done, total, status):
    if total <= 0:
        click.echo(f"\r  {status}", nl=False)
        return
    pct = int(100 * done / total)
    filled = int(30 * done / total)
    bar = "#" * filled + "-" * (30 - filled)
    click.echo(f"\r  [{bar}] {pct:3d}% ({done}/{total}) {status}", nl=False)
    if done >= total:
        click.echo()


def _get_password(confirm=False):
    pw = getpass.getpass("Password: ")
    if not pw:
        click.echo("Error: empty password.", err=True); sys.exit(1)
    if confirm:
        if getpass.getpass("Confirm password: ") != pw:
            click.echo("Error: passwords don't match.", err=True); sys.exit(1)
    return pw


def _get_trap_codes(count):
    codes = []
    for i in range(count):
        code = getpass.getpass(f"Trap code #{i+1}: ")
        if not code:
            click.echo("Error: trap code cannot be empty.", err=True); sys.exit(1)
        codes.append(code)
    return codes


def _fmt(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024: return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


@click.group()
@click.version_option(version="2.0.0", prog_name="Fortress")
def cli():
    """
    ===============================================================
      FORTRESS v2 -- 6-Layer Cascade Encryption
      Post-Quantum / Triple-KDF / Traps / Duress Mode
    ===============================================================
    """
    pass


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path(), required=False)
@click.option("--level", "-l", default="paranoid",
              type=click.Choice(["standard", "high", "paranoid", "fortress"]))
@click.option("--pq-key", type=click.Path(exists=True), help="ML-KEM-1024 public key")
@click.option("--traps", "-t", type=int, default=0, help="Number of trap codes (1-5)")
@click.option("--duress", is_flag=True, help="Enable duress (dead man's switch) mode")
@click.option("--duress-file", type=click.Path(exists=True), help="Dummy data file for duress")
@click.option("--chunk-size", default=1048576, type=int)
def encrypt(input_file, output_file, level, pq_key, traps, duress, duress_file, chunk_size):
    """Encrypt a file with 6-layer cascade + optional traps & duress."""
    if output_file is None:
        output_file = input_file + ".fortress"

    click.echo(f"\n  FORTRESS ENCRYPT")
    click.echo(f"  Input:    {input_file} ({_fmt(os.path.getsize(input_file))})")
    click.echo(f"  Output:   {output_file}")
    click.echo(f"  Security: {level.upper()}")
    click.echo(f"  Layers:   6 (AES-256-GCM x2, ChaCha20 x2, Camellia-256 x2)")

    pk = pq.load_public_key(pq_key) if pq_key else None
    if pk: click.echo(f"  PQ Mode:  ML-KEM-1024 (hybrid)")

    # Trap codes
    trap_codes = None
    if traps > 0:
        if traps > 5:
            click.echo("Error: max 5 trap codes", err=True); sys.exit(1)
        click.echo(f"  Traps:    {traps} sequential codes (WRONG CODE = FILE DESTROYED)")
        click.echo()
        click.echo("  Set your trap code sequence:")
        trap_codes = []
        for i in range(traps):
            code = getpass.getpass(f"  Trap code #{i+1}: ")
            confirm = getpass.getpass(f"  Confirm #{i+1}:   ")
            if code != confirm:
                click.echo("  Error: codes don't match.", err=True); sys.exit(1)
            if not code:
                click.echo("  Error: empty code.", err=True); sys.exit(1)
            trap_codes.append(code)
        click.echo(f"  [OK] {traps} trap codes set")

    # Duress mode
    duress_password = None
    duress_data = None
    if duress:
        click.echo(f"  Duress:   ENABLED (dead man's switch)")
        click.echo()
        if duress_file:
            with open(duress_file, "rb") as df:
                duress_data = df.read()
            click.echo(f"  Duress dummy data: {duress_file} ({_fmt(len(duress_data))})")
        else:
            click.echo("  Enter dummy data (press Enter then Ctrl-D when done):")
            duress_data = click.get_text_stream("stdin").read().encode("utf-8") if not sys.stdin.isatty() else b"Nothing sensitive here."
            if not duress_data:
                duress_data = b"No sensitive data found."
            click.echo(f"  Duress dummy data: {_fmt(len(duress_data))}")

        duress_password = getpass.getpass("  Duress password: ")
        dp_confirm = getpass.getpass("  Confirm duress:  ")
        if duress_password != dp_confirm:
            click.echo("  Error: duress passwords don't match.", err=True); sys.exit(1)

    click.echo()
    password = _get_password(confirm=True)

    if duress_password and password == duress_password:
        click.echo("  Error: real and duress passwords must be different!", err=True)
        sys.exit(1)

    start = time.time()
    try:
        result = encrypt_file(
            input_file, output_file, password,
            pq_public_key=pk, security_level=level, chunk_size=chunk_size,
            progress=_progress, trap_codes=trap_codes,
            duress_password=duress_password, duress_data=duress_data,
        )
    except Exception as e:
        click.echo(f"\n  ERROR: {e}", err=True); sys.exit(1)

    elapsed = time.time() - start
    click.echo(f"\n  Encrypted in {elapsed:.1f}s")
    click.echo(f"  Output: {_fmt(result['output_size'])}")
    click.echo(f"  Traps:  {result['traps_set']}")
    click.echo(f"  Duress: {'Yes' if result['duress_enabled'] else 'No'}")
    click.echo()


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path(), required=False)
@click.option("--pq-key", type=click.Path(exists=True), help="ML-KEM-1024 secret key")
@click.option("--confirm-duress-wipe", is_flag=True,
              help="If the duress password is entered, immediately wipe the "
                   "real data section without an interactive confirmation "
                   "prompt (for scripted use).")
def decrypt(input_file, output_file, pq_key, confirm_duress_wipe):
    """Decrypt a .fortress file. Wrong trap codes = FILE DESTROYED."""
    if output_file is None:
        output_file = input_file[:-9] if input_file.endswith(".fortress") else input_file + ".dec"

    click.echo(f"\n  FORTRESS DECRYPT")
    click.echo(f"  Input:  {input_file}")
    click.echo(f"  Output: {output_file}")

    sk = pq.load_secret_key(pq_key) if pq_key else None

    # Read header to check for traps
    from .format import read_header_raw
    try:
        with open(input_file, "rb") as f:
            header = read_header_raw(f)
    except Exception as e:
        click.echo(f"\n  FAILED: {e}", err=True); sys.exit(1)

    # Trap codes first
    trap_codes = None
    if header.trap_count > 0:
        click.echo(f"\n  WARNING: This file has {header.trap_count} trap code(s).")
        click.echo(f"  WARNING: Wrong code = FILE PERMANENTLY DESTROYED")
        click.echo()
        trap_codes = _get_trap_codes(header.trap_count)

    click.echo()
    password = _get_password()

    start = time.time()
    try:
        result = decrypt_file(
            input_file, output_file, password,
            pq_secret_key=sk, progress=_progress, trap_codes=trap_codes,
            confirm_duress_wipe=confirm_duress_wipe,
        )
    except TrapTriggered as e:
        click.echo(f"\n\n  TRAP TRIGGERED: {e}", err=True)
        sys.exit(2)
    except ValueError as e:
        # Defense in depth: the core is expected to clean up any partial
        # output itself on failure (AUDIT_FINDINGS.md FC-03), but never
        # leave a half-decrypted file behind at the CLI layer either.
        if os.path.exists(output_file):
            try: os.remove(output_file)
            except OSError: pass
        click.echo(f"\n  FAILED: {e}", err=True); sys.exit(1)

    # Duress password recognized but the real data wipe wasn't pre-confirmed
    # via --confirm-duress-wipe: ask explicitly before doing anything
    # irreversible (AUDIT_FINDINGS.md FC-02).
    if result.get("duress") and not result.get("real_data_wiped", False):
        click.echo()
        if result.get("audit_fork_real_data_preserved"):
            # Non-destructive audit fork: there is nothing to confirm, the
            # real data is never wiped by this build. Don't ask a question
            # whose "yes" answer would then falsely claim destruction.
            click.echo("  NOTE: duress password recognized (audit fork -- "
                       "real data is never wiped by this build).")
        else:
            click.echo("  NOTE: duress password recognized.")
            click.echo("  NOTE: the real data section has NOT been wiped yet.")
            if click.confirm("  Permanently destroy the real data section now?", default=False):
                result = decrypt_file(
                    input_file, output_file, password,
                    pq_secret_key=sk, progress=_progress,
                    confirm_duress_wipe=True,
                )
                click.echo("  Real data section destroyed.")
            else:
                click.echo("  Real data section left intact.")

    elapsed = time.time() - start
    click.echo(f"\n  Decrypted in {elapsed:.1f}s")
    click.echo(f"  Size: {_fmt(result['original_size'])}")
    click.echo(f"  Chunks: {result['chunks']}")
    click.echo(f"  Verified: {result['verified']}")
    click.echo()


@cli.command("msg-enc")
@click.argument("message")
@click.option("--level", "-l", default="standard",
              type=click.Choice(["standard", "high", "paranoid", "fortress"]))
@click.option("--traps", "-t", type=int, default=0)
def msg_encrypt(message, level, traps):
    """Encrypt a text message."""
    trap_codes = _get_trap_codes(traps) if traps > 0 else None
    password = _get_password(confirm=True)
    try:
        token = encrypt_message(message, password, security_level=level, trap_codes=trap_codes)
        click.echo(f"\n{token}\n")
    except Exception as e:
        click.echo(f"Error: {e}", err=True); sys.exit(1)


@cli.command("msg-dec")
@click.argument("token")
def msg_decrypt(token):
    """Decrypt a Fortress message token."""
    from .format import read_header_raw
    import base64, io
    try:
        raw = base64.urlsafe_b64decode(token[9:]) if token.startswith("FORTRESS:") else b""
        if raw:
            buf = io.BytesIO(raw)
            h = read_header_raw(buf)
            trap_codes = _get_trap_codes(h.trap_count) if h.trap_count > 0 else None
        else:
            trap_codes = None
    except Exception as e:
        click.echo(f"FAILED: {e}", err=True); sys.exit(1)
    password = _get_password()
    try:
        click.echo(f"\n{decrypt_message(token, password, trap_codes=trap_codes)}\n")
    except ValueError as e:
        click.echo(f"FAILED: {e}", err=True); sys.exit(1)


@cli.command()
@click.option("--output-dir", "-o", default=".")
@click.option("--name", "-n", default="fortress")
def keygen(output_dir, name):
    """Generate ML-KEM-1024 post-quantum keypair."""
    if not pq.is_available():
        click.echo("Error: pqcrypto not installed", err=True); sys.exit(1)
    pk, sk = pq.generate_keypair()
    pub_path, sec_path = pq.save_keypair(pk, sk, output_dir, name)
    click.echo(f"  Public:  {pub_path}")
    click.echo(f"  Secret:  {sec_path}")
    click.echo(f"  WARNING: Keep {sec_path} safe!")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
def info(input_file):
    """Show .fortress file metadata."""
    from .format import read_header_raw
    try:
        with open(input_file, "rb") as f:
            h = read_header_raw(f)
    except Exception as e:
        click.echo(f"Error: {e}", err=True); sys.exit(1)
    modes = {0: "Password", 1: "PQ-Only", 2: "Hybrid PQ"}
    click.echo(f"\n  FORTRESS FILE INFO")
    click.echo(f"  Version:     {h.version}")
    click.echo(f"  Mode:        {modes.get(h.mode, '?')}")
    click.echo(f"  Orig size:   {_fmt(h.original_size)}")
    click.echo(f"  Chunks:      {h.total_chunks}")
    click.echo(f"  Argon2id:    t={h.argon2_time}, m={_fmt(h.argon2_memory*1024)}, p={h.argon2_parallelism}")
    click.echo(f"  scrypt:      N={h.scrypt_n}, r={h.scrypt_r}, p={h.scrypt_p}")
    click.echo(f"  Trap codes:  {h.trap_count}")
    click.echo(f"  Duress mode: {'Yes' if h.duress_enabled else 'No'}")
    click.echo(f"  Commitment:  {h.key_commitment[:16].hex()}...")
    click.echo()


def main():
    # The banner and progress output use box-drawing/emoji characters. On a
    # default Windows console (cp1252, not UTF-8), writing them raises
    # UnicodeEncodeError and crashes the CLI before any command runs.
    # Reconfigure to UTF-8 with a replace fallback so output degrades
    # gracefully instead of aborting the whole process.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    cli()

if __name__ == "__main__":
    main()
