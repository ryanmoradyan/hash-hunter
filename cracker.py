"""
cracker.py -- Hashcat subprocess integration for optional cracking.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from rich.console import Console

console = Console()


def _write_temp_hash_file(hashes: List[str]) -> str:
    """Write hashes to a named temp file; caller must delete."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="hh_")
    for h in hashes:
        tmp.write(h.strip() + "\n")
    tmp.close()
    return tmp.name


def _run_hashcat(hash_file: str, mode: int, wordlist: str, outfile: str) -> dict:
    """Execute hashcat and return a result dict."""
    cmd = [
        "hashcat",
        "-m", str(mode),
        hash_file,
        wordlist,
        "--quiet",
        "--potfile-disable",
        "--outfile", outfile,
        "--outfile-format", "2",   # hash:plain
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            "ok": result.returncode in (0, 1),   # 1 = "exhausted" is normal
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "stderr": (
                "hashcat not found -- install it and ensure it is in your PATH.\n"
                "Download: https://hashcat.net/hashcat/"
            ),
            "returncode": -1,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "stderr": "hashcat timed out after 5 minutes.", "returncode": -1}


def crack_hashes(hashes: List[str], hashcat_mode: int, wordlist: str) -> Optional[List[dict]]:
    """
    Attempt to crack hashes with hashcat.

    Returns a list of {"hash": ..., "plaintext": ...} dicts for cracked hashes,
    an empty list when none were cracked, or None on hard error.
    """
    if not Path(wordlist).exists():
        console.print(f"[bold red]Error:[/bold red] Wordlist not found: {wordlist}")
        return None

    hash_file = _write_temp_hash_file(hashes)
    out_file = hash_file + ".out"

    try:
        result = _run_hashcat(hash_file, hashcat_mode, wordlist, out_file)

        if not result["ok"]:
            msg = result["stderr"] or f"hashcat exited with code {result['returncode']}"
            console.print(f"[bold red]hashcat error:[/bold red] {msg}")
            return None

        if result["stderr"]:
            console.print(f"[yellow]hashcat warning:[/yellow] {result['stderr']}")

        cracked: List[dict] = []
        if Path(out_file).exists():
            for line in Path(out_file).read_text().splitlines():
                line = line.strip()
                if ":" in line:
                    hash_part, _, plain = line.partition(":")
                    cracked.append({"hash": hash_part, "plaintext": plain})
        return cracked

    finally:
        for f in (hash_file, out_file):
            try:
                os.unlink(f)
            except FileNotFoundError:
                pass
