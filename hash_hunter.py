#!/usr/bin/env python3
"""
hash_hunter.py -- Main CLI entry point for Hash Hunter.

Usage:
    python hash_hunter.py -H "5f4dcc3b5aa765d61d8327deb882cf99"
    python hash_hunter.py -f hashes.txt
    python hash_hunter.py -H "<hash>" --crack --wordlist /usr/share/wordlists/rockyou.txt
    python hash_hunter.py -H "<hash>" --identify-only
    python hash_hunter.py -H "<hash>" --format hashcat
    python hash_hunter.py -H "<hash>" --format john | clip
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from hash_types import HashMatch, identify_hash
from cracker import crack_hashes

console = Console()
VERSION = "1.0.0"

# Raw string so backslashes in the ASCII art don't need escaping.
BANNER = r"""
 _   _           _       _   _             _
| | | | __ _ ___| |__   | | | |_   _ _ __ | |_ ___ _ __
| |_| |/ _` / __| '_ \  | |_| | | | | '_ \| __/ _ \ '__|
|  _  | (_| \__ \ | | | |  _  | |_| | | | | ||  __/ |
|_| |_|\__,_|___/_| |_| |_| |_|\__,_|_| |_|\__\___|_|"""

_CONFIDENCE = {
    "high":   "[bold green]\u25a0\u25a0\u25a0\u25a0\u25a0  High[/bold green]",
    "medium": "[bold yellow]\u25a0\u25a0\u25a0    Medium[/bold yellow]",
    "low":    "[bold red]\u25a0      Low[/bold red]",
}


def _print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        f"[dim]  Hash Identification & Cracking Assistant for CTF / Pentesting  |  v{VERSION}[/dim]\n"
    )


def _conf(level: str) -> str:
    return _CONFIDENCE.get(level, level)


def _display_hash(
    hash_str: str,
    matches: List[HashMatch],
    wordlist: Optional[str],
    crack: bool,
    identify_only: bool = False,
    fmt: Optional[str] = None,
) -> None:
    # -- --format mode: plain stdout only, pipeable ---------------------------
    if fmt is not None:
        wl = wordlist or "/usr/share/wordlists/rockyou.txt"
        for m in matches:
            if fmt == "hashcat" and m.hashcat_mode is not None:
                print(f"hashcat -m {m.hashcat_mode} hash.txt {wl}")
            elif fmt == "john" and m.john_format != "N/A":
                print(f"john --format={m.john_format} --wordlist={wl} hash.txt")
        return

    display = hash_str if len(hash_str) <= 76 else hash_str[:73] + "..."
    console.print(
        Panel(
            f"[bold white]{display}[/bold white]\n[dim]Length: {len(hash_str)} characters[/dim]",
            title="[bold cyan]Hash[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    if not matches:
        console.print(
            "  [bold red]No matching hash type found.[/bold red]\n"
            "  [dim]The hash may be salted, non-standard, or truncated.[/dim]\n"
        )
        return

    # -- identification table -------------------------------------------------
    tbl = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=True,
        header_style="bold magenta",
        padding=(0, 1),
    )
    tbl.add_column("Type",        style="bold white",  min_width=20)
    tbl.add_column("Description", style="dim white",   min_width=40)
    tbl.add_column("Hashcat",     style="bold green",  min_width=10, justify="center")
    tbl.add_column("John",        style="bold yellow", min_width=22, justify="center")
    tbl.add_column("Confidence",  min_width=16)

    for m in matches:
        hc = f"-m {m.hashcat_mode}" if m.hashcat_mode is not None else "[dim]N/A[/dim]"
        tbl.add_row(m.name, m.description, hc, f"--format={m.john_format}", _conf(m.confidence))

    console.print(tbl)

    if identify_only:
        console.print()
        return

    # -- command suggestions --------------------------------------------------
    wl = wordlist or "/usr/share/wordlists/rockyou.txt"
    console.print("\n[bold cyan]  Suggested Commands[/bold cyan]")
    console.print("  [dim]# Save the hash first:[/dim]")
    console.print(f"  [dim]echo {hash_str!r} > hash.txt[/dim]\n")

    for m in matches:
        console.print(f"  [bold green]# {m.name} -- hashcat[/bold green]")
        if m.hashcat_mode is not None:
            console.print(f"  hashcat -m {m.hashcat_mode} hash.txt {wl}")
        else:
            console.print(f"  [dim](hashcat mode unavailable: {m.description})[/dim]")
        console.print(f"\n  [bold yellow]# {m.name} -- john[/bold yellow]")
        console.print(f"  john --format={m.john_format} --wordlist={wl} hash.txt\n")

    if not crack or not wordlist:
        return

    # -- optional cracking ----------------------------------------------------
    console.print(Rule("[bold red]  Cracking  [/bold red]"))
    crackable = [m for m in matches if m.hashcat_mode is not None]

    if not crackable:
        console.print("[yellow]  No hashcat-supported mode for this hash type -- skipping.[/yellow]\n")
        return

    target = next((m for m in crackable if m.confidence == "high"), crackable[0])
    console.print(
        f"  [bold]Cracking as [cyan]{target.name}[/cyan] "
        f"(hashcat -m {target.hashcat_mode})[/bold]\n"
    )

    results = crack_hashes([hash_str], target.hashcat_mode, wordlist)
    if results is None:
        return

    if results:
        rt = Table(
            box=box.SIMPLE, border_style="green",
            show_header=True, header_style="bold green",
        )
        rt.add_column("Hash",      style="dim white")
        rt.add_column("Plaintext", style="bold green")
        for r in results:
            rt.add_row(r["hash"], r["plaintext"])
        console.print(rt)
        console.print(f"  [bold green]Cracked {len(results)} hash(es).[/bold green]")
    else:
        console.print("  [yellow]No passwords found in the provided wordlist.[/yellow]")

    console.print()


def _process_hashes(
    hashes: List[str],
    wordlist: Optional[str],
    crack: bool,
    identify_only: bool = False,
    fmt: Optional[str] = None,
) -> None:
    cleaned = [h.strip() for h in hashes if h.strip() and not h.startswith("#")]
    if not cleaned:
        console.print("[yellow]No hashes to process.[/yellow]")
        return
    for i, h in enumerate(cleaned):
        if len(cleaned) > 1 and fmt is None:
            console.print(Rule(f"[dim]Hash {i + 1} of {len(cleaned)}[/dim]"))
        matches = identify_hash(h)
        _display_hash(h, matches, wordlist=wordlist, crack=crack,
                      identify_only=identify_only, fmt=fmt)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hash_hunter",
        description="Hash Hunter -- identify and optionally crack hashes (CTF/pentesting)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python hash_hunter.py -H 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "  python hash_hunter.py -f hashes.txt\n"
            "  python hash_hunter.py -H <hash> --crack --wordlist /usr/share/wordlists/rockyou.txt\n"
            "  python hash_hunter.py -H <hash> --identify-only\n"
            "  python hash_hunter.py -H <hash> --format hashcat\n"
            "  python hash_hunter.py -H <hash> --format john | clip\n"
        ),
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-H", "--hash", metavar="HASH", help="Single hash string to identify")
    src.add_argument("-f", "--file", metavar="FILE", help="File of hashes, one per line")
    p.add_argument(
        "--crack", action="store_true",
        help="Attempt to crack hashes with hashcat (requires --wordlist)",
    )
    p.add_argument(
        "--wordlist", metavar="PATH",
        help="Wordlist path for hashcat (used with --crack)",
    )
    p.add_argument(
        "--identify-only", action="store_true",
        help="Show hash type(s) only -- no suggested commands, no cracking output",
    )
    p.add_argument(
        "--format", metavar="TOOL", choices=["john", "hashcat"],
        help="Print only TOOL commands to plain stdout (pipeable). TOOL: john|hashcat",
    )
    p.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    p.add_argument("--version",   action="version",   version=f"Hash Hunter v{VERSION}")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    if args.crack and not args.wordlist:
        console.print("[bold red]Error:[/bold red] --crack requires --wordlist.")
        sys.exit(1)

    if not args.no_banner and args.format is None:
        _print_banner()

    if args.hash:
        hashes = [args.hash]
    else:
        p = Path(args.file)
        if not p.exists():
            console.print(f"[bold red]Error:[/bold red] File not found: {args.file}")
            sys.exit(1)
        hashes = p.read_text(encoding="utf-8", errors="replace").splitlines()

    _process_hashes(
        hashes,
        wordlist=args.wordlist,
        crack=args.crack,
        identify_only=args.identify_only,
        fmt=args.format,
    )


if __name__ == "__main__":
    main()
