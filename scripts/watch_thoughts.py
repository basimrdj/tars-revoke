#!/usr/bin/env python3
"""Watch TARS think — pretty live tail of tars_thoughts.jsonl.

Usage:
    python3 scripts/watch_thoughts.py            # follow new thoughts only
    python3 scripts/watch_thoughts.py --all      # show everything from start
    python3 scripts/watch_thoughts.py --kind wish    # filter by kind
    python3 scripts/watch_thoughts.py --salience 0.5 # only thoughts >= salience
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path


# ANSI colors per thought kind. Salience controls intensity.
KIND_COLORS = {
    "reflection":  "\033[36m",    # cyan
    "observation": "\033[32m",    # green
    "wish":        "\033[35m",    # magenta
    "critique":    "\033[31m",    # red
    "fragment":    "\033[90m",    # grey
}
RESET = "\033[0m"
DIM   = "\033[2m"
BOLD  = "\033[1m"

# Mood → tiny symbol, just for at-a-glance vibe scanning
MOOD_GLYPH = {
    "curious": "?", "bored": "z", "amused": ":)", "focused": ">",
    "uneasy": "!", "content": ".",
}


def fmt(thought: dict) -> str:
    kind = thought.get("kind", "?")
    mood = thought.get("mood", "?")
    sal  = float(thought.get("salience", 0.0))
    ts   = thought.get("ts", "")[11:19]   # HH:MM:SS only
    content = thought.get("content", "").strip()
    color = KIND_COLORS.get(kind, "")
    glyph = MOOD_GLYPH.get(mood, mood[:1])
    bar = "█" * int(round(sal * 5)) + "·" * (5 - int(round(sal * 5)))
    head = f"{DIM}{ts}{RESET} {color}{kind:<10}{RESET} {glyph} {DIM}sal:{RESET}{bar}"
    body = content if len(content) < 200 else content[:197] + "…"
    return f"{head}\n  {color}{body}{RESET}"


def follow(path: Path, args) -> None:
    if args.all and path.exists():
        with path.open(encoding="utf-8") as f:
            for line in f:
                emit_if_match(line, args)

    # Wait for the file to exist (TARS may not have written its first thought yet)
    while not path.exists():
        sys.stderr.write(f"\r{DIM}waiting for {path.name}…{RESET}")
        sys.stderr.flush()
        time.sleep(0.5)
    sys.stderr.write("\r" + " " * 70 + "\r")

    with path.open(encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            pos = f.tell()
            line = f.readline()
            if line:
                emit_if_match(line, args)
            else:
                f.seek(pos)
                time.sleep(0.5)


def emit_if_match(line: str, args) -> None:
    line = line.strip()
    if not line:
        return
    try:
        t = json.loads(line)
    except Exception:
        return
    if args.kind and t.get("kind") != args.kind:
        return
    try:
        if float(t.get("salience", 0.0)) < args.salience:
            return
    except Exception:
        return
    print(fmt(t), flush=True)


def main() -> int:
    p = argparse.ArgumentParser(description="Live tail of TARS's inner thoughts.")
    p.add_argument("--all", action="store_true",
                   help="Replay everything from the start, then follow.")
    p.add_argument("--kind", choices=list(KIND_COLORS.keys()),
                   help="Only show thoughts of this kind.")
    p.add_argument("--salience", type=float, default=0.0,
                   help="Only show thoughts at or above this salience (0.0-1.0).")
    p.add_argument("--path", default=None,
                   help="Override path to thoughts file.")
    args = p.parse_args()

    here = Path(__file__).resolve().parent.parent
    path = Path(args.path) if args.path else here / "tars_thoughts.jsonl"
    sys.stderr.write(f"{BOLD}watching:{RESET} {path}\n")
    if args.kind: sys.stderr.write(f"  filter: kind={args.kind}\n")
    if args.salience: sys.stderr.write(f"  filter: salience>={args.salience}\n")
    sys.stderr.write("\n")
    sys.stderr.flush()
    try:
        follow(path, args)
    except KeyboardInterrupt:
        sys.stderr.write("\nbye\n")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
