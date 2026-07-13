#!/usr/bin/env python3
"""TARS — Deepgram TTS Discovery Probe (Phase −1 R6 evaluation)

Question we're answering: does Deepgram Aura have a voice that matches
TARS's deep/tactical/deadpan personality AS WELL AS MiMo's `Dean` does,
AND is it faster, AND can we keep the inline-tag expressiveness palette
that R5 unlocked? If yes to all three, switch. If any of them fails,
stay with MiMo.

Probes:

  A. /v1/speak with the most TARS-leaning Aura-2 male voices         (latency + voice fit)
  B. /v1/speak with classic Aura-1 male voices                       (older but battle-tested)
  C. SSML/break behavior — does <break time="500ms"/> work?          (silence control)
  D. Inline-tag survival — does Deepgram speak `[sigh]` literally    (R5 palette compatibility)
     or strip it? (Either is a regression vs MiMo; literal-spelling is the worse one.)
  E. Streaming TTFA — first audio byte arrival on the streaming endpoint  (real speed claim)

Budget: ~12 API calls (~$0.05 worst case at Deepgram pricing).

Output:
  scratch/probe_deepgram/<probe_id>.{wav,bin}
  scratch/probe_deepgram/REPORT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests


PROBE_TEXT = (
    "Newton's third law of motion. The only way humans have ever figured "
    "out of getting somewhere is to leave something behind."
)

PROBE_TEXT_TAGS = (
    "Hello there. [pause] I am running a test. [sigh] Just kidding."
)

PROBE_TEXT_SHORT = "Yes."

# Aura-2 (newest, "natural and expressive" per Deepgram docs).
# We pick male voices most likely to match a deep/tactical/deadpan persona.
AURA2_CANDIDATES = [
    "aura-2-zeus-en",
    "aura-2-mars-en",
    "aura-2-orion-en",
    "aura-2-saturn-en",
    "aura-2-jupiter-en",
    "aura-2-pluto-en",
    "aura-2-atlas-en",
    "aura-2-hyperion-en",
    "aura-2-odysseus-en",
]

# Aura-1 (older, lower latency, less expressive).
AURA1_CANDIDATES = [
    "aura-orion-en",
    "aura-perseus-en",
    "aura-zeus-en",
    "aura-angus-en",
]


@dataclass
class ProbeResult:
    name:    str
    ok:      bool
    bytes_received: int = 0
    audio_format:   Optional[str] = None
    file_path:      Optional[str] = None
    ttfa_ms:        Optional[int] = None
    total_ms:       int = 0
    duration_s:     Optional[float] = None
    error:          Optional[str] = None
    extra:          Dict[str, Any] = field(default_factory=dict)


def wav_duration(b: bytes) -> Optional[float]:
    """Parse WAV header → duration in seconds. None on parse fail."""
    if not b.startswith(b"RIFF") or len(b) < 44:
        return None
    i = 12
    byte_rate = data_size = 0
    while i < len(b) - 8:
        cid = b[i:i+4]
        sz  = struct.unpack("<I", b[i+4:i+8])[0]
        if cid == b"fmt ":
            byte_rate = struct.unpack("<I", b[i+16:i+20])[0]
        elif cid == b"data":
            data_size = sz
            break
        i += 8 + sz
    return (data_size / byte_rate) if byte_rate else None


def hash16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def load_env() -> Tuple[str, str]:
    """Manual .env loader (avoids dotenv's stack-frame heredoc bug)."""
    env: Dict[str, str] = {}
    try:
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    api  = os.getenv("DEEPGRAM_API_KEY") or env.get("DEEPGRAM_API_KEY", "")
    base = os.getenv("DEEPGRAM_TTS_BASE", "https://api.deepgram.com")
    return api, base


def fetch_speak(session: requests.Session, base_url: str, model: str,
                text: str, encoding: str = "linear16",
                sample_rate: int = 24000,
                container: str = "wav") -> Tuple[Optional[bytes], int, int, Optional[str]]:
    """Call Deepgram /v1/speak. Returns (audio_bytes, ttfa_ms, total_ms, err)."""
    url = base_url.rstrip("/") + "/v1/speak"
    params = {"model": model, "encoding": encoding,
              "sample_rate": sample_rate, "container": container}
    payload = {"text": text}
    t0 = time.time()
    try:
        resp = session.post(url, params=params, json=payload,
                            timeout=30, stream=True)
    except Exception as e:
        return None, 0, 0, f"network: {e}"
    if resp.status_code != 200:
        body = resp.text[:300]
        return None, 0, int((time.time()-t0)*1000), f"HTTP {resp.status_code}: {body}"
    # Measure TTFA: first content byte received.
    chunks: List[bytes] = []
    ttfa_ms: Optional[int] = None
    for chunk in resp.iter_content(chunk_size=4096):
        if chunk:
            if ttfa_ms is None:
                ttfa_ms = int((time.time() - t0) * 1000)
            chunks.append(chunk)
    audio = b"".join(chunks)
    total_ms = int((time.time() - t0) * 1000)
    return audio, ttfa_ms or total_ms, total_ms, None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="scratch/probe_deepgram")
    p.add_argument("--listen", action="store_true",
                   help="afplay successful clips after each fetch")
    p.add_argument("--quick", action="store_true",
                   help="3 Aura-2 voices instead of 9 + 4")
    args = p.parse_args()

    api_key, base_url = load_env()
    if not api_key:
        print("ERROR: DEEPGRAM_API_KEY not set", file=sys.stderr)
        return 2

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    print(f"target  : {base_url}")
    print(f"out dir : {out_dir}")

    sess = requests.Session()
    sess.headers.update({"Authorization": f"Token {api_key}",
                          "Content-Type":   "application/json"})

    results: List[ProbeResult] = []

    def run(probe_id: str, model: str, text: str = PROBE_TEXT) -> ProbeResult:
        print(f"\n  ─ {probe_id}  (model={model}, text='{text[:50]}…' len={len(text)})…", flush=True)
        audio, ttfa, total, err = fetch_speak(sess, base_url, model, text)
        if err:
            r = ProbeResult(probe_id, False, total_ms=total, error=err)
            results.append(r); print(f"      ✗ {err}"); return r
        if not audio:
            r = ProbeResult(probe_id, False, total_ms=total, error="no audio bytes")
            results.append(r); print(f"      ✗ no audio bytes"); return r
        path = os.path.join(out_dir, f"{probe_id}.wav")
        with open(path, "wb") as f: f.write(audio)
        dur = wav_duration(audio)
        r = ProbeResult(
            probe_id, True, len(audio),
            "wav" if audio.startswith(b"RIFF") else "raw",
            path, ttfa, total, dur,
            extra={"sha16": hash16(audio)},
        )
        results.append(r)
        print(f"      ✓ {len(audio):>8,} B  ttfa={ttfa}ms  total={total}ms  "
              f"dur={dur:.2f}s  sha={r.extra['sha16']}")
        if args.listen and audio.startswith(b"RIFF"):
            try:
                import subprocess
                subprocess.run(["afplay", path], timeout=20)
            except Exception:
                pass
        return r

    aura2_set = AURA2_CANDIDATES[:3] if args.quick else AURA2_CANDIDATES
    aura1_set = [] if args.quick else AURA1_CANDIDATES

    print(f"\n[A] Aura-2 candidates ({len(aura2_set)} voices)")
    for v in aura2_set:
        run(f"A_{v}", v)

    print(f"\n[B] Aura-1 candidates ({len(aura1_set)} voices)")
    for v in aura1_set:
        run(f"B_{v}", v)

    print(f"\n[C] SSML/break expressiveness (zeus, longest text)")
    run("C_ssml_break", "aura-2-zeus-en",
        "Hello there. <break time=\"600ms\"/> I am running a test. "
        "<break time=\"400ms\"/> Just kidding.")

    print(f"\n[D] Inline-tag survival — does Deepgram strip or speak [pause]/[sigh]?")
    run("D_inline_tags", "aura-2-zeus-en", PROBE_TEXT_TAGS)

    print(f"\n[E] Short-utterance TTFA (the cache-bypass speed-test)")
    run("E_short_zeus",  "aura-2-zeus-en", PROBE_TEXT_SHORT)
    run("E_short_orion", "aura-2-orion-en", PROBE_TEXT_SHORT)

    # -------- Report -----------------------------------------------------
    report_path = os.path.join(out_dir, "REPORT.md")
    print(f"\n\nWriting report → {report_path}")
    write_report(results, report_path, base_url)
    print("\nProbe done. Listen to the clips and pick a TARS-fit voice (or none).")
    return 0


def write_report(results: List[ProbeResult], path: str, base: str) -> None:
    L: List[str] = []
    L.append(f"# Deepgram TTS Probe — {time.strftime('%Y-%m-%d %H:%M')}\n")
    L.append(f"Base: `{base}`\n")

    L.append("## Latency table (sorted by TTFA)\n")
    L.append("| Probe | Model | TTFA(ms) | Total(ms) | Bytes | Duration | Notes |")
    L.append("|---|---|---:|---:|---:|---:|---|")
    sortable = [r for r in results if r.ok]
    sortable.sort(key=lambda r: r.ttfa_ms or 1e9)
    for r in sortable:
        notes = ""
        if r.name.startswith("C_"): notes = "SSML break test"
        if r.name.startswith("D_"): notes = "[pause]/[sigh] survival test"
        if r.name.startswith("E_"): notes = "short utterance"
        model = r.name.split("_", 1)[1] if "_" in r.name else "?"
        L.append(
            f"| `{r.name}` | `{model}` | {r.ttfa_ms} | {r.total_ms} | "
            f"{r.bytes_received:,} | {r.duration_s:.2f}s | {notes} |"
        )
    L.append("")

    fails = [r for r in results if not r.ok]
    if fails:
        L.append("## Failures\n")
        L.append("| Probe | Error |")
        L.append("|---|---|")
        for r in fails:
            L.append(f"| `{r.name}` | {r.error} |")
        L.append("")

    L.append("## Headline numbers\n")
    successes = [r for r in results if r.ok]
    if successes:
        ttfas = [r.ttfa_ms for r in successes if r.ttfa_ms is not None]
        if ttfas:
            L.append(f"- Best TTFA: **{min(ttfas)} ms**")
            L.append(f"- Median TTFA: **{sorted(ttfas)[len(ttfas)//2]} ms**")
            L.append(f"- Worst TTFA: **{max(ttfas)} ms**")
    L.append("")

    L.append("## Full probe log (JSON)\n```json")
    L.append(json.dumps([{
        "name": r.name, "ok": r.ok, "ttfa_ms": r.ttfa_ms,
        "total_ms": r.total_ms, "bytes": r.bytes_received,
        "duration_s": r.duration_s, "error": r.error, "extra": r.extra,
    } for r in results], indent=2))
    L.append("```")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    sys.exit(main())
