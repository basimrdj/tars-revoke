#!/usr/bin/env python3
"""TARS — MiMo TTS Discovery Probe (Round 4 Voice Triage)

Goal: find a TTS configuration that gives a CONSISTENT voice across calls.
The current `mimo-v2.5-tts-voicedesign` setup re-interprets its voice prompt
on every call, producing per-call voice drift and the occasional "weird"
clip. Round 4's strategy is to discover what variants the live API actually
accepts, save audio samples for human comparison, and pick a winner.

Probes performed (in order, fail-safe):

  A. ``mimo-v2.5-tts-voicedesign`` × same prompt × 3 calls    (drift baseline)
  B. ``mimo-v2.5-tts``  × ``mimo_default`` voice × 3 calls    (fixed-voice candidate)
  C. ``mimo-v2.5-tts``  × candidate voice IDs                 (voice catalog discovery)
  D. ``/v1/audio/speech``  endpoint                           (alternate API surface)
  E. ``mimo-v2.5-tts-voicedesign`` × ``stream: true``         (streaming feasibility)
  F. ``audio.format`` options (mp3 | wav | opus | pcm)        (codec catalog)

For each probe the script writes:

  scratch/probe_audio/<probe_id>.{mp3,wav,bin}    (audio bytes if returned)
  scratch/probe_audio/REPORT.md                   (machine + human notes)

Usage:
    python3 scripts/probe_mimo_tts.py            # full sweep
    python3 scripts/probe_mimo_tts.py --quick    # only A + B + first 3 of C
    python3 scripts/probe_mimo_tts.py --listen   # autoplay each successful clip

After the sweep, listen to the samples and decide which model+voice pair to
make the new default. The findings get folded into
``docs/MIMO_TTS_RESEARCH.md`` and ``Speaker`` is reconfigured accordingly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv


# ─── config ─────────────────────────────────────────────────────────────────

PROBE_TEXT = (
    "Newton's third law. The only way humans have ever figured out of "
    "getting somewhere is to leave something behind."
)

VOICEDESIGN_PROMPT = (
    "A tactical robot. Deep, resonant male voice, extremely clear "
    "enunciation, slight metallic studio texture. Sounds highly "
    "intelligent and deliberate. CURRENT EMOTION: Neutral, deadpan, "
    "and tactical."
)

# Best-effort guesses at voice IDs based on the OpenAI compatibility surface +
# the one known-working id (mimo_default). Probe will report which fail.
CANDIDATE_VOICES = [
    "mimo_default",
    "mimo_male",
    "mimo_female",
    "mimo_neutral",
    "mimo_robot",
    "mimo_robotic",
    "mimo_tactical",
    # Common OpenAI voice ids — sometimes echoed by OpenAI-compatible vendors.
    "alloy",
    "echo",
    "onyx",
    "nova",
    "shimmer",
    "fable",
    "sage",
    "ash",
    "coral",
    "verse",
]


@dataclass
class ProbeResult:
    name: str
    ok: bool
    bytes_received: int = 0
    audio_format: Optional[str] = None
    file_path: Optional[str] = None
    duration_ms: int = 0
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


# ─── helpers ────────────────────────────────────────────────────────────────

def magic_format(b: bytes) -> Optional[str]:
    if not b or len(b) < 4:
        return None
    if b.startswith(b"RIFF"):
        return "wav"
    if b.startswith(b"ID3") or b[:2] in (b"\xff\xfb", b"\xff\xfa", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    if b.startswith(b"OggS"):
        return "ogg/opus"
    if b.startswith(b"\x1a\x45\xdf\xa3"):
        return "matroska/webm"
    return None


def save_audio(out_dir: str, probe_id: str, audio: bytes) -> Tuple[str, str]:
    fmt = magic_format(audio) or "bin"
    ext = "wav" if fmt == "wav" else "mp3" if fmt == "mp3" else "bin"
    path = os.path.join(out_dir, f"{probe_id}.{ext}")
    with open(path, "wb") as f:
        f.write(audio)
    return path, fmt


def hash_audio(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def post_chat_completions(session: requests.Session, base_url: str,
                          payload: Dict, timeout_s: float = 90.0,
                          stream: bool = False) -> requests.Response:
    return session.post(
        base_url.rstrip("/") + "/chat/completions",
        json=payload,
        timeout=timeout_s,
        stream=stream,
    )


def post_audio_speech(session: requests.Session, base_url: str,
                      payload: Dict, timeout_s: float = 90.0) -> requests.Response:
    return session.post(
        base_url.rstrip("/") + "/audio/speech",
        json=payload,
        timeout=timeout_s,
    )


# ─── individual probes ──────────────────────────────────────────────────────

def probe_voicedesign(session, base_url, fmt: str = "wav",
                      prompt: str = VOICEDESIGN_PROMPT,
                      text: str = PROBE_TEXT) -> Tuple[Optional[bytes], Optional[str]]:
    payload = {
        "model": "mimo-v2.5-tts-voicedesign",
        "messages": [
            {"role": "user",      "content": prompt},
            {"role": "assistant", "content": text},
        ],
        "modalities": ["text", "audio"],
        "audio": {"format": fmt},
    }
    resp = post_chat_completions(session, base_url, payload, 60.0)
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
    data = resp.json()
    msg = data.get("choices", [{}])[0].get("message", {})
    audio = msg.get("audio") or {}
    b64 = audio.get("data")
    if not b64:
        return None, "no audio.data field"
    try:
        return base64.b64decode(b64), None
    except Exception as e:
        return None, f"base64 decode: {e}"


def probe_fixed_voice(session, base_url, voice: str, fmt: str = "wav",
                      text: str = PROBE_TEXT) -> Tuple[Optional[bytes], Optional[str]]:
    payload = {
        "model": "mimo-v2.5-tts",
        "messages": [
            {"role": "assistant", "content": text},
        ],
        "modalities": ["text", "audio"],
        "audio": {"format": fmt, "voice": voice},
    }
    resp = post_chat_completions(session, base_url, payload, 60.0)
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
    data = resp.json()
    msg = data.get("choices", [{}])[0].get("message", {})
    audio = msg.get("audio") or {}
    b64 = audio.get("data")
    if not b64:
        return None, "no audio.data field"
    try:
        return base64.b64decode(b64), None
    except Exception as e:
        return None, f"base64 decode: {e}"


def probe_audio_speech(session, base_url, voice: str = "mimo_default",
                       fmt: str = "wav",
                       text: str = PROBE_TEXT) -> Tuple[Optional[bytes], Optional[str]]:
    """Try the OpenAI-style /v1/audio/speech endpoint. Many OpenAI-compatible
    vendors expose it; some don't."""
    payload = {
        "model": "mimo-v2.5-tts",
        "input": text,
        "voice": voice,
        "response_format": fmt,
    }
    try:
        resp = post_audio_speech(session, base_url, payload, 60.0)
    except Exception as e:
        return None, f"network: {e}"
    if resp.status_code == 200:
        ct = resp.headers.get("Content-Type", "")
        if "json" in ct:
            return None, f"unexpected JSON response: {resp.text[:200]}"
        return resp.content, None
    return None, f"HTTP {resp.status_code}: {resp.text[:200]}"


def probe_streaming_voicedesign(session, base_url,
                                fmt: str = "wav") -> Tuple[bool, str]:
    """Probe whether /chat/completions accepts stream=true with the audio
    modality. Returns (server_accepted_stream, summary)."""
    payload = {
        "model": "mimo-v2.5-tts-voicedesign",
        "messages": [
            {"role": "user",      "content": VOICEDESIGN_PROMPT},
            {"role": "assistant", "content": "Streaming test."},
        ],
        "modalities": ["text", "audio"],
        "audio": {"format": fmt},
        "stream": True,
    }
    try:
        resp = post_chat_completions(session, base_url, payload, 30.0, stream=True)
    except Exception as e:
        return False, f"network: {e}"
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    ct = resp.headers.get("Content-Type", "")
    chunks_seen = 0
    sample_lines: List[str] = []
    bytes_seen = 0
    for raw_line in resp.iter_lines(decode_unicode=False):
        if not raw_line:
            continue
        chunks_seen += 1
        bytes_seen += len(raw_line)
        if len(sample_lines) < 3:
            try:
                sample_lines.append(raw_line[:240].decode("utf-8", "replace"))
            except Exception:
                sample_lines.append(repr(raw_line[:80]))
        if chunks_seen >= 8:
            break
    return (chunks_seen > 0,
            f"content_type={ct!r} chunks_seen={chunks_seen} "
            f"bytes={bytes_seen} sample={sample_lines!r}")


# ─── orchestrator ───────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--quick",  action="store_true",
                   help="Run only the most informative subset of probes.")
    p.add_argument("--listen", action="store_true",
                   help="afplay each successful clip immediately after fetch.")
    p.add_argument("--out", default="scratch/probe_audio",
                   help="Directory for audio + report (default: scratch/probe_audio)")
    args = p.parse_args()

    load_dotenv()
    api_key  = os.getenv("MIMO_API_KEY")
    base_url = os.getenv("MIMO_BASE_URL", "https://token-plan-sgp.xiaomimimo.com/v1")
    if not api_key:
        print("ERROR: MIMO_API_KEY not set. Aborting.", file=sys.stderr)
        return 2
    print(f"Probe target: {base_url}")
    print(f"Output dir  : {args.out}")
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    })

    results: List[ProbeResult] = []

    def run(probe_id: str, fn, *fn_args, **fn_kwargs):
        t0 = time.time()
        print(f"\n  ─ {probe_id}…", flush=True)
        try:
            audio, err = fn(*fn_args, **fn_kwargs)
        except Exception as exc:
            r = ProbeResult(probe_id, False, error=f"exception: {exc}",
                            duration_ms=int((time.time()-t0)*1000))
            results.append(r); print(f"      ✗ {r.error}"); return r
        dt = int((time.time()-t0)*1000)
        if audio is None:
            r = ProbeResult(probe_id, False, error=err, duration_ms=dt)
            results.append(r); print(f"      ✗ {err}"); return r
        path, fmt = save_audio(out_dir, probe_id, audio)
        r = ProbeResult(probe_id, True, len(audio), fmt, path, dt,
                        extra={"sha256_16": hash_audio(audio)})
        results.append(r)
        print(f"      ✓ {len(audio):,} bytes  fmt={fmt}  in {dt} ms  sha={r.extra['sha256_16']}")
        if args.listen and shutil.which("afplay") and fmt in ("mp3", "wav"):
            try: subprocess.run(["afplay", path], timeout=20)
            except Exception: pass
        return r

    # ── Probe A: VoiceDesign drift baseline ──────────────────────────────
    print("\n[A] VoiceDesign — same prompt × 3 calls (drift baseline)")
    for i in range(1, 4):
        run(f"A_voicedesign_call{i}", probe_voicedesign, session, base_url, "wav")

    # ── Probe B: fixed-voice consistency candidate ───────────────────────
    print("\n[B] mimo-v2.5-tts × mimo_default × 3 calls (fixed-voice candidate)")
    for i in range(1, 4):
        run(f"B_fixedvoice_default_call{i}", probe_fixed_voice,
            session, base_url, "mimo_default", "wav")

    # ── Probe C: voice catalog discovery ─────────────────────────────────
    voices = CANDIDATE_VOICES if not args.quick else CANDIDATE_VOICES[:3]
    print(f"\n[C] mimo-v2.5-tts × candidate voices ({len(voices)} ids)")
    for v in voices:
        run(f"C_voice_{v}", probe_fixed_voice, session, base_url, v, "wav")

    # ── Probe D: /v1/audio/speech alternate endpoint ─────────────────────
    print("\n[D] /v1/audio/speech endpoint")
    run("D_audio_speech_default", probe_audio_speech,
        session, base_url, "mimo_default", "wav")

    # ── Probe E: streaming feasibility ───────────────────────────────────
    print("\n[E] stream: true on voicedesign")
    try:
        ok, summary = probe_streaming_voicedesign(session, base_url, "wav")
        results.append(ProbeResult(
            "E_streaming", bool(ok),
            error=None if ok else "no chunks streamed",
            extra={"summary": summary},
        ))
        print(f"      {'✓' if ok else '✗'}  {summary}")
    except Exception as exc:
        results.append(ProbeResult("E_streaming", False, error=f"exception: {exc}"))
        print(f"      ✗ {exc}")

    # ── Probe F: audio format codec catalog ──────────────────────────────
    if not args.quick:
        print("\n[F] audio.format catalog (mp3 / wav / opus / pcm / flac)")
        for fmt in ("mp3", "wav", "opus", "pcm", "flac"):
            run(f"F_format_{fmt}", probe_voicedesign, session, base_url, fmt)

    # ── Report ───────────────────────────────────────────────────────────
    report_path = os.path.join(out_dir, "REPORT.md")
    print(f"\n\nWriting report → {report_path}")
    write_report(results, report_path, base_url)
    print("\nDone. Listen to the .wav/.mp3 files in the output dir and pick a winner.")
    return 0


def write_report(results: List[ProbeResult], path: str, base_url: str) -> None:
    lines: List[str] = []
    lines.append(f"# MiMo TTS Probe — {time.strftime('%Y-%m-%d %H:%M')}\n")
    lines.append(f"Base URL: `{base_url}`\n")

    # Drift analysis: are the 3 voicedesign calls byte-identical?
    a_hashes = sorted({r.extra.get("sha256_16")
                       for r in results
                       if r.name.startswith("A_") and r.ok})
    b_hashes = sorted({r.extra.get("sha256_16")
                       for r in results
                       if r.name.startswith("B_") and r.ok})
    lines.append("## Drift summary\n")
    lines.append(f"- VoiceDesign distinct hashes (3 calls):    **{len(a_hashes)}** "
                 f"→ {'STABLE' if len(a_hashes) == 1 else 'DRIFTS'}")
    lines.append(f"- mimo-v2.5-tts/default distinct hashes (3): **{len(b_hashes)}** "
                 f"→ {'STABLE' if len(b_hashes) == 1 else 'DRIFTS'}\n")

    lines.append("## Voice catalog (probe C)\n")
    lines.append("| Voice ID | OK | Bytes | Format | Error |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        if not r.name.startswith("C_"):
            continue
        v = r.name.replace("C_voice_", "")
        lines.append(
            f"| `{v}` | {'✓' if r.ok else '✗'} | {r.bytes_received or '—'} | "
            f"{r.audio_format or '—'} | {r.error or ''} |"
        )
    lines.append("")

    lines.append("## Endpoints + streaming + formats\n")
    lines.append("| Probe | OK | Bytes | Format | Error |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        if r.name.startswith(("A_", "B_", "C_")):
            continue
        lines.append(
            f"| `{r.name}` | {'✓' if r.ok else '✗'} | {r.bytes_received or '—'} | "
            f"{r.audio_format or '—'} | {r.error or ''} |"
        )
    lines.append("")

    lines.append("## Full probe log\n")
    lines.append("```json")
    payload = [
        {
            "name": r.name, "ok": r.ok, "bytes": r.bytes_received,
            "fmt": r.audio_format, "ms": r.duration_ms,
            "error": r.error, "extra": r.extra,
        }
        for r in results
    ]
    lines.append(json.dumps(payload, indent=2))
    lines.append("```")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
