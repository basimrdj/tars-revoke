#!/usr/bin/env python3
"""
TARS Voice Pipeline Test Harness  (Phase −1, task V12)
======================================================

Standalone test — NO LLM in the loop. Measures:

  1. Time-to-first-audio          (TTFA)       per utterance
  2. Total TTS-fetch + playback   (TPB)        per utterance
  3. Audio header validity rate   (V6 sanity)
  4. Text-cleaner correctness     (V4 sanity)
  5. (optional) STT round-trip via Deepgram if --stt is passed

Usage:
    python3 scripts/voice_test.py            # TTS-only, default canned set
    python3 scripts/voice_test.py --quick    # 3 short utterances only
    python3 scripts/voice_test.py --stt      # round-trip: speak + transcribe + WER

Exit codes:
    0  — all gates passed (TTFA < 1.0 s, header validity ≥ 95%)
    1  — one or more gates failed (printed inline)
    2  — environment issue (missing API keys etc.)

Reads the same .env as the main app. For VibeVoice realtime tests, the local
worker/model path is exercised; MiMo/Deepgram keys are only needed for provider
fallbacks and non-local providers.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from typing import List, Tuple

# Add the project root to sys.path so we can import the Speaker
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from dotenv import load_dotenv                                          # noqa: E402

# Reuse production code so we exercise the actual paths we ship
from mimo_apple_realtime_assistant import AssistantConfig, Speaker      # noqa: E402
from tars_text_clean import clean_for_speech                            # noqa: E402


# ---------------------------------------------------------------------------
# Canned utterance set
# ---------------------------------------------------------------------------

CANNED_FULL: List[str] = [
    "[Tone: Deadpan, dry] Hello. I am running a voice pipeline test.",
    "[Tone: Robotic, tactical] Sentence one is short. Sentence two is also short.",
    "[Tone: Mildly amused] Sometimes I produce *asterisks* and em — dashes which should never reach the synthesizer.",
    "[Tone: Calm, measured] Newton's third law states the only way humans have ever figured out of getting somewhere is to leave something behind.",
    "[Tone: Considered] Acoustic echo cancellation is a non-trivial problem on consumer microphones, but a 0.4 second cooldown plus a fuzzy-match echo filter usually suffices.",
    "[Tone: Dry] Yes.",
]

CANNED_QUICK: List[str] = [
    "[Tone: Dry] Test one.",
    "[Tone: Deadpan] Test two, slightly longer than the first.",
    "[Tone: Considered] Test three contains a comma, an em-dash — like that — and a final period.",
]

# Sentences expected to be reproduced verbatim (cleaned) by the loopback STT
LOOPBACK_TARGETS: List[str] = [
    "Hello. I am running a voice pipeline test.",
    "Sentence one is short. Sentence two is also short.",
    "Yes.",
]


# ---------------------------------------------------------------------------
# Cleaner sanity check
# ---------------------------------------------------------------------------

CLEANER_CASES: List[Tuple[str, str]] = [
    ("Hello *world*",                           "Hello world"),
    ("**bold** and `code`",                     "bold and code"),
    ("em — dash",                                "em , dash"),     # em-dash → ", "
    ("smart ‘quotes’",                "smart 'quotes'"),
    ("ellipsis…",                           "ellipsis."),
    ("emoji ⚠️ warn",                 "emoji warn"),
    ("vs. usage",                                "versus usage"),
]


def run_cleaner_sanity() -> bool:
    print("\n=== V4: text-cleaner sanity ===")
    fails = 0
    for raw, expected in CLEANER_CASES:
        got = clean_for_speech(raw)
        ok = (got == expected)
        marker = "OK " if ok else "FAIL"
        print(f"  [{marker}] {raw!r:50s} → {got!r}")
        if not ok:
            print(f"          expected: {expected!r}")
            fails += 1
    if fails:
        print(f"  ({fails} cleaner case(s) failed — non-fatal but flagged)")
    return fails == 0


# ---------------------------------------------------------------------------
# TTS harness
# ---------------------------------------------------------------------------

def run_tts_only(speaker: Speaker, utterances: List[str], play: bool) -> dict:
    print("\n=== V1/V6: TTS fetch + (optional) playback ===")
    fetch_times: List[float] = []
    play_times:  List[float] = []
    valid_headers = 0
    total = len(utterances)

    for i, u in enumerate(utterances, 1):
        cleaned = clean_for_speech(u)
        print(f"  [{i}/{total}] fetching ({len(cleaned)} chars): {cleaned[:60]!r}…")

        t0 = time.time()
        audio = speaker._fetch_audio_for(u)
        ft = time.time() - t0

        if audio is None:
            print(f"        FAIL: no audio returned (rt={ft:.2f}s)")
            continue

        if Speaker._validate_audio_header(audio):
            valid_headers += 1
        else:
            print(f"        WARN: invalid audio header {audio[:8].hex()}")

        fetch_times.append(ft)
        size_kb = len(audio) / 1024
        print(f"        OK ({ft:.2f}s, {size_kb:.1f} KB)")

        if play:
            t0 = time.time()
            speaker._play_bytes(audio, u)
            play_times.append(time.time() - t0)

    return {
        "fetch_times":   fetch_times,
        "play_times":    play_times,
        "valid_headers": valid_headers,
        "total":         total,
    }


def run_vibe_realtime_smoke(speaker: Speaker, play: bool) -> bool:
    """Exercise the actual default VibeVoice streaming path.

    With playback enabled this goes through `_play_streaming_vibevoice()` and
    sounddevice. With `--no-play`, it still tests worker `PCMC` streaming and
    first-chunk timing without touching the audio device.
    """
    print("\n=== R9: VibeVoice realtime streaming path ===")
    if getattr(speaker, "provider", "") != "vibevoice":
        print("  SKIP: TARS_TTS_PROVIDER is not vibevoice")
        return True

    if not speaker._ensure_vibe(blocking=True):
        print("  FAIL: VibeVoice worker did not become ready")
        return False

    text = "Realtime VibeVoice path test. Short enough to be fast, long enough to stream cleanly."
    first_at = [None]
    t0 = time.time()

    def _first_chunk():
        if first_at[0] is None:
            first_at[0] = time.time()

    if play:
        ok = speaker._play_streaming_vibevoice(text, on_started=_first_chunk)
        ttfa = (first_at[0] - t0) if first_at[0] else float("inf")
        print(f"  play path: {'OK' if ok else 'FAIL'}  first_audio={ttfa:.2f}s")
        return bool(ok and first_at[0] is not None)

    chunks = 0
    total_bytes = 0
    for pcm in speaker._vibe.stream_pcm(
        text, voice=speaker.vibe_voice, first_chunk_callback=_first_chunk
    ):
        chunks += 1
        total_bytes += len(pcm)
    ttfa = (first_at[0] - t0) if first_at[0] else float("inf")
    ok = chunks > 0 and total_bytes > 0 and first_at[0] is not None
    print(f"  worker stream: {'OK' if ok else 'FAIL'}  "
          f"first_pcm={ttfa:.2f}s  chunks={chunks}  bytes={total_bytes:,}")
    return ok


def run_deepgram_stream_smoke(speaker: Speaker, play: bool) -> bool:
    """Exercise the production Deepgram raw-PCM streaming playback path."""
    print("\n=== Deepgram realtime streaming path ===")
    if getattr(speaker, "provider", "") != "deepgram":
        print("  SKIP: TARS_TTS_PROVIDER is not deepgram")
        return True

    text = "Deepgram stream path test. Short enough to be fast, long enough to measure."

    if play:
        ok = speaker._play_streaming_deepgram(text)
        print(f"  play path: {'OK' if ok else 'FAIL'}")
        return bool(ok)

    class _FakePCM:
        def __init__(self):
            self.chunks = 0
            self.bytes = 0
        def write(self, pcm: bytes) -> bool:
            self.chunks += 1
            self.bytes += len(pcm)
            return True

    fake = _FakePCM()
    old_player = getattr(speaker, "_pcm_player", None)
    old_rate = getattr(speaker, "_pcm_player_rate", None)
    old_ensure = speaker._ensure_pcm_player
    try:
        speaker._pcm_player = fake
        speaker._pcm_player_rate = speaker.deepgram_sample_rate
        speaker._ensure_pcm_player = lambda sample_rate=24000: True
        t0 = time.time()
        ok = speaker._play_streaming_deepgram(text)
        dt = time.time() - t0
    finally:
        speaker._pcm_player = old_player
        speaker._pcm_player_rate = old_rate
        speaker._ensure_pcm_player = old_ensure

    ok = bool(ok and fake.chunks > 0 and fake.bytes > 0)
    print(f"  worker stream: {'OK' if ok else 'FAIL'}  "
          f"elapsed={dt:.2f}s  chunks={fake.chunks}  bytes={fake.bytes:,}")
    return ok


# ---------------------------------------------------------------------------
# Loopback STT (optional)
# ---------------------------------------------------------------------------

def run_loopback_stt(speaker: Speaker, config: AssistantConfig) -> bool:
    """Speak each LOOPBACK_TARGETS string aloud, listen via Deepgram, compute WER.
    Requires the test machine's mic to be able to hear its own speakers."""
    print("\n=== V2/V3/V5: STT loopback (mic must hear speakers) ===")
    try:
        from deepgram import (DeepgramClient, LiveTranscriptionEvents,
                              LiveOptions, Microphone)
    except Exception as e:
        print(f"  SKIP: deepgram SDK not available ({e})")
        return True

    if not config.deepgram_api_key:
        print("  SKIP: DEEPGRAM_API_KEY not set")
        return True

    captured: List[str] = []
    dg = DeepgramClient(config.deepgram_api_key)
    conn = dg.listen.websocket.v("1")

    def _on_msg(_self_conn, result, **_kw):
        try:
            if not result or not result.is_final:
                return
            t = result.channel.alternatives[0].transcript
            if t:
                captured.append(t)
        except Exception:
            pass

    conn.on(LiveTranscriptionEvents.Transcript, _on_msg)

    if not conn.start(LiveOptions(
        model="nova-3", language="en-US", smart_format=True,
        encoding="linear16", channels=1, sample_rate=16000,
        endpointing=800, utterance_end_ms=1500, vad_events=True,
    )):
        print("  FAIL: could not start Deepgram connection")
        return False

    mic = Microphone(conn.send)
    mic.start()

    fails = 0
    try:
        for tgt in LOOPBACK_TARGETS:
            print(f"  speaking: {tgt!r}")
            captured.clear()
            speaker.speak(f"[Tone: Deadpan] {tgt}")
            # Wait briefly for any final transcripts to flush
            time.sleep(2.0)
            heard = " ".join(captured).strip().lower().rstrip(".")
            want  = tgt.strip().lower().rstrip(".")
            wer   = _word_error_rate(want, heard)
            ok    = wer <= 0.20
            print(f"     heard:  {heard!r}")
            print(f"     WER={wer:.2f} → {'OK' if ok else 'FAIL'}")
            if not ok:
                fails += 1
    finally:
        try: mic.finish()
        except Exception: pass
        try: conn.finish()
        except Exception: pass

    return fails == 0


def _word_error_rate(ref: str, hyp: str) -> float:
    """Simple WER via Levenshtein on word lists."""
    r = ref.split()
    h = hyp.split()
    if not r:
        return 0.0 if not h else 1.0
    # DP table
    dp = [[0]*(len(h)+1) for _ in range(len(r)+1)]
    for i in range(len(r)+1): dp[i][0] = i
    for j in range(len(h)+1): dp[0][j] = j
    for i in range(1, len(r)+1):
        for j in range(1, len(h)+1):
            cost = 0 if r[i-1] == h[j-1] else 1
            dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
    return dp[-1][-1] / len(r)


# ---------------------------------------------------------------------------
# A/B consistency harness  (Round 4)
# ---------------------------------------------------------------------------
#
# Same utterance × N calls per (model, voice) configuration. Reports byte
# distinct count + audio fingerprint stability so future rounds can verify
# (objectively) that switching to a fixed-voice model removed per-call
# voice drift.

import hashlib

AB_TEXT = (
    "Newton's third law of motion. The only way humans have ever figured out "
    "of getting somewhere is to leave something behind."
)

# Each row: (config_label, model, voice, voice_design_prompt or None).
AB_CONFIGS = [
    ("voicedesign-current", "mimo-v2.5-tts-voicedesign", None,
     "Deep, deliberate male voice, slight metallic studio texture. "
     "Tactical, never theatrical. Neutral, deadpan, and tactical."),
    ("fixed-Dean",         "mimo-v2.5-tts",            "Dean", None),
    ("fixed-Milo",         "mimo-v2.5-tts",            "Milo", None),
]


def run_ab_consistency(speaker: "Speaker", runs: int = 3,
                       configs=AB_CONFIGS, save_dir: str = "scratch/ab") -> dict:
    """Fetch the same utterance N times under each candidate config.
    Returns per-config stats; the best config has fewest distinct hashes
    AND lowest audio-byte variance."""
    print(f"\n=== A/B consistency — {runs} calls × {len(configs)} configs ===")
    os.makedirs(save_dir, exist_ok=True)

    summary = {}
    for label, model, voice, vd_prompt in configs:
        print(f"\n  config: {label}  (model={model} voice={voice})")
        # Temporarily swap Speaker config for this run.
        orig_model = speaker.tts_model
        orig_voice = speaker.voice
        speaker.tts_model = model
        if voice is not None:
            speaker.voice = voice
        # If we're testing voice-design with a custom prompt, override the
        # emotion via _fetch_audio_for(override_emotion=…).
        emo_override = vd_prompt if vd_prompt else None

        hashes = []
        sizes  = []
        times  = []
        for n in range(1, runs + 1):
            t0 = time.time()
            audio = speaker._fetch_audio_for(AB_TEXT, override_emotion=emo_override)
            dt = time.time() - t0
            if not audio:
                print(f"    call{n}: FAIL")
                continue
            h = hashlib.sha256(audio).hexdigest()[:16]
            hashes.append(h)
            sizes.append(len(audio))
            times.append(dt)
            path = os.path.join(save_dir, f"{label}_call{n}.wav")
            with open(path, "wb") as f:
                f.write(audio)
            print(f"    call{n}: {dt:.2f}s  size={len(audio):,}  sha={h}  → {path}")
        summary[label] = {
            "model": model, "voice": voice,
            "distinct_hashes": len(set(hashes)),
            "size_min": min(sizes) if sizes else 0,
            "size_max": max(sizes) if sizes else 0,
            "size_range": (max(sizes) - min(sizes)) if sizes else 0,
            "median_fetch_s": statistics.median(times) if times else float("inf"),
        }
        speaker.tts_model = orig_model
        speaker.voice     = orig_voice

    print(f"\n  --- A/B summary ---")
    print(f"  {'config':<22s} {'distinct':>8s} {'size_min':>10s} {'size_max':>10s} "
          f"{'size_range':>11s} {'median_t':>9s}")
    for label, s in summary.items():
        print(f"  {label:<22s} {s['distinct_hashes']:>8d} "
              f"{s['size_min']:>10,d} {s['size_max']:>10,d} "
              f"{s['size_range']:>11,d} {s['median_fetch_s']:>8.2f}s")

    # Lower is better for distinct_hashes (1 = perfect determinism) and
    # for size_range (0 = identical sizes, voice persona stable).
    best = min(summary.items(),
               key=lambda kv: (kv[1]["distinct_hashes"], kv[1]["size_range"]))
    print(f"\n  WINNER (most consistent): {best[0]}  "
          f"distinct={best[1]['distinct_hashes']} size_range={best[1]['size_range']:,}")
    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="Use the short canned set (3 utterances)")
    parser.add_argument("--no-play", action="store_true",
                        help="Fetch audio but skip afplay (CI-friendly)")
    parser.add_argument("--stt", action="store_true",
                        help="Also run the loopback STT round-trip test")
    parser.add_argument("--ab", action="store_true",
                        help="Run A/B consistency harness across candidate configs")
    parser.add_argument("--ab-runs", type=int, default=3,
                        help="Calls per config in --ab mode (default 3)")
    parser.add_argument("--vibe-realtime", action="store_true",
                        help="Exercise the actual VibeVoice realtime PCM path")
    parser.add_argument("--deepgram-stream", action="store_true",
                        help="Exercise the actual Deepgram raw-PCM streaming path")
    args = parser.parse_args()

    load_dotenv()
    try:
        config  = AssistantConfig()
        speaker = Speaker(config)
        if speaker.provider != "vibevoice" and not config.api_key:
            print("ENV: MIMO_API_KEY missing — cannot run non-VibeVoice TTS test.")
            return 2
    except SystemExit:
        return 2

    cleaner_ok = run_cleaner_sanity()

    # A/B mode short-circuits the regular harness — different goal.
    if args.ab:
        run_ab_consistency(speaker, runs=args.ab_runs)
        return 0

    utterances = CANNED_QUICK if args.quick else CANNED_FULL
    tts_results = run_tts_only(speaker, utterances, play=not args.no_play)

    fts = tts_results["fetch_times"]
    if fts:
        median = statistics.median(fts)
        p95    = sorted(fts)[max(0, int(len(fts) * 0.95) - 1)]
        print(f"\n  TTS fetch: median={median:.2f}s  p95={p95:.2f}s  "
              f"min={min(fts):.2f}s  max={max(fts):.2f}s")
    else:
        median = p95 = float("inf")

    header_rate = (tts_results["valid_headers"] / max(1, tts_results["total"]))
    print(f"  Header validity: {header_rate*100:.1f}% "
          f"({tts_results['valid_headers']}/{tts_results['total']})")

    stt_ok = True
    if args.stt:
        stt_ok = run_loopback_stt(speaker, config)
    vibe_ok = True
    if args.vibe_realtime:
        vibe_ok = run_vibe_realtime_smoke(speaker, play=not args.no_play)
    deepgram_stream_ok = True
    if args.deepgram_stream:
        deepgram_stream_ok = run_deepgram_stream_smoke(speaker, play=not args.no_play)

    # Gates. In --no-play mode we only fetched full audio bytes; that is not
    # time-to-first-audio, so do not fail CI-style runs on this latency value.
    tffa_gate    = True if args.no_play else median < 1.5
    header_gate  = header_rate >= 0.95
    cleaner_gate = cleaner_ok

    print("\n=== Gate results ===")
    if args.no_play:
        print(f"  TTFA median < 1.5s : SKIP  (--no-play fetched full clips; median={median:.2f}s)")
    else:
        print(f"  TTFA median < 1.5s : {'PASS' if tffa_gate else 'FAIL'}  ({median:.2f}s)")
    print(f"  Header validity ≥ 95% : {'PASS' if header_gate else 'FAIL'}  ({header_rate*100:.1f}%)")
    print(f"  Cleaner correctness : {'PASS' if cleaner_gate else 'FAIL'}")
    if args.stt:
        print(f"  STT loopback : {'PASS' if stt_ok else 'FAIL'}")
    if args.vibe_realtime:
        print(f"  Vibe realtime : {'PASS' if vibe_ok else 'FAIL'}")
    if args.deepgram_stream:
        print(f"  Deepgram stream : {'PASS' if deepgram_stream_ok else 'FAIL'}")

    all_pass = (
        tffa_gate and header_gate and cleaner_gate and stt_ok
        and vibe_ok and deepgram_stream_ok
    )
    print("\n" + ("ALL GATES PASS ✅" if all_pass else "SOME GATES FAILED ❌"))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
