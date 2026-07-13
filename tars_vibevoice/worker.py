#!/usr/bin/env python3
"""VibeVoice subprocess worker.

Runs inside `tars_vibevoice/venv` (which has torch 2.5.x + vibevoice pinned
to a compatible combination). The parent TARS process — running its own
Python with torch 2.9 + mlx-lm etc. — talks to this worker over stdin/
stdout via a tiny binary protocol so neither side has to share dependency
versions.

Protocol
========

Commands are read from stdin, one JSON object per line:

    {"cmd": "warm"}                              # load model + cache default voice
    {"cmd": "speak", "text": "...",              # synthesise; streams PCM frames
     "voice": "en-Carter_man",                   #   (defaults below)
     "cfg_scale": 1.5, "steps": 5}
    {"cmd": "stop"}                              # abort current speak
    {"cmd": "shutdown"}                          # graceful exit

Audio + status frames are written to stdout as binary records:

    +-----------+-----------+--------------------+
    | 4-byte BE | 4-byte    | payload (bytes)    |
    | length    | tag (ASCII)|                   |
    +-----------+-----------+--------------------+

Tags:
    "READ"   — emitted once at startup once model is loaded
    "RDYV"   — emitted after voice is cached/loaded
    "PCMS"   — start of utterance (payload = JSON: rate, channels, voice)
    "PCMC"   — PCM int16 chunk (payload = raw little-endian bytes)
    "PCME"   — end of utterance (payload empty)
    "ERR "   — error event (payload = JSON: code, message)
    "BYE "   — final frame before exit

The parent process uses sounddevice (or any int16 sink) to play `PCMC`
chunks as they arrive. A small protocol mismatch should never crash the
parent: parsing errors fall back to logging the bytes and continuing.

`stderr` is reserved for diagnostic logging (one line per event, plain
text). The parent forwards stderr lines to its own logger.
"""

from __future__ import annotations

import copy
import json
import os
from queue import Empty, Queue
import struct
import sys
import threading
import time
import traceback
import warnings
from pathlib import Path
from typing import Optional


SAMPLE_RATE = 24_000
DEFAULT_VOICE = "en-Carter_man"
DEFAULT_CFG = 1.5
DEFAULT_STEPS = 5
PCM_GAIN = float(os.environ.get("VIBEVOICE_PCM_GAIN", "0.98"))
MIN_PCM_CHUNK_MS = float(os.environ.get("VIBEVOICE_MIN_PCM_CHUNK_MS", "40"))
MAX_PCM_COALESCE_MS = float(os.environ.get("VIBEVOICE_MAX_PCM_COALESCE_MS", "80"))

VOICES_DIR = Path(__file__).resolve().parent / "voices"

# These must be set before torch/transformers import in the subprocess.
os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
warnings.filterwarnings("ignore", message=r"`torch_dtype` is deprecated.*")
warnings.filterwarnings("ignore", message=r"The tokenizer class you load.*")


def _log(msg: str) -> None:
    sys.stderr.write(f"[vibe-worker] {msg}\n")
    sys.stderr.flush()


def _frame(tag: str, payload: bytes = b"") -> None:
    """Write a single binary frame to stdout. Caller-provided payload."""
    assert len(tag) == 4, f"tag must be 4 chars, got {tag!r}"
    header = struct.pack(">I", len(payload)) + tag.encode("ascii")
    with _frame_lock:
        sys.stdout.buffer.write(header)
        if payload:
            sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()


def _err(code: str, message: str) -> None:
    _frame("ERR ", json.dumps({"code": code, "message": message}).encode("utf-8"))


# ─── Model loading ──────────────────────────────────────────────────────────

_state = {
    "torch":     None,
    "model":     None,
    "processor": None,
    "voice_cache": {},   # name → prefilled outputs
    "device":    None,
    "stop_event": threading.Event(),
    "generation_lock": threading.Lock(),
    "generation_id": 0,
    "generation_thread": None,
    "active_streamer": None,
}
_frame_lock = threading.Lock()


def _truthy_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _signal_active_generation(reason: str) -> None:
    """Best-effort interrupt for the active streamer/generation thread."""
    with _state["generation_lock"]:
        stop_event = _state.get("stop_event")
        streamer = _state.get("active_streamer")
        generation_id = _state.get("generation_id", 0)

    if stop_event:
        stop_event.set()
    if streamer is not None:
        try:
            streamer.end()
        except Exception:
            pass
    _log(f"generation stop signalled id={generation_id} reason={reason}")


def _begin_generation() -> tuple[int, threading.Event] | None:
    """Reserve the model for a new utterance, stopping any stale generation."""
    with _state["generation_lock"]:
        previous_thread = _state.get("generation_thread")
        previous_event = _state.get("stop_event")
        previous_streamer = _state.get("active_streamer")

    if previous_event:
        previous_event.set()
    if previous_streamer is not None:
        try:
            previous_streamer.end()
        except Exception:
            pass
    if previous_thread is not None and previous_thread.is_alive():
        previous_thread.join(timeout=2.0)
        if previous_thread.is_alive():
            _log("previous generation thread still alive; refusing overlap")
            return None

    with _state["generation_lock"]:
        _state["generation_id"] += 1
        generation_id = _state["generation_id"]
        stop_event = threading.Event()
        _state["stop_event"] = stop_event
        _state["active_streamer"] = None
        _state["generation_thread"] = None
    return generation_id, stop_event


def _register_generation(
    generation_id: int,
    stop_event: threading.Event,
    audio_streamer,
    thread: threading.Thread,
) -> None:
    with _state["generation_lock"]:
        if _state.get("generation_id") == generation_id:
            _state["stop_event"] = stop_event
            _state["active_streamer"] = audio_streamer
            _state["generation_thread"] = thread


def _clear_generation(generation_id: int) -> None:
    with _state["generation_lock"]:
        if _state.get("generation_id") == generation_id:
            _state["active_streamer"] = None
            _state["generation_thread"] = None


def _pick_device(torch) -> tuple[str, object, str]:
    """Match the official VibeVoice device choices, with an env override."""
    requested = os.environ.get("VIBEVOICE_DEVICE", "").strip().lower()
    if requested == "mpx":
        requested = "mps"

    cuda_ok = torch.cuda.is_available()
    mps_ok = bool(getattr(torch.backends, "mps", None)
                  and torch.backends.mps.is_available())

    if requested:
        if requested == "cuda" and cuda_ok:
            return "cuda", torch.bfloat16, "flash_attention_2"
        if requested == "mps" and mps_ok:
            return "mps", torch.float32, "sdpa"
        if requested == "cpu":
            return "cpu", torch.float32, "sdpa"
        _log(f"requested device={requested!r} unavailable; falling back to auto")

    if cuda_ok:
        return "cuda", torch.bfloat16, "flash_attention_2"
    if mps_ok:
        return "mps", torch.float32, "sdpa"
    return "cpu", torch.float32, "sdpa"


def _voice_path(name: str) -> Optional[Path]:
    p = VOICES_DIR / f"{name}.pt"
    if p.exists():
        return p
    cands = [pt for pt in VOICES_DIR.glob("*.pt") if name.lower() in pt.stem.lower()]
    return cands[0] if cands else None


def _ensure_voice(name: str) -> bool:
    if name in _state["voice_cache"]:
        return True
    path = _voice_path(name)
    if path is None:
        _err("voice_missing", f"{name} not found under {VOICES_DIR}")
        return False
    target = _state["device"]
    try:
        prefilled = _state["torch"].load(
            path, map_location=target, weights_only=False
        )
    except Exception as exc:
        _err("voice_load_failed", f"{name}: {exc}")
        return False
    _state["voice_cache"][name] = prefilled
    _log(f"voice cached: {name} ({path.stat().st_size//1024} KB)")
    return True


def load_model() -> bool:
    if _state["model"] is not None:
        return True
    t0 = time.time()
    try:
        import torch
        from vibevoice.modular.modeling_vibevoice_streaming_inference import (
            VibeVoiceStreamingForConditionalGenerationInference,
        )
        from vibevoice.processor.vibevoice_streaming_processor import (
            VibeVoiceStreamingProcessor,
        )
    except Exception as exc:
        _err("import_failed", f"{exc}\n{traceback.format_exc()}")
        return False

    _state["torch"] = torch

    device, load_dtype, attn = _pick_device(torch)
    _state["device"] = device
    _log(f"device={device} dtype={load_dtype} attn={attn}")

    model_path = os.environ.get("VIBEVOICE_MODEL_PATH",
                                  "microsoft/VibeVoice-Realtime-0.5B")
    try:
        processor = VibeVoiceStreamingProcessor.from_pretrained(model_path)
    except Exception as exc:
        _err("processor_failed", f"{exc}")
        return False
    _state["processor"] = processor

    try:
        if device == "mps":
            model = VibeVoiceStreamingForConditionalGenerationInference.from_pretrained(
                model_path,
                torch_dtype=load_dtype,
                attn_implementation=attn,
                device_map=None,
            )
            model.to("mps")
        else:
            model = VibeVoiceStreamingForConditionalGenerationInference.from_pretrained(
                model_path,
                torch_dtype=load_dtype,
                device_map=device,
                attn_implementation=attn,
            )
    except Exception as exc:
        _err("model_load_failed", f"{exc}")
        return False

    model.eval()
    model.set_ddpm_inference_steps(num_steps=DEFAULT_STEPS)
    _state["model"] = model

    # Default voice cached eagerly so the first speak is fast.
    default_voice = os.environ.get("VIBEVOICE_VOICE", DEFAULT_VOICE)
    _ensure_voice(default_voice)

    if not _boot_smoke_if_enabled(default_voice):
        return False

    _log(f"model ready in {time.time()-t0:.1f}s")
    _frame("READ", b"")
    return True


# ─── Speak ──────────────────────────────────────────────────────────────────


def _prepare_inputs(text: str, prefilled: dict) -> dict:
    processor = _state["processor"]
    target = _state["device"]
    inputs = processor.process_input_with_cached_prompt(
        text=text,
        cached_prompt=prefilled,
        padding=True,
        return_tensors="pt",
        return_attention_mask=True,
    )
    for k, v in inputs.items():
        if hasattr(v, "to"):
            inputs[k] = v.to(target)
    return inputs


def _boot_smoke_if_enabled(voice: str) -> bool:
    """Validate that the selected backend can emit the first PCM chunk.

    MPS failures can abort the whole subprocess from native code. Running a
    tiny generation before READ lets the parent keep using fallback TTS instead
    of declaring VibeVoice ready and crashing on the first real utterance.
    """
    if not _truthy_env("VIBEVOICE_BOOT_SMOKE", True):
        return True

    if not _ensure_voice(voice):
        return False

    try:
        from queue import Empty
        from vibevoice.modular.streamer import AudioStreamer
    except Exception as exc:
        _err("smoke_dep_missing", str(exc))
        return False

    torch = _state["torch"]
    model = _state["model"]
    processor = _state["processor"]
    prefilled = _state["voice_cache"][voice]
    timeout_s = float(os.environ.get("VIBEVOICE_SMOKE_TIMEOUT_S", "25"))
    stop_event = threading.Event()
    audio_streamer = AudioStreamer(batch_size=1, stop_signal=None, timeout=0.25)
    errors = []

    try:
        inputs = _prepare_inputs(
            os.environ.get(
                "VIBEVOICE_SMOKE_TEXT",
                "This is a realtime startup check.",
            ),
            prefilled,
        )
    except Exception as exc:
        _err("smoke_prepare_failed", str(exc))
        return False

    def _gen() -> None:
        try:
            with torch.inference_mode():
                model.generate(
                    **inputs,
                    max_new_tokens=None,
                    cfg_scale=DEFAULT_CFG,
                    tokenizer=processor.tokenizer,
                    generation_config={"do_sample": False},
                    audio_streamer=audio_streamer,
                    stop_check_fn=stop_event.is_set,
                    verbose=False,
                    show_progress_bar=False,
                    return_speech=False,
                    refresh_negative=True,
                    all_prefilled_outputs=copy.deepcopy(prefilled),
                )
        except Exception as exc:
            errors.append(exc)
            audio_streamer.end()

    thread = threading.Thread(target=_gen, daemon=True, name="VibeBootSmoke")
    thread.start()

    iterator = iter(audio_streamer.get_stream(0))
    deadline = time.time() + timeout_s
    got_audio = False
    while time.time() < deadline:
        if errors:
            break
        if not thread.is_alive() and audio_streamer.audio_queues[0].empty():
            break
        try:
            chunk = next(iterator)
        except Empty:
            continue
        except StopIteration:
            break
        if chunk is not None:
            got_audio = True
            break

    stop_event.set()
    audio_streamer.end()
    thread.join(timeout=2.0)

    if errors:
        _err("boot_smoke_failed", str(errors[0]))
        return False
    if not got_audio:
        _err("boot_smoke_timeout", f"no first PCM chunk within {timeout_s:.1f}s")
        return False

    _log("boot smoke produced first PCM chunk")
    return True


def do_speak(req: dict) -> None:
    text  = (req.get("text") or "").strip().replace("’", "'")
    if not text:
        _frame("PCME")
        return
    voice = req.get("voice") or os.environ.get("VIBEVOICE_VOICE", DEFAULT_VOICE)
    cfg   = float(req.get("cfg_scale", DEFAULT_CFG))
    steps = int(req.get("steps",      DEFAULT_STEPS))

    if not _ensure_voice(voice):
        _frame("PCME")
        return
    prefilled = _state["voice_cache"][voice]

    torch = _state["torch"]
    model = _state["model"]
    processor = _state["processor"]

    try:
        model.set_ddpm_inference_steps(num_steps=max(1, steps))
    except Exception:
        pass

    try:
        from vibevoice.modular.streamer import AudioStreamer
        import numpy as np
    except Exception as exc:
        _err("dep_missing", f"{exc}")
        _frame("PCME")
        return

    try:
        inputs = _prepare_inputs(text, prefilled)
    except Exception as exc:
        _err("prepare_failed", str(exc))
        _frame("PCME")
        return

    generation = _begin_generation()
    if generation is None:
        _err("generation_busy", "previous VibeVoice generation did not stop cleanly")
        _frame("PCME")
        return
    generation_id, stop_event = generation

    audio_streamer = AudioStreamer(batch_size=1, stop_signal=None, timeout=0.25)
    errors = []

    def _gen():
        try:
            with torch.inference_mode():
                model.generate(
                    **inputs,
                    max_new_tokens=None,
                    cfg_scale=cfg,
                    tokenizer=processor.tokenizer,
                    generation_config={"do_sample": False},
                    audio_streamer=audio_streamer,
                    stop_check_fn=stop_event.is_set,
                    verbose=False,
                    show_progress_bar=False,
                    refresh_negative=True,
                    all_prefilled_outputs=copy.deepcopy(prefilled),
                )
        except Exception as exc:
            errors.append(exc)
            audio_streamer.end()

    thread = threading.Thread(
        target=_gen, daemon=True, name=f"VibeGenerate-{generation_id}"
    )
    thread.start()
    _register_generation(generation_id, stop_event, audio_streamer, thread)

    # Stream-start frame
    _frame("PCMS", json.dumps({
        "rate":   SAMPLE_RATE, "channels": 1, "voice": voice,
        "cfg":    cfg, "steps": steps,
    }).encode("utf-8"))

    min_samples = max(1, int(SAMPLE_RATE * MIN_PCM_CHUNK_MS / 1000.0))
    max_coalesce_s = max(0.0, MAX_PCM_COALESCE_MS / 1000.0)
    pending = []
    pending_samples = 0
    pending_started_at = 0.0
    samples = 0
    source_chunks = 0
    emitted_chunks = 0
    clipped_samples = 0
    peak_seen = 0.0
    first_chunk_at = None
    last_emit_at = None
    max_emit_gap = 0.0
    stopped = False
    t0 = time.monotonic()

    def _to_float_mono(chunk):
        nonlocal clipped_samples, peak_seen
        if hasattr(chunk, "detach"):
            np_chunk = chunk.detach().cpu().to(torch.float32).numpy()
        else:
            np_chunk = np.asarray(chunk, dtype=np.float32)
        if np_chunk.ndim > 1:
            np_chunk = np_chunk.reshape(-1)
        if not np_chunk.size:
            return None
        np_chunk = np_chunk.astype(np.float32, copy=False) * PCM_GAIN
        abs_chunk = np.abs(np_chunk)
        peak = float(np.max(abs_chunk)) if abs_chunk.size else 0.0
        peak_seen = max(peak_seen, peak)
        if peak > 1.0:
            clipped_samples += int(np.count_nonzero(abs_chunk > 1.0))
        return np.clip(np_chunk, -1.0, 1.0)

    def _emit_pending(force: bool = False) -> None:
        nonlocal pending, pending_samples, pending_started_at
        nonlocal samples, emitted_chunks, last_emit_at, max_emit_gap
        if pending_samples <= 0:
            return
        age = time.monotonic() - pending_started_at
        if not force and pending_samples < min_samples and age < max_coalesce_s:
            return
        if len(pending) == 1:
            np_chunk = pending[0]
        else:
            np_chunk = np.concatenate(pending)
        pending = []
        pending_samples = 0
        pending_started_at = 0.0

        now = time.monotonic()
        if last_emit_at is not None:
            max_emit_gap = max(max_emit_gap, now - last_emit_at)
        last_emit_at = now

        pcm = (np_chunk * 32767.0).astype(np.int16).tobytes()
        samples += np_chunk.size
        emitted_chunks += 1
        _frame("PCMC", pcm)

    def _queue_chunk(np_chunk) -> None:
        nonlocal pending_samples, pending_started_at
        if pending_samples <= 0:
            pending_started_at = time.monotonic()
        pending.append(np_chunk)
        pending_samples += np_chunk.size
        _emit_pending(force=False)

    iterator = iter(audio_streamer.get_stream(0))
    try:
        while True:
            if stop_event.is_set():
                stopped = True
                break
            try:
                chunk = next(iterator)
            except Empty:
                _emit_pending(force=False)
                if errors:
                    break
                if not thread.is_alive():
                    _emit_pending(force=True)
                    break
                continue
            except StopIteration:
                _emit_pending(force=True)
                break

            if chunk is None:
                continue
            source_chunks += 1
            if first_chunk_at is None:
                first_chunk_at = time.monotonic()
            np_chunk = _to_float_mono(chunk)
            if np_chunk is not None:
                _queue_chunk(np_chunk)
    except Exception as exc:
        errors.append(exc)
    finally:
        stop_event.set()
        audio_streamer.end()
        thread.join(timeout=2.0)
        if thread.is_alive():
            _log(f"generation thread still alive after stop id={generation_id}")
        _clear_generation(generation_id)
        if not stopped and not errors:
            _emit_pending(force=True)
        if errors and not stopped:
            _err("generate_failed", str(errors[0]))
        _frame("PCME")
        wall_s = max(0.001, time.monotonic() - t0)
        audio_s = samples / SAMPLE_RATE if samples else 0.0
        rtf = wall_s / audio_s if audio_s > 0 else 0.0
        first_s = (first_chunk_at - t0) if first_chunk_at is not None else None
        first_label = f"{first_s:.3f}s" if first_s is not None else "none"
        clip_pct = (clipped_samples / samples * 100.0) if samples else 0.0
        _log(
            "speak done "
            f"id={generation_id} stopped={stopped} chars={len(text)} "
            f"chunks_in={source_chunks} chunks_out={emitted_chunks} "
            f"audio={audio_s:.2f}s wall={wall_s:.2f}s rtf={rtf:.2f} "
            f"first_chunk={first_label} max_emit_gap={max_emit_gap:.3f}s "
            f"peak={peak_seen:.3f} clipped={clip_pct:.2f}%"
        )


# ─── Command loop ───────────────────────────────────────────────────────────

def _read_commands(commands: Queue, shutdown_event: threading.Event) -> None:
    """Read stdin continuously so stop can interrupt active synthesis."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            _err("bad_json", str(exc))
            continue

        cmd = req.get("cmd", "")
        if cmd == "stop":
            _signal_active_generation("stop_command")
            continue

        if cmd == "shutdown":
            _signal_active_generation("shutdown")
            shutdown_event.set()
            commands.put(req)
            break

        commands.put(req)

    shutdown_event.set()
    commands.put({"cmd": "shutdown"})


def main() -> int:
    _log(f"starting; voices={[p.stem for p in VOICES_DIR.glob('*.pt')]}")
    if not load_model():
        _frame("BYE ")
        return 1

    commands: Queue = Queue()
    shutdown_event = threading.Event()
    reader = threading.Thread(
        target=_read_commands,
        args=(commands, shutdown_event),
        daemon=True,
        name="VibeCommandReader",
    )
    reader.start()

    while not shutdown_event.is_set():
        req = commands.get()
        cmd = req.get("cmd", "")
        if cmd == "speak":
            do_speak(req)
        elif cmd == "warm":
            voice = req.get("voice") or os.environ.get("VIBEVOICE_VOICE", DEFAULT_VOICE)
            ok = _ensure_voice(voice)
            _frame("RDYV", json.dumps({"voice": voice, "ok": ok}).encode("utf-8"))
        elif cmd == "stop":
            _signal_active_generation("queued_stop")
        elif cmd == "shutdown":
            break
        else:
            _err("unknown_cmd", cmd)

    _frame("BYE ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
