"""
VibeVoice Realtime 0.5B — subprocess client for TARS
=====================================================

Hosts a long-running child process inside ``tars_vibevoice/venv`` (which
pins torch 2.5.x + vibevoice deps that conflict with the parent's torch
2.9 + mlx-lm install). Communicates with the child via a tiny binary
framing protocol over stdin/stdout. The child does ALL of the heavy
PyTorch + diffusion work; the parent just feeds it text and pipes the
returned PCM chunks straight to sounddevice.

Why subprocess instead of in-process:
  - ``import vibevoice`` segfaults under torch 2.9 (verified on this Mac).
  - The two packages pin incompatible transformers versions.
  - Subprocess + isolated venv lets us update either side without
    touching the other.

Protocol (matching ``tars_vibevoice/worker.py``):
  Commands written to child stdin as line-delimited JSON.
  Frames read from child stdout as ``[4-byte BE len][4-byte tag][payload]``:
    READ  - model loaded
    RDYV  - voice cached
    PCMS  - utterance start (payload = JSON header)
    PCMC  - PCM int16 chunk
    PCME  - utterance end
    ERR   - error event
    BYE   - clean exit
  Diagnostic logs from worker arrive via stderr (forwarded into our log).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Callable, Iterator, List, Optional


SAMPLE_RATE = 24_000
DEFAULT_VOICE = "en-Carter_man"


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _voices_dir() -> Path:
    return _project_root() / "tars_vibevoice" / "voices"


def _venv_python() -> Optional[Path]:
    p = _project_root() / "tars_vibevoice" / "venv" / "bin" / "python"
    return p if p.exists() else None


def _worker_path() -> Path:
    return _project_root() / "tars_vibevoice" / "worker.py"


def _wrap_wav(pcm_int16: bytes, sample_rate: int = SAMPLE_RATE,
              channels: int = 1) -> bytes:
    byte_rate    = sample_rate * channels * 2
    block_align  = channels * 2
    data_size    = len(pcm_int16)
    riff_size    = 36 + data_size
    header = (
        b"RIFF" + struct.pack("<I", riff_size) + b"WAVE"
        + b"fmt " + struct.pack("<IHHIIHH",
                                  16, 1, channels, sample_rate,
                                  byte_rate, block_align, 16)
        + b"data" + struct.pack("<I", data_size)
    )
    return header + pcm_int16


# ─── Frame parser ───────────────────────────────────────────────────────────

def _read_exact(f, n: int) -> Optional[bytes]:
    """Read exactly n bytes from a binary file-like; return None on EOF."""
    chunks: List[bytes] = []
    remaining = n
    while remaining > 0:
        b = f.read(remaining)
        if not b:
            return None
        chunks.append(b)
        remaining -= len(b)
    return b"".join(chunks)


def _read_frame(f) -> Optional[tuple[str, bytes]]:
    header = _read_exact(f, 8)
    if header is None:
        return None
    length = struct.unpack(">I", header[:4])[0]
    tag = header[4:8].decode("ascii", errors="replace")
    payload = _read_exact(f, length) if length > 0 else b""
    if payload is None:
        return None
    return tag, payload


# ─── VibeVoiceTTS — subprocess client ───────────────────────────────────────

class VibeVoiceTTS:
    """Lifecycle:
        vibe = VibeVoiceTTS(voice="en-Carter_man", log_fn=log_info)
        vibe.start()                           # spawn child, returns once READ frame received
        for pcm in vibe.stream_pcm(text): ...  # iter int16 bytes; non-blocking start
        wav = vibe.synthesize_to_wav(text)     # one-shot; returns full WAV blob
        vibe.shutdown()                        # graceful exit

    The class is thread-safe at the level of one in-flight utterance.
    Concurrent ``stream_pcm`` calls block on the internal lock — only one
    speak at a time, which matches the human conversation model anyway.
    """

    READY_TIMEOUT_S = 300.0     # cold-start: ~5-15 s when cached, up to a few
                                # minutes on first run when the model is being
                                # pulled from HF (~1.5 GB).

    def __init__(
        self,
        voice: str = DEFAULT_VOICE,
        model_path: str = "microsoft/VibeVoice-Realtime-0.5B",
        device: str = "",            # "" = auto in worker
        cfg_scale: float = 1.5,
        inference_steps: int = 5,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.voice_name      = voice
        self.model_path      = model_path
        self.device          = device
        self.cfg_scale       = float(cfg_scale)
        self.inference_steps = int(inference_steps)
        self.log             = log_fn or (lambda m: None)

        self._proc: Optional[subprocess.Popen] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._frame_q: "Queue[tuple[str, bytes]]" = Queue()
        self._send_lock = threading.Lock()      # serialises stdin writes
        self._utt_lock  = threading.Lock()      # one utterance at a time
        self._ready_event = threading.Event()
        self._shutdown    = threading.Event()

    # -- lifecycle --------------------------------------------------------

    def available_voices(self) -> List[str]:
        d = _voices_dir()
        if not d.exists():
            return []
        return sorted(p.stem for p in d.glob("*.pt"))

    def start(self) -> bool:
        """Spawn the child process and wait for the READ frame. Returns
        False on any setup failure (caller should fall back)."""
        if self._proc is not None and self._proc.poll() is None:
            return self._ready_event.is_set()

        py = _venv_python()
        if py is None:
            self.log(f"[vibe] venv python not found at "
                     f"{_project_root() / 'tars_vibevoice/venv/bin/python'}")
            return False
        worker = _worker_path()
        if not worker.exists():
            self.log(f"[vibe] worker.py missing: {worker}")
            return False

        env = {**os.environ,
               "VIBEVOICE_VOICE":      self.voice_name,
               "VIBEVOICE_MODEL_PATH": self.model_path,
               "PYTHONUNBUFFERED":     "1",
               "PYTORCH_ENABLE_MPS_FALLBACK": "1",
               "TOKENIZERS_PARALLELISM": "false",
               "TRANSFORMERS_VERBOSITY": "error"}
        if self.device:
            env["VIBEVOICE_DEVICE"] = self.device

        try:
            self._proc = subprocess.Popen(
                [str(py), str(worker)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                bufsize=0,        # unbuffered binary I/O
            )
        except Exception as exc:
            self.log(f"[vibe] spawn failed: {exc}")
            return False

        self._ready_event.clear()
        self._shutdown.clear()
        self._stdout_thread = threading.Thread(
            target=self._stdout_pump, daemon=True, name="VibeStdout"
        )
        self._stderr_thread = threading.Thread(
            target=self._stderr_pump, daemon=True, name="VibeStderr"
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

        deadline = time.time() + self.READY_TIMEOUT_S
        ready = False
        while time.time() < deadline:
            if self._ready_event.wait(timeout=0.2):
                ready = True
                break
            if self._proc is None:
                break
            rc = self._proc.poll()
            if rc is not None:
                self.log(f"[vibe] worker exited before READY (rc={rc})")
                return self._retry_cpu_after_start_failure()

        if not ready:
            self.log("[vibe] worker did not become READY in time")
            return self._retry_cpu_after_start_failure()
        self.log("[vibe] worker READY")
        return True

    def _retry_cpu_after_start_failure(self) -> bool:
        """Auto-device mode should prefer MPS for speed, then CPU for
        reliability if the MPS worker dies before it can prove audio output."""
        explicit_device = (self.device or os.environ.get("VIBEVOICE_DEVICE", "")).strip()
        retry_enabled = os.environ.get(
            "VIBEVOICE_AUTO_CPU_FALLBACK", "1"
        ).strip().lower() in {"1", "true", "yes", "on"}

        self.shutdown()
        if explicit_device or not retry_enabled:
            return False

        self.device = "cpu"
        self.log("[vibe] retrying worker on CPU after auto-device startup failure")
        return self.start()

    def shutdown(self) -> None:
        self._shutdown.set()
        proc = self._proc
        if proc is None:
            return
        try:
            with self._send_lock:
                if proc.stdin and not proc.stdin.closed:
                    try:
                        proc.stdin.write(b'{"cmd":"shutdown"}\n')
                        proc.stdin.flush()
                    except Exception:
                        pass
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    proc.kill()
        finally:
            self._proc = None

    @property
    def is_ready(self) -> bool:
        return (self._proc is not None and self._proc.poll() is None
                and self._ready_event.is_set())

    # -- frame pumps ------------------------------------------------------

    def _stdout_pump(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        while not self._shutdown.is_set():
            f = _read_frame(proc.stdout)
            if f is None:
                break
            tag, payload = f
            if tag == "READ":
                self._ready_event.set()
                continue
            self._frame_q.put((tag, payload))
        # signal EOF to any consumer waiting on a stream
        self._frame_q.put(("EOF ", b""))

    def _stderr_pump(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in iter(proc.stderr.readline, b""):
            if not line:
                break
            try:
                txt = line.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            if not txt:
                continue
            if self._suppress_worker_log(txt):
                continue
            if len(txt) > 700:
                txt = txt[:700] + " ... [truncated]"
            self.log(txt)

    @staticmethod
    def _suppress_worker_log(txt: str) -> bool:
        noisy_bits = (
            "The tokenizer class you load from this checkpoint",
            "The class this function is called from is",
            "`torch_dtype` is deprecated",
            "Some weights of VibeVoiceStreamingForConditionalGenerationInference",
            "You should probably TRAIN this model",
        )
        if any(bit in txt for bit in noisy_bits):
            return True
        return "Prefilled " in txt and "current step" in txt

    # -- send commands ----------------------------------------------------

    def _send(self, cmd: dict) -> None:
        if self._proc is None or self._proc.stdin is None:
            return
        line = json.dumps(cmd, ensure_ascii=False) + "\n"
        with self._send_lock:
            try:
                self._proc.stdin.write(line.encode("utf-8"))
                self._proc.stdin.flush()
            except (OSError, BrokenPipeError) as exc:
                self.log(f"[vibe] stdin write failed: {exc}")

    def _clear_frame_queue(self) -> int:
        """Drop any leftover frames before a new utterance starts."""
        dropped = 0
        while True:
            try:
                self._frame_q.get_nowait()
                dropped += 1
            except Empty:
                break
        if dropped:
            self.log(f"[vibe] dropped {dropped} stale frame(s) before utterance")
        return dropped

    def _drain_until_stream_end(self, timeout_s: float = 2.0) -> None:
        """Best-effort cleanup after stop/timeout so late frames do not poison
        the next utterance."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                tag, _payload = self._frame_q.get(timeout=0.1)
            except Empty:
                continue
            if tag in ("PCME", "ERR ", "EOF "):
                return

    # -- public synth APIs ------------------------------------------------

    def stream_pcm(
        self,
        text: str,
        voice: Optional[str] = None,
        cfg_scale: Optional[float] = None,
        inference_steps: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        first_chunk_callback: Optional[Callable[[], None]] = None,
    ) -> Iterator[bytes]:
        """Yield int16 PCM bytes at SAMPLE_RATE while the worker streams.
        Aborts cleanly when ``stop_event`` is set. ``first_chunk_callback``
        fires on the very first PCMC frame — useful for measuring TTFA."""
        if not self.is_ready:
            return
        if not text or not text.strip():
            return

        with self._utt_lock:
            self._clear_frame_queue()
            cmd = {
                "cmd":   "speak",
                "text":  text,
                "voice": voice or self.voice_name,
            }
            if cfg_scale is not None:
                cmd["cfg_scale"] = float(cfg_scale)
            if inference_steps is not None:
                cmd["steps"] = int(inference_steps)
            self._send(cmd)

            seen_pcms = False
            seen_first_chunk = False
            stop_sent = False
            try:
                while True:
                    if stop_event is not None and stop_event.is_set() and not stop_sent:
                        # Tell the worker to abort; drain frames until PCME.
                        self._send({"cmd": "stop"})
                        stop_sent = True
                    try:
                        tag, payload = self._frame_q.get(timeout=15.0)
                    except Empty:
                        self.log("[vibe] frame_q timeout — aborting utterance")
                        self._send({"cmd": "stop"})
                        self._drain_until_stream_end()
                        return
                    if tag == "PCMS":
                        seen_pcms = True
                        continue
                    if tag == "PCMC":
                        if not seen_first_chunk and first_chunk_callback:
                            seen_first_chunk = True
                            try: first_chunk_callback()
                            except Exception: pass
                        if stop_event is not None and stop_event.is_set():
                            continue
                        yield payload
                        continue
                    if tag == "PCME":
                        return
                    if tag == "ERR ":
                        try:
                            err = json.loads(payload.decode("utf-8"))
                            self.log(f"[vibe] worker error: {err}")
                        except Exception:
                            self.log(f"[vibe] worker error: {payload[:120]!r}")
                        return
                    if tag == "EOF ":
                        return
                    if tag == "RDYV":
                        # Voice was newly cached; keep going.
                        continue
            finally:
                pass

    def synthesize_to_wav(
        self,
        text: str,
        voice: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> Optional[bytes]:
        chunks: List[bytes] = []
        for pcm in self.stream_pcm(text, voice=voice, stop_event=stop_event):
            chunks.append(pcm)
        if not chunks:
            return None
        return _wrap_wav(b"".join(chunks))


# ─── Streaming player — sounddevice-based ───────────────────────────────────

class StreamingPCMPlayer:
    """Minimal sounddevice wrapper. The PCMC chunks from VibeVoice land
    here directly — no intermediate file, no afplay. TTFA = (worker first
    PCMC) + (sounddevice latency, typically <50 ms)."""

    def __init__(self, sample_rate: int = SAMPLE_RATE, channels: int = 1,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.sample_rate = sample_rate
        self.channels = channels
        self.log = log_fn or (lambda m: None)
        self._stream = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if self._stream is not None:
            self._stop.clear()
            return True
        try:
            import sounddevice as sd
        except Exception as exc:
            self.log(f"[vibe-play] sounddevice unavailable: {exc}")
            return False
        try:
            stream = sd.RawOutputStream(
                samplerate=self.sample_rate,
                channels=self.channels,
                dtype="int16",
                blocksize=0,
            )
            stream.start()
        except Exception as exc:
            self.log(f"[vibe-play] sounddevice start failed: {exc}")
            return False
        self._stream = stream
        self._stop.clear()
        return True

    def write(self, pcm: bytes) -> bool:
        if self._stream is None or self._stop.is_set():
            return False
        try:
            self._stream.write(pcm)
            return True
        except Exception as exc:
            self.log(f"[vibe-play] write failed: {exc}")
            return False

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        if self._stream is None:
            return
        try:
            self._stream.stop()
            self._stream.close()
        except Exception:
            pass
        self._stream = None


# ─── Self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """Smoke test the wrapper without spawning the worker."""
    print("VibeVoice subprocess client self-test")
    voices = sorted((_voices_dir()).glob("*.pt"))
    print(f"  voices: {[v.stem for v in voices]}")
    py = _venv_python()
    print(f"  venv python: {py}  exists={py is not None and py.exists()}")
    worker = _worker_path()
    print(f"  worker:      {worker}  exists={worker.exists()}")
    fake_pcm = (b"\x00\x00") * 24_000
    wav = _wrap_wav(fake_pcm)
    assert wav.startswith(b"RIFF") and len(wav) == 44 + len(fake_pcm)
    print(f"  WAV wrapper OK ({len(wav):,} bytes)")
    print("OK")
