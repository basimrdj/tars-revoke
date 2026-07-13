"""
Deepgram Aura WebSocket TTS — true streaming text-in / streaming audio-out
==========================================================================

Why this module exists (Phase −1 R15):

The HTTP /v1/speak path (used in R12) is request/response. Each phrase
chunk costs a TLS handshake + synthesis round-trip — that's the 1-2 s
gap users hear between chunks of a multi-sentence reply.

Deepgram's WebSocket Speak endpoint solves this. ONE persistent socket
per conversation. Push text fragments as the LLM emits them; binary
audio frames stream back continuously. No per-chunk handshake cost,
no waiting for one synthesis to finish before sending the next.

Protocol (Deepgram docs):
    Open:   wss://<host>/v1/speak?model=<model>&encoding=linear16&sample_rate=24000
    Auth:   Authorization: Token <key>   (header)
    Send:   {"type":"Speak","text":"..."}     — push text to synth queue
            {"type":"Flush"}                   — force audio output for queued text
            {"type":"Clear"}                   — abandon queued audio (barge-in)
            {"type":"Close"}                   — close cleanly
    Recv:   raw binary PCM int16 LE frames
            JSON status messages: Metadata, Flushed, Cleared, Warning

Public API mirrors the existing PCM player so Speaker can drop it in
behind the same provider routing.

Design:
  - one persistent WebSocket per Speaker instance, opened lazily
  - reader thread pumps binary frames → sounddevice player
  - audio plays as chunks arrive (no buffering; sub-300 ms TTFA target)
  - speak_text / flush / clear are non-blocking writer-side
  - reconnect with backoff on socket death; Speaker falls back to HTTP
    path if ensure() fails
"""

from __future__ import annotations

import json
import os
import struct
import threading
import time
import urllib.parse
from typing import Callable, List, Optional

try:
    from websockets.sync.client import connect as ws_connect
    from websockets.exceptions import ConnectionClosed, WebSocketException
    _WS_OK = True
except Exception as _exc:                                       # pragma: no cover
    _WS_OK = False
    ws_connect = None  # type: ignore
    ConnectionClosed = WebSocketException = Exception           # type: ignore


SAMPLE_RATE_DEFAULT = 24_000


def _wrap_wav(pcm_int16: bytes, sample_rate: int = SAMPLE_RATE_DEFAULT,
              channels: int = 1) -> bytes:
    """Wrap raw int16 LE PCM in a RIFF/WAVE container — used by the
    HTTP-fallback `synthesize_to_wav` path."""
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


class DeepgramTTSStream:
    """Persistent Deepgram Aura WebSocket TTS client.

    Lifecycle:
        ws = DeepgramTTSStream(api_key, model="aura-2-atlas-en", log_fn=log)
        ws.ensure()                       # opens the socket; idempotent
        ws.speak_text("Hello there. ")    # push text to synth queue
        ws.speak_text("How are you?")
        ws.flush()                        # force audio output for queued text
        ws.wait_audio_end(timeout=15)     # block until Flushed status received
        # ... next utterance reuses the same socket
        ws.close()                        # only on Speaker.shutdown()
    """

    BACKOFF_SCHEDULE_S = (1.0, 2.0, 5.0, 10.0, 30.0)

    def __init__(
        self,
        api_key: str,
        model: str = "aura-2-atlas-en",
        base: str = "https://api.sac1.deepgram.com",
        sample_rate: int = SAMPLE_RATE_DEFAULT,
        log_fn: Optional[Callable[[str], None]] = None,
        on_audio: Optional[Callable[[bytes], bool]] = None,
        on_status: Optional[Callable[[dict], None]] = None,
    ):
        self.api_key      = api_key
        self.model        = model
        self.sample_rate  = sample_rate
        self.log          = log_fn or (lambda _m: None)
        self.on_audio     = on_audio                  # called with each PCM frame
        self.on_status    = on_status                  # called with each JSON msg

        # https://… → wss://…
        if base.startswith("https://"):
            self.ws_base = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            self.ws_base = "ws://" + base[len("http://"):]
        else:
            self.ws_base = base

        self._ws = None
        self._reader_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()                  # guards send + open
        self._stop_event   = threading.Event()
        self._connected    = threading.Event()
        self._flushed_event = threading.Event()        # set when worker emits Flushed
        self._cleared_event = threading.Event()
        self._restart_attempts = 0
        self.audio_bytes_session = 0                   # observability counter

    # ── connection lifecycle ─────────────────────────────────────────────

    def ensure(self) -> bool:
        """Open the socket if not already connected. Returns True if ready.
        Synchronous and idempotent. Safe to call before every utterance."""
        if not _WS_OK:
            self.log("[dg-tts-ws] websockets lib unavailable")
            return False
        if not self.api_key:
            self.log("[dg-tts-ws] missing DEEPGRAM_API_KEY")
            return False
        with self._lock:
            if self._ws is not None and self._connected.is_set():
                return True
            return self._connect_locked()

    def _connect_locked(self) -> bool:
        """Caller holds self._lock. Spawns reader thread on success."""
        params = urllib.parse.urlencode({
            "model":       self.model,
            "encoding":    "linear16",
            "sample_rate": self.sample_rate,
        })
        url = f"{self.ws_base.rstrip('/')}/v1/speak?{params}"
        try:
            self._ws = ws_connect(
                url,
                additional_headers={"Authorization": f"Token {self.api_key}"},
                max_size=None,        # audio frames can be large
                open_timeout=10,
                close_timeout=2,
            )
        except Exception as exc:
            self.log(f"[dg-tts-ws] connect failed: {exc}")
            self._ws = None
            return False

        self._stop_event.clear()
        self._flushed_event.clear()
        self._cleared_event.clear()
        self._connected.set()
        self._reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True, name="DgTtsWsReader"
        )
        self._reader_thread.start()
        self.log(f"[dg-tts-ws] connected ({self.model})")
        return True

    def close(self) -> None:
        """Graceful shutdown. Sends Close, drains reader."""
        self._stop_event.set()
        with self._lock:
            ws = self._ws
            self._ws = None
            self._connected.clear()
        if ws is not None:
            try:
                ws.send(json.dumps({"type": "Close"}))
            except Exception:
                pass
            try:
                ws.close()
            except Exception:
                pass

    # ── public send API ──────────────────────────────────────────────────

    def speak_text(self, text: str) -> bool:
        """Queue text for synthesis. Non-blocking. Audio for THIS text
        starts streaming back as soon as Deepgram has enough context.
        Returns False if the socket isn't connected."""
        if not text:
            return True
        with self._lock:
            ws = self._ws
            if ws is None or not self._connected.is_set():
                return False
            try:
                ws.send(json.dumps({"type": "Speak", "text": text}))
                return True
            except (ConnectionClosed, WebSocketException, OSError) as exc:
                self.log(f"[dg-tts-ws] speak_text send failed: {exc}")
                self._connected.clear()
                return False

    def flush(self) -> bool:
        """Force the synth to emit audio for everything queued so far. The
        reader thread sets `_flushed_event` when Deepgram acknowledges with
        a `Flushed` status. Caller can `wait_audio_end()` to block until
        that arrives."""
        with self._lock:
            ws = self._ws
            if ws is None or not self._connected.is_set():
                return False
            self._flushed_event.clear()
            try:
                ws.send(json.dumps({"type": "Flush"}))
                return True
            except (ConnectionClosed, WebSocketException, OSError) as exc:
                self.log(f"[dg-tts-ws] flush send failed: {exc}")
                self._connected.clear()
                return False

    def clear(self) -> bool:
        """Abandon any queued audio that hasn't been emitted yet — for
        barge-in. Reader thread sets `_cleared_event` on the Cleared ack."""
        with self._lock:
            ws = self._ws
            if ws is None or not self._connected.is_set():
                return False
            self._cleared_event.clear()
            try:
                ws.send(json.dumps({"type": "Clear"}))
                return True
            except (ConnectionClosed, WebSocketException, OSError) as exc:
                self.log(f"[dg-tts-ws] clear send failed: {exc}")
                self._connected.clear()
                return False

    def wait_audio_end(self, timeout: float = 30.0) -> bool:
        """Block until the most recent Flush is acknowledged. Returns True
        if the Flushed event arrived, False on timeout."""
        return self._flushed_event.wait(timeout=timeout)

    # ── reader thread ───────────────────────────────────────────────────

    def _reader_loop(self) -> None:
        """Pump frames from the socket. Binary frames → on_audio callback;
        JSON status frames → on_status callback + internal events."""
        ws = self._ws
        if ws is None:
            return
        try:
            for msg in ws:
                if self._stop_event.is_set():
                    break
                if isinstance(msg, (bytes, bytearray)):
                    self.audio_bytes_session += len(msg)
                    if self.on_audio:
                        try:
                            keep = self.on_audio(bytes(msg))
                        except Exception as exc:
                            self.log(f"[dg-tts-ws] on_audio raised: {exc}")
                            keep = True
                        if keep is False:
                            break
                else:
                    # JSON status
                    try:
                        payload = json.loads(msg)
                    except Exception:
                        continue
                    msg_type = (payload.get("type") or "").lower()
                    if msg_type == "flushed":
                        self._flushed_event.set()
                    elif msg_type == "cleared":
                        self._cleared_event.set()
                    elif msg_type == "warning":
                        self.log(f"[dg-tts-ws] warning: {payload}")
                    if self.on_status:
                        try: self.on_status(payload)
                        except Exception: pass
        except (ConnectionClosed, WebSocketException, OSError) as exc:
            self.log(f"[dg-tts-ws] reader closed: {exc}")
        except Exception as exc:                                  # pragma: no cover
            self.log(f"[dg-tts-ws] reader error: {exc}")
        finally:
            self._connected.clear()
            # Set events so callers blocked on them don't hang on disconnect.
            self._flushed_event.set()
            self._cleared_event.set()


# ─── Self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """Doesn't actually open a socket — just sanity-checks the module."""
    print(f"websockets available: {_WS_OK}")
    fake_pcm = b"\x00\x00" * 24_000
    wav = _wrap_wav(fake_pcm)
    assert wav.startswith(b"RIFF") and len(wav) == 44 + len(fake_pcm)
    print(f"WAV wrapper OK ({len(wav):,} bytes)")
    print("OK")
