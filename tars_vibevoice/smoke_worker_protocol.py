#!/usr/bin/env python3
"""Fast protocol smoke for worker.py without loading VibeVoice.

This monkeypatches the VibeVoice streamer/model imports so the worker can be
checked for frame ordering, chunk coalescing, clipping, and stop signalling.
"""

from __future__ import annotations

import contextlib
import queue
import sys
import threading
import types
from pathlib import Path

import numpy as np


sys.path.insert(0, str(Path(__file__).resolve().parent))


class FakeAudioStreamer:
    def __init__(self, batch_size=1, stop_signal=None, timeout=None):
        self.timeout = timeout
        self._queue = queue.Queue()
        self._ended = threading.Event()

    def push(self, chunk) -> None:
        self._queue.put(chunk)

    def end(self) -> None:
        self._ended.set()
        self._queue.put(None)

    def get_stream(self, index):
        while True:
            try:
                item = self._queue.get(timeout=self.timeout)
            except queue.Empty:
                raise
            if item is None:
                return
            yield item


def install_fake_vibevoice_modules() -> None:
    vibevoice = types.ModuleType("vibevoice")
    modular = types.ModuleType("vibevoice.modular")
    streamer = types.ModuleType("vibevoice.modular.streamer")
    streamer.AudioStreamer = FakeAudioStreamer
    sys.modules["vibevoice"] = vibevoice
    sys.modules["vibevoice.modular"] = modular
    sys.modules["vibevoice.modular.streamer"] = streamer


class FakeTorch:
    float32 = object()

    def inference_mode(self):
        return contextlib.nullcontext()


class FakeProcessor:
    tokenizer = object()


class FakeModel:
    def set_ddpm_inference_steps(self, num_steps):
        self.steps = num_steps

    def generate(self, **kwargs):
        streamer = kwargs["audio_streamer"]
        for chunk in (
            np.full(100, 0.20, dtype=np.float32),
            np.full(200, 1.50, dtype=np.float32),
            np.full(900, 0.40, dtype=np.float32),
        ):
            if kwargs["stop_check_fn"]():
                break
            streamer.push(chunk)
        streamer.end()


def main() -> int:
    install_fake_vibevoice_modules()

    import worker

    frames = []
    worker._frame = lambda tag, payload=b"": frames.append((tag, payload))
    worker._ensure_voice = lambda voice: True
    worker._prepare_inputs = lambda text, prefilled: {}
    worker._state["torch"] = FakeTorch()
    worker._state["model"] = FakeModel()
    worker._state["processor"] = FakeProcessor()
    worker._state["voice_cache"] = {"en-Carter_man": {}}
    worker._state["active_streamer"] = None
    worker._state["generation_thread"] = None

    worker.do_speak({"cmd": "speak", "text": "Protocol smoke."})

    tags = [tag for tag, _ in frames]
    assert tags[0] == "PCMS", tags
    assert tags[-1] == "PCME", tags
    pcm_frames = [payload for tag, payload in frames if tag == "PCMC"]
    assert len(pcm_frames) == 1, f"expected coalesced PCMC, got {len(pcm_frames)}"

    pcm = np.frombuffer(pcm_frames[0], dtype=np.int16)
    assert len(pcm) == 1200, len(pcm)
    assert np.max(np.abs(pcm)) == 32767, "fixed clipping should cap overs"

    stop_event = threading.Event()
    streamer = FakeAudioStreamer(timeout=0.01)
    worker._state["stop_event"] = stop_event
    worker._state["active_streamer"] = streamer
    worker._signal_active_generation("smoke")
    assert stop_event.is_set(), "stop event was not set"
    assert streamer._ended.is_set(), "streamer was not ended"

    print("worker protocol smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
