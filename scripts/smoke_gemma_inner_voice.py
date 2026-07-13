#!/usr/bin/env python3
"""Smoke tests for the Gemma inner-voice path.

Default mode is fast and offline: it verifies the registry route plus Gemma-
style parser/gate cases. Pass ``--start-server`` to boot the same MLX launcher
used by TARS and request one real thought from the cached Gemma model.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from tars_inner_voice import InnerVoice
from tars_model_registry import ModelRegistry
from tars_thought_gate import ThoughtQualityGate


MODEL = "mlx-community/gemma-4-e4b-it-4bit"


def wait_models(port: int) -> None:
    url = f"http://127.0.0.1:{port}/v1/models"
    for _ in range(90):
        try:
            resp = requests.get(url, timeout=1)
            if resp.status_code == 200 and MODEL in resp.text:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("Gemma MLX server did not become ready")


def assert_registry() -> None:
    spec = ModelRegistry(str(PROJECT_DIR)).get("inner_fast")
    assert spec is not None and spec.model == MODEL, spec


def assert_parsing_and_gate() -> None:
    gate = ThoughtQualityGate()
    samples = [
        (
            "<think>I should decide the format.</think>\n"
            "Need to verify the actual launcher path before trusting the model swap.\n"
            "KIND=reflection MOOD=focused SALIENCE=0.82"
        ),
        (
            "assistant\n```text\nKIND: critique | MOOD: precise | SALIENCE: 0.71\n"
            "The weak-model symptom should be tested through the same inner-voice prompt."
            "\n```"
        ),
        (
            "THOUGHT: Gemma is only useful if its thoughts survive hygiene checks.\n"
            "KIND=observation, MOOD=careful, SALIENCE=0.66"
        ),
    ]
    for raw in samples:
        content, kind, mood, salience = InnerVoice._parse_response(raw)
        if not content or kind not in {"reflection", "observation", "wish", "critique", "fragment"}:
            raise AssertionError(f"parse failed: raw={raw!r}")
        ok, reason = gate.validate(
            {"content": content, "kind": kind, "mood": mood, "salience": salience},
            [],
        )
        if not ok:
            raise AssertionError(f"gate rejected parsed fixture: {reason}; raw={raw!r}")


def assert_live_generation(port: int) -> None:
    env = dict(os.environ)
    env.setdefault("TARS_LOCAL_MAX_TOKENS", "96")
    env.setdefault("TARS_LOCAL_CHAT_TEMPLATE_ARGS", '{"enable_thinking": false}')
    cmd = [
        str(PROJECT_DIR / "scripts" / "start_local_model.sh"),
        "127.0.0.1",
        str(port),
        MODEL,
    ]
    log = tempfile.NamedTemporaryFile(
        "w+",
        prefix="tars_gemma_smoke_",
        suffix=".log",
        delete=False,
    )
    proc = subprocess.Popen(
        cmd,
        cwd=str(PROJECT_DIR),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        try:
            wait_models(port)
        except Exception:
            log.flush()
            log.seek(0)
            tail = log.read()[-4000:]
            raise RuntimeError(f"Gemma MLX server did not become ready. Log tail:\n{tail}")
        payload = {
            "model": MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are TARS's private inner voice. Output one short, "
                        "specific thought, then exactly one metadata line."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Context: the user replaced the weak inner model with Gemma. "
                        "Think one useful private thought. Format:\n"
                        "<thought>\nKIND=reflection MOOD=focused SALIENCE=0.74"
                    ),
                },
            ],
            "max_tokens": 96,
            "temperature": 0.2,
            "stream": False,
        }
        resp = requests.post(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        msg = resp.json()["choices"][0]["message"]
        raw = (msg.get("content") or msg.get("reasoning") or "").strip()
        content, kind, mood, salience = InnerVoice._parse_response(raw)
        ok, reason = ThoughtQualityGate().validate(
            {"content": content, "kind": kind, "mood": mood, "salience": salience},
            [],
        )
        if not (content and kind in {"reflection", "observation", "wish", "critique", "fragment"}):
            raise AssertionError(f"parse failed: raw={raw!r}")
        if not ok:
            raise AssertionError(f"gate rejected thought: {reason}; raw={raw!r}")
        print("GEMMA INNER VOICE SMOKE OK")
        print(f"model={MODEL}")
        print(f"thought={content}")
        print(f"kind={kind} mood={mood} salience={salience:.2f}")
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
        try:
            log.close()
            os.unlink(log.name)
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="boot the real MLX server and request one live Gemma thought",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("TARS_GEMMA_SMOKE_PORT", "9891")),
        help="port for the temporary live MLX server",
    )
    args = parser.parse_args()

    assert_registry()
    assert_parsing_and_gate()
    if args.start_server:
        assert_live_generation(args.port)
    else:
        print("GEMMA INNER VOICE OFFLINE SMOKE OK")
        print(f"model={MODEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
