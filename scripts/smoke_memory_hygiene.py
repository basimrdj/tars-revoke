#!/usr/bin/env python3
"""Offline smoke test for episodic-memory prompt hygiene."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tars_memory import EMBED_DIM_3_SMALL, Memory, SALIENCE_FLOOR


class FakeEmbedder:
    model = "fake-embedding"

    def __init__(self) -> None:
        self.texts = []
        self.success_count = 0
        self.fail_count = 0

    def embed(self, text: str):
        self.texts.append(text)
        self.success_count += 1
        return self._vec(text)

    def embed_batch(self, texts):
        return [self.embed(t) for t in texts]

    @staticmethod
    def _vec(text: str):
        v = np.zeros(EMBED_DIM_3_SMALL, dtype=np.float32)
        low = text.lower()
        v[0] = 1.0
        if "database" in low or "recall" in low:
            v[1] = 3.0
        if "project" in low or "context" in low:
            v[2] = 2.0
        if "api error" in low or "invalid api key" in low:
            v[3] = 5.0
        return v


def _install_fake_embedder(mem: Memory) -> FakeEmbedder:
    fake = FakeEmbedder()
    mem.embedder = fake
    mem.episodes.embedder = fake
    return fake


def _insert_legacy_noisy_row(mem: Memory) -> None:
    ts = datetime.now().isoformat(timespec="microseconds")
    vec = FakeEmbedder._vec("MiMo API error 401 invalid api key")
    with mem.episodes._lock, mem.episodes._conn:
        mem.episodes._conn.execute(
            """INSERT INTO episodes
                   (id, ts, role, content, embedding, embed_model, salience,
                    tags, memory_type, confidence, utility_score, provenance,
                    contradicts)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "legacy_noisy",
                ts,
                "system",
                "MiMo API error 401: Invalid API Key",
                vec.tobytes(),
                "legacy",
                0.95,
                "[]",
                "workspace",
                0.9,
                0.9,
                "{}",
                "[]",
            ),
        )
    mem.episodes._cache_dirty = True


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        mem = Memory(d)
        fake = _install_fake_embedder(mem)

        clean_id = mem.add_turn(
            "user",
            "The user wants database recall to preserve durable project context.",
            memory_type="social",
            salience=0.7,
        )
        noisy_reply_id = mem.add_turn(
            "assistant",
            '[Tone: Calm] MiMo API error 401: {"error":{"message":"Invalid API Key"}}',
            memory_type="episodic",
            salience=0.8,
        )
        noisy_world_id = mem.add_event({
            "id": "evt_noise_world",
            "source": "world",
            "kind": "prediction_error",
            "content": "Prediction error 1.00: MiMo API error 429: quota exhausted",
            "salience": 1.0,
            "raw": {"prediction": {"actual_source": "assistant"}},
        })
        noisy_skill_id = mem.add_event({
            "id": "evt_skill_failure",
            "source": "tool",
            "kind": "skill_failure",
            "content": "Skill failed: HTTP 500 from RPC worker",
            "salience": 0.9,
            "raw": {"tool": "demo"},
        })
        clean_world_id = mem.add_event({
            "id": "evt_clean_world",
            "source": "world",
            "kind": "prediction_error",
            "content": "Prediction error 0.20: user corrected the database recall plan",
            "salience": 0.55,
            "raw": {"prediction": {"actual_source": "user"}},
        })
        _insert_legacy_noisy_row(mem)

        embedded_text = "\n".join(fake.texts).lower()
        assert clean_id and clean_world_id
        assert "durable project context" in embedded_text
        assert "api error 401" not in embedded_text
        assert "quota exhausted" not in embedded_text
        assert "http 500" not in embedded_text

        with mem.episodes._lock:
            rows = mem.episodes._conn.execute(
                """SELECT id, tags, provenance, salience, embedding
                     FROM episodes
                    WHERE id IN (?, ?, ?)""",
                (noisy_reply_id, noisy_world_id, noisy_skill_id),
            ).fetchall()
        assert len(rows) == 3
        for _eid, tags_json, provenance_json, salience, embedding in rows:
            tags = json.loads(tags_json)
            provenance = json.loads(provenance_json)
            assert "quarantine:prompt_recall" in tags
            assert provenance["memory_hygiene"]["prompt_visible"] is False
            assert float(salience) < SALIENCE_FLOOR
            assert embedding is None

        bundle = mem.retrieve_for_prompt("database recall project context")
        surfaced = json.dumps(bundle).lower()
        assert "durable project context" in surfaced
        assert "api error" not in surfaced
        assert "invalid api key" not in surfaced
        assert "quota exhausted" not in surfaced
        assert "http 500" not in surfaced
        assert "legacy_noisy" not in surfaced

    print("memory hygiene smoke OK")


if __name__ == "__main__":
    main()
