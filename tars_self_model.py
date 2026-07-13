"""
TARS Quantitative Self-Model  (Phase 2.5I)
==========================================

Evidence-backed self-state for TARS. This is deliberately not a personality
file and not a poetic identity layer. It tracks capability estimates,
uncertainties, failures, successes, drift, and calibration.

Persistence:
  * tars_self_model.json

All updates require an event/report note. The numbers are small nudges, never
big rewrites. Later phases can use committee approval for identity changes.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


SELF_MODEL_FILE = "tars_self_model.json"

CAPABILITY_KEYS = (
    "voice_stability",
    "stt_reliability",
    "tts_consistency",
    "memory_recall",
    "inner_thought_quality",
    "world_model_accuracy",
    "goal_pursuit",
    "skill_building",
    "social_attunement",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _clamp01(value: Any, default: float = 0.0) -> float:
    try:
        x = float(value)
    except Exception:
        x = default
    return max(0.0, min(1.0, x))


def _atomic_json_write(path: str, payload: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)


def _read_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return copy.deepcopy(default)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return copy.deepcopy(default)


def _to_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        try:
            return obj.to_dict()
        except Exception:
            return {}
    return getattr(obj, "__dict__", {}) if hasattr(obj, "__dict__") else {}


def _compact(text: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."

def _sanitize_note(text: str) -> str:
    if not text:
        return ""
    # Strip TTS tags like [Tone: Dry], [pause], [inhale]
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Reject recursive prediction errors
    if text.count("Prediction error") > 1:
        return ""
        
    return _compact(text, 180)


def _default_state() -> Dict[str, Any]:
    return {
        "capabilities": {
            "voice_stability": 0.55,
            "stt_reliability": 0.55,
            "tts_consistency": 0.50,
            "memory_recall": 0.60,
            "inner_thought_quality": 0.55,
            "world_model_accuracy": 0.35,
            "goal_pursuit": 0.50,
            "skill_building": 0.55,
            "social_attunement": 0.55,
        },
        "confidence_calibration": 0.45,
        "drift_score": 0.0,
        "known_failure_modes": [
            "Voice and STT/TTS quality need live-field validation.",
            "Mind modules must remain fail-soft so voice/chat stays usable.",
        ],
        "stable_traits": [],
        "active_uncertainties": [
            "World model accuracy is unproven until prediction logs accumulate.",
            "Sleep consolidation needs repeated reports before it can be trusted.",
        ],
        "recent_successes": [],
        "recent_failures": [],
        "evidence": [],
        "last_updated": _now_iso(),
    }


class SelfModel:
    """Quantitative, evidence-backed self-state."""

    def __init__(self, project_dir: str,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.project_dir = project_dir
        self.path = os.path.join(project_dir, SELF_MODEL_FILE)
        self.log = log_fn or (lambda _m: None)
        self._lock = threading.RLock()
        self._state = self._merge_defaults(_read_json(self.path, _default_state()))
        self._save()

    def state(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._state)

    def addendum(self) -> str:
        st = self.state()
        caps = st.get("capabilities", {}) or {}
        weak = sorted(caps.items(), key=lambda kv: float(kv[1]))[:3]
        strong = sorted(caps.items(), key=lambda kv: -float(kv[1]))[:3]
        failures = st.get("known_failure_modes", []) or []
        unknowns = st.get("active_uncertainties", []) or []
        return (
            "## Self-Model\n"
            "These are measured estimates, not identity claims.\n"
            f"- strongest: {', '.join(f'{k}={float(v):.2f}' for k, v in strong)}\n"
            f"- weakest: {', '.join(f'{k}={float(v):.2f}' for k, v in weak)}\n"
            f"- calibration={_clamp01(st.get('confidence_calibration', 0.0)):.2f}, "
            f"drift_score={_clamp01(st.get('drift_score', 0.0)):.2f}\n"
            f"- known_failure_modes: {'; '.join(_compact(x, 120) for x in failures[:3]) or '(none logged)'}\n"
            f"- active_uncertainties: {'; '.join(_compact(x, 120) for x in unknowns[:3]) or '(none)'}"
        )

    def update_from_event(self, event: Any) -> Dict[str, Any]:
        d = _to_dict(event)
        source = str(d.get("source", "") or "")
        kind = str(d.get("kind", "") or "")
        content = str(d.get("content", "") or "")
        event_id = str(d.get("id", "") or "")
        raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
        applied: Dict[str, Any] = {}

        if kind == "prediction_error":
            pred = raw.get("prediction") if isinstance(raw.get("prediction"), dict) else raw
            return self.update_from_prediction_error(pred, source_event_id=event_id)

        if kind == "skill_failure":
            self.record_failure(
                "skill_building",
                _compact(content or "Skill failure event", 180),
                source_event_id=event_id,
                delta=-0.05,
            )
            applied["skill_building"] = -0.05

        elif kind == "skill_result":
            self.record_success(
                "skill_building",
                _compact(content or "Skill result event", 180),
                source_event_id=event_id,
                delta=0.025,
            )
            applied["skill_building"] = 0.025

        elif kind == "workspace_frame":
            winner = raw.get("winner") if isinstance(raw.get("winner"), dict) else {}
            w_source = str(winner.get("source", "") or "")
            if w_source == "user":
                self._nudge("social_attunement", 0.005, "workspace captured user turn", event_id)
                applied["social_attunement"] = 0.005
            if w_source in {"memory", "system"} and "memory" in str(winner.get("content", "")).lower():
                self._nudge("memory_recall", 0.005, "workspace used memory signal", event_id)
                applied["memory_recall"] = 0.005

        elif kind == "sleep_summary":
            return self.update_from_sleep_report(raw.get("report") or raw, source_event_id=event_id)

        elif source == "inner_voice" or kind == "thought":
            tags = d.get("tags") if isinstance(d.get("tags"), list) else []
            if "critique" in tags or "wrong" in content.lower() or "failed" in content.lower():
                self._add_failure_mode(_compact(content, 180))
                self._nudge("inner_thought_quality", -0.01, "inner critique/failure thought", event_id)
                applied["inner_thought_quality"] = -0.01

        # Lightweight voice/system error inference from text, if those
        # events are ever published onto the bus.
        lower = content.lower()
        if any(w in lower for w in ("deepgram", "stt", "transcription")) and any(
            w in lower for w in ("error", "failed", "timeout", "closed")
        ):
            self.record_failure("stt_reliability", _compact(content, 180), event_id, delta=-0.03)
            applied["stt_reliability"] = -0.03
        if any(w in lower for w in ("tts", "voice", "audio")) and any(
            w in lower for w in ("error", "failed", "glitch", "timeout")
        ):
            self.record_failure("tts_consistency", _compact(content, 180), event_id, delta=-0.03)
            applied["tts_consistency"] = -0.03

        if applied:
            self._touch()
        return applied

    def update_from_prediction_error(self, prediction: Dict[str, Any],
                                     source_event_id: str = "") -> Dict[str, Any]:
        if not isinstance(prediction, dict):
            return {}
        error = prediction.get("prediction_error")
        if error is None:
            return {}
        error = _clamp01(error)
        target_accuracy = 1.0 - error
        with self._lock:
            caps = self._state["capabilities"]
            prev = _clamp01(caps.get("world_model_accuracy", 0.35), 0.35)
            caps["world_model_accuracy"] = round(_clamp01(prev * 0.85 + target_accuracy * 0.15), 3)
            prev_cal = _clamp01(self._state.get("confidence_calibration", 0.45), 0.45)
            self._state["confidence_calibration"] = round(
                _clamp01(prev_cal * 0.9 + target_accuracy * 0.1), 3
            )
            
            # Store aggregate stats separately
            agg = self._state.setdefault("prediction_stats", {"count": 0, "avg_error": 0.0})
            c = agg.setdefault("count", 0)
            avg = agg.setdefault("avg_error", 0.0)
            agg["avg_error"] = (avg * c + error) / (c + 1)
            agg["count"] = c + 1
            
            sit = _sanitize_note(prediction.get("situation", ""))
            if not sit:
                self._touch_locked()
                self._save()
                return {
                    "world_model_accuracy": self.state()["capabilities"]["world_model_accuracy"],
                    "confidence_calibration": self.state()["confidence_calibration"],
                }
                
            note = f"World prediction error={error:.2f}: {sit}"
            
            if error >= 0.70:
                self._append_bounded("recent_failures", self._entry(note, source_event_id))
                self._add_failure_mode("World model badly missed a recent transition.")
            elif error <= 0.30:
                self._append_bounded("recent_successes", self._entry(note, source_event_id))
            
            # Only append evidence if it's a strong signal
            if error >= 0.70 or error <= 0.30:
                self._append_evidence("world_model_accuracy", note, source_event_id)
                
            self._touch_locked()
        self._save()
        return {
            "world_model_accuracy": self.state()["capabilities"]["world_model_accuracy"],
            "confidence_calibration": self.state()["confidence_calibration"],
        }

    def update_from_sleep_report(self, report: Dict[str, Any],
                                 source_event_id: str = "") -> Dict[str, Any]:
        if not isinstance(report, dict):
            return {}
        mode = report.get("mode") or report.get("type") or "sleep"
        themes = report.get("themes") or []
        contradictions = report.get("contradictions") or []
        beliefs = report.get("new_semantic_beliefs") or []
        note = f"{mode} report: themes={len(themes)}, beliefs={len(beliefs)}, contradictions={len(contradictions)}"
        delta_mem = 0.01 if themes or beliefs else 0.0
        delta_goal = 0.01 if report.get("concerns") else 0.0
        with self._lock:
            if delta_mem:
                self._nudge_locked("memory_recall", delta_mem, note, source_event_id)
            if delta_goal:
                self._nudge_locked("goal_pursuit", delta_goal, note, source_event_id)
            if contradictions:
                self._add_failure_mode("Sleep found unresolved memory contradictions.")
            self._append_bounded("recent_successes", self._entry(note, source_event_id))
            self._touch_locked()
        self._save()
        return {"memory_recall": delta_mem, "goal_pursuit": delta_goal}

    def record_success(self, capability: str, note: str,
                       source_event_id: str = "", delta: float = 0.02) -> None:
        with self._lock:
            self._nudge_locked(capability, abs(delta), note, source_event_id)
            self._append_bounded("recent_successes", self._entry(note, source_event_id))
            self._touch_locked()
        self._save()

    def record_failure(self, capability: str, note: str,
                       source_event_id: str = "", delta: float = -0.03) -> None:
        with self._lock:
            self._nudge_locked(capability, -abs(delta), note, source_event_id)
            self._append_bounded("recent_failures", self._entry(note, source_event_id))
            self._add_failure_mode(note)
            self._touch_locked()
        self._save()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _merge_defaults(self, state: Dict[str, Any]) -> Dict[str, Any]:
        merged = _default_state()
        if isinstance(state, dict):
            for key, value in state.items():
                if isinstance(value, dict) and isinstance(merged.get(key), dict):
                    merged[key].update(value)
                else:
                    merged[key] = value
        caps = merged.setdefault("capabilities", {})
        for key in CAPABILITY_KEYS:
            caps[key] = _clamp01(caps.get(key, _default_state()["capabilities"][key]))
        return merged

    def _save(self) -> None:
        with self._lock:
            try:
                _atomic_json_write(self.path, self._state)
            except Exception as exc:
                self.log(f"[self-model] save failed: {exc}")

    def _nudge(self, capability: str, delta: float,
               note: str, source_event_id: str = "") -> None:
        with self._lock:
            self._nudge_locked(capability, delta, note, source_event_id)
            self._touch_locked()
        self._save()

    def _nudge_locked(self, capability: str, delta: float,
                      note: str, source_event_id: str = "") -> None:
        if capability not in CAPABILITY_KEYS:
            return
        caps = self._state["capabilities"]
        caps[capability] = round(_clamp01(caps.get(capability, 0.5) + float(delta)), 3)
        self._append_evidence(capability, note, source_event_id)

    def _append_evidence(self, capability: str, note: str, source_event_id: str = "") -> None:
        self._append_bounded("evidence", {
            "ts": _now_iso(),
            "capability": capability,
            "note": _compact(note, 220),
            "source_event_id": source_event_id,
        }, limit=80)

    def _append_bounded(self, key: str, item: Dict[str, Any], limit: int = 12) -> None:
        items = self._state.setdefault(key, [])
        if not isinstance(items, list):
            items = []
            self._state[key] = items
            
        new_sid = item.get("source_event_id", "")
        new_note = item.get("note", "")
        
        for ex in items:
            if new_sid and ex.get("source_event_id") == new_sid:
                return # exact duplicate
            if not new_sid and not ex.get("source_event_id") and ex.get("note") == new_note:
                return # content duplicate with no source id
                
        items.append(item)
        del items[:-limit]

    @staticmethod
    def _entry(note: str, source_event_id: str = "") -> Dict[str, Any]:
        return {
            "ts": _now_iso(),
            "note": _compact(note, 220),
            "source_event_id": source_event_id,
        }

    def _add_failure_mode(self, note: str) -> None:
        note = _sanitize_note(note)
        if not note or "Prediction error" in note or "World prediction error" in note:
            return
        modes = self._state.setdefault("known_failure_modes", [])
        if not isinstance(modes, list):
            modes = []
            self._state["known_failure_modes"] = modes
        if note not in modes:
            modes.append(note)
            del modes[:-10]

    def _touch(self) -> None:
        with self._lock:
            self._touch_locked()
        self._save()

    def _touch_locked(self) -> None:
        self._state["last_updated"] = _now_iso()
        # Drift stays bounded until later personality phases can compare
        # against soul/personality embeddings. For now it rises only when
        # self-state changes repeatedly.
        self._state["drift_score"] = round(
            _clamp01(float(self._state.get("drift_score", 0.0)) * 0.98), 3
        )


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        sm = SelfModel(td, log_fn=print)
        sm.update_from_event({
            "id": "evt_fail",
            "source": "skill",
            "kind": "skill_failure",
            "content": "Skill execution failed during a smoke test.",
        })
        sm.update_from_prediction_error({
            "situation": "testing world model",
            "prediction_error": 0.25,
        })
        assert "## Self-Model" in sm.addendum()
        st = sm.state()
        assert 0.0 <= st["capabilities"]["world_model_accuracy"] <= 1.0
        print("SELF MODEL SELF-TEST OK")
