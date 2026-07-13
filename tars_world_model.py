"""
TARS World Model  (Phase 2.5H)
==============================

Maintains a compact, persistent estimate of "what situation are we in,
what is likely next, and how wrong was the last prediction?"

This module is intentionally deterministic and fail-soft. It does not start
or call a model. The orchestrator feeds it workspace frames and later events;
it writes:

  * tars_world_state.json
  * tars_world_predictions.jsonl

The JSONL is append-only. When a prediction is resolved we append a second
record with the same id and actual/error fields rather than rewriting history.
Metrics can collapse by id later.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional


WORLD_STATE_FILE = "tars_world_state.json"
WORLD_PREDICTIONS_FILE = "tars_world_predictions.jsonl"

_TOKEN_RE = re.compile(r"[a-z0-9']+")
_STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "i", "you", "he", "she", "it", "we", "they", "me", "my", "your",
    "his", "her", "their", "our", "to", "of", "in", "on", "for", "with",
    "and", "or", "but", "so", "that", "this", "these", "those", "what",
    "when", "where", "why", "how", "do", "does", "did", "done", "have",
    "has", "had", "will", "would", "can", "could", "should", "just",
    "now", "then", "there", "here", "about", "from", "into", "as",
}

PROJECT_KEYWORDS = {
    "tars": "TARS",
    "mimo": "MiMo realtime assistant",
    "deepgram": "voice pipeline",
    "stt": "voice pipeline",
    "tts": "voice pipeline",
    "voice": "voice pipeline",
    "vibevoice": "local TTS research",
    "memory": "memory system",
    "workspace": "global workspace",
    "world": "world model",
    "self-model": "self-model",
    "self model": "self-model",
    "sleep": "sleep consolidation",
    "phase 2.5": "Phase 2.5 mind core",
    "mind": "mind simulator",
    "codex": "self-evolution builder",
    "skill": "skill system",
    "plan": "Phase plan",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _clamp01(value: Any, default: float = 0.0) -> float:
    try:
        x = float(value)
    except Exception:
        x = default
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


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


def _append_jsonl(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


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


def _tokens(text: str) -> set:
    toks = _TOKEN_RE.findall((text or "").lower())
    return {t for t in toks if t not in _STOPWORDS and len(t) > 1}


def _jaccard(a: str, b: str) -> float:
    ta = _tokens(a)
    tb = _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / max(1, len(ta | tb))


def _compact(text: str, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def _default_state() -> Dict[str, Any]:
    return {
        "current_situation": "No active workspace frame yet.",
        "user_state": {
            "likely_focus": "",
            "emotion_estimate": "unknown",
            "goal": "",
            "uncertainty": 0.0,
        },
        "environment_state": {
            "available_inputs": ["voice", "memory", "inner_voice", "workspace"],
            "future_inputs": ["screen", "calendar", "camera"],
        },
        "active_projects": [],
        "likely_next_states": [],
        "possible_actions": [],
        "prediction_confidence": 0.0,
        "last_prediction_error": 0.0,
        "last_updated": "",
        "last_workspace_frame_id": "",
        "open_prediction_id": "",
    }


class WorldModel:
    """Persistent current-situation estimator and prediction logger."""

    def __init__(self, project_dir: str,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.project_dir = project_dir
        self.state_path = os.path.join(project_dir, WORLD_STATE_FILE)
        self.pred_path = os.path.join(project_dir, WORLD_PREDICTIONS_FILE)
        self.log = log_fn or (lambda _m: None)
        self._lock = threading.RLock()
        self._state: Dict[str, Any] = _read_json(self.state_path, _default_state())
        self._state = self._merge_defaults(self._state)
        self._save()

    def state(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._state)

    def addendum(self) -> str:
        """System-prompt section. Short by design."""
        st = self.state()
        user = st.get("user_state", {}) or {}
        nexts = st.get("likely_next_states", []) or []
        actions = st.get("possible_actions", []) or []
        projects = st.get("active_projects", []) or []
        return (
            "## World Model\n"
            f"- current_situation: {_compact(st.get('current_situation', ''), 220)}\n"
            f"- user_focus: {_compact(user.get('likely_focus', '') or 'unknown', 160)}\n"
            f"- user_goal: {_compact(user.get('goal', '') or 'unknown', 160)}\n"
            f"- emotion_estimate: {user.get('emotion_estimate', 'unknown')}  "
            f"uncertainty={_clamp01(user.get('uncertainty', 0.0)):.2f}\n"
            f"- active_projects: {', '.join(projects[:4]) if projects else '(none detected)'}\n"
            f"- likely_next: {'; '.join(nexts[:3]) if nexts else '(not predicted yet)'}\n"
            f"- possible_actions: {', '.join(actions[:5]) if actions else '(none)'}\n"
            f"- prediction_confidence={_clamp01(st.get('prediction_confidence', 0.0)):.2f}, "
            f"last_error={_clamp01(st.get('last_prediction_error', 0.0)):.2f}"
        )

    def update_from_workspace(self, frame: Any,
                              event: Optional[Any] = None) -> Dict[str, Any]:
        """Absorb a workspace frame and open a prediction for the next event."""
        frame_d = _to_dict(frame)
        if not frame_d and event is not None:
            raw = _to_dict(event).get("raw")
            if isinstance(raw, dict):
                frame_d = raw.get("frame") or {}
        winner = frame_d.get("winner") if isinstance(frame_d, dict) else None
        if not isinstance(winner, dict) or not winner:
            return {}

        content = str(winner.get("content", "") or "")
        source = str(winner.get("source", "system") or "system")
        extra = winner.get("extra") if isinstance(winner.get("extra"), dict) else {}
        appraisal = extra.get("appraisal") if isinstance(extra.get("appraisal"), dict) else {}

        situation = self._situation_from_winner(source, content, appraisal)
        likely_next = self._likely_next_states(source, content, appraisal)
        actions = self._possible_actions(source, content, appraisal)
        confidence = self._prediction_confidence(winner, appraisal)
        projects = self._active_projects(content, previous=self._state.get("active_projects", []))

        state_update = {
            "current_situation": situation,
            "user_state": {
                "likely_focus": self._focus_from_content(content),
                "emotion_estimate": self._emotion_from_appraisal(appraisal, content),
                "goal": self._goal_from_content(content, appraisal),
                "uncertainty": _clamp01(winner.get("uncertainty", appraisal.get("uncertainty", 0.0))),
            },
            "environment_state": {
                "available_inputs": ["voice", "memory", "inner_voice", "workspace"],
                "future_inputs": ["screen", "calendar", "camera"],
            },
            "active_projects": projects,
            "likely_next_states": likely_next,
            "possible_actions": actions,
            "prediction_confidence": confidence,
            "last_updated": _now_iso(),
            "last_workspace_frame_id": frame_d.get("id", ""),
        }

        prediction = {
            "id": "pred_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6],
            "ts": _now_iso(),
            "situation": situation,
            "predicted_next": likely_next,
            "chosen_action": actions[0] if actions else "wait",
            "expected_user_reaction": self._expected_user_reaction(content, appraisal),
            "actual_next_event": "",
            "actual_event_id": "",
            "prediction_error": None,
            "source_workspace_frame_id": frame_d.get("id", ""),
            "source_event_id": self._first_evidence_id(winner),
            "status": "open",
        }

        with self._lock:
            self._state.update(state_update)
            self._state["open_prediction_id"] = prediction["id"]
            self._save_locked()
            _append_jsonl(self.pred_path, prediction)
        return prediction

    def observe_event(self, event: Any) -> Optional[Dict[str, Any]]:
        """Resolve the currently open prediction against a new event."""
        d = _to_dict(event)
        kind = str(d.get("kind", "") or "")
        source = str(d.get("source", "") or "")
        if kind in {"workspace_frame", "prediction_error", "sleep_summary"}:
            return None
        if source in {"world", "sleep"}:
            return None

        actual = _compact(str(d.get("content", "") or ""), 500)
        if not actual:
            return None

        with self._lock:
            pred_id = self._state.get("open_prediction_id") or ""
        if not pred_id:
            return None

        pred = self._latest_prediction(pred_id)
        if not pred or pred.get("status") == "resolved":
            return None
        if d.get("id") and d.get("id") == pred.get("source_event_id"):
            return None

        score = self._prediction_match(pred, actual, kind=kind, source=source)
        error = round(1.0 - _clamp01(score), 3)
        resolved = dict(pred)
        resolved.update({
            "resolved_ts": _now_iso(),
            "actual_next_event": actual,
            "actual_event_id": d.get("id", ""),
            "actual_source": source,
            "actual_kind": kind,
            "prediction_error": error,
            "status": "resolved",
        })

        with self._lock:
            _append_jsonl(self.pred_path, resolved)
            self._state["last_prediction_error"] = error
            self._state["open_prediction_id"] = ""
            # Lower confidence after large errors, preserve it after good hits.
            prev_conf = _clamp01(self._state.get("prediction_confidence", 0.0))
            self._state["prediction_confidence"] = round(
                _clamp01((prev_conf * 0.75) + ((1.0 - error) * 0.25)), 3
            )
            self._state["last_updated"] = _now_iso()
            self._save_locked()
        return resolved

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _merge_defaults(self, state: Dict[str, Any]) -> Dict[str, Any]:
        merged = _default_state()
        if isinstance(state, dict):
            for k, v in state.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k].update(v)
                else:
                    merged[k] = v
        return merged

    def _save(self) -> None:
        with self._lock:
            self._save_locked()

    def _save_locked(self) -> None:
        try:
            _atomic_json_write(self.state_path, self._state)
        except Exception as exc:
            self.log(f"[world] save failed: {exc}")

    def _latest_prediction(self, pred_id: str) -> Optional[Dict[str, Any]]:
        if not pred_id or not os.path.exists(self.pred_path):
            return None
        found = None
        try:
            with open(self.pred_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read = min(size, 512 * 1024)
                f.seek(size - read)
                blob = f.read().decode("utf-8", errors="replace")
            for line in blob.splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("id") == pred_id:
                    found = rec
        except Exception:
            return None
        return found

    @staticmethod
    def _first_evidence_id(winner: Dict[str, Any]) -> str:
        evidence = winner.get("evidence")
        if isinstance(evidence, list) and evidence:
            return str(evidence[0])
        return ""

    def _prediction_match(self, pred: Dict[str, Any], actual: str,
                          *, kind: str, source: str) -> float:
        # Phase 2.5R-G: Ensure predictions are scored reliably
        predicted = pred.get("predicted_next") or []
        texts = [str(x) for x in predicted if x]
        if pred.get("expected_user_reaction"):
            texts.append(str(pred["expected_user_reaction"]))
        
        # Base Jaccard score
        best = max((_jaccard(t, actual) for t in texts), default=0.0)

        # Heuristics for common abstract flows
        lower_actual = actual.lower()
        joined_pred = " ".join(texts).lower()
        
        if source == "user" and "user" in joined_pred:
            best = max(best, 0.35)
        if source == "assistant" and ("answer" in joined_pred or "respond" in joined_pred or "reply" in joined_pred):
            best = max(best, 0.45)
        if "follow-up" in joined_pred and ("?" in actual or kind == "utterance"):
            best = max(best, 0.45)
            
        # Error / Correction flows
        if any(w in lower_actual for w in ("wrong", "broken", "error", "failed", "stop", "no")):
            if any(w in joined_pred for w in ("correction", "problem", "fix", "pressure", "frustration")):
                best = max(best, 0.75) # High match if we predicted frustration and they were frustrated
                
        # Very short responses (acknowledgments)
        if len(_tokens(actual)) <= 2:
            if "wait" in joined_pred or "listen" in joined_pred:
                best = max(best, 0.50)
            else:
                best = max(best, 0.25)
                
        return _clamp01(best)

    @staticmethod
    def _situation_from_winner(source: str, content: str,
                               appraisal: Dict[str, Any]) -> str:
        uncertainty = _clamp01(appraisal.get("uncertainty", 0.0))
        goal_tension = _clamp01(appraisal.get("goal_tension", 0.0))
        prefix = {
            "user": "The user turn is driving attention",
            "assistant": "The assistant reply is being evaluated",
            "inner_voice": "A private thought is competing for attention",
            "memory": "Retrieved memory is shaping the current context",
            "system": "A system event is shaping the current context",
        }.get(source, f"{source} event is shaping the current context")
        flags = []
        if uncertainty >= 0.55:
            flags.append("uncertainty is elevated")
        if goal_tension >= 0.55:
            flags.append("goal pressure is elevated")
        tail = "; ".join(flags) if flags else "low immediate conflict"
        return f"{prefix}: {_compact(content, 180)} ({tail})."

    @staticmethod
    def _focus_from_content(content: str) -> str:
        toks = [t for t in _TOKEN_RE.findall((content or "").lower())
                if t not in _STOPWORDS and len(t) > 2]
        if not toks:
            return ""
        counts = Counter(toks)
        return " ".join(t for t, _ in counts.most_common(6))

    @staticmethod
    def _emotion_from_appraisal(appraisal: Dict[str, Any], content: str) -> str:
        val = float(appraisal.get("valence", 0.0) or 0.0)
        arousal = _clamp01(appraisal.get("arousal", 0.0))
        lower = (content or "").lower()
        if any(w in lower for w in ("bro", "comon", "bruh", "fix", "broken")):
            return "impatient / high-expectation"
        if val > 0.35:
            return "positive"
        if val < -0.35:
            return "frustrated or negative"
        if arousal > 0.65:
            return "activated"
        return "neutral or mixed"

    @staticmethod
    def _goal_from_content(content: str, appraisal: Dict[str, Any]) -> str:
        lower = (content or "").lower()
        if any(w in lower for w in ("fix", "broken", "error", "failed", "bug")):
            return "get a concrete fix without breaking the working build"
        if any(w in lower for w in ("implement", "build", "add", "next step")):
            return "advance the project according to the plan"
        if any(w in lower for w in ("faster", "optimize", "latency", "quick")):
            return "improve speed and responsiveness"
        if "?" in content:
            return "get a direct answer with evidence"
        if _clamp01(appraisal.get("goal_tension", 0.0)) > 0.5:
            return "resolve a high-pressure open goal"
        return "continue the current interaction coherently"

    @staticmethod
    def _likely_next_states(source: str, content: str,
                            appraisal: Dict[str, Any]) -> List[str]:
        lower = (content or "").lower()
        out: List[str] = []
        if source == "user" and "?" in content:
            out.append("assistant answers; user may ask a follow-up or correct missing context")
        if any(w in lower for w in ("fix", "broken", "error", "failed", "not good")):
            out.append("user expects visible repair work and will judge by runtime behavior")
        if any(w in lower for w in ("implement", "build", "phase", "plan")):
            out.append("assistant should change code in small verified steps")
        if _clamp01(appraisal.get("uncertainty", 0.0)) > 0.6:
            out.append("clarification may be needed before risky action")
        if not out:
            out.append("conversation continues around the current focus")
        out.append("workspace and memory should preserve the fresh turn over stale events")
        return out[:4]

    @staticmethod
    def _possible_actions(source: str, content: str,
                          appraisal: Dict[str, Any]) -> List[str]:
        lower = (content or "").lower()
        actions = ["answer_or_think"]
        if any(w in lower for w in ("implement", "build", "fix", "add")):
            actions = ["make_verified_code_change", "run_offline_tests", "log_session_state"]
        elif "?" in content:
            actions = ["answer_directly", "retrieve_memory", "ask_clarifying_question_if_needed"]
        if _clamp01(appraisal.get("uncertainty", 0.0)) > 0.65:
            actions.append("reduce_uncertainty_before_acting")
        actions.append("wait_if_user_is_speaking")
        return actions

    @staticmethod
    def _prediction_confidence(winner: Dict[str, Any],
                               appraisal: Dict[str, Any]) -> float:
        conf = _clamp01(winner.get("confidence", 0.6), default=0.6)
        sal = _clamp01(winner.get("salience", 0.0))
        uncertainty = _clamp01(appraisal.get("uncertainty", winner.get("uncertainty", 0.0)))
        value = 0.25 + (0.35 * conf) + (0.25 * sal) - (0.25 * uncertainty)
        return round(_clamp01(value), 3)

    @staticmethod
    def _expected_user_reaction(content: str, appraisal: Dict[str, Any]) -> str:
        lower = (content or "").lower()
        if any(w in lower for w in ("fix", "broken", "faster", "optimize", "implement")):
            return "user will look for concrete progress, tests, and no regressions"
        if "?" in content:
            return "user will expect a direct answer and may ask a follow-up"
        if _clamp01(appraisal.get("goal_tension", 0.0)) > 0.6:
            return "user may stay impatient until the goal visibly advances"
        return "user likely continues or waits for the assistant"

    @staticmethod
    def _active_projects(content: str, previous: Iterable[str]) -> List[str]:
        lower = (content or "").lower()
        found = list(previous or [])
        for key, label in PROJECT_KEYWORDS.items():
            if key in lower and label not in found:
                found.append(label)
        return found[-8:]


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        wm = WorldModel(td, log_fn=print)
        frame = {
            "id": "ws_test",
            "winner": {
                "source": "user",
                "content": "Bro implement the next Phase 2.5 steps and don't break voice.",
                "salience": 0.8,
                "uncertainty": 0.3,
                "confidence": 0.9,
                "evidence": ["evt_user"],
                "extra": {"appraisal": {"uncertainty": 0.3, "goal_tension": 0.8}},
            },
        }
        pred = wm.update_from_workspace(frame)
        assert pred["id"]
        resolved = wm.observe_event({
            "id": "evt_assistant",
            "source": "assistant",
            "kind": "utterance",
            "content": "I will make verified code changes and run offline tests.",
        })
        assert resolved and resolved["prediction_error"] is not None
        assert "## World Model" in wm.addendum()
        print("WORLD MODEL SELF-TEST OK")
