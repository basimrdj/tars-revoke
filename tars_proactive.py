"""
TARS Proactive Learner
======================

Runs in the background after each user turn (rate-limited) to extract:
  - User identity / name
  - Communication preferences (length, tone, formality)
  - Recurring topics / interests
  - Implicit capability wishes (things the user keeps trying that TARS can't do)

Stored in `tars_learnings.json` and injected into TARS's system prompt at boot
so the assistant carries memory of who you are across sessions.

Rate-limited: by default 1 LLM analysis per 5 minutes (cheap on tokens, plenty
of signal accumulates). Buffered turns are batched in the next run.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from tars_event_bus import emit_safe


class ProactiveLearner:
    """Background-threaded learner that updates tars_learnings.json."""

    LEARNINGS_FILE     = "tars_learnings.json"
    DEFAULT_INTERVAL_S = 5 * 60      # one LLM call per 5 min worst case
    BUFFER_LIMIT       = 30          # never let buffer grow unbounded

    DEFAULT_LEARNINGS: Dict = {
        "user_name":           None,
        "preferences":         [],
        "frequent_topics":     [],
        "capability_wishes":   [],
        "communication_style": None,
        "last_updated":        None,
    }

    def __init__(self, project_dir: str, chat_fn: Callable, log_fn,
                 interval_s: Optional[int] = None, event_bus=None):
        self.project_dir   = project_dir
        self.chat_fn       = chat_fn
        self.log           = log_fn
        self.interval_s    = interval_s or self.DEFAULT_INTERVAL_S
        self.path          = os.path.join(project_dir, self.LEARNINGS_FILE)
        self.event_bus     = event_bus

        self._buffer: List[Dict[str, str]] = []          # [{user, tars}, ...]
        self._buffer_lock = threading.Lock()
        self._learnings_lock = threading.Lock()
        self._last_run = 0.0
        self._thread: Optional[threading.Thread] = None
        self._running = False

        self.learnings: Dict = self._load()

    def set_event_bus(self, event_bus) -> None:
        self.event_bus = event_bus

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> Dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                merged = dict(self.DEFAULT_LEARNINGS)
                merged.update(data or {})
                return merged
            except Exception:
                pass
        return dict(self.DEFAULT_LEARNINGS)

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.learnings, f, indent=2, default=str)
            os.replace(tmp, self.path)
        except Exception as e:
            self.log(f"[learner] save failed: {e}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def observe(self, user_text: str, tars_reply: str) -> None:
        """Cheap — just append to a buffer. The thread drains periodically."""
        if not user_text:
            return
        with self._buffer_lock:
            self._buffer.append({
                "user": user_text[:600],
                "tars": (tars_reply or "")[:400],
                "ts":   datetime.now().isoformat(),
            })
            if len(self._buffer) > self.BUFFER_LIMIT:
                # keep newest
                self._buffer = self._buffer[-self.BUFFER_LIMIT:]

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="TarsProactiveLearner")
        self._thread.start()
        self.log(f"[learner] proactive learner started (interval {self.interval_s}s).")

    def stop(self) -> None:
        self._running = False

    def system_prompt_addendum(self) -> str:
        """A compact paragraph to splice into TARS's system prompt at boot."""
        with self._learnings_lock:
            l = dict(self.learnings)
        if not any(l.get(k) for k in ("user_name", "preferences",
                                      "frequent_topics", "capability_wishes",
                                      "communication_style")):
            return ""
        lines = ["[Persistent User Profile — earned from prior conversations]"]
        if l.get("user_name"):
            lines.append(f"- User name: {l['user_name']}")
        if l.get("communication_style"):
            lines.append(f"- Style: {l['communication_style']}")
        if l.get("preferences"):
            prefs = ", ".join(l["preferences"][:6])
            lines.append(f"- Preferences: {prefs}")
        if l.get("frequent_topics"):
            tops = ", ".join(l["frequent_topics"][:6])
            lines.append(f"- Frequent topics: {tops}")
        if l.get("capability_wishes"):
            wishes = ", ".join(l["capability_wishes"][:6])
            lines.append(f"- Recurring capability wishes: {wishes}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------
    def _run_loop(self) -> None:
        time.sleep(15)
        while self._running:
            try:
                if (time.time() - self._last_run) < self.interval_s:
                    time.sleep(10)
                    continue

                with self._buffer_lock:
                    drained = self._buffer
                    self._buffer = []

                if not drained:
                    time.sleep(10)
                    continue

                self._last_run = time.time()
                self._analyze(drained)
            except Exception as e:
                self.log(f"[learner] loop error: {e}")
                time.sleep(30)

    def _analyze(self, turns: List[Dict[str, str]]) -> None:
        """Send buffered turns to the LLM and merge results into learnings."""
        with self._learnings_lock:
            current = dict(self.learnings)

        transcript = "\n".join(
            f"USER: {t['user']}\nASSISTANT: {t['tars']}" for t in turns[-15:]
        )[:4000]

        existing_blob = json.dumps(
            {k: v for k, v in current.items() if k != "last_updated"},
            indent=2, default=str)[:1500]

        prompt = [
            {"role": "system", "content": (
                "You are extracting a long-term user profile for a voice assistant. "
                "Update (do NOT replace) the existing profile based on the new transcript. "
                "Return ONLY valid JSON with these keys, all optional:\n"
                "  user_name (string|null)\n"
                "  preferences (array of short strings — communication preferences, lifestyle, tone)\n"
                "  frequent_topics (array of short strings)\n"
                "  capability_wishes (array of short strings — things the user repeatedly wishes the assistant could do)\n"
                "  communication_style (one short sentence)\n"
                "Rules:\n"
                "  - Merge intelligently with existing entries (deduplicate, keep best wording).\n"
                "  - At most 8 items per array. Trim oldest/weakest if over.\n"
                "  - If you have nothing new, echo the existing values.\n"
                "  - Output ONLY the JSON object. No markdown, no commentary."
            )},
            {"role": "user", "content":
                f"EXISTING PROFILE:\n{existing_blob}\n\n"
                f"NEW TRANSCRIPT:\n{transcript}"}
        ]

        try:
            raw = self.chat_fn(prompt)
        except Exception as e:
            self.log(f"[learner] chat error: {e}")
            return

        if not raw or raw.lower().startswith(("mimo api", "error", "i couldn")):
            return

        # Strip markdown fences if the model added them
        cleaned = raw.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            data = json.loads(cleaned)
        except Exception:
            # Try to grab the first {...} block
            m = re.search(r"\{.*\}", cleaned, re.S)
            if not m:
                self.log(f"[learner] could not parse model JSON: {cleaned[:120]}")
                return
            try:
                data = json.loads(m.group(0))
            except Exception as e:
                self.log(f"[learner] JSON parse failed: {e}")
                return

        if not isinstance(data, dict):
            return

        with self._learnings_lock:
            before = dict(self.learnings)
            for key in ("user_name", "communication_style"):
                v = data.get(key)
                if isinstance(v, str) and v.strip() and v.lower() not in ("null", "none"):
                    self.learnings[key] = v.strip()
            for key in ("preferences", "frequent_topics", "capability_wishes"):
                v = data.get(key)
                if isinstance(v, list):
                    cleaned_list = [str(x).strip() for x in v
                                    if isinstance(x, (str, int, float)) and str(x).strip()]
                    self.learnings[key] = cleaned_list[:8]
            self.learnings["last_updated"] = datetime.now().isoformat()
            after = dict(self.learnings)
            self._save()

        self._emit_profile_event(before, after)
        self.log(f"[learner] profile updated "
                 f"(name={self.learnings.get('user_name')!r}, "
                 f"prefs={len(self.learnings.get('preferences', []))}, "
                 f"wishes={len(self.learnings.get('capability_wishes', []))})")

    def _emit_profile_event(self, before: Dict[str, Any], after: Dict[str, Any]) -> None:
        style_changed = (
            (before.get("communication_style") or "")
            != (after.get("communication_style") or "")
        )
        new_preferences = self._new_items(before.get("preferences"), after.get("preferences"))
        new_wishes = self._new_items(before.get("capability_wishes"), after.get("capability_wishes"))
        if not (style_changed or new_preferences or new_wishes):
            return

        parts: List[str] = []
        if style_changed and after.get("communication_style"):
            parts.append(f"style={after['communication_style']}")
        if new_preferences:
            parts.append("new preferences=" + "; ".join(new_preferences[:3]))
        if new_wishes:
            parts.append("new capability wishes=" + "; ".join(new_wishes[:3]))
        content = "User profile/affective signal updated: " + " | ".join(parts)
        emit_safe(
            self.event_bus,
            self.log,
            "memory",
            "emotion_shift",
            content[:700],
            raw={
                "before": before,
                "after": after,
                "new_preferences": new_preferences,
                "new_capability_wishes": new_wishes,
            },
            salience=0.68 if style_changed else 0.58,
            uncertainty=0.35,
            valence=0.10,
            arousal=0.30,
            tags=["profile", "affective", "proactive_learner"],
            severity="info",
        )

    @staticmethod
    def _new_items(before: Any, after: Any) -> List[str]:
        before_set = {str(x).strip().lower() for x in (before or []) if str(x).strip()}
        out = []
        for item in after or []:
            text = str(item).strip()
            if text and text.lower() not in before_set:
                out.append(text)
        return out
