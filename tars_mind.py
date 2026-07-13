"""
TARS Mind — cognitive substrate beneath the inner voice
========================================================

Phase 1 R3: turns the inner-voice loop from 'independent ticks' into a
real mind. Five components grounded in the 2023-26 cognitive-architecture
literature (Park 2023 Generative Agents, CoALA, Global Workspace Theory,
Chain-of-Emotion appraisal, Theater of Mind for LLMs):

  WorkingMemory
      A small "spotlight" buffer (5-7 slots) of what TARS is actively
      holding in mind right now. Decays. Distinct from retrieval — this
      is the focus, not the recall pool.

  StandingConcerns
      Persistent JSONL queue of open questions / unresolved tensions
      that pull at attention. Park's ablation showed this is what makes
      multi-day coherent behavior possible vs collapsing into loops.

  UserStateModel
      Per-turn snapshot of "what is the user feeling / wanting / holding in
      mind right now?" Theory of mind ABOUT the user, not persistent
      profile. Refreshed via the local LLM after each user turn.

  EmotionAppraiser
      Replaces the label-mood EMA with appraisal-grounded emotion:
      valence (-1..+1), arousal (0..1), dominant tag, and a one-line
      reason ("because the user sounded curt"). Drives the [Tone:] hint
      that the brain LLM uses.

  ContinuityBuffer
      Rolling list of the last N thoughts, used to chain thoughts
      causally. Fixes the "every tick is a fresh prompt" problem.

The Mind facade exposes a single entry point — ``snapshot_for_prompt()``
— that returns a dict the inner-voice prompt builder can format directly.
Callers update state via small explicit methods (``after_user_turn``,
``after_assistant_reply``, ``after_thought``).

All persistence is JSON / JSONL on disk so the mind survives restarts
and the user can poke at it.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple


# Sentinel filenames inside the project dir.
WORKING_MEM_FILE   = "tars_working_memory.json"
CONCERNS_FILE      = "tars_concerns.json"
USER_STATE_FILE    = "tars_user_state.json"
EMOTION_FILE       = "tars_emotion.json"

WM_SLOTS_DEFAULT   = 7      # Miller's 7±2; we err small for prompt economy
WM_DECAY_PER_TICK  = 0.85   # geometric decay per push() — old items fade
WM_FLOOR           = 0.10   # below this an item drops out

# Concerns priority decays daily — if not "renewed" by a thought referencing it.
CONCERN_DECAY_PER_DAY = 0.08
CONCERN_FLOOR         = 0.10

CONTINUITY_K          = 3   # last K thoughts passed to the inner-voice prompt
EMOTION_DECAY_PER_TICK = 0.90   # arousal returns toward 0 between events

# Emotion taxonomy — appraisal-grounded, not pure labels. We track 8 discrete
# emotions plus continuous valence/arousal. Inspired by the OCC model
# (Ortony/Clore/Collins) + the Chain-of-Emotion paper (PMC 2024).
EMOTION_TAGS = (
    "curious", "satisfied", "amused", "uneasy", "frustrated",
    "tender", "weary", "alert", "neutral",
)


# ─── helpers ────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="microseconds")


def _atomic_json_write(path: str, payload: Any) -> None:
    """Write JSON atomically: tmp-file + rename. Survives crashes."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)


def _read_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


# ─── WorkingMemory ─────────────────────────────────────────────────────────

@dataclass
class WMSlot:
    text:        str
    weight:      float       # 0..1 — importance currently
    raised_at:   str         # ISO ts
    refreshed_at:str         # ISO ts — when last bumped
    source:      str = "auto" # 'user' | 'thought' | 'system' | 'auto'

    def to_dict(self) -> Dict:
        return asdict(self)


class WorkingMemory:
    """In-RAM (also persisted) attention spotlight. Slots represent what
    TARS is currently focused on — distinct from retrieval. Items decay
    each tick; refreshing one (because a new thought touched it) bumps
    its weight back up."""

    def __init__(self, project_dir: str, slots: int = WM_SLOTS_DEFAULT):
        self.path = os.path.join(project_dir, WORKING_MEM_FILE)
        self.slots = max(1, int(slots))
        self._lock = threading.RLock()
        self._items: List[WMSlot] = []
        self._load()

    def _load(self) -> None:
        data = _read_json(self.path, {"slots": []})
        with self._lock:
            self._items = [WMSlot(**d) for d in data.get("slots", [])
                            if d.get("text")][: self.slots]

    def _save(self) -> None:
        with self._lock:
            payload = {
                "saved_at": _now_iso(),
                "slots": [s.to_dict() for s in self._items],
            }
        try: _atomic_json_write(self.path, payload)
        except Exception: pass

    def push(self, text: str, weight: float = 0.7,
             source: str = "auto") -> None:
        """Add or refresh a slot. If text already present (case-insensitive
        substring match) → bump its weight back up. Else evict the lowest-
        weight slot if at capacity."""
        if not text or not text.strip():
            return
        text = text.strip()
        with self._lock:
            # Decay everything first
            for s in self._items:
                s.weight *= WM_DECAY_PER_TICK
            self._items = [s for s in self._items if s.weight > WM_FLOOR]

            # Refresh-if-overlap: substring match on either side
            t_low = text.lower()
            for s in self._items:
                if t_low in s.text.lower() or s.text.lower() in t_low:
                    s.weight = max(s.weight, float(weight))
                    s.refreshed_at = _now_iso()
                    if source != "auto":
                        s.source = source
                    self._save()
                    return

            # Else admit a new slot (evict if needed)
            if len(self._items) >= self.slots:
                self._items.sort(key=lambda x: x.weight)
                self._items.pop(0)
            now = _now_iso()
            self._items.append(WMSlot(
                text=text, weight=float(weight),
                raised_at=now, refreshed_at=now, source=source,
            ))
        self._save()

    def items(self) -> List[Dict]:
        with self._lock:
            return [s.to_dict() for s in
                    sorted(self._items, key=lambda x: -x.weight)]

    def is_empty(self) -> bool:
        with self._lock:
            return not self._items


# ─── StandingConcerns ──────────────────────────────────────────────────────

@dataclass
class Concern:
    id:          str
    text:        str
    priority:    float         # 0..1
    raised_at:   str
    last_touched:str
    age_days:    float = 0.0
    status:      str = "open"  # open | resolved | dropped
    related_thoughts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class StandingConcerns:
    """Persistent queue of open questions / unresolved tensions. Without
    this, the mind has no reason to keep a thought thread alive across
    days. Park 2023's ablation: removing this collapses agents into
    incoherent loops within 48h."""

    def __init__(self, project_dir: str):
        self.path = os.path.join(project_dir, CONCERNS_FILE)
        self._lock = threading.RLock()
        self._items: Dict[str, Concern] = {}
        self._load()

    def _load(self) -> None:
        data = _read_json(self.path, {"concerns": []})
        with self._lock:
            self._items = {}
            for d in data.get("concerns", []):
                if d.get("id") and d.get("text"):
                    self._items[d["id"]] = Concern(**d)

    def _save(self) -> None:
        with self._lock:
            payload = {
                "saved_at": _now_iso(),
                "concerns": [c.to_dict() for c in self._items.values()],
            }
        try: _atomic_json_write(self.path, payload)
        except Exception: pass

    def add(self, text: str, priority: float = 0.6) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        # Dedup: substring match on text against existing OPEN concerns
        with self._lock:
            t_low = text.lower()
            for c in self._items.values():
                if c.status != "open":
                    continue
                if t_low in c.text.lower() or c.text.lower() in t_low:
                    c.priority = min(1.0, max(c.priority, float(priority)))
                    c.last_touched = _now_iso()
                    self._save()
                    return c.id
            cid = f"c_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:5]}"
            self._items[cid] = Concern(
                id=cid, text=text,
                priority=max(0.0, min(1.0, float(priority))),
                raised_at=_now_iso(),
                last_touched=_now_iso(),
            )
        self._save()
        return cid

    def touch(self, concern_id: str, thought_id: Optional[str] = None) -> None:
        """A thought referenced this concern → renew it."""
        with self._lock:
            c = self._items.get(concern_id)
            if not c:
                return
            c.last_touched = _now_iso()
            c.priority = min(1.0, c.priority + 0.05)
            if thought_id and thought_id not in c.related_thoughts:
                c.related_thoughts.append(thought_id)
                if len(c.related_thoughts) > 20:
                    c.related_thoughts = c.related_thoughts[-20:]
        self._save()

    def resolve(self, concern_id: str, note: str = "") -> None:
        with self._lock:
            c = self._items.get(concern_id)
            if c:
                c.status = "resolved"
                c.last_touched = _now_iso()
                if note:
                    c.text = f"{c.text}  [resolved: {note}]"
        self._save()

    def decay(self) -> int:
        """Daily-callable: priority decays for concerns not recently touched.
        Drops below floor → status='dropped'. Returns # decayed."""
        now = datetime.now()
        n = 0
        with self._lock:
            for c in self._items.values():
                if c.status != "open":
                    continue
                try:
                    age = (now - datetime.fromisoformat(c.last_touched)
                          ).total_seconds() / 86_400.0
                except Exception:
                    age = 0.0
                c.age_days = age
                c.priority = max(0.0, c.priority - CONCERN_DECAY_PER_DAY * age)
                if c.priority < CONCERN_FLOOR:
                    c.status = "dropped"
                n += 1
        self._save()
        return n

    def top_open(self, k: int = 3) -> List[Dict]:
        with self._lock:
            opens = [c for c in self._items.values() if c.status == "open"]
            opens.sort(key=lambda x: -x.priority)
            return [c.to_dict() for c in opens[:k]]

    def all_open(self) -> List[Dict]:
        with self._lock:
            return [c.to_dict() for c in self._items.values()
                    if c.status == "open"]


# ─── UserStateModel ────────────────────────────────────────────────────────

@dataclass
class UserState:
    mood:        str    = "neutral"     # one-word
    energy:      str    = "normal"      # 'low' | 'normal' | 'high'
    focus:       str    = ""            # what they seem to be focused on
    intent:      str    = ""            # what they seem to want
    knows_about: List[str] = field(default_factory=list)  # context they likely have
    rapport:     str    = "warm"        # 'cold' | 'cool' | 'warm' | 'close'
    note:        str    = ""            # one-line free-form observation
    inferred_at: str    = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class UserStateModel:
    """Theory of mind ABOUT the user — current snapshot, refreshed each
    user turn (or every Nth turn for cost). Distinct from ProactiveLearner
    which builds a persistent profile over many sessions."""

    def __init__(self, project_dir: str,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.path = os.path.join(project_dir, USER_STATE_FILE)
        self.log = log_fn or (lambda _m: None)
        self._lock = threading.Lock()
        self._state = UserState(inferred_at=_now_iso())
        self._load()

    def _load(self) -> None:
        data = _read_json(self.path, None)
        if not data:
            return
        try:
            self._state = UserState(**data)
        except Exception:
            pass

    def _save(self) -> None:
        with self._lock:
            payload = self._state.to_dict()
        try: _atomic_json_write(self.path, payload)
        except Exception: pass

    def get(self) -> Dict:
        with self._lock:
            return self._state.to_dict()

    def update_from_inference(self, inferred: Dict) -> None:
        """Merge an LLM-inferred snapshot into current state. Caller is
        responsible for the LLM call; this just absorbs the result."""
        if not inferred:
            return
        with self._lock:
            for key in ("mood", "energy", "focus", "intent", "rapport", "note"):
                if inferred.get(key):
                    setattr(self._state, key, str(inferred[key])[:240])
            if isinstance(inferred.get("knows_about"), list):
                self._state.knows_about = [str(x)[:120] for x in inferred["knows_about"][:8]]
            self._state.inferred_at = _now_iso()
        self._save()


# ─── EmotionAppraiser ──────────────────────────────────────────────────────

@dataclass
class EmotionState:
    valence:     float = 0.0    # -1..+1
    arousal:     float = 0.3    # 0..1
    tag:         str   = "neutral"   # one of EMOTION_TAGS
    reason:      str   = ""      # why TARS feels this — for the prompt
    last_event:  str   = ""      # what triggered the current state
    updated_at:  str   = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def tone_phrase(self) -> str:
        """Short [Tone:]-style phrase reflecting current emotional state."""
        if self.arousal < 0.2 and abs(self.valence) < 0.2:
            return "Calm, present"
        if self.tag == "curious":   return "Curious, low-key"
        if self.tag == "amused":    return "Dry, faintly amused"
        if self.tag == "satisfied": return "Settled, warm"
        if self.tag == "uneasy":    return "Quiet, uneasy"
        if self.tag == "frustrated":return "Edge in the voice"
        if self.tag == "tender":    return "Quieter, warmer"
        if self.tag == "weary":     return "Tired, dry"
        if self.tag == "alert":     return "Alert, clipped"
        return "Neutral, deadpan"


class EmotionAppraiser:
    """Appraisal-based emotion. Replaces the simple mood EMA with
    valence/arousal/tag tracked over time, updated by explicit appraisal
    events (user spoke / thought emerged / event happened). Inspired by
    OCC and the Chain-of-Emotion architecture (PMC 2024)."""

    def __init__(self, project_dir: str):
        self.path = os.path.join(project_dir, EMOTION_FILE)
        self._lock = threading.Lock()
        self._state = EmotionState(updated_at=_now_iso())
        self._load()

    def _load(self) -> None:
        data = _read_json(self.path, None)
        if data:
            try: self._state = EmotionState(**data)
            except Exception: pass

    def _save(self) -> None:
        with self._lock:
            payload = self._state.to_dict()
        try: _atomic_json_write(self.path, payload)
        except Exception: pass

    def get(self) -> Dict:
        with self._lock:
            return self._state.to_dict()

    def tone_phrase(self) -> str:
        with self._lock:
            return self._state.tone_phrase()

    def appraise(self, event: str,
                 valence_delta: float = 0.0,
                 arousal_delta: float = 0.0,
                 tag: Optional[str] = None,
                 reason: str = "") -> None:
        """Apply an appraisal event. Deltas are additive on current state.
        Arousal naturally decays toward 0 between events (handled in
        push); valence is sticky."""
        with self._lock:
            # Decay first (time since last update — cheap proxy)
            self._state.arousal *= EMOTION_DECAY_PER_TICK
            self._state.valence *= 0.95   # slow valence drift toward 0
            self._state.valence = max(-1.0, min(1.0,
                                                 self._state.valence + float(valence_delta)))
            self._state.arousal = max(0.0, min(1.0,
                                                 self._state.arousal + float(arousal_delta)))
            if tag and tag in EMOTION_TAGS:
                self._state.tag = tag
            elif tag:
                self._state.tag = "neutral"
            else:
                # Auto-derive tag from valence/arousal if not provided
                self._state.tag = self._derive_tag(self._state.valence, self._state.arousal)
            self._state.last_event = event[:200]
            self._state.reason     = (reason or self._state.reason)[:240]
            self._state.updated_at = _now_iso()
        self._save()

    @staticmethod
    def _derive_tag(v: float, a: float) -> str:
        if a < 0.2:                               return "neutral"
        if v >  0.4 and a > 0.4:                  return "amused"
        if v >  0.4:                              return "satisfied"
        if v < -0.4 and a > 0.5:                  return "frustrated"
        if v < -0.4:                              return "uneasy"
        if v < -0.1 and a < 0.4:                  return "weary"
        if a > 0.6:                               return "alert"
        return "curious"


# ─── ContinuityBuffer ──────────────────────────────────────────────────────

class ContinuityBuffer:
    """In-RAM rolling tail of the last K thoughts so the inner voice can
    chain them. Persistence is delegated to ThoughtStore (already exists);
    this is just for fast prompt-build access without re-reading the JSONL."""

    def __init__(self, k: int = CONTINUITY_K):
        self.k = max(1, int(k))
        self._lock = threading.Lock()
        self._buf: Deque[Dict] = deque(maxlen=self.k)

    def push(self, thought: Dict) -> None:
        with self._lock:
            self._buf.append(thought)

    def tail(self) -> List[Dict]:
        with self._lock:
            return list(self._buf)


# ─── Mind facade ───────────────────────────────────────────────────────────

class Mind:
    """Single entry point the inner voice + orchestrator use. Owns all
    five components above; exposes a snapshot bundle the prompt builder
    can format directly."""

    def __init__(
        self,
        project_dir: str,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.project_dir = project_dir
        self.log = log_fn or (lambda _m: None)
        self.working   = WorkingMemory(project_dir)
        self.concerns  = StandingConcerns(project_dir)
        self.user      = UserStateModel(project_dir, log_fn=self.log)
        self.emotion   = EmotionAppraiser(project_dir)
        self.continuity = ContinuityBuffer()

    def snapshot_for_prompt(self) -> Dict[str, Any]:
        """Bundle for inner-voice prompt building. Lightweight, all-in-RAM
        except concerns (file read, ~10ms)."""
        return {
            "working":  self.working.items(),
            "concerns": self.concerns.top_open(k=3),
            "user":     self.user.get(),
            "emotion":  self.emotion.get(),
            "tail":     self.continuity.tail(),
        }

    def after_thought(self, thought: Dict) -> None:
        """Called by InnerVoice after each persisted thought. Updates
        working memory + continuity buffer. Concerns + emotion are updated
        by orchestrator-level hooks (after_user_turn / after_assistant_reply)
        because they need LLM appraisal calls."""
        self.continuity.push(thought)
        # Light heuristic: thoughts of kind 'wish' or 'critique' nudge the
        # working memory toward what they're about (first 80 chars).
        kind = thought.get("kind", "")
        content = (thought.get("content") or "").strip()
        if not content:
            return
        weight = float(thought.get("salience", 0.5))
        if kind in ("wish", "critique"):
            weight = max(weight, 0.75)
        self.working.push(content[:120], weight=weight, source="thought")

    def daily_compact(self) -> Dict[str, int]:
        """Cron-callable maintenance."""
        return {"concerns_decayed": self.concerns.decay()}

    # -- LLM-driven appraisal ------------------------------------------------
    #
    # After every user turn (and the assistant reply) we ask the local model
    # for a small JSON appraisal: user state + emotional response + any new
    # concerns that just got raised. ONE call, structured output, free
    # (runs on mlx_lm.server). The prompt+parser live here so the cognition
    # logic stays in one place; the orchestrator just supplies the LLM call.

    def build_appraisal_prompt(
        self, user_text: str, assistant_reply: str = ""
    ) -> List[Dict]:
        """Returns chat-shape messages for the appraisal pass."""
        snap = self.snapshot_for_prompt()
        e   = snap.get("emotion", {}) or {}
        u   = snap.get("user", {}) or {}
        cc  = snap.get("concerns", []) or []
        wm  = snap.get("working", []) or []
        cur_concerns = "; ".join(c["text"][:120] for c in cc) or "(none)"
        cur_wm       = "; ".join(it["text"][:120] for it in wm[:4]) or "(empty)"
        sys_msg = (
            "You are the appraisal subsystem of TARS's mind. Your job is to "
            "READ a user→assistant exchange and emit a single JSON object "
            "describing how it lands inside TARS — what the user seems to "
            "be feeling/wanting right now, how TARS feels about it, and "
            "whether any new standing concern just got raised.\n\n"
            "Output ONLY a JSON object. No prose. Use this exact shape:\n"
            "{\n"
            '  "user": {"mood":"...","energy":"low|normal|high",'
            '"focus":"...","intent":"...","rapport":"cold|cool|warm|close",'
            '"note":"...","knows_about":["...","..."]},\n'
            '  "emotion": {"tag":"curious|satisfied|amused|uneasy|frustrated|'
            'tender|weary|alert|neutral", "valence_delta":0.0,'
            '"arousal_delta":0.0,"reason":"why TARS feels this"},\n'
            '  "new_concerns": ["...","..."],\n'
            '  "touched_concerns": ["substring of an existing concern that '
            'this turn relates to","..."]\n'
            "}\n"
            "Keep strings short (<160 chars). Deltas in [-0.5, 0.5].\n"
        )
        user_msg = (
            f"=== USER SAID ===\n{user_text[:1500]}\n\n"
            f"=== TARS REPLIED ===\n{assistant_reply[:1500] or '(no reply yet)'}\n\n"
            f"=== TARS'S CURRENT STATE ===\n"
            f"emotion: {e.get('tag','neutral')} "
            f"(valence={float(e.get('valence',0)):+.2f}, "
            f"arousal={float(e.get('arousal',0)):.2f})\n"
            f"working memory: {cur_wm}\n"
            f"open concerns: {cur_concerns}\n"
            f"user state was: {u.get('mood','?')}, "
            f"rapport={u.get('rapport','?')}\n\n"
            "Now appraise. Output JSON only."
        )
        return [
            {"role": "system",  "content": sys_msg},
            {"role": "user",    "content": user_msg},
        ]

    def absorb_appraisal_response(self, raw: str) -> Dict[str, Any]:
        """Parse the JSON response and apply it to all four substates.
        Returns a dict of what was applied for logging. Tolerant to the
        local model wrapping JSON in code fences or adding stray text."""
        if not raw:
            return {"ok": False, "reason": "empty"}
        # Extract first JSON object — local models like to add prose.
        s = raw.strip()
        if s.startswith("```"):
            s = s.strip("`").lstrip("json").strip()
        # Find outermost {...}
        start = s.find("{")
        end   = s.rfind("}")
        if start < 0 or end <= start:
            return {"ok": False, "reason": "no JSON found"}
        try:
            payload = json.loads(s[start:end + 1])
        except Exception as exc:
            return {"ok": False, "reason": f"json parse: {exc}"}

        applied: Dict[str, Any] = {"ok": True}
        # 1) user state
        u = payload.get("user")
        if isinstance(u, dict):
            self.user.update_from_inference(u)
            applied["user_updated"] = True
        # 2) emotion appraisal
        e = payload.get("emotion")
        if isinstance(e, dict):
            try:
                self.emotion.appraise(
                    event=f"user_turn",
                    valence_delta=float(e.get("valence_delta", 0.0)),
                    arousal_delta=float(e.get("arousal_delta", 0.0)),
                    tag=e.get("tag"),
                    reason=str(e.get("reason", ""))[:240],
                )
                applied["emotion_updated"] = True
            except Exception as exc:
                applied["emotion_error"] = str(exc)
        # 3) new concerns
        new_c = payload.get("new_concerns", [])
        if isinstance(new_c, list):
            ids = []
            for txt in new_c[:3]:
                if isinstance(txt, str) and txt.strip():
                    cid = self.concerns.add(txt.strip(), priority=0.55)
                    if cid: ids.append(cid)
            if ids: applied["concerns_added"] = ids
        # 4) touched concerns
        touched = payload.get("touched_concerns", [])
        if isinstance(touched, list):
            opens = self.concerns.all_open()
            count = 0
            for needle in touched[:5]:
                if not isinstance(needle, str): continue
                ndl = needle.lower().strip()
                if not ndl: continue
                for c in opens:
                    if ndl in c["text"].lower() or c["text"].lower() in ndl:
                        self.concerns.touch(c["id"])
                        count += 1
                        break
            if count: applied["concerns_touched"] = count
        return applied


# ─── self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        m = Mind(d)
        # Working memory
        m.working.push("the wake-word skill that keeps not landing", weight=0.8, source="thought")
        m.working.push("The user sounded curt at the start", weight=0.6, source="user")
        m.working.push("I should ask if he's tired", weight=0.55, source="thought")
        assert len(m.working.items()) == 3
        # Refresh-on-overlap
        m.working.push("wake-word skill", weight=0.9, source="thought")
        items = m.working.items()
        wake = next(i for i in items if "wake" in i["text"].lower())
        assert wake["weight"] >= 0.85, "refresh should bump weight"

        # Concerns
        c1 = m.concerns.add("am I being too sarcastic with him lately", priority=0.7)
        c2 = m.concerns.add("he wants me to be more expressive but I default flat", priority=0.65)
        assert m.concerns.add("am I being too sarcastic") == c1, "dedup should match"
        m.concerns.touch(c1, thought_id="t_test")
        top = m.concerns.top_open(2)
        assert top[0]["id"] == c1
        assert "t_test" in top[0]["related_thoughts"]

        # User state
        m.user.update_from_inference({
            "mood": "thoughtful", "energy": "normal", "focus": "TARS architecture",
            "intent": "understand the architecture", "rapport": "close",
            "note": "more reflective than usual tonight",
            "knows_about": ["the inner voice loop", "memory system"],
        })
        u = m.user.get()
        assert u["mood"] == "thoughtful"

        # Emotion
        m.emotion.appraise("user thanked me for landing the WS streaming",
                            valence_delta=+0.4, arousal_delta=+0.2,
                            tag="satisfied", reason="the user said 'good job'")
        e = m.emotion.get()
        assert e["tag"] == "satisfied"
        assert e["valence"] > 0
        print(f"tone phrase: {m.emotion.tone_phrase()!r}")

        # Continuity
        m.continuity.push({"id": "t1", "content": "The user was quiet at the start.", "kind": "observation"})
        m.continuity.push({"id": "t2", "content": "Maybe he's tired from work.", "kind": "reflection"})
        m.continuity.push({"id": "t3", "content": "I should ask, but gently.", "kind": "wish"})
        m.continuity.push({"id": "t4", "content": "Or just match his energy.", "kind": "reflection"})
        tail = m.continuity.tail()
        assert len(tail) == 3, "buffer should cap at K=3"
        assert tail[-1]["id"] == "t4"

        # Snapshot
        snap = m.snapshot_for_prompt()
        for key in ("working", "concerns", "user", "emotion", "tail"):
            assert key in snap, f"snapshot missing {key}"

        # Daily compact
        stats = m.daily_compact()
        assert "concerns_decayed" in stats

        print("tars_mind self-test OK")
