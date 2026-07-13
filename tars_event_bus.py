"""
TARS Cognitive Event Bus  (Phase 2.5B)
======================================

Shared nervous system. Every meaningful occurrence in the system becomes a
typed `CognitiveEvent` published here. Subscribers (workspace, memory,
inner voice, sleep, world model) react.

Design constraints (from PLAN.md / Phase 2.5):

  * Fail-soft. If the bus crashes, the voice loop must keep working.
  * Subscriber callbacks run synchronously on the publisher's thread by
    default but are wrapped in try/except so one bad subscriber never
    breaks publish().
  * Events are persisted to `tars_events.jsonl` (append-only). Survives
    restart. Old events can be tail-loaded for in-memory query.
  * Thread-safe via a single `RLock`.

NOT in scope here (later phases):
  * Cross-process bus
  * Replay / time-travel debugging
  * Backpressure (subscriber slow → drop policy) — current load is tiny
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional


EVENT_LOG_FILENAME = "tars_events.jsonl"
DEFAULT_TAIL_RETENTION = 2000          # in-memory ring buffer size

# Canonical sources / kinds — strings, not enums, so user/codex can extend
# without touching this file. We document the canonical set for grep-ability.
CANONICAL_SOURCES = (
    "user", "assistant", "inner_voice", "memory", "goal",
    "system", "sensor", "sleep", "skill", "self",
)
CANONICAL_KINDS = (
    "utterance", "thought", "memory_write", "memory_contradiction",
    "prediction_error", "goal_conflict", "goal_progress", "emotion_shift",
    "skill_result", "skill_failure", "sensor_change", "self_restore",
    "desire_candidate", "self_critique", "sleep_summary",
    "workspace_frame",
)


@dataclass
class CognitiveEvent:
    id: str
    ts: str
    source: str
    kind: str
    content: str = ""
    entities: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    salience: float = 0.0
    uncertainty: float = 0.0
    valence: float = 0.0
    arousal: float = 0.0
    tags: List[str] = field(default_factory=list)
    # Phase 2.5R-C: Throttling & severity
    severity: str = "info"  # "debug", "info", "important", "critical"
    candidate_eligible: bool = False
    reason_candidate_eligible: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def make(cls, source: str, kind: str, content: str = "",
             *, entities: Optional[List[str]] = None,
             raw: Optional[Dict[str, Any]] = None,
             salience: float = 0.0, uncertainty: float = 0.0,
             valence: float = 0.0, arousal: float = 0.0,
             tags: Optional[List[str]] = None,
             severity: str = "info") -> "CognitiveEvent":
        
        # Determine candidate eligibility
        eligible = False
        reason = None
        if severity in ("important", "critical"):
            eligible = True
            reason = f"severity_{severity}"
        elif uncertainty >= 0.7:
            eligible = True
            reason = "high_uncertainty"
        elif kind in ("user_correction", "prediction_error", "skill_failure", "memory_contradiction", "self_restore"):
            eligible = True
            reason = f"kind_requires_attention:{kind}"
            
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        eid = "evt_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") \
              + uuid.uuid4().hex[:6]
        return cls(
            id=eid, ts=ts, source=source, kind=kind, content=content,
            entities=list(entities or []),
            raw=dict(raw or {}),
            salience=float(salience), uncertainty=float(uncertainty),
            valence=float(valence), arousal=float(arousal),
            tags=list(tags or []),
            severity=severity,
            candidate_eligible=eligible,
            reason_candidate_eligible=reason
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CognitiveEvent":
        # Tolerate missing/extra keys for forward-compat with persisted logs.
        known = {f.name for f in dataclasses.fields(cls)}
        clean = {k: v for k, v in d.items() if k in known}
        clean.setdefault("entities", [])
        clean.setdefault("raw", {})
        clean.setdefault("tags", [])
        clean.setdefault("severity", "info")
        clean.setdefault("candidate_eligible", False)
        return cls(**clean)


# Subscriber callable signature: (event) -> None
SubscriberFn = Callable[[CognitiveEvent], None]


def emit_safe(event_bus: Optional["EventBus"], log_fn: Optional[Callable[[str], None]],
              source: str, kind: str, content: str = "", **kwargs) -> Optional[str]:
    """Fail-soft event helper for modules that should not depend on the bus."""
    if event_bus is None:
        return None
    try:
        return event_bus.emit(source, kind, content, **kwargs)
    except Exception as e:
        if log_fn is not None:
            try:
                log_fn(f"[event-bus] emit({source}, {kind}) failed: {e}")
            except Exception:
                pass
        return None


class EventBus:
    """Pub/sub + JSONL persistence + in-memory tail buffer."""

    def __init__(self, project_dir: str, log_fn: Optional[Callable[[str], None]] = None,
                 *, tail_retention: int = DEFAULT_TAIL_RETENTION,
                 persist: bool = True):
        self.project_dir = project_dir
        self.path = os.path.join(project_dir, EVENT_LOG_FILENAME)
        self._log = log_fn or (lambda *a, **k: None)
        self._persist = persist
        self._lock = threading.RLock()
        self._is_debug = os.getenv("TARS_DEBUG", "0") == "1"
        # Subscribers indexed by kind. Special key "*" = wildcard.
        self._subs: Dict[str, List[SubscriberFn]] = defaultdict(list)
        # Ring buffer of recent events for fast tail/since/high-salience queries
        self._tail: deque = deque(maxlen=int(tail_retention))
        # Hydrate the in-memory tail from the JSONL on disk so a restart
        # doesn't lose recent context.
        if persist:
            self._hydrate_tail()

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------
    def subscribe(self, kind: str, fn: SubscriberFn) -> None:
        """Register `fn` to be called for every event with this `kind`.
        Use `kind="*"` to subscribe to ALL events."""
        if not callable(fn):
            raise TypeError("subscriber must be callable")
        with self._lock:
            self._subs[kind].append(fn)

    def unsubscribe(self, kind: str, fn: SubscriberFn) -> bool:
        with self._lock:
            try:
                self._subs[kind].remove(fn)
                return True
            except (ValueError, KeyError):
                return False

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------
    def publish(self, event: CognitiveEvent) -> str:
        """Persist + dispatch synchronously. Subscriber failures are
        contained (logged, not raised) so one bad subscriber never breaks
        the bus."""
        
        # 2.5R-C Event Throttling: Skip storing debug events if not debugging
        if event.severity == "debug" and not self._is_debug:
            return event.id
            
        with self._lock:
            self._tail.append(event)
            if self._persist:
                self._append_jsonl(event)
            # Snapshot subscribers so we don't hold the lock during dispatch
            kind_subs = list(self._subs.get(event.kind, ()))
            wildcard_subs = list(self._subs.get("*", ()))

        for fn in kind_subs + wildcard_subs:
            try:
                fn(event)
            except Exception as e:
                self._log(f"[event-bus] subscriber {fn!r} for {event.kind!r} raised: {e}")

        return event.id

    def emit(self, source: str, kind: str, content: str = "", **kwargs) -> str:
        """Convenience: build an event from kwargs and publish in one call.
        Returns the event id."""
        return self.publish(CognitiveEvent.make(source, kind, content, **kwargs))

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def tail(self, n: int = 20) -> List[CognitiveEvent]:
        with self._lock:
            return list(self._tail)[-int(n):]

    def since(self, seconds: int) -> List[CognitiveEvent]:
        cutoff = time.time() - float(seconds)
        with self._lock:
            return [e for e in self._tail if self._ts_to_epoch(e.ts) >= cutoff]

    def high_salience(self, threshold: float = 0.7,
                      n: int = 50) -> List[CognitiveEvent]:
        with self._lock:
            results = [e for e in self._tail if e.salience >= float(threshold)]
        return results[-int(n):]

    def by_kind(self, kind: str, n: int = 50) -> List[CognitiveEvent]:
        with self._lock:
            results = [e for e in self._tail if e.kind == kind]
        return results[-int(n):]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _append_jsonl(self, event: CognitiveEvent) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), default=str) + "\n")
        except Exception as e:
            self._log(f"[event-bus] persist failed: {e}")

    def _hydrate_tail(self) -> None:
        if not os.path.exists(self.path):
            return
        retention = self._tail.maxlen or DEFAULT_TAIL_RETENTION
        recent: deque = deque(maxlen=retention)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        recent.append(CognitiveEvent.from_dict(json.loads(line)))
                    except Exception:
                        continue
        except Exception as e:
            self._log(f"[event-bus] hydrate failed: {e}")
            return
        with self._lock:
            self._tail.extend(recent)

    @staticmethod
    def _ts_to_epoch(ts: str) -> float:
        try:
            # Trim trailing 'Z' and parse
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return 0.0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        bus = EventBus(td, log_fn=lambda m: print("[log]", m))
        seen: List[str] = []
        bus.subscribe("utterance", lambda e: seen.append(("u", e.id)))
        bus.subscribe("*",         lambda e: seen.append(("*", e.id)))

        # Basic publish
        e1 = bus.emit("user", "utterance", "Hello there.",
                      entities=["TARS"], salience=0.9, valence=0.2, arousal=0.4)
        e2 = bus.emit("inner_voice", "thought", "I should be more concise.",
                      salience=0.3, uncertainty=0.4)

        assert any(t == ("u", e1) for t in seen), seen
        assert sum(1 for t in seen if t[0] == "*") == 2, seen

        # Misbehaving subscriber must NOT break the bus
        def bad(_e):
            raise RuntimeError("intentional")
        bus.subscribe("utterance", bad)
        e3 = bus.emit("user", "utterance", "Still working?", salience=0.95)
        assert any(t == ("u", e3) for t in seen)

        # Queries
        assert len(bus.tail(10)) >= 3
        assert any(e.salience >= 0.7 for e in bus.high_salience(0.7))
        assert all(e.kind == "thought" for e in bus.by_kind("thought"))

        # Persistence + hydrate on a fresh bus
        path = os.path.join(td, EVENT_LOG_FILENAME)
        assert os.path.exists(path)
        bus2 = EventBus(td)
        assert len(bus2.tail(10)) >= 3, "hydrate failed"
        ids_after_reload = [e.id for e in bus2.tail(10)]
        assert e1 in ids_after_reload, "lost first event after reload"

        # since() basic check
        s = bus.since(60)
        assert len(s) >= 3, s

        print("EVENT BUS SELF-TEST OK")
