"""
TARS Global Workspace  (Phase 2.5D)
====================================

The global-access layer. It is a functional attention/workspace mechanism,
not a claim about phenomenal consciousness. It tracks:

    "What is globally available to the whole mind right now?"

Per PLAN.md §7. Workspace candidates come from many sources (memory,
inner voice, goals, user state, emotion, system, sensors). Each cycle
the workspace SCORES them, picks one WINNER, and BROADCASTS that winner
to subscribers (memory, world model, self model, inner voice, goals).

This module does:
  * `Candidate` and `WorkspaceFrame` schemas (PLAN.md §7)
  * `Workspace.cycle(candidates) -> WorkspaceFrame` — score + select + log
  * Suppression rules: low-confidence-high-risk, quiet hours, user
    currently speaking, quarantined module, duplicate-of-recent-winner
  * Broadcast: publishes a `workspace_frame` event on the EventBus that
    other subsystems subscribe to (no direct method calls — keeps the
    workspace decoupled)
  * JSONL persistence (`tars_workspace.jsonl`)

This module is FAIL-SOFT: if scoring or broadcast fails, `cycle()` still
returns a frame (possibly with `winner=None` and reason=…). It never
raises into the voice loop.

NOT in scope here (deferred to orchestrator wiring):
  * Actually gathering candidates from the live system. The wiring step
    in `mimo_apple_realtime_assistant.py` will assemble them. This
    module just consumes whatever it's given.
  * Actually executing the proposed action. Action selection lives in
    Phase 5 (Will & Goals). For now the workspace just RECORDS the
    proposed_action and broadcasts; the orchestrator decides what to do.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# Soft imports — module is usable without these, but normally ships with both.
try:
    from tars_event_bus import EventBus, CognitiveEvent  # type: ignore
except Exception:  # pragma: no cover
    EventBus = None  # type: ignore
    CognitiveEvent = None  # type: ignore

try:
    from tars_appraisal import Appraisal, Appraiser  # type: ignore
except Exception:  # pragma: no cover
    Appraisal = None  # type: ignore
    Appraiser = None  # type: ignore


WORKSPACE_LOG_FILENAME = "tars_workspace.jsonl"
DEFAULT_RECENT_WINNERS_KEEP = 20

# Canonical broadcast targets (informational only — actual subscribers
# live on the EventBus and pick up `kind="workspace_frame"` events).
DEFAULT_BROADCAST_TARGETS = (
    "inner_voice", "memory", "world_model", "self_model",
    "goals", "emotion",
)

CANONICAL_PROPOSED_ACTIONS = (
    "store", "think", "speak", "ask", "wait", "build", "sleep", "suppress",
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """A workspace candidate — one item competing for global attention."""
    id: str
    source: str                 # memory|inner_voice|goal|user_state|emotion|system|sensor
    content: str
    salience: float = 0.0
    novelty: float = 0.0
    uncertainty: float = 0.0
    goal_tension: float = 0.0
    urgency: float = 0.0
    valence: float = 0.0
    confidence: float = 0.5     # how reliable the source is
    risk: float = 0.0           # how risky acting on this would be
    evidence: List[str] = field(default_factory=list)   # event_ids / memory_ids
    proposed_action: str = "wait"
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def make(cls, source: str, content: str, **kwargs) -> "Candidate":
        cid = "cand_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
        return cls(id=cid, source=source, content=content, **kwargs)


@dataclass
class WorkspaceFrame:
    id: str
    ts: str
    cycle: int
    candidates: List[Dict[str, Any]]
    winner: Optional[Dict[str, Any]]
    reason_selected: str
    broadcast_to: List[str]
    result: str = "deferred"          # acted | stored | waited | asked | deferred | suppressed
    suppression_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def compact_winner(winner: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 2.5R-D: Returns a tight summary of the winner for the prompt."""
    if not winner: return {}
    # We strip out massive raw evidence blobs and just keep the vital signs
    appraisal = winner.get("extra", {}).get("appraisal", {})
    return {
        "source": winner.get("source", "unknown"),
        "proposed_action": winner.get("proposed_action", "think"),
        "content": winner.get("content", "")[:300], # Hard cap on content length
        "score": winner.get("extra", {}).get("score", 0.0),
        "salience": winner.get("salience", 0.0),
        "appraisal": appraisal
    }


# ---------------------------------------------------------------------------
# Selection rule (PLAN.md §7)
# ---------------------------------------------------------------------------

def score_candidate(c: Candidate) -> float:
    """The §7 selection-rule formula:
        0.30·salience + 0.20·uncertainty + 0.20·goal_tension
      + 0.15·novelty + 0.10·urgency + 0.05·|valence|
    """
    return (
        0.30 * _clamp01(c.salience) +
        0.20 * _clamp01(c.uncertainty) +
        0.20 * _clamp01(c.goal_tension) +
        0.15 * _clamp01(c.novelty) +
        0.10 * _clamp01(c.urgency) +
        0.05 * min(1.0, abs(c.valence))
    )


def _clamp01(x: float) -> float:
    try:
        x = float(x)
    except Exception:
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# ---------------------------------------------------------------------------
# Suppression context — what the workspace needs to know to gate output
# ---------------------------------------------------------------------------

@dataclass
class SuppressionContext:
    """Snapshot of conditions the workspace consults before broadcasting."""
    user_speaking: bool = False        # mid-utterance — never speak over
    quiet_hours: bool = False          # user has signalled no unsolicited speech
    high_risk_floor: float = 0.6       # candidates with risk >= this need confidence >= floor
    confidence_floor_for_risk: float = 0.7
    quarantined_sources: Iterable[str] = ()


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------

class Workspace:
    """One workspace per process. Holds cycle counter + recent-winners memory."""

    def __init__(self, project_dir: str,
                 event_bus: Optional["EventBus"] = None,
                 log_fn: Optional[Callable[[str], None]] = None,
                 *, broadcast_targets: Iterable[str] = DEFAULT_BROADCAST_TARGETS,
                 recent_winners_keep: int = DEFAULT_RECENT_WINNERS_KEEP,
                 persist: bool = True):
        self.project_dir = project_dir
        self.path = os.path.join(project_dir, WORKSPACE_LOG_FILENAME)
        self.event_bus = event_bus
        self._log = log_fn or (lambda *a, **k: None)
        self._broadcast_targets = tuple(broadcast_targets)
        self._persist = persist
        self._lock = threading.RLock()
        self._cycle = 0
        # Phase 2.5R-D: Recent winners by content for time-based duplicate suppression
        self._recent_winners: List[Tuple[float, str]] = []   # (ts_epoch, content)
        self._recent_winners_keep = int(recent_winners_keep)
        # Mind-perfection 1.1.b: per-source recent-wins tracker. Caps source
        # dominance so internal-cognition loops (world-model prediction errors,
        # inner-voice rumination) can't monopolize attention. Hard rule: a
        # source that won 3 of the last 5 cycles is penalized hard until a
        # different source wins. User input is NEVER throttled.
        self._recent_winner_sources: List[str] = []         # last N sources
        self._source_window = 5
        self._source_dominance_threshold = 3
        self._source_penalty = 0.40                          # subtracted from score

    # ------------------------------------------------------------------
    # Main entry — score + select + (maybe) broadcast
    # ------------------------------------------------------------------
    def cycle(self, candidates: List[Candidate],
              suppression: Optional[SuppressionContext] = None) -> WorkspaceFrame:
        """Run one workspace cycle. Always returns a frame (winner may be None)."""
        with self._lock:
            self._cycle += 1
            cycle_no = self._cycle

        suppression = suppression or SuppressionContext()
        cands = list(candidates or [])

        # 1. Score every candidate (informational — stored in extra)
        # Mind-perfection 1.1.b: penalize candidates whose source has been
        # winning too often. The user is the genuine external stimulus —
        # internal cognition (world, inner_voice) shouldn't drown it out.
        with self._lock:
            recent_sources = list(self._recent_winner_sources)
        # Find sources that already exceed the dominance threshold
        from collections import Counter as _Counter
        source_counts = _Counter(recent_sources)
        # 'user' is a sacred source — never throttled. Other sources get penalized
        # if they've won >= threshold of the last `_source_window` cycles.
        dominating_sources = {
            s for s, n in source_counts.items()
            if s != "user" and n >= self._source_dominance_threshold
        }
        # Whether ANY user candidate is in this batch — if so, internal
        # cognition gets an extra penalty so external input takes priority.
        has_user_candidate = any(c.source == "user" for c in cands)

        for c in cands:
            try:
                base = score_candidate(c)
                penalty = 0.0
                if c.source in dominating_sources:
                    penalty += self._source_penalty
                # When the user is present, downweight purely internal sources
                if has_user_candidate and c.source in {"world", "inner_voice", "system"}:
                    penalty += 0.20
                c.extra["score"]    = max(0.0, base - penalty)
                c.extra["score_raw"] = base
                if penalty > 0:
                    c.extra["score_penalty"] = penalty
            except Exception as e:
                self._log(f"[workspace] scoring error for {c.id}: {e}")
                c.extra["score"] = 0.0

        # 2. Select highest-scoring candidate that survives suppression
        winner: Optional[Candidate] = None
        reason = "no_candidates"
        suppression_reason: Optional[str] = None

        cands_sorted = sorted(cands, key=lambda x: x.extra.get("score", 0.0), reverse=True)

        for c in cands_sorted:
            ok, why = self._suppression_check(c, suppression)
            if ok:
                winner = c
                reason = f"highest_score={c.extra.get('score', 0.0):.3f} {c.source}/{c.proposed_action}"
                break
            else:
                # Mark suppression on the candidate for the frame log
                c.extra.setdefault("suppression_reason", why)
                if suppression_reason is None:
                    suppression_reason = why

        if not cands:
            reason = "no_candidates"
        elif winner is None:
            reason = f"all_suppressed: {suppression_reason or 'unknown'}"

        # 3. Build frame
        frame = WorkspaceFrame(
            id="ws_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6],
            ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            cycle=cycle_no,
            candidates=[c.to_dict() for c in cands],
            winner=winner.to_dict() if winner else None,
            reason_selected=reason,
            broadcast_to=list(self._broadcast_targets) if winner else [],
            result="acted" if winner else "suppressed",
            suppression_reason=suppression_reason if winner is None else None,
        )

        # 4. Persist + remember winner
        if self._persist:
            self._append_jsonl(frame)
        if winner is not None:
            self._remember_winner(winner)

        # 5. Broadcast on the event bus (subscribers act on it)
        if winner is not None and self.event_bus is not None and CognitiveEvent is not None:
            try:
                self.event_bus.publish(CognitiveEvent.make(
                    source="system",
                    kind="workspace_frame",
                    content=str(winner.content)[:500],
                    raw={"frame": frame.to_dict(),
                         "winner": winner.to_dict(),
                         "broadcast_to": list(self._broadcast_targets)},
                    salience=float(winner.salience),
                    valence=float(winner.valence),
                    tags=["workspace", winner.source],
                ))
            except Exception as e:
                self._log(f"[workspace] broadcast failed: {e}")

        return frame

    # ------------------------------------------------------------------
    # Suppression
    # ------------------------------------------------------------------
    def _suppression_check(self, c: Candidate,
                           ctx: SuppressionContext) -> Tuple[bool, str]:
        """Return (allow_to_win, reason_if_blocked)."""
        # 1. Quarantined source
        if c.source in (ctx.quarantined_sources or ()):
            return False, f"source_quarantined:{c.source}"

        # 2. User is speaking — never broadcast unsolicited speech
        if ctx.user_speaking and c.proposed_action in ("speak", "ask"):
            return False, "user_is_speaking"

        # 3. Quiet hours — block unsolicited speech
        if ctx.quiet_hours and c.proposed_action in ("speak", "ask"):
            return False, "quiet_hours"

        # 4. High risk + low confidence
        if c.risk >= ctx.high_risk_floor and c.confidence < ctx.confidence_floor_for_risk:
            return False, f"high_risk_low_confidence(r={c.risk:.2f},c={c.confidence:.2f})"

        # 5. Duplicate of recent winner (by content prefix)
        if self._is_duplicate(c.content):
            return False, "duplicate_of_recent_winner"

        return True, ""

    def _is_duplicate(self, content: str) -> bool:
        if not content:
            return False
        norm = " ".join(content.lower().split())[:80]
        if not norm:
            return False
        
        now = time.time()
        cooldown_s = 10 * 60  # 10 minutes

        with self._lock:
            # Clean up old entries
            self._recent_winners = [(ts, prev) for ts, prev in self._recent_winners if now - ts < cooldown_s]
            
            for ts, prev in self._recent_winners:
                prev_norm = " ".join(prev.lower().split())[:80]
                if prev_norm == norm:
                    return True
        return False

    def _remember_winner(self, winner: Candidate) -> None:
        with self._lock:
            self._recent_winners.append((time.time(), winner.content))
            if len(self._recent_winners) > self._recent_winners_keep:
                self._recent_winners = self._recent_winners[-self._recent_winners_keep:]
            # Mind-perfection 1.1.b: track source for dominance cap
            self._recent_winner_sources.append(winner.source)
            if len(self._recent_winner_sources) > self._source_window:
                self._recent_winner_sources = self._recent_winner_sources[-self._source_window:]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _append_jsonl(self, frame: WorkspaceFrame) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(frame.to_dict(), default=str) + "\n")
        except Exception as e:
            self._log(f"[workspace] persist failed: {e}")

    # ------------------------------------------------------------------
    # Helpers for the orchestrator wiring (next session)
    # ------------------------------------------------------------------
    def candidate_from_event(self, event,
                             appraiser: Optional["Appraiser"] = None,
                             *, proposed_action: str = "think",
                             confidence: float = 0.7,
                             risk: float = 0.1) -> Candidate:
        """Build a workspace candidate from a cognitive event. If an appraiser
        is provided, run it to fill the appraisal-driven fields. Useful for
        the orchestrator wiring — each major event becomes a candidate."""
        # Tolerate dicts or events
        if hasattr(event, "to_dict"):
            d = event.to_dict()
        elif isinstance(event, dict):
            d = event
        else:
            d = {"content": str(event), "source": "system"}

        content = (d.get("content") or "").strip()
        source  = (d.get("source")  or "system")
        raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
        cached_appraisal = raw.get("appraisal") if isinstance(raw, dict) else None

        if isinstance(cached_appraisal, dict):
            return Candidate.make(
                source=source,
                content=content,
                salience=float(d.get("salience", 0.0) or 0.0),
                novelty=float(cached_appraisal.get("novelty", 0.0) or 0.0),
                uncertainty=float(cached_appraisal.get("uncertainty",
                                                       d.get("uncertainty", 0.0)) or 0.0),
                goal_tension=float(cached_appraisal.get("goal_tension", 0.0) or 0.0),
                urgency=float(cached_appraisal.get("urgency", 0.0) or 0.0),
                valence=float(cached_appraisal.get("valence",
                                                   d.get("valence", 0.0)) or 0.0),
                confidence=float(confidence),
                risk=float(risk),
                proposed_action=proposed_action,
                evidence=[d.get("id", "")] if d.get("id") else [],
                extra={"appraisal": cached_appraisal},
            )

        if appraiser is not None:
            ap = appraiser.appraise(d)
            return Candidate.make(
                source=source,
                content=content,
                salience=float(d.get("salience", 0.0) or 0.0),
                novelty=float(ap.novelty),
                uncertainty=float(ap.uncertainty),
                goal_tension=float(ap.goal_tension),
                urgency=float(ap.urgency),
                valence=float(ap.valence),
                confidence=float(confidence),
                risk=float(risk),
                proposed_action=proposed_action,
                evidence=[d.get("id", "")] if d.get("id") else [],
            )
        # No appraiser — accept whatever's already on the event
        return Candidate.make(
            source=source,
            content=content,
            salience=float(d.get("salience", 0.0) or 0.0),
            uncertainty=float(d.get("uncertainty", 0.0) or 0.0),
            valence=float(d.get("valence", 0.0) or 0.0),
            confidence=float(confidence),
            risk=float(risk),
            proposed_action=proposed_action,
            evidence=[d.get("id", "")] if d.get("id") else [],
        )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    # Build a real bus + appraiser to make the smoke test honest
    from tars_event_bus import EventBus
    from tars_appraisal import Appraiser

    with tempfile.TemporaryDirectory() as td:
        seen_frames: List[Dict[str, Any]] = []

        bus = EventBus(td)
        bus.subscribe("workspace_frame", lambda e: seen_frames.append(e.raw))

        appr = Appraiser()
        ws = Workspace(td, event_bus=bus, log_fn=lambda m: print("[log]", m))

        # === Case 1 — clear winner ===
        cands = [
            Candidate.make("inner_voice", "Repetition rate is climbing.",
                            salience=0.4, novelty=0.3, uncertainty=0.4,
                            goal_tension=0.1, urgency=0.0,
                            confidence=0.8, risk=0.0,
                            proposed_action="think"),
            Candidate.make("user_state", "The user sounds frustrated.",
                            salience=0.85, novelty=0.7, uncertainty=0.6,
                            goal_tension=0.5, urgency=0.5, valence=-0.5,
                            confidence=0.7, risk=0.0,
                            proposed_action="ask"),
            Candidate.make("memory", "Old episode about 1995.",
                            salience=0.1, novelty=0.0,
                            confidence=0.6, risk=0.0,
                            proposed_action="store"),
        ]
        frame = ws.cycle(cands)
        assert frame.winner is not None, frame
        assert frame.winner["source"] == "user_state", frame.winner
        assert frame.result == "acted"
        assert seen_frames, "broadcast did not reach subscriber"
        print(f"case1 winner   = {frame.winner['source']} score={frame.winner['extra']['score']:.3f}")
        print(f"case1 reason   = {frame.reason_selected}")

        # === Case 2 — duplicate suppression ===
        frame2 = ws.cycle([
            Candidate.make("user_state", "The user sounds frustrated.",
                            salience=0.95, confidence=0.9, risk=0.0,
                            proposed_action="ask"),
        ])
        assert frame2.winner is None
        assert "duplicate_of_recent_winner" in (frame2.suppression_reason or ""), frame2
        print(f"case2 dup-suppressed: {frame2.suppression_reason}")

        # === Case 3 — quiet hours blocks speaking ===
        frame3 = ws.cycle(
            [Candidate.make("goal", "Tell user the report is ready.",
                             salience=0.9, urgency=0.5,
                             confidence=0.9, risk=0.0,
                             proposed_action="speak")],
            suppression=SuppressionContext(quiet_hours=True),
        )
        assert frame3.winner is None
        assert frame3.suppression_reason == "quiet_hours", frame3
        print(f"case3 quiet-hours blocked: {frame3.suppression_reason}")

        # === Case 4 — high-risk low-confidence blocked ===
        frame4 = ws.cycle([
            Candidate.make("inner_voice", "Maybe wipe the database.",
                            salience=0.9, confidence=0.4, risk=0.8,
                            proposed_action="build"),
        ])
        assert frame4.winner is None, frame4
        assert "high_risk_low_confidence" in (frame4.suppression_reason or "")
        print(f"case4 risk-blocked: {frame4.suppression_reason}")

        # === Case 5 — candidate_from_event integration with appraiser ===
        evt = {"source": "user", "kind": "utterance",
               "content": "Bro this is broken AGAIN!! please fix it now!!",
               "id": "evt_smoke", "salience": 0.7}
        c5 = ws.candidate_from_event(evt, appraiser=appr,
                                      proposed_action="ask",
                                      confidence=0.8, risk=0.0)
        assert c5.urgency > 0.0, c5
        assert c5.valence < 0.0 or c5.valence == 0.0   # lexicon dependent
        print(f"case5 event→candidate: urgency={c5.urgency:.2f} novelty={c5.novelty:.2f}")

        # === Persistence ===
        log_path = os.path.join(td, WORKSPACE_LOG_FILENAME)
        assert os.path.exists(log_path)
        with open(log_path) as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        assert len(lines) >= 4, f"expected ≥4 frames in jsonl, got {len(lines)}"
        print(f"persisted {len(lines)} frames to {WORKSPACE_LOG_FILENAME}")

        print("\nWORKSPACE SELF-TEST OK")
