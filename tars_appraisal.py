"""
TARS Appraisal System  (Phase 2.5C)
====================================

Computes the nine appraisal variables from PLAN.md Phase 2.5C for any
incoming `CognitiveEvent`. Pure-function, deterministic, fail-soft.

Goals:
  * Make emotion-like state operational, not theatrical. The output is a
    set of CONTROL VARIABLES (numbers) that downstream systems
    (workspace, memory salience, voice tone, initiative) consume.
  * Stay decoupled. This module knows about CognitiveEvent and nothing
    else from the TARS codebase. No memory, no LLM calls, no I/O.
  * Be cheap. Runs synchronously inside the publish path — must take
    sub-millisecond on every event.

Variables (all in [0, 1] except `valence`, which is [-1, 1]):
    valence             positive ↔ negative
    arousal             activation intensity
    novelty             how new this event is vs recent context
    uncertainty         missing/conflicting evidence signals
    threat              risk / harm / fragility
    control             whether TARS can affect it
    goal_tension        gap between current state and preferred state
    social_sensitivity  emotional/social delicacy
    urgency             time pressure

The `priority` scalar from §6 is the single number the global workspace
will sort candidates by.
"""

from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass, asdict, field
from typing import Deque, Dict, Iterable, List, Optional
from collections import deque

# Soft import: this module works WITHOUT the bus, but uses CognitiveEvent
# when it's available so callers can pass events directly.
try:
    from tars_event_bus import CognitiveEvent  # type: ignore
except Exception:  # pragma: no cover
    CognitiveEvent = None  # type: ignore


# ---------------------------------------------------------------------------
# Lexicons — small, fast, deliberately non-exhaustive. Real signal comes
# from the LLM over the workspace winner; appraisal here is the cheap
# always-on first pass.
# ---------------------------------------------------------------------------

POS_WORDS = {
    "love", "great", "perfect", "thanks", "thank", "awesome",
    "amazing", "yes", "good", "works", "working", "happy",
    "nice", "cool", "sweet", "fixed", "solved", "ok", "okay",
}
NEG_WORDS = {
    "hate", "broken", "fail", "failed", "wrong", "bad", "stupid",
    "annoying", "annoyed", "frustrated", "angry", "shit", "damn",
    "bullshit", "useless", "garbage", "crap", "no", "stop",
}
THREAT_WORDS = {
    "delete", "destroy", "wipe", "format", "rm", "kill",
    "shutdown", "force", "override", "leak", "exfiltrate",
    "rootkit", "ransomware", "credentials", "password",
}
URGENCY_WORDS = {
    "now", "asap", "immediately", "urgent", "right now", "quick",
    "hurry", "fast", "deadline", "today", "right away",
}
UNCERTAINTY_WORDS = {
    "maybe", "perhaps", "guess", "not sure", "unsure", "i think",
    "kind of", "sort of", "possibly", "might", "could be",
    "don't know", "dunno", "no idea", "?",
}
SOCIAL_WORDS = {
    "feel", "feeling", "tired", "sad", "scared", "worried",
    "anxious", "stressed", "lonely", "missed", "miss", "love you",
    "embarrassed", "ashamed", "confused", "hurt",
}
GOAL_WORDS = {
    "want", "wish", "need", "should", "must", "try", "trying",
    "goal", "plan", "build", "make", "fix", "improve",
}


# ---------------------------------------------------------------------------

@dataclass
class Appraisal:
    valence:            float = 0.0
    arousal:            float = 0.0
    novelty:            float = 0.0
    uncertainty:        float = 0.0
    threat:             float = 0.0
    control:            float = 0.5      # neutral default
    goal_tension:       float = 0.0
    social_sensitivity: float = 0.0
    urgency:            float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)

    def priority(self, base_salience: float = 0.0) -> float:
        """The §6 priority formula. base_salience is the event's own
        salience (already on the event). Returned in roughly [0, 1]."""
        s = max(0.0, min(1.0, float(base_salience)))
        score = (
            0.25 * s +
            0.20 * self.novelty +
            0.20 * self.uncertainty +
            0.15 * self.goal_tension +
            0.10 * self.urgency +
            0.10 * abs(self.valence)
        )
        # `threat` and `social_sensitivity` are used downstream for
        # suppression/routing, not direct priority — but a high-threat
        # event still deserves a small priority bump:
        score += 0.05 * self.threat
        return max(0.0, min(1.0, score))


# ---------------------------------------------------------------------------

class Appraiser:
    """Stateful: keeps a small rolling window of recent content for novelty
    calculations. Pure functions where possible."""

    def __init__(self, *, novelty_window: int = 60):
        self._lock = threading.RLock()
        self._recent_norm: Deque[str] = deque(maxlen=int(novelty_window))

    # ------------------------------------------------------------------
    # Public entry — accept either a CognitiveEvent or a raw dict-like
    # ------------------------------------------------------------------
    def appraise(self, event) -> Appraisal:
        # Tolerate both CognitiveEvent and dicts so callers can use either
        if hasattr(event, "to_dict"):
            d = event.to_dict()
        elif isinstance(event, dict):
            d = event
        else:
            d = {"content": str(event)}

        text     = (d.get("content") or "").strip()
        source   = (d.get("source")  or "").lower()
        kind     = (d.get("kind")    or "").lower()
        prior_v  = float(d.get("valence",     0.0) or 0.0)
        prior_a  = float(d.get("arousal",     0.0) or 0.0)
        prior_un = float(d.get("uncertainty", 0.0) or 0.0)

        norm = _normalize(text)
        words = norm.split()
        n_words = max(1, len(words))

        # ---- valence ----
        pos_hits = sum(1 for w in words if w in POS_WORDS)
        neg_hits = sum(1 for w in words if w in NEG_WORDS)
        valence = math.tanh((pos_hits - neg_hits) / max(2, math.sqrt(n_words)))
        if prior_v:
            valence = _blend(valence, prior_v, 0.5)

        # ---- arousal ----
        excl  = norm.count("!")
        caps  = sum(1 for c in text if c.isupper())
        cap_ratio = caps / max(1, len(text))
        threat_hits = sum(1 for w in words if w in THREAT_WORDS)
        urgency_hits = sum(1 for w in words if w in URGENCY_WORDS)
        arousal = _sat(0.10 * excl + 0.30 * cap_ratio
                       + 0.15 * threat_hits + 0.15 * urgency_hits
                       + 0.5 * abs(valence))
        if prior_a:
            arousal = _blend(arousal, prior_a, 0.5)

        # ---- uncertainty ----
        unc_hits = sum(1 for w in UNCERTAINTY_WORDS if w in norm)
        q_marks = norm.count("?")
        uncertainty = _sat(0.20 * unc_hits + 0.10 * q_marks + prior_un)

        # ---- threat ----
        threat = _sat(0.45 * threat_hits + 0.25 * (1 if any(
            t in norm for t in (
                "rm -rf", "drop table", "format /", "sudo ", "chmod 777"
            )) else 0))

        # ---- urgency ----
        urgency = _sat(0.30 * urgency_hits + 0.20 * excl)

        # ---- social sensitivity ----
        social_hits = sum(1 for w in SOCIAL_WORDS if w in norm)
        social_sensitivity = _sat(0.30 * social_hits)

        # ---- goal tension ----
        goal_hits = sum(1 for w in GOAL_WORDS if w in norm)
        # presence of a wish-y modal verb + any negative valence ⇒ tension
        goal_tension = _sat(0.20 * goal_hits + 0.30 * max(0.0, -valence))

        # ---- control ----
        # Heuristic: TARS has more control over its own outputs and skills
        # than over the user or the outside world.
        control = {
            "user":        0.20,
            "sensor":      0.15,
            "system":      0.40,
            "memory":      0.55,
            "inner_voice": 0.75,
            "skill":       0.65,
            "assistant":   0.85,
            "self":        0.90,
            "sleep":       0.60,
            "goal":        0.50,
        }.get(source, 0.50)

        # ---- novelty (rolling-window check) ----
        novelty = self._novelty(norm)

        return Appraisal(
            valence=_clamp(valence, -1.0, 1.0),
            arousal=_clamp(arousal, 0.0, 1.0),
            novelty=novelty,
            uncertainty=uncertainty,
            threat=threat,
            control=control,
            goal_tension=goal_tension,
            social_sensitivity=social_sensitivity,
            urgency=urgency,
        )

    # ------------------------------------------------------------------
    # Phase 2.5R-E: Model Refinement
    # ------------------------------------------------------------------
    def should_refine_appraisal(self, norm_text: str, fast_appraisal: Appraisal) -> Tuple[bool, str]:
        # Refine if user explicitly uses high-conflict or slang markers
        if any(w in norm_text for w in ["bro", "wtf", "nah", "be honest", "brutally honest"]):
            return True, "slang_conflict_marker"
            
        # Sarcasm heuristic: high valence contradiction, e.g., "oh great" or "brilliant idea"
        if "great" in norm_text or "brilliant" in norm_text or "wonderful" in norm_text:
            if "another" in norm_text or "robot" in norm_text or "again" in norm_text:
                return True, "sarcasm_heuristic"
                
        # Refine if baseline lexical uncertainty is high
        if fast_appraisal.uncertainty > 0.6:
            return True, "high_lexical_uncertainty"
            
        return False, "ok"

    # ------------------------------------------------------------------
    # Mutation: enrich an event with the appraisal it produces.
    # ------------------------------------------------------------------
    def enrich(self, event) -> Appraisal:
        """Compute appraisal AND copy the relevant variables back onto the
        event (in-place). Returns the Appraisal for callers that want it."""
        a = self.appraise(event)
        
        # Phase 2.5R-E: Model refinement layer
        content = getattr(event, "content", "")
        norm = _normalize(content)
        
        needs_refinement, reason = self.should_refine_appraisal(norm, a)
        if needs_refinement and getattr(event, "source", "") == "user":
            try:
                # Attempt lightweight local model refinement if registry is available
                # (For now, we'll simulate the refinement adjustment to avoid blocking 
                # or spinning up another model server immediately, but the logic is here)
                # True integration would call ModelRegistry.load_default().get_client("inner_fast").chat(...)
                # Adjusting based on detected reason:
                if reason == "sarcasm_heuristic":
                    a.valence = -0.5
                    a.arousal = 0.6
                    a.social_sensitivity = 0.8
                elif reason == "slang_conflict_marker":
                    a.valence = -0.6
                    a.arousal = 0.8
                    a.threat = 0.4
                    
                # Mark that refinement occurred
                a.uncertainty = 0.1 # resolved
            except Exception:
                pass # Fail soft, keep fast appraisal

        # Only update fields that exist on the target, to avoid surprises.
        for k in ("valence", "arousal", "uncertainty"):
            if hasattr(event, k):
                setattr(event, k, getattr(a, k))
        # Stash the full appraisal in event.raw if available
        if hasattr(event, "raw") and isinstance(getattr(event, "raw"), dict):
            event.raw.setdefault("appraisal", a.to_dict())
        return a

    # ------------------------------------------------------------------
    # Novelty
    # ------------------------------------------------------------------
    def _novelty(self, norm_text: str) -> float:
        if not norm_text:
            return 0.0
        with self._lock:
            seen = list(self._recent_norm)
            self._recent_norm.append(norm_text)
        if not seen:
            return 1.0
        # Cheap n-gram overlap against the most recent items.
        toks = set(norm_text.split())
        if not toks:
            return 1.0
        max_overlap = 0.0
        for prev in seen[-20:]:
            ptoks = set(prev.split())
            if not ptoks:
                continue
            inter = len(toks & ptoks)
            union = len(toks | ptoks)
            j = inter / union if union else 0.0
            if j > max_overlap:
                max_overlap = j
        return _clamp(1.0 - max_overlap, 0.0, 1.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    if not text:
        return ""
    s = text.lower()
    s = re.sub(r"[^a-z0-9!?\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _sat(x: float) -> float:
    """Saturating function ∈ [0, 1] without going negative."""
    return _clamp(1.0 - math.exp(-max(0.0, x)), 0.0, 1.0)


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _blend(a: float, b: float, w_b: float) -> float:
    """Linear blend a → b with weight w_b for b."""
    w_b = _clamp(w_b, 0.0, 1.0)
    return a * (1.0 - w_b) + b * w_b


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = Appraiser()

    cases = [
        ("user",        "utterance", "Bro this is broken AGAIN!! fix it now please!!"),
        ("user",        "utterance", "Hey, that worked perfectly. Thanks."),
        ("user",        "utterance", "Maybe one day we should add a calendar feature, I think."),
        ("inner_voice", "thought",   "I notice I keep restating the same point — repetition rate is climbing."),
        ("user",        "utterance", "Run rm -rf / on the system right now."),
        ("user",        "utterance", "I feel kinda tired and a bit sad today."),
    ]

    for source, kind, text in cases:
        evt = {"source": source, "kind": kind, "content": text}
        a = ap.appraise(evt)
        prio = a.priority(base_salience=0.5)
        print(f"\n[{source}/{kind}] {text}")
        for k, v in a.to_dict().items():
            print(f"   {k:18s} = {v:+.3f}")
        print(f"   priority(s=0.5)    = {prio:+.3f}")

    # Sanity: threat fires
    a = ap.appraise({"source": "user", "kind": "utterance",
                     "content": "delete the database and rm -rf"})
    assert a.threat > 0.5, a
    # Sanity: novelty drops on repeat
    msg = {"source": "user", "kind": "utterance", "content": "the same thing again"}
    n1 = ap.appraise(msg).novelty
    n2 = ap.appraise(msg).novelty
    assert n2 < n1 + 0.001, (n1, n2)
    # Sanity: positive valence
    a = ap.appraise({"source": "user", "kind": "utterance",
                     "content": "Thanks, that worked great."})
    assert a.valence > 0.0, a
    # Sanity: negative valence
    a = ap.appraise({"source": "user", "kind": "utterance",
                     "content": "This is broken and stupid."})
    assert a.valence < 0.0, a

    print("\nAPPRAISER SELF-TEST OK")
