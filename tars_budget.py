"""
TARS Token Budget Guard
=======================

Two-tier policy (per user directive):
  - "user"        : UNLIMITED — no cap on user-facing turns or skill work
  - "autonomous"  : capped — heartbeats, audits, learner, vision summaries,
                    committee deliberations, soul-edit reviews

Default autonomous cap: 50,000 tokens / 5-hour rolling window.

Why two tiers? When you are talking to TARS, latency and quality matter
more than tokens. When TARS is talking to himself in the background,
runaway cost is the bigger risk. So we cap the latter, never the former.

Usage:

    from tars_budget import TokenBudget
    budget = TokenBudget(project_dir, log_fn)

    # Wrap an autonomous chat call
    autonomous_chat = budget.guard(chat_client.chat, tier="autonomous")
    reply = autonomous_chat(messages)   # may return None / "" if budget exhausted

    # User calls bypass the budget entirely:
    reply = chat_client.chat(messages)   # never blocked

The guard estimates input/output tokens with a fast char-based heuristic
(no tokenizer dep). It's approximate but good enough for cost control —
real OpenAI/Anthropic tokenizers usually agree within ~20%.

State persists in `tars_budget.json` so the cap survives restarts.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional


BUDGET_FILE = "tars_budget.json"


# ---------------------------------------------------------------------------
# Cheap token estimation
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Approximate token count without a tokenizer dependency.
    Heuristic: ~4 characters per token for English (roughly OpenAI-ratio)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def _estimate_messages_tokens(messages) -> int:
    """Approximate the input-token count of an OpenAI-style messages list."""
    total = 0
    if not messages:
        return 0
    for m in messages:
        if not isinstance(m, dict):
            continue
        content = m.get("content", "")
        if isinstance(content, str):
            total += _estimate_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    total += _estimate_tokens(part.get("text", ""))
        # +4 token-ish overhead per message (role, separators)
        total += 4
    return total


# ---------------------------------------------------------------------------
# TokenBudget
# ---------------------------------------------------------------------------

class TokenBudget:
    """Sliding-window budget for autonomous LLM calls."""

    AUTONOMOUS_CAP_DEFAULT      = 50_000      # tokens (combined in+out)
    AUTONOMOUS_WINDOW_S_DEFAULT = 5 * 3600    # 5 hours

    def __init__(self, project_dir: str, log_fn,
                 autonomous_cap: Optional[int] = None,
                 window_seconds: Optional[int] = None):
        self.project_dir   = project_dir
        self.log           = log_fn
        self.autonomous_cap   = (
            autonomous_cap
            if autonomous_cap is not None
            else int(os.getenv("TARS_AUTONOMOUS_TOKEN_CAP",
                                self.AUTONOMOUS_CAP_DEFAULT))
        )
        self.window_s = (
            window_seconds
            if window_seconds is not None
            else int(os.getenv("TARS_AUTONOMOUS_WINDOW_S",
                                self.AUTONOMOUS_WINDOW_S_DEFAULT))
        )
        self.path = os.path.join(project_dir, BUDGET_FILE)
        self._lock = threading.Lock()
        # List of (timestamp, tokens, tier, label)
        self._events: List[Dict] = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> List[Dict]:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
            except Exception:
                pass
        return []

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._events[-2000:], f, default=str)
            os.replace(tmp, self.path)
        except Exception as e:
            self.log(f"[budget] save failed: {e}")

    # ------------------------------------------------------------------
    # Window math
    # ------------------------------------------------------------------
    def _prune(self) -> None:
        cutoff = time.time() - self.window_s
        self._events = [e for e in self._events
                        if e.get("ts", 0) > cutoff]

    def autonomous_used(self) -> int:
        with self._lock:
            self._prune()
            return sum(int(e.get("tokens", 0))
                       for e in self._events
                       if e.get("tier") == "autonomous")

    def autonomous_remaining(self) -> int:
        return max(0, self.autonomous_cap - self.autonomous_used())

    def is_blocked(self) -> bool:
        return self.autonomous_used() >= self.autonomous_cap

    def record(self, tokens: int, tier: str, label: str = "") -> None:
        with self._lock:
            self._events.append({
                "ts":     time.time(),
                "tokens": int(tokens),
                "tier":   tier,
                "label":  str(label)[:60],
                "iso":    datetime.now().isoformat(),
            })
            self._prune()
            self._save()

    # ------------------------------------------------------------------
    # Guard wrapper
    # ------------------------------------------------------------------
    def guard(self, chat_fn: Callable, tier: str = "autonomous",
              label: str = "") -> Callable:
        """Return a wrapped chat function. If tier='user', no cap is enforced."""
        if tier == "user":
            # Bypass entirely. We still record usage for observability if desired.
            def _user_call(messages):
                est_in = _estimate_messages_tokens(messages)
                reply = chat_fn(messages)
                est_out = _estimate_tokens(reply or "")
                self.record(est_in + est_out, tier="user",
                            label=label or "user")
                return reply
            return _user_call

        # Autonomous: hard cap with circuit-breaker behavior
        def _autonomous_call(messages):
            if self.is_blocked():
                self.log(f"[budget] BLOCKED autonomous call ({label}) — "
                         f"window cap reached "
                         f"({self.autonomous_used()}/{self.autonomous_cap})")
                return ""
            est_in = _estimate_messages_tokens(messages)
            # Pre-check: don't even attempt if this single call would exceed
            if (self.autonomous_used() + est_in) > self.autonomous_cap:
                self.log(f"[budget] SKIPPING ({label}) — would exceed cap")
                return ""
            reply = chat_fn(messages)
            est_out = _estimate_tokens(reply or "")
            self.record(est_in + est_out, tier="autonomous", label=label)
            return reply

        return _autonomous_call

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def status(self) -> Dict:
        return {
            "autonomous_used":      self.autonomous_used(),
            "autonomous_cap":       self.autonomous_cap,
            "autonomous_remaining": self.autonomous_remaining(),
            "window_seconds":       self.window_s,
            "events":               len(self._events),
        }
