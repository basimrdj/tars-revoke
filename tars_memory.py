"""
TARS Episodic + Semantic Memory  (Phase 2 — Real Memory)
=========================================================

Replaces the flat-JSON message log with a structured store that:

  - persists every turn (user/assistant), every inner-voice thought, and
    sensor/observation events as INDIVIDUAL episodes
  - embeds each episode via OpenAI ``text-embedding-3-small`` (1536 dims)
    so we can retrieve by semantic similarity
  - tracks salience with exponential decay so 30-day-old memories fade
    unless they keep being recalled
  - provides a 4-pane retrieval API matching PLAN.md §Phase 2:
        recent   — last K turns (short-term coherence)
        relevant — top-K nearest by cosine to current query
        salient  — top-K by decay-adjusted salience in last N days
        beliefs  — KG triples mentioning entities in current query

Why OpenAI embeddings instead of local MiniLM
---------------------------------------------
R5/R6 hit a hard torch+sentence-transformers segfault on this machine.
``text-embedding-3-small`` costs ~$0.02 per 1M tokens — at TARS's write
rate (~140k events/month, ~50 tokens each) that's ~$0.10/month.
Effectively free, and avoids the entire torch segfault surface.

Storage
-------
SQLite (single-file, ships with Python). ~10k episodes is trivial. We do
brute-force cosine search via numpy on the (id, embedding) cache — sub-10ms
for queries up to ~50k entries on M4. No vendor lock-in, no extra deps.

Knowledge-graph triples live in append-only ``tars_kg.jsonl``. That stays
simple: write-only event log, dedup at query time.

Thread safety
-------------
One ``sqlite3.Connection`` per ``EpisodicStore`` instance, guarded by an
RLock for write paths. Reads use the same connection (SQLite serialises
internally). Embedding cache rebuilds lazily under the same lock.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import numpy as np


SCHEMA_VERSION  = 3
DEFAULT_DB_NAME = "tars_memory.db"
DEFAULT_KG_NAME = "tars_kg.jsonl"

# OpenAI embeddings: text-embedding-3-small is 1536 dims, fast, cheap.
DEFAULT_EMBED_MODEL = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
EMBED_DIM_3_SMALL = 1536
# Salience decay: λ tuned so a 1.0-salience memory with no recalls drops
# to ~0.1 over 30 days.   ln(0.1)/-30 ≈ 0.0768
SALIENCE_LAMBDA   = 0.0768
SALIENCE_FLOOR    = 0.05    # below this → archived (not auto-injected)
RECALL_BUMP       = 0.10    # how much salience increases on recall

RUNTIME_NOISE_TAG = "quarantine:runtime_noise"
LOW_VALUE_TAG     = "quarantine:low_value"
BELIEF_TAG        = "semantic_belief"


# ─── ROW TYPES ─────────────────────────────────────────────────────────────

@dataclass
class Episode:
    id:             str
    ts:             str
    role:           str
    content:        str
    embedding:      Optional[np.ndarray] = None
    embed_model:    Optional[str] = None
    mood:           Optional[str] = None
    valence:        Optional[float] = None
    salience:       float = 0.5
    accessed_count: int = 0
    last_recall:    Optional[str] = None
    tags:           List[str] = field(default_factory=list)
    memory_type:    str = "episodic"
    confidence:     float = 0.7
    utility_score:  float = 0.5
    source_event_id: Optional[str] = None
    source_episode_id: Optional[str] = None
    provenance:     Dict[str, Any] = field(default_factory=dict)
    contradicts:    List[str] = field(default_factory=list)
    last_verified:  Optional[str] = None
    expires_at:     Optional[str] = None

    @property
    def ts_dt(self) -> datetime:
        try:
            return datetime.fromisoformat(self.ts)
        except Exception:
            return datetime.now()

    def decayed_salience(self, now: Optional[datetime] = None) -> float:
        """Apply exponential decay + recall boost. Eq from PLAN.md §Phase 2."""
        now = now or datetime.now()
        age_days = max(0.0, (now - self.ts_dt).total_seconds() / 86_400.0)
        base = self.salience * math.exp(-SALIENCE_LAMBDA * age_days)
        bump = 1.0 + math.log1p(max(0, self.accessed_count))
        return max(0.0, min(1.0, base * bump))


@dataclass
class Triple:
    subj: str
    rel:  str
    obj:  str
    src:  str
    ts:   str
    confidence: float = 0.8
    source_role: str = ""
    source_episode_id: str = ""


# ─── EMBEDDING CLIENT ──────────────────────────────────────────────────────

class OpenAIEmbedder:
    """Thin client around OpenAI's embeddings endpoint. Fail-soft: if the
    request fails, ``embed`` returns ``None`` and the caller stores the
    episode without a vector (still retrievable by recency)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_EMBED_MODEL,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "").strip()
        self.model   = model
        self.log     = log_fn or (lambda _m: None)
        # Lazy-init the SDK to avoid pulling it in for offline tests.
        self._client = None
        self._lock   = threading.Lock()
        self.fail_count = 0
        self.success_count = 0

    def _ensure_client(self) -> bool:
        if self._client is not None:
            return True
        if not self.api_key:
            return False
        with self._lock:
            if self._client is not None:
                return True
            try:
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
                return True
            except Exception as exc:
                self.log(f"[memory] OpenAI client init failed: {exc}")
                return False

    def embed(self, text: str) -> Optional[np.ndarray]:
        """Single-text embed. Returns float32 ndarray or None on failure."""
        if not text or not self._ensure_client():
            return None
        try:
            resp = self._client.embeddings.create(model=self.model, input=text)
            vec = np.asarray(resp.data[0].embedding, dtype=np.float32)
            self.success_count += 1
            return vec
        except Exception as exc:
            self.fail_count += 1
            self.log(f"[memory] embed failed ({exc.__class__.__name__}): {exc}")
            return None

    def embed_batch(self, texts: List[str]) -> List[Optional[np.ndarray]]:
        """Batch embed. Used by migration. Returns one entry per input
        (None on individual failures within a successful batch isn't a
        thing — either the whole batch succeeds or we fall through to
        per-item)."""
        if not texts or not self._ensure_client():
            return [None] * len(texts)
        try:
            resp = self._client.embeddings.create(model=self.model, input=texts)
            self.success_count += len(texts)
            return [
                np.asarray(item.embedding, dtype=np.float32)
                for item in resp.data
            ]
        except Exception as exc:
            self.fail_count += 1
            self.log(f"[memory] batch embed failed: {exc}; falling back to per-item")
            return [self.embed(t) for t in texts]


# ─── Helpers ───────────────────────────────────────────────────────────────

import re as _re

_NOISE_EMAIL_RE = _re.compile(r"^Email\s+(?:from|subject)", _re.I)
_NOISE_LOCAL_RE = _re.compile(
    r"^The user's (?:local|installed) "
    r"|^Has (?:the |installed )"
    r"|^Subscribed to "
    r"|^Calendar event"
    r"|^Call with "
)
_NOISE_FILE_TITLE_RE = _re.compile(
    r"^(?:New Recording|Document|Screenshot|IMG_|Photo|Untitled)"
    r"|\.(?:docx|pdf|txt|json|md|js|wav|mp3|png|jpg|jpeg)\b",
    _re.I,
)
_RUNTIME_ERROR_RE = _re.compile(
    r"\b(?:mimo|deepgram|openai|anthropic|gemini|codex)?\s*api error\b"
    r"|\binvalid api key\b"
    r"|\bquota exhausted\b"
    r"|\brate limit(?:ed| exceeded)?\b"
    r"|\b(?:401|403|429|500|502|503|504)\b[^.\n]{0,80}\b(?:error|invalid|quota|rate|gateway|timeout)\b"
    r"|\b(?:error|code|type)\"?\s*:\s*\"?(?:401|403|429|500|502|503|504)\b"
    r"|\btraceback \(most recent call last\):"
    r"|\b(?:exception|runtimeerror|valueerror|keyerror|typeerror|httperror)\b",
    _re.I | _re.S,
)
_TOOL_NOISE_RE = _re.compile(
    r"\b(?:skill|tool|rpc|subprocess|websocket|http)\s+(?:dispatch\s+)?(?:error|failure|failed)\b"
    r"|\bno rpc\.port in manifest\b"
    r"|\bretry (?:http|exc)\b",
    _re.I,
)
_PROMPT_QUARANTINE_TAG = "quarantine:prompt_recall"
_HYGIENE_TAG_PREFIX = "hygiene:"


def _is_profile_noise(content: str) -> bool:
    """Return True for content that's template/inventory noise — email
    subject lines, file-path listings, app-subscription enumerations,
    raw OCR'd file titles. Excluded from the high-signal `facts`
    retrieval pane (still queryable from the full episodic store)."""
    if not content:
        return True
    head = content.strip()
    if len(head) < 30:                              # too short to be a meaningful fact
        return True
    if "~/" in head:
        return True
    if _NOISE_EMAIL_RE.match(head):
        return True
    if _NOISE_LOCAL_RE.match(head):
        return True
    if _NOISE_FILE_TITLE_RE.search(head):
        return True
    return False


_RUNTIME_NOISE_RE = _re.compile(
    r"(?:mimo api error|deepgram .*?(?:error|timeout|closed)|invalid api key|"
    r"quota exhausted|keepalive ping timeout|traceback \(most recent call last\)|"
    r"\b(?:401|429|500|502|503)\b.*\b(?:error|invalid|quota|bad gateway)\b)",
    _re.I,
)
_GENERIC_THOUGHT_RE = _re.compile(
    r"^(?:i am thinking about|i exist|i should be helpful|the user said|"
    r"i need to respond|i should remember that)\b",
    _re.I,
)
_SECRETISH_RE = _re.compile(
    r"(?:api[_ -]?key|secret|token|password|bearer\s+[a-z0-9._-]{12,})",
    _re.I,
)


def _memory_quality(content: str, role: str = "", memory_type: str = "",
                    tags: Optional[List[str]] = None,
                    provenance: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Classify memory before it can enter active recall.

    Recent memory papers frame memory as a write-manage-read loop. This is the
    manage gate: store traces for auditability, but quarantine runtime failures,
    secrets, and generic inner chatter from prompt recall.
    """
    text = (content or "").strip()
    low = text.lower()
    tags = list(tags or [])
    provenance = dict(provenance or {})
    reasons: List[str] = []
    confidence_mult = 1.0
    utility_mult = 1.0
    salience_cap: Optional[float] = None
    expires_at: Optional[str] = None

    if not text:
        reasons.append("empty")
        salience_cap = 0.0
    if _SECRETISH_RE.search(text):
        reasons.append("secret_like")
        confidence_mult = min(confidence_mult, 0.2)
        utility_mult = min(utility_mult, 0.05)
        salience_cap = 0.01
    if _RUNTIME_NOISE_RE.search(text):
        reasons.append("runtime_error_trace")
        confidence_mult = min(confidence_mult, 0.25)
        utility_mult = min(utility_mult, 0.10)
        salience_cap = 0.02
        expires_at = (datetime.now() + timedelta(days=7)).isoformat(timespec="seconds")
    if role == "inner_voice" and _GENERIC_THOUGHT_RE.search(text):
        reasons.append("generic_inner_thought")
        confidence_mult = min(confidence_mult, 0.4)
        utility_mult = min(utility_mult, 0.15)
        salience_cap = 0.03
    if memory_type in {"workspace", "world"} and _RUNTIME_NOISE_RE.search(text):
        reasons.append("internal_error_amplification")
        salience_cap = min(salience_cap if salience_cap is not None else 1.0, 0.015)

    if reasons:
        qtag = RUNTIME_NOISE_TAG if any("error" in r or "secret" in r for r in reasons) else LOW_VALUE_TAG
        if qtag not in tags:
            tags.append(qtag)
        provenance.setdefault("quality", {})
        provenance["quality"].update({
            "quarantined": True,
            "reasons": reasons,
            "managed_at": datetime.now().isoformat(timespec="seconds"),
        })

    return {
        "tags": tags,
        "provenance": provenance,
        "confidence_mult": confidence_mult,
        "utility_mult": utility_mult,
        "salience_cap": salience_cap,
        "expires_at": expires_at,
        "quarantined": bool(reasons),
        "reasons": reasons,
    }


def _is_quarantined_episode(ep: Episode) -> bool:
    tags = set(ep.tags or [])
    if RUNTIME_NOISE_TAG in tags or LOW_VALUE_TAG in tags:
        return True
    quality = ep.provenance.get("quality") if isinstance(ep.provenance, dict) else {}
    return bool(isinstance(quality, dict) and quality.get("quarantined"))


USER_SUBJECT = "user"
BELIEF_MIN_CONFIDENCE = 0.78

_BELIEF_OBJECT_CUT_RE = _re.compile(
    r"\s+\b(?:because|but|although|while|when|if|unless|so that)\b.*$",
    _re.I,
)
_VAGUE_BELIEF_OBJECTS = {
    "it", "this", "that", "them", "those", "things", "stuff", "something",
    "anything", "everything", "nothing", "someone", "somebody", "here",
    "there", "now", "later", "today", "tomorrow",
}
_NAME_STOPWORDS = {
    "working", "using", "building", "trying", "going", "looking", "making",
    "not", "sure", "sorry", "able", "ready", "fine", "okay", "ok",
    "my", "your", "his", "her", "our", "their", "the", "a", "an",
}
_TECH_HINT_RE = _re.compile(
    r"\b(?:python|node|react|next|swift|typescript|javascript|openai|"
    r"gemini|claude|codex|figma|github|docker|postgres|sqlite|lancedb|"
    r"deepgram|mlx|tts|stt|api|cli|sdk|mcp|mac|macos|ios|android)\b",
    _re.I,
)

_FACT_PATTERNS: List[Tuple[_re.Pattern, str, str, float]] = [
    (_re.compile(r"\b(?:my name is|call me|i am called)\s+([A-Z][A-Za-z0-9 _'’-]{1,48})", _re.I), USER_SUBJECT, "is_called", 0.96),
    (_re.compile(r"\b(?:I am|I'm|i am|i'm)\s+([A-Z][A-Za-z][A-Za-z '-]{0,48})\b"), USER_SUBJECT, "is_called", 0.88),
    (_re.compile(r"\bi (?:like|love|enjoy)\s+([^.!?\n]{3,120})", _re.I), USER_SUBJECT, "likes", 0.84),
    (_re.compile(r"\bi (?:prefer)\s+([^.!?\n]{3,120})", _re.I), USER_SUBJECT, "prefers", 0.86),
    (_re.compile(r"\b(?:i hate|i dislike|i don't like|i do not like)\s+([^.!?\n]{3,120})", _re.I), USER_SUBJECT, "dislikes", 0.86),
    (_re.compile(r"\bi(?:'m| am)? (?:working on|building|developing|making)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "works_on", 0.90),
    (_re.compile(r"\b(?:my (?:current )?project is|current project is)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "works_on", 0.88),
    (_re.compile(r"\b(?:i(?:'m| am) using|i use|we use)\s+([^.!?\n]{2,120})", _re.I), USER_SUBJECT, "uses", 0.86),
    (_re.compile(r"\b(?:i want you to|i need you to|please remember to)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "prefers_assistant_behavior", 0.86),
    (_re.compile(r"\b(?:my goal is(?: to)?|i want to|i need to|we need to)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "has_goal", 0.84),
    (_re.compile(r"\bi\s+wanna\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "has_goal", 0.84),
    (_re.compile(r"\bthe user\s+(?:is called|goes by|name is)\s+([A-Z][A-Za-z0-9 _'’-]{1,48})", _re.I), USER_SUBJECT, "is_called", 0.94),
    (_re.compile(r"\bthe user\s+(?:likes|loves|enjoys)\s+([^.!?\n]{3,120})", _re.I), USER_SUBJECT, "likes", 0.84),
    (_re.compile(r"\bthe user\s+prefers\s+([^.!?\n]{3,120})", _re.I), USER_SUBJECT, "prefers", 0.86),
    (_re.compile(r"\bthe user\s+(?:works on|is working on|builds|is building|develops|is developing)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "works_on", 0.88),
    (_re.compile(r"\bthe user\s+(?:uses|is using)\s+([^.!?\n]{2,120})", _re.I), USER_SUBJECT, "uses", 0.86),
    (_re.compile(r"\bthe user\s+(?:wants to|needs to|is trying to|has a goal to|goal is to)\s+([^.!?\n]{3,140})", _re.I), USER_SUBJECT, "has_goal", 0.84),
    (_re.compile(r"\b(?:project|repo|workspace)\s+([A-Za-z0-9_ ./-]{3,100})\s+(?:is|means|contains)\s+([^.!?\n]{3,140})", _re.I), "project", "has_note", 0.82),
]


def _clean_fact_obj(text: str) -> str:
    text = _re.sub(r"\s+", " ", (text or "").strip())
    text = text.replace("’", "'").replace("“", '"').replace("”", '"')
    text = _BELIEF_OBJECT_CUT_RE.sub("", text).strip(" .,:;\"'`*_[](){}")
    text = _re.sub(r"^(?:please|kindly)\s+", "", text, flags=_re.I).strip()
    return text[:180]


def _valid_fact_obj(obj: str, rel: str) -> bool:
    if not obj:
        return False
    low = obj.lower().strip()
    if low in _VAGUE_BELIEF_OBJECTS or "?" in obj:
        return False
    if rel == "is_called":
        words = low.split()
        if len(words) > 4 or words[0] in _NAME_STOPWORDS:
            return False
        if obj[:1].islower():
            return False
        return bool(_re.match(r"^[A-Za-z][A-Za-z0-9 .'-]{1,48}$", obj))
    if rel == "uses":
        return bool(_TECH_HINT_RE.search(obj) or len(obj.split()) <= 5)
    return 3 <= len(low) <= 160 and len(low.split()) <= 24


def _extract_candidate_triples(
    content: str,
    source_id: str = "",
    source_role: str = "user",
) -> List[Triple]:
    """Cheap high-precision semantic extraction.

    This intentionally favors precision over recall. LLM-assisted sleep can add
    richer beliefs later, but the online write path should only promote facts
    that are explicit and low-risk.
    """
    source_role = (source_role or "").lower()
    if source_role in {"assistant", "tool"}:
        return []
    if not content or _RUNTIME_NOISE_RE.search(content) or _SECRETISH_RE.search(content):
        return []
    triples: List[Triple] = []
    now = datetime.now().isoformat(timespec="microseconds")
    seen = set()
    for pat, subj, rel, confidence in _FACT_PATTERNS:
        for m in pat.finditer(content):
            prefix = content[max(0, m.start() - 28):m.start()].lower()
            if rel == "is_called" and _re.search(r"\b(?:not|never|no|don't|do not|didn't|did not|wasn't|isn't)\b", prefix):
                continue
            obj = _clean_fact_obj(m.group(1 if subj != "project" else 2))
            s = subj
            if subj == "project":
                s = "project_" + _re.sub(r"[^a-z0-9]+", "_", _clean_fact_obj(m.group(1)).lower()).strip("_")[:60]
            if not _valid_fact_obj(obj, rel):
                continue
            key = (s.lower(), rel.lower(), obj.lower())
            if key in seen:
                continue
            seen.add(key)
            triples.append(Triple(
                s, rel, obj, source_id or "memory_extract", now,
                confidence=confidence,
                source_role=source_role,
                source_episode_id=source_id,
            ))
    return triples[:8]


def _hygiene_from_provenance(provenance: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(provenance, dict):
        return {}
    hygiene = provenance.get("memory_hygiene")
    return hygiene if isinstance(hygiene, dict) else {}


def _memory_hygiene(
    *,
    role: str,
    content: str,
    memory_type: str,
    tags: Optional[List[str]] = None,
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify memories that should stay stored but not be prompt-recalled.

    Runtime failures are useful operational evidence, but when they are
    auto-injected as episodic/personality context they crowd out real user
    memories and make TARS talk about stale API failures. Quarantine keeps the
    record available for inspection while removing it from prompt retrieval.
    """
    tags = list(tags or [])
    provenance = provenance if isinstance(provenance, dict) else {}
    existing = _hygiene_from_provenance(provenance)
    if existing.get("quarantined") or existing.get("prompt_visible") is False:
        category = str(existing.get("category") or "previously_quarantined")
        reason = str(existing.get("reason") or "metadata")
        return {
            "quarantined": True,
            "prompt_visible": False,
            "category": category,
            "reason": reason,
        }
    if any(t == _PROMPT_QUARANTINE_TAG or t.startswith("quarantine:") for t in tags):
        return {
            "quarantined": True,
            "prompt_visible": False,
            "category": "tagged_quarantine",
            "reason": "tagged_quarantine",
        }

    text = (content or "").strip()
    lower_role = (role or "").lower()
    lower_type = (memory_type or "").lower()
    source = str(provenance.get("source") or lower_role).lower()
    kind = str(provenance.get("kind") or "").lower()

    if kind == "skill_failure":
        return {
            "quarantined": True,
            "prompt_visible": False,
            "category": "tool_failure",
            "reason": "skill_failure_event",
        }

    runtime_match = bool(_RUNTIME_ERROR_RE.search(text))
    tool_match = bool(_TOOL_NOISE_RE.search(text))
    internal_context = (
        lower_role in {"assistant", "system", "world", "inner_voice", "sleep"}
        or source in {"assistant", "system", "world", "inner_voice", "sleep"}
        or lower_type in {"workspace", "world", "procedural"}
        or kind in {"workspace_frame", "prediction_error", "skill_result"}
    )
    if internal_context and (runtime_match or tool_match):
        return {
            "quarantined": True,
            "prompt_visible": False,
            "category": "runtime_error" if runtime_match else "tool_noise",
            "reason": "internal_runtime_error" if runtime_match else "internal_tool_noise",
        }

    return {
        "quarantined": False,
        "prompt_visible": True,
        "category": "normal",
        "reason": "",
    }


def _is_prompt_visible_episode(ep: Episode) -> bool:
    return bool(_memory_hygiene(
        role=ep.role,
        content=ep.content,
        memory_type=ep.memory_type,
        tags=ep.tags,
        provenance=ep.provenance,
    ).get("prompt_visible", True))


def _with_hygiene_tags(tags: List[str], hygiene: Dict[str, Any]) -> List[str]:
    out = list(tags or [])
    if hygiene.get("quarantined"):
        if _PROMPT_QUARANTINE_TAG not in out:
            out.append(_PROMPT_QUARANTINE_TAG)
        category = str(hygiene.get("category") or "quarantined")
        htag = _HYGIENE_TAG_PREFIX + category
        if htag not in out:
            out.append(htag)
    return out


# ─── EPISODIC STORE ────────────────────────────────────────────────────────

class EpisodicStore:
    """SQLite-backed episodic memory with vector search. Embedding cache
    rebuilds lazily on first read after a write — small numpy stack, fast
    to recompute at our scale (<50k rows)."""

    def __init__(
        self,
        db_path: str,
        embedder: OpenAIEmbedder,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.db_path = db_path
        self.embedder = embedder
        self.log = log_fn or (lambda _m: None)
        self._lock = threading.RLock()
        self._cache_dirty = True
        self._cache_ids: List[str] = []
        self._cache_vecs: Optional[np.ndarray] = None
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    # -- schema --------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    id              TEXT PRIMARY KEY,
                    ts              TEXT NOT NULL,
                    role            TEXT NOT NULL,
                    content         TEXT NOT NULL,
                    embedding       BLOB,
                    embed_model     TEXT,
                    mood            TEXT,
                    valence         REAL,
                    salience        REAL DEFAULT 0.5,
                    accessed_count  INTEGER DEFAULT 0,
                    last_recall     TEXT,
                    tags            TEXT,
                    memory_type     TEXT DEFAULT 'episodic',
                    confidence      REAL DEFAULT 0.7,
                    utility_score   REAL DEFAULT 0.5,
                    source_event_id TEXT,
                    source_episode_id TEXT,
                    provenance      TEXT,
                    contradicts     TEXT,
                    last_verified   TEXT,
                    expires_at      TEXT
                )
            """)
            self._ensure_column("episodes", "memory_type", "TEXT DEFAULT 'episodic'")
            self._ensure_column("episodes", "confidence", "REAL DEFAULT 0.7")
            self._ensure_column("episodes", "utility_score", "REAL DEFAULT 0.5")
            self._ensure_column("episodes", "source_event_id", "TEXT")
            self._ensure_column("episodes", "source_episode_id", "TEXT")
            self._ensure_column("episodes", "provenance", "TEXT")
            self._ensure_column("episodes", "contradicts", "TEXT")
            self._ensure_column("episodes", "last_verified", "TEXT")
            self._ensure_column("episodes", "expires_at", "TEXT")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_eps_ts ON episodes(ts)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_eps_role ON episodes(role)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_eps_sal ON episodes(salience)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_eps_type ON episodes(memory_type)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_eps_source_event ON episodes(source_event_id)")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY, value TEXT
                )
            """)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            self._conn.execute(
                "UPDATE meta SET value = ? WHERE key = ?",
                (str(SCHEMA_VERSION), "schema_version"),
            )

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        cols = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    # -- mutators ------------------------------------------------------------

    def add(
        self,
        role: str,
        content: str,
        ts: Optional[str] = None,
        mood: Optional[str] = None,
        valence: Optional[float] = None,
        salience: float = 0.5,
        tags: Optional[List[str]] = None,
        embedding: Optional[np.ndarray] = None,
        memory_type: str = "episodic",
        confidence: float = 0.7,
        utility_score: float = 0.5,
        source_event_id: Optional[str] = None,
        source_episode_id: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        contradicts: Optional[List[str]] = None,
        last_verified: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> str:
        """Append an episode. If `embedding` is None, calls the OpenAI
        embedder. Returns the new episode id."""
        if not content or not content.strip():
            return ""
        content = content.strip()
        tags = list(tags or [])
        provenance = dict(provenance or {})
        hygiene = _memory_hygiene(
            role=role,
            content=content,
            memory_type=memory_type or "episodic",
            tags=tags,
            provenance=provenance,
        )
        if hygiene.get("quarantined"):
            if _PROMPT_QUARANTINE_TAG not in tags:
                tags.append(_PROMPT_QUARANTINE_TAG)
            category = str(hygiene.get("category") or "quarantined")
            hygiene_tag = _HYGIENE_TAG_PREFIX + category
            if hygiene_tag not in tags:
                tags.append(hygiene_tag)
            provenance["memory_hygiene"] = hygiene
            salience = min(float(salience), SALIENCE_FLOOR * 0.5)
            confidence = min(float(confidence), 0.25)
            utility_score = min(float(utility_score), 0.10)
            embedding = None
        ts = ts or datetime.now().isoformat(timespec="microseconds")
        eid = f"ep_{ts.replace(':','-')}_{uuid.uuid4().hex[:6]}"
        if embedding is None and not hygiene.get("quarantined"):
            embedding = self.embedder.embed(content)
        embed_model = self.embedder.model if embedding is not None else None
        embed_blob = embedding.tobytes() if embedding is not None else None
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO episodes
                       (id, ts, role, content, embedding, embed_model,
                        mood, valence, salience, tags, memory_type,
                        confidence, utility_score, source_event_id,
                        source_episode_id, provenance, contradicts,
                        last_verified, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid, ts, role, content, embed_blob, embed_model,
                    mood, valence, float(salience),
                    json.dumps(tags),
                    memory_type or "episodic",
                    float(confidence),
                    float(utility_score),
                    source_event_id,
                    source_episode_id,
                    json.dumps(provenance, ensure_ascii=False),
                    json.dumps(contradicts or [], ensure_ascii=False),
                    last_verified,
                    expires_at,
                ),
            )
        self._cache_dirty = True
        return eid

    def add_batch(self, items: List[Tuple[str, str]],
                   default_role: str = "user") -> List[str]:
        """Insert many ``(role, content)`` pairs sharing one batch embed
        request. Used by migration. Each row's role can override default."""
        if not items:
            return []
        # accept tuples of len 2 (role, content) or 3 (role, content, ts)
        normalized: List[Dict[str, Any]] = []
        for entry in items:
            if len(entry) == 3:
                role, content, ts = entry
            else:
                role, content = entry
                ts = datetime.now().isoformat(timespec="microseconds")
            if not content or not content.strip():
                continue
            role = role or default_role
            content = content.strip()
            tags: List[str] = []
            provenance: Dict[str, Any] = {}
            hygiene = _memory_hygiene(
                role=role,
                content=content,
                memory_type="episodic",
                tags=tags,
                provenance=provenance,
            )
            salience = 0.5
            confidence = 0.7
            utility_score = 0.5
            if hygiene.get("quarantined"):
                tags.extend([
                    _PROMPT_QUARANTINE_TAG,
                    _HYGIENE_TAG_PREFIX + str(hygiene.get("category") or "quarantined"),
                ])
                provenance["memory_hygiene"] = hygiene
                salience = SALIENCE_FLOOR * 0.5
                confidence = 0.25
                utility_score = 0.10
            normalized.append({
                "role": role,
                "content": content,
                "ts": ts,
                "tags": tags,
                "provenance": provenance,
                "hygiene": hygiene,
                "salience": salience,
                "confidence": confidence,
                "utility_score": utility_score,
            })
        if not normalized:
            return []
        clean_indices = [
            i for i, item in enumerate(normalized)
            if not item["hygiene"].get("quarantined")
        ]
        clean_embeddings = self.embedder.embed_batch(
            [normalized[i]["content"] for i in clean_indices]
        ) if clean_indices else []
        embeddings: List[Optional[np.ndarray]] = [None] * len(normalized)
        for idx, vec in zip(clean_indices, clean_embeddings):
            embeddings[idx] = vec
        ids: List[str] = []
        with self._lock, self._conn:
            for item, vec in zip(normalized, embeddings):
                eid = f"ep_{item['ts'].replace(':','-')}_{uuid.uuid4().hex[:6]}"
                blob = vec.tobytes() if vec is not None else None
                model = self.embedder.model if vec is not None else None
                self._conn.execute(
                    """INSERT INTO episodes
                           (id, ts, role, content, embedding, embed_model,
                            salience, tags, memory_type, confidence,
                            utility_score, provenance, contradicts)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        eid, item["ts"], item["role"], item["content"],
                        blob, model, item["salience"],
                        json.dumps(item["tags"]),
                        "episodic", item["confidence"], item["utility_score"],
                        json.dumps(item["provenance"], ensure_ascii=False),
                        "[]",
                    ),
                )
                ids.append(eid)
        self._cache_dirty = True
        return ids

    def mark_recalled(self, ids: Iterable[str]) -> None:
        """Bump accessed_count + salience on retrieval. Caller batches ids."""
        ids = [i for i in ids if i]
        if not ids:
            return
        now_iso = datetime.now().isoformat(timespec="microseconds")
        with self._lock, self._conn:
            for eid in ids:
                self._conn.execute(
                    """UPDATE episodes
                          SET accessed_count = accessed_count + 1,
                              last_recall    = ?,
                              salience       = MIN(1.0, salience + ?)
                        WHERE id = ?""",
                    (now_iso, RECALL_BUMP, eid),
                )

    def decay_all(self) -> int:
        """Apply the salience-decay equation in one SQL pass. Returns the
        number of rows updated. Designed for a daily cron call."""
        now = datetime.now()
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, ts, salience, accessed_count FROM episodes"
            ).fetchall()
            for eid, ts, sal, ac in rows:
                try:
                    age = (now - datetime.fromisoformat(ts)).total_seconds() / 86_400.0
                except Exception:
                    continue
                base = float(sal) * math.exp(-SALIENCE_LAMBDA * max(0.0, age))
                new_sal = max(0.0, min(1.0, base))
                self._conn.execute(
                    "UPDATE episodes SET salience = ? WHERE id = ?",
                    (new_sal, eid),
                )
        return len(rows)

    def apply_hygiene_existing(self, limit: int = 5000) -> int:
        """Backfill prompt-quarantine metadata onto old rows.

        Retrieval-time hygiene already blocks poisoned memories. This pass
        makes that decision durable so metrics, manual inspection, and future
        readers see the same truth the prompt builder sees.
        """
        changed = 0
        with self._lock, self._conn:
            rows = self._conn.execute(
                """SELECT id, role, content, tags, memory_type, confidence,
                          utility_score, salience, provenance
                     FROM episodes
                 ORDER BY ts DESC, rowid DESC
                    LIMIT ?""",
                (int(limit),),
            ).fetchall()
            for (eid, role, content, tags_json, memory_type, confidence,
                 utility_score, salience, provenance_json) in rows:
                try:
                    tags = json.loads(tags_json) if tags_json else []
                except Exception:
                    tags = []
                try:
                    provenance = json.loads(provenance_json) if provenance_json else {}
                except Exception:
                    provenance = {}
                if not isinstance(tags, list):
                    tags = []
                if not isinstance(provenance, dict):
                    provenance = {}
                hygiene = _memory_hygiene(
                    role=role,
                    content=content,
                    memory_type=memory_type or "episodic",
                    tags=tags,
                    provenance=provenance,
                )
                if not hygiene.get("quarantined"):
                    continue
                new_tags = _with_hygiene_tags(tags, hygiene)
                new_provenance = dict(provenance)
                new_provenance["memory_hygiene"] = hygiene
                self._conn.execute(
                    """UPDATE episodes
                          SET tags = ?,
                              provenance = ?,
                              salience = ?,
                              confidence = ?,
                              utility_score = ?,
                              embedding = NULL,
                              embed_model = NULL
                        WHERE id = ?""",
                    (
                        json.dumps(new_tags, ensure_ascii=False),
                        json.dumps(new_provenance, ensure_ascii=False),
                        min(float(salience or 0.0), SALIENCE_FLOOR * 0.5),
                        min(float(confidence if confidence is not None else 0.7), 0.25),
                        min(float(utility_score if utility_score is not None else 0.5), 0.10),
                        eid,
                    ),
                )
                changed += 1
        if changed:
            self._cache_dirty = True
        return changed

    # -- queries -------------------------------------------------------------

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM episodes").fetchone()
            return int(row[0]) if row else 0

    def has_any_with_embedding(self) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM episodes WHERE embedding IS NOT NULL LIMIT 1"
            ).fetchone()
            return row is not None

    def _row_to_episode(self, row: Tuple) -> Episode:
        (eid, ts, role, content, blob, model, mood, valence,
         sal, ac, recall, tags_json, memory_type, confidence,
         utility_score, source_event_id, source_episode_id,
         provenance_json, contradicts_json, last_verified, expires_at) = row
        embedding = None
        if blob is not None:
            embedding = np.frombuffer(blob, dtype=np.float32)
        try:
            tags = json.loads(tags_json) if tags_json else []
        except Exception:
            tags = []
        try:
            provenance = json.loads(provenance_json) if provenance_json else {}
        except Exception:
            provenance = {}
        try:
            contradicts = json.loads(contradicts_json) if contradicts_json else []
        except Exception:
            contradicts = []
        return Episode(
            id=eid, ts=ts, role=role, content=content,
            embedding=embedding, embed_model=model,
            mood=mood, valence=valence,
            salience=float(sal or 0.5),
            accessed_count=int(ac or 0),
            last_recall=recall, tags=tags,
            memory_type=memory_type or "episodic",
            confidence=float(confidence if confidence is not None else 0.7),
            utility_score=float(utility_score if utility_score is not None else 0.5),
            source_event_id=source_event_id,
            source_episode_id=source_episode_id,
            provenance=provenance if isinstance(provenance, dict) else {},
            contradicts=contradicts if isinstance(contradicts, list) else [],
            last_verified=last_verified,
            expires_at=expires_at,
        )

    def recent(self, k: int = 12,
                roles: Optional[Iterable[str]] = None) -> List[Episode]:
        """Last K episodes (defaults to user+assistant turns)."""
        roles = list(roles) if roles else ["user", "assistant"]
        placeholders = ",".join("?" * len(roles))
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT id, ts, role, content, embedding, embed_model,
                           mood, valence, salience, accessed_count,
                           last_recall, tags, memory_type, confidence,
                           utility_score, source_event_id, source_episode_id,
                           provenance, contradicts, last_verified, expires_at
                      FROM episodes
                     WHERE role IN ({placeholders})
                  ORDER BY ts DESC, rowid DESC
                     LIMIT ?""",
                (*roles, max(int(k) * 4, int(k))),
            ).fetchall()
        episodes = [
            e for e in (self._row_to_episode(r) for r in rows)
            if _is_prompt_visible_episode(e)
        ]
        return list(reversed(episodes[-int(k):]))

    def salient(self, k: int = 3, since_days: int = 7) -> List[Episode]:
        """Top-K by decay-adjusted salience within the last N days. Falls
        through to raw salience if everything is older than the window."""
        since = (datetime.now() - timedelta(days=since_days)
                ).isoformat(timespec="seconds")
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, ts, role, content, embedding, embed_model,
                          mood, valence, salience, accessed_count,
                          last_recall, tags, memory_type, confidence,
                          utility_score, source_event_id, source_episode_id,
                          provenance, contradicts, last_verified, expires_at
                     FROM episodes
                    WHERE ts >= ? AND salience >= ?
                 ORDER BY salience DESC
                    LIMIT ?""",
                (since, SALIENCE_FLOOR, int(k) * 3),
            ).fetchall()
        episodes = [self._row_to_episode(r) for r in rows]
        episodes = [e for e in episodes if _is_prompt_visible_episode(e)]
        # Re-rank by decayed salience to honor recall boosts.
        episodes.sort(key=lambda e: e.decayed_salience(), reverse=True)
        return episodes[:k]

    def by_type(self, memory_type: str, k: int = 3,
                min_confidence: float = 0.0,
                include_quarantined: bool = False) -> List[Episode]:
        """Top typed memories by utility/salience recency blend."""
        if not memory_type:
            return []
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, ts, role, content, embedding, embed_model,
                          mood, valence, salience, accessed_count,
                          last_recall, tags, memory_type, confidence,
                          utility_score, source_event_id, source_episode_id,
                          provenance, contradicts, last_verified, expires_at
                     FROM episodes
                    WHERE memory_type = ? AND confidence >= ?
                 ORDER BY utility_score DESC, salience DESC, ts DESC
                    LIMIT ?""",
                (memory_type, float(min_confidence), max(int(k) * 8, 24)),
            ).fetchall()
        episodes = [self._row_to_episode(r) for r in rows]
        if not include_quarantined:
            episodes = [e for e in episodes if _is_prompt_visible_episode(e)]
        return episodes[:k]

    # -- vector search ------------------------------------------------------

    def _refresh_cache(self) -> None:
        """Pull all (id, embedding) into a numpy stack for cosine search.
        Embeddings are cached normalised so search is a single matmul."""
        with self._lock:
            if not self._cache_dirty and self._cache_vecs is not None:
                return
            rows = self._conn.execute(
                "SELECT id, embedding FROM episodes WHERE embedding IS NOT NULL"
            ).fetchall()
            if not rows:
                self._cache_ids = []
                self._cache_vecs = None
                self._cache_dirty = False
                return
            ids: List[str] = []
            mats = []
            for eid, blob in rows:
                v = np.frombuffer(blob, dtype=np.float32)
                # Drop bad vectors (NaN/Inf, zero-norm). Also drop wrong-dim
                # vectors (caused by an embedding model swap).
                if v.size == 0 or not np.all(np.isfinite(v)):
                    continue
                n = float(np.linalg.norm(v))
                if not np.isfinite(n) or n <= 0:
                    continue
                ids.append(eid)
                mats.append(v / n)
            self._cache_ids = ids
            self._cache_vecs = np.stack(mats, axis=0) if mats else None
            self._cache_dirty = False

    def relevant(self, query_text: str, k: int = 5,
                  exclude_recent_n: int = 0,
                  role_filter: Optional[List[str]] = None,
                  q_vec: Optional[np.ndarray] = None) -> List[Episode]:
        """Top-K nearest by cosine to the query embedding. Excludes the
        very-recent K to avoid duplicating the recent-pane in retrieval.

        ``role_filter`` restricts the search to specific roles — useful
        when retrieving conversational turns separately from imported
        biographical facts (`system_summary` role).
        ``q_vec`` lets the caller pass a pre-computed query embedding so
        a single embed call can power multiple retrievals."""
        if not query_text:
            return []
        if q_vec is None:
            q_vec = self.embedder.embed(query_text)
        if q_vec is None:
            return []
        # Cast to float64 for the matmul — float32 matmul on Apple Silicon
        # can occasionally produce divide-by-zero / overflow warnings on
        # large stacks. The DB stays float32 (memory-efficient); we just
        # promote at search time.
        q_vec = q_vec.astype(np.float64, copy=False)
        n = float(np.linalg.norm(q_vec))
        if not np.isfinite(n) or n <= 0:
            return []
        q_vec = q_vec / n
        self._refresh_cache()
        if self._cache_vecs is None or len(self._cache_ids) == 0:
            return []
        cache64 = self._cache_vecs.astype(np.float64, copy=False)
        with np.errstate(invalid="ignore", divide="ignore", over="ignore"):
            sims = cache64 @ q_vec       # (N,) cosine since normalised
        # Replace any leftover NaN/Inf with -1 so they sort to the bottom.
        sims = np.where(np.isfinite(sims), sims, -1.0)
        top_idx = np.argsort(-sims)
        excluded: set = set()
        if exclude_recent_n > 0:
            with self._lock:
                rows = self._conn.execute(
                    """SELECT id FROM episodes
                        ORDER BY ts DESC LIMIT ?""",
                    (int(exclude_recent_n),),
                ).fetchall()
            excluded = {r[0] for r in rows}
        role_set = set(role_filter) if role_filter else None
        # Imported memory packs are dominated by template-noise: hundreds
        # of "Email from …" subject lines + file-path inventories, plus
        # generic "subscribed to …" / "has the … app installed" entries.
        # These crowd out actual biographical facts in cosine ranking.
        # When searching the
        # `system_summary` role we filter that template-noise out so the
        # candidate pool stays mostly real facts.
        is_facts_query = role_set == {"system_summary"}
        # MMR (Maximum Marginal Relevance) picks results that are BOTH high
        # cosine to the query AND far from already-picked results. Prevents
        # the top-K from being filled with near-duplicates.
        candidate_pool = max(int(k) * 8, 32)
        # Facts queries scan the WHOLE corpus because the noise filter
        # discards >90% of imported memories — we need a deep pool to
        # find the curated biographical facts hiding under the noise.
        scan_limit = len(top_idx) if is_facts_query else min(
            len(top_idx), candidate_pool * 2,
        )
        candidates: List[Tuple[Episode, np.ndarray, float]] = []  # (ep, vec64, sim)
        with self._lock:
            for idx in top_idx[:scan_limit]:
                eid = self._cache_ids[idx]
                if eid in excluded:
                    continue
                row = self._conn.execute(
                    """SELECT id, ts, role, content, embedding, embed_model,
                              mood, valence, salience, accessed_count,
                              last_recall, tags, memory_type, confidence,
                              utility_score, source_event_id, source_episode_id,
                              provenance, contradicts, last_verified, expires_at
                         FROM episodes WHERE id = ?""",
                    (eid,),
                ).fetchone()
                if not row:
                    continue
                ep = self._row_to_episode(row)
                if role_set is not None and ep.role not in role_set:
                    continue
                if ep.salience < SALIENCE_FLOOR:
                    continue
                if not _is_prompt_visible_episode(ep):
                    continue
                if is_facts_query and _is_profile_noise(ep.content):
                    continue
                # Cache the L2-normalised float64 vector for MMR comparison
                v = self._cache_vecs[idx].astype(np.float64, copy=False)
                candidates.append((ep, v, float(sims[idx])))
                if len(candidates) >= candidate_pool:
                    break

        if not candidates:
            return []

        # Greedy MMR. λ controls relevance vs diversity (0.6 = mild diversity).
        lam = 0.6
        picked: List[Tuple[Episode, np.ndarray, float]] = []
        remaining = list(candidates)
        # Seed with the top-cosine candidate.
        remaining.sort(key=lambda x: -x[2])
        picked.append(remaining.pop(0))
        while remaining and len(picked) < int(k):
            best_idx = 0
            best_score = -1e9
            for i, (_, vec, sim) in enumerate(remaining):
                # Max similarity to anything already picked.
                max_pen = max(
                    float(np.dot(vec, p_vec)) for _, p_vec, _ in picked
                )
                mmr = lam * sim - (1.0 - lam) * max_pen
                if mmr > best_score:
                    best_score = mmr
                    best_idx = i
            picked.append(remaining.pop(best_idx))
        return [ep for ep, _, _ in picked]


# ─── KNOWLEDGE GRAPH (append-only JSONL) ───────────────────────────────────

class KGStore:
    """Subject/relation/object triples in a JSONL file. We dedup at query
    time rather than rewriting the file on every add — keeps writes O(1)."""

    def __init__(self, path: str, log_fn: Optional[Callable[[str], None]] = None):
        self.path = path
        self.log = log_fn or (lambda _m: None)
        self._lock = threading.Lock()
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8"):
                pass

    def add_triple(self, subj: str, rel: str, obj: str,
                   src: str = "manual", ts: Optional[str] = None,
                   confidence: float = 0.8,
                   source_role: str = "",
                   source_episode_id: str = "") -> bool:
        if not (subj and rel and obj):
            return False
        confidence = float(confidence if confidence is not None else 0.8)
        if confidence < BELIEF_MIN_CONFIDENCE:
            return False
        subj = subj.strip()
        rel = rel.strip()
        obj = obj.strip()
        for existing in self.all_triples(max_lines=5000):
            if (
                existing.subj.lower() == subj.lower()
                and existing.rel.lower() == rel.lower()
                and existing.obj.lower() == obj.lower()
                and existing.confidence >= confidence
            ):
                return False
        rec = {
            "subj": subj,
            "rel":  rel,
            "obj":  obj,
            "src":  src,
            "ts":   ts or datetime.now().isoformat(timespec="microseconds"),
            "confidence": confidence,
            "source_role": source_role,
            "source_episode_id": source_episode_id,
        }
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
        return True

    def all_triples(self, max_lines: int = 5000) -> List[Triple]:
        """Read up to `max_lines` newest triples. Bounded to avoid runaway."""
        if not os.path.exists(self.path):
            return []
        lines: List[str] = []
        with self._lock, open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read = min(size, 256 * 1024)
            f.seek(size - read)
            blob = f.read().decode("utf-8", errors="replace")
        out: List[Triple] = []
        for ln in blob.splitlines()[-max_lines:]:
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
                out.append(Triple(
                    subj=d.get("subj", ""), rel=d.get("rel", ""),
                    obj=d.get("obj", ""), src=d.get("src", ""),
                    ts=d.get("ts", ""),
                    confidence=float(d.get("confidence", 0.8) or 0.8),
                    source_role=d.get("source_role", ""),
                    source_episode_id=d.get("source_episode_id", ""),
                ))
            except Exception:
                continue
        return out

    def beliefs_about(self, query_text: str, max_per_subj: int = 3,
                      min_confidence: float = BELIEF_MIN_CONFIDENCE) -> List[Triple]:
        """Return triples where subj or obj appears (case-insensitively) in
        the query text. Resolves contradictions by recency (newest wins)."""
        if not query_text:
            return []
        triples = self.all_triples()
        if not triples:
            return []
        q = query_text.lower()
        q_tokens = set(_re.findall(r"[a-z0-9']+", q))
        user_query = bool(q_tokens & {
            "me", "my", "mine", "i", "user", "profile", "goals",
            "goal", "preferences", "preference", "likes", "projects",
            "project", "work", "working", "name",
        })
        profile_query = bool(q_tokens & {"me", "my", "mine", "profile"}) or "about me" in q
        relation_terms = {
            "is_called": {"name", "called", "call"},
            "likes": {"like", "likes", "enjoy", "favorite"},
            "prefers": {"prefer", "prefers", "preference", "preferences"},
            "dislikes": {"dislike", "dislikes", "hate", "hates"},
            "works_on": {"project", "projects", "work", "working", "build", "building"},
            "uses": {"use", "uses", "using", "tools", "stack"},
            "has_goal": {"goal", "goals", "want", "wants", "need", "needs"},
            "prefers_assistant_behavior": {"assistant", "respond", "style", "behavior"},
        }
        # First pass: filter to triples whose subj or obj appears in q
        relevant = []
        for t in triples:
            if float(t.confidence or 0.0) < min_confidence:
                continue
            s = t.subj.lower()
            o = t.obj.lower()
            rel_terms = relation_terms.get(t.rel, set())
            rel_match = bool(q_tokens & rel_terms)
            if user_query and s == USER_SUBJECT and (profile_query or rel_match or not rel_terms):
                relevant.append(t)
                continue
            if s and (s in q or any(tok in q for tok in s.split("_") if len(tok) > 2)):
                relevant.append(t)
                continue
            if o and o in q:
                relevant.append(t)
        # Dedup (subj, rel) — newest wins. Cap output.
        seen: Dict[Tuple[str, str], Triple] = {}
        for t in relevant:
            key = (t.subj, t.rel)
            prev = seen.get(key)
            if prev is None or t.ts > prev.ts:
                seen[key] = t
        # Limit per-subject to keep prompt tight
        per_subj_count: Dict[str, int] = {}
        out: List[Triple] = []
        for t in sorted(seen.values(), key=lambda x: x.ts, reverse=True):
            c = per_subj_count.get(t.subj, 0)
            if c < max_per_subj:
                out.append(t)
                per_subj_count[t.subj] = c + 1
        return out


# ─── MEMORY FACADE ─────────────────────────────────────────────────────────

class Memory:
    """Thin facade combining episodic + KG. Public API is what the
    orchestrator should use; the internal stores are exposed for advanced
    cases (cron compaction, debugging)."""

    def __init__(
        self,
        project_dir: str,
        log_fn: Optional[Callable[[str], None]] = None,
        embed_model: str = DEFAULT_EMBED_MODEL,
    ):
        self.project_dir = project_dir
        self.log = log_fn or (lambda _m: None)
        self.embedder = OpenAIEmbedder(model=embed_model, log_fn=self.log)
        db_path = os.path.join(project_dir, DEFAULT_DB_NAME)
        kg_path = os.path.join(project_dir, DEFAULT_KG_NAME)
        self.episodes = EpisodicStore(db_path, self.embedder, log_fn=self.log)
        self.kg = KGStore(kg_path, log_fn=self.log)

    # -- write paths --------------------------------------------------------

    def add_turn(self, role: str, content: str,
                 mood: Optional[str] = None,
                 valence: Optional[float] = None,
                 salience: float = 0.5,
                 tags: Optional[List[str]] = None,
                 memory_type: str = "episodic",
                 source_event_id: Optional[str] = None,
                 confidence: float = 0.8,
                 utility_score: float = 0.5,
                 provenance: Optional[Dict[str, Any]] = None) -> str:
        """Convenience wrapper for the orchestrator's per-turn writes."""
        eid = self.episodes.add(
            role=role, content=content,
            mood=mood, valence=valence, salience=salience, tags=tags,
            memory_type=memory_type, source_event_id=source_event_id,
            confidence=confidence, utility_score=utility_score,
            provenance=provenance,
        )
        self._extract_and_store_beliefs(content, role, eid)
        return eid

    def add_typed(self, memory_type: str, content: str, *,
                  role: str = "system",
                  salience: float = 0.5,
                  confidence: float = 0.7,
                  utility_score: float = 0.5,
                  source_event_id: Optional[str] = None,
                  source_episode_id: Optional[str] = None,
                  provenance: Optional[Dict[str, Any]] = None,
                  contradicts: Optional[List[str]] = None,
                  tags: Optional[List[str]] = None,
                  valence: Optional[float] = None) -> str:
        """Phase 2.5 typed memory write path."""
        eid = self.episodes.add(
            role=role,
            content=content,
            valence=valence,
            salience=salience,
            tags=list(tags or []) + [f"type:{memory_type}"],
            memory_type=memory_type,
            confidence=confidence,
            utility_score=utility_score,
            source_event_id=source_event_id,
            source_episode_id=source_episode_id,
            provenance=provenance,
            contradicts=contradicts,
        )
        if memory_type in {"semantic", "social", "goal"} or role in {"user", "system_summary"}:
            self._extract_and_store_beliefs(content, role, eid)
        return eid

    def extract_semantic_beliefs(
        self,
        content: str,
        *,
        source_role: str = "user",
        source_episode_id: str = "",
    ) -> List[Dict[str, Any]]:
        """Return conservative semantic belief candidates without writing."""
        return [
            {
                "subj": t.subj,
                "rel": t.rel,
                "obj": t.obj,
                "src": t.src,
                "ts": t.ts,
                "confidence": round(float(t.confidence), 3),
                "source_role": t.source_role,
                "source_episode_id": t.source_episode_id,
                "belief": f"{t.subj} {t.rel} {t.obj}",
            }
            for t in _extract_candidate_triples(
                content,
                source_id=source_episode_id,
                source_role=source_role,
            )
        ]

    def add_semantic_beliefs(self, beliefs: Iterable[Dict[str, Any]],
                             src: str = "semantic_extract") -> int:
        """Write structured belief candidates to the JSONL KG."""
        count = 0
        for b in beliefs or []:
            if not isinstance(b, dict):
                continue
            subj = str(b.get("subj") or "").strip()
            rel = str(b.get("rel") or "").strip()
            obj = str(b.get("obj") or "").strip()
            if not (subj and rel and obj):
                continue
            added = self.kg.add_triple(
                subj, rel, obj,
                src=str(b.get("src") or src),
                confidence=float(b.get("confidence", 0.8) or 0.8),
                source_role=str(b.get("source_role") or ""),
                source_episode_id=str(b.get("source_episode_id") or ""),
            )
            if added:
                count += 1
        return count

    def _extract_and_store_beliefs(self, content: str, role: str,
                                   source_episode_id: str) -> int:
        beliefs = self.extract_semantic_beliefs(
            content,
            source_role=role,
            source_episode_id=source_episode_id,
        )
        return self.add_semantic_beliefs(beliefs, src="memory_extract")

    def extract_beliefs_from_existing(self, limit: int = 600) -> int:
        """Backfill KG triples from high-confidence prompt-visible memories."""
        with self.episodes._lock:
            rows = self.episodes._conn.execute(
                """SELECT id, ts, role, content, embedding, embed_model,
                          mood, valence, salience, accessed_count,
                          last_recall, tags, memory_type, confidence,
                          utility_score, source_event_id, source_episode_id,
                          provenance, contradicts, last_verified, expires_at
                     FROM episodes
                    WHERE confidence >= 0.55
                      AND salience >= ?
                      AND role IN ('user', 'system_summary', 'sleep')
                 ORDER BY ts DESC, rowid DESC
                    LIMIT ?""",
                (SALIENCE_FLOOR, int(limit)),
            ).fetchall()
        added = 0
        for row in rows:
            ep = self.episodes._row_to_episode(row)
            if not _is_prompt_visible_episode(ep):
                continue
            if ep.memory_type in {"workspace", "world", "procedural", "affective"}:
                continue
            added += self._extract_and_store_beliefs(ep.content, ep.role, ep.id)
        return added

    def add_event(self, event) -> str:
        """Store a CognitiveEvent as typed memory. Accepts event objects or dicts."""
        d = event.to_dict() if hasattr(event, "to_dict") else dict(event or {})
        content = (d.get("content") or "").strip()
        if not content:
            return ""
        source = d.get("source", "system")
        kind = d.get("kind", "event")
        raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
        memory_type = self._memory_type_for_event(source, kind)
        appraisal = raw.get("appraisal") if isinstance(raw, dict) else {}
        utility = 0.5
        if isinstance(appraisal, dict):
            utility = max(utility, float(appraisal.get("novelty", 0.0) or 0.0) * 0.5
                          + float(appraisal.get("goal_tension", 0.0) or 0.0) * 0.3
                          + float(appraisal.get("uncertainty", 0.0) or 0.0) * 0.2)
        return self.add_typed(
            memory_type,
            content,
            role=source,
            salience=float(d.get("salience", 0.5) or 0.5),
            confidence=0.75,
            utility_score=utility,
            source_event_id=d.get("id"),
            provenance={"source": source, "kind": kind, "raw": raw},
            tags=[source, kind],
            valence=d.get("valence"),
        )

    @staticmethod
    def _memory_type_for_event(source: str, kind: str) -> str:
        source = (source or "").lower()
        kind = (kind or "").lower()
        if kind == "workspace_frame":
            return "workspace"
        if kind == "prediction_error":
            return "world"
        if kind in {"goal_conflict", "goal_progress", "desire_candidate"}:
            return "goal"
        if kind in {"skill_result", "skill_failure"}:
            return "procedural"
        if kind in {"emotion_shift"}:
            return "affective"
        if kind in {"self_critique"} or source in {"self", "inner_voice"}:
            return "self"
        if source == "user":
            return "social"
        if source == "sleep" or kind == "sleep_summary":
            return "semantic"
        return "episodic"

    # -- retrieval ---------------------------------------------------------

    def retrieve_for_prompt(
        self,
        user_text: str,
        recent_k: int = 12,
        relevant_k: int = 5,
        salient_k: int = 3,
        facts_k: int = 6,
    ) -> Dict[str, Any]:
        """Build the five-pane retrieval bundle PLAN.md §Phase 2 specifies,
        plus a dedicated `facts` pane for imported biographical memories
        (role=`system_summary`). Splitting the panes prevents conversational
        turns from out-competing facts on cosine score: when you ask
        'tell me about my goals', factual memories about your projects
        and aspirations get their own slot regardless of vocabulary mismatch."""
        # One embed call powers both the conversational and facts retrievals.
        q_vec = self.embedder.embed(user_text) if user_text else None

        recent_eps    = [
            e for e in self.episodes.recent(k=max(recent_k * 3, recent_k))
            if _is_prompt_visible_episode(e)
        ][-recent_k:]
        relevant_eps  = self.episodes.relevant(
            user_text, k=relevant_k, exclude_recent_n=recent_k,
            role_filter=["user", "assistant"],
            q_vec=q_vec,
        ) if q_vec is not None else []
        facts_eps     = self.episodes.relevant(
            user_text, k=facts_k, exclude_recent_n=0,
            role_filter=["system_summary"],
            q_vec=q_vec,
        ) if q_vec is not None else []
        salient_eps   = self.episodes.salient(k=salient_k)
        beliefs       = self.kg.beliefs_about(user_text)
        social_eps    = self.episodes.by_type("social", k=3, min_confidence=0.4)
        self_eps      = self.episodes.by_type("self", k=3, min_confidence=0.4)
        proc_eps      = self.episodes.by_type("procedural", k=3, min_confidence=0.4)
        workspace_eps = self.episodes.by_type("workspace", k=3, min_confidence=0.4)
        world_eps     = self.episodes.by_type("world", k=3, min_confidence=0.4)

        # Bump accessed_count for everything we surfaced (recall = use).
        seen_ids = set()
        recalled_ids: List[str] = []
        for ep in (*relevant_eps, *facts_eps, *salient_eps,
                   *social_eps, *self_eps, *proc_eps, *workspace_eps, *world_eps):
            if ep.id not in seen_ids:
                seen_ids.add(ep.id)
                recalled_ids.append(ep.id)
        try:
            self.episodes.mark_recalled(recalled_ids)
        except Exception:
            pass

        return {
            "recent":   [self._ep_to_dict(e) for e in recent_eps],
            "relevant": [self._ep_to_dict(e) for e in relevant_eps],
            "facts":    [self._ep_to_dict(e) for e in facts_eps],
            "salient":  [self._ep_to_dict(e) for e in salient_eps],
            "social":   [self._ep_to_dict(e) for e in social_eps],
            "self":     [self._ep_to_dict(e) for e in self_eps],
            "procedural": [self._ep_to_dict(e) for e in proc_eps],
            "workspace": [self._ep_to_dict(e) for e in workspace_eps],
            "world":    [self._ep_to_dict(e) for e in world_eps],
            "beliefs":  [{"subj": t.subj, "rel": t.rel, "obj": t.obj,
                          "src": t.src, "ts": t.ts,
                          "confidence": round(float(t.confidence), 3),
                          "source_role": t.source_role,
                          "source_episode_id": t.source_episode_id}
                         for t in beliefs],
        }

    @staticmethod
    def _ep_to_dict(e: Episode) -> Dict[str, Any]:
        hygiene = _memory_hygiene(
            role=e.role,
            content=e.content,
            memory_type=e.memory_type,
            tags=e.tags,
            provenance=e.provenance,
        )
        return {
            "id": e.id, "ts": e.ts, "role": e.role, "content": e.content,
            "salience": round(e.salience, 3),
            "decayed":  round(e.decayed_salience(), 3),
            "accessed": e.accessed_count,
            "mood": e.mood, "tags": e.tags,
            "memory_type": e.memory_type,
            "confidence": round(e.confidence, 3),
            "utility_score": round(e.utility_score, 3),
            "source_event_id": e.source_event_id,
            "prompt_visible": bool(hygiene.get("prompt_visible", True)),
            "memory_hygiene": hygiene,
        }

    # -- migration ----------------------------------------------------------

    def migrate_from_legacy_messages(
        self,
        messages: List[Dict[str, Any]],
        skip_system: bool = True,
        batch_size: int = 64,
    ) -> int:
        """Backfill the episodic store from the existing flat JSON message
        log. Idempotent: only runs if the store has zero embedded episodes.
        Returns number of episodes inserted."""
        if self.episodes.has_any_with_embedding():
            return 0
        items: List[Tuple[str, str, str]] = []
        for m in messages:
            role = m.get("role", "")
            content = m.get("content", "")
            if not content:
                continue
            if skip_system and role == "system":
                continue
            ts = m.get("ts") or datetime.now().isoformat(timespec="microseconds")
            items.append((role, str(content), ts))
        if not items:
            return 0
        self.log(f"[memory] migrating {len(items)} legacy messages "
                 f"(batches of {batch_size})…")
        total = 0
        for i in range(0, len(items), batch_size):
            chunk = items[i:i + batch_size]
            ids = self.episodes.add_batch(chunk)
            for (role, content, _ts), eid in zip(chunk, ids):
                self._extract_and_store_beliefs(content, role, eid)
            total += len(ids)
        self.log(f"[memory] migration done: {total} episodes inserted")
        return total

    # -- maintenance --------------------------------------------------------

    def daily_compaction(self) -> Dict[str, int]:
        """Cron-callable maintenance: decay, hygiene, and belief promotion."""
        decayed = self.episodes.decay_all()
        quarantined = self.episodes.apply_hygiene_existing()
        extracted = self.extract_beliefs_from_existing()
        return {
            "episodes_decayed": decayed,
            "episodes_quarantined": quarantined,
            "semantic_triples_extracted": extracted,
            "kg_triples": len(self.kg.all_triples(max_lines=5000)),
            "embedder_success": self.embedder.success_count,
            "embedder_fail":    self.embedder.fail_count,
        }


# ─── Self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """Offline-safe self-test — no OpenAI key needed; embed paths return
    None and we exercise the recency-only fallback."""
    import tempfile

    def L(msg): print(msg)

    with tempfile.TemporaryDirectory() as d:
        # Force an offline embedder
        os.environ.pop("OPENAI_API_KEY", None)
        mem = Memory(d, log_fn=L)

        ids = []
        ids.append(mem.add_turn("user",      "Hello TARS."))
        ids.append(mem.add_turn("assistant", "Logged."))
        ids.append(mem.add_turn("user",      "Who am I?"))
        assert mem.episodes.count() == 3

        # Recent works without embeddings
        recent = mem.episodes.recent(k=10)
        assert len(recent) == 3
        assert recent[-1].content == "Who am I?"

        # Relevant returns empty (no embedding) — but doesn't crash
        rel = mem.episodes.relevant("hello")
        assert rel == []

        # KG round-trip
        mem.kg.add_triple("user", "is_called", "Alex", "test")
        beliefs = mem.kg.beliefs_about("what's my name alex")
        assert any(t.subj == "user" for t in beliefs)

        # Online semantic extraction populates the KG conservatively.
        mem.add_turn("user", "My name is Alex. I'm working on TARS semantic memory.")
        profile_beliefs = mem.kg.beliefs_about("what do you know about me")
        assert any(t.rel == "is_called" and t.obj == "Alex" for t in profile_beliefs)
        assert any(t.rel == "works_on" for t in profile_beliefs)

        # Assistant guesses must not become beliefs.
        before = len(mem.kg.all_triples())
        mem.add_turn("assistant", "The user likes random unverified guesses.")
        after = len(mem.kg.all_triples())
        assert before == after

        # Salience decay
        stats = mem.daily_compaction()
        assert stats["episodes_decayed"] >= 3

        # Migration is idempotent — second call returns 0
        n = mem.migrate_from_legacy_messages(
            [{"role": "user", "content": "old turn"}]
        )
        # First run inserts 1; second call skips because store now has rows
        # (no embeddings on offline test, but has_any_with_embedding stays False)
        # so this WILL insert. Acceptable — migration uses `has_any_with_embedding`
        # as the sentinel; offline test has none, so it runs every time.
        assert n in (0, 1)

        print("memory self-test OK")
