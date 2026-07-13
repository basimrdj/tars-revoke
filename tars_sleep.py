"""
TARS Sleep / Consolidation  (Phase 2.5G)
========================================

Offline consolidation for the mind simulator. This is not a second model and
does not block the voice loop. It performs deterministic cleanup and writes
reports that can later be upgraded with stronger-model consolidation.

Modes:
  * micro_sleep  - fast maintenance: duplicates, memory decay, workspace themes
  * deep_sleep   - daily consolidation: themes, semantic/social memories
  * weekly_sleep - slower review: traits, stale concerns, skill candidates

Reports are persisted under tars_sleep_reports/.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


REPORT_DIR = "tars_sleep_reports"
THOUGHTS_FILE = "tars_thoughts.jsonl"
WORKSPACE_FILE = "tars_workspace.jsonl"
EVENTS_FILE = "tars_events.jsonl"

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
_ASSERTION_TERMS = {
    "prefer", "prefers", "preferred", "want", "wants", "wanted", "need",
    "needs", "needed", "use", "uses", "used", "must", "should", "avoid",
    "requires", "require", "means", "done", "active", "inactive", "working",
    "works", "support", "supports", "cannot", "can't", "wont", "won't",
}
_LOW_SIGNAL_TERMS = {
    "okay", "ok", "yeah", "yes", "no", "thanks", "thank", "lol", "hmm",
    "uh", "um", "test", "testing",
}
_NEGATIVE_MARKERS = (
    " can't ", " cannot ", " won't ", " not ", " never ", " no longer ",
    " doesn't ", " does not ", " isn't ", " aren't ", " failed ", " broken ",
    " inactive ", " missing ", " unavailable ", " blocked ",
)
_POSITIVE_MARKERS = (
    " can ", " will ", " works ", " working ", " active ", " available ",
    " enabled ", " implemented ", " done ", " supports ", " has ",
)
_ASSERTION_PATTERNS = (
    " prefer", " wants", " needs", " must ", " should ", " do not ", " don't ",
    " cannot ", " can't ", " is ", " are ", " uses ", " requires ", " goal:",
    " focus ", " truth", " reality", " active", " inactive", " working",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _safe_date() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _safe_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:5]


def _atomic_json_write(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)


def _compact(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _read_jsonl_tail(path: str, max_bytes: int = 512 * 1024) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read = min(size, max_bytes)
            f.seek(size - read)
            blob = f.read().decode("utf-8", errors="replace")
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _since(records: Iterable[Dict[str, Any]], hours: float) -> List[Dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out = []
    for rec in records:
        dt = _parse_iso(str(rec.get("ts", "") or ""))
        if dt is None:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt >= cutoff:
            out.append(rec)
    return out


def _tokens(text: str) -> List[str]:
    raw = _TOKEN_RE.findall((text or "").lower())
    return [t for t in raw if t not in _STOPWORDS and len(t) > 2]


def _norm(text: str) -> str:
    return " ".join(_tokens(text))[:120]


def _jaccard(a: str, b: str) -> float:
    ta = set(_tokens(a))
    tb = set(_tokens(b))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / max(1, len(ta | tb))


def _line_sentences(text: str) -> List[str]:
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [_compact(p, 260) for p in parts if len(_tokens(p)) >= 3]


def _topic_key(text: str, limit: int = 8) -> str:
    toks = [
        t for t in _tokens(text)
        if t not in _ASSERTION_TERMS and t not in _LOW_SIGNAL_TERMS
    ]
    return " ".join(toks[:limit])


def _claim_polarity(text: str) -> Optional[str]:
    low = f" {(text or '').lower()} "
    if any(marker in low for marker in _NEGATIVE_MARKERS):
        return "negative"
    if any(marker in low for marker in _POSITIVE_MARKERS):
        return "positive"
    if any(marker in low for marker in (" maybe ", " might ", " unsure ", " uncertain ")):
        return "uncertain"
    return None


class SleepEngine:
    """Deterministic consolidation engine."""

    def __init__(
        self,
        project_dir: str,
        log_fn: Optional[Callable[[str], None]] = None,
        *,
        memory: Any = None,
        mind: Any = None,
        self_model: Any = None,
    ):
        self.project_dir = project_dir
        self.report_dir = os.path.join(project_dir, REPORT_DIR)
        self.log = log_fn or (lambda _m: None)
        self.memory = memory
        self.mind = mind
        self.self_model = self_model
        self._lock = threading.RLock()
        os.makedirs(self.report_dir, exist_ok=True)

    def set_runtime(self, *, memory: Any = None, mind: Any = None,
                    self_model: Any = None) -> None:
        if memory is not None:
            self.memory = memory
        if mind is not None:
            self.mind = mind
        if self_model is not None:
            self.self_model = self_model

    def micro_sleep(self) -> Dict[str, Any]:
        """Fast, safe maintenance. Can run every couple of hours."""
        with self._lock:
            thoughts, thought_catchup = self._window_or_tail(self._thoughts(), hours=8, limit=80)
            frames, frame_catchup = self._window_or_tail(self._workspace_frames(), hours=8, limit=80)
            events, event_catchup = self._window_or_tail(self._events(), hours=8, limit=160)
            items = self._text_items(events, thoughts, frames)

            duplicates = self._duplicate_groups(thoughts, key="content")
            themes = self._themes(
                [item["content"] for item in items],
                limit=8,
            )
            beliefs = self._semantic_beliefs(items, max_items=3)
            contradictions = self._contradiction_candidates(items)
            beliefs = self._mark_belief_truth_status(beliefs, contradictions)
            archive_candidates = self._archive_candidates(items, duplicates=duplicates)
            quarantine_candidates = self._quarantine_candidates(items)
            concerns = self._concerns_snapshot()

            memory_stats = {}
            if self.memory is not None:
                try:
                    memory_stats = self.memory.daily_compaction()
                except Exception as exc:
                    memory_stats = {"error": str(exc)[:180]}

            mind_stats = {}
            if self.mind is not None:
                try:
                    mind_stats = self.mind.daily_compact()
                except Exception as exc:
                    mind_stats = {"error": str(exc)[:180]}

            report = self._base_report("micro")
            report.update({
                "episodes_reviewed": len(events),
                "thoughts_reviewed": len(thoughts),
                "workspace_frames_reviewed": len(frames),
                "themes": themes,
                "new_semantic_beliefs": beliefs,
                "updated_social_models": [],
                "updated_self_model": {},
                "contradictions": contradictions,
                "contradiction_candidates": contradictions,
                "archive_candidates": archive_candidates,
                "quarantine_candidates": quarantine_candidates,
                "forgotten_or_archived": archive_candidates + quarantine_candidates,
                "skill_candidates": self._skill_candidates(events),
                "concerns": concerns,
                "trait_candidates": self._trait_candidates(thoughts, events),
                "duplicates_merged": sum(max(0, len(g.get("ids", [])) - 1) for g in duplicates),
                "duplicate_groups": duplicates[:8],
                "memory_stats": memory_stats,
                "mind_stats": mind_stats,
                "catchup_mode": bool(thought_catchup or frame_catchup or event_catchup),
                "catchup_sources": {
                    "thoughts": bool(thought_catchup),
                    "workspace_frames": bool(frame_catchup),
                    "events": bool(event_catchup),
                },
            })

            self._write_typed_memories(report)
            self._update_self_model(report)
            return self._write_report(report)

    def deep_sleep(self) -> Dict[str, Any]:
        """Phase 2.5R-F: Daily consolidation with model-assisted processing if available."""
        with self._lock:
            events, event_catchup = self._window_or_tail(self._events(), hours=24, limit=300)
            thoughts, thought_catchup = self._window_or_tail(self._thoughts(), hours=24, limit=160)
            frames, frame_catchup = self._window_or_tail(self._workspace_frames(), hours=24, limit=160)
            items = self._text_items(events, thoughts, frames)
            contents = [item["content"] for item in items]
            themes = self._themes(contents, limit=10)
            beliefs = self._semantic_beliefs(items, max_items=8)
            social = self._social_models(events)
            contradictions = self._contradiction_candidates(items)
            beliefs = self._mark_belief_truth_status(beliefs, contradictions)
            archive_candidates = self._archive_candidates(items)
            quarantine_candidates = self._quarantine_candidates(items)

            report = self._base_report("deep")
            report.update({
                "episodes_reviewed": len(events),
                "thoughts_reviewed": len(thoughts),
                "workspace_frames_reviewed": len(frames),
                "themes": themes,
                "new_semantic_beliefs": beliefs,
                "updated_social_models": social,
                "updated_self_model": {
                    "source": "deep_sleep",
                    "themes_seen": len(themes),
                    "semantic_beliefs_seen": len(beliefs),
                    "contradictions_seen": len(contradictions),
                    "archive_candidates_seen": len(archive_candidates),
                    "quarantine_candidates_seen": len(quarantine_candidates),
                },
                "contradictions": contradictions,
                "contradiction_candidates": contradictions,
                "archive_candidates": archive_candidates,
                "quarantine_candidates": quarantine_candidates,
                "forgotten_or_archived": archive_candidates + quarantine_candidates,
                "skill_candidates": self._skill_candidates(events),
                "concerns": self._concerns_snapshot(limit=8),
                "trait_candidates": self._trait_candidates(thoughts, events),
                "catchup_mode": bool(thought_catchup or frame_catchup or event_catchup),
                "catchup_sources": {
                    "thoughts": bool(thought_catchup),
                    "workspace_frames": bool(frame_catchup),
                    "events": bool(event_catchup),
                },
            })

            self._write_typed_memories(report)
            self._update_self_model(report)
            
            # Write markdown report
            report_md = f"""# TARS Sleep Report (Deep Sleep)
Date: {report.get('ts', '')[:10]}
Type: {report.get('mode')}

## Episodes Reviewed
- Events: {len(events)}
- Thoughts: {len(thoughts)}
- Workspace Frames: {len(frames)}

## Themes
{chr(10).join(f"- {t.get('label', t)}" for t in themes)}

## New Semantic Beliefs
{self._format_md_items(beliefs)}

## Social Model Updates
{chr(10).join(f"- {s}" for s in social)}

## Self-Model Evidence
{report.get('updated_self_model', {})}

## Contradictions
{self._format_md_items(contradictions)}

## Archive Candidates
{self._format_md_items(archive_candidates)}

## Quarantine Candidates
{self._format_md_items(quarantine_candidates)}

## Skill Candidates
{chr(10).join(f"- {s}" for s in report.get('skill_candidates', []))}

## Concerns to Revisit
{chr(10).join(f"- {c.get('content', c)}" for c in report.get('concerns', []))}
"""
            # Optionally write this to disk
            md_path = os.path.join(self.report_dir, f"{report.get('ts', '').replace(':', '')[:15]}_deep_sleep.md")
            try:
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(report_md)
            except Exception as e:
                self.log(f"[sleep] failed to write MD report: {e}")

            return self._write_report(report)

    def weekly_sleep(self) -> Dict[str, Any]:
        with self._lock:
            reports = self._recent_reports(limit=50)
            theme_texts = []
            previous_beliefs = []
            for rep in reports:
                for theme in rep.get("themes", []) or []:
                    if isinstance(theme, dict):
                        theme_texts.append(theme.get("label", ""))
                    else:
                        theme_texts.append(str(theme))
                for belief in rep.get("new_semantic_beliefs", []) or []:
                    previous_beliefs.append(self._belief_text(belief))
            themes = self._themes(theme_texts, limit=10)
            items = [
                {
                    "id": f"weekly_belief_{idx}",
                    "source": "sleep_report",
                    "record_type": "sleep_report",
                    "ts": "",
                    "content": belief,
                    "salience": 0.6,
                }
                for idx, belief in enumerate(previous_beliefs)
            ]
            beliefs = self._semantic_beliefs(items, max_items=5)
            beliefs = self._mark_belief_truth_status(beliefs, [])
            archive_candidates = self._archive_candidates(items)
            report = self._base_report("weekly")
            report.update({
                "episodes_reviewed": sum(int(r.get("episodes_reviewed", 0) or 0) for r in reports),
                "themes": themes,
                "new_semantic_beliefs": beliefs,
                "updated_social_models": [],
                "updated_self_model": {"source": "weekly_sleep", "reports_reviewed": len(reports)},
                "contradictions": [],
                "contradiction_candidates": [],
                "archive_candidates": archive_candidates,
                "quarantine_candidates": [],
                "forgotten_or_archived": archive_candidates,
                "skill_candidates": [],
                "concerns": self._concerns_snapshot(limit=10),
                "trait_candidates": [
                    f"Stable weekly focus: {t['label']}" for t in themes[:5]
                ],
            })
            self._write_typed_memories(report)
            self._update_self_model(report)
            return self._write_report(report)

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------
    def _thoughts(self) -> List[Dict[str, Any]]:
        return _read_jsonl_tail(os.path.join(self.project_dir, THOUGHTS_FILE))

    def _workspace_frames(self) -> List[Dict[str, Any]]:
        return _read_jsonl_tail(os.path.join(self.project_dir, WORKSPACE_FILE))

    def _events(self) -> List[Dict[str, Any]]:
        return _read_jsonl_tail(os.path.join(self.project_dir, EVENTS_FILE))

    @staticmethod
    def _window_or_tail(
        records: List[Dict[str, Any]],
        *,
        hours: float,
        limit: int,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        window = _since(records, hours=hours)
        if window:
            return window, False
        return list(records[-int(limit):]), bool(records)

    def _recent_reports(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not os.path.isdir(self.report_dir):
            return []
        paths = [
            os.path.join(self.report_dir, p)
            for p in os.listdir(self.report_dir)
            if p.endswith(".json") and not p.startswith("latest_")
        ]
        paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        out = []
        for path in paths[:limit]:
            try:
                with open(path, encoding="utf-8") as f:
                    rec = json.load(f)
                if isinstance(rec, dict):
                    out.append(rec)
            except Exception:
                continue
        return out

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def _text_items(self, events: List[Dict[str, Any]], thoughts: List[Dict[str, Any]],
                    frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for idx, event in enumerate(events):
            content = str(event.get("content", "") or event.get("text", "") or "")
            if not content:
                continue
            items.append({
                "id": str(event.get("id") or f"event_{idx}"),
                "ts": str(event.get("ts", "") or ""),
                "source": str(event.get("source", "") or event.get("role", "") or "event"),
                "record_type": "event",
                "content": content,
                "salience": float(event.get("salience", 0.5) or 0.5),
            })
        for idx, thought in enumerate(thoughts):
            content = str(thought.get("content", "") or thought.get("text", "") or "")
            if not content:
                continue
            items.append({
                "id": str(thought.get("id") or f"thought_{idx}"),
                "ts": str(thought.get("ts", "") or ""),
                "source": str(thought.get("kind", "") or "inner_voice"),
                "record_type": "thought",
                "content": content,
                "salience": float(thought.get("salience", 0.45) or 0.45),
            })
        for idx, frame in enumerate(frames):
            winner = frame.get("winner") if isinstance(frame.get("winner"), dict) else {}
            content = str(winner.get("content", "") or "")
            if not content:
                continue
            items.append({
                "id": str(frame.get("id") or winner.get("id") or f"workspace_{idx}"),
                "ts": str(frame.get("ts", "") or winner.get("ts", "") or ""),
                "source": str(winner.get("source", "") or "workspace"),
                "record_type": "workspace",
                "content": content,
                "salience": float(winner.get("salience", frame.get("salience", 0.5)) or 0.5),
            })
        return items

    def _semantic_beliefs(self, items: List[Dict[str, Any]], max_items: int = 6) -> List[Dict[str, Any]]:
        structured = self._semantic_beliefs_from_memory(items, max_items=max_items)
        if structured:
            return structured

        buckets: Dict[str, Dict[str, Any]] = {}
        for item in items:
            for sentence in _line_sentences(str(item.get("content", "") or "")):
                low = sentence.lower()
                if sentence.endswith("?"):
                    continue
                has_assertion = any(pattern in f" {low} " for pattern in _ASSERTION_PATTERNS)
                is_user_directive = item.get("source") == "user" and len(_tokens(sentence)) >= 5
                if not has_assertion and not is_user_directive:
                    continue
                topic = _topic_key(sentence)
                if not topic:
                    continue
                bucket = buckets.setdefault(topic, {
                    "topic": topic,
                    "belief": self._belief_sentence(sentence, str(item.get("source", ""))),
                    "support_count": 0,
                    "sources": Counter(),
                    "evidence": [],
                    "confidence": 0.0,
                })
                bucket["support_count"] += 1
                bucket["sources"][str(item.get("record_type", "unknown"))] += 1
                if len(bucket["evidence"]) < 3:
                    bucket["evidence"].append({
                        "id": item.get("id", ""),
                        "source": item.get("source", ""),
                        "record_type": item.get("record_type", ""),
                        "quote": _compact(sentence, 180),
                    })
        beliefs = []
        for bucket in buckets.values():
            support = int(bucket["support_count"])
            source_count = len(bucket["sources"])
            bucket["sources"] = dict(bucket["sources"])
            bucket["confidence"] = round(min(0.85, 0.35 + support * 0.12 + source_count * 0.08), 2)
            bucket["truth_status"] = "candidate"
            beliefs.append(bucket)
        beliefs.sort(
            key=lambda b: (
                int(b.get("support_count", 0) or 0),
                float(b.get("confidence", 0.0) or 0.0),
            ),
            reverse=True,
        )
        return beliefs[:max_items]

    def _semantic_beliefs_from_memory(
        self,
        items: List[Dict[str, Any]],
        max_items: int = 6,
    ) -> List[Dict[str, Any]]:
        if self.memory is None or not hasattr(self.memory, "extract_semantic_beliefs"):
            return []
        out: List[Dict[str, Any]] = []
        seen = set()
        for item in items:
            source = str(item.get("source") or "")
            if source not in {"user", "system_summary", "sleep_report"}:
                continue
            content = str(item.get("content", "") or "")
            if not content:
                continue
            try:
                beliefs = self.memory.extract_semantic_beliefs(
                    content,
                    source_role=source,
                    source_episode_id=str(item.get("id") or ""),
                )
            except Exception:
                beliefs = []
            for belief in beliefs:
                key = (
                    str(belief.get("subj", "")).lower(),
                    str(belief.get("rel", "")).lower(),
                    str(belief.get("obj", "")).lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                belief = dict(belief)
                belief.setdefault("topic", " ".join(k for k in key if k))
                belief.setdefault("support_count", 1)
                belief.setdefault("truth_status", "supported")
                belief.setdefault("evidence", [{
                    "id": item.get("id", ""),
                    "source": source,
                    "record_type": item.get("record_type", ""),
                    "quote": _compact(content, 180),
                }])
                out.append(belief)
                if len(out) >= max_items:
                    return out
        return out

    def _mark_belief_truth_status(self, beliefs: List[Dict[str, Any]],
                                  contradictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        contradiction_topics = [
            str(c.get("topic", "") or "")
            for c in contradictions
            if isinstance(c, dict)
        ]
        for belief in beliefs:
            topic = str(belief.get("topic", "") or "")
            conflicted = any(_jaccard(topic, ctopic) >= 0.34 for ctopic in contradiction_topics)
            if conflicted:
                belief["truth_status"] = "conflicted_candidate"
                belief["recommended_action"] = "resolve contradiction before durable storage"
            elif belief.get("truth_status") == "supported":
                continue
            elif int(belief.get("support_count", 0) or 0) >= 2:
                belief["truth_status"] = "supported_candidate"
            else:
                belief["truth_status"] = "single_source_candidate"
        return beliefs

    def _belief_sentence(self, sentence: str, source: str) -> str:
        sentence = _compact(sentence, 220)
        if source == "user":
            return f"The user stated or requested: {sentence}"
        return sentence

    def _contradiction_candidates(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        claims: List[Tuple[str, str, Dict[str, Any], str]] = []
        for item in items:
            for sentence in _line_sentences(str(item.get("content", "") or "")):
                polarity = _claim_polarity(sentence)
                if polarity not in {"positive", "negative"}:
                    continue
                topic = _topic_key(sentence)
                if not topic:
                    continue
                claims.append((topic, polarity, item, sentence))

        out: List[Dict[str, Any]] = []
        seen = set()
        for idx, (topic, polarity, item, sentence) in enumerate(claims):
            opposite = "negative" if polarity == "positive" else "positive"
            for other_topic, other_polarity, other_item, other_sentence in claims[idx + 1:]:
                if other_polarity != opposite:
                    continue
                score = _jaccard(topic, other_topic)
                if score < 0.34:
                    continue
                key = tuple(sorted([topic, other_topic]))
                if key in seen:
                    continue
                seen.add(key)
                negative = (sentence, item) if polarity == "negative" else (other_sentence, other_item)
                positive = (sentence, item) if polarity == "positive" else (other_sentence, other_item)
                out.append({
                    "topic": topic if len(topic) >= len(other_topic) else other_topic,
                    "status": "candidate",
                    "reason": "positive and negative claims share a topic",
                    "confidence": round(min(0.9, 0.45 + score), 2),
                    "negative_evidence": self._evidence_item(negative[1], negative[0]),
                    "positive_evidence": self._evidence_item(positive[1], positive[0]),
                    "recommended_action": "review before storing either claim as durable truth",
                })
                break
            if len(out) >= 10:
                break
        return out

    def _archive_candidates(self, items: Optional[List[Dict[str, Any]]] = None,
                            duplicates: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for group in duplicates or []:
            ids = group.get("ids", []) or []
            candidates.append({
                "kind": "duplicate",
                "action": "archive_duplicate_copies",
                "reason": f"{group.get('count', 0)} near-identical records found",
                "ids": ids[1:] if len(ids) > 1 else ids,
                "keep": ids[0] if ids else None,
                "representative": group.get("representative", ""),
            })
        for item in items or []:
            content = str(item.get("content", "") or "")
            toks = _tokens(content)
            if not toks:
                continue
            low_signal = len(toks) <= 2 or all(t in _LOW_SIGNAL_TERMS for t in toks)
            low_salience = float(item.get("salience", 0.5) or 0.5) < 0.12
            if low_signal or low_salience:
                candidates.append({
                    "kind": "low_signal",
                    "action": "archive_if_not_referenced",
                    "reason": "low salience or little reusable semantic content",
                    "id": item.get("id", ""),
                    "source": item.get("source", ""),
                    "content": _compact(content, 160),
                })
            if len(candidates) >= 12:
                break
        return candidates[:12]

    def _quarantine_candidates(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for item in items:
            content = str(item.get("content", "") or "")
            sentences = _line_sentences(content)
            sentence_norms = [_norm(s) for s in sentences if _norm(s)]
            repeated_sentence = (
                len(sentence_norms) >= 3 and len(set(sentence_norms)) / len(sentence_norms) <= 0.5
            )
            repeated_tokens = self._max_token_run(content) >= 5
            unsupported_truth = (
                item.get("source") != "user"
                and any(term in content.lower() for term in ("definitely", "guaranteed", "perfect", "already active"))
            )
            if repeated_sentence or repeated_tokens or unsupported_truth:
                reason = "repetitive loop" if repeated_sentence or repeated_tokens else "unsupported certainty claim"
                candidates.append({
                    "kind": "quarantine",
                    "action": "hold_out_of_durable_memory",
                    "reason": reason,
                    "id": item.get("id", ""),
                    "source": item.get("source", ""),
                    "content": _compact(content, 180),
                })
            if len(candidates) >= 10:
                break
        return candidates

    @staticmethod
    def _max_token_run(text: str) -> int:
        toks = _tokens(text)
        best = 0
        current = 0
        previous = None
        for tok in toks:
            if tok == previous:
                current += 1
            else:
                current = 1
                previous = tok
            best = max(best, current)
        return best

    @staticmethod
    def _evidence_item(item: Dict[str, Any], sentence: str) -> Dict[str, Any]:
        return {
            "id": item.get("id", ""),
            "source": item.get("source", ""),
            "record_type": item.get("record_type", ""),
            "quote": _compact(sentence, 180),
        }

    @staticmethod
    def _belief_text(belief: Any) -> str:
        if isinstance(belief, dict):
            return str(belief.get("belief") or belief.get("content") or belief.get("topic") or "")
        return str(belief or "")

    @staticmethod
    def _is_conflicted_belief(belief: Any) -> bool:
        return isinstance(belief, dict) and str(belief.get("truth_status", "")).startswith("conflicted")

    @staticmethod
    def _format_md_items(items: List[Any]) -> str:
        if not items:
            return "- none"
        lines = []
        for item in items:
            if isinstance(item, dict):
                title = item.get("belief") or item.get("topic") or item.get("content") or item.get("reason") or item
                lines.append(f"- {title}")
                if item.get("truth_status"):
                    lines.append(f"  - truth_status: {item.get('truth_status')}")
                if item.get("reason"):
                    lines.append(f"  - reason: {item.get('reason')}")
                if item.get("confidence") is not None:
                    lines.append(f"  - confidence: {item.get('confidence')}")
                evidence = item.get("evidence") or []
                if evidence:
                    quotes = [
                        e.get("quote", "")
                        for e in evidence
                        if isinstance(e, dict) and e.get("quote")
                    ][:2]
                    if quotes:
                        lines.append(f"  - evidence: {' | '.join(quotes)}")
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)

    def _duplicate_groups(self, records: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
        buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for rec in records:
            text = str(rec.get(key, "") or "")
            n = _norm(text)
            if not n:
                continue
            admitted = False
            for existing in list(buckets.keys()):
                if _jaccard(n, existing) >= 0.82:
                    buckets[existing].append(rec)
                    admitted = True
                    break
            if not admitted:
                buckets[n].append(rec)
        groups = []
        for norm, items in buckets.items():
            if len(items) <= 1:
                continue
            groups.append({
                "norm": norm,
                "count": len(items),
                "ids": [str(i.get("id", "")) for i in items if i.get("id")],
                "representative": _compact(str(items[0].get(key, "") or ""), 180),
            })
        groups.sort(key=lambda g: g["count"], reverse=True)
        return groups

    def _themes(self, texts: Iterable[str], limit: int = 8) -> List[Dict[str, Any]]:
        counts: Counter = Counter()
        examples: Dict[str, str] = {}
        for text in texts:
            toks = _tokens(text)
            if not toks:
                continue
            counts.update(toks)
            for tok in toks:
                examples.setdefault(tok, _compact(text, 160))
        themes = []
        for word, count in counts.most_common(limit * 2):
            if count < 2 and len(themes) >= 3:
                continue
            themes.append({
                "label": word,
                "count": int(count),
                "example": examples.get(word, ""),
            })
            if len(themes) >= limit:
                break
        return themes

    def _semantic_beliefs_from_themes(self, themes: List[Dict[str, Any]],
                                      max_items: int = 5) -> List[str]:
        out = []
        for theme in themes[:max_items]:
            label = theme.get("label")
            count = int(theme.get("count", 0) or 0)
            if not label:
                continue
            if count >= 2:
                out.append(f"Recent cognition repeatedly centered on '{label}' ({count} mentions).")
        return out

    def _social_models(self, events: List[Dict[str, Any]]) -> List[str]:
        user_events = [e for e in events if e.get("source") == "user" and e.get("content")]
        themes = self._themes([e.get("content", "") for e in user_events], limit=4)
        out = []
        for theme in themes:
            out.append(f"The user recently focused on '{theme['label']}' ({theme['count']} mentions).")
        return out

    def _obvious_contradictions(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        positives: Dict[str, str] = {}
        negatives: Dict[str, str] = {}
        for e in events:
            text = str(e.get("content", "") or "")
            toks = _tokens(text)
            if not toks:
                continue
            key = " ".join(toks[:5])
            low = text.lower()
            if any(p in low for p in (" can't ", " cannot ", " won't ", " not ")):
                negatives[key] = _compact(text, 160)
            elif any(p in low for p in (" can ", " will ", " works ", " working ")):
                positives[key] = _compact(text, 160)
        out = []
        for key, neg in negatives.items():
            for pkey, pos in positives.items():
                if _jaccard(key, pkey) >= 0.5:
                    out.append({"topic": key, "negative": neg, "positive": pos})
                    break
        return out[:8]

    def _skill_candidates(self, events: List[Dict[str, Any]]) -> List[str]:
        candidates = []
        for e in events:
            text = str(e.get("content", "") or "")
            low = text.lower()
            if any(w in low for w in ("wish", "need", "should be able", "can't", "cannot")):
                if any(w in low for w in ("skill", "tool", "open", "search", "build", "automate")):
                    candidates.append(_compact(text, 180))
        return candidates[:8]

    def _trait_candidates(self, thoughts: List[Dict[str, Any]],
                          events: List[Dict[str, Any]]) -> List[str]:
        texts = [str(t.get("content", "")) for t in thoughts] + [
            str(e.get("content", "")) for e in events
        ]
        joined = "\n".join(texts).lower()
        out = []
        for word in ("careful", "direct", "fast", "expressive", "reliable"):
            if joined.count(word) >= 2:
                out.append(f"Possible earned trait candidate: {word}")
        return out[:6]

    def _concerns_snapshot(self, limit: int = 5) -> List[str]:
        if self.mind is None:
            return []
        try:
            concerns = self.mind.concerns.top_open(k=limit)
        except Exception:
            return []
        return [_compact(c.get("text", ""), 180) for c in concerns if c.get("text")]

    @staticmethod
    def _winner_content(frame: Dict[str, Any]) -> str:
        winner = frame.get("winner") if isinstance(frame.get("winner"), dict) else {}
        return str(winner.get("content", "") or "")

    # ------------------------------------------------------------------
    # Persistence/writeback
    # ------------------------------------------------------------------
    def _base_report(self, mode: str) -> Dict[str, Any]:
        return {
            "id": f"sleep_{mode}_{_safe_stamp()}",
            "mode": mode,
            "date": _safe_date(),
            "ts": _now_iso(),
            "episodes_reviewed": 0,
            "themes": [],
            "new_semantic_beliefs": [],
            "updated_social_models": [],
            "updated_self_model": {},
            "contradictions": [],
            "forgotten_or_archived": [],
            "skill_candidates": [],
            "concerns": [],
            "trait_candidates": [],
        }

    def _write_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        mode = report.get("mode", "sleep")
        path = os.path.join(self.report_dir, f"{mode}_{_safe_stamp()}.json")
        latest = os.path.join(self.report_dir, f"latest_{mode}.json")
        _atomic_json_write(path, report)
        _atomic_json_write(latest, report)
        report["path"] = path
        return report

    def _write_typed_memories(self, report: Dict[str, Any]) -> None:
        if self.memory is None:
            return
        try:
            beliefs = report.get("new_semantic_beliefs") or []
            if beliefs:
                if hasattr(self.memory, "add_semantic_beliefs"):
                    self.memory.add_semantic_beliefs(
                        [b for b in beliefs if isinstance(b, dict) and not self._is_conflicted_belief(b)],
                        src=f"sleep:{report.get('mode', 'sleep')}",
                    )
                belief_texts = [
                    self._belief_text(b)
                    for b in beliefs
                    if self._belief_text(b) and not self._is_conflicted_belief(b)
                ]
                if belief_texts:
                    self.memory.add_typed(
                        "semantic",
                        "Sleep consolidation candidates: " + " ".join(belief_texts[:4]),
                        role="sleep",
                        salience=0.55,
                        confidence=0.65,
                        utility_score=0.65,
                        provenance={"source": "sleep", "report_id": report.get("id")},
                        tags=["sleep", report.get("mode", "sleep")],
                    )
                goal_texts = [
                    self._belief_text(b)
                    for b in beliefs
                    if (
                        isinstance(b, dict)
                        and not self._is_conflicted_belief(b)
                        and (
                            str(b.get("rel") or "") == "has_goal"
                            or any(term in self._belief_text(b).lower() for term in (" goal", " wants", " needs", " want to", " need to"))
                        )
                    )
                ]
                if goal_texts:
                    self.memory.add_typed(
                        "goal",
                        "Sleep-consolidated goals: " + " | ".join(goal_texts[:4]),
                        role="sleep",
                        salience=0.55,
                        confidence=0.62,
                        utility_score=0.68,
                        provenance={"source": "sleep", "report_id": report.get("id")},
                        tags=["sleep", "goal"],
                    )
            social = report.get("updated_social_models") or []
            if social:
                self.memory.add_typed(
                    "social",
                    "Sleep-updated social model: " + " ".join(social[:3]),
                    role="sleep",
                    salience=0.55,
                    confidence=0.6,
                    utility_score=0.6,
                    provenance={"source": "sleep", "report_id": report.get("id")},
                    tags=["sleep", "social"],
                )
            concerns = report.get("concerns") or []
            if concerns:
                self.memory.add_typed(
                    "goal",
                    "Open concerns after sleep: " + " | ".join(concerns[:5]),
                    role="sleep",
                    salience=0.5,
                    confidence=0.65,
                    utility_score=0.6,
                    provenance={"source": "sleep", "report_id": report.get("id")},
                    tags=["sleep", "concerns"],
                )
            skill_candidates = report.get("skill_candidates") or []
            if skill_candidates:
                self.memory.add_typed(
                    "procedural",
                    "Sleep-derived procedural candidates: " + " | ".join(skill_candidates[:4]),
                    role="sleep",
                    salience=0.5,
                    confidence=0.6,
                    utility_score=0.65,
                    provenance={"source": "sleep", "report_id": report.get("id")},
                    tags=["sleep", "procedural"],
                )
            trait_candidates = report.get("trait_candidates") or []
            if trait_candidates:
                self.memory.add_typed(
                    "affective",
                    "Sleep-derived affective/self-style candidates: " + " | ".join(trait_candidates[:4]),
                    role="sleep",
                    salience=0.45,
                    confidence=0.55,
                    utility_score=0.55,
                    provenance={"source": "sleep", "report_id": report.get("id")},
                    tags=["sleep", "affective"],
                )
        except Exception as exc:
            self.log(f"[sleep] typed-memory write failed: {exc}")

    def _update_self_model(self, report: Dict[str, Any]) -> None:
        if self.self_model is None:
            return
        try:
            self.self_model.update_from_sleep_report(report)
        except Exception as exc:
            self.log(f"[sleep] self-model update failed: {exc}")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, THOUGHTS_FILE), "w", encoding="utf-8") as f:
            now = _now_iso()
            f.write(json.dumps({"id": "t1", "ts": now, "content": "Phase 2.5 world model needs metrics."}) + "\n")
            f.write(json.dumps({"id": "t2", "ts": now, "content": "Phase 2.5 world model needs metrics."}) + "\n")
        engine = SleepEngine(td, log_fn=print)
        rep = engine.micro_sleep()
        assert rep["duplicates_merged"] >= 1
        deep = engine.deep_sleep()
        assert deep["mode"] == "deep"
        print("SLEEP ENGINE SELF-TEST OK")
