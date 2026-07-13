"""
TARS Mind Metrics  (Phase 2.5J)
===============================

Offline report builder for the mind simulator. Reads append-only logs and
JSON state, computes simple metrics, and formats a daily cognitive report.

No network, no model, no assistant boot.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


WORKSPACE_FILE = "tars_workspace.jsonl"
THOUGHTS_FILE = "tars_thoughts.jsonl"
PREDICTIONS_FILE = "tars_world_predictions.jsonl"
SELF_MODEL_FILE = "tars_self_model.json"
SLEEP_DIR = "tars_sleep_reports"
MEMORY_DB = "tars_memory.db"

_TOKEN_RE = re.compile(r"[a-z0-9']+")
_STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "i", "you", "he", "she", "it", "we", "they", "me", "my", "your",
    "to", "of", "in", "on", "for", "with", "and", "or", "but", "so",
    "that", "this", "what", "when", "where", "why", "how", "do", "does",
    "did", "have", "has", "had", "will", "would", "can", "could", "should",
}


def _read_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _read_jsonl_tail(path: str, max_bytes: int = 1024 * 1024) -> List[Dict[str, Any]]:
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
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _tokens(text: str) -> set:
    toks = _TOKEN_RE.findall((text or "").lower())
    return {t for t in toks if t not in _STOPWORDS and len(t) > 2}


def _norm(text: str) -> str:
    return " ".join(sorted(_tokens(text)))[:160]


def _mean(values: Iterable[float]) -> float:
    vals = [float(v) for v in values]
    if not vals:
        return 0.0
    return sum(vals) / len(vals)


class MindMetrics:
    def __init__(self, project_dir: str):
        self.project_dir = project_dir

    def report(self) -> Dict[str, Any]:
        workspace = self._workspace_metrics()
        memory = self._memory_metrics()
        inner_voice = self._inner_voice_metrics()
        world = self._world_metrics()
        self_model = self._self_model_metrics()
        sleep = self._sleep_metrics()
        definition = self._definition_of_done(
            workspace, memory, inner_voice, world, self_model, sleep,
        )
        maturity = self._maturity_metrics(
            workspace, memory, inner_voice, world, self_model, sleep, definition,
        )
        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "workspace": workspace,
            "memory": memory,
            "inner_voice": inner_voice,
            "world_model": world,
            "self_model": self_model,
            "sleep": sleep,
            "definition_of_done": definition,
            "maturity": maturity,
        }

    def format_markdown(self, report: Optional[Dict[str, Any]] = None) -> str:
        rep = report or self.report()
        dod = rep.get("definition_of_done", {})
        lines = [
            "# TARS Mind Report",
            "",
            f"Generated: {rep.get('generated_at', '')}",
            "",
            "## Phase 2.5 Definition of Done",
        ]
        for key, ok in dod.items():
            mark = "OK" if ok else "TODO"
            lines.append(f"- {mark}: {key}")
        maturity = rep.get("maturity", {})
        lines += ["", "## Scaffold vs Maturity"]
        lines += [
            f"- scaffold_presence_score: {maturity.get('scaffold_presence_score', 0.0):.2f}",
            f"- maturity_score: {maturity.get('maturity_score', 0.0):.2f}",
            f"- sleep_consolidation_score: {maturity.get('sleep_consolidation_score', 0.0):.2f}",
            f"- maturity_level: {maturity.get('maturity_level', 'unknown')}",
        ]
        bottlenecks = maturity.get("bottlenecks", []) or []
        lines.append(f"- bottlenecks: {', '.join(bottlenecks) if bottlenecks else 'none'}")
        lines += ["", "## Workspace"]
        ws = rep["workspace"]
        lines += [
            f"- frames: {ws['frames']}",
            f"- duplicate_winner_rate: {ws['duplicate_winner_rate']:.2f}",
            f"- high_salience_capture_rate: {ws['high_salience_capture_rate']:.2f}",
            f"- suppressed_noise_rate: {ws['suppressed_noise_rate']:.2f}",
        ]
        mem = rep["memory"]
        lines += ["", "## Memory"]
        lines += [
            f"- total_rows: {mem['total_rows']}",
            f"- by_type: {json.dumps(mem['by_type'], sort_keys=True)}",
            f"- contradiction_count: {mem['contradiction_count']}",
            f"- selective_forgetting_rate: {mem['selective_forgetting_rate']:.2f}",
            f"- semantic_belief_growth: {mem['semantic_belief_growth']}",
        ]
        iv = rep["inner_voice"]
        lines += ["", "## Inner Voice"]
        lines += [
            f"- thoughts_seen: {iv['thoughts_seen']}",
            f"- thoughts_per_hour_est: {iv['thoughts_per_hour_est']:.2f}",
            f"- wish_to_desire_rate: {iv['wish_to_desire_rate']:.2f}",
            f"- repetition_rate: {iv['repetition_rate']:.2f}",
        ]
        world = rep["world_model"]
        lines += ["", "## World Model"]
        lines += [
            f"- predictions: {world['predictions']}",
            f"- resolved_predictions: {world['resolved_predictions']}",
            f"- prediction_error_mean: {world['prediction_error_mean']:.2f}",
            f"- prediction_error_trend: {world['prediction_error_trend']}",
        ]
        sm = rep["self_model"]
        lines += ["", "## Self-Model"]
        lines += [
            f"- calibration_score: {sm['calibration_score']:.2f}",
            f"- drift_score: {sm['drift_score']:.2f}",
            f"- known_failure_modes: {sm['known_failure_modes']}",
            f"- weakest_capabilities: {', '.join(sm['weakest_capabilities'])}",
        ]
        sleep = rep["sleep"]
        lines += ["", "## Sleep"]
        lines += [
            f"- reports: {sleep['reports']}",
            f"- useful_report_rate: {sleep['useful_report_rate']:.2f}",
            f"- duplicates_merged: {sleep['duplicates_merged']}",
            f"- beliefs_created: {sleep['beliefs_created']}",
            f"- beliefs_with_evidence: {sleep['beliefs_with_evidence']}",
            f"- contradiction_candidates: {sleep['contradiction_candidates']}",
            f"- contradictions_resolved: {sleep['contradictions_resolved']}",
            f"- archive_candidates: {sleep['archive_candidates']}",
            f"- quarantine_candidates: {sleep['quarantine_candidates']}",
            f"- skill_candidates_created: {sleep['skill_candidates_created']}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Metric groups
    # ------------------------------------------------------------------
    def _workspace_metrics(self) -> Dict[str, Any]:
        frames = _read_jsonl_tail(os.path.join(self.project_dir, WORKSPACE_FILE))
        winners = []
        duplicate = 0
        seen = set()
        high_salience_possible = 0
        high_salience_captured = 0
        suppressed = 0
        for frame in frames:
            winner = frame.get("winner") if isinstance(frame.get("winner"), dict) else None
            if not winner:
                suppressed += 1
                continue
            content = str(winner.get("content", "") or "")
            n = _norm(content)
            if n and n in seen:
                duplicate += 1
            if n:
                seen.add(n)
            winners.append(winner)
            cands = frame.get("candidates") or []
            high = [
                c for c in cands
                if isinstance(c, dict) and float(c.get("salience", 0.0) or 0.0) >= 0.7
            ]
            if high:
                high_salience_possible += 1
                if float(winner.get("salience", 0.0) or 0.0) >= 0.7:
                    high_salience_captured += 1
        total = len(frames)
        return {
            "frames": total,
            "winners": len(winners),
            "duplicate_winner_rate": duplicate / max(1, len(winners)),
            "high_salience_capture_rate": high_salience_captured / max(1, high_salience_possible),
            "suppressed_noise_rate": suppressed / max(1, total),
        }

    def _memory_metrics(self) -> Dict[str, Any]:
        path = os.path.join(self.project_dir, MEMORY_DB)
        out = {
            "total_rows": 0,
            "by_type": {},
            "contradiction_count": 0,
            "selective_forgetting_rate": 0.0,
            "semantic_belief_growth": 0,
        }
        if not os.path.exists(path):
            return out
        try:
            conn = sqlite3.connect(path)
            try:
                out["total_rows"] = int(conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0])
                rows = conn.execute(
                    "SELECT memory_type, COUNT(*) FROM episodes GROUP BY memory_type"
                ).fetchall()
                out["by_type"] = {str(k or "episodic"): int(v) for k, v in rows}
                out["contradiction_count"] = int(conn.execute(
                    "SELECT COUNT(*) FROM episodes WHERE contradicts IS NOT NULL AND contradicts NOT IN ('', '[]')"
                ).fetchone()[0])
                low = int(conn.execute(
                    "SELECT COUNT(*) FROM episodes WHERE salience < 0.05"
                ).fetchone()[0])
                out["selective_forgetting_rate"] = low / max(1, out["total_rows"])
                out["semantic_belief_growth"] = int(out["by_type"].get("semantic", 0))
            finally:
                conn.close()
        except Exception:
            return out
        return out

    def _inner_voice_metrics(self) -> Dict[str, Any]:
        thoughts = _read_jsonl_tail(os.path.join(self.project_dir, THOUGHTS_FILE))
        norms = []
        duplicates = 0
        wishes = 0
        desires = 0
        for t in thoughts:
            content = str(t.get("content", "") or "")
            n = _norm(content)
            if n and n in norms:
                duplicates += 1
            if n:
                norms.append(n)
            if t.get("kind") == "wish":
                wishes += 1
                if t.get("led_to"):
                    desires += 1
        per_hour = len(thoughts) / 24.0 if thoughts else 0.0
        return {
            "thoughts_seen": len(thoughts),
            "thoughts_per_hour_est": per_hour,
            "accepted_vs_dropped": {"accepted_persisted": len(thoughts), "dropped": None},
            "wish_to_desire_rate": desires / max(1, wishes),
            "critique_usefulness": None,
            "repetition_rate": duplicates / max(1, len(thoughts)),
        }

    def _world_metrics(self) -> Dict[str, Any]:
        preds = _read_jsonl_tail(os.path.join(self.project_dir, PREDICTIONS_FILE))
        latest_by_id: Dict[str, Dict[str, Any]] = {}
        for pred in preds:
            pid = pred.get("id")
            if pid:
                latest_by_id[str(pid)] = pred
        latest = list(latest_by_id.values())
        resolved = [p for p in latest if p.get("prediction_error") is not None]
        errors = [float(p.get("prediction_error", 0.0)) for p in resolved]
        trend = "flat"
        if len(errors) >= 6:
            old = _mean(errors[-10:-5])
            new = _mean(errors[-5:])
            if new < old - 0.05:
                trend = "improving"
            elif new > old + 0.05:
                trend = "worsening"
        return {
            "predictions": len(latest),
            "resolved_predictions": len(resolved),
            "prediction_error_mean": _mean(errors),
            "prediction_error_trend": trend,
            "best_action_accuracy": None,
            "user_reaction_prediction_accuracy": None,
        }

    def _self_model_metrics(self) -> Dict[str, Any]:
        default = {}
        try:
            from tars_self_model import _default_state  # type: ignore
            default = _default_state()
        except Exception:
            default = {}
        st = _read_json(os.path.join(self.project_dir, SELF_MODEL_FILE), default)
        caps = st.get("capabilities", {}) if isinstance(st, dict) else {}
        weakest = sorted(caps.items(), key=lambda kv: float(kv[1] or 0.0))[:3]
        return {
            "calibration_score": float(st.get("confidence_calibration", 0.0) or 0.0),
            "capability_estimate_error": None,
            "drift_score": float(st.get("drift_score", 0.0) or 0.0),
            "failure_mode_detection_rate": None,
            "known_failure_modes": len(st.get("known_failure_modes", []) or []),
            "weakest_capabilities": [f"{k}={float(v):.2f}" for k, v in weakest],
        }

    def _sleep_metrics(self) -> Dict[str, Any]:
        root = os.path.join(self.project_dir, SLEEP_DIR)
        if not os.path.isdir(root):
            return {
                "reports": 0,
                "duplicates_merged": 0,
                "beliefs_created": 0,
                "beliefs_with_evidence": 0,
                "memories_archived": 0,
                "legacy_forgotten_or_archived_entries": 0,
                "contradiction_candidates": 0,
                "contradictions_resolved": 0,
                "archive_candidates": 0,
                "quarantine_candidates": 0,
                "skill_candidates_created": 0,
                "useful_report_rate": 0.0,
                "latest_report_mode": None,
                "latest_report_at": None,
            }
        reports = []
        for name in os.listdir(root):
            if not name.endswith(".json") or name.startswith("latest_"):
                continue
            path = os.path.join(root, name)
            rec = _read_json(path, {})
            if isinstance(rec, dict):
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    mtime = 0.0
                reports.append((mtime, rec))
        reports.sort(key=lambda pair: pair[0])
        recs = [rec for _, rec in reports]
        beliefs = [
            belief
            for rec in recs
            for belief in (rec.get("new_semantic_beliefs", []) or [])
        ]
        contradiction_candidates = sum(
            self._count_report_items(rec, "contradiction_candidates", "contradictions")
            for rec in recs
        )
        archive_candidates = sum(
            self._count_report_items(rec, "archive_candidates")
            for rec in recs
        )
        quarantine_candidates = sum(
            self._count_report_items(rec, "quarantine_candidates")
            for rec in recs
        )
        useful_reports = [
            rec for rec in recs
            if (rec.get("new_semantic_beliefs") or rec.get("contradiction_candidates")
                or rec.get("archive_candidates") or rec.get("quarantine_candidates"))
        ]
        latest = recs[-1] if recs else {}
        return {
            "reports": len(recs),
            "duplicates_merged": sum(int(r.get("duplicates_merged", 0) or 0) for r in recs),
            "beliefs_created": len(beliefs),
            "beliefs_with_evidence": sum(1 for belief in beliefs if self._belief_has_evidence(belief)),
            "memories_archived": sum(int(r.get("memories_archived", 0) or 0) for r in recs),
            "legacy_forgotten_or_archived_entries": sum(
                len(r.get("forgotten_or_archived", []) or []) for r in recs
            ),
            "contradiction_candidates": contradiction_candidates,
            "contradictions_resolved": sum(
                self._count_report_items(r, "resolved_contradictions", "contradictions_resolved")
                for r in recs
            ),
            "archive_candidates": archive_candidates,
            "quarantine_candidates": quarantine_candidates,
            "skill_candidates_created": sum(len(r.get("skill_candidates", []) or []) for r in recs),
            "useful_report_rate": len(useful_reports) / max(1, len(recs)),
            "latest_report_mode": latest.get("mode"),
            "latest_report_at": latest.get("ts"),
        }

    @staticmethod
    def _count_report_items(report: Dict[str, Any], *keys: str) -> int:
        for key in keys:
            value = report.get(key)
            if isinstance(value, list):
                return len(value)
            elif isinstance(value, int):
                return value
        return 0

    @staticmethod
    def _belief_has_evidence(belief: Any) -> bool:
        if not isinstance(belief, dict):
            return False
        evidence = belief.get("evidence") or []
        support = int(belief.get("support_count", 0) or 0)
        return support > 0 and isinstance(evidence, list) and bool(evidence)

    @staticmethod
    def _definition_of_done(workspace: Dict[str, Any],
                            memory: Dict[str, Any],
                            inner_voice: Dict[str, Any],
                            world: Dict[str, Any],
                            self_model: Dict[str, Any],
                            sleep: Dict[str, Any]) -> Dict[str, bool]:
        mem_types = set(memory.get("by_type", {}).keys())
        needed = {
            "episodic", "semantic", "procedural", "social", "self",
            "affective", "workspace", "world", "goal",
        }
        return {
            "global workspace frames exist": workspace.get("frames", 0) > 0,
            "typed memory schema has expected memory types": needed.issubset(mem_types),
            "inner voice thoughts are persisted": inner_voice.get("thoughts_seen", 0) > 0,
            "sleep reports exist": sleep.get("reports", 0) > 0,
            "sleep reports contain evidence-backed beliefs": sleep.get("beliefs_with_evidence", 0) > 0,
            "sleep reports surface truth-maintenance candidates": (
                sleep.get("contradiction_candidates", 0) > 0
                or memory.get("contradiction_count", 0) > 0
            ),
            "sleep reports surface archive/quarantine candidates": (
                sleep.get("archive_candidates", 0) + sleep.get("quarantine_candidates", 0) > 0
            ),
            "world predictions are logged": world.get("predictions", 0) > 0,
            "prediction error is tracked": world.get("resolved_predictions", 0) > 0,
            "self-model has earned failure modes": self_model.get("known_failure_modes", 0) > 0,
            "mind metrics report is available": True,
        }

    @staticmethod
    def _maturity_metrics(workspace: Dict[str, Any],
                          memory: Dict[str, Any],
                          inner_voice: Dict[str, Any],
                          world: Dict[str, Any],
                          self_model: Dict[str, Any],
                          sleep: Dict[str, Any],
                          definition: Dict[str, bool]) -> Dict[str, Any]:
        mem_types = set(memory.get("by_type", {}).keys())
        typed_diversity = min(1.0, len(mem_types) / 9.0)
        repetition_rate = float(inner_voice.get("repetition_rate", 0.0) or 0.0)
        predictions = int(world.get("predictions", 0) or 0)
        resolved = int(world.get("resolved_predictions", 0) or 0)
        beliefs = int(sleep.get("beliefs_created", 0) or 0)
        beliefs_with_evidence = int(sleep.get("beliefs_with_evidence", 0) or 0)
        contradiction_signal = int(sleep.get("contradiction_candidates", 0) or 0) + int(
            memory.get("contradiction_count", 0) or 0
        )
        cleanup_signal = int(sleep.get("archive_candidates", 0) or 0) + int(
            sleep.get("quarantine_candidates", 0) or 0
        )
        components = {
            "workspace_signal": min(1.0, float(workspace.get("frames", 0) or 0) / 20.0),
            "typed_memory_diversity": typed_diversity,
            "inner_voice_non_repetition": 0.0 if inner_voice.get("thoughts_seen", 0) <= 0 else max(0.0, 1.0 - repetition_rate),
            "world_feedback": 0.0 if predictions <= 0 else min(1.0, resolved / max(1, predictions)),
            "self_model_grounding": min(
                1.0,
                float(self_model.get("calibration_score", 0.0) or 0.0)
                + min(0.5, int(self_model.get("known_failure_modes", 0) or 0) / 10.0),
            ),
            "sleep_evidence_quality": 0.0 if beliefs <= 0 else beliefs_with_evidence / max(1, beliefs),
            "truth_maintenance": min(1.0, contradiction_signal / 3.0),
            "cleanup_hygiene": min(1.0, cleanup_signal / 3.0),
        }
        maturity_score = _mean(components.values())
        sleep_consolidation_score = _mean([
            components["sleep_evidence_quality"],
            components["truth_maintenance"],
            components["cleanup_hygiene"],
        ])
        scaffold_presence_score = sum(1 for ok in definition.values() if ok) / max(1, len(definition))
        if sleep.get("reports", 0) <= 0:
            level = "scaffold_only"
        elif maturity_score < 0.25:
            level = "scaffold_only"
        elif maturity_score < 0.50:
            level = "emerging"
        elif maturity_score < 0.72:
            level = "useful"
        else:
            level = "maturing"
        if sleep_consolidation_score < 0.35 and level in {"useful", "maturing"}:
            level = "emerging"
        bottlenecks = [
            name for name, score in components.items()
            if score < 0.35
        ][:5]
        return {
            "scaffold_presence_score": round(scaffold_presence_score, 2),
            "maturity_score": round(maturity_score, 2),
            "sleep_consolidation_score": round(sleep_consolidation_score, 2),
            "maturity_level": level,
            "components": {k: round(v, 2) for k, v in components.items()},
            "bottlenecks": bottlenecks,
        }


if __name__ == "__main__":
    metrics = MindMetrics(os.path.dirname(os.path.abspath(__file__)))
    print(metrics.format_markdown())
