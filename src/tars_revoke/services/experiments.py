from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tars_revoke.errors import ValidationError

_SHELL_EXECUTABLES = {
    "bash",
    "cmd",
    "cmd.exe",
    "dash",
    "fish",
    "powershell",
    "pwsh",
    "sh",
    "zsh",
}


def _field(record: object, *names: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        for name in names:
            if name in record:
                return record[name]
    for name in names:
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value)).lower()


@dataclass(frozen=True)
class CandidateDecision:
    candidate_id: str
    accepted: bool
    reasons: tuple[str, ...]
    score: tuple[int, int, int, int] | None


@dataclass(frozen=True)
class ExperimentSelection:
    candidate: object
    score: tuple[int, int, int, int]
    decisions: tuple[CandidateDecision, ...]


class ExperimentSelector:
    """Validate typed experiments and prove bounded least-cost selection."""

    def __init__(
        self,
        *,
        allowed_roots: Sequence[Path] = (),
        allowed_executables: Iterable[str] = (),
        maximum_risk_rank: int = 1,
    ) -> None:
        self.allowed_roots = tuple(path.resolve() for path in allowed_roots)
        self.allowed_executables = {str(name) for name in allowed_executables}
        self.maximum_risk_rank = int(maximum_risk_rank)

    def evaluate(
        self,
        candidate: object,
        *,
        live_hypothesis_ids: Iterable[str],
    ) -> CandidateDecision:
        candidate_id = str(_field(candidate, "id", "candidate_id", default=""))
        reasons: list[str] = []
        if not candidate_id:
            reasons.append("missing_candidate_id")
        live_ids = tuple(sorted(set(str(item) for item in live_hypothesis_ids)))
        if len(live_ids) < 2:
            raise ValidationError("at least two live hypotheses are required")

        argv_raw = _field(candidate, "argv", "command", default=())
        if isinstance(argv_raw, str) or not isinstance(argv_raw, Sequence):
            reasons.append("command_must_be_argv")
            argv: tuple[str, ...] = ()
        else:
            argv = tuple(str(part) for part in argv_raw)
            if not argv or any(not part or "\x00" in part for part in argv):
                reasons.append("invalid_argv")

        if argv:
            executable = os.path.basename(argv[0]).lower()
            if executable in _SHELL_EXECUTABLES:
                reasons.append("shell_execution_forbidden")
            if self.allowed_executables and executable not in self.allowed_executables:
                reasons.append("executable_not_allowed")

        predictions_raw = _field(
            candidate,
            "predictions",
            "predicted_outcomes",
            "predicted_outcome_by_hypothesis",
            default={},
        )
        predictions = dict(predictions_raw) if isinstance(predictions_raw, Mapping) else {}
        missing = [hypothesis_id for hypothesis_id in live_ids if hypothesis_id not in predictions]
        if missing:
            reasons.append("missing_hypothesis_predictions")
        else:
            outcomes = {str(predictions[hypothesis_id]) for hypothesis_id in live_ids}
            if len(outcomes) < 2:
                reasons.append("not_discriminating")

        risk_rank_raw = _field(candidate, "risk_rank", default=None)
        if risk_rank_raw is None:
            risk_name = _enum_value(_field(candidate, "risk", default="low"))
            risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(risk_name, 3)
        else:
            risk_rank = int(risk_rank_raw)
        if risk_rank < 0:
            reasons.append("invalid_risk_rank")
        if risk_rank > self.maximum_risk_rank:
            reasons.append("risk_exceeds_policy")

        touched_raw = _field(candidate, "touched_files", default=()) or ()
        touched_files = tuple(Path(str(path).replace("\\", "/")) for path in touched_raw)
        for path in touched_files:
            if ".." in path.parts:
                reasons.append("touched_file_out_of_scope")
                break
            if path.is_absolute():
                resolved_candidates: tuple[Path, ...] = (path.resolve(),)
            else:
                resolved_candidates = tuple(
                    (root / path).resolve() for root in self.allowed_roots
                )
            if self.allowed_roots and not any(
                resolved == root or root in resolved.parents
                for resolved in resolved_candidates
                for root in self.allowed_roots
            ):
                reasons.append("touched_file_out_of_scope")
                break

        estimated_runtime_ms = int(_field(candidate, "estimated_runtime_ms", default=0) or 0)
        if estimated_runtime_ms < 0:
            reasons.append("negative_runtime")

        command_count = int(_field(candidate, "command_count", default=1) or 1)
        if command_count < 1:
            reasons.append("invalid_command_count")

        score = (
            risk_rank,
            len(touched_files),
            estimated_runtime_ms,
            command_count,
        )
        return CandidateDecision(
            candidate_id=candidate_id,
            accepted=not reasons,
            reasons=tuple(sorted(set(reasons))),
            score=score if not reasons else None,
        )

    def select(
        self,
        candidates: Iterable[object],
        *,
        live_hypothesis_ids: Iterable[str],
        minimum_candidates: int = 3,
    ) -> ExperimentSelection:
        candidate_list = list(candidates)
        if len(candidate_list) < minimum_candidates:
            raise ValidationError(f"at least {minimum_candidates} candidates are required")

        live_ids = tuple(live_hypothesis_ids)
        decisions = tuple(
            self.evaluate(candidate, live_hypothesis_ids=live_ids)
            for candidate in candidate_list
        )
        accepted: list[tuple[object, tuple[int, int, int, int], CandidateDecision]] = []
        for candidate, decision in zip(candidate_list, decisions, strict=True):
            if decision.accepted and decision.score is not None:
                accepted.append((candidate, decision.score, decision))
        if not accepted:
            raise ValidationError("no safe discriminating experiment candidate")
        candidate, score, _decision = min(
            accepted,
            key=lambda item: (item[1], item[2].candidate_id),
        )
        return ExperimentSelection(candidate=candidate, score=score, decisions=decisions)
