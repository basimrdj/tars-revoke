from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tars_revoke.errors import AuthorizationError, ValidationError
from tars_revoke.services.experiments import ExperimentSelector
from tars_revoke.services.repair import (
    RepairAttempt,
    RepairOrchestrator,
    RevocationPacket,
)


@dataclass(frozen=True)
class Candidate:
    id: str
    argv: tuple[str, ...]
    predictions: dict[str, str]
    risk_rank: int
    estimated_runtime_ms: int
    touched_files: tuple[str, ...] = field(default_factory=tuple)
    command_count: int = 1


def _candidate(
    candidate_id: str,
    *,
    runtime: int,
    touched: tuple[str, ...] = (),
    argv: tuple[str, ...] = ("python", "probe.py"),
    predictions: dict[str, str] | None = None,
    risk: int = 0,
) -> Candidate:
    return Candidate(
        id=candidate_id,
        argv=argv,
        predictions=predictions or {"uuid": "reject", "opaque": "accept"},
        risk_rank=risk,
        estimated_runtime_ms=runtime,
        touched_files=touched,
    )


def test_selects_lexicographically_smallest_safe_discriminating_candidate(tmp_path: Path) -> None:
    selector = ExperimentSelector(
        allowed_roots=[tmp_path],
        allowed_executables={"python", "pytest"},
    )
    candidates = [
        _candidate("full", runtime=20_000, argv=("pytest",)),
        _candidate("service", runtime=4_000, touched=(str(tmp_path / "service.py"),)),
        _candidate("probe", runtime=50),
    ]

    selection = selector.select(candidates, live_hypothesis_ids=("uuid", "opaque"))

    assert selection.candidate.id == "probe"
    assert selection.score[:4] == (0, 0, 50, 1)
    assert all(decision.accepted for decision in selection.decisions)


def test_rejects_shell_and_non_discriminating_candidates() -> None:
    selector = ExperimentSelector(allowed_executables={"python"})
    candidates = [
        _candidate("shell", runtime=1, argv=("sh", "-c", "echo nope")),
        _candidate(
            "same",
            runtime=2,
            predictions={"uuid": "pass", "opaque": "pass"},
        ),
        _candidate("risky", runtime=3, risk=3),
    ]

    with pytest.raises(ValidationError, match="no safe discriminating"):
        selector.select(candidates, live_hypothesis_ids=("uuid", "opaque"))

    decisions = [
        selector.evaluate(candidate, live_hypothesis_ids=("uuid", "opaque"))
        for candidate in candidates
    ]
    assert "shell_execution_forbidden" in decisions[0].reasons
    assert "not_discriminating" in decisions[1].reasons
    assert "risk_exceeds_policy" in decisions[2].reasons


def test_rejects_out_of_scope_touched_file(tmp_path: Path) -> None:
    selector = ExperimentSelector(
        allowed_roots=[tmp_path / "worktree"],
        allowed_executables={"python"},
    )
    candidate = _candidate(
        "escape",
        runtime=1,
        touched=(str(tmp_path / "outside.txt"),),
    )

    decision = selector.evaluate(candidate, live_hypothesis_ids=("uuid", "opaque"))

    assert not decision.accepted
    assert "touched_file_out_of_scope" in decision.reasons


def test_relative_candidate_path_is_rooted_safely_and_score_has_four_cost_fields(
    tmp_path: Path,
) -> None:
    selector = ExperimentSelector(
        allowed_roots=[tmp_path / "worktree"],
        allowed_executables={"python"},
    )
    candidates = [
        _candidate("z-tie", runtime=1, touched=("billing/probe.py",)),
        _candidate("a-tie", runtime=1, touched=("billing/probe.py",)),
        _candidate("slower", runtime=2, touched=("billing/probe.py",)),
    ]

    selection = selector.select(candidates, live_hypothesis_ids=("uuid", "opaque"))

    assert selection.candidate.id == "a-tie"
    assert selection.score == (0, 1, 1, 1)
    escaped = selector.evaluate(
        _candidate("escape", runtime=1, touched=(r"..\outside.py",)),
        live_hypothesis_ids=("uuid", "opaque"),
    )
    assert "touched_file_out_of_scope" in escaped.reasons


class EscapingRepairAdapter:
    def resume_and_repair(self, packet: RevocationPacket) -> RepairAttempt:
        return RepairAttempt(
            session_id="session-1",
            response_ids=("response-1",),
            changed_paths=(r"billing\..\secrets.txt",),
            replacement_effect_ids=("replacement-1",),
            metadata={},
        )


class VerificationMustNotRun:
    def run(self, argv: tuple[str, ...]):  # type: ignore[no-untyped-def]
        raise AssertionError("verification must not run for an escaped repair")


def test_repair_scope_rejects_normalized_path_traversal() -> None:
    packet = RevocationPacket(
        original_goal="repair customer id handling",
        revocation_case_id="case-1",
        invalidated_premise={"id": "premise-1"},
        replacement_evidence={"id": "evidence-2"},
        evidence_diff={"type": ["uuid", "opaque"]},
        affected_effects=(),
        quarantine_ref="refs/tars/quarantine/case-1",
        selected_experiment={"id": "probe"},
        experiment_result={"observed": "opaque"},
        allowed_repair_scope=("billing",),
        targeted_test_argv=("pytest", "tests/test_billing.py"),
        full_test_argv=("pytest",),
        active_premise_revisions={"premise-2": "a" * 64},
    )
    orchestrator = RepairOrchestrator(
        repair_adapter=EscapingRepairAdapter(),
        verification_adapter=VerificationMustNotRun(),
    )

    with pytest.raises(AuthorizationError, match="escaped"):
        orchestrator.run(packet)
