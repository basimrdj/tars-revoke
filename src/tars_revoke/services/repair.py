from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

from tars_revoke.errors import AuthorizationError, ValidationError


def _normalize_repair_path(path: str, *, field: str) -> str:
    candidate = PurePosixPath(str(path).replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValidationError(f"{field} must be a contained relative path: {path}")
    normalized = candidate.as_posix()
    if normalized in {"", "."}:
        raise ValidationError(f"{field} must name a file or directory")
    return normalized


@dataclass(frozen=True)
class RevocationPacket:
    original_goal: str
    revocation_case_id: str
    invalidated_premise: Mapping[str, Any]
    replacement_evidence: Mapping[str, Any]
    evidence_diff: Mapping[str, Any]
    affected_effects: tuple[Mapping[str, Any], ...]
    quarantine_ref: str
    selected_experiment: Mapping[str, Any]
    experiment_result: Mapping[str, Any]
    allowed_repair_scope: tuple[str, ...]
    targeted_test_argv: tuple[str, ...]
    full_test_argv: tuple[str, ...]
    active_premise_revisions: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.original_goal.strip():
            raise ValidationError("repair packet requires the original goal")
        if not self.allowed_repair_scope:
            raise ValidationError("repair packet requires a bounded repair scope")
        for path in self.allowed_repair_scope:
            _normalize_repair_path(path, field="allowed repair scope")
        if not self.targeted_test_argv or not self.full_test_argv:
            raise ValidationError("repair packet requires targeted and full tests")


@dataclass(frozen=True)
class RepairAttempt:
    session_id: str
    response_ids: tuple[str, ...]
    changed_paths: tuple[str, ...]
    replacement_effect_ids: tuple[str, ...]
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class VerificationRun:
    argv: tuple[str, ...]
    exit_code: int
    stdout_digest: str
    stderr_digest: str

    @property
    def passed(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class RepairResult:
    attempt: RepairAttempt
    targeted: VerificationRun
    full: VerificationRun


class RepairAdapter(Protocol):
    def resume_and_repair(self, packet: RevocationPacket) -> RepairAttempt: ...


class VerificationAdapter(Protocol):
    def run(self, argv: tuple[str, ...]) -> VerificationRun: ...


class RepairOrchestrator:
    """Bounded Codex repair followed by mandatory two-stage verification."""

    def __init__(
        self,
        *,
        repair_adapter: RepairAdapter,
        verification_adapter: VerificationAdapter,
    ) -> None:
        self.repair_adapter = repair_adapter
        self.verification_adapter = verification_adapter

    def run(self, packet: RevocationPacket) -> RepairResult:
        attempt = self.repair_adapter.resume_and_repair(packet)
        allowed = tuple(
            _normalize_repair_path(path, field="allowed repair scope")
            for path in packet.allowed_repair_scope
        )
        escaped: list[str] = []
        for path in attempt.changed_paths:
            try:
                normalized = _normalize_repair_path(path, field="changed path")
            except ValidationError:
                escaped.append(path)
                continue
            if not any(
                normalized == root or normalized.startswith(f"{root}/")
                for root in allowed
            ):
                escaped.append(path)
        if escaped:
            raise AuthorizationError(
                f"repair escaped its allowed scope: {', '.join(sorted(escaped))}"
            )
        targeted = self.verification_adapter.run(packet.targeted_test_argv)
        if not targeted.passed:
            raise AuthorizationError("targeted verification failed; replacement action denied")
        full = self.verification_adapter.run(packet.full_test_argv)
        if not full.passed:
            raise AuthorizationError("full verification failed; replacement action denied")
        return RepairResult(attempt=attempt, targeted=targeted, full=full)
