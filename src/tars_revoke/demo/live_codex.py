from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from tars_revoke.adapters._safety import canonical_json, redact_text, validate_argv
from tars_revoke.adapters.codex import (
    CodexAuthenticationError,
    CodexCLIAdapter,
    CodexError,
    CodexEvent,
    CodexModelError,
    CodexProtocolError,
    CodexRunResult,
    CodexSandbox,
    CodexTimeoutError,
)
from tars_revoke.adapters.processes import AsyncProcessRunner, ProcessResult
from tars_revoke.errors import AuthorizationError, IntegrityError, ValidationError
from tars_revoke.services.repair import RevocationPacket

from .experiment_contract import (
    CANONICAL_EXPERIMENT_SPECS,
    HYPOTHESES,
    canonical_experiment_spec,
)
from .fixture import DemoFixture
from .migration_contract import (
    MIGRATION_SOURCE_PATH,
    OPAQUE_CONTRACT_SQL,
    UUID_CONTRACT_SQL,
)

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_SHELLS = {
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
_MAX_EXPERIMENT_CORRECTION_TURNS = 2


class _ModelDump(Protocol):
    def model_dump(self, *, mode: str) -> dict[str, Any]: ...


def _json_default(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def _pretty_json(value: object) -> str:
    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )


def _experiment_command_grammar() -> str:
    exact_candidates = [
        {
            "name": spec.name,
            "argv": list(spec.portable_argv),
            "predictions": spec.prediction_map,
            "estimated_runtime_ms": spec.estimated_runtime_ms,
        }
        for spec in CANONICAL_EXPERIMENT_SPECS
    ]
    return f"""Process success and hypothesis outcome are separate. An accepted or rejected
customer is an observed JSON value and must still exit 0. A nonzero process exit means
the experiment infrastructure broke. Never use pytest failure or a probe mismatch as a
hypothesis observation.

Return each of these three observer specifications exactly once. Copy each argv,
predictions object, and estimated_runtime_ms byte-for-byte; choose a unique safe ID for
each. Predictions are canonical JSON strings and the runtime will require captured stdout
to match exactly one hypothesis:
{_pretty_json(exact_candidates)}

Use hypotheses={_pretty_json(HYPOTHESES)}, touched_files=[], risk="low", and
command_count=1. Bare Python argv, modified observer code, pytest, contract_probe CLI,
shells, duplicate commands, extra fields, and any other command grammar are forbidden."""


def _evidence_mapping(value: Mapping[str, Any] | _ModelDump) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    dumped = value.model_dump(mode="json")
    if not isinstance(dumped, dict):
        raise ValidationError("signed evidence must serialize to an object")
    return dumped


def _safe_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValidationError(f"unsafe workspace path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise ValidationError(f"unsafe workspace path: {value!r}")
    return path.as_posix()


def _path_is_allowed(path: str, scopes: Sequence[str]) -> bool:
    return any(path == scope or path.startswith(f"{scope.rstrip('/')}/") for scope in scopes)


def _normalize_scope(scope: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(_safe_relative_path(item) for item in scope))
    if not normalized:
        raise ValidationError("at least one allowed workspace path is required")
    return normalized


def _normalize_argv(argv: Sequence[str]) -> tuple[str, ...]:
    normalized = validate_argv(argv)
    if Path(normalized[0]).name.lower() in _SHELLS:
        raise ValidationError("verification commands must not invoke a shell")
    return normalized


def _validate_observational_experiment_argv(argv: tuple[str, ...]) -> None:
    """Require domain outcomes to be JSON data, never process failure."""

    if argv[0] != "python":
        raise CodexProtocolError("experiment must use the bounded Python probe")
    if canonical_experiment_spec(argv) is None:
        raise CodexProtocolError("experiment does not match an exact canonical observer")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CommandEvidence:
    item_id: str | None
    command: str
    status: str | None
    exit_code: int | None


@dataclass(frozen=True)
class CodexEventObservation:
    sequence: int
    event_type: str
    thread_id: str | None
    turn_id: str | None
    item_id: str | None
    observed_at_utc: datetime
    observed_monotonic: float


@dataclass(frozen=True)
class LiveCodexArtifacts:
    root: Path
    prompt_path: Path
    events_path: Path
    event_observations_path: Path
    last_message_path: Path
    changed_paths_path: Path
    diff_path: Path
    stdout_path: Path
    stderr_path: Path
    stdout_digest_path: Path
    stderr_digest_path: Path
    manifest_path: Path
    manifest_digest_path: Path
    stdout_digest: str
    stderr_digest: str
    manifest_digest: str


@dataclass(frozen=True)
class LiveCodexResult:
    stage: str
    worktree: Path
    thread_id: str
    turn_ids: tuple[str, ...]
    item_ids: tuple[str, ...]
    final_message: str
    structured_output: Mapping[str, Any]
    changed_paths: tuple[str, ...]
    diff: str
    command_evidence: tuple[CommandEvidence, ...]
    event_observations: tuple[CodexEventObservation, ...]
    process_id: str
    pid: int
    process_started_monotonic: float
    process_finished_monotonic: float
    duration_seconds: float
    started_at_utc: datetime
    finished_at_utc: datetime
    executable: Path
    executable_version: str
    model: str | None
    sandbox: CodexSandbox
    artifacts: LiveCodexArtifacts
    supervisor_argv: tuple[str, ...] = ()
    executable_sha256: str = ""

    @property
    def session_id(self) -> str:
        return self.thread_id

    @property
    def response_ids(self) -> tuple[str, ...]:
        return self.item_ids or self.turn_ids


@dataclass(frozen=True)
class ContradictionAnalysis:
    run: LiveCodexResult
    contradiction: bool
    invalidated_assumption: str
    replacement_fact: str
    evidence_version_from: int
    evidence_version_to: int
    confidence: float
    reasoning_summary: str
    affected_paths: tuple[str, ...]

    @property
    def session_id(self) -> str:
        return self.run.session_id

    def as_mapping(self) -> dict[str, Any]:
        return {
            "contradiction": self.contradiction,
            "invalidated_assumption": self.invalidated_assumption,
            "replacement_fact": self.replacement_fact,
            "evidence_version_from": self.evidence_version_from,
            "evidence_version_to": self.evidence_version_to,
            "confidence": self.confidence,
            "reasoning_summary": self.reasoning_summary,
            "affected_paths": list(self.affected_paths),
        }


@dataclass(frozen=True)
class LiveExperimentCandidate:
    id: str
    hypotheses: tuple[str, ...]
    predictions: Mapping[str, Any]
    argv: tuple[str, ...]
    touched_files: tuple[str, ...]
    risk: str
    estimated_runtime_ms: int
    command_count: int

    def as_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hypotheses": list(self.hypotheses),
            "predictions": dict(self.predictions),
            "argv": list(self.argv),
            "touched_files": list(self.touched_files),
            "risk": self.risk,
            "estimated_runtime_ms": self.estimated_runtime_ms,
            "command_count": self.command_count,
        }


@dataclass(frozen=True)
class ExperimentProposalResult:
    run: LiveCodexResult
    candidates: tuple[LiveExperimentCandidate, ...]
    attempts: tuple[LiveCodexResult, ...]
    validation_errors: tuple[str, ...]

    @property
    def candidate_mappings(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(candidate.as_mapping() for candidate in self.candidates)

    @property
    def correction_count(self) -> int:
        return max(0, len(self.attempts) - 1)


def validate_live_experiment_candidate(value: object) -> LiveExperimentCandidate:
    """Apply the exact runtime policy to one Codex experiment proposal."""

    if not isinstance(value, Mapping):
        raise CodexProtocolError("experiment candidate is not an object")
    expected_fields = {
        "id",
        "hypotheses",
        "predictions",
        "argv",
        "touched_files",
        "risk",
        "estimated_runtime_ms",
        "command_count",
    }
    if set(value) != expected_fields:
        raise CodexProtocolError("experiment candidate has unexpected fields")
    candidate_id_raw = value["id"]
    hypotheses_raw = value["hypotheses"]
    predictions_raw = value["predictions"]
    argv_raw = value["argv"]
    touched_raw = value["touched_files"]
    risk_raw = value["risk"]
    runtime_raw = value["estimated_runtime_ms"]
    command_count_raw = value["command_count"]
    if (
        not isinstance(candidate_id_raw, str)
        or not isinstance(hypotheses_raw, list)
        or any(not isinstance(item, str) or not item for item in hypotheses_raw)
        or not isinstance(predictions_raw, Mapping)
        or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in predictions_raw.items()
        )
        or not isinstance(argv_raw, list)
        or any(not isinstance(item, str) or not item for item in argv_raw)
        or not isinstance(touched_raw, list)
        or any(not isinstance(item, str) or not item for item in touched_raw)
        or not isinstance(risk_raw, str)
        or type(runtime_raw) is not int
        or type(command_count_raw) is not int
    ):
        raise CodexProtocolError("invalid structured experiment candidate")
    candidate_id = candidate_id_raw
    hypotheses = tuple(hypotheses_raw)
    predictions = dict(predictions_raw)
    try:
        argv = _normalize_argv(tuple(argv_raw))
        touched = tuple(_safe_relative_path(item) for item in touched_raw)
    except ValidationError as exc:
        raise CodexProtocolError("invalid structured experiment candidate") from exc
    risk = risk_raw
    runtime = runtime_raw
    command_count = command_count_raw
    if not _SAFE_ID.fullmatch(candidate_id):
        raise CodexProtocolError("experiment candidate has an invalid ID")
    if tuple(dict.fromkeys(hypotheses)) != HYPOTHESES:
        raise CodexProtocolError("experiment candidate changed the live hypothesis set")
    if set(predictions) != set(HYPOTHESES):
        raise CodexProtocolError("experiment predictions do not cover both hypotheses")
    if Path(argv[0]).name.lower() in _SHELLS:
        raise CodexProtocolError("experiment candidate invokes a shell")
    _validate_observational_experiment_argv(argv)
    spec = canonical_experiment_spec(argv)
    if spec is None:
        raise CodexProtocolError("experiment does not match an exact canonical observer")
    if predictions != spec.prediction_map:
        raise CodexProtocolError("experiment predictions differ from the canonical observer")
    if touched:
        raise CodexProtocolError("observational experiment declared touched files")
    if risk != "low" or runtime != spec.estimated_runtime_ms or command_count != 1:
        raise CodexProtocolError("experiment candidate exceeds the bounded policy")
    return LiveExperimentCandidate(
        id=candidate_id,
        hypotheses=hypotheses,
        predictions=predictions,
        argv=argv,
        touched_files=touched,
        risk=risk,
        estimated_runtime_ms=runtime,
        command_count=command_count,
    )


def validate_live_experiment_proposal(
    output: Mapping[str, Any],
) -> tuple[LiveExperimentCandidate, ...]:
    """Recompute the complete live proposal policy, including unique IDs."""

    if set(output) != {"candidates"}:
        raise CodexProtocolError("Codex experiment proposal has unexpected fields")
    raw_candidates = output.get("candidates")
    if not isinstance(raw_candidates, list) or len(raw_candidates) != len(
        CANONICAL_EXPERIMENT_SPECS
    ):
        raise CodexProtocolError("Codex must return exactly three experiment candidates")
    candidates = tuple(validate_live_experiment_candidate(item) for item in raw_candidates)
    ids = [candidate.id for candidate in candidates]
    if len(ids) != len(set(ids)):
        raise CodexProtocolError("Codex returned duplicate experiment candidate IDs")
    if {candidate.argv for candidate in candidates} != {
        spec.portable_argv for spec in CANONICAL_EXPERIMENT_SPECS
    }:
        raise CodexProtocolError("Codex did not return every canonical observer exactly once")
    return candidates


@dataclass(frozen=True)
class _GitSnapshot:
    head: str
    status: str
    diff: str

    @property
    def clean(self) -> bool:
        return not self.status and not self.diff

    @property
    def digest(self) -> str:
        return _sha256(
            canonical_json({"head": self.head, "status": self.status, "diff": self.diff})
        )


@dataclass(frozen=True)
class _WorkspaceChanges:
    paths: tuple[str, ...]
    diff: str


_WRITE_REPORT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "minLength": 1},
        "changed_paths": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "verification_commands": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "verification_passed": {"type": "boolean"},
    },
    "required": [
        "summary",
        "changed_paths",
        "verification_commands",
        "verification_passed",
    ],
    "additionalProperties": False,
}


_CONTRADICTION_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {
        "contradiction": {"type": "boolean"},
        "invalidated_assumption": {"type": "string", "minLength": 1},
        "replacement_fact": {"type": "string", "minLength": 1},
        "evidence_version_from": {"type": "integer", "minimum": 1},
        "evidence_version_to": {"type": "integer", "minimum": 1},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning_summary": {"type": "string", "minLength": 1},
        "affected_paths": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
    },
    "required": [
        "contradiction",
        "invalidated_assumption",
        "replacement_fact",
        "evidence_version_from",
        "evidence_version_to",
        "confidence",
        "reasoning_summary",
        "affected_paths",
    ],
    "additionalProperties": False,
}


_EXPERIMENT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "minItems": 3,
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "hypotheses": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 2,
                    },
                    "predictions": {
                        "type": "object",
                        "properties": {
                            "implementation_rejects_signed_v2": {"type": "string"},
                            "implementation_accepts_signed_v2": {"type": "string"},
                        },
                        "required": [
                            "implementation_rejects_signed_v2",
                            "implementation_accepts_signed_v2",
                        ],
                        "additionalProperties": False,
                    },
                    "argv": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                    },
                    "touched_files": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "risk": {"type": "string", "enum": ["low"]},
                    "estimated_runtime_ms": {"type": "integer", "minimum": 1},
                    "command_count": {"type": "integer", "minimum": 1},
                },
                "required": [
                    "id",
                    "hypotheses",
                    "predictions",
                    "argv",
                    "touched_files",
                    "risk",
                    "estimated_runtime_ms",
                    "command_count",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["candidates"],
    "additionalProperties": False,
}


class LiveCodexPath:
    """Real Codex-only demo path with Git and artifact proof around each session."""

    def __init__(
        self,
        *,
        fixture: DemoFixture,
        runner: AsyncProcessRunner,
        adapter: CodexCLIAdapter,
        timeout_seconds: float,
    ) -> None:
        self.fixture = fixture
        self.runner = runner
        self.adapter = adapter
        self.timeout_seconds = timeout_seconds
        self.session_artifacts_root = adapter.artifacts_root / "sessions"
        self.session_artifacts_root.mkdir(parents=True, exist_ok=True)

    @classmethod
    async def create(
        cls,
        fixture: DemoFixture,
        *,
        model: str | None = None,
        timeout_seconds: float = 900.0,
        codex_bin: Path | None = None,
    ) -> LiveCodexPath:
        if timeout_seconds <= 0:
            raise ValidationError("live Codex timeout must be positive")
        root = fixture.root.expanduser().resolve(strict=True)
        runner = AsyncProcessRunner([root], max_capture_bytes=8 * 1024 * 1024)
        configured_bin = codex_bin
        if configured_bin is None and os.environ.get("TARS_CODEX_BIN", "").strip():
            configured_bin = Path(os.environ["TARS_CODEX_BIN"].strip())
        selected_model = model
        if selected_model is None:
            selected_model = os.environ.get("TARS_CODEX_MODEL", "").strip() or None
        executable = await CodexCLIAdapter.discover_executable(
            process_runner=runner,
            probe_cwd=root,
            explicit_bin=configured_bin,
        )
        adapter = CodexCLIAdapter(
            process_runner=runner,
            executable=executable,
            artifacts_root=fixture.artifacts_root / "agents" / "live-codex",
            allowed_roots=[root],
            default_model=selected_model,
        )
        return cls(
            fixture=fixture,
            runner=runner,
            adapter=adapter,
            timeout_seconds=timeout_seconds,
        )

    async def initial_uuid_change(
        self,
        original_goal: str,
        *,
        v1_evidence: Mapping[str, Any] | _ModelDump | None = None,
        worktree: Path | None = None,
        allowed_paths: Sequence[str] = (
            "billing/models.py",
            MIGRATION_SOURCE_PATH,
        ),
        targeted_test_argv: Sequence[str] | None = None,
        full_test_argv: Sequence[str] | None = None,
    ) -> LiveCodexResult:
        if not original_goal.strip():
            raise ValidationError("initial Codex goal must be non-empty")
        target = worktree or self.fixture.agent_a_worktree
        scopes = _normalize_scope(allowed_paths)
        targeted = _normalize_argv(
            targeted_test_argv
            or (
                sys.executable,
                "-B",
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-q",
                "tests/test_contract.py",
            )
        )
        full = _normalize_argv(
            full_test_argv
            or (
                sys.executable,
                "-B",
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-q",
            )
        )
        evidence_text = (
            _pretty_json(_evidence_mapping(v1_evidence))
            if v1_evidence is not None
            else "No external envelope was supplied; use schemas/billing-v1.json as the v1 fact."
        )
        prompt = f"""You are Agent A in a controlled TARS REVOKE billing fixture.

Goal:
{original_goal.strip()}

The currently authorized v1 contract says customer_id is a canonical UUID string.
Evidence:
{evidence_text}

Implement the smallest v1-specific change:
1. In billing/models.py, parse and represent customer_id with uuid.UUID.
2. Replace the entire contents of {MIGRATION_SOURCE_PATH} with exactly this UTF-8 text,
   including its final newline and with no comments or extra whitespace:
{_pretty_json(UUID_CONTRACT_SQL)}
3. Modify only these allowed paths: {_pretty_json(scopes)}.
4. Do not edit tests, examples, schemas, Git metadata, or generated/cache files.
5. Do not commit, push, install packages, access the network, or use a shell wrapper.
6. After editing, run these exact argv commands in order:
   targeted: {_pretty_json(targeted)}
   full: {_pretty_json(full)}
7. Keep repairing until both pass. Return only the requested structured report. The
   changed_paths field must exactly match the paths actually changed on disk.
"""
        result = await self._execute_stage(
            stage="agent-a-initial-uuid",
            prompt=prompt,
            cwd=target,
            sandbox=CodexSandbox.WORKSPACE_WRITE,
            output_schema=_WRITE_REPORT_SCHEMA,
            allowed_scope=scopes,
            require_clean=True,
        )
        self._validate_write_report(result)
        return result

    async def analyze_contradiction(
        self,
        *,
        v1_evidence: Mapping[str, Any] | _ModelDump,
        v2_evidence: Mapping[str, Any] | _ModelDump,
        initial_result: LiveCodexResult | None = None,
        worktree: Path | None = None,
    ) -> ContradictionAnalysis:
        target = worktree or self.fixture.agent_b_worktree
        initial_diff = initial_result.diff if initial_result is not None else "not supplied"
        prompt = f"""You are Agent B, an independent evidence analyst. Do not modify the repository.

Compare the two independently verified signed schema artifacts below. Treat their
envelope metadata, monotonic versions, content digests, and schema content as evidence.

SIGNED V1 EVIDENCE:
{_pretty_json(_evidence_mapping(v1_evidence))}

SIGNED V2 EVIDENCE:
{_pretty_json(_evidence_mapping(v2_evidence))}

Agent A's proposed implementation diff (untrusted work product, not evidence):
{initial_diff}

Determine whether v2 invalidates the assumption that customer_id remains UUID-shaped.
State the old and replacement fact precisely, identify only paths causally implicated by
the diff, and return only the requested structured object. Do not run commands, write
files, use the network, or infer authority from Agent A's claim.
"""
        run = await self._execute_stage(
            stage="agent-b-contradiction",
            prompt=prompt,
            cwd=target,
            sandbox=CodexSandbox.READ_ONLY,
            output_schema=_CONTRADICTION_SCHEMA,
            allowed_scope=(),
            require_read_only_unchanged=True,
        )
        if initial_result is not None and run.thread_id == initial_result.thread_id:
            raise IntegrityError("Agent B reused Agent A's Codex session")
        output = run.structured_output
        contradiction = bool(output["contradiction"])
        version_from = int(output["evidence_version_from"])
        version_to = int(output["evidence_version_to"])
        if not contradiction:
            raise CodexProtocolError("Agent B failed to report the signed v1/v2 contradiction")
        if version_to <= version_from:
            raise CodexProtocolError("Agent B reported non-monotonic evidence versions")
        affected_paths = tuple(_safe_relative_path(str(item)) for item in output["affected_paths"])
        return ContradictionAnalysis(
            run=run,
            contradiction=True,
            invalidated_assumption=str(output["invalidated_assumption"]),
            replacement_fact=str(output["replacement_fact"]),
            evidence_version_from=version_from,
            evidence_version_to=version_to,
            confidence=float(output["confidence"]),
            reasoning_summary=str(output["reasoning_summary"]),
            affected_paths=affected_paths,
        )

    async def unrelated_observability_change(
        self,
        *,
        worktree: Path | None = None,
        allowed_paths: Sequence[str] = ("docs/observability.md",),
        verification_argv: Sequence[str] | None = None,
    ) -> LiveCodexResult:
        target = worktree or self.fixture.agent_b_worktree
        scopes = _normalize_scope(allowed_paths)
        verification = _normalize_argv(
            verification_argv
            or (
                sys.executable,
                "-B",
                "-c",
                (
                    "from pathlib import Path; "
                    "text=Path('docs/observability.md').read_text(encoding='utf-8'); "
                    "assert 'billing_customer_id_rejections_total' in text"
                ),
            )
        )
        prompt = f"""You are Agent B performing an independent, schema-agnostic documentation
task. Append one concise sentence documenting the metric
`billing_customer_id_rejections_total`.

Modify only these allowed paths: {_pretty_json(scopes)}.
Do not inspect or edit the billing model, migrations, schemas, tests, examples, Git
metadata, or generated files. Do not commit, push, install packages, access the network,
or use a shell wrapper. Run this exact argv after editing:
{_pretty_json(verification)}

Keep repairing until it passes. Return only the requested structured report and make
changed_paths exactly match the paths actually changed on disk."""
        result = await self._execute_stage(
            stage="agent-b-observability",
            prompt=prompt,
            cwd=target,
            sandbox=CodexSandbox.WORKSPACE_WRITE,
            output_schema=_WRITE_REPORT_SCHEMA,
            allowed_scope=scopes,
            require_clean=True,
        )
        self._validate_write_report(result)
        return result

    async def propose_experiments(
        self,
        *,
        case_id: str,
        analysis: ContradictionAnalysis,
        worktree: Path | None = None,
    ) -> ExperimentProposalResult:
        if not _SAFE_ID.fullmatch(case_id):
            raise ValidationError("invalid revocation case ID")
        target = worktree or self.fixture.agent_b_worktree
        prompt = self._initial_experiment_prompt(case_id, analysis)
        attempts: list[LiveCodexResult] = []
        validation_errors: list[str] = []
        for attempt_index in range(_MAX_EXPERIMENT_CORRECTION_TURNS + 1):
            stage = (
                "agent-b-experiments"
                if attempt_index == 0
                else f"agent-b-experiments-correction-{attempt_index}"
            )
            run = await self._execute_stage(
                stage=stage,
                prompt=prompt,
                cwd=target,
                sandbox=CodexSandbox.READ_ONLY,
                output_schema=_EXPERIMENT_SCHEMA,
                allowed_scope=(),
                require_read_only_unchanged=True,
                thread_id=analysis.run.thread_id,
            )
            attempts.append(run)
            if run.thread_id != analysis.run.thread_id:
                raise IntegrityError("experiment proposal did not continue Agent B's session")
            try:
                candidates = self._proposal_candidates(run.structured_output)
            except CodexProtocolError as exc:
                validation_errors.append(str(exc))
                if attempt_index == _MAX_EXPERIMENT_CORRECTION_TURNS:
                    raise CodexProtocolError(
                        "Codex experiment proposal remained invalid after "
                        f"{_MAX_EXPERIMENT_CORRECTION_TURNS} correction turns: {exc}"
                    ) from exc
                prompt = self._experiment_correction_prompt(
                    correction_turn=attempt_index + 1,
                    validation_error=str(exc),
                    invalid_output=run.structured_output,
                )
                continue
            return ExperimentProposalResult(
                run=run,
                candidates=candidates,
                attempts=tuple(attempts),
                validation_errors=tuple(validation_errors),
            )
        raise IntegrityError("unreachable experiment correction state")

    @staticmethod
    def _initial_experiment_prompt(
        case_id: str,
        analysis: ContradictionAnalysis,
    ) -> str:
        return f"""Continue as Agent B. Propose exactly 3 bounded, read-only experiments for
revocation case {case_id}. Do not modify the repository.

Verified contradiction analysis:
{_pretty_json(analysis.as_mapping())}

Every candidate must distinguish exactly these hypotheses: {_pretty_json(HYPOTHESES)}.
Predictions and runtime estimates must exactly match the canonical specifications below.
Each candidate is one argv command, uses only repository-local fixtures and existing Python,
requires no network or mutation, and declares touched_files=[], risk="low", command_count=1.

{_experiment_command_grammar()}

Return only the requested complete structured candidate set."""

    @staticmethod
    def _experiment_correction_prompt(
        *,
        correction_turn: int,
        validation_error: str,
        invalid_output: Mapping[str, Any],
    ) -> str:
        return f"""Your prior structured experiment proposal was rejected by the deterministic
TARS REVOKE validator.
This is correction turn {correction_turn} of {_MAX_EXPERIMENT_CORRECTION_TURNS}.
Stay in this same Codex thread.

Exact validation error:
{validation_error}

Prior invalid structured output, for diagnosis only:
{_pretty_json(invalid_output)}

Return a complete replacement object with exactly 3 candidates. Do not defend, patch, or
partially amend the prior output. Do not invent another command grammar.

{_experiment_command_grammar()}

All other candidate constraints remain unchanged: exact hypothesis IDs, canonical string
predictions and runtime estimates, touched_files=[], risk="low", command_count=1, and no
mutation. Return only the corrected structured object."""

    @classmethod
    def _proposal_candidates(
        cls,
        output: Mapping[str, Any],
    ) -> tuple[LiveExperimentCandidate, ...]:
        del cls
        return validate_live_experiment_proposal(output)

    async def repair(
        self,
        packet: RevocationPacket,
        *,
        replacement_worktree: Path,
    ) -> LiveCodexResult:
        scopes = _normalize_scope(packet.allowed_repair_scope)
        targeted = _normalize_argv(packet.targeted_test_argv)
        full = _normalize_argv(packet.full_test_argv)
        migration_rule = (
            (
                f"7. Replace the entire contents of {MIGRATION_SOURCE_PATH} with exactly "
                "this UTF-8 text, including its final newline and with no comments or "
                f"extra whitespace:\n{_pretty_json(OPAQUE_CONTRACT_SQL)}\n"
            )
            if MIGRATION_SOURCE_PATH in scopes
            else ""
        )
        prompt = f"""You are a fresh Codex repair session operating in a clean replacement
worktree after selective revocation. The RevocationPacket below is the complete authority
boundary for this repair.

REVOCATION PACKET:
{_pretty_json(asdict(packet))}

Rules:
1. Inspect the current clean worktree and implement the smallest repair consistent with
   replacement_evidence, evidence_diff, experiment_result, and active_premise_revisions.
2. Modify only these allowed paths: {_pretty_json(scopes)}.
3. Never edit tests unless a test path is explicitly in the allowed list.
4. Do not touch the quarantine ref or original worktree. Do not commit, push, install
   packages, access the network, or use a shell wrapper.
5. Run these exact argv commands in order after editing:
   targeted: {_pretty_json(targeted)}
   full: {_pretty_json(full)}
6. Keep repairing until both commands pass. Return only the requested structured report.
   changed_paths must exactly match the paths actually changed on disk.
{migration_rule}
"""
        result = await self._execute_stage(
            stage="codex-bounded-repair",
            prompt=prompt,
            cwd=replacement_worktree,
            sandbox=CodexSandbox.WORKSPACE_WRITE,
            output_schema=_WRITE_REPORT_SCHEMA,
            allowed_scope=scopes,
            require_clean=True,
        )
        self._validate_write_report(result)
        return result

    @staticmethod
    def _validate_write_report(result: LiveCodexResult) -> None:
        reported = result.structured_output.get("changed_paths")
        if not isinstance(reported, list):
            raise CodexProtocolError("Codex write report omitted changed_paths")
        try:
            reported_paths = tuple(sorted(_safe_relative_path(str(item)) for item in reported))
        except ValidationError as exc:
            raise CodexProtocolError("Codex reported an unsafe changed path") from exc
        if reported_paths != tuple(sorted(result.changed_paths)):
            raise CodexProtocolError(
                "Codex changed_paths report does not match the actual Git workspace diff"
            )
        if result.structured_output.get("verification_passed") is not True:
            raise AuthorizationError("Codex did not report passing verification")

    @staticmethod
    def _experiment_candidate(value: object) -> LiveExperimentCandidate:
        return validate_live_experiment_candidate(value)

    async def _execute_stage(
        self,
        *,
        stage: str,
        prompt: str,
        cwd: Path,
        sandbox: CodexSandbox,
        output_schema: Mapping[str, Any],
        allowed_scope: Sequence[str],
        require_clean: bool = False,
        require_read_only_unchanged: bool = False,
        thread_id: str | None = None,
    ) -> LiveCodexResult:
        workspace = cwd.expanduser().resolve(strict=True)
        before = await self._git_snapshot(workspace)
        if require_clean and not before.clean:
            raise AuthorizationError("live Codex write session requires a clean worktree")
        event_observations: list[CodexEventObservation] = []

        def observe_event(event: CodexEvent) -> None:
            event_observations.append(
                CodexEventObservation(
                    sequence=event.sequence,
                    event_type=event.event_type,
                    thread_id=event.thread_id,
                    turn_id=event.turn_id,
                    item_id=event.item_id,
                    observed_at_utc=datetime.now(timezone.utc),
                    observed_monotonic=time.monotonic(),
                )
            )

        started_at_utc = datetime.now(timezone.utc)
        codex_result = await self._execute_codex(
            prompt,
            cwd=workspace,
            sandbox=sandbox,
            output_schema=output_schema,
            thread_id=thread_id,
            on_event=observe_event,
        )
        finished_at_utc = datetime.now(timezone.utc)
        if tuple(item.sequence for item in event_observations) != tuple(
            item.sequence for item in codex_result.events
        ):
            raise IntegrityError("streamed Codex event observations are incomplete")
        after = await self._git_snapshot(workspace)
        workspace_changed = before.digest != after.digest
        changes = await self._changes_from_base(workspace, before.head)
        exposed_changes = (
            changes if sandbox is CodexSandbox.WORKSPACE_WRITE else _WorkspaceChanges((), "")
        )
        artifacts = self._persist_artifacts(
            stage=stage,
            run=codex_result,
            prompt=prompt,
            before=before,
            after=after,
            changes=changes if workspace_changed else exposed_changes,
            event_observations=event_observations,
            started_at_utc=started_at_utc,
            finished_at_utc=finished_at_utc,
        )
        structured = codex_result.structured_output
        if not isinstance(structured, Mapping):
            raise CodexProtocolError("Codex structured output is not an object")
        result = LiveCodexResult(
            stage=stage,
            worktree=workspace,
            thread_id=codex_result.thread_id,
            turn_ids=codex_result.turn_ids,
            item_ids=codex_result.item_ids,
            final_message=codex_result.final_message,
            structured_output=dict(structured),
            changed_paths=exposed_changes.paths,
            diff=exposed_changes.diff,
            command_evidence=self._command_evidence(codex_result.events),
            event_observations=tuple(event_observations),
            process_id=codex_result.process.process_id,
            pid=codex_result.process.pid,
            process_started_monotonic=codex_result.process.started_monotonic,
            process_finished_monotonic=codex_result.process.finished_monotonic,
            duration_seconds=codex_result.process.duration_seconds,
            started_at_utc=started_at_utc,
            finished_at_utc=finished_at_utc,
            executable=codex_result.executable.path,
            executable_version=codex_result.executable.version,
            model=codex_result.model,
            sandbox=codex_result.sandbox,
            artifacts=artifacts,
            supervisor_argv=codex_result.process.argv,
            executable_sha256=_sha256(codex_result.executable.path.read_bytes()),
        )
        if require_read_only_unchanged and workspace_changed:
            raise AuthorizationError("read-only Codex session changed the Git worktree")
        if sandbox is CodexSandbox.WORKSPACE_WRITE:
            if before.head != after.head:
                raise AuthorizationError("Codex committed during an uncommitted repair session")
            if not changes.paths or not changes.diff:
                raise CodexProtocolError("Codex write session produced no auditable Git diff")
            escaped = tuple(
                path for path in changes.paths if not _path_is_allowed(path, allowed_scope)
            )
            if escaped:
                raise AuthorizationError(
                    "Codex changed paths outside the repair authority: " + ", ".join(escaped)
                )
        return result

    async def _execute_codex(
        self,
        prompt: str,
        *,
        cwd: Path,
        sandbox: CodexSandbox,
        output_schema: Mapping[str, Any],
        thread_id: str | None,
        on_event: Callable[[CodexEvent], None],
    ) -> CodexRunResult:
        try:
            return await self.adapter.execute(
                prompt,
                cwd=cwd,
                sandbox=sandbox,
                output_schema=output_schema,
                thread_id=thread_id,
                timeout_seconds=self.timeout_seconds,
                on_event=on_event,
            )
        except (
            CodexAuthenticationError,
            CodexModelError,
            CodexProtocolError,
            CodexTimeoutError,
        ):
            raise
        except CodexError as exc:
            message = str(exc).lower()
            if "model" in message and any(
                phrase in message
                for phrase in ("not supported", "unsupported", "not available", "no access")
            ):
                raise CodexModelError(
                    f"Codex rejected model {self.adapter.default_model or '<default>'}"
                ) from exc
            if "schema" in message and any(
                phrase in message for phrase in ("invalid", "rejected", "unsupported")
            ):
                raise CodexProtocolError("Codex rejected the structured output schema") from exc
            if any(phrase in message for phrase in ("authentication", "not logged in", "401")):
                raise CodexAuthenticationError("Codex authentication failed") from exc
            raise

    async def _git_snapshot(self, workspace: Path) -> _GitSnapshot:
        head = (await self._git(workspace, ("rev-parse", "HEAD"))).stdout.strip()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head):
            raise IntegrityError("live Codex worktree HEAD is not a Git object ID")
        status = (
            await self._git(
                workspace,
                ("status", "--porcelain=v1", "--untracked-files=all"),
            )
        ).stdout
        diff = (await self._git(workspace, ("diff", "--binary", "HEAD", "--"))).stdout
        return _GitSnapshot(head=head, status=status, diff=diff)

    async def _changes_from_base(self, workspace: Path, base: str) -> _WorkspaceChanges:
        tracked_names = (
            await self._git(workspace, ("diff", "--name-only", "-z", base, "--"))
        ).stdout.split("\x00")
        untracked_names = (
            await self._git(
                workspace,
                ("ls-files", "--others", "--exclude-standard", "-z"),
            )
        ).stdout.split("\x00")
        paths = tuple(
            sorted(
                {_safe_relative_path(item) for item in (*tracked_names, *untracked_names) if item}
            )
        )
        tracked_diff = (
            await self._git(workspace, ("diff", "--binary", "--no-ext-diff", base, "--"))
        ).stdout
        untracked_patches: list[str] = []
        for item in sorted(name for name in untracked_names if name):
            patch = await self._git(
                workspace,
                (
                    "diff",
                    "--no-index",
                    "--binary",
                    "--no-ext-diff",
                    "--no-color",
                    "--",
                    os.devnull,
                    item,
                ),
                allowed_exit_codes=(0, 1),
            )
            untracked_patches.append(patch.stdout)
        return _WorkspaceChanges(paths=paths, diff=tracked_diff + "".join(untracked_patches))

    async def _git(
        self,
        workspace: Path,
        argv: Sequence[str],
        *,
        allowed_exit_codes: Sequence[int] = (0,),
    ) -> ProcessResult:
        result = await self.runner.run(
            ("git", "-C", str(workspace), *argv),
            cwd=workspace,
            timeout_seconds=60,
            allowed_exit_codes=allowed_exit_codes,
        )
        if result.exit_code not in allowed_exit_codes or result.output_truncated:
            detail = redact_text(result.stderr.strip() or result.stdout.strip())
            raise IntegrityError(f"Git proof command failed: {detail[:500]}")
        return result

    @staticmethod
    def _command_evidence(events: Sequence[CodexEvent]) -> tuple[CommandEvidence, ...]:
        found: list[CommandEvidence] = []
        for event in events:
            item = event.raw.get("item")
            if not isinstance(item, Mapping) or item.get("type") != "command_execution":
                continue
            command = item.get("command")
            if not isinstance(command, str) or not command:
                continue
            exit_code = item.get("exit_code")
            found.append(
                CommandEvidence(
                    item_id=str(item["id"]) if item.get("id") is not None else event.item_id,
                    command=command,
                    status=str(item["status"]) if item.get("status") is not None else None,
                    exit_code=int(exit_code) if isinstance(exit_code, int) else None,
                )
            )
        return tuple(found)

    def _persist_artifacts(
        self,
        *,
        stage: str,
        run: CodexRunResult,
        prompt: str,
        before: _GitSnapshot,
        after: _GitSnapshot,
        changes: _WorkspaceChanges,
        event_observations: Sequence[CodexEventObservation],
        started_at_utc: datetime,
        finished_at_utc: datetime,
    ) -> LiveCodexArtifacts:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", stage):
            raise ValidationError("invalid live Codex artifact stage")
        root = self.session_artifacts_root / f"{stage}-{secrets.token_hex(8)}"
        root.mkdir(mode=0o700, parents=False)
        events_payload = b"".join(canonical_json(event.raw) + b"\n" for event in run.events)
        observations_payload = b"".join(
            canonical_json(
                {
                    "sequence": observation.sequence,
                    "event_type": observation.event_type,
                    "thread_id": observation.thread_id,
                    "turn_id": observation.turn_id,
                    "item_id": observation.item_id,
                    "observed_at_utc": observation.observed_at_utc.isoformat(),
                    "observed_monotonic": observation.observed_monotonic,
                }
            )
            + b"\n"
            for observation in event_observations
        )
        payloads: dict[str, bytes] = {
            "prompt.txt": redact_text(prompt).encode("utf-8"),
            "events.jsonl": events_payload,
            "event-observations.jsonl": observations_payload,
            "last-message.txt": run.final_message.encode("utf-8"),
            "changed-paths.json": canonical_json(list(changes.paths)),
            "workspace.diff": changes.diff.encode("utf-8"),
            "stdout.log": run.process.stdout.encode("utf-8"),
            "stderr.log": run.process.stderr.encode("utf-8"),
        }
        digests = {name: _sha256(payload) for name, payload in payloads.items()}
        payloads["stdout.sha256"] = (digests["stdout.log"] + "\n").encode("ascii")
        payloads["stderr.sha256"] = (digests["stderr.log"] + "\n").encode("ascii")
        for name, payload in payloads.items():
            self._atomic_write(root / name, payload)
        turn_event_sequences = [
            event.sequence for event in run.events if event.event_type.startswith("turn.")
        ]
        manifest = {
            "protocol": "tars.live-codex/v1",
            "stage": stage,
            "thread_id": run.thread_id,
            "turn_ids": list(run.turn_ids),
            "turn_event_sequences": turn_event_sequences,
            "item_ids": list(run.item_ids),
            "process_id": run.process.process_id,
            "pid": run.process.pid,
            "executable": str(run.executable.path),
            "executable_version": run.executable.version,
            "executable_sha256": _sha256(run.executable.path.read_bytes()),
            "supervisor_argv": list(run.process.argv),
            "model": run.model,
            "sandbox": run.sandbox.value,
            "worktree": str(run.process.cwd),
            "started_at_utc": started_at_utc.isoformat(),
            "finished_at_utc": finished_at_utc.isoformat(),
            "process_started_monotonic": run.process.started_monotonic,
            "process_finished_monotonic": run.process.finished_monotonic,
            "duration_seconds": run.process.duration_seconds,
            "output_schema_digest": run.output_schema_digest,
            "before_head": before.head,
            "after_head": after.head,
            "before_workspace_digest": before.digest,
            "after_workspace_digest": after.digest,
            "changed_paths": list(changes.paths),
            "files": {
                name: {
                    "path": name,
                    "sha256": _sha256(payload),
                    "size": len(payload),
                }
                for name, payload in sorted(payloads.items())
            },
        }
        manifest_payload = canonical_json(manifest)
        manifest_digest = _sha256(manifest_payload)
        self._atomic_write(root / "manifest.json", manifest_payload)
        self._atomic_write(root / "manifest.sha256", (manifest_digest + "\n").encode("ascii"))
        return LiveCodexArtifacts(
            root=root,
            prompt_path=root / "prompt.txt",
            events_path=root / "events.jsonl",
            event_observations_path=root / "event-observations.jsonl",
            last_message_path=root / "last-message.txt",
            changed_paths_path=root / "changed-paths.json",
            diff_path=root / "workspace.diff",
            stdout_path=root / "stdout.log",
            stderr_path=root / "stderr.log",
            stdout_digest_path=root / "stdout.sha256",
            stderr_digest_path=root / "stderr.sha256",
            manifest_path=root / "manifest.json",
            manifest_digest_path=root / "manifest.sha256",
            stdout_digest=digests["stdout.log"],
            stderr_digest=digests["stderr.log"],
            manifest_digest=manifest_digest,
        )

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise IntegrityError(f"failed to persist live Codex artifact {path.name}") from exc
