from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from tars_revoke.errors import ValidationError

from .canonical import canonical_digest, canonical_json
from .enums import (
    ActionState,
    ActionType,
    AgentState,
    DispatchReconciliationOutcome,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    EvidenceRole,
    ExperimentState,
    LeaseState,
    NodeKind,
    OutboxState,
    PremiseState,
    ReceiptState,
    Reversibility,
    RevocationCaseState,
    RevocationMemberKind,
    RiskLevel,
    RunState,
    SessionState,
    SignatureStatus,
    TestKind,
    TestState,
    ValueSemantics,
    VerificationStatus,
    WarrantState,
)

NonEmptyStr = Annotated[str, Field(min_length=1)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]


class DomainModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        str_strip_whitespace=True,
    )

    @field_validator("id", check_fields=False)
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("id must be non-empty and contain no control characters")
        return value


class Run(DomainModel):
    id: NonEmptyStr
    name: NonEmptyStr
    state: RunState = RunState.DECLARED
    root_path: NonEmptyStr
    created_at: AwareDatetime
    updated_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class Agent(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    name: NonEmptyStr
    role: NonEmptyStr
    worktree_path: NonEmptyStr
    state: AgentState = AgentState.DECLARED
    created_at: AwareDatetime
    updated_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class AgentSession(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    agent_id: NonEmptyStr
    provider: NonEmptyStr
    external_session_id: str | None = None
    state: SessionState = SessionState.DECLARED
    started_at: AwareDatetime
    updated_at: AwareDatetime
    ended_at: AwareDatetime | None = None
    process_id: int | None = Field(default=None, ge=1)
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_interval(self) -> AgentSession:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("ended_at cannot precede started_at")
        return self


class EvidenceSource(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    name: NonEmptyStr
    uri: NonEmptyStr
    issuer: NonEmptyStr
    public_key: str | None = None
    signature_algorithm: str | None = None
    pinned_identity: NonEmptyStr
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class ArtifactRef(DomainModel):
    digest: Digest
    size: int = Field(ge=0)
    media_type: NonEmptyStr = "application/octet-stream"
    relative_path: NonEmptyStr
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class EvidenceRecord(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    source_id: NonEmptyStr
    source_uri: NonEmptyStr
    source_version: int = Field(ge=0)
    observed_at: AwareDatetime
    valid_at: AwareDatetime
    digest: Digest
    signature_status: SignatureStatus
    verification_status: VerificationStatus
    artifact_digest: Digest | None = None
    normalized_premises: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class Premise(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    scope: NonEmptyStr
    subject: NonEmptyStr
    relation: NonEmptyStr
    value: Any
    value_digest: Digest
    semantics: ValueSemantics
    state: PremiseState = PremiseState.PROPOSED
    valid_at: AwareDatetime
    invalid_at: AwareDatetime | None = None
    invalidated_by_evidence_id: str | None = None
    replaces_premise_id: str | None = None
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def populate_value_digest(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and "value" in value and not value.get("value_digest"):
            copy = dict(value)
            copy["value_digest"] = canonical_digest(copy["value"])
            return copy
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Premise:
        canonical_json(self.value)
        expected = canonical_digest(self.value)
        if self.value_digest != expected:
            raise ValueError("value_digest does not match canonical premise value")
        terminal = self.state in {PremiseState.INVALIDATED, PremiseState.SUPERSEDED}
        if terminal and self.invalid_at is None:
            raise ValueError("terminal premise revisions require invalid_at")
        if self.state == PremiseState.INVALIDATED and not self.invalidated_by_evidence_id:
            raise ValueError("invalidated premise requires invalidating evidence")
        if not terminal and self.invalid_at is not None:
            raise ValueError("non-terminal premise cannot have invalid_at")
        if self.invalid_at is not None and self.invalid_at < self.valid_at:
            raise ValueError("invalid_at cannot precede valid_at")
        if self.replaces_premise_id == self.id:
            raise ValueError("premise cannot replace itself")
        return self


class PremiseEvidence(DomainModel):
    premise_id: NonEmptyStr
    evidence_id: NonEmptyStr
    role: EvidenceRole
    confidence: Probability
    created_at: AwareDatetime


class GraphNode(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    kind: NodeKind
    entity_id: NonEmptyStr
    scope: NonEmptyStr
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class DependencyEdge(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    source_node_id: NonEmptyStr
    target_node_id: NonEmptyStr
    edge_type: EdgeType
    strength: EdgeStrength
    scope: NonEmptyStr
    declared_by: NonEmptyStr
    confidence: Probability
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_self_edge(self) -> DependencyEdge:
        if self.source_node_id == self.target_node_id:
            raise ValueError("dependency edge cannot point to itself")
        return self


class Warrant(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    agent_id: str | None = None
    scope: NonEmptyStr
    authorized_targets: tuple[NonEmptyStr, ...]
    state: WarrantState = WarrantState.DECLARED
    risk: RiskLevel
    revision_epoch: int = Field(default=0, ge=0)
    artifact_hashes: Mapping[str, Digest] = Field(default_factory=dict)
    required_tests: tuple[str, ...] = ()
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    revoked_at: AwareDatetime | None = None
    revoke_cause: str | None = None
    replaces_warrant_id: str | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Warrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("warrant expiry must follow issue time")
        if self.state == WarrantState.REVOKED and self.revoked_at is None:
            raise ValueError("revoked warrant requires revoked_at")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("revoked_at cannot precede issued_at")
        if self.replaces_warrant_id == self.id:
            raise ValueError("warrant cannot replace itself")
        if not self.authorized_targets or len(set(self.authorized_targets)) != len(
            self.authorized_targets
        ):
            raise ValueError("warrant requires unique authorized targets")
        return self


class WarrantPremise(DomainModel):
    warrant_id: NonEmptyStr
    premise_id: NonEmptyStr
    premise_digest: Digest
    created_at: AwareDatetime


class ActionIntent(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    agent_id: NonEmptyStr
    warrant_id: NonEmptyStr
    scope: NonEmptyStr
    action_type: ActionType
    target: NonEmptyStr
    payload_digest: Digest
    premise_vector: Mapping[str, Digest]
    artifact_vector: Mapping[str, Digest] = Field(default_factory=dict)
    risk: RiskLevel
    reversibility: Reversibility
    state: ActionState = ActionState.DECLARED
    not_before: AwareDatetime | None = None
    lease_id: str | None = None
    idempotency_key: NonEmptyStr
    replaces_action_id: str | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    dispatched_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    failure_reason: str | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> ActionIntent:
        if self.state in {ActionState.AUTHORIZED, ActionState.DISPATCHING} and not self.lease_id:
            raise ValueError("authorized or dispatching action requires a lease")
        if self.state == ActionState.DISPATCHING and self.dispatched_at is None:
            raise ValueError("dispatching action requires dispatched_at")
        if self.state == ActionState.EXECUTED and self.completed_at is None:
            raise ValueError("executed action requires completed_at")
        if self.replaces_action_id == self.id:
            raise ValueError("action cannot replace itself")
        return self


class EffectRecord(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    action_id: NonEmptyStr
    scope: NonEmptyStr
    target: NonEmptyStr
    effect_type: EffectType
    before_hash: str | None = None
    after_hash: str | None = None
    forward_artifact_digest: Digest | None = None
    reverse_artifact_digest: Digest | None = None
    reversibility: Reversibility
    compensation_handler: str | None = None
    state: EffectState = EffectState.DECLARED
    created_at: AwareDatetime
    updated_at: AwareDatetime
    dispatched_at: AwareDatetime | None = None
    compensated_at: AwareDatetime | None = None
    compensation_attempts: int = Field(default=0, ge=0)
    idempotency_key: NonEmptyStr
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_reversibility(self) -> EffectRecord:
        if self.reversibility == Reversibility.REVERSIBLE and not self.compensation_handler:
            raise ValueError("reversible effect requires a compensation handler")
        if self.state in {EffectState.DISPATCHING, EffectState.EXECUTED} and (
            self.dispatched_at is None
        ):
            raise ValueError("dispatching or executed effect requires dispatched_at")
        if self.state == EffectState.ROLLED_BACK and self.compensated_at is None:
            raise ValueError("rolled-back effect requires compensated_at")
        return self


class DispatchReconciliationRecord(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    action_id: NonEmptyStr
    effect_id: NonEmptyStr
    adapter: NonEmptyStr
    outcome: DispatchReconciliationOutcome
    expected: Mapping[str, Any]
    observed: Mapping[str, Any]
    reason: NonEmptyStr
    reconciled_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class ExecutionLease(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    action_id: NonEmptyStr
    effect_id: NonEmptyStr
    warrant_id: NonEmptyStr
    epoch: int = Field(ge=0)
    token_digest: Digest
    state: LeaseState = LeaseState.ACTIVE
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    consumed_at: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None
    idempotency_key: NonEmptyStr
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> ExecutionLease:
        if self.expires_at <= self.issued_at:
            raise ValueError("lease expiry must follow issue time")
        if self.state == LeaseState.CONSUMED and self.consumed_at is None:
            raise ValueError("consumed lease requires consumed_at")
        if self.state == LeaseState.REVOKED and self.revoked_at is None:
            raise ValueError("revoked lease requires revoked_at")
        return self


class RevocationCase(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    premise_id: NonEmptyStr
    trigger_evidence_id: NonEmptyStr
    state: RevocationCaseState = RevocationCaseState.OPEN
    reason: NonEmptyStr
    opened_at: AwareDatetime
    updated_at: AwareDatetime
    closed_at: AwareDatetime | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> RevocationCase:
        if self.state == RevocationCaseState.CLOSED and self.closed_at is None:
            raise ValueError("closed revocation case requires closed_at")
        return self


class RevocationMember(DomainModel):
    case_id: NonEmptyStr
    node_id: NonEmptyStr
    member_kind: RevocationMemberKind
    entity_id: NonEmptyStr
    dependency_path: tuple[str, ...]
    created_at: AwareDatetime

    @field_validator("dependency_path")
    @classmethod
    def require_path(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("revocation member requires a dependency path")
        return value


class ExperimentCandidate(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    case_id: NonEmptyStr
    hypotheses: tuple[str, ...]
    predictions: Mapping[str, Any]
    argv: tuple[str, ...]
    fixture_refs: tuple[str, ...] = ()
    touched_files: tuple[str, ...] = ()
    risk: RiskLevel
    estimated_runtime_ms: int = Field(ge=0)
    command_count: int = Field(default=1, ge=1)
    state: ExperimentState = ExperimentState.PROPOSED
    rejection_reason: str | None = None
    score: tuple[int, int, int, int] | None = None
    created_at: AwareDatetime
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_candidate(self) -> ExperimentCandidate:
        if len(set(self.hypotheses)) < 2:
            raise ValueError("experiment requires at least two distinct hypotheses")
        if not self.argv or any(not arg for arg in self.argv):
            raise ValueError("experiment argv must be non-empty")
        if self.state == ExperimentState.REJECTED and not self.rejection_reason:
            raise ValueError("rejected experiment requires a reason")
        return self


class ExperimentRun(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    case_id: NonEmptyStr
    candidate_id: NonEmptyStr
    action_id: str | None = None
    state: ExperimentState
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    exit_code: int | None = None
    stdout_artifact_digest: Digest | None = None
    stderr_artifact_digest: Digest | None = None
    environment_digest: Digest
    observed_outcome: Any | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class TestRun(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    case_id: str | None = None
    action_id: str | None = None
    kind: TestKind
    argv: tuple[str, ...]
    state: TestState = TestState.PENDING
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    exit_code: int | None = None
    stdout_artifact_digest: Digest | None = None
    stderr_artifact_digest: Digest | None = None
    environment_digest: Digest
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @field_validator("argv")
    @classmethod
    def require_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not arg for arg in value):
            raise ValueError("test argv must be non-empty")
        return value


class Receipt(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    case_id: str | None = None
    state: ReceiptState = ReceiptState.DRAFT
    artifact_digest: Digest | None = None
    canonical_digest: Digest
    event_head_digest: Digest
    manifest_digest: Digest
    created_at: AwareDatetime
    verified_at: AwareDatetime | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_verification(self) -> Receipt:
        if self.state == ReceiptState.VERIFIED and self.verified_at is None:
            raise ValueError("verified receipt requires verified_at")
        return self


class EventRecord(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    sequence: int = Field(gt=0)
    kind: NonEmptyStr
    aggregate_type: NonEmptyStr
    aggregate_id: NonEmptyStr
    payload: Mapping[str, Any]
    created_at: AwareDatetime
    previous_hash: Digest
    event_hash: Digest


class OutboxRecord(DomainModel):
    id: NonEmptyStr
    run_id: NonEmptyStr
    event_id: NonEmptyStr
    topic: NonEmptyStr
    payload: Mapping[str, Any]
    state: OutboxState = OutboxState.PENDING
    attempts: int = Field(default=0, ge=0)
    available_at: AwareDatetime
    locked_at: AwareDatetime | None = None
    published_at: AwareDatetime | None = None
    last_error: str | None = None
    created_at: AwareDatetime


def ensure_json_value(value: Any) -> None:
    """Public validator for service boundaries accepting arbitrary JSON values."""

    try:
        canonical_json(value)
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - defensive normalization boundary
        raise ValidationError(str(exc)) from exc


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("datetime must be timezone-aware")
    return value
