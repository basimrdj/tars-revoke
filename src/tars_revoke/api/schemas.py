from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DemoStartRequest(ApiModel):
    scenario: str = Field(default="external-schema-v2", pattern=r"^external-schema-v2$")
    live_codex: bool = True


class RunInfo(ApiModel):
    id: str
    scenario: str
    execution_mode: Literal["live-codex", "scripted", "unknown"]
    status: str
    revocation_status: str | None = None
    started_at: datetime
    closed_at: datetime | None = None
    sequence: int = Field(ge=0)


class AgentSnapshot(ApiModel):
    id: str
    name: str
    task: str
    status: str
    thread_id: str | None = None
    worktree: str | None = None
    warrant_id: str | None = None
    lease_id: str | None = None
    last_heartbeat_at: datetime | None = None
    pushed_at: datetime | None = None


class CausalNodeSnapshot(ApiModel):
    id: str
    kind: str
    label: str
    detail: str | None = None
    status: str
    depth: int = Field(ge=0)
    lane: int = Field(ge=0)


class CausalEdgeSnapshot(ApiModel):
    id: str
    source: str
    target: str
    kind: str
    strength: str
    affected: bool


class CausalGraphSnapshot(ApiModel):
    nodes: tuple[CausalNodeSnapshot, ...] = ()
    edges: tuple[CausalEdgeSnapshot, ...] = ()


class WarrantSnapshot(ApiModel):
    id: str
    agent_id: str
    status: str
    issued_at: datetime
    expires_at: datetime | None = None
    lease_epoch: int = Field(ge=0)
    premise_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    artifact_hashes: Mapping[str, str] = Field(default_factory=dict)
    required_tests: tuple[str, ...] = ()
    revoked_reason: str | None = None


class EffectSnapshot(ApiModel):
    id: str
    agent_id: str
    action_id: str
    label: str
    effect_type: str
    target: str
    state: str
    reversibility: str
    before_hash: str | None = None
    after_hash: str | None = None
    compensated_at: datetime | None = None


class ExperimentCandidateSnapshot(ApiModel):
    id: str
    label: str
    command: tuple[str, ...]
    risk_rank: int = Field(ge=0)
    touched_files: int = Field(ge=0)
    estimated_runtime_ms: int = Field(ge=0)
    command_count: int = Field(ge=1)
    validation_status: str
    selected: bool
    predictions: Mapping[str, Any] = Field(default_factory=dict)


class ExperimentSnapshot(ApiModel):
    status: str
    candidates: tuple[ExperimentCandidateSnapshot, ...] = ()
    chosen_id: str | None = None
    exit_code: int | None = None
    result_digest: str | None = None


class EventSnapshot(ApiModel):
    sequence: int = Field(gt=0)
    type: str
    occurred_at: datetime
    summary: str
    status: str | None = None


class ReceiptSummary(ApiModel):
    id: str
    status: str
    digest: str
    event_count: int = Field(ge=0)
    proof_scope: tuple[str, ...] = ()
    verified_at: datetime | None = None
    path: str | None = None


class FailureSummary(ApiModel):
    status: Literal["FAILED", "CANCELLED"]
    error_type: str
    message: str
    stage: str
    occurred_at: datetime
    receipt_digest: str | None = None
    finalization_errors: tuple[str, ...] = ()


class RunSnapshot(ApiModel):
    run: RunInfo
    agents: tuple[AgentSnapshot, ...] = ()
    graph: CausalGraphSnapshot = Field(default_factory=CausalGraphSnapshot)
    warrants: tuple[WarrantSnapshot, ...] = ()
    effects: tuple[EffectSnapshot, ...] = ()
    experiment: ExperimentSnapshot | None = None
    events: tuple[EventSnapshot, ...] = ()
    receipt: ReceiptSummary | None = None
    failure: FailureSummary | None = None
    selected_warrant_id: str | None = None


class DoctorCheck(ApiModel):
    name: str
    ok: bool
    detail: str


class DoctorReport(ApiModel):
    ok: bool
    checks: tuple[DoctorCheck, ...]
