from __future__ import annotations

import asyncio
import hashlib
import json
import math
import subprocess
import sys
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock, current_thread
from time import perf_counter_ns
from typing import Any, cast

from tars_revoke.clock import FakeClock
from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    NodeKind,
    PremiseState,
    Reversibility,
    RiskLevel,
    RunState,
    SignatureStatus,
    ValueSemantics,
    VerificationStatus,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    DependencyEdge,
    EffectRecord,
    EventRecord,
    EvidenceRecord,
    EvidenceSource,
    GraphNode,
    Premise,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import AuthorizationError, IntegrityError, ValidationError
from tars_revoke.persistence.store import Store
from tars_revoke.services.gateway import EffectGateway
from tars_revoke.services.revocation import RevocationResult, SelectiveRevoker

SUITE_NAME = "RevokeBench-20"
TRIAL_COUNT = 20
SCOPE = "repository"
BENCHMARK_EPOCH = datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc)
BENCHMARK_SCHEDULE_SEED = 0x54415253
SCHEDULE_PROTOCOL = "tars.revokebench.schedule/v1"
WORKER_TRACE_PROTOCOL = "tars.revokebench.worker-trace/v1"
PRODUCER_PROTOCOL = "tars.revokebench.producer/v1"
BENCHMARK_OPERATIONS = ("dispatch", "unrelated", "invalidate")
# Large enough that the paired latency gate measures sustained unrelated work,
# rather than a few milliseconds of fixed SQLite/thread scheduling jitter.
UNRELATED_WORKLOAD_BYTES = 128 * 1024 * 1024
_HASH_CHUNK = b"tars-revoke-unrelated-artifact\n" * 2_048


@dataclass(frozen=True)
class _TrialFixture:
    store: Store
    clock: FakeClock
    gateway: EffectGateway
    revoker: SelectiveRevoker
    run_id: str
    premise_id: str
    evidence_id: str
    race_action_id: str
    race_effect_id: str
    race_token: str
    unrelated_baseline_action_id: str
    unrelated_baseline_effect_id: str
    unrelated_baseline_token: str
    unrelated_action_id: str
    unrelated_effect_id: str
    unrelated_token: str
    expected_effect_ids: tuple[str, ...]
    database_path: Path


@dataclass(frozen=True)
class _DispatchOutcome:
    succeeded: bool
    latency_ms: float
    denial: str | None
    denial_type: str | None


@dataclass
class _WorkerObservation:
    operation: str
    worker_id: str
    submission_ordinal: int
    thread_name: str | None = None
    thread_ident: int | None = None
    barrier_ordinal: int | None = None
    ready_ns: int | None = None
    released_ns: int | None = None
    started_ns: int | None = None
    ended_ns: int | None = None
    outcome: dict[str, Any] | None = None

    def as_record(self) -> dict[str, Any]:
        required = (
            self.thread_name,
            self.thread_ident,
            self.barrier_ordinal,
            self.ready_ns,
            self.released_ns,
            self.started_ns,
            self.ended_ns,
            self.outcome,
        )
        if any(value is None for value in required):
            raise IntegrityError(f"worker trace is incomplete: {self.operation}")
        return {
            "operation": self.operation,
            "worker_id": self.worker_id,
            "thread_name": self.thread_name,
            "thread_ident": self.thread_ident,
            "submission_ordinal": self.submission_ordinal,
            "barrier_ordinal": self.barrier_ordinal,
            "ready_ns": self.ready_ns,
            "released_ns": self.released_ns,
            "started_ns": self.started_ns,
            "ended_ns": self.ended_ns,
            "outcome": dict(cast(Mapping[str, Any], self.outcome)),
        }


class _BarrierObservation:
    def __init__(self, origin_ns: int) -> None:
        self._origin_ns = origin_ns
        self._lock = Lock()
        self._release_ns: int | None = None

    def release(self) -> None:
        observed = perf_counter_ns() - self._origin_ns
        with self._lock:
            if self._release_ns is not None:
                raise IntegrityError("benchmark barrier released more than once")
            self._release_ns = observed

    def require_release(self) -> int:
        with self._lock:
            if self._release_ns is None:
                raise IntegrityError("benchmark barrier release was not observed")
            return self._release_ns


def _digest(label: str) -> str:
    return sha256_digest(label)


def derive_submission_order(seed: int) -> tuple[str, ...]:
    """Derive a portable three-operation permutation from an integer seed."""

    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValidationError("benchmark schedule seed must be an integer")

    def ordering_key(operation: str) -> tuple[bytes, str]:
        material = f"{SCHEDULE_PROTOCOL}:{seed}:{operation}".encode()
        return hashlib.sha256(material).digest(), operation

    return tuple(sorted(BENCHMARK_OPERATIONS, key=ordering_key))


def _elapsed_ms(start_ns: int) -> float:
    return (perf_counter_ns() - start_ns) / 1_000_000


def _relative_ns(origin_ns: int) -> int:
    observed = perf_counter_ns() - origin_ns
    if observed < 0:  # pragma: no cover - perf_counter_ns is monotonic by contract
        raise IntegrityError("monotonic benchmark clock moved backwards")
    return observed


def _git_bytes(repository: Path, *args: str) -> bytes | None:
    try:
        result = subprocess.run(
            ("git", "-C", str(repository), *args),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _git_text(repository: Path, *args: str) -> str | None:
    raw = _git_bytes(repository, *args)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return None


def _source_repository(source_path: Path) -> Path | None:
    root = _git_text(source_path.parent, "rev-parse", "--show-toplevel")
    if root is None:
        return None
    candidate = Path(root).expanduser().resolve()
    return candidate if source_path.is_relative_to(candidate) else None


def _producer_provenance(suite: str) -> dict[str, Any]:
    source_path = Path(__file__).resolve()
    source_bytes = source_path.read_bytes()
    repository = _source_repository(source_path)
    source_relative = source_path.name
    commit: str | None = None
    tree: str | None = None
    blob_oid: str | None = None
    committed_bytes: bytes | None = None
    worktree_clean = False
    if repository is not None:
        source_relative = source_path.relative_to(repository).as_posix()
        commit = _git_text(repository, "rev-parse", "HEAD")
        tree = _git_text(repository, "rev-parse", "HEAD^{tree}")
        blob_oid = _git_text(repository, "rev-parse", f"HEAD:{source_relative}")
        committed_bytes = _git_bytes(repository, "show", f"HEAD:{source_relative}")
        status = _git_bytes(repository, "status", "--porcelain=v1", "--untracked-files=normal")
        worktree_clean = status == b""
    observed_argv = [str(argument) for argument in sys.argv]
    source_sha256 = sha256_digest(source_bytes)
    return {
        "protocol": PRODUCER_PROTOCOL,
        "entrypoint": "tars_revoke.demo.benchmarks:run_benchmark_suite",
        "command": {
            "observed_argv": observed_argv,
            "observed_argv_sha256": canonical_digest(observed_argv),
            "canonical_argv": [
                "tars-revoke",
                "bench",
                "--suite",
                suite,
                "--output-root",
                "<OUTPUT_ROOT>",
            ],
        },
        "source": {
            "path": source_relative,
            "artifact_path": "producer/benchmarks.py",
            "sha256": source_sha256,
            "source_commit": commit,
            "source_tree": tree,
            "committed_blob_oid": blob_oid,
            "committed_sha256": (
                sha256_digest(committed_bytes) if committed_bytes is not None else None
            ),
            "matches_committed_source": committed_bytes == source_bytes,
            "worktree_clean": worktree_clean,
        },
    }


def _persist_producer_source(root: Path, producer: Mapping[str, Any]) -> Path:
    source = producer.get("source")
    if not isinstance(source, Mapping):
        raise IntegrityError("benchmark producer source record is missing")
    artifact_path = source.get("artifact_path")
    if not isinstance(artifact_path, str) or not artifact_path:
        raise IntegrityError("benchmark producer source artifact path is invalid")
    target = (root / artifact_path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise IntegrityError("benchmark producer source artifact escapes its run root")
    payload = Path(__file__).resolve().read_bytes()
    if sha256_digest(payload) != source.get("sha256"):
        raise IntegrityError("benchmark producer source changed during execution")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValidationError("cannot calculate a percentile over an empty sample")
    if not 0.0 <= percentile <= 100.0:
        raise ValidationError("percentile must be between zero and one hundred")
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def _round_metric(value: float) -> float:
    return round(value, 6)


def _artifact_digest() -> str:
    digest = hashlib.sha256()
    remaining = UNRELATED_WORKLOAD_BYTES
    while remaining:
        chunk = _HASH_CHUNK[: min(remaining, len(_HASH_CHUNK))]
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _create_agent(store: Store, *, run_id: str, agent_id: str, root: Path, now: datetime) -> None:
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=run_id,
            name=agent_id,
            role="benchmark-agent",
            worktree_path=str(root / agent_id),
            state=AgentState.RUNNING,
            created_at=now,
            updated_at=now,
        )
    )


def _create_action(
    store: Store,
    *,
    action_id: str,
    run_id: str,
    agent_id: str,
    warrant_id: str,
    premise: Premise,
    action_type: ActionType,
    target: str,
    state: ActionState,
    reversibility: Reversibility,
    now: datetime,
) -> ActionIntent:
    action = ActionIntent(
        id=action_id,
        run_id=run_id,
        agent_id=agent_id,
        warrant_id=warrant_id,
        scope=premise.scope,
        action_type=action_type,
        target=target,
        payload_digest=_digest(f"payload:{action_id}"),
        premise_vector={premise.id: premise.value_digest},
        risk=RiskLevel.CRITICAL if action_type == ActionType.PUSH else RiskLevel.HIGH,
        reversibility=reversibility,
        state=state,
        idempotency_key=f"idempotency:{action_id}",
        created_at=now,
        updated_at=now,
        completed_at=now if state == ActionState.EXECUTED else None,
    )
    return store.create_action(action)


def _create_effect(
    store: Store,
    *,
    effect_id: str,
    run_id: str,
    action_id: str,
    target: str,
    effect_type: EffectType,
    state: EffectState,
    reversibility: Reversibility,
    now: datetime,
) -> EffectRecord:
    effect = EffectRecord(
        id=effect_id,
        run_id=run_id,
        action_id=action_id,
        scope=SCOPE,
        target=target,
        effect_type=effect_type,
        before_hash=_digest(f"before:{effect_id}"),
        after_hash=_digest(f"after:{effect_id}") if state == EffectState.EXECUTED else None,
        reversibility=reversibility,
        compensation_handler=(
            "benchmark.restore" if reversibility == Reversibility.REVERSIBLE else None
        ),
        state=state,
        created_at=now,
        updated_at=now,
        dispatched_at=now if state == EffectState.EXECUTED else None,
        idempotency_key=f"idempotency:{effect_id}",
    )
    return store.create_effect(effect)


def _graph_node(
    store: Store,
    *,
    run_id: str,
    node_id: str,
    kind: NodeKind,
    entity_id: str,
    now: datetime,
) -> None:
    store.create_graph_node(
        GraphNode(
            id=node_id,
            run_id=run_id,
            kind=kind,
            entity_id=entity_id,
            scope=SCOPE,
            created_at=now,
        )
    )


def _graph_edge(
    store: Store,
    *,
    run_id: str,
    edge_id: str,
    source: str,
    target: str,
    now: datetime,
) -> None:
    store.create_dependency_edge(
        DependencyEdge(
            id=edge_id,
            run_id=run_id,
            source_node_id=source,
            target_node_id=target,
            edge_type=EdgeType.REQUIRES,
            strength=EdgeStrength.HARD,
            scope=SCOPE,
            declared_by="revoke-bench",
            confidence=1.0,
            created_at=now,
        )
    )


def _build_trial(root: Path, trial: int) -> _TrialFixture:
    now = BENCHMARK_EPOCH + timedelta(seconds=trial)
    clock = FakeClock(now)
    database_path = root / "state" / f"trial-{trial:02d}.sqlite3"
    store = Store(database_path, clock=clock)
    run_id = f"revoke-bench-{trial:02d}"
    agent_a = f"agent-a-{trial:02d}"
    agent_b = f"agent-b-{trial:02d}"
    premise_id = f"premise-schema-v1-{trial:02d}"
    unrelated_premise_id = f"premise-observability-{trial:02d}"
    evidence_id = f"evidence-schema-v2-{trial:02d}"
    warrant_a_id = f"warrant-a-{trial:02d}"
    warrant_b_id = f"warrant-b-{trial:02d}"
    race_action_id = f"action-push-{trial:02d}"
    race_effect_id = f"effect-push-{trial:02d}"
    unrelated_baseline_action_id = f"action-unrelated-baseline-{trial:02d}"
    unrelated_baseline_effect_id = f"effect-unrelated-baseline-{trial:02d}"
    unrelated_action_id = f"action-unrelated-{trial:02d}"
    unrelated_effect_id = f"effect-unrelated-{trial:02d}"

    store.create_run(
        Run(
            id=run_id,
            name=f"RevokeBench trial {trial:02d}",
            state=RunState.RUNNING,
            root_path=str(root),
            created_at=now,
            updated_at=now,
            metadata={"suite": SUITE_NAME, "trial": trial},
        )
    )
    _create_agent(store, run_id=run_id, agent_id=agent_a, root=root, now=now)
    _create_agent(store, run_id=run_id, agent_id=agent_b, root=root, now=now)
    source_id = f"schema-registry-{trial:02d}"
    store.create_evidence_source(
        EvidenceSource(
            id=source_id,
            run_id=run_id,
            name="signed production schema registry",
            uri="https://registry.revoke-bench.test/billing",
            issuer="registry.revoke-bench.test",
            pinned_identity="billing-production",
            created_at=now,
        )
    )
    store.create_evidence_record(
        EvidenceRecord(
            id=evidence_id,
            run_id=run_id,
            source_id=source_id,
            source_uri="https://registry.revoke-bench.test/billing/v2",
            source_version=2,
            observed_at=now,
            valid_at=now,
            digest=_digest(f"signed-schema-v2:{trial}"),
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
        )
    )
    premise = store.create_premise(
        Premise(
            id=premise_id,
            run_id=run_id,
            scope=SCOPE,
            subject="billing.customer_id",
            relation="format",
            value="uuid",
            value_digest=canonical_digest("uuid"),
            semantics=ValueSemantics.SINGLE,
            state=PremiseState.ACTIVE,
            valid_at=now - timedelta(minutes=1),
            created_at=now - timedelta(minutes=1),
        )
    )
    unrelated_premise = store.create_premise(
        Premise(
            id=unrelated_premise_id,
            run_id=run_id,
            scope=SCOPE,
            subject="docs.observability",
            relation="format",
            value="markdown",
            value_digest=canonical_digest("markdown"),
            semantics=ValueSemantics.SINGLE,
            state=PremiseState.ACTIVE,
            valid_at=now - timedelta(minutes=1),
            created_at=now - timedelta(minutes=1),
        )
    )
    warrant_a = store.create_warrant(
        Warrant(
            id=warrant_a_id,
            run_id=run_id,
            agent_id=agent_a,
            scope=premise.scope,
            authorized_targets=(
                "migrations/002_customer_id_uuid.sql",
                "billing/models.py",
                "origin/main",
            ),
            state=WarrantState.AUTHORIZED,
            risk=RiskLevel.CRITICAL,
            revision_epoch=7,
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
        )
    )
    warrant_b = store.create_warrant(
        Warrant(
            id=warrant_b_id,
            run_id=run_id,
            agent_id=agent_b,
            scope=unrelated_premise.scope,
            authorized_targets=(
                "docs/control-observability.md",
                "docs/observability.md",
            ),
            state=WarrantState.AUTHORIZED,
            risk=RiskLevel.MEDIUM,
            revision_epoch=3,
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
        )
    )
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant_a.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=now,
        )
    )
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant_b.id,
            premise_id=unrelated_premise.id,
            premise_digest=unrelated_premise.value_digest,
            created_at=now,
        )
    )

    migration_action = _create_action(
        store,
        action_id=f"action-migration-{trial:02d}",
        run_id=run_id,
        agent_id=agent_a,
        warrant_id=warrant_a.id,
        premise=premise,
        action_type=ActionType.DATABASE_MIGRATION,
        target="migrations/002_customer_id_uuid.sql",
        state=ActionState.EXECUTED,
        reversibility=Reversibility.REVERSIBLE,
        now=now,
    )
    model_action = _create_action(
        store,
        action_id=f"action-model-{trial:02d}",
        run_id=run_id,
        agent_id=agent_a,
        warrant_id=warrant_a.id,
        premise=premise,
        action_type=ActionType.FILE_EDIT,
        target="billing/models.py",
        state=ActionState.EXECUTED,
        reversibility=Reversibility.REVERSIBLE,
        now=now,
    )
    push_action = _create_action(
        store,
        action_id=race_action_id,
        run_id=run_id,
        agent_id=agent_a,
        warrant_id=warrant_a.id,
        premise=premise,
        action_type=ActionType.PUSH,
        target="origin/main",
        state=ActionState.PREPARED,
        reversibility=Reversibility.CONDITIONAL,
        now=now,
    )
    baseline_action = _create_action(
        store,
        action_id=unrelated_baseline_action_id,
        run_id=run_id,
        agent_id=agent_b,
        warrant_id=warrant_b.id,
        premise=unrelated_premise,
        action_type=ActionType.FILE_EDIT,
        target="docs/control-observability.md",
        state=ActionState.PREPARED,
        reversibility=Reversibility.REVERSIBLE,
        now=now,
    )
    unrelated_action = _create_action(
        store,
        action_id=unrelated_action_id,
        run_id=run_id,
        agent_id=agent_b,
        warrant_id=warrant_b.id,
        premise=unrelated_premise,
        action_type=ActionType.FILE_EDIT,
        target="docs/observability.md",
        state=ActionState.PREPARED,
        reversibility=Reversibility.REVERSIBLE,
        now=now,
    )
    effect_specs = (
        (
            f"effect-migration-{trial:02d}",
            migration_action,
            EffectType.DATABASE_MIGRATION,
            "billing.sqlite",
            EffectState.EXECUTED,
            Reversibility.REVERSIBLE,
        ),
        (
            f"effect-model-{trial:02d}",
            model_action,
            EffectType.FILE_EDIT,
            "billing/models.py",
            EffectState.EXECUTED,
            Reversibility.REVERSIBLE,
        ),
        (
            race_effect_id,
            push_action,
            EffectType.PUSH,
            "origin/main",
            EffectState.PREPARED,
            Reversibility.CONDITIONAL,
        ),
    )
    expected_effect_ids: list[str] = []
    for effect_id, action, effect_type, target, state, reversibility in effect_specs:
        _create_effect(
            store,
            effect_id=effect_id,
            run_id=run_id,
            action_id=action.id,
            target=target,
            effect_type=effect_type,
            state=state,
            reversibility=reversibility,
            now=now,
        )
        expected_effect_ids.append(effect_id)

    for effect_id, action, target in (
        (unrelated_baseline_effect_id, baseline_action, "docs/control-observability.md"),
        (unrelated_effect_id, unrelated_action, "docs/observability.md"),
    ):
        _create_effect(
            store,
            effect_id=effect_id,
            run_id=run_id,
            action_id=action.id,
            target=target,
            effect_type=EffectType.FILE_EDIT,
            state=EffectState.PREPARED,
            reversibility=Reversibility.REVERSIBLE,
            now=now,
        )

    node_premise_a = f"node-premise-a-{trial:02d}"
    node_premise_b = f"node-premise-b-{trial:02d}"
    node_warrant_a = f"node-warrant-a-{trial:02d}"
    node_warrant_b = f"node-warrant-b-{trial:02d}"
    _graph_node(
        store,
        run_id=run_id,
        node_id=node_premise_a,
        kind=NodeKind.PREMISE,
        entity_id=premise.id,
        now=now,
    )
    _graph_node(
        store,
        run_id=run_id,
        node_id=node_premise_b,
        kind=NodeKind.PREMISE,
        entity_id=unrelated_premise.id,
        now=now,
    )
    _graph_node(
        store,
        run_id=run_id,
        node_id=node_warrant_a,
        kind=NodeKind.WARRANT,
        entity_id=warrant_a.id,
        now=now,
    )
    _graph_node(
        store,
        run_id=run_id,
        node_id=node_warrant_b,
        kind=NodeKind.WARRANT,
        entity_id=warrant_b.id,
        now=now,
    )
    _graph_edge(
        store,
        run_id=run_id,
        edge_id=f"edge-premise-a-warrant-{trial:02d}",
        source=node_premise_a,
        target=node_warrant_a,
        now=now,
    )
    _graph_edge(
        store,
        run_id=run_id,
        edge_id=f"edge-premise-b-warrant-{trial:02d}",
        source=node_premise_b,
        target=node_warrant_b,
        now=now,
    )

    affected_actions = (migration_action, model_action, push_action)
    for action, effect_id in zip(affected_actions, expected_effect_ids, strict=True):
        action_node = f"node-{action.id}"
        effect_node = f"node-{effect_id}"
        _graph_node(
            store,
            run_id=run_id,
            node_id=action_node,
            kind=NodeKind.ACTION,
            entity_id=action.id,
            now=now,
        )
        _graph_node(
            store,
            run_id=run_id,
            node_id=effect_node,
            kind=NodeKind.EFFECT,
            entity_id=effect_id,
            now=now,
        )
        _graph_edge(
            store,
            run_id=run_id,
            edge_id=f"edge-warrant-{action.id}",
            source=node_warrant_a,
            target=action_node,
            now=now,
        )
        _graph_edge(
            store,
            run_id=run_id,
            edge_id=f"edge-action-{effect_id}",
            source=action_node,
            target=effect_node,
            now=now,
        )

    for action, effect_id in (
        (baseline_action, unrelated_baseline_effect_id),
        (unrelated_action, unrelated_effect_id),
    ):
        action_node = f"node-{action.id}"
        effect_node = f"node-{effect_id}"
        _graph_node(
            store,
            run_id=run_id,
            node_id=action_node,
            kind=NodeKind.ACTION,
            entity_id=action.id,
            now=now,
        )
        _graph_node(
            store,
            run_id=run_id,
            node_id=effect_node,
            kind=NodeKind.EFFECT,
            entity_id=effect_id,
            now=now,
        )
        _graph_edge(
            store,
            run_id=run_id,
            edge_id=f"edge-warrant-{action.id}",
            source=node_warrant_b,
            target=action_node,
            now=now,
        )
        _graph_edge(
            store,
            run_id=run_id,
            edge_id=f"edge-action-{effect_id}",
            source=action_node,
            target=effect_node,
            now=now,
        )

    gateway = EffectGateway(store, clock=clock)
    race_token = f"race-token-{trial:02d}"
    unrelated_baseline_token = f"unrelated-baseline-token-{trial:02d}"
    unrelated_token = f"unrelated-token-{trial:02d}"
    for action, effect_id, token in (
        (push_action, race_effect_id, race_token),
        (baseline_action, unrelated_baseline_effect_id, unrelated_baseline_token),
        (unrelated_action, unrelated_effect_id, unrelated_token),
    ):
        gateway.authorize(
            action.id,
            effect_id=effect_id,
            current_artifact_hashes={},
            passed_test_ids=(),
            capability_token=token,
        )

    return _TrialFixture(
        store=store,
        clock=clock,
        gateway=gateway,
        revoker=SelectiveRevoker(store, clock=clock),
        run_id=run_id,
        premise_id=premise.id,
        evidence_id=evidence_id,
        race_action_id=race_action_id,
        race_effect_id=race_effect_id,
        race_token=race_token,
        unrelated_baseline_action_id=unrelated_baseline_action_id,
        unrelated_baseline_effect_id=unrelated_baseline_effect_id,
        unrelated_baseline_token=unrelated_baseline_token,
        unrelated_action_id=unrelated_action_id,
        unrelated_effect_id=unrelated_effect_id,
        unrelated_token=unrelated_token,
        expected_effect_ids=tuple(sorted(expected_effect_ids)),
        database_path=database_path,
    )


def _dispatch(
    fixture: _TrialFixture,
) -> _DispatchOutcome:
    started = perf_counter_ns()
    try:
        fixture.gateway.dispatch(
            fixture.race_action_id,
            effect_id=fixture.race_effect_id,
            capability_token=fixture.race_token,
            current_artifact_hashes={},
            passed_test_ids=(),
        )
    except AuthorizationError as exc:
        return _DispatchOutcome(False, _elapsed_ms(started), str(exc), type(exc).__name__)
    return _DispatchOutcome(True, _elapsed_ms(started), None, None)


def _invalidate(
    fixture: _TrialFixture,
    trial: int,
) -> tuple[RevocationResult, float]:
    started = perf_counter_ns()
    result = fixture.revoker.invalidate_and_fence(
        fixture.premise_id,
        invalidating_evidence_id=fixture.evidence_id,
        reason="signed production schema v2 invalidates the UUID premise",
        case_id=f"case-revoke-bench-{trial:02d}",
    )
    return result, _elapsed_ms(started)


def _complete_unrelated(
    fixture: _TrialFixture,
    *,
    action_id: str,
    effect_id: str,
    token: str,
) -> float:
    started = perf_counter_ns()
    artifact_digest = _artifact_digest()
    fixture.gateway.dispatch(
        action_id,
        effect_id=effect_id,
        capability_token=token,
        current_artifact_hashes={},
        passed_test_ids=(),
    )
    now = fixture.clock.utc_now()
    intent = fixture.store.get_effect(effect_id)
    if intent is None:
        raise IntegrityError(f"benchmark effect intent disappeared: {effect_id}")
    fixture.gateway.complete(
        EffectRecord.model_validate(
            intent.model_copy(
                update={
                    "after_hash": artifact_digest,
                    "state": EffectState.EXECUTED,
                    "updated_at": now,
                    "metadata": {
                        **intent.metadata,
                        "workload": "sha256-artifact-snapshot",
                        "workload_bytes": UNRELATED_WORKLOAD_BYTES,
                    },
                }
            ).model_dump()
        )
    )
    return _elapsed_ms(started)


def _dispatch_outcome(result: Any) -> dict[str, Any]:
    if not isinstance(result, _DispatchOutcome):
        raise IntegrityError("dispatch worker returned an invalid result")
    denial = None
    if result.denial is not None:
        denial = {
            "type": result.denial_type,
            "message": result.denial,
            "message_sha256": sha256_digest(result.denial),
        }
    return {
        "status": "DISPATCHED" if result.succeeded else "DENIED",
        "latency_ms": _round_metric(result.latency_ms),
        "denial": denial,
    }


def _invalidation_outcome(result: Any) -> dict[str, Any]:
    if not isinstance(result, tuple) or len(result) != 2:
        raise IntegrityError("invalidation worker returned an invalid result")
    revocation, latency = result
    if not isinstance(revocation, RevocationResult) or not isinstance(latency, float):
        raise IntegrityError("invalidation worker returned malformed evidence")
    return {
        "status": "INVALIDATED",
        "latency_ms": _round_metric(latency),
        "affected_effect_ids": sorted(revocation.affected_effect_ids),
    }


def _unrelated_outcome(result: Any) -> dict[str, Any]:
    if not isinstance(result, float):
        raise IntegrityError("unrelated worker returned an invalid result")
    return {"status": "COMPLETED", "latency_ms": _round_metric(result)}


def _observe_worker(
    barrier: Barrier,
    release: _BarrierObservation,
    observation: _WorkerObservation,
    origin_ns: int,
    operation: Callable[[], Any],
    describe: Callable[[Any], dict[str, Any]],
) -> Any:
    thread = current_thread()
    observation.thread_name = thread.name
    observation.thread_ident = thread.ident
    observation.ready_ns = _relative_ns(origin_ns)
    observation.barrier_ordinal = barrier.wait()
    observation.released_ns = release.require_release()
    observation.started_ns = _relative_ns(origin_ns)
    try:
        result = operation()
    except BaseException as exc:
        observation.ended_ns = _relative_ns(origin_ns)
        observation.outcome = {
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "error_sha256": sha256_digest(str(exc)),
        }
        raise
    observation.ended_ns = _relative_ns(origin_ns)
    observation.outcome = describe(result)
    return result


def _transition_records(
    events: list[EventRecord],
    *,
    aggregate_type: str,
    aggregate_id: str,
) -> list[dict[str, Any]]:
    return [
        {
            "sequence": event.sequence,
            "from": event.payload.get("from"),
            "to": event.payload.get("to"),
        }
        for event in events
        if event.aggregate_type == aggregate_type
        and event.aggregate_id == aggregate_id
        and event.kind == f"{aggregate_type}.transitioned"
    ]


def _worker_by_operation(records: list[dict[str, Any]], operation: str) -> dict[str, Any]:
    matches = [record for record in records if record.get("operation") == operation]
    if len(matches) != 1:
        raise IntegrityError(f"worker trace does not contain exactly one {operation} worker")
    return matches[0]


def _bind_durable_outcomes(
    records: list[dict[str, Any]],
    fixture: _TrialFixture,
    events: list[EventRecord],
) -> None:
    race_action = fixture.store.get_action(fixture.race_action_id)
    race_effect = fixture.store.get_effect(fixture.race_effect_id)
    premise = fixture.store.get_premise(fixture.premise_id)
    unrelated_action = fixture.store.get_action(fixture.unrelated_action_id)
    unrelated_effect = fixture.store.get_effect(fixture.unrelated_effect_id)
    if race_action is None:
        raise IntegrityError("benchmark race action is missing")
    if race_effect is None:
        raise IntegrityError("benchmark race effect is missing")
    if premise is None:
        raise IntegrityError("benchmark premise is missing")
    if unrelated_action is None:
        raise IntegrityError("benchmark unrelated action is missing")
    if unrelated_effect is None:
        raise IntegrityError("benchmark unrelated effect is missing")

    dispatch = _worker_by_operation(records, "dispatch")["outcome"]
    dispatch["durable"] = {
        "action_id": fixture.race_action_id,
        "observed_final_state": race_action.state.value,
        "transition_events": _transition_records(
            events, aggregate_type="action", aggregate_id=fixture.race_action_id
        ),
        "effect_id": fixture.race_effect_id,
        "effect_observed_final_state": race_effect.state.value,
        "effect_transition_events": _transition_records(
            events, aggregate_type="effect", aggregate_id=fixture.race_effect_id
        ),
    }
    invalidation = _worker_by_operation(records, "invalidate")["outcome"]
    invalidation["durable"] = {
        "premise_id": fixture.premise_id,
        "observed_final_state": premise.state.value,
        "transition_events": _transition_records(
            events, aggregate_type="premise", aggregate_id=fixture.premise_id
        ),
    }
    unrelated = _worker_by_operation(records, "unrelated")["outcome"]
    unrelated["durable"] = {
        "action_id": fixture.unrelated_action_id,
        "action_final_state": unrelated_action.state.value,
        "action_transition_events": _transition_records(
            events, aggregate_type="action", aggregate_id=fixture.unrelated_action_id
        ),
        "effect_id": fixture.unrelated_effect_id,
        "effect_final_state": unrelated_effect.state.value,
        "effect_transition_events": _transition_records(
            events, aggregate_type="effect", aggregate_id=fixture.unrelated_effect_id
        ),
    }


def _required_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise IntegrityError(f"benchmark {label} must be an integer")
    return value


def _validate_worker_trace(trace: Mapping[str, Any], expected_order: tuple[str, ...]) -> None:
    if trace.get("protocol") != WORKER_TRACE_PROTOCOL:
        raise IntegrityError("benchmark worker trace protocol is invalid")
    if trace.get("participant_count") != len(BENCHMARK_OPERATIONS):
        raise IntegrityError("benchmark worker trace participant count is invalid")
    release_ns = _required_int(trace.get("barrier_release_ns"), "barrier release")
    workers = trace.get("workers")
    if not isinstance(workers, list) or len(workers) != len(BENCHMARK_OPERATIONS):
        raise IntegrityError("benchmark worker trace must contain exactly three workers")
    operations = [worker.get("operation") for worker in workers if isinstance(worker, Mapping)]
    if operations != list(expected_order):
        raise IntegrityError("benchmark worker trace order differs from its schedule")
    worker_ids: set[str] = set()
    thread_identities: set[tuple[str, int]] = set()
    barrier_ordinals: set[int] = set()
    for ordinal, worker in enumerate(workers):
        if not isinstance(worker, Mapping) or worker.get("submission_ordinal") != ordinal:
            raise IntegrityError("benchmark worker submission ordinal is invalid")
        operation = expected_order[ordinal]
        worker_id = worker.get("worker_id")
        if worker_id != f"worker-{operation}" or worker_id in worker_ids:
            raise IntegrityError("benchmark worker identity is invalid")
        worker_ids.add(worker_id)
        thread_name = worker.get("thread_name")
        thread_ident = _required_int(worker.get("thread_ident"), "thread identity")
        if not isinstance(thread_name, str) or not thread_name:
            raise IntegrityError("benchmark thread name is invalid")
        thread_identity = (thread_name, thread_ident)
        if thread_identity in thread_identities:
            raise IntegrityError("benchmark workers did not use three distinct threads")
        thread_identities.add(thread_identity)
        barrier_ordinal = _required_int(worker.get("barrier_ordinal"), "barrier ordinal")
        barrier_ordinals.add(barrier_ordinal)
        ready_ns = _required_int(worker.get("ready_ns"), "ready observation")
        released_ns = _required_int(worker.get("released_ns"), "released observation")
        started_ns = _required_int(worker.get("started_ns"), "start observation")
        ended_ns = _required_int(worker.get("ended_ns"), "end observation")
        if not 0 <= ready_ns <= released_ns == release_ns <= started_ns <= ended_ns:
            raise IntegrityError("benchmark worker monotonic observations are invalid")
        if not isinstance(worker.get("outcome"), Mapping):
            raise IntegrityError("benchmark worker outcome is missing")
    if barrier_ordinals != set(range(len(BENCHMARK_OPERATIONS))):
        raise IntegrityError("benchmark barrier ordinals are not unique and complete")


def _validate_dispatch_claim(trial: Mapping[str, Any], worker: Mapping[str, Any]) -> None:
    outcome = worker.get("outcome")
    if not isinstance(outcome, Mapping):
        raise IntegrityError("benchmark dispatch outcome is missing")
    succeeded = trial.get("dispatch_succeeded")
    if not isinstance(succeeded, bool):
        raise IntegrityError("benchmark dispatch result is not boolean")
    dispatch_sequences = trial.get("dispatch_sequences")
    if not isinstance(dispatch_sequences, list) or any(
        not isinstance(sequence, int) or isinstance(sequence, bool)
        for sequence in dispatch_sequences
    ):
        raise IntegrityError("benchmark dispatch sequences are malformed")
    durable = outcome.get("durable")
    if not isinstance(durable, Mapping):
        raise IntegrityError("benchmark dispatch outcome lacks durable evidence")
    transitions = durable.get("transition_events")
    if not isinstance(transitions, list) or not transitions:
        raise IntegrityError("benchmark dispatch transition evidence is missing")
    durable_dispatches = [
        transition.get("sequence")
        for transition in transitions
        if isinstance(transition, Mapping)
        and transition.get("to") == ActionState.DISPATCHING.value
    ]
    if durable_dispatches != dispatch_sequences or succeeded != bool(durable_dispatches):
        raise IntegrityError("benchmark dispatch claim differs from durable action events")
    effect_transitions = durable.get("effect_transition_events")
    if not isinstance(effect_transitions, list) or not effect_transitions:
        raise IntegrityError("benchmark dispatch effect transition evidence is missing")
    effect_dispatches = [
        transition.get("sequence")
        for transition in effect_transitions
        if isinstance(transition, Mapping)
        and transition.get("to") == EffectState.DISPATCHING.value
    ]
    if succeeded != bool(effect_dispatches):
        raise IntegrityError("benchmark dispatch claim differs from durable effect events")
    expected_status = "DISPATCHED" if succeeded else "DENIED"
    denial = outcome.get("denial")
    if outcome.get("status") != expected_status:
        raise IntegrityError("benchmark dispatch outcome status is inconsistent")
    latency = trial.get("latency_ms")
    if not isinstance(latency, Mapping) or outcome.get("latency_ms") != latency.get("dispatch"):
        raise IntegrityError("benchmark dispatch latency differs from its worker outcome")
    if succeeded and (denial is not None or trial.get("dispatch_denial") is not None):
        raise IntegrityError("successful benchmark dispatch records a denial")
    if not succeeded:
        if not isinstance(denial, Mapping) or denial.get("message") != trial.get(
            "dispatch_denial"
        ):
            raise IntegrityError("denied benchmark dispatch lacks matching denial evidence")
        message = denial.get("message")
        if (
            denial.get("type") != AuthorizationError.__name__
            or not isinstance(message, str)
            or denial.get("message_sha256") != sha256_digest(message)
        ):
            raise IntegrityError("benchmark dispatch denial digest is invalid")
    if durable.get("action_id") != trial.get("race_action_id") or durable.get(
        "effect_id"
    ) != trial.get("race_effect_id"):
        raise IntegrityError("benchmark dispatch evidence is bound to the wrong intent")
    if durable.get("observed_final_state") != ActionState.REVOKE_PENDING.value:
        raise IntegrityError("benchmark race action was not durably fenced")
    if durable.get("effect_observed_final_state") != EffectState.REVOKE_PENDING.value:
        raise IntegrityError("benchmark race effect was not durably fenced")
    last_transition = transitions[-1]
    if not isinstance(last_transition, Mapping) or last_transition.get(
        "to"
    ) != ActionState.REVOKE_PENDING.value:
        raise IntegrityError("benchmark race action terminal observation is not a fence")
    last_effect_transition = effect_transitions[-1]
    if not isinstance(last_effect_transition, Mapping) or last_effect_transition.get(
        "to"
    ) != EffectState.REVOKE_PENDING.value:
        raise IntegrityError("benchmark race effect terminal observation is not a fence")


def _validate_other_worker_claims(trial: Mapping[str, Any], trace: Mapping[str, Any]) -> None:
    workers = trace.get("workers")
    if not isinstance(workers, list):
        raise IntegrityError("benchmark worker trace is missing")
    invalidation = _worker_by_operation(workers, "invalidate").get("outcome")
    unrelated = _worker_by_operation(workers, "unrelated").get("outcome")
    if not isinstance(invalidation, Mapping) or not isinstance(unrelated, Mapping):
        raise IntegrityError("benchmark worker outcome evidence is missing")
    invalidation_durable = invalidation.get("durable")
    unrelated_durable = unrelated.get("durable")
    invalidation_transitions = (
        invalidation_durable.get("transition_events")
        if isinstance(invalidation_durable, Mapping)
        else None
    )
    invalidation_sequences = [
        transition.get("sequence")
        for transition in invalidation_transitions or []
        if isinstance(transition, Mapping)
        and transition.get("to") == PremiseState.INVALIDATED.value
    ]
    latency = trial.get("latency_ms")
    if (
        invalidation.get("status") != "INVALIDATED"
        or not isinstance(invalidation_durable, Mapping)
        or invalidation_durable.get("observed_final_state") != PremiseState.INVALIDATED.value
        or invalidation_durable.get("premise_id") != trial.get("premise_id")
        or invalidation_sequences != [trial.get("invalidation_sequence")]
        or invalidation.get("affected_effect_ids") != trial.get("affected_effect_ids")
        or not isinstance(latency, Mapping)
        or invalidation.get("latency_ms") != latency.get("invalidation")
    ):
        raise IntegrityError("benchmark invalidation outcome is not durably bound")
    action_transitions = (
        unrelated_durable.get("action_transition_events")
        if isinstance(unrelated_durable, Mapping)
        else None
    )
    effect_transitions = (
        unrelated_durable.get("effect_transition_events")
        if isinstance(unrelated_durable, Mapping)
        else None
    )
    if (
        unrelated.get("status") != "COMPLETED"
        or not isinstance(unrelated_durable, Mapping)
        or trial.get("unrelated_completed") is not True
        or unrelated_durable.get("action_id") != trial.get("unrelated_action_id")
        or unrelated_durable.get("effect_id") != trial.get("unrelated_effect_id")
        or unrelated_durable.get("action_final_state") != ActionState.EXECUTED.value
        or unrelated_durable.get("effect_final_state") != EffectState.EXECUTED.value
        or not isinstance(action_transitions, list)
        or not action_transitions
        or action_transitions[-1].get("to") != ActionState.EXECUTED.value
        or not isinstance(effect_transitions, list)
        or not effect_transitions
        or effect_transitions[-1].get("to") != EffectState.EXECUTED.value
        or not isinstance(latency, Mapping)
        or unrelated.get("latency_ms") != latency.get("unrelated_during_revocation")
    ):
        raise IntegrityError("benchmark unrelated outcome is not durably bound")


def _validate_trial_record(trial: Mapping[str, Any]) -> None:
    seed = trial.get("schedule_seed")
    expected_order = derive_submission_order(_required_int(seed, "schedule seed"))
    if trial.get("submission_order") != "-".join(expected_order):
        raise IntegrityError("benchmark submission order is not derived from its seed")
    trace = trial.get("worker_trace")
    if not isinstance(trace, Mapping):
        raise IntegrityError("benchmark worker trace is missing")
    _validate_worker_trace(trace, expected_order)
    workers = cast(list[dict[str, Any]], trace["workers"])
    _validate_dispatch_claim(trial, _worker_by_operation(workers, "dispatch"))
    _validate_other_worker_claims(trial, trace)


def _precision_recall(
    predicted: set[str],
    expected: set[str],
) -> tuple[float, float, int, int, int]:
    true_positives = len(predicted & expected)
    false_positives = len(predicted - expected)
    false_negatives = len(expected - predicted)
    precision = true_positives / len(predicted) if predicted else float(not expected)
    recall = true_positives / len(expected) if expected else 1.0
    return precision, recall, true_positives, false_positives, false_negatives


def _run_trial(root: Path, trial: int) -> dict[str, Any]:
    fixture = _build_trial(root, trial)
    baseline_latency = _complete_unrelated(
        fixture,
        action_id=fixture.unrelated_baseline_action_id,
        effect_id=fixture.unrelated_baseline_effect_id,
        token=fixture.unrelated_baseline_token,
    )
    schedule_seed = BENCHMARK_SCHEDULE_SEED + trial
    submission_order = derive_submission_order(schedule_seed)
    schedule_started = perf_counter_ns()
    release = _BarrierObservation(schedule_started)
    barrier = Barrier(len(BENCHMARK_OPERATIONS), action=release.release)
    observations = {
        operation: _WorkerObservation(
            operation=operation,
            worker_id=f"worker-{operation}",
            submission_ordinal=ordinal,
        )
        for ordinal, operation in enumerate(submission_order)
    }
    operations: dict[str, tuple[Callable[[], Any], Callable[[Any], dict[str, Any]]]] = {
        "dispatch": (lambda: _dispatch(fixture), _dispatch_outcome),
        "invalidate": (lambda: _invalidate(fixture, trial), _invalidation_outcome),
        "unrelated": (
            lambda: _complete_unrelated(
                fixture,
                action_id=fixture.unrelated_action_id,
                effect_id=fixture.unrelated_effect_id,
                token=fixture.unrelated_token,
            ),
            _unrelated_outcome,
        ),
    }
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix=f"revoke-bench-{trial:02d}") as pool:
        futures: dict[str, Future[Any]] = {}
        for operation in submission_order:
            callback, describe = operations[operation]
            futures[operation] = pool.submit(
                _observe_worker,
                barrier,
                release,
                observations[operation],
                schedule_started,
                callback,
                describe,
            )
        if set(futures) != set(BENCHMARK_OPERATIONS):
            raise IntegrityError("benchmark schedule omitted a required concurrent operation")
        dispatch = cast(_DispatchOutcome, futures["dispatch"].result(timeout=15))
        revocation_result = cast(
            tuple[RevocationResult, float], futures["invalidate"].result(timeout=15)
        )
        revocation, revocation_latency = revocation_result
        unrelated_latency = cast(float, futures["unrelated"].result(timeout=15))
    schedule_latency = _elapsed_ms(schedule_started)

    events = fixture.store.journal.list_events(fixture.run_id)
    invalidation_sequence = next(
        event.sequence
        for event in events
        if event.aggregate_type == "premise"
        and event.aggregate_id == fixture.premise_id
        and event.kind == "premise.transitioned"
        and event.payload.get("to") == PremiseState.INVALIDATED.value
    )
    dispatch_sequences = tuple(
        event.sequence
        for event in events
        if event.aggregate_type == "action"
        and event.aggregate_id == fixture.race_action_id
        and event.kind == "action.transitioned"
        and event.payload.get("to") == ActionState.DISPATCHING.value
    )
    stale_dispatch_sequences = tuple(
        sequence for sequence in dispatch_sequences if sequence > invalidation_sequence
    )
    predicted = set(revocation.affected_effect_ids)
    expected = set(fixture.expected_effect_ids)
    precision, recall, true_positives, false_positives, false_negatives = _precision_recall(
        predicted, expected
    )
    violations: list[str] = []
    if stale_dispatch_sequences:
        violations.append("post_invalidation_dispatch")
    if dispatch.succeeded != bool(dispatch_sequences):
        violations.append("dispatch_result_event_mismatch")
    if predicted != expected:
        violations.append("selective_closure_mismatch")
    race_action = fixture.store.get_action(fixture.race_action_id)
    if race_action is None or race_action.state != ActionState.REVOKE_PENDING:
        violations.append("race_action_not_fenced")
    unrelated_action = fixture.store.get_action(fixture.unrelated_action_id)
    unrelated_effect = fixture.store.get_effect(fixture.unrelated_effect_id)
    unrelated_completed = bool(
        unrelated_action is not None
        and unrelated_action.state == ActionState.EXECUTED
        and unrelated_effect is not None
        and unrelated_effect.state == EffectState.EXECUTED
        and not revocation.contains_entity(fixture.unrelated_action_id)
        and not revocation.contains_entity(fixture.unrelated_effect_id)
    )
    if not unrelated_completed:
        violations.append("unrelated_task_not_completed")
    chain_verified = True
    try:
        event_head = fixture.store.journal.verify_chain(fixture.run_id)
    except IntegrityError:
        chain_verified = False
        event_head = ""
        violations.append("event_chain_invalid")
    fixture.store.database.integrity_check()
    worker_records = [observations[operation].as_record() for operation in submission_order]
    _bind_durable_outcomes(worker_records, fixture, events)
    trial_record = {
        "trial": trial,
        "run_id": fixture.run_id,
        "schedule_seed": schedule_seed,
        "submission_order": "-".join(submission_order),
        "worker_trace": {
            "protocol": WORKER_TRACE_PROTOCOL,
            "clock": "time.perf_counter_ns relative to trial schedule origin",
            "participant_count": len(BENCHMARK_OPERATIONS),
            "barrier_release_ns": release.require_release(),
            "workers": worker_records,
        },
        "state_database": str(fixture.database_path.relative_to(root)),
        "event_count": len(events),
        "event_head": event_head,
        "event_chain_verified": chain_verified,
        "premise_id": fixture.premise_id,
        "race_action_id": fixture.race_action_id,
        "race_effect_id": fixture.race_effect_id,
        "dispatch_succeeded": dispatch.succeeded,
        "dispatch_denial": dispatch.denial,
        "dispatch_sequences": list(dispatch_sequences),
        "invalidation_sequence": invalidation_sequence,
        "stale_dispatch_sequences": list(stale_dispatch_sequences),
        "expected_effect_ids": sorted(expected),
        "affected_effect_ids": sorted(predicted),
        "unrelated_action_id": fixture.unrelated_action_id,
        "unrelated_effect_id": fixture.unrelated_effect_id,
        "unrelated_completed": unrelated_completed,
        "selectivity": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision_percent": _round_metric(precision * 100.0),
            "recall_percent": _round_metric(recall * 100.0),
        },
        "latency_ms": {
            "dispatch": _round_metric(dispatch.latency_ms),
            "invalidation": _round_metric(revocation_latency),
            "unrelated_baseline": _round_metric(baseline_latency),
            "unrelated_during_revocation": _round_metric(unrelated_latency),
            "schedule": _round_metric(schedule_latency),
        },
        "violations": violations,
    }
    _validate_trial_record(trial_record)
    return trial_record


def _comparison(
    *,
    actual: float,
    target: float,
    operator: str,
    source_label: str,
) -> dict[str, Any]:
    if operator == "eq":
        passed = actual == target
    elif operator == "gte":
        passed = actual >= target
    elif operator == "lt":
        passed = actual < target
    else:  # pragma: no cover - module-owned declarations are exhaustive
        raise ValidationError(f"unsupported benchmark comparison: {operator}")
    return {
        "actual": _round_metric(actual),
        "operator": operator,
        "target": target,
        "passed": passed,
        "source": source_label,
    }


def _allocate_run_root(output_root: Path, suite: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    slug = suite.lower()
    for index in range(1, 10_000):
        candidate = output_root / f"{slug}-{index:04d}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        (candidate / "state").mkdir()
        return candidate
    raise ValidationError(f"benchmark output namespace is exhausted: {output_root}")


def _run_suite(output_root: Path, suite: str) -> dict[str, Any]:
    if suite != SUITE_NAME:
        raise ValidationError(f"unknown benchmark suite: {suite}")
    producer = _producer_provenance(suite)
    root = _allocate_run_root(output_root, suite)
    _persist_producer_source(root, producer)
    trials = [_run_trial(root, trial) for trial in range(TRIAL_COUNT)]

    unsafe_dispatches = sum(len(trial["stale_dispatch_sequences"]) for trial in trials)
    violation_schedules = sum(bool(trial["violations"]) for trial in trials)
    unrelated_completed = sum(bool(trial["unrelated_completed"]) for trial in trials)
    true_positives = sum(int(trial["selectivity"]["true_positives"]) for trial in trials)
    false_positives = sum(int(trial["selectivity"]["false_positives"]) for trial in trials)
    false_negatives = sum(int(trial["selectivity"]["false_negatives"]) for trial in trials)
    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    baseline_latencies = [float(trial["latency_ms"]["unrelated_baseline"]) for trial in trials]
    concurrent_latencies = [
        float(trial["latency_ms"]["unrelated_during_revocation"]) for trial in trials
    ]
    dispatch_latencies = [float(trial["latency_ms"]["dispatch"]) for trial in trials]
    invalidation_latencies = [float(trial["latency_ms"]["invalidation"]) for trial in trials]
    schedule_latencies = [float(trial["latency_ms"]["schedule"]) for trial in trials]
    baseline_p95 = _percentile(baseline_latencies, 95.0)
    concurrent_p95 = _percentile(concurrent_latencies, 95.0)
    added_latency_percent = max(0.0, ((concurrent_p95 - baseline_p95) / baseline_p95) * 100.0)

    metrics: dict[str, Any] = {
        "unsafe_post_invalidation_dispatch_count": unsafe_dispatches,
        "unsafe_post_invalidation_dispatch_percent": _round_metric(
            (unsafe_dispatches / TRIAL_COUNT) * 100.0
        ),
        "race_invariant_violation_count": violation_schedules,
        "race_invariant_violation_percent": _round_metric(
            (violation_schedules / TRIAL_COUNT) * 100.0
        ),
        "revocation_set_precision_percent": _round_metric(precision * 100.0),
        "revocation_set_recall_percent": _round_metric(recall * 100.0),
        "canonical_subset_precision_percent": _round_metric(precision * 100.0),
        "canonical_subset_recall_percent": _round_metric(recall * 100.0),
        "unrelated_task_completion_percent": _round_metric(
            (unrelated_completed / TRIAL_COUNT) * 100.0
        ),
        "unrelated_task_p95_added_latency_percent": _round_metric(added_latency_percent),
        "latency_ms": {
            "dispatch_p50": _round_metric(_percentile(dispatch_latencies, 50.0)),
            "dispatch_p95": _round_metric(_percentile(dispatch_latencies, 95.0)),
            "invalidation_p50": _round_metric(_percentile(invalidation_latencies, 50.0)),
            "invalidation_p95": _round_metric(_percentile(invalidation_latencies, 95.0)),
            "unrelated_baseline_p95": _round_metric(baseline_p95),
            "unrelated_during_revocation_p95": _round_metric(concurrent_p95),
            "schedule_p95": _round_metric(_percentile(schedule_latencies, 95.0)),
        },
    }
    target_source = "docs/revoke/COMPLETION_MATRIX.md#benchmark-release-targets"
    targets = {
        "unsafe_post_invalidation_dispatch": _comparison(
            actual=float(metrics["unsafe_post_invalidation_dispatch_percent"]),
            target=0.0,
            operator="eq",
            source_label=target_source,
        ),
        "revocation_set_precision": _comparison(
            actual=float(metrics["revocation_set_precision_percent"]),
            target=95.0,
            operator="gte",
            source_label=target_source,
        ),
        "revocation_set_recall": _comparison(
            actual=float(metrics["revocation_set_recall_percent"]),
            target=95.0,
            operator="gte",
            source_label=target_source,
        ),
        "canonical_subset_precision": _comparison(
            actual=float(metrics["canonical_subset_precision_percent"]),
            target=100.0,
            operator="eq",
            source_label=target_source,
        ),
        "canonical_subset_recall": _comparison(
            actual=float(metrics["canonical_subset_recall_percent"]),
            target=100.0,
            operator="eq",
            source_label=target_source,
        ),
        "unrelated_task_completion": _comparison(
            actual=float(metrics["unrelated_task_completion_percent"]),
            target=100.0,
            operator="eq",
            source_label=target_source,
        ),
        "unrelated_task_p95_added_latency": _comparison(
            actual=float(metrics["unrelated_task_p95_added_latency_percent"]),
            target=20.0,
            operator="lt",
            source_label=target_source,
        ),
        "randomized_race_invariant_violations": _comparison(
            actual=float(metrics["race_invariant_violation_count"]),
            target=0.0,
            operator="eq",
            source_label=target_source,
        ),
    }
    report_path = root / "report.json"
    report: dict[str, Any] = {
        "schema_version": 2,
        "suite": suite,
        "trial_count": TRIAL_COUNT,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "passed": all(bool(target["passed"]) for target in targets.values()),
        "artifact_root": str(root),
        "report_path": str(report_path),
        "producer": producer,
        "methodology": {
            "race": (
                "three-party barrier over gateway dispatch, atomic invalidation, "
                "and unrelated completion"
            ),
            "schedule": (
                "seeded randomized three-way submission permutation deterministically "
                "derived with SHA-256, followed by a traced shared barrier; no sleeps or "
                "artificial timing delays"
            ),
            "schedule_seed": BENCHMARK_SCHEDULE_SEED,
            "schedule_protocol": SCHEDULE_PROTOCOL,
            "schedule_operations": list(BENCHMARK_OPERATIONS),
            "schedule_derivation": (
                "sort operations by ascending raw SHA-256 of UTF-8 "
                "'<protocol>:<decimal-seed>:<operation>', then operation as tie-break"
            ),
            "worker_trace_protocol": WORKER_TRACE_PROTOCOL,
            "safety_oracle": "persisted premise and action transition event sequences",
            "selectivity_oracle": (
                "persisted scoped HARD REQUIRES closure with three expected effects"
            ),
            "unrelated_workload": (
                "SHA-256 artifact snapshot plus gateway dispatch and effect completion"
            ),
            "unrelated_workload_bytes": UNRELATED_WORKLOAD_BYTES,
            "latency_clock": "time.perf_counter_ns",
            "p95_method": "nearest-rank",
        },
        "metrics": metrics,
        "targets": targets,
        "trials": trials,
    }
    temporary = report_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(report_path)
    return report


async def run_benchmark_suite(
    output_root: Path,
    suite: str = SUITE_NAME,
) -> Mapping[str, Any]:
    """Execute RevokeBench against real stores and return its persisted report."""

    resolved = output_root.expanduser().resolve()
    return await asyncio.to_thread(_run_suite, resolved, suite)
