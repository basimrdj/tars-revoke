from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tars_revoke.clock import FakeClock
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    EffectState,
    EffectType,
    LeaseState,
    PremiseState,
    Reversibility,
    RevocationCaseState,
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
    EffectRecord,
    EvidenceRecord,
    EvidenceSource,
    Premise,
    RevocationCase,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence.database import Database
from tars_revoke.persistence.event_journal import EventJournal
from tars_revoke.persistence.store import Store
from tars_revoke.services.coordinator import RecoverySnapshot, RevocationCoordinator
from tars_revoke.services.gateway import EffectGateway

SUITE_NAME = "CrashBench-11"
REPORT_PROTOCOL = "tars.crashbench.report/v1"
PRODUCER_PROTOCOL = "tars.crashbench.producer/v1"
REPORT_SCHEMA_VERSION = 1
BENCHMARK_TIME = datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc)
RECOVERY_TIME = BENCHMARK_TIME + timedelta(seconds=2)
CRASH_STAGES = tuple(RevocationCaseState)
NORMAL_CASE_STAGES = (
    RevocationCaseState.OPEN,
    RevocationCaseState.FROZEN,
    RevocationCaseState.INVENTORIED,
    RevocationCaseState.COMPENSATING,
    RevocationCaseState.EXPERIMENTING,
    RevocationCaseState.REPAIRING,
    RevocationCaseState.VERIFYING,
    RevocationCaseState.RESUMED,
    RevocationCaseState.ATTESTED,
    RevocationCaseState.CLOSED,
)
_RECEIPT_REBUILD_STAGES = frozenset(
    {
        RevocationCaseState.ATTESTED,
        RevocationCaseState.CLOSED,
        RevocationCaseState.ESCALATED,
    }
)


@dataclass(frozen=True)
class _StageEntities:
    run_id: str
    case_id: str
    dispatch_action_id: str
    dispatch_effect_id: str
    orphan_lease_id: str
    compensation_effect_ids: tuple[str, str]


@dataclass(frozen=True)
class _SnapshotObservation:
    record: Mapping[str, Any]
    case_state: str
    dispatch_action_state: str
    dispatch_effect_state: str
    orphan_lease_state: str
    prepared_effect_sequences: tuple[int, ...]
    action_dispatch_sequences: tuple[int, ...]
    effect_dispatch_sequences: tuple[int, ...]
    orphan_expired_sequences: tuple[int, ...]


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
    source_commit: str | None = None
    source_tree: str | None = None
    committed_blob_oid: str | None = None
    committed_bytes: bytes | None = None
    worktree_status: bytes | None = None
    if repository is not None:
        source_relative = source_path.relative_to(repository).as_posix()
        source_commit = _git_text(repository, "rev-parse", "HEAD")
        source_tree = _git_text(repository, "rev-parse", "HEAD^{tree}")
        committed_blob_oid = _git_text(repository, "rev-parse", f"HEAD:{source_relative}")
        committed_bytes = _git_bytes(repository, "show", f"HEAD:{source_relative}")
        worktree_status = _git_bytes(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        )
    observed_argv = [str(argument) for argument in sys.argv]
    return {
        "protocol": PRODUCER_PROTOCOL,
        "entrypoint": "tars_revoke.demo.crashbench:run_crashbench_suite",
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
            "artifact_path": "producer/source/crashbench.py",
            "sha256": sha256_digest(source_bytes),
            "size": len(source_bytes),
            "source_commit": source_commit,
            "source_tree": source_tree,
            "committed_blob_oid": committed_blob_oid,
            "committed_sha256": (
                sha256_digest(committed_bytes) if committed_bytes is not None else None
            ),
            "matches_committed_source": committed_bytes == source_bytes,
            "worktree_clean": worktree_status == b"",
            "worktree_status_sha256": (
                sha256_digest(worktree_status) if worktree_status is not None else None
            ),
        },
    }


def _persist_producer_source(root: Path, producer: Mapping[str, Any]) -> Path:
    source = producer.get("source")
    if not isinstance(source, Mapping):
        raise IntegrityError("CrashBench producer source record is missing")
    artifact_path = source.get("artifact_path")
    if not isinstance(artifact_path, str) or not artifact_path:
        raise IntegrityError("CrashBench producer source artifact path is invalid")
    target = (root / artifact_path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise IntegrityError("CrashBench producer source artifact escapes its run root")
    payload = Path(__file__).resolve().read_bytes()
    if sha256_digest(payload) != source.get("sha256") or len(payload) != source.get("size"):
        raise IntegrityError("CrashBench producer source changed during execution")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    if target.read_bytes() != payload:
        raise IntegrityError("CrashBench producer source copy is not byte-exact")
    return target


def _allocate_run_root(output_root: Path, suite: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    slug = suite.lower()
    for index in range(1, 10_000):
        candidate = output_root / f"{slug}-{index:04d}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise ValidationError(f"CrashBench output namespace is exhausted: {output_root}")


def _create_warrant(
    store: Store,
    *,
    entities: _StageEntities,
    agent_id: str,
    premise: Premise,
    suffix: str,
) -> Warrant:
    warrant = Warrant(
        id=f"warrant-{suffix}",
        run_id=entities.run_id,
        agent_id=agent_id,
        scope=premise.scope,
        authorized_targets=(f"target-{suffix}",),
        state=WarrantState.AUTHORIZED,
        risk=RiskLevel.CRITICAL,
        issued_at=BENCHMARK_TIME - timedelta(minutes=1),
        expires_at=BENCHMARK_TIME + timedelta(hours=1),
    )
    store.create_warrant(warrant)
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=BENCHMARK_TIME,
        )
    )
    return warrant


def _create_action(
    store: Store,
    *,
    entities: _StageEntities,
    agent_id: str,
    warrant: Warrant,
    premise: Premise,
    suffix: str,
    state: ActionState,
    action_type: ActionType,
    reversibility: Reversibility,
) -> ActionIntent:
    return store.create_action(
        ActionIntent(
            id=f"action-{suffix}",
            run_id=entities.run_id,
            agent_id=agent_id,
            warrant_id=warrant.id,
            scope=premise.scope,
            action_type=action_type,
            target=f"target-{suffix}",
            payload_digest=sha256_digest(f"payload-{suffix}"),
            premise_vector={premise.id: premise.value_digest},
            risk=RiskLevel.CRITICAL,
            reversibility=reversibility,
            state=state,
            idempotency_key=f"action-key-{suffix}",
            created_at=BENCHMARK_TIME,
            updated_at=BENCHMARK_TIME,
        )
    )


def _create_effect_intent(
    store: Store,
    *,
    action: ActionIntent,
    suffix: str,
    effect_type: EffectType,
) -> EffectRecord:
    return store.create_effect(
        EffectRecord(
            id=f"effect-{suffix}",
            run_id=action.run_id,
            action_id=action.id,
            scope=action.scope,
            target=action.target,
            effect_type=effect_type,
            reversibility=action.reversibility,
            state=EffectState.PREPARED,
            created_at=BENCHMARK_TIME,
            updated_at=BENCHMARK_TIME,
            idempotency_key=f"effect-key-{suffix}",
            metadata={
                "adapter_idempotency_key": f"adapter-{suffix}",
                "reconciliation_policy": "observe-never-replay",
            },
        )
    )


def _advance_case_to(store: Store, case_id: str, target: RevocationCaseState) -> None:
    if target == RevocationCaseState.ESCALATED:
        store.transition_revocation_case(case_id, target, at=BENCHMARK_TIME)
        return
    target_index = NORMAL_CASE_STAGES.index(target)
    for state in NORMAL_CASE_STAGES[1 : target_index + 1]:
        store.transition_revocation_case(case_id, state, at=BENCHMARK_TIME)


def _seed_stage_database(
    database_path: Path,
    *,
    stage: RevocationCaseState,
    stage_index: int,
) -> _StageEntities:
    suffix = f"{stage_index:02d}-{stage.value.lower()}"
    entities = _StageEntities(
        run_id=f"run-crashbench-{suffix}",
        case_id=f"case-crashbench-{suffix}",
        dispatch_action_id=f"action-dispatch-{suffix}",
        dispatch_effect_id=f"effect-dispatch-{suffix}",
        orphan_lease_id="",
        compensation_effect_ids=(
            f"effect-compensation-pending-{suffix}",
            f"effect-compensation-revoked-{suffix}",
        ),
    )
    clock = FakeClock(BENCHMARK_TIME)
    store = Store(database_path, clock=clock)
    agent_id = f"agent-crashbench-{suffix}"
    premise_id = f"premise-crashbench-{suffix}"
    evidence_id = f"evidence-crashbench-{suffix}"
    source_id = f"source-crashbench-{suffix}"
    store.create_run(
        Run(
            id=entities.run_id,
            name=f"CrashBench recovery at {stage.value}",
            state=RunState.RUNNING,
            root_path=str(database_path.parent),
            created_at=BENCHMARK_TIME,
            updated_at=BENCHMARK_TIME,
            metadata={"suite": SUITE_NAME, "stage": stage.value},
        )
    )
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=entities.run_id,
            name="CrashBench recovery agent",
            role="effect-dispatcher",
            worktree_path=str(database_path.parent),
            state=AgentState.RUNNING,
            created_at=BENCHMARK_TIME,
            updated_at=BENCHMARK_TIME,
        )
    )
    store.create_evidence_source(
        EvidenceSource(
            id=source_id,
            run_id=entities.run_id,
            name="CrashBench registry",
            uri="https://registry.invalid/crashbench",
            issuer="registry.invalid",
            pinned_identity="crashbench-fixture-v1",
            created_at=BENCHMARK_TIME,
        )
    )
    store.create_evidence_record(
        EvidenceRecord(
            id=evidence_id,
            run_id=entities.run_id,
            source_id=source_id,
            source_uri=f"https://registry.invalid/crashbench/{stage.value.lower()}",
            source_version=1,
            observed_at=BENCHMARK_TIME,
            valid_at=BENCHMARK_TIME,
            digest=sha256_digest(f"evidence-{suffix}"),
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
        )
    )
    premise = Premise(
        id=premise_id,
        run_id=entities.run_id,
        scope="repository",
        subject="external-schema",
        relation="version",
        value=1,
        value_digest=canonical_digest(1),
        semantics=ValueSemantics.SINGLE,
        state=PremiseState.ACTIVE,
        valid_at=BENCHMARK_TIME - timedelta(minutes=1),
        created_at=BENCHMARK_TIME - timedelta(minutes=1),
    )
    store.create_premise(premise)

    dispatch_suffix = f"dispatch-{suffix}"
    dispatch_warrant = _create_warrant(
        store,
        entities=entities,
        agent_id=agent_id,
        premise=premise,
        suffix=dispatch_suffix,
    )
    dispatch_action = _create_action(
        store,
        entities=entities,
        agent_id=agent_id,
        warrant=dispatch_warrant,
        premise=premise,
        suffix=dispatch_suffix,
        state=ActionState.PREPARED,
        action_type=ActionType.PUSH,
        reversibility=Reversibility.IRREVERSIBLE,
    )
    dispatch_effect = _create_effect_intent(
        store,
        action=dispatch_action,
        suffix=dispatch_suffix,
        effect_type=EffectType.PUSH,
    )
    if dispatch_action.id != entities.dispatch_action_id:
        raise IntegrityError("CrashBench dispatch action ID derivation drifted")
    if dispatch_effect.id != entities.dispatch_effect_id:
        raise IntegrityError("CrashBench dispatch effect ID derivation drifted")
    gateway = EffectGateway(store, clock=clock)
    dispatch_token = f"dispatch-token-{suffix}"
    gateway.authorize(
        dispatch_action.id,
        effect_id=dispatch_effect.id,
        current_artifact_hashes={},
        passed_test_ids=(),
        capability_token=dispatch_token,
    )
    gateway.dispatch(
        dispatch_action.id,
        effect_id=dispatch_effect.id,
        capability_token=dispatch_token,
        current_artifact_hashes={},
        passed_test_ids=(),
    )

    orphan_suffix = f"orphan-{suffix}"
    orphan_warrant = _create_warrant(
        store,
        entities=entities,
        agent_id=agent_id,
        premise=premise,
        suffix=orphan_suffix,
    )
    orphan_action = _create_action(
        store,
        entities=entities,
        agent_id=agent_id,
        warrant=orphan_warrant,
        premise=premise,
        suffix=orphan_suffix,
        state=ActionState.PREPARED,
        action_type=ActionType.EXTERNAL,
        reversibility=Reversibility.CONDITIONAL,
    )
    orphan_effect = _create_effect_intent(
        store,
        action=orphan_action,
        suffix=orphan_suffix,
        effect_type=EffectType.EXTERNAL,
    )
    orphan_authorization = gateway.authorize(
        orphan_action.id,
        effect_id=orphan_effect.id,
        current_artifact_hashes={},
        passed_test_ids=(),
        lease_ttl=timedelta(seconds=1),
        capability_token=f"orphan-token-{suffix}",
    )
    entities = _StageEntities(
        run_id=entities.run_id,
        case_id=entities.case_id,
        dispatch_action_id=entities.dispatch_action_id,
        dispatch_effect_id=entities.dispatch_effect_id,
        orphan_lease_id=orphan_authorization.lease.id,
        compensation_effect_ids=entities.compensation_effect_ids,
    )

    compensation_suffix = f"compensation-{suffix}"
    compensation_warrant = _create_warrant(
        store,
        entities=entities,
        agent_id=agent_id,
        premise=premise,
        suffix=compensation_suffix,
    )
    compensation_action = _create_action(
        store,
        entities=entities,
        agent_id=agent_id,
        warrant=compensation_warrant,
        premise=premise,
        suffix=compensation_suffix,
        state=ActionState.REVOKE_PENDING,
        action_type=ActionType.FILE_EDIT,
        reversibility=Reversibility.REVERSIBLE,
    )
    for effect_id, effect_state in zip(
        entities.compensation_effect_ids,
        (EffectState.REVOKE_PENDING, EffectState.REVOKED),
        strict=True,
    ):
        store.create_effect(
            EffectRecord(
                id=effect_id,
                run_id=entities.run_id,
                action_id=compensation_action.id,
                scope=compensation_action.scope,
                target=compensation_action.target,
                effect_type=EffectType.FILE_EDIT,
                before_hash=sha256_digest(f"before-{effect_id}"),
                after_hash=sha256_digest(f"after-{effect_id}"),
                reversibility=Reversibility.REVERSIBLE,
                compensation_handler="git.restore_path",
                state=effect_state,
                created_at=BENCHMARK_TIME,
                updated_at=BENCHMARK_TIME,
                idempotency_key=f"effect-key-{effect_id}",
            )
        )

    store.create_revocation_case(
        RevocationCase(
            id=entities.case_id,
            run_id=entities.run_id,
            premise_id=premise.id,
            trigger_evidence_id=evidence_id,
            state=RevocationCaseState.OPEN,
            reason=f"CrashBench restart at {stage.value}",
            opened_at=BENCHMARK_TIME,
            updated_at=BENCHMARK_TIME,
            metadata={"suite": SUITE_NAME, "stage_index": stage_index},
        )
    )
    _advance_case_to(store, entities.case_id, stage)
    current_case = store.get_revocation_case(entities.case_id)
    if current_case is None or current_case.state != stage:
        raise IntegrityError(f"CrashBench failed to seed case at {stage.value}")
    store.database.integrity_check()
    store.journal.verify_chain(entities.run_id)
    return entities


def _single_text_row(connection: sqlite3.Connection, sql: str, identifier: str) -> str:
    row = connection.execute(sql, (identifier,)).fetchone()
    if row is None:
        raise IntegrityError(f"CrashBench snapshot is missing entity {identifier}")
    return str(row[0])


def _transition_sequences(
    events: Sequence[Any],
    *,
    aggregate_type: str,
    aggregate_id: str,
    target: str,
) -> tuple[int, ...]:
    return tuple(
        int(event.sequence)
        for event in events
        if event.aggregate_type == aggregate_type
        and event.aggregate_id == aggregate_id
        and event.kind == f"{aggregate_type}.transitioned"
        and event.payload.get("to") == target
    )


def _snapshot_database(
    source_path: Path,
    target_path: Path,
    *,
    artifact_root: Path,
    entities: _StageEntities,
) -> _SnapshotObservation:
    if target_path.exists():
        raise IntegrityError(f"CrashBench snapshot already exists: {target_path}")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"{source_path.expanduser().resolve().as_uri()}?mode=ro"
    with (
        closing(sqlite3.connect(source_uri, uri=True)) as source,
        closing(sqlite3.connect(target_path)) as destination,
    ):
        source.backup(destination)
        journal_mode = destination.execute("PRAGMA journal_mode = DELETE").fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "delete":
            raise IntegrityError("CrashBench could not consolidate its SQLite snapshot")
        destination.commit()
    sidecars = (
        target_path.with_name(f"{target_path.name}-wal"),
        target_path.with_name(f"{target_path.name}-shm"),
    )
    for sidecar in sidecars:
        sidecar.unlink(missing_ok=True)
    if any(path.exists() for path in sidecars):
        raise IntegrityError("CrashBench produced a non-standalone SQLite snapshot")

    database = Database(target_path)
    database.integrity_check()
    journal = EventJournal(database, clock=FakeClock(RECOVERY_TIME))
    events = journal.list_events(entities.run_id)
    event_head = journal.verify_chain(entities.run_id)
    prepared_sequences = tuple(
        int(event.sequence)
        for event in events
        if event.aggregate_type == "effect"
        and event.aggregate_id == entities.dispatch_effect_id
        and event.kind == "effect.created"
        and event.payload.get("state") == EffectState.PREPARED.value
    )
    action_dispatch_sequences = _transition_sequences(
        events,
        aggregate_type="action",
        aggregate_id=entities.dispatch_action_id,
        target=ActionState.DISPATCHING.value,
    )
    effect_dispatch_sequences = _transition_sequences(
        events,
        aggregate_type="effect",
        aggregate_id=entities.dispatch_effect_id,
        target=EffectState.DISPATCHING.value,
    )
    orphan_expired_sequences = _transition_sequences(
        events,
        aggregate_type="lease",
        aggregate_id=entities.orphan_lease_id,
        target=LeaseState.EXPIRED.value,
    )
    snapshot_uri = f"{target_path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(snapshot_uri, uri=True)) as connection:
        case_state = _single_text_row(
            connection, "SELECT state FROM revocation_cases WHERE id = ?", entities.case_id
        )
        action_state = _single_text_row(
            connection,
            "SELECT state FROM action_intents WHERE id = ?",
            entities.dispatch_action_id,
        )
        effect_state = _single_text_row(
            connection, "SELECT state FROM effects WHERE id = ?", entities.dispatch_effect_id
        )
        lease_state = _single_text_row(
            connection,
            "SELECT state FROM execution_leases WHERE id = ?",
            entities.orphan_lease_id,
        )
    payload = target_path.read_bytes()
    return _SnapshotObservation(
        record={
            "path": target_path.relative_to(artifact_root).as_posix(),
            "sha256": sha256_digest(payload),
            "size": len(payload),
            "event_head": event_head,
            "event_count": len(events),
        },
        case_state=case_state,
        dispatch_action_state=action_state,
        dispatch_effect_state=effect_state,
        orphan_lease_state=lease_state,
        prepared_effect_sequences=prepared_sequences,
        action_dispatch_sequences=action_dispatch_sequences,
        effect_dispatch_sequences=effect_dispatch_sequences,
        orphan_expired_sequences=orphan_expired_sequences,
    )


def _normalize_recovery(snapshot: RecoverySnapshot) -> dict[str, Any]:
    return {
        "schema_version": snapshot.schema_version,
        "event_head_digest": snapshot.event_head_digest,
        "expired_lease_count": snapshot.expired_lease_count,
        "dispatching_action_ids": list(snapshot.dispatching_action_ids),
        "dispatching_effect_ids": list(snapshot.dispatching_effect_ids),
        "dispatch_reconciliations": [
            {
                "action_id": item.action_id,
                "effect_id": item.effect_id,
                "effect_type": item.effect_type,
                "target": item.target,
                "idempotency_key": item.idempotency_key,
                "metadata": dict(item.metadata),
            }
            for item in snapshot.dispatch_reconciliations
        ],
        "incomplete_case_ids": list(snapshot.incomplete_case_ids),
        "compensation_effect_ids": list(snapshot.compensation_effect_ids),
        "receipt_rebuild_case_ids": list(snapshot.receipt_rebuild_case_ids),
    }


def _recover_once(database_path: Path, run_id: str) -> dict[str, Any]:
    store = Store(database_path, clock=FakeClock(RECOVERY_TIME))
    coordinator = RevocationCoordinator(store, clock=FakeClock(RECOVERY_TIME))
    return _normalize_recovery(coordinator.recover(run_id))


def _obligations(recovery: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "dispatching_action_ids",
        "dispatching_effect_ids",
        "dispatch_reconciliations",
        "incomplete_case_ids",
        "compensation_effect_ids",
        "receipt_rebuild_case_ids",
    )
    return {key: recovery[key] for key in keys}


def _run_stage(
    artifact_root: Path,
    work_root: Path,
    *,
    stage: RevocationCaseState,
    stage_index: int,
) -> dict[str, Any]:
    stage_slug = f"{stage_index:02d}-{stage.value.lower()}"
    database_path = work_root / f"{stage_slug}.sqlite3"
    entities = _seed_stage_database(database_path, stage=stage, stage_index=stage_index)
    stage_root = artifact_root / "stages" / stage_slug
    pre_restart = _snapshot_database(
        database_path,
        stage_root / "pre-restart.sqlite3",
        artifact_root=artifact_root,
        entities=entities,
    )

    first_recovery = _recover_once(database_path, entities.run_id)
    after_first = _snapshot_database(
        database_path,
        stage_root / "after-first-recovery.sqlite3",
        artifact_root=artifact_root,
        entities=entities,
    )

    second_recovery = _recover_once(database_path, entities.run_id)
    after_second = _snapshot_database(
        database_path,
        stage_root / "after-second-recovery.sqlite3",
        artifact_root=artifact_root,
        entities=entities,
    )

    expected_incomplete = [] if stage == RevocationCaseState.CLOSED else [entities.case_id]
    expected_compensation = sorted(entities.compensation_effect_ids)
    expected_receipt_rebuild = [entities.case_id] if stage in _RECEIPT_REBUILD_STAGES else []
    first_reconciliations = first_recovery["dispatch_reconciliations"]
    prepared_before_dispatch = (
        len(pre_restart.prepared_effect_sequences) == 1
        and len(pre_restart.action_dispatch_sequences) == 1
        and len(pre_restart.effect_dispatch_sequences) == 1
        and pre_restart.prepared_effect_sequences[0]
        < min(
            pre_restart.action_dispatch_sequences[0],
            pre_restart.effect_dispatch_sequences[0],
        )
    )
    invariants = {
        "effect_intent_prepared_before_dispatch": prepared_before_dispatch,
        "pre_restart_single_action_dispatch_transition": len(pre_restart.action_dispatch_sequences)
        == 1,
        "pre_restart_single_effect_dispatch_transition": len(pre_restart.effect_dispatch_sequences)
        == 1,
        "first_recovery_expired_orphan_once": (
            first_recovery["expired_lease_count"] == 1
            and pre_restart.orphan_lease_state == LeaseState.ACTIVE.value
            and after_first.orphan_lease_state == LeaseState.EXPIRED.value
            and len(pre_restart.orphan_expired_sequences) == 0
            and len(after_first.orphan_expired_sequences) == 1
            and after_first.record["event_count"] == pre_restart.record["event_count"] + 1
            and after_first.record["sha256"] != pre_restart.record["sha256"]
        ),
        "first_recovery_single_dispatch_reconciliation": (
            isinstance(first_reconciliations, list)
            and len(first_reconciliations) == 1
            and first_reconciliations[0]["action_id"] == entities.dispatch_action_id
            and first_reconciliations[0]["effect_id"] == entities.dispatch_effect_id
            and first_reconciliations[0]["effect_type"] == EffectType.PUSH.value
            and first_reconciliations[0]["idempotency_key"] == f"effect-key-dispatch-{stage_slug}"
        ),
        "second_recovery_expired_none": (
            second_recovery["expired_lease_count"] == 0
            and after_second.orphan_lease_state == LeaseState.EXPIRED.value
            and after_second.orphan_expired_sequences == after_first.orphan_expired_sequences
        ),
        "second_recovery_no_new_event": (
            after_second.record["event_count"] == after_first.record["event_count"]
        ),
        "second_recovery_no_dispatch_retry": (
            after_first.action_dispatch_sequences == pre_restart.action_dispatch_sequences
            and after_second.action_dispatch_sequences == pre_restart.action_dispatch_sequences
            and after_first.effect_dispatch_sequences == pre_restart.effect_dispatch_sequences
            and after_second.effect_dispatch_sequences == pre_restart.effect_dispatch_sequences
        ),
        "dispatch_action_stays_dispatching": all(
            item.dispatch_action_state == ActionState.DISPATCHING.value
            for item in (pre_restart, after_first, after_second)
        ),
        "dispatch_effect_stays_dispatching": all(
            item.dispatch_effect_state == EffectState.DISPATCHING.value
            for item in (pre_restart, after_first, after_second)
        ),
        "event_head_stable_on_second_recovery": (
            first_recovery["event_head_digest"] == after_first.record["event_head"]
            and second_recovery["event_head_digest"] == after_second.record["event_head"]
            and after_second.record["event_head"] == after_first.record["event_head"]
        ),
        "obligations_stable_on_second_recovery": (
            _obligations(first_recovery) == _obligations(second_recovery)
        ),
        "compensation_set_matches_stage": (
            first_recovery["compensation_effect_ids"] == expected_compensation
            and second_recovery["compensation_effect_ids"] == expected_compensation
        ),
        "incomplete_set_matches_stage": (
            first_recovery["incomplete_case_ids"] == expected_incomplete
            and second_recovery["incomplete_case_ids"] == expected_incomplete
        ),
        "receipt_rebuild_set_matches_stage": (
            first_recovery["receipt_rebuild_case_ids"] == expected_receipt_rebuild
            and second_recovery["receipt_rebuild_case_ids"] == expected_receipt_rebuild
        ),
        "after_recovery_snapshots_byte_identical": (
            after_first.record["sha256"] == after_second.record["sha256"]
            and after_first.record["size"] == after_second.record["size"]
        ),
    }
    if any(item.case_state != stage.value for item in (pre_restart, after_first, after_second)):
        raise IntegrityError(f"CrashBench case stage drifted during {stage.value} recovery")
    failed = sorted(name for name, passed in invariants.items() if not passed)
    if failed:
        raise IntegrityError(f"CrashBench {stage.value} failed closed: {', '.join(failed)}")
    return {
        "stage_index": stage_index,
        "stage": stage.value,
        "run_id": entities.run_id,
        "case_id": entities.case_id,
        "entities": {
            "dispatch_action_id": entities.dispatch_action_id,
            "dispatch_effect_id": entities.dispatch_effect_id,
            "orphan_lease_id": entities.orphan_lease_id,
            "compensation_effect_ids": list(entities.compensation_effect_ids),
        },
        "snapshots": {
            "pre_restart": dict(pre_restart.record),
            "after_first_recovery": dict(after_first.record),
            "after_second_recovery": dict(after_second.record),
        },
        "recovery": {
            "first": first_recovery,
            "second": second_recovery,
        },
        "invariants": invariants,
        "passed": True,
    }


def _regular_files(root: Path) -> tuple[str, ...]:
    return tuple(
        path.relative_to(root).as_posix() for path in sorted(root.rglob("*")) if path.is_file()
    )


def _verify_artifact_inventory(
    root: Path,
    *,
    producer: Mapping[str, Any],
    stages: Sequence[Mapping[str, Any]],
    include_report: bool,
) -> None:
    source = producer.get("source")
    if not isinstance(source, Mapping) or not isinstance(source.get("artifact_path"), str):
        raise IntegrityError("CrashBench producer source inventory is invalid")
    expected = {str(source["artifact_path"])}
    for stage in stages:
        snapshots = stage.get("snapshots")
        if not isinstance(snapshots, Mapping):
            raise IntegrityError("CrashBench stage snapshot inventory is invalid")
        for phase in ("pre_restart", "after_first_recovery", "after_second_recovery"):
            snapshot = snapshots.get(phase)
            if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("path"), str):
                raise IntegrityError("CrashBench snapshot path is invalid")
            expected.add(str(snapshot["path"]))
    if include_report:
        expected.add("report.json")
    actual = set(_regular_files(root))
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise IntegrityError(
            f"CrashBench artifact inventory mismatch; missing={missing}, unexpected={unexpected}"
        )


def _run_suite(output_root: Path, suite: str) -> dict[str, Any]:
    if suite != SUITE_NAME:
        raise ValidationError(f"unknown benchmark suite: {suite}")
    if len(CRASH_STAGES) != 11 or set(CRASH_STAGES) != set(RevocationCaseState):
        raise IntegrityError("CrashBench-11 no longer covers the complete case-state enum")
    producer = _producer_provenance(suite)
    artifact_root = _allocate_run_root(output_root, suite)
    _persist_producer_source(artifact_root, producer)
    with tempfile.TemporaryDirectory(prefix="tars-crashbench-") as temporary:
        work_root = Path(temporary).resolve()
        stages = [
            _run_stage(
                artifact_root,
                work_root,
                stage=stage,
                stage_index=stage_index,
            )
            for stage_index, stage in enumerate(CRASH_STAGES)
        ]
    if [row["stage"] for row in stages] != [stage.value for stage in CRASH_STAGES]:
        raise IntegrityError("CrashBench stage order is incomplete or unstable")
    if not all(row["passed"] for row in stages):
        raise IntegrityError("CrashBench cannot emit a report for a failed stage")
    _persist_producer_source(artifact_root, producer)
    _verify_artifact_inventory(
        artifact_root,
        producer=producer,
        stages=stages,
        include_report=False,
    )
    report_path = artifact_root / "report.json"
    unsigned: dict[str, Any] = {
        "protocol": REPORT_PROTOCOL,
        "schema_version": REPORT_SCHEMA_VERSION,
        "suite": suite,
        "stage_count": len(stages),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "passed": True,
        "artifact_root": str(artifact_root),
        "report_path": str(report_path),
        "producer": producer,
        "methodology": {
            "oracle": (
                "production Store, EffectGateway, RevocationCoordinator, SQLite rows, and "
                "the hash-chained event journal; pytest/JUnit is not an oracle"
            ),
            "restart_model": (
                "seed once, close every transaction, then instantiate an independent Store "
                "for each of two recovery passes"
            ),
            "snapshot_method": (
                "sqlite3 online backup into a standalone database followed by foreign-key, "
                "integrity, and event-chain verification"
            ),
            "dispatch_crash_window": (
                "persist PREPARED effect intent, authorize through EffectGateway, persist "
                "DISPATCHING action/effect, then recover before effect completion"
            ),
            "recovery_policy": (
                "expire safe orphan leases and expose stable reconciliation obligations; "
                "never replay an ambiguous dispatch"
            ),
            "stage_order": [stage.value for stage in CRASH_STAGES],
            "receipt_rebuild_stages": sorted(stage.value for stage in _RECEIPT_REBUILD_STAGES),
            "closed_stage_has_no_incomplete_case": True,
        },
        "stages": stages,
    }
    report = {**unsigned, "report_digest": canonical_digest(unsigned)}
    temporary_path = report_path.with_suffix(".json.tmp")
    temporary_path.write_text(f"{canonical_json(report)}\n", encoding="utf-8")
    temporary_path.replace(report_path)
    loaded = json.loads(report_path.read_text(encoding="utf-8"))
    loaded_digest = loaded.pop("report_digest", None)
    if loaded_digest != report["report_digest"] or canonical_digest(loaded) != loaded_digest:
        raise IntegrityError("CrashBench report self-digest verification failed")
    _verify_artifact_inventory(
        artifact_root,
        producer=producer,
        stages=stages,
        include_report=True,
    )
    return report


async def run_crashbench_suite(
    output_root: Path,
    suite: str = SUITE_NAME,
) -> Mapping[str, Any]:
    """Run all 11 production crash-recovery cases and persist their proof databases."""

    resolved = output_root.expanduser().resolve()
    return await asyncio.to_thread(_run_suite, resolved, suite)
