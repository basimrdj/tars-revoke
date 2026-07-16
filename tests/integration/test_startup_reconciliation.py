from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tars_revoke.config import Settings
from tars_revoke.demo.manager import RunManager
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    DispatchReconciliationOutcome,
    EffectState,
    EffectType,
    Reversibility,
    RiskLevel,
    RunState,
    WarrantState,
)
from tars_revoke.domain.models import ActionIntent, Agent, EffectRecord, Run, Warrant
from tars_revoke.persistence.store import Store


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository_fixture(tmp_path: Path) -> tuple[Path, Path, str, str]:
    repository = tmp_path / "repository"
    remote = tmp_path / "remote.git"
    repository.mkdir()
    _git("init", "--initial-branch=main", cwd=repository)
    _git("config", "user.email", "tars@example.test", cwd=repository)
    _git("config", "user.name", "TARS Test", cwd=repository)
    (repository / "README.md").write_text("baseline\n", encoding="utf-8")
    _git("add", "README.md", cwd=repository)
    _git("commit", "-m", "baseline", cwd=repository)
    baseline_oid = _git("rev-parse", "HEAD", cwd=repository)
    (repository / "README.md").write_text("authorized source\n", encoding="utf-8")
    _git("add", "README.md", cwd=repository)
    _git("commit", "-m", "authorized source", cwd=repository)
    source_oid = _git("rev-parse", "HEAD", cwd=repository)
    _git("init", "--bare", str(remote))
    _git("remote", "add", "origin", str(remote.resolve()), cwd=repository)
    return repository.resolve(), remote.resolve(), baseline_oid, source_oid


def _seed_dispatching_push(
    data_dir: Path,
    *,
    repository: Path,
    remote: Path,
    source_oid: str,
    suffix: str,
) -> tuple[Path, str, str, str]:
    run_id = f"run-startup-{suffix}"
    artifact_root = data_dir / "runs" / run_id / "artifacts" / run_id
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    agent_id = f"agent-{suffix}"
    warrant_id = f"warrant-{suffix}"
    action_id = f"action-{suffix}"
    effect_id = f"effect-{suffix}"
    destination = f"refs/heads/recovery-{suffix}"
    refspec = f"HEAD:{destination}"
    target = f"origin:{destination}"
    scope = f"scope-{suffix}"
    store.create_run(
        Run(
            id=run_id,
            name="Startup reconciliation",
            state=RunState.RUNNING,
            root_path=str(artifact_root.parent),
            created_at=now,
            updated_at=now,
            metadata={"scenario": "external-schema-v2", "repair_provider": "scripted"},
        )
    )
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=run_id,
            name="Push agent",
            role="coding-agent",
            worktree_path=str(repository),
            state=AgentState.RUNNING,
            created_at=now,
            updated_at=now,
        )
    )
    store.create_warrant(
        Warrant(
            id=warrant_id,
            run_id=run_id,
            agent_id=agent_id,
            scope=scope,
            authorized_targets=(target,),
            state=WarrantState.AUTHORIZED,
            risk=RiskLevel.HIGH,
            revision_epoch=4,
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
        )
    )
    store.create_action(
        ActionIntent(
            id=action_id,
            run_id=run_id,
            agent_id=agent_id,
            warrant_id=warrant_id,
            scope=scope,
            action_type=ActionType.PUSH,
            target=target,
            payload_digest=sha256_digest(refspec),
            premise_vector={},
            risk=RiskLevel.HIGH,
            reversibility=Reversibility.IRREVERSIBLE,
            state=ActionState.DISPATCHING,
            lease_id=f"lease-{suffix}",
            idempotency_key=f"push-action-{suffix}",
            created_at=now,
            updated_at=now,
            dispatched_at=now,
        )
    )
    store.create_effect(
        EffectRecord(
            id=effect_id,
            run_id=run_id,
            action_id=action_id,
            scope=scope,
            target=target,
            effect_type=EffectType.PUSH,
            after_hash=source_oid,
            reversibility=Reversibility.IRREVERSIBLE,
            state=EffectState.DISPATCHING,
            created_at=now,
            updated_at=now,
            dispatched_at=now,
            idempotency_key=f"push-effect-{suffix}",
            metadata={
                "repository": str(repository),
                "remote": "origin",
                "remote_url": str(remote),
                "destination": destination,
                "refspec": refspec,
                "source_oid": source_oid,
            },
        )
    )
    return artifact_root, run_id, action_id, effect_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("remote_state", "outcome", "action_state", "effect_state"),
    (
        (
            "missing",
            DispatchReconciliationOutcome.NOT_APPLIED,
            ActionState.FAILED,
            EffectState.FAILED,
        ),
        (
            "applied",
            DispatchReconciliationOutcome.APPLIED,
            ActionState.EXECUTED,
            EffectState.EXECUTED,
        ),
        (
            "conflict",
            DispatchReconciliationOutcome.CONFLICT,
            ActionState.CONTAINMENT_REQUIRED,
            EffectState.CONTAINMENT_REQUIRED,
        ),
    ),
)
async def test_manager_reconciles_push_without_replaying_after_restart(
    tmp_path: Path,
    remote_state: str,
    outcome: DispatchReconciliationOutcome,
    action_state: ActionState,
    effect_state: EffectState,
) -> None:
    repository, remote, baseline_oid, source_oid = _repository_fixture(tmp_path)
    suffix = remote_state
    destination = f"refs/heads/recovery-{suffix}"
    if remote_state == "applied":
        _git("push", "origin", f"{source_oid}:{destination}", cwd=repository)
    elif remote_state == "conflict":
        _git("push", "origin", f"{baseline_oid}:{destination}", cwd=repository)
    data_dir = tmp_path / "data"
    artifact_root, run_id, action_id, effect_id = _seed_dispatching_push(
        data_dir,
        repository=repository,
        remote=remote,
        source_oid=source_oid,
        suffix=suffix,
    )

    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    try:
        store = manager.store_for(run_id)
        records = store.list_dispatch_reconciliations(run_id)
        assert len(records) == 1
        assert records[0].outcome == outcome
        assert records[0].metadata["startup_policy"] == "observe-never-replay"
        assert store.get_action(action_id).state == action_state  # type: ignore[union-attr]
        assert store.get_effect(effect_id).state == effect_state  # type: ignore[union-attr]
        assert store.get_run(run_id).state == RunState.FAILED  # type: ignore[union-attr]
        events = store.journal.list_events(run_id)
        reconciliation_events = [
            event for event in events if event.kind == "dispatch.reconciled"
        ]
        assert len(reconciliation_events) == 1
        assert reconciliation_events[0].payload["outcome"] == outcome.value
        failure_event = next(event for event in events if event.kind == "run.failure_recorded")
        assert reconciliation_events[0].sequence < failure_event.sequence
        assert (artifact_root / "failure-receipt.json").is_file()
    finally:
        await manager.close()

    remote_head = _git("rev-parse", destination, cwd=remote) if remote_state != "missing" else None
    expected_head = source_oid if remote_state == "applied" else baseline_oid
    assert remote_head == (None if remote_state == "missing" else expected_head)


@pytest.mark.asyncio
async def test_startup_reconciliation_is_idempotent_across_repeated_manager_starts(
    tmp_path: Path,
) -> None:
    repository, remote, _baseline_oid, source_oid = _repository_fixture(tmp_path)
    data_dir = tmp_path / "data"
    artifact_root, run_id, _action_id, _effect_id = _seed_dispatching_push(
        data_dir,
        repository=repository,
        remote=remote,
        source_oid=source_oid,
        suffix="repeat",
    )

    first = RunManager(Settings(data_dir=data_dir))
    await first.start()
    await first.close()
    first_store = Store(artifact_root / "state.sqlite")
    first_events = first_store.journal.list_events(run_id)
    first_reconciliations = first_store.list_dispatch_reconciliations(run_id)

    second = RunManager(Settings(data_dir=data_dir))
    await second.start()
    await second.close()
    second_store = Store(artifact_root / "state.sqlite")
    assert second_store.list_dispatch_reconciliations(run_id) == first_reconciliations
    assert second_store.journal.list_events(run_id) == first_events
