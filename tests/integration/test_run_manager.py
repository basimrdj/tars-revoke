from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tars_revoke.api.snapshot import build_snapshot
from tars_revoke.config import Settings
from tars_revoke.demo.failures import finalize_without_masking, load_failure_receipt
from tars_revoke.demo.manager import RunManager
from tars_revoke.demo.scenario import CanonicalScenario
from tars_revoke.domain.enums import (
    AgentState,
    ReceiptState,
    RevocationCaseState,
    RunState,
)
from tars_revoke.domain.models import Run
from tars_revoke.errors import ValidationError
from tars_revoke.persistence.artifacts import ArtifactStore
from tars_revoke.persistence.store import Store


@pytest.mark.asyncio
async def test_manager_recovers_durable_run_after_process_restart(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    artifact_root = data_dir / "runs" / "run-recovered" / "artifacts" / "run-recovered"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = datetime(2026, 7, 14, tzinfo=timezone.utc)
    store.create_run(
        Run(
            id="run-recovered",
            name="Recovered canonical run",
            state=RunState.COMPLETED,
            root_path=str(artifact_root.parent),
            created_at=now,
            updated_at=now,
            metadata={
                "scenario": "external-schema-v2",
                "repair_provider": "live-codex",
            },
        )
    )

    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    try:
        assert manager.current_run_id == "run-recovered"
        assert manager.store_for("run-recovered").get_run("run-recovered") is not None
        assert manager.artifact_root_for("run-recovered") == artifact_root
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_manager_marks_orphaned_running_run_failed_instead_of_rehydrating_running(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_root = data_dir / "runs" / "run-orphaned" / "artifacts" / "run-orphaned"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = datetime(2026, 7, 14, tzinfo=timezone.utc)
    store.create_run(
        Run(
            id="run-orphaned",
            name="Orphaned canonical run",
            state=RunState.RUNNING,
            root_path=str(artifact_root.parent),
            created_at=now,
            updated_at=now,
            metadata={"scenario": "external-schema-v2", "repair_provider": "scripted"},
        )
    )

    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    try:
        recovered = manager.store_for("run-orphaned")
        assert recovered.get_run("run-orphaned").state == RunState.FAILED  # type: ignore[union-attr]
        receipt = load_failure_receipt(artifact_root, run_id="run-orphaned")
        assert "executor disappeared" in receipt.message
        with pytest.raises(ValidationError, match="executor disappeared"):
            await manager.verify("run-orphaned")
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_manager_restart_reconciles_receipt_files_left_before_database_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    artifact_root = data_dir / "runs" / "run-crash-window" / "artifacts" / "run-crash-window"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = datetime(2026, 7, 14, tzinfo=timezone.utc)
    store.create_run(
        Run(
            id="run-crash-window",
            name="Crash-window canonical run",
            state=RunState.RUNNING,
            root_path=str(artifact_root.parent),
            created_at=now,
            updated_at=now,
            metadata={"scenario": "external-schema-v2", "repair_provider": "scripted"},
        )
    )

    def crash_before_artifact(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError("simulated process loss after failure receipt rename")

    with monkeypatch.context() as crash:
        crash.setattr(ArtifactStore, "put_bytes", crash_before_artifact)
        failure, issue = finalize_without_masking(
            store=store,
            run_id="run-crash-window",
            artifact_root=artifact_root,
            error=RuntimeError("original experiment failure"),
        )
    assert failure is not None and issue is not None
    assert store.get_run("run-crash-window").state == RunState.FAILED  # type: ignore[union-attr]
    assert store.get_receipt("run-crash-window:failure-receipt") is None

    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    try:
        receipt = manager.store_for("run-crash-window").get_receipt(
            "run-crash-window:failure-receipt"
        )
        assert receipt is not None
        assert receipt.state == ReceiptState.INVALID
        assert receipt.artifact_digest == failure.receipt_digest
        assert manager.store_for("run-crash-window").get_artifact(failure.receipt_digest)
        with pytest.raises(ValidationError, match="original experiment failure"):
            await manager.verify("run-crash-window")
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_live_manager_verification_requires_concurrency_and_live_codex_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    artifact_root = data_dir / "runs" / "run-live" / "artifacts" / "run-live"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = datetime(2026, 7, 14, tzinfo=timezone.utc)
    store.create_run(
        Run(
            id="run-live",
            name="Live canonical run",
            state=RunState.COMPLETED,
            root_path=str(artifact_root.parent),
            created_at=now,
            updated_at=now,
            metadata={"scenario": "external-schema-v2", "repair_provider": "live-codex"},
        )
    )
    captured: dict[str, object] = {}

    def capture_verify(root: Path, *, required_requirement_ids: object) -> object:
        captured["root"] = root
        captured["requirements"] = tuple(required_requirement_ids)  # type: ignore[arg-type]
        return object()

    monkeypatch.setattr("tars_revoke.demo.manager.verify_bundle", capture_verify)
    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    try:
        await manager.verify("run-live")
    finally:
        await manager.close()

    assert captured["root"] == artifact_root
    requirements = captured["requirements"]
    assert "R-01" in requirements  # type: ignore[operator]
    assert "R-14" in requirements  # type: ignore[operator]


@pytest.mark.asyncio
async def test_manager_failure_at_experiment_is_durable_fail_closed_and_restartable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    secret = "manager-test-secret-key"
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    async def reject_experiment(
        self: CanonicalScenario,
        case_id: str,
        premise_v2: object,
    ) -> dict[str, object]:
        del self, case_id, premise_v2
        raise ValidationError(f"invalid experiment proposal OPENAI_API_KEY={secret}")

    monkeypatch.setattr(CanonicalScenario, "_run_experiment", reject_experiment)
    manager = RunManager(Settings(data_dir=data_dir))
    await manager.start()
    run_id = await manager.start_demo(scenario="external-schema-v2", live_codex=False)
    managed = manager._runs[run_id]
    assert managed.task is not None
    with pytest.raises(ValidationError, match="invalid experiment proposal"):
        await managed.task

    artifact_root = manager.artifact_root_for(run_id)
    store = manager.store_for(run_id)
    failure = load_failure_receipt(artifact_root, run_id=run_id)
    assert secret not in failure.message
    assert failure.stage == RevocationCaseState.EXPERIMENTING.value
    assert store.get_run(run_id).state == RunState.FAILED  # type: ignore[union-attr]
    assert {case.state for case in store.list_revocation_cases(run_id)} == {
        RevocationCaseState.ESCALATED
    }
    assert {agent.state for agent in store.list_agents(run_id)} == {AgentState.FAILED}
    failure_receipts = [
        receipt
        for receipt in store.list_receipts(run_id)
        if receipt.metadata.get("kind") == "failure"
    ]
    assert len(failure_receipts) == 1
    assert failure_receipts[0].state == ReceiptState.INVALID
    with pytest.raises(ValidationError, match="run failed: invalid experiment proposal"):
        await manager.verify(run_id)
    await manager.close()

    restarted = RunManager(Settings(data_dir=data_dir))
    await restarted.start()
    try:
        assert restarted.current_run_id == run_id
        restarted_store = restarted.store_for(run_id)
        assert restarted_store.get_run(run_id).state == RunState.FAILED  # type: ignore[union-attr]
        snapshot = build_snapshot(restarted_store, run_id)
        assert snapshot.run.status == RunState.FAILED.value
        assert snapshot.run.revocation_status == RevocationCaseState.ESCALATED.value
        assert snapshot.receipt is not None
        assert snapshot.receipt.status == ReceiptState.INVALID.value
        assert snapshot.failure is not None
        assert snapshot.failure.message == failure.message
        assert secret not in snapshot.failure.message
        with pytest.raises(ValidationError, match="run failed: invalid experiment proposal"):
            await restarted.verify(run_id)
    finally:
        await restarted.close()
