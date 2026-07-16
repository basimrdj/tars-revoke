from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tars_revoke.demo.failures import (
    FAILURE_RECEIPT_NAME,
    FAILURE_RECEIPT_SHA_NAME,
    finalize_failed_run,
    finalize_without_masking,
    load_failure_receipt,
)
from tars_revoke.domain.enums import (
    AgentState,
    ReceiptState,
    RunState,
    SessionState,
)
from tars_revoke.domain.models import Agent, AgentSession, Run
from tars_revoke.persistence.artifacts import ArtifactStore
from tars_revoke.persistence.store import Store

NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)


def _active_store(tmp_path: Path, run_id: str = "run-failure") -> tuple[Store, Path]:
    root = tmp_path / "artifacts" / run_id
    root.mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "logs" / "progress.json").write_text('{"stage":"experiment"}\n')
    store = Store(root / "state.sqlite")
    store.create_run(
        Run(
            id=run_id,
            name="Failure finalization test",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_agent(
        Agent(
            id="agent-active",
            run_id=run_id,
            name="Agent A",
            role="experiment",
            worktree_path=str(tmp_path / "worktree"),
            state=AgentState.RUNNING,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_agent_session(
        AgentSession(
            id="session-active",
            run_id=run_id,
            agent_id="agent-active",
            provider="test",
            state=SessionState.RUNNING,
            started_at=NOW,
            updated_at=NOW,
        )
    )
    return store, root


def test_failure_finalizer_persists_sanitized_invalid_receipt_and_terminal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, root = _active_store(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "unit-test-super-secret-value")

    failure = finalize_failed_run(
        store=store,
        run_id="run-failure",
        artifact_root=root,
        error=ValueError(
            "invalid experiment OPENAI_API_KEY=unit-test-super-secret-value "
            f"at {Path.home()}/private"
        ),
    )

    content = (root / FAILURE_RECEIPT_NAME).read_bytes()
    payload = json.loads(content)
    assert "unit-test-super-secret-value" not in content.decode()
    assert str(Path.home()) not in content.decode()
    assert "<redacted>" in payload["failure"]["message"]
    assert payload["failure"]["stage"] == "agent_session.created"
    assert payload["receipt_state"] == "INVALID"
    assert payload["artifact_inventory"]["files"] == [
        {
            "path": "logs/progress.json",
            "sha256": hashlib.sha256(b'{"stage":"experiment"}\n').hexdigest(),
            "size": 23,
        }
    ]
    assert (root / FAILURE_RECEIPT_SHA_NAME).read_text().strip() == hashlib.sha256(
        content
    ).hexdigest()
    assert store.get_run("run-failure").state == RunState.FAILED  # type: ignore[union-attr]
    assert store.get_agent("agent-active").state == AgentState.FAILED  # type: ignore[union-attr]
    assert (
        store.get_agent_session("session-active").state == SessionState.FAILED  # type: ignore[union-attr]
    )
    receipt = store.get_receipt("run-failure:failure-receipt")
    assert receipt is not None
    assert receipt.state == ReceiptState.INVALID
    assert receipt.case_id is None
    assert receipt.event_head_digest == payload["event_chain"]["head_digest"]
    assert receipt.event_head_digest in {
        event.event_hash for event in store.journal.list_events("run-failure")
    }
    assert failure == load_failure_receipt(root, run_id="run-failure")


def test_cancellation_persists_cancelled_agents_sessions_and_invalid_receipt(
    tmp_path: Path,
) -> None:
    store, root = _active_store(tmp_path, run_id="run-cancelled")

    failure = finalize_failed_run(
        store=store,
        run_id="run-cancelled",
        artifact_root=root,
        error=asyncio.CancelledError(),
    )

    assert failure.status == "CANCELLED"
    assert store.get_run("run-cancelled").state == RunState.CANCELLED  # type: ignore[union-attr]
    assert store.get_agent("agent-active").state == AgentState.CANCELLED  # type: ignore[union-attr]
    assert (
        store.get_agent_session("session-active").state  # type: ignore[union-attr]
        == SessionState.CANCELLED
    )
    receipt = store.get_receipt("run-cancelled:failure-receipt")
    assert receipt is not None and receipt.state == ReceiptState.INVALID


def test_finalization_issue_does_not_replace_source_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, root = _active_store(tmp_path)
    source = RuntimeError("source failure")

    def broken_create_receipt(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("receipt disk unavailable")

    monkeypatch.setattr(store, "create_receipt", broken_create_receipt)

    try:
        raise source
    except RuntimeError as caught:
        _failure, finalization_issue = finalize_without_masking(
            store=store,
            run_id="run-failure",
            artifact_root=root,
            error=caught,
        )
        assert caught is source
        assert finalization_issue is not None
        assert "FailureFinalizationError" in finalization_issue


def test_retry_reconciles_files_persisted_before_artifact_and_receipt_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, root = _active_store(tmp_path)
    source = RuntimeError("experiment proposal was invalid")
    original_put_bytes = ArtifactStore.put_bytes

    def crash_before_artifact(self: ArtifactStore, content: bytes, **kwargs: object) -> object:
        del self, content, kwargs
        raise OSError("simulated crash after receipt rename")

    monkeypatch.setattr(ArtifactStore, "put_bytes", crash_before_artifact)
    recovered_from_files, finalization_issue = finalize_without_masking(
        store=store,
        run_id="run-failure",
        artifact_root=root,
        error=source,
    )

    assert recovered_from_files is not None
    assert finalization_issue is not None
    assert store.get_run("run-failure").state == RunState.FAILED  # type: ignore[union-attr]
    assert store.get_receipt("run-failure:failure-receipt") is None
    assert store.get_artifact(recovered_from_files.receipt_digest) is None
    before = (root / FAILURE_RECEIPT_NAME).read_bytes()
    event_count_before = len(store.journal.list_events("run-failure"))

    monkeypatch.setattr(ArtifactStore, "put_bytes", original_put_bytes)
    reconciled = finalize_failed_run(
        store=store,
        run_id="run-failure",
        artifact_root=root,
        error=RuntimeError("a restart must preserve the original failure receipt"),
    )

    assert reconciled == recovered_from_files
    assert (root / FAILURE_RECEIPT_NAME).read_bytes() == before
    receipt = store.get_receipt("run-failure:failure-receipt")
    assert receipt is not None
    assert receipt.state == ReceiptState.INVALID
    assert receipt.artifact_digest == reconciled.receipt_digest
    assert store.get_artifact(reconciled.receipt_digest) is not None
    assert len(store.journal.list_events("run-failure")) == event_count_before + 1
