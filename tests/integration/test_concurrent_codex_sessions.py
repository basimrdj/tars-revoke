from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from tars_revoke.adapters.codex import CodexSandbox
from tars_revoke.demo.concurrency import verify_concurrent_codex_proof
from tars_revoke.demo.live_codex import (
    CodexEventObservation,
    LiveCodexArtifacts,
    LiveCodexResult,
)
from tars_revoke.demo.scenario import CanonicalScenario
from tars_revoke.domain.canonical import canonical_json, sha256_digest
from tars_revoke.domain.enums import SessionState


class _ConcurrentLiveDouble:
    def __init__(
        self,
        *,
        agent_a: LiveCodexResult,
        agent_b: LiveCodexResult,
    ) -> None:
        self.results = {"agent_a": agent_a, "agent_b": agent_b}
        self.entered: list[tuple[str, Path]] = []
        self.both_entered = asyncio.Event()

    async def _arrive(self, lane: str, worktree: Path) -> LiveCodexResult:
        self.entered.append((lane, worktree.resolve()))
        if len(self.entered) == 2:
            self.both_entered.set()
        await asyncio.wait_for(self.both_entered.wait(), timeout=1)
        return self.results[lane]

    async def initial_uuid_change(self, *_args: Any, **kwargs: Any) -> LiveCodexResult:
        return await self._arrive("agent_a", cast(Path, kwargs["worktree"]))

    async def unrelated_observability_change(
        self,
        **kwargs: Any,
    ) -> LiveCodexResult:
        return await self._arrive("agent_b", cast(Path, kwargs["worktree"]))


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def _fake_live_result(
    scenario: CanonicalScenario,
    *,
    lane: str,
    offset: float,
    now: datetime,
) -> LiveCodexResult:
    is_agent_a = lane == "agent_a"
    ordinal = "a" if is_agent_a else "b"
    stage = "agent-a-initial-uuid" if is_agent_a else "agent-b-observability"
    worktree = (
        scenario.fixture.agent_a_worktree if is_agent_a else scenario.fixture.agent_b_worktree
    )
    root = scenario.artifact_root / "agents" / "live-codex" / "sessions" / f"{stage}-test"
    root.mkdir(parents=True)
    thread_id = f"thread-{ordinal}"
    process_id = f"proc-{ordinal}"
    pid = 4000 + (1 if is_agent_a else 2)
    started_monotonic = 100.0 + offset
    finished_monotonic = 120.0 + offset
    observed_monotonic = 105.0 + offset
    started_at = now + timedelta(seconds=offset)
    finished_at = now + timedelta(seconds=20 + offset)
    observed_at = now + timedelta(seconds=5 + offset)
    event = {"id": thread_id, "type": "thread.started"}
    event_bytes = (canonical_json(event) + "\n").encode()
    observation = {
        "sequence": 1,
        "event_type": "thread.started",
        "thread_id": thread_id,
        "turn_id": None,
        "item_id": None,
        "observed_at_utc": observed_at.isoformat(),
        "observed_monotonic": observed_monotonic,
    }
    observation_bytes = (canonical_json(observation) + "\n").encode()
    prompt_path = _write(root / "prompt.txt", f"prompt {ordinal}\n".encode())
    events_path = _write(root / "events.jsonl", event_bytes)
    observations_path = _write(root / "event-observations.jsonl", observation_bytes)
    last_message_path = _write(root / "last-message.txt", b"{}\n")
    changed_paths_path = _write(root / "changed-paths.json", b"[]\n")
    diff_path = _write(root / "workspace.diff", b"diff\n")
    stdout_path = _write(root / "stdout.log", event_bytes)
    stderr_path = _write(root / "stderr.log", b"")
    stdout_digest = sha256_digest(stdout_path.read_bytes())
    stderr_digest = sha256_digest(stderr_path.read_bytes())
    stdout_digest_path = _write(root / "stdout.sha256", f"{stdout_digest}\n".encode())
    stderr_digest_path = _write(root / "stderr.sha256", f"{stderr_digest}\n".encode())
    files = {
        path.name: {
            "path": path.name,
            "sha256": sha256_digest(path.read_bytes()),
            "size": path.stat().st_size,
        }
        for path in (
            prompt_path,
            events_path,
            observations_path,
            last_message_path,
            changed_paths_path,
            diff_path,
            stdout_path,
            stderr_path,
            stdout_digest_path,
            stderr_digest_path,
        )
    }
    manifest = {
        "protocol": "tars.live-codex/v1",
        "stage": stage,
        "thread_id": thread_id,
        "process_id": process_id,
        "pid": pid,
        "worktree": str(worktree.resolve()),
        "started_at_utc": started_at.isoformat(),
        "finished_at_utc": finished_at.isoformat(),
        "process_started_monotonic": started_monotonic,
        "process_finished_monotonic": finished_monotonic,
        "duration_seconds": finished_monotonic - started_monotonic,
        "files": files,
    }
    manifest_path = _write(root / "manifest.json", canonical_json(manifest).encode())
    manifest_digest = sha256_digest(manifest_path.read_bytes())
    manifest_digest_path = _write(
        root / "manifest.sha256",
        f"{manifest_digest}\n".encode(),
    )
    artifacts = LiveCodexArtifacts(
        root=root,
        prompt_path=prompt_path,
        events_path=events_path,
        event_observations_path=observations_path,
        last_message_path=last_message_path,
        changed_paths_path=changed_paths_path,
        diff_path=diff_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_digest_path=stdout_digest_path,
        stderr_digest_path=stderr_digest_path,
        manifest_path=manifest_path,
        manifest_digest_path=manifest_digest_path,
        stdout_digest=stdout_digest,
        stderr_digest=stderr_digest,
        manifest_digest=manifest_digest,
    )
    return LiveCodexResult(
        stage=stage,
        worktree=worktree.resolve(),
        thread_id=thread_id,
        turn_ids=(),
        item_ids=(),
        final_message="{}",
        structured_output={},
        changed_paths=("billing/models.py",) if is_agent_a else ("docs/observability.md",),
        diff="diff\n",
        command_evidence=(),
        event_observations=(
            CodexEventObservation(
                sequence=1,
                event_type="thread.started",
                thread_id=thread_id,
                turn_id=None,
                item_id=None,
                observed_at_utc=observed_at,
                observed_monotonic=observed_monotonic,
            ),
        ),
        process_id=process_id,
        pid=pid,
        process_started_monotonic=started_monotonic,
        process_finished_monotonic=finished_monotonic,
        duration_seconds=finished_monotonic - started_monotonic,
        started_at_utc=started_at,
        finished_at_utc=finished_at,
        executable=Path("/Applications/Codex.app/Contents/Resources/codex"),
        executable_version="codex-cli test",
        model=None,
        sandbox=CodexSandbox.WORKSPACE_WRITE,
        artifacts=artifacts,
    )


@pytest.mark.asyncio
async def test_scenario_starts_both_live_lanes_before_either_can_finish(
    tmp_path: Path,
) -> None:
    scenario = await CanonicalScenario.prepare(tmp_path, run_id="concurrent-launch")
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    expected_a = _fake_live_result(scenario, lane="agent_a", offset=0.0, now=now)
    expected_b = _fake_live_result(scenario, lane="agent_b", offset=2.0, now=now)
    live = _ConcurrentLiveDouble(agent_a=expected_a, agent_b=expected_b)
    scenario._signed_evidence[1] = {"version": 1, "digest": "signed-v1"}
    scenario.live_codex = cast(Any, live)

    try:
        result_a, result_b = await scenario._run_live_initial_pair(
            allowed_initial_paths=(
                "billing/models.py",
                "migrations/002_customer_id_contract.sql",
            )
        )
    finally:
        scenario.live_codex = None
        await scenario.close()

    assert (result_a, result_b) == (expected_a, expected_b)
    assert set(live.entered) == {
        ("agent_a", scenario.fixture.agent_a_worktree.resolve()),
        ("agent_b", scenario.fixture.agent_b_worktree.resolve()),
    }
    assert len({worktree for _, worktree in live.entered}) == 2


@pytest.mark.asyncio
async def test_scenario_persists_two_completed_sessions_and_verified_overlap(
    tmp_path: Path,
) -> None:
    scenario = await CanonicalScenario.prepare(tmp_path, run_id="concurrent-wiring")
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    agent_a = _fake_live_result(scenario, lane="agent_a", offset=0.0, now=now)
    agent_b = _fake_live_result(scenario, lane="agent_b", offset=2.0, now=now)

    try:
        proof_path = scenario._persist_live_concurrency_proof(agent_a, agent_b)
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        verified = verify_concurrent_codex_proof(
            proof,
            artifact_root=scenario.artifact_root,
            expected_run_id=scenario.fixture.run_id,
        )
        sessions = scenario.store.list_agent_sessions(scenario.fixture.run_id)
    finally:
        await scenario.close()

    assert verified.valid
    assert verified.overlap_duration_seconds == 18.0
    assert len(sessions) == 2
    assert {session.state for session in sessions} == {SessionState.COMPLETED}
    assert {session.external_session_id for session in sessions} == {"thread-a", "thread-b"}
    assert {session.process_id for session in sessions} == {4001, 4002}
    assert len({session.agent_id for session in sessions}) == 2
