from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tars_revoke.demo.concurrency import (
    CodexSessionEvidence,
    LiveEventEvidence,
    build_concurrent_codex_proof,
    verify_concurrent_codex_proof,
)
from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.errors import IntegrityError


def _session(
    root: Path,
    *,
    lane: str,
    offset: float,
    started_at: datetime,
) -> CodexSessionEvidence:
    ordinal = "a" if lane == "agent_a" else "b"
    worktree = root / f"worktree-{ordinal}"
    worktree.mkdir()
    artifacts = root / "agents" / ordinal
    artifacts.mkdir(parents=True)
    manifest = artifacts / "manifest.json"
    events = artifacts / "events.jsonl"
    observations = artifacts / "event-observations.jsonl"
    process_started = 100.0 + offset
    process_ended = 120.0 + offset
    process_started_at = started_at + timedelta(seconds=offset)
    process_ended_at = started_at + timedelta(seconds=20 + offset)
    observed = 105.0 + offset
    observed_at = started_at + timedelta(seconds=observed - 100.0)
    raw = f'{{"type":"turn.started","lane":"{lane}"}}'.encode()
    events.write_bytes(raw + b"\n")
    observation_row = {
        "sequence": 1,
        "event_type": "turn.started",
        "thread_id": f"thread-{ordinal}",
        "turn_id": f"turn-{ordinal}",
        "item_id": None,
        "observed_at_utc": observed_at.isoformat(),
        "observed_monotonic": observed,
    }
    observations.write_text(
        json.dumps(observation_row, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_row = {
        "protocol": "tars.live-codex/v1",
        "stage": "agent-a-initial-uuid" if lane == "agent_a" else "agent-b-observability",
        "thread_id": f"thread-{ordinal}",
        "process_id": f"proc-{ordinal}",
        "pid": 1000 + (1 if ordinal == "a" else 2),
        "worktree": str(worktree.resolve()),
        "started_at_utc": process_started_at.isoformat(),
        "finished_at_utc": process_ended_at.isoformat(),
        "process_started_monotonic": process_started,
        "process_finished_monotonic": process_ended,
        "duration_seconds": process_ended - process_started,
        "files": {
            "events.jsonl": {
                "path": "events.jsonl",
                "sha256": sha256_digest(events.read_bytes()),
                "size": events.stat().st_size,
            },
            "event-observations.jsonl": {
                "path": "event-observations.jsonl",
                "sha256": sha256_digest(observations.read_bytes()),
                "size": observations.stat().st_size,
            },
        },
    }
    manifest.write_text(
        json.dumps(manifest_row, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return CodexSessionEvidence(
        lane=lane,
        agent_id=f"agent-{ordinal}",
        session_record_id=f"session-{ordinal}",
        external_session_id=f"thread-{ordinal}",
        provider="live-codex",
        worktree=worktree,
        process_handle_id=f"proc-{ordinal}",
        pid=1000 + (1 if ordinal == "a" else 2),
        started_at=process_started_at,
        ended_at=process_ended_at,
        started_monotonic=process_started,
        ended_monotonic=process_ended,
        manifest_path=manifest,
        events_path=events,
        event_observations_path=observations,
        events=(
            LiveEventEvidence(
                sequence=1,
                event_type="turn.started",
                observed_at=observed_at,
                observed_monotonic=observed,
                raw_digest=sha256_digest(raw),
                thread_id=f"thread-{ordinal}",
                turn_id=f"turn-{ordinal}",
            ),
        ),
    )


def test_build_and_verify_requires_real_interval_and_event_overlap(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    sessions = (
        _session(tmp_path, lane="agent_a", offset=0.0, started_at=now),
        _session(tmp_path, lane="agent_b", offset=2.0, started_at=now),
    )

    proof = build_concurrent_codex_proof(
        run_id="run-live",
        artifact_root=tmp_path,
        sessions=sessions,
    )
    verification = verify_concurrent_codex_proof(
        proof,
        artifact_root=tmp_path,
        expected_run_id="run-live",
    )

    assert verification.valid
    assert verification.external_session_ids == ("thread-a", "thread-b")
    assert verification.process_handle_ids == ("proc-a", "proc-b")
    assert verification.overlap_duration_seconds == 18.0


def test_builder_rejects_overlapping_processes_without_live_event_overlap(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    agent_a = _session(tmp_path, lane="agent_a", offset=0.0, started_at=now)
    agent_b = _session(tmp_path, lane="agent_b", offset=2.0, started_at=now)
    agent_b = replace(
        agent_b,
        events=(
            replace(
                agent_b.events[0],
                observed_at=agent_b.ended_at - timedelta(milliseconds=1),
                observed_monotonic=121.999,
            ),
        ),
    )

    with pytest.raises(IntegrityError, match="no live Codex event"):
        build_concurrent_codex_proof(
            run_id="run-live",
            artifact_root=tmp_path,
            sessions=(agent_a, agent_b),
        )


def test_verifier_detects_referenced_artifact_tampering(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    sessions = (
        _session(tmp_path, lane="agent_a", offset=0.0, started_at=now),
        _session(tmp_path, lane="agent_b", offset=2.0, started_at=now),
    )
    proof = build_concurrent_codex_proof(
        run_id="run-live",
        artifact_root=tmp_path,
        sessions=sessions,
    )
    sessions[0].manifest_path.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(IntegrityError, match=r"artifact size changed|artifact digest changed"):
        verify_concurrent_codex_proof(
            proof,
            artifact_root=tmp_path,
            expected_run_id="run-live",
        )


def test_verifier_rejects_a_relabelled_duplicate_thread(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    sessions = (
        _session(tmp_path, lane="agent_a", offset=0.0, started_at=now),
        _session(tmp_path, lane="agent_b", offset=2.0, started_at=now),
    )
    proof = build_concurrent_codex_proof(
        run_id="run-live",
        artifact_root=tmp_path,
        sessions=sessions,
    )
    payload = dict(proof)
    rows = [dict(row) for row in proof["sessions"]]  # type: ignore[index]
    rows[1]["external_session_id"] = rows[0]["external_session_id"]
    unsigned = dict(payload)
    unsigned["sessions"] = rows
    unsigned.pop("integrity")
    payload["sessions"] = rows
    payload["integrity"] = {"canonical_digest": canonical_digest(unsigned)}

    with pytest.raises(IntegrityError, match="distinct external_session_id"):
        verify_concurrent_codex_proof(payload, artifact_root=tmp_path)


def test_verifier_rejects_a_self_digested_fabricated_event_timestamp(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    sessions = (
        _session(tmp_path, lane="agent_a", offset=0.0, started_at=now),
        _session(tmp_path, lane="agent_b", offset=2.0, started_at=now),
    )
    proof = build_concurrent_codex_proof(
        run_id="run-live",
        artifact_root=tmp_path,
        sessions=sessions,
    )
    forged = deepcopy(proof)
    forged["sessions"][0]["events_in_overlap"][0]["observed_monotonic"] += 0.25
    unsigned = dict(forged)
    unsigned.pop("integrity")
    forged["integrity"] = {"canonical_digest": canonical_digest(unsigned)}

    with pytest.raises(IntegrityError, match="streamed observation"):
        verify_concurrent_codex_proof(forged, artifact_root=tmp_path)


def test_verifier_rejects_manifest_metadata_forgery_even_with_updated_hash(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
    sessions = (
        _session(tmp_path, lane="agent_a", offset=0.0, started_at=now),
        _session(tmp_path, lane="agent_b", offset=2.0, started_at=now),
    )
    proof = build_concurrent_codex_proof(
        run_id="run-live",
        artifact_root=tmp_path,
        sessions=sessions,
    )
    manifest_path = sessions[0].manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["process_id"] = "proc-forged"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    forged = deepcopy(proof)
    manifest_record = forged["sessions"][0]["artifacts"]["manifest"]
    manifest_record["sha256"] = sha256_digest(manifest_path.read_bytes())
    manifest_record["size"] = manifest_path.stat().st_size
    unsigned = dict(forged)
    unsigned.pop("integrity")
    forged["integrity"] = {"canonical_digest": canonical_digest(unsigned)}

    with pytest.raises(IntegrityError, match="process handle differs"):
        verify_concurrent_codex_proof(forged, artifact_root=tmp_path)
