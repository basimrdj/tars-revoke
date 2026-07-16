from __future__ import annotations

import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.errors import IntegrityError, ValidationError

CONCURRENT_CODEX_PROOF_PROTOCOL = "tars.concurrent-codex/v1"
_LANES = ("agent_a", "agent_b")


@dataclass(frozen=True)
class LiveEventEvidence:
    sequence: int
    event_type: str
    observed_at: datetime
    observed_monotonic: float
    raw_digest: str
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None


@dataclass(frozen=True)
class CodexSessionEvidence:
    lane: str
    agent_id: str
    session_record_id: str
    external_session_id: str
    provider: str
    worktree: Path
    process_handle_id: str
    pid: int
    started_at: datetime
    ended_at: datetime
    started_monotonic: float
    ended_monotonic: float
    manifest_path: Path
    events_path: Path
    event_observations_path: Path
    events: tuple[LiveEventEvidence, ...]


@dataclass(frozen=True)
class ConcurrentCodexVerification:
    valid: bool
    run_id: str
    session_record_ids: tuple[str, str]
    external_session_ids: tuple[str, str]
    process_handle_ids: tuple[str, str]
    overlap_duration_seconds: float
    proof_digest: str


def build_concurrent_codex_proof(
    *,
    run_id: str,
    artifact_root: Path,
    sessions: Sequence[CodexSessionEvidence],
) -> Mapping[str, Any]:
    """Build a self-digested proof of two genuinely overlapping Codex runs.

    The overlap oracle is the process runner's recorded interval and streamed
    event observation times.  Delays inserted by the scenario are deliberately
    irrelevant: each lane must have an actual Codex JSONL event observed inside
    the intersection of both real process intervals.
    """

    if not run_id:
        raise ValidationError("concurrent Codex proof requires a run ID")
    if len(sessions) != 2 or {item.lane for item in sessions} != set(_LANES):
        raise ValidationError("concurrent Codex proof requires exactly Agent A and Agent B")
    ordered = tuple(sorted(sessions, key=lambda item: item.lane))
    _validate_distinct_sessions(ordered)
    for session in ordered:
        _validate_session_evidence(session)

    overlap_start = max(item.started_monotonic for item in ordered)
    overlap_end = min(item.ended_monotonic for item in ordered)
    if overlap_end <= overlap_start:
        raise IntegrityError("Codex process intervals do not overlap")
    overlap_started_at = max(item.started_at for item in ordered)
    overlap_ended_at = min(item.ended_at for item in ordered)
    if overlap_ended_at <= overlap_started_at:
        raise IntegrityError("Codex UTC process intervals do not overlap")

    root = artifact_root.expanduser().resolve(strict=True)
    session_rows: list[dict[str, Any]] = []
    for session in ordered:
        events_in_overlap = tuple(
            event
            for event in session.events
            if overlap_start <= event.observed_monotonic <= overlap_end
        )
        if not events_in_overlap:
            raise IntegrityError(
                f"{session.lane} emitted no live Codex event during the shared process interval"
            )
        session_rows.append(
            {
                "lane": session.lane,
                "agent_id": session.agent_id,
                "session_record_id": session.session_record_id,
                "external_session_id": session.external_session_id,
                "provider": session.provider,
                "worktree": str(session.worktree.expanduser().resolve(strict=True)),
                "process_handle_id": session.process_handle_id,
                "pid": session.pid,
                "process_interval": {
                    "started_at": session.started_at,
                    "ended_at": session.ended_at,
                    "started_monotonic": session.started_monotonic,
                    "ended_monotonic": session.ended_monotonic,
                    "duration_seconds": session.ended_monotonic
                    - session.started_monotonic,
                },
                "live_event_count": len(session.events),
                "events_in_overlap": [_event_row(event) for event in events_in_overlap],
                "artifacts": {
                    "manifest": _artifact_row(root, session.manifest_path),
                    "events": _artifact_row(root, session.events_path),
                    "event_observations": _artifact_row(
                        root,
                        session.event_observations_path,
                    ),
                },
            }
        )

    body: dict[str, Any] = {
        "protocol": CONCURRENT_CODEX_PROOF_PROTOCOL,
        "run_id": run_id,
        "oracle": "process-runner-interval-and-streamed-jsonl-observation",
        "sessions": session_rows,
        "overlap": {
            "started_at": overlap_started_at,
            "ended_at": overlap_ended_at,
            "started_monotonic": overlap_start,
            "ended_monotonic": overlap_end,
            "duration_seconds": overlap_end - overlap_start,
            "both_lanes_have_live_events": True,
        },
    }
    return {**body, "integrity": {"canonical_digest": canonical_digest(body)}}


def verify_concurrent_codex_proof(
    payload: Mapping[str, Any],
    *,
    artifact_root: Path,
    expected_run_id: str | None = None,
) -> ConcurrentCodexVerification:
    """Independently verify the concurrency proof and its referenced files."""

    if payload.get("protocol") != CONCURRENT_CODEX_PROOF_PROTOCOL:
        raise IntegrityError("unsupported concurrent Codex proof protocol")
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise IntegrityError("concurrent Codex proof run ID is missing")
    if expected_run_id is not None and run_id != expected_run_id:
        raise IntegrityError("concurrent Codex proof belongs to a different run")
    integrity = payload.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {"canonical_digest"}:
        raise IntegrityError("concurrent Codex proof integrity section is malformed")
    expected_digest = integrity.get("canonical_digest")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise IntegrityError("concurrent Codex proof digest is malformed")
    unsigned = dict(payload)
    unsigned.pop("integrity", None)
    if not hmac.compare_digest(canonical_digest(unsigned), expected_digest):
        raise IntegrityError("concurrent Codex proof digest is invalid")

    sessions_raw = payload.get("sessions")
    if not isinstance(sessions_raw, list) or len(sessions_raw) != 2:
        raise IntegrityError("concurrent Codex proof must contain exactly two sessions")
    if any(not isinstance(item, Mapping) for item in sessions_raw):
        raise IntegrityError("concurrent Codex proof contains an invalid session")
    sessions = [dict(item) for item in sessions_raw if isinstance(item, Mapping)]
    if {item.get("lane") for item in sessions} != set(_LANES):
        raise IntegrityError("concurrent Codex proof does not identify Agent A and Agent B")

    distinct_fields = (
        "agent_id",
        "session_record_id",
        "external_session_id",
        "worktree",
        "process_handle_id",
        "pid",
    )
    for field in distinct_fields:
        values = [item.get(field) for item in sessions]
        if any(value in (None, "") for value in values) or len(set(values)) != 2:
            raise IntegrityError(f"concurrent Codex sessions do not have distinct {field}")
    if any(item.get("provider") != "live-codex" for item in sessions):
        raise IntegrityError("R-01 requires two live Codex providers")

    overlap = payload.get("overlap")
    if not isinstance(overlap, Mapping):
        raise IntegrityError("concurrent Codex overlap section is missing")
    overlap_start = _finite_number(overlap.get("started_monotonic"), "overlap start")
    overlap_end = _finite_number(overlap.get("ended_monotonic"), "overlap end")
    overlap_duration = _finite_number(overlap.get("duration_seconds"), "overlap duration")
    if overlap_end <= overlap_start or overlap_duration <= 0:
        raise IntegrityError("concurrent Codex overlap is not positive")
    if abs((overlap_end - overlap_start) - overlap_duration) > 1e-6:
        raise IntegrityError("concurrent Codex overlap duration is inconsistent")
    overlap_started_at = _aware_datetime(overlap.get("started_at"), "overlap started_at")
    overlap_ended_at = _aware_datetime(overlap.get("ended_at"), "overlap ended_at")
    if overlap_ended_at <= overlap_started_at:
        raise IntegrityError("concurrent Codex UTC overlap is not positive")
    if overlap.get("both_lanes_have_live_events") is not True:
        raise IntegrityError("concurrent Codex proof does not claim live events in both lanes")

    root = artifact_root.expanduser().resolve(strict=True)
    starts: list[float] = []
    ends: list[float] = []
    wall_starts: list[datetime] = []
    wall_ends: list[datetime] = []
    for session in sessions:
        interval = session.get("process_interval")
        if not isinstance(interval, Mapping):
            raise IntegrityError("concurrent Codex process interval is missing")
        started = _finite_number(interval.get("started_monotonic"), "process start")
        ended = _finite_number(interval.get("ended_monotonic"), "process end")
        duration = _finite_number(interval.get("duration_seconds"), "process duration")
        started_at = _aware_datetime(interval.get("started_at"), "process started_at")
        ended_at = _aware_datetime(interval.get("ended_at"), "process ended_at")
        if ended <= started or duration <= 0 or ended_at <= started_at:
            raise IntegrityError("concurrent Codex process interval is not positive")
        if abs((ended - started) - duration) > 1e-6:
            raise IntegrityError("concurrent Codex process duration is inconsistent")
        starts.append(started)
        ends.append(ended)
        wall_starts.append(started_at)
        wall_ends.append(ended_at)

        events = session.get("events_in_overlap")
        if not isinstance(events, list) or not events:
            raise IntegrityError("each concurrent Codex lane needs a live event in the overlap")
        for event in events:
            _verify_event_row(event, overlap_start=overlap_start, overlap_end=overlap_end)
        count = session.get("live_event_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < len(events):
            raise IntegrityError("concurrent Codex live event count is invalid")

        artifacts = session.get("artifacts")
        if not isinstance(artifacts, Mapping) or set(artifacts) != {
            "manifest",
            "events",
            "event_observations",
        }:
            raise IntegrityError("concurrent Codex session artifacts are incomplete")
        verified_artifacts = {
            str(label): _verify_artifact_row(root, artifact)
            for label, artifact in artifacts.items()
        }
        _verify_raw_events(events, events_path=verified_artifacts["events"])
        _verify_event_observations(
            events,
            observations_path=verified_artifacts["event_observations"],
        )
        _verify_session_manifest(
            session,
            interval=interval,
            manifest_path=verified_artifacts["manifest"],
            events_path=verified_artifacts["events"],
            observations_path=verified_artifacts["event_observations"],
        )

    derived_start = max(starts)
    derived_end = min(ends)
    if derived_end <= derived_start:
        raise IntegrityError("Codex process intervals do not overlap")
    if abs(derived_start - overlap_start) > 1e-6 or abs(derived_end - overlap_end) > 1e-6:
        raise IntegrityError("concurrent Codex overlap does not match process intervals")
    if max(wall_starts) != overlap_started_at or min(wall_ends) != overlap_ended_at:
        raise IntegrityError("concurrent Codex UTC overlap does not match process intervals")

    ordered = sorted(sessions, key=lambda item: str(item["lane"]))
    return ConcurrentCodexVerification(
        valid=True,
        run_id=run_id,
        session_record_ids=(
            str(ordered[0]["session_record_id"]),
            str(ordered[1]["session_record_id"]),
        ),
        external_session_ids=(
            str(ordered[0]["external_session_id"]),
            str(ordered[1]["external_session_id"]),
        ),
        process_handle_ids=(
            str(ordered[0]["process_handle_id"]),
            str(ordered[1]["process_handle_id"]),
        ),
        overlap_duration_seconds=overlap_duration,
        proof_digest=expected_digest,
    )


def _validate_distinct_sessions(sessions: Sequence[CodexSessionEvidence]) -> None:
    fields: tuple[tuple[str, Sequence[object]], ...] = (
        ("agent IDs", [item.agent_id for item in sessions]),
        ("session record IDs", [item.session_record_id for item in sessions]),
        ("Codex thread IDs", [item.external_session_id for item in sessions]),
        ("worktrees", [item.worktree.expanduser().resolve(strict=True) for item in sessions]),
        ("process handles", [item.process_handle_id for item in sessions]),
        ("PIDs", [item.pid for item in sessions]),
    )
    for label, values in fields:
        if len(set(values)) != 2:
            raise IntegrityError(f"concurrent Codex proof requires distinct {label}")


def _validate_session_evidence(session: CodexSessionEvidence) -> None:
    if session.lane not in _LANES:
        raise ValidationError("invalid concurrent Codex lane")
    for label, value in (
        ("agent ID", session.agent_id),
        ("session record ID", session.session_record_id),
        ("Codex thread ID", session.external_session_id),
        ("provider", session.provider),
        ("process handle", session.process_handle_id),
    ):
        if not value:
            raise ValidationError(f"concurrent Codex {label} is required")
    if session.provider != "live-codex":
        raise IntegrityError("R-01 accepts only live Codex sessions")
    if session.pid <= 0:
        raise IntegrityError("concurrent Codex PID must be positive")
    if session.started_at.tzinfo is None or session.ended_at.tzinfo is None:
        raise IntegrityError("concurrent Codex UTC interval must be timezone-aware")
    if session.ended_at <= session.started_at:
        raise IntegrityError("concurrent Codex UTC interval must be positive")
    if session.ended_monotonic <= session.started_monotonic:
        raise IntegrityError("concurrent Codex monotonic interval must be positive")
    if not session.events:
        raise IntegrityError("concurrent Codex session has no streamed live events")
    for event in session.events:
        if event.sequence <= 0 or not event.event_type or event.observed_at.tzinfo is None:
            raise IntegrityError("concurrent Codex event evidence is malformed")
        if len(event.raw_digest) != 64:
            raise IntegrityError("concurrent Codex event digest is malformed")
        if not session.started_monotonic <= event.observed_monotonic <= session.ended_monotonic:
            raise IntegrityError("live Codex event falls outside its process interval")


def _event_row(event: LiveEventEvidence) -> dict[str, Any]:
    return {
        "sequence": event.sequence,
        "event_type": event.event_type,
        "observed_at": event.observed_at,
        "observed_monotonic": event.observed_monotonic,
        "raw_digest": event.raw_digest,
        "thread_id": event.thread_id,
        "turn_id": event.turn_id,
        "item_id": event.item_id,
    }


def _artifact_row(root: Path, path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve(strict=True)
    if resolved == root or root not in resolved.parents:
        raise IntegrityError(f"concurrent Codex artifact escapes the run root: {path}")
    if not resolved.is_file() or resolved.is_symlink():
        raise IntegrityError(f"concurrent Codex artifact is not a regular file: {path}")
    content = resolved.read_bytes()
    return {
        "path": resolved.relative_to(root).as_posix(),
        "sha256": sha256_digest(content),
        "size": len(content),
    }


def _verify_artifact_row(root: Path, value: object) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "size"}:
        raise IntegrityError("concurrent Codex artifact record is malformed")
    path = (root / str(value.get("path", ""))).resolve()
    if path == root or root not in path.parents or not path.is_file() or path.is_symlink():
        raise IntegrityError("concurrent Codex artifact is missing or escapes the run root")
    content = path.read_bytes()
    size = value.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size != len(content):
        raise IntegrityError("concurrent Codex artifact size changed")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not hmac.compare_digest(
        sha256_digest(content), digest
    ):
        raise IntegrityError("concurrent Codex artifact digest changed")
    return path


def _verify_raw_events(events: Sequence[object], *, events_path: Path) -> None:
    lines = events_path.read_bytes().splitlines()
    for event in events:
        if not isinstance(event, Mapping):
            raise IntegrityError("concurrent Codex live event is malformed")
        sequence = event.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise IntegrityError("concurrent Codex live event sequence is invalid")
        if sequence <= 0 or sequence > len(lines):
            raise IntegrityError("concurrent Codex live event is absent from raw JSONL")
        raw_line = lines[sequence - 1]
        if not hmac.compare_digest(sha256_digest(raw_line), str(event.get("raw_digest", ""))):
            raise IntegrityError("concurrent Codex live event digest differs from raw JSONL")
        try:
            raw = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise IntegrityError("concurrent Codex raw event is not valid JSON") from exc
        if not isinstance(raw, Mapping) or raw.get("type") != event.get("event_type"):
            raise IntegrityError("concurrent Codex live event type differs from raw JSONL")


def _verify_event_observations(
    events: Sequence[object],
    *,
    observations_path: Path,
) -> None:
    observed_by_sequence: dict[int, Mapping[str, Any]] = {}
    observation_lines = observations_path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(observation_lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError("Codex event observation artifact is not valid JSONL") from exc
        if not isinstance(value, Mapping):
            raise IntegrityError("Codex event observation row is not an object")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
            raise IntegrityError(
                f"Codex event observation row {line_number} has an invalid sequence"
            )
        if sequence in observed_by_sequence:
            raise IntegrityError("Codex event observation artifact has duplicate sequences")
        observed_by_sequence[sequence] = value

    for event in events:
        if not isinstance(event, Mapping):
            raise IntegrityError("concurrent Codex live event is malformed")
        sequence = event.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise IntegrityError("concurrent Codex live event sequence is invalid")
        observed = observed_by_sequence.get(sequence)
        if observed is None:
            raise IntegrityError("claimed live event is absent from event observations")
        field_pairs = (
            ("event_type", "event_type"),
            ("thread_id", "thread_id"),
            ("turn_id", "turn_id"),
            ("item_id", "item_id"),
        )
        if any(event.get(left) != observed.get(right) for left, right in field_pairs):
            raise IntegrityError("claimed live event differs from its streamed observation")
        claimed_monotonic = _finite_number(
            event.get("observed_monotonic"),
            "claimed event monotonic",
        )
        observed_monotonic = _finite_number(
            observed.get("observed_monotonic"),
            "streamed event monotonic",
        )
        if claimed_monotonic != observed_monotonic:
            raise IntegrityError("claimed live event timestamp differs from streamed observation")
        if _aware_datetime(event.get("observed_at"), "claimed event observed_at") != (
            _aware_datetime(observed.get("observed_at_utc"), "streamed event observed_at")
        ):
            raise IntegrityError("claimed live event UTC time differs from streamed observation")


def _verify_session_manifest(
    session: Mapping[str, Any],
    *,
    interval: Mapping[str, Any],
    manifest_path: Path,
    events_path: Path,
    observations_path: Path,
) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IntegrityError("live Codex session manifest is not valid JSON") from exc
    if not isinstance(manifest, Mapping) or manifest.get("protocol") != "tars.live-codex/v1":
        raise IntegrityError("live Codex session manifest protocol is invalid")
    expected_stage = {
        "agent_a": "agent-a-initial-uuid",
        "agent_b": "agent-b-observability",
    }.get(str(session.get("lane")))
    comparisons = (
        (manifest.get("stage"), expected_stage, "stage"),
        (manifest.get("thread_id"), session.get("external_session_id"), "thread ID"),
        (manifest.get("process_id"), session.get("process_handle_id"), "process handle"),
        (manifest.get("pid"), session.get("pid"), "PID"),
        (manifest.get("worktree"), session.get("worktree"), "worktree"),
        (
            manifest.get("process_started_monotonic"),
            interval.get("started_monotonic"),
            "process start",
        ),
        (
            manifest.get("process_finished_monotonic"),
            interval.get("ended_monotonic"),
            "process end",
        ),
        (manifest.get("duration_seconds"), interval.get("duration_seconds"), "duration"),
    )
    for actual, expected, label in comparisons:
        if actual != expected:
            raise IntegrityError(f"concurrent Codex {label} differs from session manifest")
    if _aware_datetime(manifest.get("started_at_utc"), "manifest started_at") != (
        _aware_datetime(interval.get("started_at"), "proof started_at")
    ):
        raise IntegrityError("concurrent Codex start UTC differs from session manifest")
    if _aware_datetime(manifest.get("finished_at_utc"), "manifest finished_at") != (
        _aware_datetime(interval.get("ended_at"), "proof ended_at")
    ):
        raise IntegrityError("concurrent Codex end UTC differs from session manifest")

    files = manifest.get("files")
    if not isinstance(files, Mapping):
        raise IntegrityError("live Codex manifest file inventory is missing")
    for name, expected_path in (
        ("events.jsonl", events_path),
        ("event-observations.jsonl", observations_path),
    ):
        entry = files.get(name)
        if not isinstance(entry, Mapping):
            raise IntegrityError(f"live Codex manifest does not cover {name}")
        if entry.get("path") != name or expected_path.parent != manifest_path.parent:
            raise IntegrityError(f"live Codex manifest {name} path is inconsistent")
        content = expected_path.read_bytes()
        if entry.get("size") != len(content) or entry.get("sha256") != sha256_digest(content):
            raise IntegrityError(f"live Codex manifest {name} integrity differs from artifact")


def _verify_event_row(value: object, *, overlap_start: float, overlap_end: float) -> None:
    if not isinstance(value, Mapping):
        raise IntegrityError("concurrent Codex live event is malformed")
    sequence = value.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise IntegrityError("concurrent Codex live event sequence is invalid")
    if not isinstance(value.get("event_type"), str) or not value["event_type"]:
        raise IntegrityError("concurrent Codex live event type is missing")
    _aware_datetime(value.get("observed_at"), "live event observed_at")
    observed = _finite_number(value.get("observed_monotonic"), "live event monotonic")
    if not overlap_start <= observed <= overlap_end:
        raise IntegrityError("claimed live event falls outside the shared process interval")
    digest = value.get("raw_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise IntegrityError("concurrent Codex live event digest is malformed")


def _aware_datetime(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise IntegrityError(f"concurrent Codex {label} is invalid") from exc
    else:
        raise IntegrityError(f"concurrent Codex {label} is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntegrityError(f"concurrent Codex {label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _finite_number(value: object, label: str) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise IntegrityError(f"concurrent Codex {label} is invalid")
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise IntegrityError(f"concurrent Codex {label} is not finite")
    return result
