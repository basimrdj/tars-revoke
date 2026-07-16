from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import (
    AgentState,
    ReceiptState,
    RevocationCaseState,
    RunState,
    SessionState,
)
from tars_revoke.domain.models import Receipt
from tars_revoke.errors import IntegrityError
from tars_revoke.persistence.artifacts import ArtifactStore
from tars_revoke.persistence.event_journal import GENESIS_HASH
from tars_revoke.persistence.store import Store

FAILURE_RECEIPT_NAME = "failure-receipt.json"
FAILURE_RECEIPT_SHA_NAME = "failure-receipt.sha256"
FAILURE_RECEIPT_VERSION = 1
_FAILURE_RECEIPT_KIND = "tars-revoke-failure"
_TERMINAL_RUN_STATES = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
_TERMINAL_CASE_STATES = {
    RevocationCaseState.CLOSED,
    RevocationCaseState.ESCALATED,
}
_ACTIVE_AGENT_STATES = {AgentState.RUNNING, AgentState.PAUSED}
_ACTIVE_SESSION_STATES = {SessionState.RUNNING, SessionState.PAUSED}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|cookie|"
    r"password|private[_-]?key|secret|token)\b\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")
ResultT = TypeVar("ResultT")


class RecoveredRunInterruption(RuntimeError):
    """A prior executor disappeared without recording a terminal run state."""


class FailureFinalizationError(RuntimeError):
    """The best-effort failure boundary could not persist its required receipt."""


@dataclass(frozen=True)
class DurableFailure:
    run_id: str
    status: str
    error_type: str
    message: str
    stage: str
    occurred_at: datetime
    receipt_path: Path
    receipt_digest: str
    event_head_digest: str
    event_head_sequence: int
    artifact_count: int
    finalization_errors: tuple[str, ...] = ()


def _parse_datetime(value: object) -> datetime:
    normalized = str(value)
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed


def sanitize_failure_text(value: object, *, limit: int = 1_000) -> str:
    """Return useful operator context without credentials, home paths, or controls."""

    text = str(value) if value is not None else ""
    sensitive_values: list[str] = []
    for name, candidate in os.environ.items():
        upper = name.upper()
        is_sensitive = any(
            marker in upper
            for marker in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "COOKIE")
        ) or upper.endswith("_KEY")
        if is_sensitive and len(candidate) >= 4:
            sensitive_values.append(candidate)
    for candidate in sorted(set(sensitive_values), key=len, reverse=True):
        text = text.replace(candidate, "<redacted>")
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = _BEARER.sub("Bearer <redacted>", text)
    text = _OPENAI_KEY.sub("<redacted>", text)
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "<home>")
    text = _CONTROL.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return "run cancelled" if limit else ""
    if len(text) > limit:
        return f"{text[: max(0, limit - 1)]}…"
    return text


def _receipt_id(run_id: str) -> str:
    return f"{run_id}:failure-receipt"


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _is_inventory_file(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    if path.is_symlink() or not path.is_file():
        return False
    if relative.name in {FAILURE_RECEIPT_NAME, FAILURE_RECEIPT_SHA_NAME}:
        return False
    if relative.name == "state.sqlite" or relative.name.startswith("state.sqlite-"):
        return False
    return not relative.name.startswith(f".{FAILURE_RECEIPT_NAME}.")


def _artifact_inventory(root: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not _is_inventory_file(root, path):
            continue
        content = path.read_bytes()
        inventory.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_digest(content),
                "size": len(content),
            }
        )
    return inventory


def _attempt(
    label: str,
    operation: Callable[[], ResultT],
    errors: list[str],
) -> ResultT | None:
    try:
        return operation()
    except BaseException as exc:
        errors.append(
            sanitize_failure_text(f"{label}: {type(exc).__name__}: {exc}")
        )
        return None


def _recorded_failure_is_terminal(store: Store, run_id: str) -> bool:
    run = store.get_run(run_id)
    if run is None or run.state not in {RunState.FAILED, RunState.CANCELLED}:
        return False
    if any(case.state not in _TERMINAL_CASE_STATES for case in store.list_revocation_cases(run_id)):
        return False
    if any(agent.state in _ACTIVE_AGENT_STATES for agent in store.list_agents(run_id)):
        return False
    return not any(
        session.state in _ACTIVE_SESSION_STATES
        for session in store.list_agent_sessions(run_id)
    )


def _failure_stage(store: Store, run_id: str) -> str:
    cases = store.list_revocation_cases(run_id)
    if cases:
        return cases[-1].state.value
    head = store.journal.head(run_id)
    return head.kind if head is not None else "PREPARATION"


def _failure_from_payload(path: Path, payload: dict[str, Any], digest: str) -> DurableFailure:
    if payload.get("failure_receipt_version") != FAILURE_RECEIPT_VERSION:
        raise IntegrityError("failure receipt version is unsupported")
    if payload.get("kind") != _FAILURE_RECEIPT_KIND:
        raise IntegrityError("failure receipt kind is invalid")
    failure = payload.get("failure")
    event_chain = payload.get("event_chain")
    inventory = payload.get("artifact_inventory")
    if not isinstance(failure, dict) or not isinstance(event_chain, dict):
        raise IntegrityError("failure receipt summary is incomplete")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
        raise IntegrityError("failure receipt artifact inventory is incomplete")
    try:
        occurred_at = _parse_datetime(failure.get("occurred_at", ""))
    except ValueError as exc:
        raise IntegrityError("failure receipt timestamp must be timezone-aware") from exc
    finalization_errors = payload.get("finalization_errors", [])
    if not isinstance(finalization_errors, list) or any(
        not isinstance(item, str) for item in finalization_errors
    ):
        raise IntegrityError("failure receipt finalization errors are invalid")
    return DurableFailure(
        run_id=str(payload.get("run_id", "")),
        status=str(failure.get("status", "FAILED")),
        error_type=str(failure.get("error_type", "UnknownFailure")),
        message=str(failure.get("message", "run failed without a recorded reason")),
        stage=str(failure.get("stage", "UNKNOWN")),
        occurred_at=occurred_at,
        receipt_path=path,
        receipt_digest=digest,
        event_head_digest=str(event_chain.get("head_digest", GENESIS_HASH)),
        event_head_sequence=int(event_chain.get("head_sequence", 0)),
        artifact_count=len(inventory["files"]),
        finalization_errors=tuple(finalization_errors),
    )


def load_failure_receipt(artifact_root: Path, *, run_id: str | None = None) -> DurableFailure:
    root = artifact_root.expanduser().resolve()
    path = root / FAILURE_RECEIPT_NAME
    sha_path = root / FAILURE_RECEIPT_SHA_NAME
    if not path.is_file() or path.is_symlink() or not sha_path.is_file() or sha_path.is_symlink():
        raise FileNotFoundError(f"durable failure receipt is missing under {root}")
    content = path.read_bytes()
    digest = sha256_digest(content)
    expected = sha_path.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(digest, expected):
        raise IntegrityError("failure-receipt.sha256 does not match failure-receipt.json")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise IntegrityError("failure receipt is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise IntegrityError("failure receipt must contain a JSON object")
    record = _failure_from_payload(path, parsed, digest)
    if run_id is not None and record.run_id != run_id:
        raise IntegrityError("failure receipt run ID does not match durable state")
    return record


def _reconcile_failure_receipt(
    store: Store,
    run_id: str,
    artifact_root: Path,
) -> DurableFailure:
    """Complete the file -> artifact -> INVALID row commit protocol idempotently."""

    record = load_failure_receipt(artifact_root, run_id=run_id)
    content = record.receipt_path.read_bytes()
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:  # pragma: no cover - load already validates this
        raise IntegrityError("failure receipt is not valid JSON") from exc
    if not isinstance(payload, dict):  # pragma: no cover - load already validates this
        raise IntegrityError("failure receipt must contain a JSON object")
    inventory = payload.get("artifact_inventory")
    if not isinstance(inventory, dict):
        raise IntegrityError("failure receipt artifact inventory is incomplete")
    files = inventory.get("files")
    manifest_digest = inventory.get("digest")
    if not isinstance(files, list) or not isinstance(manifest_digest, str):
        raise IntegrityError("failure receipt artifact inventory digest is missing")
    if not hmac.compare_digest(canonical_digest(files), manifest_digest):
        raise IntegrityError("failure receipt artifact inventory digest is invalid")

    event_head = store.journal.verify_chain(run_id)
    event_hashes = {event.event_hash for event in store.journal.list_events(run_id)}
    if record.event_head_digest != GENESIS_HASH and record.event_head_digest not in event_hashes:
        raise IntegrityError("failure receipt event head is absent from the durable journal")
    if record.event_head_digest == GENESIS_HASH and event_head != GENESIS_HASH:
        raise IntegrityError("failure receipt claims genesis for a non-empty journal")

    artifact = ArtifactStore(artifact_root / "objects", clock=store.clock).put_bytes(
        content,
        media_type="application/json",
        metadata={"kind": "failure-receipt", "run_id": run_id},
    )
    stored_artifact = store.get_artifact(artifact.digest)
    if stored_artifact is None:
        store.create_artifact(artifact)
    elif (
        stored_artifact.size != artifact.size
        or stored_artifact.media_type != artifact.media_type
        or stored_artifact.relative_path != artifact.relative_path
    ):
        raise IntegrityError("registered failure receipt artifact metadata is inconsistent")

    case_id_raw = payload.get("case_id")
    case_id = case_id_raw if isinstance(case_id_raw, str) and case_id_raw else None
    receipt_id = _receipt_id(run_id)
    receipt = store.get_receipt(receipt_id)
    expected_canonical_digest = canonical_digest(payload)
    if receipt is None:
        store.create_receipt(
            Receipt(
                id=receipt_id,
                run_id=run_id,
                case_id=case_id,
                state=ReceiptState.INVALID,
                artifact_digest=artifact.digest,
                canonical_digest=expected_canonical_digest,
                event_head_digest=record.event_head_digest,
                manifest_digest=manifest_digest,
                created_at=record.occurred_at,
                metadata={
                    "kind": "failure",
                    "path": FAILURE_RECEIPT_NAME,
                    "status": record.status,
                    "error_type": record.error_type,
                    "message": record.message,
                    "stage": record.stage,
                    "occurred_at": record.occurred_at.isoformat(),
                    "receipt_sha256": record.receipt_digest,
                    "event_head_sequence": record.event_head_sequence,
                    "artifact_count": record.artifact_count,
                    "finalization_errors": record.finalization_errors,
                    "proof_scope": (),
                },
            )
        )
    elif (
        receipt.state != ReceiptState.INVALID
        or receipt.run_id != run_id
        or receipt.case_id != case_id
        or receipt.artifact_digest != artifact.digest
        or receipt.canonical_digest != expected_canonical_digest
        or receipt.event_head_digest != record.event_head_digest
        or receipt.manifest_digest != manifest_digest
    ):
        raise IntegrityError("durable failure receipt row is inconsistent with its files")
    return record


def recover_failure(
    store: Store,
    run_id: str,
    artifact_root: Path,
) -> DurableFailure | None:
    """Recover a sanitized reason from the receipt, receipt row, or failure event."""

    try:
        return load_failure_receipt(artifact_root, run_id=run_id)
    except (FileNotFoundError, IntegrityError, OSError, ValueError):
        pass

    for receipt in reversed(store.list_receipts(run_id)):
        if receipt.state != ReceiptState.INVALID or receipt.metadata.get("kind") != "failure":
            continue
        metadata = receipt.metadata
        occurred_raw = str(metadata.get("occurred_at", receipt.created_at.isoformat()))
        try:
            occurred_at = _parse_datetime(occurred_raw)
        except ValueError:
            occurred_at = receipt.created_at
        return DurableFailure(
            run_id=run_id,
            status=str(metadata.get("status", "FAILED")),
            error_type=str(metadata.get("error_type", "UnknownFailure")),
            message=str(metadata.get("message", "run failed without a recorded reason")),
            stage=str(metadata.get("stage", "UNKNOWN")),
            occurred_at=occurred_at,
            receipt_path=artifact_root / str(metadata.get("path", FAILURE_RECEIPT_NAME)),
            receipt_digest=str(metadata.get("receipt_sha256", receipt.canonical_digest)),
            event_head_digest=receipt.event_head_digest,
            event_head_sequence=int(metadata.get("event_head_sequence", 0)),
            artifact_count=int(metadata.get("artifact_count", 0)),
            finalization_errors=tuple(
                str(item) for item in metadata.get("finalization_errors", ())
            ),
        )

    for event in reversed(store.journal.list_events(run_id)):
        if event.kind != "run.failure_recorded":
            continue
        occurred_raw = str(event.payload.get("occurred_at", event.created_at.isoformat()))
        try:
            occurred_at = _parse_datetime(occurred_raw)
        except ValueError:
            occurred_at = event.created_at
        return DurableFailure(
            run_id=run_id,
            status=str(event.payload.get("status", "FAILED")),
            error_type=str(event.payload.get("error_type", "UnknownFailure")),
            message=str(event.payload.get("message", "run failed without a recorded reason")),
            stage=str(event.payload.get("stage", "UNKNOWN")),
            occurred_at=occurred_at,
            receipt_path=artifact_root / FAILURE_RECEIPT_NAME,
            receipt_digest="",
            event_head_digest=event.event_hash,
            event_head_sequence=event.sequence,
            artifact_count=0,
        )
    return None


def finalize_failed_run(
    *,
    store: Store,
    run_id: str,
    artifact_root: Path,
    error: BaseException,
) -> DurableFailure:
    """Persist a fail-closed terminal record without ever raising the source error."""

    root = artifact_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        on_disk = load_failure_receipt(root, run_id=run_id)
    except (FileNotFoundError, IntegrityError, OSError, ValueError):
        on_disk = None
    if on_disk is not None and _recorded_failure_is_terminal(store, run_id):
        return _reconcile_failure_receipt(store, run_id, root)

    run = store.get_run(run_id)
    if run is None:
        raise FailureFinalizationError(f"run {run_id} does not exist")
    requested_cancellation = isinstance(error, (asyncio.CancelledError, KeyboardInterrupt))
    cancelled = requested_cancellation or run.state == RunState.DECLARED
    status = RunState.CANCELLED if cancelled else RunState.FAILED
    agent_status = AgentState.CANCELLED if cancelled else AgentState.FAILED
    session_status = SessionState.CANCELLED if cancelled else SessionState.FAILED
    occurred_at = store.clock.utc_now()
    message = sanitize_failure_text(error)
    if requested_cancellation and (not message or message == "run cancelled"):
        message = "run cancelled before canonical completion"
    error_type = re.sub(r"[^A-Za-z0-9_.-]", "", type(error).__name__) or "UnknownFailure"
    stage = _failure_stage(store, run_id)
    errors: list[str] = []

    cases_before = {case.id: case.state.value for case in store.list_revocation_cases(run_id)}
    for case in store.list_revocation_cases(run_id):
        if case.state not in _TERMINAL_CASE_STATES:
            def escalate_case(case_id: str = case.id) -> object:
                return store.transition_revocation_case(
                    case_id,
                    RevocationCaseState.ESCALATED,
                    at=occurred_at,
                )

            _attempt(
                f"escalate revocation case {case.id}",
                escalate_case,
                errors,
            )
    for session in store.list_agent_sessions(run_id):
        if session.state in _ACTIVE_SESSION_STATES or (
            cancelled and session.state == SessionState.DECLARED
        ):
            def terminate_session(session_id: str = session.id) -> object:
                return store.transition_agent_session(
                    session_id,
                    session_status,
                    at=occurred_at,
                )

            _attempt(
                f"terminate agent session {session.id}",
                terminate_session,
                errors,
            )
    for agent in store.list_agents(run_id):
        if agent.state in _ACTIVE_AGENT_STATES or (
            cancelled and agent.state == AgentState.DECLARED
        ):
            def terminate_agent(agent_id: str = agent.id) -> object:
                return store.transition_agent(
                    agent_id,
                    agent_status,
                    at=occurred_at,
                )

            _attempt(
                f"terminate agent {agent.id}",
                terminate_agent,
                errors,
            )
    current_run = store.get_run(run_id)
    if current_run is not None and current_run.state not in _TERMINAL_RUN_STATES:
        _attempt(
            f"terminate run {run_id}",
            lambda: store.transition_run(run_id, status, at=occurred_at),
            errors,
        )

    failure_event = _attempt(
        "append failure event",
        lambda: store.journal.append(
            run_id=run_id,
            kind="run.failure_recorded",
            aggregate_type="run",
            aggregate_id=run_id,
            payload={
                "status": status.value,
                "error_type": error_type,
                "message": message,
                "stage": stage,
                "occurred_at": occurred_at,
                "summary": f"Run {status.value.lower()}: {message}",
            },
        ),
        errors,
    )
    verified_head = _attempt(
        "verify event chain",
        lambda: store.journal.verify_chain(run_id),
        errors,
    )
    head = store.journal.head(run_id)
    event_head_digest = (
        str(verified_head)
        if verified_head is not None
        else (head.event_hash if head is not None else GENESIS_HASH)
    )
    event_head_sequence = head.sequence if head is not None else 0
    if (
        failure_event is not None
        and head is not None
        and failure_event.event_hash != head.event_hash
    ):
        errors.append("failure event is not the durable event-chain head")

    inventory = _artifact_inventory(root)
    inventory_digest = canonical_digest(inventory)
    cases_after = {case.id: case.state.value for case in store.list_revocation_cases(run_id)}
    run_after = store.get_run(run_id)
    payload: dict[str, Any] = {
        "failure_receipt_version": FAILURE_RECEIPT_VERSION,
        "kind": _FAILURE_RECEIPT_KIND,
        "run_id": run_id,
        "case_id": next(reversed(cases_after), None),
        "receipt_state": ReceiptState.INVALID.value,
        "run_state": run_after.state.value if run_after is not None else status.value,
        "failure": {
            "status": status.value,
            "error_type": error_type,
            "message": message,
            "stage": stage,
            "occurred_at": occurred_at,
        },
        "revocation_cases": {
            "before": cases_before,
            "after": cases_after,
        },
        "agents": [
            {"id": agent.id, "state": agent.state.value}
            for agent in store.list_agents(run_id)
        ],
        "agent_sessions": [
            {"id": session.id, "agent_id": session.agent_id, "state": session.state.value}
            for session in store.list_agent_sessions(run_id)
        ],
        "event_chain": {
            "head_digest": event_head_digest,
            "head_sequence": event_head_sequence,
            "verified": verified_head is not None,
        },
        "artifact_inventory": {
            "digest": inventory_digest,
            "files": inventory,
            "excluded": [
                "state.sqlite and SQLite sidecars (mutable durable state)",
                "failure-receipt.json and failure-receipt.sha256 (self-reference)",
            ],
        },
        "finalization_errors": errors,
    }
    receipt_bytes = f"{canonical_json(payload)}\n".encode()
    receipt_digest = sha256_digest(receipt_bytes)
    receipt_path = root / FAILURE_RECEIPT_NAME
    _atomic_write(receipt_path, receipt_bytes)
    _atomic_write(root / FAILURE_RECEIPT_SHA_NAME, f"{receipt_digest}\n".encode("ascii"))
    try:
        return _reconcile_failure_receipt(store, run_id, root)
    except BaseException as exc:
        raise FailureFinalizationError(
            sanitize_failure_text(
                f"reconcile invalid receipt: {type(exc).__name__}: {exc}"
            )
        ) from exc


def finalize_without_masking(
    *,
    store: Store,
    run_id: str,
    artifact_root: Path,
    error: BaseException,
) -> tuple[DurableFailure | None, str | None]:
    """Run finalization behind an error boundary suitable for an active ``except``."""

    try:
        return (
            finalize_failed_run(
                store=store,
                run_id=run_id,
                artifact_root=artifact_root,
                error=error,
            ),
            None,
        )
    except BaseException as finalization_error:
        recovered = recover_failure(store, run_id, artifact_root)
        issue = sanitize_failure_text(
            f"{type(finalization_error).__name__}: {finalization_error}"
        )
        return recovered, issue
