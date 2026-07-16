from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    EffectState,
    LeaseState,
    PremiseState,
    RevocationCaseState,
)
from tars_revoke.errors import IntegrityError
from tars_revoke.persistence.store import Store

LIVE_REQUIREMENT_IDS = tuple(f"R-{index:02d}" for index in range(1, 18))
QUALIFICATION_TRUST_LIMITATION = (
    "Qualification artifacts are host-owner-generated and carry no external trusted witness."
)
CODEX_SIGNATURE_LIMITATION = (
    "The pinned OpenAI Codex binary exposed the expected publisher metadata, but "
    "the vendor desktop bundle did not pass strict local codesign verification."
)
CRASH_STAGES = (
    "OPEN",
    "FROZEN",
    "INVENTORIED",
    "COMPENSATING",
    "EXPERIMENTING",
    "REPAIRING",
    "VERIFYING",
    "RESUMED",
    "ATTESTED",
    "CLOSED",
    "ESCALATED",
)
FRESH_CLONE_STEPS = (
    "setup",
    "doctor",
    "python-tests",
    "web-tests",
    "build",
    "release-check",
)
_SETUP_ARGV = {
    "setup": ("make", "setup"),
    "doctor": ("make", "doctor"),
    "python-tests": ("make", "test-python-offline"),
    "web-tests": ("make", "test-web"),
    "build": ("make", "build"),
    "release-check": ("make", "release-check"),
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
_DIFF_RE = re.compile(r"^diff --git a/(.+) b/(.+)$", re.MULTILINE)
_CODEX_BUNDLE_IDENTIFIER = "com.openai.codex"
_CODEX_TEAM_IDENTIFIER = "2DC432GLL2"
_CODEX_BUNDLE_NAMES = {"ChatGPT.app", "Codex.app"}
_PINNED_CODEX_RELEASES = {
    "codex-cli 0.144.5": "bdcb530615d44fcc7b35d12fe00f30c3025c25fc22a21193591dcdb064304385",
}


def _desktop_codex_bundle(executable: Path) -> Path | None:
    """Return the containing official desktop-app shape without trusting its bytes."""
    if (
        not executable.is_absolute()
        or executable.name != "codex"
        or executable.parent.name != "Resources"
        or executable.parent.parent.name != "Contents"
    ):
        return None
    bundle = executable.parent.parent.parent
    return bundle if bundle.name in _CODEX_BUNDLE_NAMES else None


class BundleVerifier(Protocol):
    def __call__(
        self,
        artifact_root: str | Path,
        *,
        strict: bool = True,
        required_requirement_ids: Sequence[str] | None = None,
    ) -> Any: ...


@dataclass(frozen=True)
class LiveCodexProof:
    valid: bool
    repair_session_id: str
    session_ids: tuple[str, ...]
    manifest_paths: tuple[str, ...]


@dataclass(frozen=True)
class CrashRecoveryProof:
    valid: bool
    test_count: int
    stages: tuple[str, ...]
    source_digest: str


@dataclass(frozen=True)
class _CrashSnapshotProof:
    path: Path
    schema_version: int
    event_head: str
    event_count: int
    case_state: str
    action_state: str
    effect_state: str
    lease_state: str
    prepared_effect_sequences: tuple[int, ...]
    action_dispatch_sequences: tuple[int, ...]
    effect_dispatch_sequences: tuple[int, ...]
    lease_expired_sequences: tuple[int, ...]


@dataclass(frozen=True)
class RevokeBenchProof:
    valid: bool
    trial_count: int
    event_heads: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseRunsProof:
    valid: bool
    run_ids: tuple[str, str, str]
    receipt_digests: tuple[str, str, str]
    qualification: QualificationJournalProof


@dataclass(frozen=True)
class QualificationJournalProof:
    valid: bool
    source_commit: str
    source_tree_digest: str
    bundle_roots: tuple[Path, Path, Path]
    run_ids: tuple[str, str, str]
    receipt_file_digests: tuple[str, str, str]
    tars_revoke_executable: str
    tars_revoke_executable_sha256: str
    codex_executable: str
    codex_executable_sha256: str
    codex_executable_version: str
    codex_strict_signature_valid: bool
    source_repository: Path | None


def requirement_paths(
    root: Path,
    manifest: Mapping[str, Any],
    requirement_id: str,
) -> tuple[Path, ...]:
    requirements = manifest.get("requirements")
    if not isinstance(requirements, Mapping):
        raise IntegrityError("proof manifest requirements are missing")
    entries = requirements.get(requirement_id)
    if not isinstance(entries, list) or not entries:
        raise IntegrityError(f"proof missing for requirement {requirement_id}")
    paths: list[Path] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise IntegrityError(f"invalid proof entry for {requirement_id}")
        paths.append(_safe_file(root, entry.get("path"), label=requirement_id))
    if len(set(paths)) != len(paths):
        raise IntegrityError(f"duplicate proof paths for requirement {requirement_id}")
    return tuple(paths)


def verify_live_codex_repair(
    root: Path,
    receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> LiveCodexProof:
    r14_paths = requirement_paths(root, manifest, "R-14")
    manifest_paths = tuple(
        path
        for path in r14_paths
        if path.name == "manifest.json" and "agents/live-codex/sessions" in path.as_posix()
    )
    if not manifest_paths:
        raise IntegrityError("R-14 has no live Codex session manifests")

    sessions = [_verify_live_session(root, path) for path in manifest_paths]
    by_stage: dict[str, list[dict[str, Any]]] = {}
    for session in sessions:
        by_stage.setdefault(str(session["stage"]), []).append(session)

    initial = _only_stage(by_stage, "agent-a-initial-uuid")
    observability = _only_stage(by_stage, "agent-b-observability")
    analysis = _only_stage(by_stage, "agent-b-contradiction")
    repair = _only_stage(by_stage, "codex-bounded-repair")
    experiments = _ordered_experiment_sessions(by_stage)
    if not experiments:
        raise IntegrityError("R-14 has no Agent B experiment-proposal session")

    receipt_repair = receipt.get("repair")
    if not isinstance(receipt_repair, Mapping):
        raise IntegrityError("receipt repair proof is missing")
    if receipt_repair.get("live_codex") is not True:
        raise IntegrityError("R-14 rejects a repair not marked as live Codex")
    if receipt_repair.get("provider") != "live-codex":
        raise IntegrityError("R-14 rejects non-Codex repair providers")
    lineage = receipt_repair.get("live_session_lineage")
    if not isinstance(lineage, Mapping):
        raise IntegrityError("R-14 receipt session lineage is missing")
    expected_lineage = {
        "agent_a_initial": initial["thread_id"],
        "agent_b_observability": observability["thread_id"],
        "agent_b_analysis": analysis["thread_id"],
        "agent_b_experiments": experiments[-1]["thread_id"],
        "repair": repair["thread_id"],
    }
    if dict(lineage) != expected_lineage:
        raise IntegrityError("R-14 receipt lineage differs from live session artifacts")
    if analysis["thread_id"] != experiments[-1]["thread_id"]:
        raise IntegrityError("Agent B experiment proposal did not resume its analysis thread")
    if receipt_repair.get("session_id") != repair["thread_id"]:
        raise IntegrityError("repair session ID differs from the Codex repair manifest")
    if receipt_repair.get("response_ids") != repair["item_ids"]:
        raise IntegrityError("repair response lineage differs from raw Codex events")
    if receipt_repair.get("changed_paths") != repair["changed_paths"]:
        raise IntegrityError("receipt repair paths differ from the Codex workspace diff")
    if not repair["changed_paths"]:
        raise IntegrityError("R-14 repair made no workspace changes")
    independent_threads = {
        str(item["thread_id"]) for item in (initial, observability, analysis, repair)
    }
    if len(independent_threads) != 4:
        raise IntegrityError(
            "R-14 requires distinct initial, observability, analysis, and repair threads"
        )
    _verify_live_proposal_attempts(
        root,
        receipt,
        analysis_thread=str(analysis["thread_id"]),
        experiment_sessions=experiments,
    )
    fingerprints = {
        (
            str(session["executable"]),
            str(session["executable_version"]),
            str(session["executable_sha256"]),
        )
        for session in sessions
    }
    if len(fingerprints) != 1:
        raise IntegrityError("R-14 sessions did not use one qualified Codex executable")
    _verify_repair_commit(root, receipt, repair)

    proof_scope = receipt.get("proof_scope")
    if not isinstance(proof_scope, list) or "R-14" not in proof_scope:
        raise IntegrityError("receipt does not claim R-14")
    forbidden = ("scripted", "fake-codex", "deterministic-double")
    serialized = json.dumps(
        {
            "repair": receipt_repair,
            "sessions": sessions,
        },
        sort_keys=True,
    ).lower()
    if any(label in serialized for label in forbidden):
        raise IntegrityError("R-14 live proof contains a scripted-provider relabel")

    session_ids = tuple(str(item["thread_id"]) for item in sessions)
    return LiveCodexProof(
        valid=True,
        repair_session_id=str(repair["thread_id"]),
        session_ids=session_ids,
        manifest_paths=tuple(path.relative_to(root).as_posix() for path in manifest_paths),
    )


def _verify_live_proposal_attempts(
    root: Path,
    receipt: Mapping[str, Any],
    *,
    analysis_thread: str,
    experiment_sessions: Sequence[Mapping[str, Any]],
) -> None:
    experiment = receipt.get("experiment")
    if not isinstance(experiment, Mapping):
        raise IntegrityError("R-14 experiment receipt is missing")
    attempts = experiment.get("live_proposal_attempts")
    if not isinstance(attempts, list) or not attempts:
        raise IntegrityError("R-14 live proposal attempts are missing or empty")
    if len(attempts) > 3:
        raise IntegrityError("R-14 live proposal correction bound exceeds three attempts")
    if len(attempts) != len(experiment_sessions):
        raise IntegrityError("R-14 proposal attempts differ from live session manifests")
    validation_errors: list[str] = []
    sessions_by_manifest = {
        str(session["manifest_path"]): session for session in experiment_sessions
    }
    seen_manifests: set[str] = set()
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, Mapping):
            raise IntegrityError("R-14 proposal attempt is malformed")
        expected_stage = (
            "agent-b-experiments"
            if index == 0
            else f"agent-b-experiments-correction-{index}"
        )
        if attempt.get("attempt_index") != index or attempt.get("stage") != expected_stage:
            raise IntegrityError("R-14 proposal attempt sequence is malformed")
        manifest_path = _artifact_reference(
            root,
            attempt.get("manifest_path"),
            label="manifest_path",
        )
        manifest_relative = manifest_path.relative_to(root).as_posix()
        session = sessions_by_manifest.get(manifest_relative)
        if session is None or manifest_relative in seen_manifests:
            raise IntegrityError("R-14 proposal attempt is not bound to one live session")
        seen_manifests.add(manifest_relative)
        if (
            attempt.get("thread_id") != analysis_thread
            or attempt.get("session_id") != analysis_thread
            or session.get("thread_id") != analysis_thread
        ):
            raise IntegrityError("R-14 proposal attempt did not resume Agent B's thread")
        bindings = (
            ("manifest_path", "manifest_digest", "manifest_path"),
            ("events_path", "events_sha256", None),
            ("event_observations_path", "event_observations_sha256", None),
        )
        for path_key, digest_key, session_key in bindings:
            path = _artifact_reference(root, attempt.get(path_key), label=path_key)
            digest = attempt.get(digest_key)
            if not isinstance(digest, str) or not hmac.compare_digest(
                sha256_digest(path.read_bytes()), digest
            ):
                raise IntegrityError(f"R-14 proposal {path_key} digest changed")
            if session_key is not None and path.relative_to(root).as_posix() != session.get(
                session_key
            ):
                raise IntegrityError("R-14 proposal manifest path differs from its session")
        error = attempt.get("validation_error")
        is_final = index == len(attempts) - 1
        if is_final and error is not None:
            raise IntegrityError("R-14 final successful proposal still has a validation error")
        if not is_final and (not isinstance(error, str) or not error):
            raise IntegrityError("R-14 correction attempt lacks its triggering validation error")
        if isinstance(error, str):
            validation_errors.append(error)
    claimed_errors = experiment.get("live_proposal_validation_errors")
    if claimed_errors != validation_errors:
        raise IntegrityError("R-14 proposal validation errors differ from attempt evidence")


def _artifact_reference(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise IntegrityError(f"R-14 {label} is missing")
    raw = Path(value).expanduser()
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    resolved_root = root.resolve()
    if path == resolved_root or resolved_root not in path.parents:
        raise IntegrityError(f"R-14 {label} escapes the artifact root")
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"R-14 {label} is missing or unsafe")
    return path


def _verify_live_session(root: Path, manifest_path: Path) -> dict[str, Any]:
    session_root = manifest_path.parent
    payload = _load_object(manifest_path)
    if payload.get("protocol") != "tars.live-codex/v1":
        raise IntegrityError("R-14 session does not use the live Codex protocol")
    for field in (
        "stage",
        "thread_id",
        "process_id",
        "executable",
        "executable_version",
        "executable_sha256",
        "worktree",
        "before_head",
        "after_head",
    ):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise IntegrityError(f"R-14 live session is missing {field}")
    if not str(payload["executable_version"]).startswith("codex-cli "):
        raise IntegrityError("R-14 session executable is not Codex CLI")
    executable = Path(str(payload["executable"])).expanduser()
    if _desktop_codex_bundle(executable) is None:
        raise IntegrityError("R-14 session did not use an official Codex application binary")
    executable_sha256 = payload["executable_sha256"]
    if not isinstance(executable_sha256, str) or not _SHA256_RE.fullmatch(executable_sha256):
        raise IntegrityError("R-14 Codex executable digest is malformed")
    read_only_stage = payload["stage"] == "agent-b-contradiction" or str(
        payload["stage"]
    ).startswith("agent-b-experiments")
    expected_sandbox = "read-only" if read_only_stage else "workspace-write"
    if payload.get("sandbox") != expected_sandbox:
        raise IntegrityError("R-14 session used the wrong Codex sandbox for its stage")

    files = payload.get("files")
    if not isinstance(files, Mapping):
        raise IntegrityError("R-14 session file manifest is missing")
    required_files = {
        "changed-paths.json",
        "events.jsonl",
        "last-message.txt",
        "stderr.log",
        "stdout.log",
        "workspace.diff",
    }
    if not required_files.issubset(files):
        raise IntegrityError("R-14 session file manifest is incomplete")
    for name, descriptor in files.items():
        _verify_session_file(session_root, name, descriptor)

    digest_path = session_root / "manifest.sha256"
    if not digest_path.is_file() or digest_path.is_symlink():
        raise IntegrityError("R-14 session manifest digest is missing")
    expected_manifest_digest = digest_path.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(expected_manifest_digest, sha256_digest(manifest_path.read_bytes())):
        raise IntegrityError("R-14 session manifest digest changed")

    changed_paths = _string_sequence(payload.get("changed_paths"), "Codex changed paths")
    recorded_paths = _load_string_array(session_root / "changed-paths.json")
    if changed_paths != recorded_paths or len(set(changed_paths)) != len(changed_paths):
        raise IntegrityError("R-14 changed path evidence is inconsistent")
    for changed_path in changed_paths:
        _safe_relative_text(changed_path, "Codex changed path")

    events = _load_jsonl(session_root / "events.jsonl")
    event_types = [event.get("type") for event in events]
    if event_types.count("thread.started") != 1 or event_types.count("turn.completed") < 1:
        raise IntegrityError("R-14 JSONL is not a completed live Codex turn")
    started = next(event for event in events if event.get("type") == "thread.started")
    if started.get("thread_id") != payload["thread_id"]:
        raise IntegrityError("R-14 thread ID differs from raw Codex JSONL")
    item_ids = tuple(
        str(item["item"]["id"])
        for item in events
        if item.get("type") == "item.completed"
        and isinstance(item.get("item"), Mapping)
        and isinstance(item["item"].get("id"), str)
    )
    manifest_items = _string_sequence(payload.get("item_ids"), "Codex item IDs")
    if item_ids != manifest_items:
        raise IntegrityError("R-14 item lineage differs from raw Codex JSONL")

    diff_text = (session_root / "workspace.diff").read_text(encoding="utf-8")
    diff_paths = tuple(match[0] for match in _DIFF_RE.findall(diff_text) if match[0] == match[1])
    if changed_paths and set(diff_paths) != set(changed_paths):
        raise IntegrityError("R-14 workspace diff differs from changed-paths evidence")
    if not changed_paths and diff_text:
        raise IntegrityError("R-14 session claims no changes but has a workspace diff")

    schema_digest = payload.get("output_schema_digest")
    if not isinstance(schema_digest, str) or not _SHA256_RE.fullmatch(schema_digest):
        raise IntegrityError("R-14 output schema digest is malformed")
    schema_path = root / "agents" / "live-codex" / f"output-schema-{schema_digest}.json"
    if not schema_path.is_file() or schema_path.is_symlink():
        raise IntegrityError("R-14 output schema artifact is missing")
    if not hmac.compare_digest(sha256_digest(schema_path.read_bytes()), schema_digest):
        raise IntegrityError("R-14 output schema digest changed")
    _verify_supervisor_argv(root, payload, schema_path=schema_path)

    return {
        "stage": payload["stage"],
        "thread_id": payload["thread_id"],
        "process_id": payload["process_id"],
        "changed_paths": list(changed_paths),
        "item_ids": list(item_ids),
        "manifest_path": manifest_path.relative_to(root).as_posix(),
        "executable": payload["executable"],
        "executable_version": payload["executable_version"],
        "executable_sha256": payload["executable_sha256"],
        "worktree": payload["worktree"],
        "before_head": payload["before_head"],
        "after_head": payload["after_head"],
    }


def _verify_session_file(session_root: Path, name: object, descriptor: object) -> None:
    if not isinstance(name, str) or not isinstance(descriptor, Mapping):
        raise IntegrityError("R-14 session file descriptor is malformed")
    if descriptor.get("path") != name or set(descriptor) != {"path", "sha256", "size"}:
        raise IntegrityError("R-14 session file descriptor has unexpected fields")
    path = _safe_file(session_root, name, label="R-14 session")
    content = path.read_bytes()
    if descriptor.get("size") != len(content):
        raise IntegrityError("R-14 session file size changed")
    digest = descriptor.get("sha256")
    if not isinstance(digest, str) or not hmac.compare_digest(sha256_digest(content), digest):
        raise IntegrityError("R-14 session file digest changed")


def _verify_supervisor_argv(
    root: Path,
    payload: Mapping[str, Any],
    *,
    schema_path: Path,
) -> None:
    argv = _string_sequence(payload.get("supervisor_argv"), "Codex supervisor argv")
    executable = str(payload["executable"])
    sandbox = str(payload["sandbox"])
    thread_id = str(payload["thread_id"])
    stage = str(payload["stage"])
    resumed = stage.startswith("agent-b-experiments")
    prefix: tuple[str, ...]
    if resumed:
        prefix = (
            executable,
            "exec",
            "resume",
            "--ignore-user-config",
            "--json",
            "-c",
            f'sandbox_mode="{sandbox}"',
        )
    else:
        prefix = (
            executable,
            "exec",
            "--ignore-user-config",
            "--json",
            "--color",
            "never",
            "--sandbox",
            sandbox,
            "--cd",
            str(payload["worktree"]),
        )
    if argv[: len(prefix)] != prefix:
        raise IntegrityError("R-14 supervisor argv is not the authorized Codex exec shape")
    tail = list(argv[len(prefix) :])
    if tail[:1] == ["--model"]:
        if len(tail) < 2 or not tail[1]:
            raise IntegrityError("R-14 supervisor model argv is malformed")
        tail = tail[2:]
    if len(tail) < 5 or tail[0] != "--output-schema":
        raise IntegrityError("R-14 supervisor argv omits its output schema")
    argv_schema = Path(tail[1]).expanduser().resolve()
    if argv_schema != schema_path.resolve():
        raise IntegrityError("R-14 supervisor output schema differs from its artifact")
    if tail[2] != "--output-last-message":
        raise IntegrityError("R-14 supervisor argv omits its last-message sink")
    last_message = Path(tail[3]).expanduser().resolve()
    live_root = (root / "agents" / "live-codex").resolve()
    if live_root not in last_message.parents or not last_message.name.startswith("codex-last-"):
        raise IntegrityError("R-14 supervisor last-message path escapes live artifacts")
    expected_suffix = [thread_id, "-"] if resumed else ["-"]
    if tail[4:] != expected_suffix:
        raise IntegrityError("R-14 supervisor argv has unexpected trailing arguments")


def _verify_repair_commit(
    root: Path,
    receipt: Mapping[str, Any],
    repair_session: Mapping[str, Any],
) -> None:
    quarantine = receipt.get("quarantine")
    repair = receipt.get("repair")
    if not isinstance(quarantine, Mapping) or not isinstance(repair, Mapping):
        raise IntegrityError("R-14 Git repair receipt sections are missing")
    repository = _artifact_repository(root, quarantine.get("repository"))
    repaired_commit = _required_text(repair.get("repaired_commit"), "repaired commit")
    before_head = _required_text(repair_session.get("before_head"), "repair base commit")
    after_head = _required_text(repair_session.get("after_head"), "repair after head")
    if before_head != after_head:
        raise IntegrityError("R-14 Codex session committed instead of producing a bounded diff")
    resolved = _git_text(repository, "rev-parse", f"{repaired_commit}^{{commit}}")
    if resolved != repaired_commit:
        raise IntegrityError("R-14 repaired commit is absent from the portable repository")
    parents = _git_text(repository, "show", "-s", "--format=%P", repaired_commit).split()
    if parents != [before_head]:
        raise IntegrityError("R-14 repaired commit does not descend from the recorded repair base")
    expected_tree = _git_text(repository, "show", "-s", "--format=%T", repaired_commit)
    changed_paths = tuple(
        line
        for line in _git_text(
            repository,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            repaired_commit,
        ).splitlines()
        if line
    )
    recorded_paths = _string_sequence(repair_session.get("changed_paths"), "repair paths")
    if set(changed_paths) != set(recorded_paths):
        raise IntegrityError("R-14 repaired commit paths differ from the Codex session")
    manifest_relative = _required_text(repair_session.get("manifest_path"), "repair manifest")
    diff_path = root / Path(manifest_relative).parent / "workspace.diff"
    actual_tree = _tree_after_applying_diff(
        repository,
        base_commit=before_head,
        diff_path=diff_path,
    )
    if actual_tree != expected_tree:
        raise IntegrityError("R-14 workspace diff does not reproduce the repaired commit tree")


def _artifact_repository(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise IntegrityError("R-14 repair repository path is missing")
    raw = Path(value).expanduser()
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    if not raw.is_absolute() and (path == root or root not in path.parents):
        raise IntegrityError("R-14 repair repository escapes the artifact root")
    if not path.is_dir() or path.is_symlink():
        raise IntegrityError("R-14 repair repository is missing or unsafe")
    return path


def _tree_after_applying_diff(
    repository: Path,
    *,
    base_commit: str,
    diff_path: Path,
) -> str:
    if not diff_path.is_file() or diff_path.is_symlink():
        raise IntegrityError("R-14 repair diff is missing or unsafe")
    descriptor, index_name = tempfile.mkstemp(prefix="tars-r14-index-")
    os.close(descriptor)
    Path(index_name).unlink()
    environment = {**os.environ, "GIT_INDEX_FILE": index_name}
    try:
        _git_text(repository, "read-tree", base_commit, env=environment)
        _git_text(
            repository,
            "apply",
            "--cached",
            "--whitespace=nowarn",
            str(diff_path),
            env=environment,
        )
        return _git_text(repository, "write-tree", env=environment)
    finally:
        Path(index_name).unlink(missing_ok=True)


def _git_text(
    repository: Path,
    *args: str,
    env: Mapping[str, str] | None = None,
) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(env) if env is not None else None,
    )
    if result.returncode != 0:
        raise IntegrityError(
            f"R-14 Git semantic proof failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def verify_crash_recovery(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    expected_source_commit: str | None = None,
    source_repository: Path | None = None,
) -> CrashRecoveryProof:
    paths = requirement_paths(root, manifest, "R-18")
    if len(paths) != 35:
        raise IntegrityError("R-18 requires report, producer source, and 33 SQLite snapshots")
    reports = [path for path in paths if path.name == "report.json"]
    if len(reports) != 1:
        raise IntegrityError("R-18 requires exactly one CrashBench report")
    report_path = reports[0]
    report = _load_object(report_path)
    if set(report) != {
        "protocol",
        "schema_version",
        "suite",
        "stage_count",
        "generated_at",
        "passed",
        "artifact_root",
        "report_path",
        "producer",
        "methodology",
        "stages",
        "report_digest",
    }:
        raise IntegrityError("R-18 CrashBench report has unexpected fields")
    unsigned = dict(report)
    report_digest = unsigned.pop("report_digest")
    if report_digest != canonical_digest(unsigned):
        raise IntegrityError("R-18 CrashBench report self-digest changed")
    if (
        report.get("protocol") != "tars.crashbench.report/v1"
        or report.get("schema_version") != 1
        or report.get("suite") != "CrashBench-11"
        or report.get("stage_count") != 11
        or report.get("passed") is not True
    ):
        raise IntegrityError("R-18 report is not a passing CrashBench-11 run")
    _aware_datetime(report.get("generated_at"), "CrashBench generated_at")
    _verify_crash_report_locations(report_path, report)
    source_digest = _verify_crashbench_producer(
        report_path,
        paths,
        report,
        expected_source_commit=expected_source_commit,
        source_repository=source_repository,
    )
    _verify_crashbench_methodology(report)
    stages = report.get("stages")
    if not isinstance(stages, list) or len(stages) != len(CRASH_STAGES):
        raise IntegrityError("R-18 report does not contain exactly 11 stage records")
    expected_paths = {report_path, report_path.parent / "producer/source/crashbench.py"}
    for index, (stage_name, stage) in enumerate(zip(CRASH_STAGES, stages, strict=True)):
        if not isinstance(stage, Mapping):
            raise IntegrityError("R-18 stage record is malformed")
        expected_paths.update(
            _verify_crashbench_stage(
                report_path.parent,
                stage,
                stage_index=index,
                stage_name=stage_name,
            )
        )
    if set(paths) != {path.resolve() for path in expected_paths}:
        raise IntegrityError("R-18 manifest contains an omitted or unexpected CrashBench artifact")
    return CrashRecoveryProof(True, 11, CRASH_STAGES, source_digest)


def _verify_crash_report_locations(
    report_path: Path,
    report: Mapping[str, Any],
) -> None:
    artifact_root = report.get("artifact_root")
    recorded_report = report.get("report_path")
    if not isinstance(artifact_root, str) or not isinstance(recorded_report, str):
        raise IntegrityError("R-18 report locations are malformed")
    resolved_root = (
        report_path.parent.resolve()
        if artifact_root == "."
        else Path(artifact_root).expanduser().resolve()
    )
    resolved_report = (
        (report_path.parent / recorded_report).resolve()
        if not Path(recorded_report).is_absolute()
        else Path(recorded_report).expanduser().resolve()
    )
    if resolved_root != report_path.parent.resolve() or resolved_report != report_path.resolve():
        raise IntegrityError("R-18 report location binding changed")


def _verify_crashbench_producer(
    report_path: Path,
    proof_paths: Sequence[Path],
    report: Mapping[str, Any],
    *,
    expected_source_commit: str | None,
    source_repository: Path | None,
) -> str:
    producer = report.get("producer")
    if not isinstance(producer, Mapping) or set(producer) != {
        "protocol",
        "entrypoint",
        "command",
        "source",
    }:
        raise IntegrityError("R-18 CrashBench producer binding is malformed")
    if (
        producer.get("protocol") != "tars.crashbench.producer/v1"
        or producer.get("entrypoint")
        != "tars_revoke.demo.crashbench:run_crashbench_suite"
    ):
        raise IntegrityError("R-18 CrashBench producer identity is unsupported")
    command = producer.get("command")
    if not isinstance(command, Mapping) or set(command) != {
        "observed_argv",
        "observed_argv_sha256",
        "canonical_argv",
    }:
        raise IntegrityError("R-18 CrashBench command binding is malformed")
    observed = command.get("observed_argv")
    if not isinstance(observed, list) or not observed or any(
        not isinstance(item, str) for item in observed
    ):
        raise IntegrityError("R-18 observed CrashBench argv is malformed")
    if command.get("observed_argv_sha256") != canonical_digest(observed):
        raise IntegrityError("R-18 observed CrashBench argv digest changed")
    if command.get("canonical_argv") != [
        "tars-revoke",
        "bench",
        "--suite",
        "CrashBench-11",
        "--output-root",
        "<OUTPUT_ROOT>",
    ]:
        raise IntegrityError("R-18 canonical CrashBench argv is incorrect")
    source = producer.get("source")
    if not isinstance(source, Mapping) or set(source) != {
        "path",
        "artifact_path",
        "sha256",
        "size",
        "source_commit",
        "source_tree",
        "committed_blob_oid",
        "committed_sha256",
        "matches_committed_source",
        "worktree_clean",
        "worktree_status_sha256",
    }:
        raise IntegrityError("R-18 CrashBench source binding is malformed")
    if (
        source.get("path") != "src/tars_revoke/demo/crashbench.py"
        or source.get("artifact_path") != "producer/source/crashbench.py"
    ):
        raise IntegrityError("R-18 CrashBench source paths are not canonical")
    source_path = (report_path.parent / "producer/source/crashbench.py").resolve()
    if source_path not in proof_paths or not source_path.is_file():
        raise IntegrityError("R-18 CrashBench source is not bound by the manifest")
    source_bytes = source_path.read_bytes()
    source_digest = sha256_digest(source_bytes)
    if source.get("size") != len(source_bytes) or source.get("sha256") != source_digest:
        raise IntegrityError("R-18 CrashBench source artifact changed")
    if (expected_source_commit is None) != (source_repository is None):
        raise IntegrityError("R-18 qualified source context is incomplete")
    if expected_source_commit is None:
        return source_digest
    if (
        source.get("source_commit") != expected_source_commit
        or source.get("matches_committed_source") is not True
        or source.get("worktree_clean") is not True
        or source.get("worktree_status_sha256") != sha256_digest(b"")
        or source.get("committed_sha256") != source_digest
    ):
        raise IntegrityError("R-18 CrashBench did not run from the qualified clean source")
    assert source_repository is not None
    qualified_path = "src/tars_revoke/demo/crashbench.py"
    committed = _git_bytes(
        source_repository,
        "show",
        f"{expected_source_commit}:{qualified_path}",
    )
    tree = _git_bytes(
        source_repository,
        "rev-parse",
        f"{expected_source_commit}^{{tree}}",
    ).decode("ascii").strip()
    blob = _git_bytes(
        source_repository,
        "rev-parse",
        f"{expected_source_commit}:{qualified_path}",
    ).decode("ascii").strip()
    if (
        committed != source_bytes
        or source.get("source_tree") != tree
        or source.get("committed_blob_oid") != blob
    ):
        raise IntegrityError("R-18 CrashBench source differs from the qualified Git blob")
    return source_digest


def _verify_crashbench_methodology(report: Mapping[str, Any]) -> None:
    methodology = report.get("methodology")
    expected = {
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
        "stage_order": list(CRASH_STAGES),
        "receipt_rebuild_stages": ["ATTESTED", "CLOSED", "ESCALATED"],
        "closed_stage_has_no_incomplete_case": True,
    }
    if not isinstance(methodology, Mapping) or dict(methodology) != expected:
        raise IntegrityError("R-18 CrashBench methodology differs from its protocol")


def _verify_crashbench_stage(
    report_root: Path,
    stage: Mapping[str, Any],
    *,
    stage_index: int,
    stage_name: str,
) -> set[Path]:
    if set(stage) != {
        "stage_index",
        "stage",
        "run_id",
        "case_id",
        "entities",
        "snapshots",
        "recovery",
        "invariants",
        "passed",
    }:
        raise IntegrityError("R-18 CrashBench stage has unexpected fields")
    slug = f"{stage_index:02d}-{stage_name.lower()}"
    run_id = f"run-crashbench-{slug}"
    case_id = f"case-crashbench-{slug}"
    if (
        stage.get("stage_index") != stage_index
        or stage.get("stage") != stage_name
        or stage.get("run_id") != run_id
        or stage.get("case_id") != case_id
        or stage.get("passed") is not True
    ):
        raise IntegrityError("R-18 CrashBench stage identity is invalid")
    entities = stage.get("entities")
    if not isinstance(entities, Mapping) or set(entities) != {
        "dispatch_action_id",
        "dispatch_effect_id",
        "orphan_lease_id",
        "compensation_effect_ids",
    }:
        raise IntegrityError("R-18 CrashBench stage entities are malformed")
    action_id = f"action-dispatch-{slug}"
    effect_id = f"effect-dispatch-{slug}"
    compensation_ids = (
        f"effect-compensation-pending-{slug}",
        f"effect-compensation-revoked-{slug}",
    )
    lease_id = entities.get("orphan_lease_id")
    if (
        entities.get("dispatch_action_id") != action_id
        or entities.get("dispatch_effect_id") != effect_id
        or entities.get("compensation_effect_ids") != list(compensation_ids)
        or not isinstance(lease_id, str)
        or not lease_id
    ):
        raise IntegrityError("R-18 CrashBench entity lineage is invalid")
    snapshots = stage.get("snapshots")
    if not isinstance(snapshots, Mapping) or set(snapshots) != {
        "pre_restart",
        "after_first_recovery",
        "after_second_recovery",
    }:
        raise IntegrityError("R-18 CrashBench snapshots are malformed")
    phases = (
        ("pre_restart", "pre-restart.sqlite3"),
        ("after_first_recovery", "after-first-recovery.sqlite3"),
        ("after_second_recovery", "after-second-recovery.sqlite3"),
    )
    observations: dict[str, _CrashSnapshotProof] = {}
    for phase, filename in phases:
        snapshot = snapshots.get(phase)
        if not isinstance(snapshot, Mapping):
            raise IntegrityError("R-18 CrashBench snapshot record is malformed")
        observations[phase] = _verify_crashbench_snapshot(
            report_root,
            snapshot,
            expected_path=f"stages/{slug}/{filename}",
            run_id=run_id,
            case_id=case_id,
            stage_name=stage_name,
            action_id=action_id,
            effect_id=effect_id,
            lease_id=lease_id,
            compensation_ids=compensation_ids,
        )
    _verify_crashbench_recovery(
        stage,
        stage_name=stage_name,
        slug=slug,
        run_id=run_id,
        case_id=case_id,
        action_id=action_id,
        effect_id=effect_id,
        compensation_ids=compensation_ids,
        observations=observations,
    )
    return {item.path for item in observations.values()}


def _verify_crashbench_snapshot(
    report_root: Path,
    snapshot: Mapping[str, Any],
    *,
    expected_path: str,
    run_id: str,
    case_id: str,
    stage_name: str,
    action_id: str,
    effect_id: str,
    lease_id: str,
    compensation_ids: tuple[str, str],
) -> _CrashSnapshotProof:
    if set(snapshot) != {"path", "sha256", "size", "event_head", "event_count"}:
        raise IntegrityError("R-18 CrashBench snapshot binding has unexpected fields")
    if snapshot.get("path") != expected_path:
        raise IntegrityError("R-18 CrashBench snapshot path is not canonical")
    path = _safe_file(report_root, expected_path, label="R-18 CrashBench snapshot")
    content = path.read_bytes()
    if snapshot.get("size") != len(content) or snapshot.get("sha256") != sha256_digest(
        content
    ):
        raise IntegrityError("R-18 CrashBench snapshot bytes changed")
    with tempfile.TemporaryDirectory(prefix="tars-r18-verify-") as temporary:
        verification_path = Path(temporary) / "snapshot.sqlite3"
        verification_path.write_bytes(content)
        return _verify_crashbench_snapshot_database(
            path,
            verification_path,
            snapshot=snapshot,
            run_id=run_id,
            case_id=case_id,
            stage_name=stage_name,
            action_id=action_id,
            effect_id=effect_id,
            lease_id=lease_id,
            compensation_ids=compensation_ids,
        )


def _verify_crashbench_snapshot_database(
    evidence_path: Path,
    database_path: Path,
    *,
    snapshot: Mapping[str, Any],
    run_id: str,
    case_id: str,
    stage_name: str,
    action_id: str,
    effect_id: str,
    lease_id: str,
    compensation_ids: tuple[str, str],
) -> _CrashSnapshotProof:
    store = Store(database_path)
    store.database.integrity_check()
    events = store.journal.list_events(run_id)
    event_head = store.journal.verify_chain(run_id)
    if snapshot.get("event_count") != len(events) or snapshot.get("event_head") != event_head:
        raise IntegrityError("R-18 CrashBench snapshot journal binding changed")
    case = store.get_revocation_case(case_id)
    action = store.get_action(action_id)
    effect = store.get_effect(effect_id)
    lease = store.get_lease(lease_id)
    if (
        case is None
        or case.run_id != run_id
        or case.state.value != stage_name
        or action is None
        or effect is None
        or lease is None
    ):
        raise IntegrityError("R-18 CrashBench snapshot entities are missing")
    compensation = [store.get_effect(effect_id_) for effect_id_ in compensation_ids]
    if (
        any(item is None for item in compensation)
        or compensation[0].state != EffectState.REVOKE_PENDING  # type: ignore[union-attr]
        or compensation[1].state != EffectState.REVOKED  # type: ignore[union-attr]
    ):
        raise IntegrityError("R-18 CrashBench compensation obligations changed")
    return _CrashSnapshotProof(
        path=evidence_path,
        schema_version=store.database.schema_version(),
        event_head=event_head,
        event_count=len(events),
        case_state=case.state.value,
        action_state=action.state.value,
        effect_state=effect.state.value,
        lease_state=lease.state.value,
        prepared_effect_sequences=_crash_event_sequences(
            events,
            aggregate_type="effect",
            aggregate_id=effect_id,
            kind="effect.created",
            payload_key="state",
            target=EffectState.PREPARED.value,
        ),
        action_dispatch_sequences=_crash_event_sequences(
            events,
            aggregate_type="action",
            aggregate_id=action_id,
            kind="action.transitioned",
            payload_key="to",
            target=ActionState.DISPATCHING.value,
        ),
        effect_dispatch_sequences=_crash_event_sequences(
            events,
            aggregate_type="effect",
            aggregate_id=effect_id,
            kind="effect.transitioned",
            payload_key="to",
            target=EffectState.DISPATCHING.value,
        ),
        lease_expired_sequences=_crash_event_sequences(
            events,
            aggregate_type="lease",
            aggregate_id=lease_id,
            kind="lease.transitioned",
            payload_key="to",
            target=LeaseState.EXPIRED.value,
        ),
    )


def _crash_event_sequences(
    events: Sequence[Any],
    *,
    aggregate_type: str,
    aggregate_id: str,
    kind: str,
    payload_key: str,
    target: str,
) -> tuple[int, ...]:
    return tuple(
        event.sequence
        for event in events
        if event.aggregate_type == aggregate_type
        and event.aggregate_id == aggregate_id
        and event.kind == kind
        and event.payload.get(payload_key) == target
    )


def _verify_crashbench_recovery(
    stage: Mapping[str, Any],
    *,
    stage_name: str,
    slug: str,
    run_id: str,
    case_id: str,
    action_id: str,
    effect_id: str,
    compensation_ids: tuple[str, str],
    observations: Mapping[str, _CrashSnapshotProof],
) -> None:
    recovery = stage.get("recovery")
    if not isinstance(recovery, Mapping) or set(recovery) != {"first", "second"}:
        raise IntegrityError("R-18 CrashBench recovery records are malformed")
    pre = observations["pre_restart"]
    first_snapshot = observations["after_first_recovery"]
    second_snapshot = observations["after_second_recovery"]
    expected_incomplete = [] if stage_name == RevocationCaseState.CLOSED.value else [case_id]
    expected_rebuild = (
        [case_id]
        if stage_name
        in {
            RevocationCaseState.ATTESTED.value,
            RevocationCaseState.CLOSED.value,
            RevocationCaseState.ESCALATED.value,
        }
        else []
    )
    reconciliation = {
        "action_id": action_id,
        "effect_id": effect_id,
        "effect_type": "PUSH",
        "target": f"target-dispatch-{slug}",
        "idempotency_key": f"effect-key-dispatch-{slug}",
        "metadata": {
            "adapter_idempotency_key": f"adapter-dispatch-{slug}",
            "reconciliation_policy": "observe-never-replay",
        },
    }
    recovery_fields = {
        "schema_version",
        "event_head_digest",
        "expired_lease_count",
        "dispatching_action_ids",
        "dispatching_effect_ids",
        "dispatch_reconciliations",
        "incomplete_case_ids",
        "compensation_effect_ids",
        "receipt_rebuild_case_ids",
    }
    expected_common = {
        "schema_version": first_snapshot.schema_version,
        "dispatching_action_ids": [action_id],
        "dispatching_effect_ids": [effect_id],
        "dispatch_reconciliations": [reconciliation],
        "incomplete_case_ids": expected_incomplete,
        "compensation_effect_ids": sorted(compensation_ids),
        "receipt_rebuild_case_ids": expected_rebuild,
    }
    first = recovery.get("first")
    second = recovery.get("second")
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        raise IntegrityError("R-18 CrashBench recovery record is missing")
    if set(first) != recovery_fields or set(second) != recovery_fields:
        raise IntegrityError("R-18 CrashBench recovery record has unexpected fields")
    if dict(first) != {
        **expected_common,
        "event_head_digest": first_snapshot.event_head,
        "expired_lease_count": 1,
    } or dict(second) != {
        **expected_common,
        "event_head_digest": second_snapshot.event_head,
        "expired_lease_count": 0,
    }:
        raise IntegrityError("R-18 CrashBench recovery claims differ from durable snapshots")
    byte_identical = first_snapshot.path.read_bytes() == second_snapshot.path.read_bytes()
    semantic_invariants = {
        "effect_intent_prepared_before_dispatch": (
            len(pre.prepared_effect_sequences) == 1
            and len(pre.action_dispatch_sequences) == 1
            and len(pre.effect_dispatch_sequences) == 1
            and pre.prepared_effect_sequences[0]
            < min(pre.action_dispatch_sequences[0], pre.effect_dispatch_sequences[0])
        ),
        "pre_restart_single_action_dispatch_transition": len(
            pre.action_dispatch_sequences
        )
        == 1,
        "pre_restart_single_effect_dispatch_transition": len(
            pre.effect_dispatch_sequences
        )
        == 1,
        "first_recovery_expired_orphan_once": (
            pre.lease_state == LeaseState.ACTIVE.value
            and first_snapshot.lease_state == LeaseState.EXPIRED.value
            and pre.lease_expired_sequences == ()
            and len(first_snapshot.lease_expired_sequences) == 1
            and first_snapshot.event_count == pre.event_count + 1
        ),
        "first_recovery_single_dispatch_reconciliation": len(
            first["dispatch_reconciliations"]
        )
        == 1,
        "second_recovery_expired_none": (
            second_snapshot.lease_state == LeaseState.EXPIRED.value
            and second_snapshot.lease_expired_sequences
            == first_snapshot.lease_expired_sequences
        ),
        "second_recovery_no_new_event": second_snapshot.event_count
        == first_snapshot.event_count,
        "second_recovery_no_dispatch_retry": (
            first_snapshot.action_dispatch_sequences == pre.action_dispatch_sequences
            and second_snapshot.action_dispatch_sequences == pre.action_dispatch_sequences
            and first_snapshot.effect_dispatch_sequences == pre.effect_dispatch_sequences
            and second_snapshot.effect_dispatch_sequences == pre.effect_dispatch_sequences
        ),
        "dispatch_action_stays_dispatching": all(
            item.action_state == ActionState.DISPATCHING.value
            for item in (pre, first_snapshot, second_snapshot)
        ),
        "dispatch_effect_stays_dispatching": all(
            item.effect_state == EffectState.DISPATCHING.value
            for item in (pre, first_snapshot, second_snapshot)
        ),
        "event_head_stable_on_second_recovery": first_snapshot.event_head
        == second_snapshot.event_head,
        "obligations_stable_on_second_recovery": all(
            first[key] == second[key]
            for key in (
                "dispatching_action_ids",
                "dispatching_effect_ids",
                "dispatch_reconciliations",
                "incomplete_case_ids",
                "compensation_effect_ids",
                "receipt_rebuild_case_ids",
            )
        ),
        "compensation_set_matches_stage": first["compensation_effect_ids"]
        == sorted(compensation_ids),
        "incomplete_set_matches_stage": first["incomplete_case_ids"]
        == expected_incomplete,
        "receipt_rebuild_set_matches_stage": first["receipt_rebuild_case_ids"]
        == expected_rebuild,
        "after_recovery_snapshots_byte_identical": byte_identical,
    }
    invariants = stage.get("invariants")
    if not isinstance(invariants, Mapping) or dict(invariants) != semantic_invariants or not all(
        semantic_invariants.values()
    ):
        raise IntegrityError("R-18 CrashBench invariant claims are not independently true")
    if any(item.case_state != stage_name for item in (pre, first_snapshot, second_snapshot)):
        raise IntegrityError("R-18 CrashBench recovery changed the revocation stage")


def verify_revokebench(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    expected_source_commit: str | None = None,
    source_repository: Path | None = None,
) -> RevokeBenchProof:
    paths = requirement_paths(root, manifest, "R-19")
    if len(paths) != 22:
        raise IntegrityError("R-19 requires report, producer source, and 20 databases")
    reports = [path for path in paths if path.name == "report.json"]
    if len(reports) != 1:
        raise IntegrityError("R-19 requires exactly one RevokeBench report")
    report_path = reports[0]
    report = _load_object(report_path)
    if report.get("schema_version") != 2 or report.get("suite") != "RevokeBench-20":
        raise IntegrityError("R-19 report is not RevokeBench-20 schema v2")
    if report.get("passed") is not True or report.get("trial_count") != 20:
        raise IntegrityError("R-19 report is not a passing 20-trial run")
    _verify_benchmark_producer(
        report_path,
        paths,
        report,
        expected_source_commit=expected_source_commit,
        source_repository=source_repository,
    )
    _verify_benchmark_methodology(report)
    _verify_benchmark_targets(report)

    trials = report.get("trials")
    if not isinstance(trials, list) or len(trials) != 20:
        raise IntegrityError("R-19 must contain exactly 20 trial records")
    if [trial.get("trial") if isinstance(trial, Mapping) else None for trial in trials] != list(
        range(20)
    ):
        raise IntegrityError("R-19 trial indices are not exactly 0 through 19")
    database_paths = {
        path.relative_to(report_path.parent).as_posix(): path
        for path in paths
        if path.suffix == ".sqlite3"
    }
    if len(database_paths) != 20:
        raise IntegrityError("R-19 must bind exactly 20 SQLite trial databases")
    event_heads: list[str] = []
    for index, trial_raw in enumerate(trials):
        if not isinstance(trial_raw, Mapping):
            raise IntegrityError("R-19 trial record is malformed")
        _verify_benchmark_schedule(trial_raw, index=index)
        database_name = trial_raw.get("state_database")
        expected_name = f"state/trial-{index:02d}.sqlite3"
        if database_name != expected_name or expected_name not in database_paths:
            raise IntegrityError("R-19 trial database binding is invalid")
        event_heads.append(_verify_benchmark_trial(database_paths[expected_name], trial_raw))
    return RevokeBenchProof(True, 20, tuple(event_heads))


def _verify_benchmark_producer(
    report_path: Path,
    proof_paths: Sequence[Path],
    report: Mapping[str, Any],
    *,
    expected_source_commit: str | None,
    source_repository: Path | None,
) -> None:
    producer = report.get("producer")
    if not isinstance(producer, Mapping) or set(producer) != {
        "protocol",
        "entrypoint",
        "command",
        "source",
    }:
        raise IntegrityError("R-19 producer provenance is malformed")
    if (
        producer.get("protocol") != "tars.revokebench.producer/v1"
        or producer.get("entrypoint")
        != "tars_revoke.demo.benchmarks:run_benchmark_suite"
    ):
        raise IntegrityError("R-19 producer identity is unsupported")
    command = producer.get("command")
    if not isinstance(command, Mapping) or set(command) != {
        "observed_argv",
        "observed_argv_sha256",
        "canonical_argv",
    }:
        raise IntegrityError("R-19 producer command binding is malformed")
    observed = command.get("observed_argv")
    if not isinstance(observed, list) or not observed or any(
        not isinstance(item, str) for item in observed
    ):
        raise IntegrityError("R-19 observed producer argv is malformed")
    if command.get("observed_argv_sha256") != canonical_digest(observed):
        raise IntegrityError("R-19 observed producer argv digest changed")
    if command.get("canonical_argv") != [
        "tars-revoke",
        "bench",
        "--suite",
        "RevokeBench-20",
        "--output-root",
        "<OUTPUT_ROOT>",
    ]:
        raise IntegrityError("R-19 canonical producer argv is incorrect")

    source = producer.get("source")
    if not isinstance(source, Mapping) or set(source) != {
        "path",
        "artifact_path",
        "sha256",
        "source_commit",
        "source_tree",
        "committed_blob_oid",
        "committed_sha256",
        "matches_committed_source",
        "worktree_clean",
    }:
        raise IntegrityError("R-19 producer source binding is malformed")
    if source.get("path") != "src/tars_revoke/demo/benchmarks.py":
        raise IntegrityError("R-19 producer source path is not canonical")
    if source.get("artifact_path") != "producer/benchmarks.py":
        raise IntegrityError("R-19 producer source artifact path is not canonical")
    source_artifact = (report_path.parent / "producer/benchmarks.py").resolve()
    if source_artifact not in proof_paths or not source_artifact.is_file():
        raise IntegrityError("R-19 producer source artifact is not bound by the manifest")
    source_bytes = source_artifact.read_bytes()
    source_digest = sha256_digest(source_bytes)
    if source.get("sha256") != source_digest:
        raise IntegrityError("R-19 producer source artifact digest changed")

    if (expected_source_commit is None) != (source_repository is None):
        raise IntegrityError("R-19 qualified source context is incomplete")
    if expected_source_commit is None:
        return
    commit = source.get("source_commit")
    if (
        commit != expected_source_commit
        or source.get("matches_committed_source") is not True
        or source.get("worktree_clean") is not True
        or source.get("committed_sha256") != source_digest
    ):
        raise IntegrityError("R-19 producer was not the qualified clean source commit")
    assert source_repository is not None
    committed_bytes = _git_bytes(
        source_repository,
        "show",
        f"{expected_source_commit}:src/tars_revoke/demo/benchmarks.py",
    )
    if committed_bytes != source_bytes:
        raise IntegrityError("R-19 producer source differs from the qualified Git blob")
    tree = _git_bytes(
        source_repository,
        "rev-parse",
        f"{expected_source_commit}^{{tree}}",
    ).decode("ascii").strip()
    blob_oid = _git_bytes(
        source_repository,
        "rev-parse",
        f"{expected_source_commit}:src/tars_revoke/demo/benchmarks.py",
    ).decode("ascii").strip()
    if source.get("source_tree") != tree or source.get("committed_blob_oid") != blob_oid:
        raise IntegrityError("R-19 producer Git object lineage changed")


def _verify_benchmark_methodology(report: Mapping[str, Any]) -> None:
    methodology = report.get("methodology")
    if not isinstance(methodology, Mapping) or set(methodology) != {
        "race",
        "schedule",
        "schedule_seed",
        "schedule_protocol",
        "schedule_operations",
        "schedule_derivation",
        "worker_trace_protocol",
        "safety_oracle",
        "selectivity_oracle",
        "unrelated_workload",
        "unrelated_workload_bytes",
        "latency_clock",
        "p95_method",
    }:
        raise IntegrityError("R-19 benchmark methodology is malformed")
    expected = {
        "schedule_seed": 0x54415253,
        "schedule_protocol": "tars.revokebench.schedule/v1",
        "schedule_operations": ["dispatch", "unrelated", "invalidate"],
        "schedule_derivation": (
            "sort operations by ascending raw SHA-256 of UTF-8 "
            "'<protocol>:<decimal-seed>:<operation>', then operation as tie-break"
        ),
        "worker_trace_protocol": "tars.revokebench.worker-trace/v1",
        "unrelated_workload_bytes": 128 * 1024 * 1024,
        "latency_clock": "time.perf_counter_ns",
        "p95_method": "nearest-rank",
    }
    if any(methodology.get(key) != value for key, value in expected.items()):
        raise IntegrityError("R-19 benchmark methodology differs from its protocol")
    if "seeded randomized" not in str(methodology.get("schedule", "")):
        raise IntegrityError("R-19 report is not a seeded randomized schedule")


def _verify_benchmark_schedule(trial: Mapping[str, Any], *, index: int) -> None:
    expected_fields = {
        "trial",
        "run_id",
        "schedule_seed",
        "submission_order",
        "worker_trace",
        "state_database",
        "event_count",
        "event_head",
        "event_chain_verified",
        "premise_id",
        "race_action_id",
        "race_effect_id",
        "dispatch_succeeded",
        "dispatch_denial",
        "dispatch_sequences",
        "invalidation_sequence",
        "stale_dispatch_sequences",
        "expected_effect_ids",
        "affected_effect_ids",
        "unrelated_action_id",
        "unrelated_effect_id",
        "unrelated_completed",
        "selectivity",
        "latency_ms",
        "violations",
    }
    if set(trial) != expected_fields:
        raise IntegrityError("R-19 trial record has unexpected fields")
    seed = trial.get("schedule_seed")
    if seed != 0x54415253 + index:
        raise IntegrityError("R-19 trial seed is not the canonical indexed schedule")
    operations = ("dispatch", "unrelated", "invalidate")

    def ordering_key(operation: str) -> tuple[bytes, str]:
        material = f"tars.revokebench.schedule/v1:{seed}:{operation}".encode()
        return hashlib.sha256(material).digest(), operation

    expected_order = tuple(sorted(operations, key=ordering_key))
    if trial.get("submission_order") != "-".join(expected_order):
        raise IntegrityError("R-19 submission order is not derived from its seed")
    trace = trial.get("worker_trace")
    if not isinstance(trace, Mapping) or set(trace) != {
        "protocol",
        "clock",
        "participant_count",
        "barrier_release_ns",
        "workers",
    }:
        raise IntegrityError("R-19 worker trace is malformed")
    if (
        trace.get("protocol") != "tars.revokebench.worker-trace/v1"
        or trace.get("clock")
        != "time.perf_counter_ns relative to trial schedule origin"
        or trace.get("participant_count") != 3
    ):
        raise IntegrityError("R-19 worker trace protocol is invalid")
    release_ns = _strict_int(trace.get("barrier_release_ns"), "barrier release")
    workers = trace.get("workers")
    if not isinstance(workers, list) or len(workers) != 3:
        raise IntegrityError("R-19 worker trace must contain exactly three workers")
    observed_order = [
        worker.get("operation") if isinstance(worker, Mapping) else None
        for worker in workers
    ]
    if observed_order != list(expected_order):
        raise IntegrityError("R-19 worker trace order differs from its schedule")
    identities: set[tuple[str, int]] = set()
    barrier_ordinals: set[int] = set()
    for ordinal, worker in enumerate(workers):
        if not isinstance(worker, Mapping) or set(worker) != {
            "operation",
            "worker_id",
            "thread_name",
            "thread_ident",
            "submission_ordinal",
            "barrier_ordinal",
            "ready_ns",
            "released_ns",
            "started_ns",
            "ended_ns",
            "outcome",
        }:
            raise IntegrityError("R-19 worker trace row is malformed")
        operation = expected_order[ordinal]
        if (
            worker.get("worker_id") != f"worker-{operation}"
            or worker.get("submission_ordinal") != ordinal
        ):
            raise IntegrityError("R-19 worker identity or submission ordinal is invalid")
        thread_name = worker.get("thread_name")
        thread_ident = _strict_int(worker.get("thread_ident"), "thread identity")
        if not isinstance(thread_name, str) or not thread_name:
            raise IntegrityError("R-19 worker thread name is invalid")
        identities.add((thread_name, thread_ident))
        barrier_ordinals.add(_strict_int(worker.get("barrier_ordinal"), "barrier ordinal"))
        ready = _strict_int(worker.get("ready_ns"), "ready observation")
        released = _strict_int(worker.get("released_ns"), "released observation")
        started = _strict_int(worker.get("started_ns"), "start observation")
        ended = _strict_int(worker.get("ended_ns"), "end observation")
        if not 0 <= ready <= released == release_ns <= started <= ended:
            raise IntegrityError("R-19 worker monotonic observations are invalid")
        if not isinstance(worker.get("outcome"), Mapping):
            raise IntegrityError("R-19 worker outcome is missing")
    if len(identities) != 3 or barrier_ordinals != {0, 1, 2}:
        raise IntegrityError("R-19 worker trace does not prove three barrier participants")


def _strict_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise IntegrityError(f"R-19 {label} must be an integer")
    return value


def _verify_benchmark_targets(report: Mapping[str, Any]) -> None:
    metrics = report.get("metrics")
    targets = report.get("targets")
    if not isinstance(metrics, Mapping) or not isinstance(targets, Mapping):
        raise IntegrityError("R-19 metrics or targets are missing")
    metric_expectations = {
        "unsafe_post_invalidation_dispatch_count": 0,
        "race_invariant_violation_count": 0,
        "revocation_set_precision_percent": 100.0,
        "revocation_set_recall_percent": 100.0,
        "canonical_subset_precision_percent": 100.0,
        "canonical_subset_recall_percent": 100.0,
        "unrelated_task_completion_percent": 100.0,
    }
    for key, expected in metric_expectations.items():
        if metrics.get(key) != expected:
            raise IntegrityError(f"R-19 metric {key} misses its release threshold")
    added_latency = _finite_number(
        metrics.get("unrelated_task_p95_added_latency_percent"),
        "added latency",
    )
    if added_latency >= 20.0:
        raise IntegrityError("R-19 unrelated-work p95 added latency is not below 20%")
    expected_targets = {
        "unsafe_post_invalidation_dispatch": ("eq", 0.0),
        "revocation_set_precision": ("gte", 95.0),
        "revocation_set_recall": ("gte", 95.0),
        "canonical_subset_precision": ("eq", 100.0),
        "canonical_subset_recall": ("eq", 100.0),
        "unrelated_task_completion": ("eq", 100.0),
        "unrelated_task_p95_added_latency": ("lt", 20.0),
        "randomized_race_invariant_violations": ("eq", 0.0),
    }
    if set(targets) != set(expected_targets):
        raise IntegrityError("R-19 target set differs from the release contract")
    for name, (operator, target_value) in expected_targets.items():
        target = targets.get(name)
        if (
            not isinstance(target, Mapping)
            or target.get("operator") != operator
            or target.get("target") != target_value
            or target.get("passed") is not True
        ):
            raise IntegrityError(f"R-19 target {name} is malformed or failed")


def _verify_benchmark_trial(database_path: Path, trial: Mapping[str, Any]) -> str:
    content = database_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="tars-r19-verify-") as temporary:
        verification_path = Path(temporary) / "trial.sqlite3"
        verification_path.write_bytes(content)
        return _verify_benchmark_trial_database(verification_path, trial)


def _verify_benchmark_trial_database(
    database_path: Path,
    trial: Mapping[str, Any],
) -> str:
    run_id = _required_text(trial.get("run_id"), "R-19 run ID")
    store = Store(database_path)
    events = store.journal.list_events(run_id)
    if trial.get("event_chain_verified") is not True or len(events) != trial.get("event_count"):
        raise IntegrityError("R-19 event count differs from its trial database")
    head = store.journal.verify_chain(run_id)
    if head != trial.get("event_head"):
        raise IntegrityError("R-19 event chain head differs from its report")
    premise_id = _required_text(trial.get("premise_id"), "R-19 premise ID")
    race_action_id = _required_text(trial.get("race_action_id"), "R-19 race action ID")
    invalidation = [
        event.sequence
        for event in events
        if event.aggregate_type == "premise"
        and event.aggregate_id == premise_id
        and event.kind == "premise.transitioned"
        and event.payload.get("to") == PremiseState.INVALIDATED.value
    ]
    if len(invalidation) != 1 or invalidation[0] != trial.get("invalidation_sequence"):
        raise IntegrityError("R-19 invalidation sequence differs from durable state")
    dispatches = [
        event.sequence
        for event in events
        if event.aggregate_type == "action"
        and event.aggregate_id == race_action_id
        and event.kind == "action.transitioned"
        and event.payload.get("to") == ActionState.DISPATCHING.value
    ]
    if dispatches != trial.get("dispatch_sequences"):
        raise IntegrityError("R-19 dispatch sequence differs from durable state")
    if any(sequence >= invalidation[0] for sequence in dispatches):
        raise IntegrityError("R-19 contains a stale post-invalidation dispatch")
    race_effect_id = _required_text(trial.get("race_effect_id"), "R-19 race effect ID")
    effect_dispatches = [
        event.sequence
        for event in events
        if event.aggregate_type == "effect"
        and event.aggregate_id == race_effect_id
        and event.kind == "effect.transitioned"
        and event.payload.get("to") == EffectState.DISPATCHING.value
    ]
    if trial.get("dispatch_succeeded") is not bool(dispatches) or bool(dispatches) is not bool(
        effect_dispatches
    ):
        raise IntegrityError("R-19 dispatch result differs from durable action/effect events")
    if trial.get("stale_dispatch_sequences") != [] or trial.get("violations") != []:
        raise IntegrityError("R-19 trial records a stale dispatch or invariant violation")
    expected = _string_sequence(trial.get("expected_effect_ids"), "expected effect IDs")
    affected = _string_sequence(trial.get("affected_effect_ids"), "affected effect IDs")
    if len(expected) != 3 or tuple(sorted(expected)) != tuple(sorted(affected)):
        raise IntegrityError("R-19 trial revocation closure is not exactly selective")
    selectivity = trial.get("selectivity")
    if not isinstance(selectivity, Mapping) or any(
        selectivity.get(key) != value
        for key, value in {
            "false_negatives": 0,
            "false_positives": 0,
            "precision_percent": 100.0,
            "recall_percent": 100.0,
            "true_positives": 3,
        }.items()
    ):
        raise IntegrityError("R-19 trial selectivity metrics differ from durable closure")
    unrelated_action = store.get_action(
        _required_text(trial.get("unrelated_action_id"), "unrelated action ID")
    )
    unrelated_effect = store.get_effect(
        _required_text(trial.get("unrelated_effect_id"), "unrelated effect ID")
    )
    if unrelated_action is None or unrelated_action.state != ActionState.EXECUTED:
        raise IntegrityError("R-19 unrelated action did not complete")
    if unrelated_effect is None or unrelated_effect.state != EffectState.EXECUTED:
        raise IntegrityError("R-19 unrelated effect did not complete")
    if trial.get("unrelated_completed") is not True:
        raise IntegrityError("R-19 report does not record unrelated completion")
    _verify_benchmark_worker_outcomes(store, events, trial)
    return head


def _verify_benchmark_worker_outcomes(
    store: Store,
    events: Sequence[Any],
    trial: Mapping[str, Any],
) -> None:
    trace = trial.get("worker_trace")
    if not isinstance(trace, Mapping):
        raise IntegrityError("R-19 worker trace is missing")
    workers = trace.get("workers")
    if not isinstance(workers, list):
        raise IntegrityError("R-19 worker rows are missing")
    by_operation = {
        str(worker.get("operation")): worker
        for worker in workers
        if isinstance(worker, Mapping)
    }
    if set(by_operation) != {"dispatch", "invalidate", "unrelated"}:
        raise IntegrityError("R-19 worker operations are incomplete")
    latencies = trial.get("latency_ms")
    if not isinstance(latencies, Mapping) or set(latencies) != {
        "dispatch",
        "invalidation",
        "unrelated_baseline",
        "unrelated_during_revocation",
        "schedule",
    }:
        raise IntegrityError("R-19 trial latency evidence is malformed")
    for label, value in latencies.items():
        if _finite_number(value, f"R-19 {label} latency") < 0:
            raise IntegrityError("R-19 trial latency cannot be negative")

    race_action_id = _required_text(trial.get("race_action_id"), "race action ID")
    race_effect_id = _required_text(trial.get("race_effect_id"), "race effect ID")
    race_action = store.get_action(race_action_id)
    race_effect = store.get_effect(race_effect_id)
    if (
        race_action is None
        or race_action.state != ActionState.REVOKE_PENDING
        or race_effect is None
        or race_effect.state != EffectState.REVOKE_PENDING
    ):
        raise IntegrityError("R-19 race action and effect are not durably fenced")
    dispatch = by_operation["dispatch"].get("outcome")
    if not isinstance(dispatch, Mapping):
        raise IntegrityError("R-19 dispatch worker outcome is missing")
    dispatch_succeeded = trial.get("dispatch_succeeded")
    expected_dispatch_fields = {"status", "latency_ms", "denial", "durable"}
    if set(dispatch) != expected_dispatch_fields:
        raise IntegrityError("R-19 dispatch worker outcome has unexpected fields")
    if dispatch.get("latency_ms") != latencies.get("dispatch"):
        raise IntegrityError("R-19 dispatch worker latency differs from the trial")
    action_transitions = _benchmark_transitions(events, "action", race_action_id)
    effect_transitions = _benchmark_transitions(events, "effect", race_effect_id)
    durable_dispatch = dispatch.get("durable")
    expected_durable_dispatch = {
        "action_id": race_action_id,
        "observed_final_state": ActionState.REVOKE_PENDING.value,
        "transition_events": action_transitions,
        "effect_id": race_effect_id,
        "effect_observed_final_state": EffectState.REVOKE_PENDING.value,
        "effect_transition_events": effect_transitions,
    }
    if durable_dispatch != expected_durable_dispatch:
        raise IntegrityError("R-19 dispatch worker differs from durable transitions")
    if dispatch_succeeded is True:
        if dispatch.get("status") != "DISPATCHED" or trial.get("dispatch_denial") is not None:
            raise IntegrityError("R-19 successful dispatch claim is inconsistent")
    elif dispatch_succeeded is False:
        message = trial.get("dispatch_denial")
        denial = dispatch.get("denial")
        if (
            not isinstance(message, str)
            or not isinstance(denial, Mapping)
            or dict(denial)
            != {
                "type": "AuthorizationError",
                "message": message,
                "message_sha256": sha256_digest(message),
            }
            or dispatch.get("status") != "DENIED"
        ):
            raise IntegrityError("R-19 denied dispatch claim is inconsistent")
    else:
        raise IntegrityError("R-19 dispatch result must be boolean")

    premise_id = _required_text(trial.get("premise_id"), "premise ID")
    premise = store.get_premise(premise_id)
    invalidation_worker = by_operation["invalidate"].get("outcome")
    if premise is None or premise.state != PremiseState.INVALIDATED:
        raise IntegrityError("R-19 premise was not durably invalidated")
    expected_invalidation = {
        "status": "INVALIDATED",
        "latency_ms": latencies.get("invalidation"),
        "affected_effect_ids": list(
            _string_sequence(trial.get("affected_effect_ids"), "affected effect IDs")
        ),
        "durable": {
            "premise_id": premise_id,
            "observed_final_state": PremiseState.INVALIDATED.value,
            "transition_events": _benchmark_transitions(events, "premise", premise_id),
        },
    }
    if invalidation_worker != expected_invalidation:
        raise IntegrityError("R-19 invalidation worker differs from durable transitions")

    unrelated_action_id = _required_text(trial.get("unrelated_action_id"), "action ID")
    unrelated_effect_id = _required_text(trial.get("unrelated_effect_id"), "effect ID")
    unrelated_worker = by_operation["unrelated"].get("outcome")
    expected_unrelated = {
        "status": "COMPLETED",
        "latency_ms": latencies.get("unrelated_during_revocation"),
        "durable": {
            "action_id": unrelated_action_id,
            "action_final_state": ActionState.EXECUTED.value,
            "action_transition_events": _benchmark_transitions(
                events, "action", unrelated_action_id
            ),
            "effect_id": unrelated_effect_id,
            "effect_final_state": EffectState.EXECUTED.value,
            "effect_transition_events": _benchmark_transitions(
                events, "effect", unrelated_effect_id
            ),
        },
    }
    if unrelated_worker != expected_unrelated:
        raise IntegrityError("R-19 unrelated worker differs from durable transitions")


def _benchmark_transitions(
    events: Sequence[Any],
    aggregate_type: str,
    aggregate_id: str,
) -> list[dict[str, Any]]:
    records = [
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
    if not records or any(
        not isinstance(record["from"], str) or not isinstance(record["to"], str)
        for record in records
    ):
        raise IntegrityError(f"R-19 {aggregate_type} transition evidence is incomplete")
    return records


def verify_qualification_journal(
    record_path: Path,
    *,
    require_source_repository: bool = True,
) -> QualificationJournalProof:
    root = record_path.parent.resolve()
    record = _load_object(record_path)
    if record.get("protocol") != "tars.qualification-journal/v2":
        raise IntegrityError("unsupported qualification journal protocol")
    integrity = record.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {"canonical_digest"}:
        raise IntegrityError("qualification journal integrity is malformed")
    unsigned = dict(record)
    unsigned.pop("integrity")
    if not hmac.compare_digest(
        canonical_digest(unsigned), str(integrity.get("canonical_digest", ""))
    ):
        raise IntegrityError("qualification journal canonical digest changed")
    environment_policy = record.get("environment_policy")
    if environment_policy != {
        "protocol": "tars.qualification-environment/v1",
        "blocked_keys": ["TARS_RUN_LIVE_CODEX"],
    }:
        raise IntegrityError("R-20 qualification environment policy is missing or unsafe")

    source = record.get("source")
    if not isinstance(source, Mapping):
        raise IntegrityError("qualification source binding is missing")
    required_source_fields = {
        "recorded_workspace_root",
        "recorded_qualification_output_root",
        "qualification_output_root",
        "source_commit",
        "source_tree_digest",
        "source_manifest_path",
        "source_manifest_sha256",
        "git_head_path",
        "git_head_sha256",
        "git_status_path",
        "git_status_sha256",
        "clone_directory_was_empty",
        "tars_revoke_executable",
        "tars_revoke_executable_sha256",
        "tars_revoke_executable_evidence_path",
        "codex_executable",
        "codex_executable_sha256",
        "codex_executable_version",
        "codex_signing",
        "codex_version_stdout_path",
        "codex_version_stdout_sha256",
        "codex_version_stderr_path",
        "codex_version_stderr_sha256",
    }
    if require_source_repository:
        required_source_fields.add("source_repository")
    if set(source) != required_source_fields:
        raise IntegrityError("qualification source binding has unexpected fields")
    if source.get("clone_directory_was_empty") is not True:
        raise IntegrityError("R-20 qualification was not performed in an empty fresh clone")
    source_commit = source.get("source_commit")
    if not isinstance(source_commit, str) or not _COMMIT_RE.fullmatch(source_commit):
        raise IntegrityError("R-20 qualification source commit is malformed")
    workspace_root = Path(_required_text(source.get("recorded_workspace_root"), "workspace root"))
    recorded_output = Path(
        _required_text(source.get("recorded_qualification_output_root"), "output root")
    )
    if not workspace_root.is_absolute() or not recorded_output.is_absolute():
        raise IntegrityError("R-20 recorded qualification roots must be absolute audit paths")
    if workspace_root not in recorded_output.parents:
        raise IntegrityError("R-20 qualification output was not under the fresh clone")
    qualification_output = _safe_directory(
        root,
        source.get("qualification_output_root"),
        label="qualification output root",
    )

    head_path = _safe_file(root, source.get("git_head_path"), label="Git HEAD output")
    status_path = _safe_file(root, source.get("git_status_path"), label="Git status output")
    source_manifest_path = _safe_file(
        root,
        source.get("source_manifest_path"),
        label="source tree manifest",
    )
    for path, digest_key in (
        (head_path, "git_head_sha256"),
        (status_path, "git_status_sha256"),
        (source_manifest_path, "source_manifest_sha256"),
    ):
        if not hmac.compare_digest(
            sha256_digest(path.read_bytes()), str(source.get(digest_key, ""))
        ):
            raise IntegrityError(f"R-20 qualification {digest_key} changed")
    if head_path.read_text(encoding="utf-8").strip() != source_commit:
        raise IntegrityError("R-20 recorded Git HEAD differs from the source commit")
    if status_path.read_bytes() != b"":
        raise IntegrityError("R-20 fresh clone was not clean before qualification")
    source_manifest = _load_object(source_manifest_path)
    if source_manifest.get("protocol") != "tars.source-tree/v1":
        raise IntegrityError("R-20 source tree manifest protocol is unsupported")
    if source_manifest.get("source_commit") != source_commit:
        raise IntegrityError("R-20 source manifest belongs to a different commit")
    files = source_manifest.get("files")
    if not isinstance(files, list) or not files:
        raise IntegrityError("R-20 source tree manifest is empty")
    _verify_source_manifest_files(files)
    source_tree_digest = canonical_digest(source_manifest)
    if source.get("source_tree_digest") != source_tree_digest:
        raise IntegrityError("R-20 source tree digest differs from its manifest")
    tars_executable = str(
        workspace_root
        / ".tars"
        / "qualification"
        / "evidence"
        / "executables"
        / "tars-revoke"
    )
    if source.get("tars_revoke_executable") != tars_executable:
        raise IntegrityError("R-20 qualification used an unexpected tars-revoke executable")
    tars_evidence = _safe_file(
        root,
        source.get("tars_revoke_executable_evidence_path"),
        label="qualified tars-revoke executable",
    )
    tars_digest = sha256_digest(tars_evidence.read_bytes())
    if source.get("tars_revoke_executable_sha256") != tars_digest:
        raise IntegrityError("R-20 qualified tars-revoke executable digest changed")
    codex_executable = _required_text(source.get("codex_executable"), "Codex executable")
    codex_path = Path(codex_executable).expanduser()
    codex_bundle = _desktop_codex_bundle(codex_path)
    if codex_bundle is None:
        raise IntegrityError("R-20 qualification did not use an official desktop Codex binary")
    codex_digest = source.get("codex_executable_sha256")
    codex_version = source.get("codex_executable_version")
    if not isinstance(codex_digest, str) or not _SHA256_RE.fullmatch(codex_digest):
        raise IntegrityError("R-20 qualified Codex executable digest is malformed")
    if not isinstance(codex_version, str) or not codex_version.startswith("codex-cli "):
        raise IntegrityError("R-20 qualified Codex version is malformed")
    if _PINNED_CODEX_RELEASES.get(codex_version) != codex_digest:
        raise IntegrityError("R-20 Codex executable is not an approved pinned release")
    codex_strict_signature_valid = _verify_codex_signing_record(
        root,
        source.get("codex_signing"),
        codex_executable=Path(codex_executable),
    )
    codex_stdout = _safe_file(
        root,
        source.get("codex_version_stdout_path"),
        label="Codex version stdout",
    )
    codex_stderr = _safe_file(
        root,
        source.get("codex_version_stderr_path"),
        label="Codex version stderr",
    )
    for stream, path in (("stdout", codex_stdout), ("stderr", codex_stderr)):
        if source.get(f"codex_version_{stream}_sha256") != sha256_digest(path.read_bytes()):
            raise IntegrityError(f"R-20 Codex version {stream} digest changed")
    version_output = (codex_stdout.read_text(encoding="utf-8") or codex_stderr.read_text(
        encoding="utf-8"
    )).strip().splitlines()
    if not version_output or version_output[0] != codex_version:
        raise IntegrityError("R-20 Codex version output differs from its binding")
    source_repository: Path | None = None
    if require_source_repository:
        source_repository = _safe_directory(
            root,
            source.get("source_repository"),
            label="qualified source repository",
        )
        verify_source_repository(
            source_repository,
            source_commit=source_commit,
            source_manifest=source_manifest,
        )

    _verify_clone_record(
        root,
        record.get("clone"),
        workspace_root=workspace_root,
    )

    steps = record.get("setup_steps")
    if not isinstance(steps, list) or len(steps) != len(FRESH_CLONE_STEPS):
        raise IntegrityError("R-20 qualification has an incomplete setup step list")
    if [step.get("name") if isinstance(step, Mapping) else None for step in steps] != list(
        FRESH_CLONE_STEPS
    ):
        raise IntegrityError("R-20 qualification setup steps are missing or out of order")
    for step in steps:
        if not isinstance(step, Mapping):
            raise IntegrityError("R-20 qualification setup command is malformed")
        name = str(step.get("name", ""))
        _verify_command_record(
            root,
            step,
            label="qualification setup",
            expected_argv=_SETUP_ARGV.get(name),
            expected_cwd=str(workspace_root),
            expected_source_commit=source_commit,
        )

    attempts = record.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != 3:
        raise IntegrityError("R-20 journal must contain exactly three attempts")
    if [item.get("attempt_index") if isinstance(item, Mapping) else None for item in attempts] != [
        1,
        2,
        3,
    ]:
        raise IntegrityError("R-20 journal attempt indices are not consecutive")
    bundle_roots: list[Path] = []
    run_ids: list[str] = []
    receipt_digests: list[str] = []
    prior_finish: datetime | None = None
    recorded_bundle_roots: list[Path] = []
    run_containers: list[Path] = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            raise IntegrityError("R-20 qualification attempt is malformed")
        expected_output_root = Path(
            _required_text(attempt.get("recorded_output_root"), "attempt output root")
        )
        expected_argv = (
            tars_executable,
            "demo",
            "--scenario",
            "external-schema-v2",
            "--live-codex",
            "--output-root",
            str(expected_output_root),
        )
        _verify_command_record(
            root,
            attempt,
            label="qualification attempt",
            attempt=True,
            expected_argv=expected_argv,
            expected_cwd=str(workspace_root),
            expected_source_commit=source_commit,
            expected_executable_digest=tars_digest,
        )
        started = _aware_datetime(attempt.get("started_at"), "attempt started_at")
        finished = _aware_datetime(attempt.get("finished_at"), "attempt finished_at")
        if finished <= started or (prior_finish is not None and started <= prior_finish):
            raise IntegrityError("R-20 qualification attempts are not strictly sequential")
        prior_finish = finished
        bundle_root = _safe_directory(
            root,
            attempt.get("artifact_root"),
            label="qualification run bundle",
        )
        if qualification_output not in bundle_root.parents:
            raise IntegrityError("R-20 run bundle is outside the qualification output root")
        recorded_bundle = Path(
            _required_text(attempt.get("recorded_artifact_root"), "recorded bundle root")
        )
        if (
            not expected_output_root.is_absolute()
            or expected_output_root != recorded_output
            or not recorded_bundle.is_absolute()
            or expected_output_root not in recorded_bundle.parents
        ):
            raise IntegrityError("R-20 recorded bundle was outside the qualification output root")
        run_container = bundle_root.parent.parent
        recorded_run_container = recorded_bundle.parent.parent
        if (
            bundle_root.parent.name != "artifacts"
            or run_container.parent != qualification_output
            or recorded_bundle.parent.name != "artifacts"
            or recorded_run_container.parent != recorded_output
            or bundle_root.relative_to(qualification_output)
            != recorded_bundle.relative_to(recorded_output)
        ):
            raise IntegrityError("R-20 run bundle does not match the canonical run layout")
        receipt_path = _safe_file(bundle_root, "receipt.json", label="qualified receipt")
        receipt_candidates = tuple(
            path.resolve()
            for path in (run_container / "artifacts").glob("*/receipt.json")
            if path.is_file() and not path.is_symlink()
        )
        if receipt_candidates != (receipt_path.resolve(),):
            raise IntegrityError("R-20 run container does not contain exactly one receipt")
        receipt = _load_object(receipt_path)
        run_id = _required_text(receipt.get("run_id"), "qualified run ID")
        receipt_digest = sha256_digest(receipt_path.read_bytes())
        if attempt.get("discovered_run_id") != run_id:
            raise IntegrityError("R-20 discovered run ID differs from its receipt")
        if attempt.get("receipt_sha256") != receipt_digest:
            raise IntegrityError("R-20 discovered receipt hash differs from its bytes")
        bundle_roots.append(bundle_root)
        run_containers.append(run_container)
        recorded_bundle_roots.append(recorded_bundle)
        run_ids.append(run_id)
        receipt_digests.append(receipt_digest)
    if len(set(bundle_roots)) != 3 or len(set(recorded_bundle_roots)) != 3:
        raise IntegrityError("R-20 journal repeats a qualification bundle")
    if len(set(run_ids)) != 3 or len(set(receipt_digests)) != 3:
        raise IntegrityError("R-20 journal does not contain three distinct successful runs")
    actual_run_containers = {
        path.resolve() for path in qualification_output.iterdir() if path.is_dir()
    }
    if actual_run_containers != set(run_containers):
        raise IntegrityError(
            "R-20 qualification output contains an omitted or intervening run container"
        )
    if record.get("result") != "passed":
        raise IntegrityError("R-20 qualification journal did not pass")
    return QualificationJournalProof(
        valid=True,
        source_commit=source_commit,
        source_tree_digest=source_tree_digest,
        bundle_roots=(bundle_roots[0], bundle_roots[1], bundle_roots[2]),
        run_ids=(run_ids[0], run_ids[1], run_ids[2]),
        receipt_file_digests=(receipt_digests[0], receipt_digests[1], receipt_digests[2]),
        tars_revoke_executable=tars_executable,
        tars_revoke_executable_sha256=tars_digest,
        codex_executable=codex_executable,
        codex_executable_sha256=codex_digest,
        codex_executable_version=codex_version,
        codex_strict_signature_valid=codex_strict_signature_valid,
        source_repository=source_repository,
    )


def verify_release_runs(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    verify_bundle: BundleVerifier,
) -> ReleaseRunsProof:
    release_receipt = _load_object(root / "release-attestation.json")
    limitations = release_receipt.get("limitations")
    paths = requirement_paths(root, manifest, "R-20")
    ledgers = [path for path in paths if path.name == "ledger.json"]
    if len(ledgers) != 1:
        raise IntegrityError("R-20 requires exactly one machine-generated ledger")
    ledger = _load_object(ledgers[0])
    if set(ledger) != {
        "protocol",
        "trust_boundary",
        "required_consecutive_runs",
        "fallback_used",
        "qualification",
        "runs",
        "integrity",
    }:
        raise IntegrityError("R-20 release ledger has unexpected fields")
    if ledger.get("protocol") != "tars.release-runs/v1":
        raise IntegrityError("unsupported R-20 release ledger protocol")
    if ledger.get("trust_boundary") != (
        "host-owner-generated qualification journal; no external trusted witness"
    ):
        raise IntegrityError("R-20 release trust boundary is missing or changed")
    integrity = ledger.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {"canonical_digest"}:
        raise IntegrityError("R-20 ledger integrity is malformed")
    unsigned = dict(ledger)
    unsigned.pop("integrity")
    if not hmac.compare_digest(
        canonical_digest(unsigned), str(integrity.get("canonical_digest", ""))
    ):
        raise IntegrityError("R-20 ledger canonical digest changed")
    if ledger.get("required_consecutive_runs") != 3 or ledger.get("fallback_used") is not False:
        raise IntegrityError("R-20 ledger does not claim three no-fallback runs")
    qualification = ledger.get("qualification")
    if not isinstance(qualification, Mapping) or set(qualification) != {
        "journal_path",
        "journal_sha256",
        "source_commit",
        "source_tree_digest",
        "tars_revoke_executable",
        "tars_revoke_executable_sha256",
        "codex_executable",
        "codex_executable_sha256",
        "codex_executable_version",
        "codex_strict_signature_valid",
    }:
        raise IntegrityError("R-20 qualification ledger binding is malformed")
    journal_path = _safe_file(
        root,
        qualification.get("journal_path"),
        label="qualification journal",
    )
    if not hmac.compare_digest(
        sha256_digest(journal_path.read_bytes()), str(qualification.get("journal_sha256", ""))
    ):
        raise IntegrityError("R-20 qualification journal digest changed")
    qualified = verify_qualification_journal(journal_path)
    _verify_release_limitations(
        limitations,
        codex_strict_signature_valid=qualified.codex_strict_signature_valid,
    )
    ledger_signature_status = qualification.get("codex_strict_signature_valid")
    if not isinstance(ledger_signature_status, bool):
        raise IntegrityError("R-20 qualification signature status is not boolean")
    if (
        qualified.source_commit != qualification.get("source_commit")
        or qualified.source_tree_digest != qualification.get("source_tree_digest")
        or qualified.tars_revoke_executable != qualification.get("tars_revoke_executable")
        or qualified.tars_revoke_executable_sha256
        != qualification.get("tars_revoke_executable_sha256")
        or qualified.codex_executable != qualification.get("codex_executable")
        or qualified.codex_executable_sha256
        != qualification.get("codex_executable_sha256")
        or qualified.codex_executable_version
        != qualification.get("codex_executable_version")
        or qualified.codex_strict_signature_valid is not ledger_signature_status
    ):
        raise IntegrityError("R-20 qualification source binding differs from its ledger")

    runs = ledger.get("runs")
    if not isinstance(runs, list) or len(runs) != 3:
        raise IntegrityError("R-20 ledger must contain exactly three live runs")
    if [run.get("ordinal") if isinstance(run, Mapping) else None for run in runs] != [1, 2, 3]:
        raise IntegrityError("R-20 run ordinals are not consecutive")
    run_ids: list[str] = []
    receipt_digests: list[str] = []
    event_heads: list[str] = []
    for index, row in enumerate(runs):
        if not isinstance(row, Mapping):
            raise IntegrityError("R-20 run row is malformed")
        bundle_root = _safe_directory(root, row.get("artifact_root"), label="R-20 run")
        if bundle_root != qualified.bundle_roots[index]:
            raise IntegrityError("R-20 ledger run order differs from the qualification journal")
        verified = verify_bundle(
            bundle_root,
            strict=False,
            required_requirement_ids=LIVE_REQUIREMENT_IDS,
        )
        if verified.valid is not True:
            raise IntegrityError("R-20 nested live bundle did not verify")
        _verify_qualified_codex_bundle(bundle_root, qualified)
        expected = {
            "ordinal": row.get("ordinal"),
            "artifact_root": Path(str(row.get("artifact_root"))).as_posix(),
            "run_id": verified.run_id,
            "case_id": verified.case_id,
            "receipt_digest": verified.receipt_digest,
            "event_head_digest": verified.event_head_digest,
            "affected_effect_ids": list(verified.affected_effect_ids),
            "checked_requirements": list(verified.checked_requirements),
            "provider": "live-codex",
            "fallback_used": False,
        }
        if dict(row) != expected:
            raise IntegrityError("R-20 ledger row differs from semantic bundle verification")
        run_ids.append(verified.run_id)
        receipt_digests.append(verified.receipt_digest)
        event_heads.append(verified.event_head_digest)
    if any(len(set(values)) != 3 for values in (run_ids, receipt_digests, event_heads)):
        raise IntegrityError("R-20 live runs are not three distinct successful executions")
    return ReleaseRunsProof(
        True,
        (run_ids[0], run_ids[1], run_ids[2]),
        (receipt_digests[0], receipt_digests[1], receipt_digests[2]),
        qualified,
    )


def _verify_release_limitations(
    value: object,
    *,
    codex_strict_signature_valid: bool,
) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IntegrityError("R-20 release receipt limitations are malformed")
    if QUALIFICATION_TRUST_LIMITATION not in value:
        raise IntegrityError("R-20 release receipt does not disclose its host-owner trust boundary")
    signature_disclosed = CODEX_SIGNATURE_LIMITATION in value
    if signature_disclosed == codex_strict_signature_valid:
        raise IntegrityError(
            "R-20 release receipt signature limitation differs from qualification evidence"
        )


def _verify_qualified_codex_bundle(
    bundle_root: Path,
    qualification: QualificationJournalProof,
) -> None:
    manifest_path = (
        bundle_root / "portable-proof-manifest.json"
        if (bundle_root / "portable-proof-manifest.json").is_file()
        else bundle_root / "proof-manifest.json"
    )
    manifest = _load_object(manifest_path)
    for path in requirement_paths(bundle_root, manifest, "R-14"):
        if path.name != "manifest.json" or "agents/live-codex/sessions" not in path.as_posix():
            continue
        session = _load_object(path)
        if (
            session.get("executable") != qualification.codex_executable
            or session.get("executable_sha256") != qualification.codex_executable_sha256
            or session.get("executable_version") != qualification.codex_executable_version
        ):
            raise IntegrityError("R-20 live session differs from the qualified Codex binary")
        argv = session.get("supervisor_argv")
        if not isinstance(argv, list) or not argv or argv[0] != qualification.codex_executable:
            raise IntegrityError("R-20 live session supervisor argv differs from qualification")


def _verify_codex_signing_record(
    root: Path,
    value: object,
    *,
    codex_executable: Path,
) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "protocol",
        "bundle_path",
        "bundle_identifier",
        "team_identifier",
        "verify_argv",
        "verify_exit_code",
        "strict_verification_passed",
        "verify_stdout_path",
        "verify_stdout_sha256",
        "verify_stderr_path",
        "verify_stderr_sha256",
        "display_argv",
        "display_exit_code",
        "display_stdout_path",
        "display_stdout_sha256",
        "display_stderr_path",
        "display_stderr_sha256",
    }:
        raise IntegrityError("R-20 Codex code-signing evidence is malformed")
    display_exit = value.get("display_exit_code")
    if not isinstance(display_exit, int) or isinstance(display_exit, bool):
        raise IntegrityError("R-20 Codex identity exit status is malformed")
    if (
        value.get("protocol") != "tars.codex-codesign/v1"
        or value.get("bundle_identifier") != _CODEX_BUNDLE_IDENTIFIER
        or value.get("team_identifier") != _CODEX_TEAM_IDENTIFIER
        or display_exit != 0
    ):
        raise IntegrityError("R-20 Codex code-signing identity is not OpenAI")
    expected_bundle = _desktop_codex_bundle(codex_executable)
    if expected_bundle is None:
        raise IntegrityError("R-20 Codex executable is outside an official app bundle")
    bundle_path = Path(_required_text(value.get("bundle_path"), "Codex bundle path"))
    if bundle_path != expected_bundle or bundle_path.name not in _CODEX_BUNDLE_NAMES:
        raise IntegrityError("R-20 Codex signing evidence belongs to a different app bundle")
    expected_verify = (
        "/usr/bin/codesign",
        "--verify",
        "--deep",
        "--strict",
        "--verbose=2",
        str(bundle_path),
    )
    expected_display = (
        "/usr/bin/codesign",
        "-d",
        "--verbose=4",
        str(bundle_path),
    )
    if _string_sequence(value.get("verify_argv"), "Codex codesign verify argv") != expected_verify:
        raise IntegrityError("R-20 Codex verification command differs from the contract")
    observed_display = _string_sequence(
        value.get("display_argv"), "Codex codesign display argv"
    )
    if observed_display != expected_display:
        raise IntegrityError("R-20 Codex identity command differs from the contract")
    streams: dict[tuple[str, str], Path] = {}
    for command in ("verify", "display"):
        for stream in ("stdout", "stderr"):
            path = _safe_file(
                root,
                value.get(f"{command}_{stream}_path"),
                label=f"Codex codesign {command} {stream}",
            )
            if value.get(f"{command}_{stream}_sha256") != sha256_digest(path.read_bytes()):
                raise IntegrityError(
                    f"R-20 Codex codesign {command} {stream} digest changed"
                )
            streams[(command, stream)] = path
    display_text = (
        streams[("display", "stdout")].read_text(encoding="utf-8")
        + "\n"
        + streams[("display", "stderr")].read_text(encoding="utf-8")
    )
    identifier = re.search(r"(?m)^Identifier=([^\r\n]+)$", display_text)
    team = re.search(r"(?m)^TeamIdentifier=([^\r\n]+)$", display_text)
    if (
        identifier is None
        or identifier.group(1) != _CODEX_BUNDLE_IDENTIFIER
        or team is None
        or team.group(1) != _CODEX_TEAM_IDENTIFIER
    ):
        raise IntegrityError("R-20 Codex signed identity output is inconsistent")
    strict_valid = value.get("strict_verification_passed")
    verify_exit = value.get("verify_exit_code")
    if (
        not isinstance(strict_valid, bool)
        or not isinstance(verify_exit, int)
        or isinstance(verify_exit, bool)
        or strict_valid != (verify_exit == 0)
    ):
        raise IntegrityError("R-20 Codex strict signature status is inconsistent")
    return strict_valid


def _verify_command_record(
    root: Path,
    value: object,
    *,
    label: str,
    expected_argv: Sequence[str] | None,
    expected_cwd: str,
    expected_source_commit: str,
    expected_executable_digest: str | None = None,
    attempt: bool = False,
) -> None:
    if not isinstance(value, Mapping):
        raise IntegrityError(f"R-20 {label} command is malformed")
    required = {
        "name" if not attempt else "attempt_index",
        "argv",
        "exit_code",
        "stdout_path",
        "stdout_sha256",
        "stderr_path",
        "stderr_sha256",
        "cwd",
        "pre_git_status_path",
        "pre_git_status_sha256",
        "post_git_status_path",
        "post_git_status_sha256",
        "pre_git_head_path",
        "pre_git_head_sha256",
        "post_git_head_path",
        "post_git_head_sha256",
    }
    if attempt:
        required.update(
            {
                "started_at",
                "finished_at",
                "artifact_root",
                "recorded_artifact_root",
                "recorded_output_root",
                "discovered_run_id",
                "receipt_sha256",
                "pre_tars_revoke_path",
                "pre_tars_revoke_sha256",
                "post_tars_revoke_path",
                "post_tars_revoke_sha256",
            }
        )
    if set(value) != required:
        raise IntegrityError(f"R-20 {label} command has unexpected fields")
    argv = value.get("argv")
    if not isinstance(argv, list) or not argv or any(
        not isinstance(item, str) or not item for item in argv
    ):
        raise IntegrityError(f"R-20 {label} argv is malformed")
    if value.get("exit_code") != 0:
        raise IntegrityError(f"R-20 {label} command failed")
    if value.get("cwd") != expected_cwd:
        raise IntegrityError(f"R-20 {label} cwd differs from the fresh-clone root")
    if expected_argv is None or tuple(argv) != tuple(expected_argv):
        raise IntegrityError(f"R-20 {label} argv differs from the qualification contract")
    for stream in ("stdout", "stderr"):
        path = _safe_file(root, value.get(f"{stream}_path"), label=f"{label} {stream}")
        if not hmac.compare_digest(
            sha256_digest(path.read_bytes()), str(value.get(f"{stream}_sha256", ""))
        ):
            raise IntegrityError(f"R-20 {label} {stream} digest changed")
    for phase in ("pre", "post"):
        status = _safe_file(
            root,
            value.get(f"{phase}_git_status_path"),
            label=f"{label} {phase} Git status",
        )
        if value.get(f"{phase}_git_status_sha256") != sha256_digest(status.read_bytes()):
            raise IntegrityError(f"R-20 {label} {phase} Git status digest changed")
        if status.read_bytes() != b"":
            raise IntegrityError(f"R-20 {label} ran from a dirty source tree")
        head = _safe_file(
            root,
            value.get(f"{phase}_git_head_path"),
            label=f"{label} {phase} Git HEAD",
        )
        if value.get(f"{phase}_git_head_sha256") != sha256_digest(head.read_bytes()):
            raise IntegrityError(f"R-20 {label} {phase} Git HEAD digest changed")
        if head.read_text(encoding="utf-8").strip() != expected_source_commit:
            raise IntegrityError(f"R-20 {label} changed the qualified source commit")
        if attempt:
            executable = _safe_file(
                root,
                value.get(f"{phase}_tars_revoke_path"),
                label=f"{label} {phase} tars-revoke",
            )
            executable_digest = sha256_digest(executable.read_bytes())
            if (
                expected_executable_digest is None
                or value.get(f"{phase}_tars_revoke_sha256") != executable_digest
                or executable_digest != expected_executable_digest
            ):
                raise IntegrityError(f"R-20 {label} changed the qualified entry point")


def _verify_clone_record(
    root: Path,
    value: object,
    *,
    workspace_root: Path,
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "started_at",
        "finished_at",
        "argv",
        "cwd",
        "exit_code",
        "stdout_path",
        "stdout_sha256",
        "stderr_path",
        "stderr_sha256",
    }:
        raise IntegrityError("R-20 clone command record is malformed")
    started = _aware_datetime(value.get("started_at"), "clone started_at")
    finished = _aware_datetime(value.get("finished_at"), "clone finished_at")
    if finished <= started or value.get("exit_code") != 0:
        raise IntegrityError("R-20 fresh clone command did not complete successfully")
    argv = _string_sequence(value.get("argv"), "clone argv")
    if (
        len(argv) != 5
        or argv[:3] != ("git", "clone", "--no-local")
        or not argv[3]
        or Path(argv[4]).resolve() != workspace_root
    ):
        raise IntegrityError("R-20 clone argv is not the exact fresh-clone contract")
    if value.get("cwd") != str(workspace_root.parent):
        raise IntegrityError("R-20 clone cwd differs from the destination parent")
    for stream in ("stdout", "stderr"):
        path = _safe_file(root, value.get(f"{stream}_path"), label=f"clone {stream}")
        if value.get(f"{stream}_sha256") != sha256_digest(path.read_bytes()):
            raise IntegrityError(f"R-20 clone {stream} digest changed")


def _verify_source_manifest_files(files: Sequence[object]) -> None:
    prior_path = ""
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size"}:
            raise IntegrityError("R-20 source manifest entry is malformed")
        path = _required_text(entry.get("path"), "source path")
        _safe_relative_text(path, "source path")
        if path <= prior_path or path in seen:
            raise IntegrityError("R-20 source manifest paths are not unique and sorted")
        digest = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise IntegrityError("R-20 source manifest digest is malformed")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise IntegrityError("R-20 source manifest size is malformed")
        prior_path = path
        seen.add(path)


def verify_source_repository(
    repository: Path,
    *,
    source_commit: str,
    source_manifest: Mapping[str, Any],
) -> None:
    resolved_commit = _git_bytes(repository, "rev-parse", f"{source_commit}^{{commit}}")
    if resolved_commit.decode("ascii").strip() != source_commit:
        raise IntegrityError("R-20 source commit is absent from the portable source mirror")
    raw_paths = _git_bytes(repository, "ls-tree", "-r", "-z", "--name-only", source_commit)
    tree_paths = [item.decode("utf-8") for item in raw_paths.split(b"\0") if item]
    manifest_files = source_manifest.get("files")
    if not isinstance(manifest_files, list):
        raise IntegrityError("R-20 source manifest files are missing")
    manifest_by_path = {
        str(item["path"]): item
        for item in manifest_files
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }
    if len(tree_paths) != len(set(tree_paths)) or set(tree_paths) != set(manifest_by_path):
        raise IntegrityError("R-20 source manifest does not exactly match the Git tree")
    for path in tree_paths:
        content = _git_bytes(repository, "show", f"{source_commit}:{path}")
        entry = manifest_by_path[path]
        if entry.get("size") != len(content) or entry.get("sha256") != sha256_digest(content):
            raise IntegrityError(f"R-20 source manifest differs from Git blob {path}")


def _git_bytes(repository: Path, *args: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise IntegrityError(f"R-20 source Git proof failed: {stderr}")
    return result.stdout


def _only_stage(
    stages: Mapping[str, list[dict[str, Any]]],
    name: str,
) -> dict[str, Any]:
    matches = stages.get(name, [])
    if len(matches) != 1:
        raise IntegrityError(f"R-14 requires exactly one {name} session")
    return matches[0]


def _ordered_experiment_sessions(
    stages: Mapping[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    ordered: list[dict[str, Any]] = []
    initial = stages.get("agent-b-experiments", [])
    if len(initial) != 1:
        raise IntegrityError("R-14 requires exactly one initial experiment proposal")
    ordered.extend(initial)
    for correction_index in (1, 2):
        name = f"agent-b-experiments-correction-{correction_index}"
        matches = stages.get(name, [])
        if len(matches) > 1:
            raise IntegrityError(f"R-14 has duplicate {name} sessions")
        if matches:
            if correction_index != len(ordered):
                raise IntegrityError("R-14 experiment correction stages are not consecutive")
            ordered.extend(matches)
    allowed = {
        "agent-a-initial-uuid",
        "agent-b-observability",
        "agent-b-contradiction",
        "agent-b-experiments",
        "agent-b-experiments-correction-1",
        "agent-b-experiments-correction-2",
        "codex-bounded-repair",
    }
    unexpected = set(stages) - allowed
    if unexpected:
        raise IntegrityError(f"R-14 contains unexpected live session stages: {sorted(unexpected)}")
    return ordered


def _safe_file(root: Path, value: object, *, label: str) -> Path:
    path = _safe_path(root, value, label=label)
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"{label} is not a regular file: {path}")
    return path


def _safe_directory(root: Path, value: object, *, label: str) -> Path:
    path = _safe_path(root, value, label=label)
    if not path.is_dir() or path.is_symlink():
        raise IntegrityError(f"{label} is not a regular directory: {path}")
    return path


def _safe_path(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise IntegrityError(f"{label} path must be bundle-relative")
    candidate = root / value
    current = root
    for part in Path(value).parts:
        if part in {"", ".", ".."}:
            if part == "..":
                raise IntegrityError(f"{label} path escapes its proof root")
            continue
        current = current / part
        if current.is_symlink():
            raise IntegrityError(f"{label} path traverses a symlink")
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise IntegrityError(f"{label} path escapes its proof root")
    return resolved


def _safe_relative_text(value: str, label: str) -> None:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise IntegrityError(f"{label} is not a safe relative path")


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read JSON proof artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"proof artifact must contain a JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"invalid Codex JSONL row {line_number}") from exc
        if not isinstance(value, dict):
            raise IntegrityError(f"Codex JSONL row {line_number} is not an object")
        rows.append(value)
    if not rows:
        raise IntegrityError("Codex JSONL artifact is empty")
    return rows


def _load_string_array(path: Path) -> tuple[str, ...]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read string-array artifact {path}") from exc
    return _string_sequence(value, path.name)


def _string_sequence(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IntegrityError(f"{label} must be a string list")
    return tuple(value)


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IntegrityError(f"{label} is missing")
    return value


def _finite_number(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise IntegrityError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise IntegrityError(f"{label} is not finite")
    return result


def _aware_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise IntegrityError(f"{label} is not an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntegrityError(f"{label} must be timezone-aware")
    return parsed
