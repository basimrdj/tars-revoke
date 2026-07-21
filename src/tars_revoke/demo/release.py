from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tars_revoke.demo.release_proofs import (
    CODEX_SIGNATURE_LIMITATION,
    LIVE_REQUIREMENT_IDS,
    QUALIFICATION_TRUST_LIMITATION,
    QualificationJournalProof,
    verify_qualification_journal,
    verify_source_repository,
)
from tars_revoke.demo.verifier import BundleVerification, verify_bundle
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import ReceiptState
from tars_revoke.domain.models import Receipt
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence.artifacts import ArtifactStore
from tars_revoke.persistence.store import Store
from tars_revoke.services.receipts import DEFAULT_REQUIREMENT_IDS, ReceiptBuilder

_SECRET_LIKE_OUTPUT_PATTERNS = (
    re.compile(rb"\b(?:sk|rk|ghp|github_pat|xox[baprs])-[A-Za-z0-9_-]{12,}\b"),
    re.compile(rb"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
        rb"-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)


@dataclass(frozen=True)
class ReleaseAttestation:
    artifact_root: Path
    receipt_path: Path
    proof_manifest_path: Path
    qualification_journal_path: Path
    release_ledger_path: Path
    verification: BundleVerification


def build_source_tree_manifest(
    repository: str | Path,
    *,
    source_commit: str,
) -> Mapping[str, Any]:
    """Hash every tracked blob at one exact commit for qualification binding."""

    root = Path(repository).expanduser().resolve(strict=True)
    paths_result = subprocess.run(
        ("git", "-C", str(root), "ls-tree", "-r", "-z", "--name-only", source_commit),
        check=False,
        capture_output=True,
        timeout=30,
    )
    if paths_result.returncode != 0:
        raise ValidationError("cannot enumerate the qualification source tree")
    paths = sorted(item.decode("utf-8") for item in paths_result.stdout.split(b"\0") if item)
    files: list[dict[str, Any]] = []
    for path in paths:
        blob = subprocess.run(
            ("git", "-C", str(root), "show", f"{source_commit}:{path}"),
            check=False,
            capture_output=True,
            timeout=30,
        )
        if blob.returncode != 0:
            raise ValidationError(f"cannot read qualification source blob: {path}")
        files.append(
            {
                "path": path,
                "sha256": sha256_digest(blob.stdout),
                "size": len(blob.stdout),
            }
        )
    if not files:
        raise ValidationError("qualification source tree is empty")
    return {
        "protocol": "tars.source-tree/v1",
        "source_commit": source_commit,
        "files": files,
    }


def seal_qualification_journal(fields: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a canonically self-digested qualification journal payload."""

    if fields.get("protocol") != "tars.qualification-journal/v2":
        raise ValidationError("qualification journal protocol is missing")
    if "integrity" in fields:
        raise ValidationError("qualification journal fields must not include integrity")
    payload = dict(fields)
    return {**payload, "integrity": {"canonical_digest": canonical_digest(payload)}}


def build_release_attestation(
    *,
    qualification_journal_path: str | Path,
    crash_report_path: str | Path,
    benchmark_report_path: str | Path,
    output_root: str | Path,
) -> ReleaseAttestation:
    """Build one portable, strict R-01 through R-20 release proof bundle.

    The three live inputs are accepted only through the qualification journal.
    The journal, not caller-supplied success flags, determines their order and
    qualification status.
    """

    journal_path = _regular_file(qualification_journal_path, "qualification journal")
    qualification = verify_qualification_journal(
        journal_path,
        require_source_repository=False,
    )
    for bundle_root in qualification.bundle_roots:
        verify_bundle(
            bundle_root,
            strict=False,
            required_requirement_ids=LIVE_REQUIREMENT_IDS,
        )

    destination = Path(output_root).expanduser().resolve()
    if destination.exists():
        raise ValidationError(f"release output already exists: {destination}")
    overlaps_source = any(
        destination == root or root in destination.parents
        for root in qualification.bundle_roots
    )
    if overlaps_source:
        raise ValidationError("release output cannot replace or contain a qualified source bundle")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    try:
        _portable_copy_bundle(qualification.bundle_roots[0], destination)
        crash_paths = _copy_crash_evidence(
            destination,
            report_path=_regular_file(crash_report_path, "CrashBench report"),
        )
        benchmark_paths = _copy_benchmark_evidence(
            destination,
            report_path=_regular_file(benchmark_report_path, "benchmark report"),
        )
        copied_journal, copied_qualification = _copy_qualification_evidence(
            destination,
            source_journal=journal_path,
            source_qualification=qualification,
        )
        ledger_path = _write_release_ledger(
            destination,
            journal_path=copied_journal,
            qualification=copied_qualification,
        )
        verification = _attest_release_root(
            destination,
            crash_paths=crash_paths,
            benchmark_paths=benchmark_paths,
            qualification_root=copied_journal.parent,
            qualification_journal=copied_journal,
            qualification=copied_qualification,
            ledger_path=ledger_path,
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return ReleaseAttestation(
        artifact_root=destination,
        receipt_path=destination / "release-attestation.json",
        proof_manifest_path=destination / "release-proof-manifest.json",
        qualification_journal_path=copied_journal,
        release_ledger_path=ledger_path,
        verification=verification,
    )


def _portable_copy_bundle(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    if destination != destination.resolve():
        raise ValidationError("portable bundle destination must be normalized")
    receipt = _load_object(source / "receipt.json")
    manifest = _load_object(source / "proof-manifest.json")
    _copy_bundle_files(source, destination)
    _backup_database(source / "state.sqlite", destination / "state.sqlite")

    repository_source = _source_git_path(source, receipt, "quarantine", "repository")
    remote_source = _source_git_path(source, receipt, "resume", "remote")
    portable_root = destination / "git" / "portable"
    repository = portable_root / "repository.git"
    remote = portable_root / "remote.git"
    _clone_mirror(repository_source, repository)
    _clone_mirror(remote_source, remote)

    rewritten = dict(receipt)
    quarantine = _mapping_copy(rewritten.get("quarantine"), "quarantine")
    resume = _mapping_copy(rewritten.get("resume"), "resume")
    quarantine["repository"] = repository.relative_to(destination).as_posix()
    resume["remote"] = remote.relative_to(destination).as_posix()
    rewritten["quarantine"] = quarantine
    rewritten["resume"] = resume
    _rewrite_live_attempt_paths(rewritten, source)

    requirements = _manifest_path_map(manifest)
    requirements.setdefault("R-17", []).append(destination / "state.sqlite")
    repository_files = _regular_tree_files(repository)
    remote_files = _regular_tree_files(remote)
    for requirement_id in ("R-10", "R-11"):
        requirements.setdefault(requirement_id, []).extend(repository_files)
    requirements.setdefault("R-16", []).extend(remote_files)
    requirements.setdefault("R-17", []).extend((*repository_files, *remote_files))
    requirements.setdefault("R-14", []).extend(_live_codex_internal_files(destination))
    _rebuild_bundle_receipt(
        destination,
        receipt=rewritten,
        requirements=requirements,
        required_ids=LIVE_REQUIREMENT_IDS,
        receipt_name="portable-receipt.json",
        manifest_name="portable-proof-manifest.json",
        digest_name="portable-receipt.sha256",
        attestation_kind="portable-run",
    )
    _initialize_attestation_database(destination)
    _register_attestation_receipt(
        destination,
        receipt_name="portable-receipt.json",
        manifest_name="portable-proof-manifest.json",
        attestation_kind="portable-run",
    )
    verify_bundle(
        destination,
        strict=False,
        required_requirement_ids=LIVE_REQUIREMENT_IDS,
    )


def _copy_bundle_files(source: Path, destination: Path) -> None:
    for path in _walk_regular_files(source):
        relative = path.relative_to(source)
        if relative.name in {"state.sqlite", "state.sqlite-wal", "state.sqlite-shm"}:
            continue
        if relative.name in {
            "attestation-state.sqlite",
            "attestation-state.sqlite-wal",
            "attestation-state.sqlite-shm",
        }:
            continue
        if relative.parts[:2] == ("git", "portable"):
            continue
        payload = path.read_bytes()
        if any(pattern.search(payload) for pattern in _SECRET_LIKE_OUTPUT_PATTERNS):
            raise IntegrityError(
                "live proof bundle contains a secret-like value and cannot be released"
            )
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def _backup_database(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise IntegrityError(f"state database is missing or unsafe: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        destination_connection = sqlite3.connect(destination)
        try:
            source_connection.backup(destination_connection)
        finally:
            destination_connection.close()
            source_connection.close()
    except sqlite3.Error as exc:
        raise IntegrityError(f"cannot consolidate state database {source}: {exc}") from exc


def _clone_mirror(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ("git", "clone", "--mirror", "--no-hardlinks", str(source), str(destination)),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise IntegrityError(
            f"cannot create portable Git mirror: {result.stderr.strip() or result.stdout.strip()}"
        )
    remove_origin = subprocess.run(
        ("git", "-C", str(destination), "remote", "remove", "origin"),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if remove_origin.returncode != 0:
        raise IntegrityError("cannot detach portable Git mirror from its source")
    _regular_tree_files(destination)


def _copy_crash_evidence(
    destination: Path,
    *,
    report_path: Path,
) -> tuple[Path, ...]:
    report = _load_object(report_path)
    producer = report.get("producer")
    source = producer.get("source") if isinstance(producer, Mapping) else None
    if (
        not isinstance(source, Mapping)
        or source.get("artifact_path") != "producer/source/crashbench.py"
    ):
        raise IntegrityError("CrashBench producer source binding is malformed")
    stages = report.get("stages")
    if not isinstance(stages, list) or len(stages) != 11:
        raise IntegrityError("CrashBench report does not contain exactly 11 stages")
    source_root = report_path.parent.resolve()
    crash_root = destination / "release-evidence" / "crash"
    crash_root.mkdir(parents=True, exist_ok=True)
    relative_paths = ["producer/source/crashbench.py"]
    for stage in stages:
        snapshots = stage.get("snapshots") if isinstance(stage, Mapping) else None
        if not isinstance(snapshots, Mapping):
            raise IntegrityError("CrashBench stage snapshot binding is malformed")
        for phase in ("pre_restart", "after_first_recovery", "after_second_recovery"):
            snapshot = snapshots.get(phase)
            path = snapshot.get("path") if isinstance(snapshot, Mapping) else None
            if not isinstance(path, str):
                raise IntegrityError("CrashBench snapshot path is missing")
            relative_paths.append(path)
    if len(relative_paths) != 34 or len(set(relative_paths)) != 34:
        raise IntegrityError("CrashBench artifact inventory is incomplete or duplicated")
    copied: list[Path] = []
    for relative in relative_paths:
        source_path = (source_root / relative).resolve()
        if source_root not in source_path.parents or not source_path.is_file():
            raise IntegrityError("CrashBench artifact escapes or is missing from its report root")
        target = (crash_root / relative).resolve()
        if crash_root.resolve() not in target.parents:
            raise IntegrityError("CrashBench copied artifact escapes its release root")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        copied.append(target)
    rewritten = dict(report)
    rewritten.pop("report_digest", None)
    rewritten["artifact_root"] = "."
    rewritten["report_path"] = "report.json"
    rewritten["report_digest"] = canonical_digest(rewritten)
    copied_report = crash_root / "report.json"
    _write_json(copied_report, rewritten)
    return (copied_report, *copied)


def _copy_benchmark_evidence(destination: Path, *, report_path: Path) -> tuple[Path, ...]:
    report = _load_object(report_path)
    producer = report.get("producer")
    source = producer.get("source") if isinstance(producer, Mapping) else None
    if not isinstance(source, Mapping) or source.get("artifact_path") != "producer/benchmarks.py":
        raise IntegrityError("benchmark producer source artifact binding is malformed")
    producer_source = (report_path.parent / "producer/benchmarks.py").resolve()
    if report_path.parent.resolve() not in producer_source.parents:
        raise IntegrityError("benchmark producer source escapes its report root")
    if (
        not producer_source.is_file()
        or sha256_digest(producer_source.read_bytes()) != source.get("sha256")
    ):
        raise IntegrityError("benchmark producer source artifact changed")
    trials = report.get("trials")
    if not isinstance(trials, list) or len(trials) != 20:
        raise IntegrityError("benchmark report does not describe exactly 20 trials")
    benchmark_root = destination / "release-evidence" / "benchmark"
    state_root = benchmark_root / "state"
    state_root.mkdir(parents=True, exist_ok=True)
    copied_source = benchmark_root / "producer" / "benchmarks.py"
    copied_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(producer_source, copied_source)
    copied_databases: list[Path] = []
    for index, trial in enumerate(trials):
        if not isinstance(trial, Mapping):
            raise IntegrityError("benchmark trial record is malformed")
        relative = trial.get("state_database")
        expected = f"state/trial-{index:02d}.sqlite3"
        if relative != expected:
            raise IntegrityError("benchmark trial database path is not canonical")
        source_database = (report_path.parent / expected).resolve()
        if report_path.parent.resolve() not in source_database.parents:
            raise IntegrityError("benchmark database escapes its report root")
        copied = benchmark_root / expected
        _backup_database(source_database, copied)
        copied_databases.append(copied)
    rewritten = dict(report)
    rewritten["artifact_root"] = "."
    rewritten["report_path"] = "report.json"
    copied_report = benchmark_root / "report.json"
    _write_json(copied_report, rewritten)
    return (copied_report, copied_source, *copied_databases)


def _copy_qualification_evidence(
    destination: Path,
    *,
    source_journal: Path,
    source_qualification: QualificationJournalProof,
) -> tuple[Path, QualificationJournalProof]:
    source_root = source_journal.parent.resolve()
    target_root = destination / "release-evidence" / "r20" / "qualification"
    target_root.mkdir(parents=True, exist_ok=True)
    bundle_roots = set(source_qualification.bundle_roots)
    for path in _walk_regular_files(source_root):
        if any(bundle == path or bundle in path.parents for bundle in bundle_roots):
            continue
        payload = path.read_bytes()
        if any(pattern.search(payload) for pattern in _SECRET_LIKE_OUTPUT_PATTERNS):
            raise IntegrityError(
                "qualification evidence contains a secret-like value and cannot be released"
            )
        relative = path.relative_to(source_root)
        target = target_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    source_record = _load_object(source_journal)
    source_binding = source_record.get("source")
    if not isinstance(source_binding, Mapping):
        raise IntegrityError("qualification source binding is missing")
    recorded_workspace = Path(str(source_binding.get("recorded_workspace_root", "")))
    source_commit = str(source_binding.get("source_commit", ""))
    source_manifest_source = (
        source_root / str(source_binding.get("source_manifest_path", ""))
    ).resolve()
    source_manifest = _load_object(source_manifest_source)
    verify_source_repository(
        recorded_workspace,
        source_commit=source_commit,
        source_manifest=source_manifest,
    )
    portable_source_repository = target_root / "source" / "repository.git"
    _clone_mirror(recorded_workspace, portable_source_repository)
    attempts = source_record.get("attempts")
    if not isinstance(attempts, list):
        raise IntegrityError("qualification attempts are missing")
    rewritten_attempts: list[dict[str, Any]] = []
    for index, (attempt_raw, bundle_source) in enumerate(
        zip(attempts, source_qualification.bundle_roots, strict=True),
        1,
    ):
        if not isinstance(attempt_raw, Mapping):
            raise IntegrityError("qualification attempt is malformed")
        relative_bundle = Path(str(attempt_raw.get("artifact_root", "")))
        target_bundle = (target_root / relative_bundle).resolve()
        if target_root.resolve() not in target_bundle.parents:
            raise IntegrityError("qualification bundle escapes its copied root")
        target_bundle.mkdir(parents=True)
        _portable_copy_bundle(bundle_source, target_bundle)
        copied_receipt = target_bundle / "receipt.json"
        rewritten = dict(attempt_raw)
        rewritten["attempt_index"] = index
        rewritten["receipt_sha256"] = sha256_digest(copied_receipt.read_bytes())
        rewritten_attempts.append(rewritten)
    rewritten_record = dict(source_record)
    rewritten_record.pop("integrity", None)
    rewritten_source = dict(source_binding)
    rewritten_source["source_repository"] = portable_source_repository.relative_to(
        target_root
    ).as_posix()
    rewritten_record["source"] = rewritten_source
    rewritten_record["attempts"] = rewritten_attempts
    rewritten_record["integrity"] = {"canonical_digest": canonical_digest(rewritten_record)}
    copied_journal = target_root / source_journal.name
    _write_json(copied_journal, rewritten_record)
    copied = verify_qualification_journal(copied_journal)
    return copied_journal, copied


def _write_release_ledger(
    root: Path,
    *,
    journal_path: Path,
    qualification: QualificationJournalProof,
) -> Path:
    runs: list[dict[str, Any]] = []
    for index, bundle_root in enumerate(qualification.bundle_roots, 1):
        verified = verify_bundle(
            bundle_root,
            strict=False,
            required_requirement_ids=LIVE_REQUIREMENT_IDS,
        )
        runs.append(
            {
                "ordinal": index,
                "artifact_root": bundle_root.relative_to(root).as_posix(),
                "run_id": verified.run_id,
                "case_id": verified.case_id,
                "receipt_digest": verified.receipt_digest,
                "event_head_digest": verified.event_head_digest,
                "affected_effect_ids": list(verified.affected_effect_ids),
                "checked_requirements": list(verified.checked_requirements),
                "provider": "live-codex",
                "fallback_used": False,
            }
        )
    ledger: dict[str, Any] = {
        "protocol": "tars.release-runs/v1",
        "trust_boundary": (
            "host-owner-generated qualification journal; no external trusted witness"
        ),
        "required_consecutive_runs": 3,
        "fallback_used": False,
        "qualification": {
            "journal_path": journal_path.relative_to(root).as_posix(),
            "journal_sha256": sha256_digest(journal_path.read_bytes()),
            "source_commit": qualification.source_commit,
            "source_tree_digest": qualification.source_tree_digest,
            "tars_revoke_executable": qualification.tars_revoke_executable,
            "tars_revoke_executable_sha256": qualification.tars_revoke_executable_sha256,
            "python_invocation_path": qualification.python_invocation_path,
            "python_resolved_path": qualification.python_resolved_path,
            "python_executable_sha256": qualification.python_executable_sha256,
            "python_runtime_inventory_digest": (
                qualification.python_runtime_inventory_digest
            ),
            "codex_executable": qualification.codex_executable,
            "codex_executable_sha256": qualification.codex_executable_sha256,
            "codex_executable_version": qualification.codex_executable_version,
            "codex_strict_signature_valid": qualification.codex_strict_signature_valid,
        },
        "runs": runs,
    }
    ledger["integrity"] = {"canonical_digest": canonical_digest(ledger)}
    ledger_path = root / "release-evidence" / "r20" / "ledger.json"
    _write_json(ledger_path, ledger)
    return ledger_path


def _attest_release_root(
    root: Path,
    *,
    crash_paths: Sequence[Path],
    benchmark_paths: Sequence[Path],
    qualification_root: Path,
    qualification_journal: Path,
    qualification: QualificationJournalProof,
    ledger_path: Path,
) -> BundleVerification:
    receipt = _load_object(root / "portable-receipt.json")
    manifest = _load_object(root / "portable-proof-manifest.json")
    requirements = _manifest_path_map(manifest)
    requirements["R-18"] = list(crash_paths)
    requirements["R-19"] = list(benchmark_paths)
    requirements["R-20"] = [ledger_path, *_regular_tree_files(qualification_root)]

    rewritten = dict(receipt)
    rewritten.pop("integrity", None)
    rewritten["proof_scope"] = list(DEFAULT_REQUIREMENT_IDS)
    verification = _mapping_copy(rewritten.get("verification"), "verification")
    verification["proof_scope"] = list(DEFAULT_REQUIREMENT_IDS)
    rewritten["verification"] = verification
    limitations = rewritten.get("limitations")
    retained = (
        [
            str(item)
            for item in limitations
            if isinstance(item, str)
            and not item.startswith(("R-01", "R-18", "R-19", "R-20"))
        ]
        if isinstance(limitations, list)
        else []
    )
    signature_limitation = (
        []
        if qualification.codex_strict_signature_valid
        else [CODEX_SIGNATURE_LIMITATION]
    )
    rewritten["limitations"] = [
        *retained,
        QUALIFICATION_TRUST_LIMITATION,
        *signature_limitation,
    ]
    rewritten["release_attestation"] = {
        "qualification_journal": qualification_journal.relative_to(root).as_posix(),
        "release_ledger": ledger_path.relative_to(root).as_posix(),
        "requirements": list(DEFAULT_REQUIREMENT_IDS),
    }
    _rebuild_bundle_receipt(
        root,
        receipt=rewritten,
        requirements=requirements,
        required_ids=DEFAULT_REQUIREMENT_IDS,
        receipt_name="release-attestation.json",
        manifest_name="release-proof-manifest.json",
        digest_name="release-attestation.sha256",
        attestation_kind="release-r01-r20",
    )
    _register_attestation_receipt(
        root,
        receipt_name="release-attestation.json",
        manifest_name="release-proof-manifest.json",
        attestation_kind="release-r01-r20",
    )
    return verify_bundle(root, strict=True)


def _rebuild_bundle_receipt(
    root: Path,
    *,
    receipt: Mapping[str, Any],
    requirements: Mapping[str, Iterable[Path]],
    required_ids: Sequence[str],
    receipt_name: str,
    manifest_name: str,
    digest_name: str,
    attestation_kind: str,
) -> None:
    receipt_fields = dict(receipt)
    integrity = receipt_fields.pop("integrity", None)
    if not isinstance(integrity, Mapping):
        raise IntegrityError("source receipt integrity is missing")
    event_head = integrity.get("event_head_digest")
    if not isinstance(event_head, str):
        raise IntegrityError("source receipt event head is missing")
    limitations = receipt_fields.get("limitations")
    sidecar_limitation = (
        "Attestation Receipt rows live in an unhashed sidecar SQLite database to avoid "
        "self-referential hashing; the verifier re-derives every row field from bound bytes."
    )
    if isinstance(limitations, list) and sidecar_limitation not in limitations:
        receipt_fields["limitations"] = [*limitations, sidecar_limitation]
    receipt_fields["attestation"] = {
        "kind": attestation_kind,
        "canonical_receipt_path": "receipt.json",
        "canonical_receipt_sha256": sha256_digest((root / "receipt.json").read_bytes()),
        "canonical_manifest_path": "proof-manifest.json",
        "canonical_manifest_sha256": sha256_digest(
            (root / "proof-manifest.json").read_bytes()
        ),
        "receipt_row_database_path": "attestation-state.sqlite",
    }
    deduplicated = {
        requirement: sorted(set(paths), key=lambda path: path.as_posix())
        for requirement, paths in requirements.items()
    }
    manifest = ReceiptBuilder.build_manifest(
        artifact_root=root,
        requirement_artifacts=deduplicated,
        required_requirement_ids=required_ids,
    )
    built = ReceiptBuilder.build(
        receipt_fields=receipt_fields,
        proof_manifest=manifest,
        event_head_digest=event_head,
    )
    _write_json(root / manifest_name, manifest)
    _write_json(root / receipt_name, built.payload)
    (root / digest_name).write_text(
        f"{sha256_digest((root / receipt_name).read_bytes())}\n",
        encoding="ascii",
    )


def _initialize_attestation_database(root: Path) -> None:
    destination = root / "attestation-state.sqlite"
    destination.unlink(missing_ok=True)
    _backup_database(root / "state.sqlite", destination)


def _register_attestation_receipt(
    root: Path,
    *,
    receipt_name: str,
    manifest_name: str,
    attestation_kind: str,
) -> None:
    receipt_path = root / receipt_name
    manifest_path = root / manifest_name
    payload = _load_object(receipt_path)
    manifest = _load_object(manifest_path)
    integrity = payload.get("integrity")
    proof_scope = payload.get("proof_scope")
    if not isinstance(integrity, Mapping) or not isinstance(proof_scope, list):
        raise IntegrityError("attestation receipt integrity or proof scope is malformed")
    store = Store(root / "attestation-state.sqlite")
    run_id = str(payload.get("run_id", ""))
    case_id = str(payload.get("case_id", ""))
    if store.get_run(run_id) is None or store.get_revocation_case(case_id) is None:
        raise IntegrityError("attestation receipt has no durable run or revocation case")
    raw_receipt = receipt_path.read_bytes()
    artifacts = ArtifactStore(root / "objects", clock=store.clock)
    artifact = artifacts.put_bytes(
        raw_receipt,
        media_type="application/json",
        metadata={"kind": attestation_kind, "run_id": run_id},
    )
    stored_artifact = store.get_artifact(artifact.digest)
    if stored_artifact is None:
        store.create_artifact(artifact)
    elif (
        stored_artifact.size != artifact.size
        or stored_artifact.media_type != artifact.media_type
        or stored_artifact.relative_path != artifact.relative_path
    ):
        raise IntegrityError("attestation receipt artifact row is inconsistent")
    now = store.clock.utc_now()
    store.create_receipt(
        Receipt(
            id=f"{run_id}:attestation:{attestation_kind}",
            run_id=run_id,
            case_id=case_id,
            state=ReceiptState.VERIFIED,
            artifact_digest=artifact.digest,
            canonical_digest=str(integrity.get("receipt_digest", "")),
            event_head_digest=str(integrity.get("event_head_digest", "")),
            manifest_digest=canonical_digest(manifest),
            created_at=now,
            verified_at=now,
            metadata={
                "kind": attestation_kind,
                "receipt_path": receipt_name,
                "manifest_path": manifest_name,
                "proof_scope": proof_scope,
                "database_excluded_from_manifest": True,
            },
        )
    )


def _manifest_path_map(manifest: Mapping[str, Any]) -> dict[str, list[Path]]:
    requirements = manifest.get("requirements")
    if not isinstance(requirements, Mapping):
        raise IntegrityError("proof manifest requirements are missing")
    result: dict[str, list[Path]] = {}
    for requirement_id, entries in requirements.items():
        if not isinstance(requirement_id, str) or not isinstance(entries, list):
            raise IntegrityError("proof manifest requirement is malformed")
        paths: list[Path] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
                raise IntegrityError("proof manifest entry is malformed")
            paths.append(Path(str(entry["path"])))
        result[requirement_id] = paths
    return result


def _source_git_path(
    root: Path,
    receipt: Mapping[str, Any],
    section_name: str,
    field_name: str,
) -> Path:
    section = receipt.get(section_name)
    if not isinstance(section, Mapping):
        raise IntegrityError(f"receipt {section_name} section is missing")
    raw = section.get(field_name)
    if not isinstance(raw, str) or not raw:
        raise IntegrityError(f"receipt {section_name}.{field_name} path is missing")
    path = Path(raw).expanduser()
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    if not path.is_absolute() and (resolved == root or root not in resolved.parents):
        raise IntegrityError("receipt Git proof path escapes its bundle")
    if not resolved.is_dir() or resolved.is_symlink():
        raise IntegrityError("receipt Git proof path is missing or unsafe")
    return resolved


def _rewrite_live_attempt_paths(receipt: dict[str, Any], source_root: Path) -> None:
    experiment = receipt.get("experiment")
    if not isinstance(experiment, Mapping):
        return
    attempts = experiment.get("live_proposal_attempts")
    if not isinstance(attempts, list):
        return
    rewritten_attempts: list[dict[str, Any]] = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            raise IntegrityError("live proposal attempt is malformed")
        rewritten = dict(attempt)
        for key in ("manifest_path", "events_path", "event_observations_path"):
            raw = rewritten.get(key)
            if not isinstance(raw, str) or not raw:
                raise IntegrityError(f"live proposal attempt {key} is missing")
            path = Path(raw).expanduser()
            resolved = path.resolve() if path.is_absolute() else (source_root / path).resolve()
            if resolved == source_root or source_root not in resolved.parents:
                raise IntegrityError(f"live proposal attempt {key} escapes its bundle")
            if not resolved.is_file() or resolved.is_symlink():
                raise IntegrityError(f"live proposal attempt {key} is missing or unsafe")
            rewritten[key] = resolved.relative_to(source_root).as_posix()
        rewritten_attempts.append(rewritten)
    rewritten_experiment = dict(experiment)
    rewritten_experiment["live_proposal_attempts"] = rewritten_attempts
    receipt["experiment"] = rewritten_experiment


def _live_codex_internal_files(root: Path) -> list[Path]:
    live_root = root / "agents" / "live-codex"
    if not live_root.is_dir() or live_root.is_symlink():
        raise IntegrityError("live Codex artifact directory is missing")
    return _regular_tree_files(live_root)


def _walk_regular_files(root: Path) -> Iterable[Path]:
    root = root.resolve(strict=True)
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise IntegrityError(f"proof tree contains a symlink: {path}")
        if path.is_file():
            yield path


def _regular_tree_files(root: Path) -> list[Path]:
    return list(_walk_regular_files(root))


def _regular_file(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"{label} must be a regular non-symlink file: {path}")
    return path


def _mapping_copy(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrityError(f"receipt {label} section is missing")
    return dict(value)


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"JSON artifact must contain an object: {path}")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value), encoding="utf-8")
