from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from tars_revoke.adapters._safety import is_python_executable
from tars_revoke.demo.concurrency import verify_concurrent_codex_proof
from tars_revoke.demo.experiment_contract import HYPOTHESES, matching_hypotheses
from tars_revoke.demo.experiment_sandbox import (
    EXPERIMENT_ENVIRONMENT,
    SANDBOX_BACKEND,
    render_macos_profile,
)
from tars_revoke.demo.release_proofs import (
    requirement_paths,
    verify_crash_recovery,
    verify_live_codex_repair,
    verify_release_runs,
    verify_revokebench,
)
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import (
    EffectState,
    ExperimentState,
    LeaseState,
    ReceiptState,
    RevocationMemberKind,
    SessionState,
    TestState,
)
from tars_revoke.domain.models import ExperimentCandidate
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence.store import Store
from tars_revoke.services.experiments import ExperimentSelector
from tars_revoke.services.receipts import (
    DEFAULT_REQUIREMENT_IDS,
    StrictReceiptVerifier,
)

CORE_REQUIREMENT_IDS = tuple(f"R-{index:02d}" for index in (*range(2, 14), *range(15, 18)))

_CANONICAL_AUTHORIZATION_TYPES = {
    "agent-a-v1-local-commit": ("LOCAL_COMMIT", "LOCAL_COMMIT"),
    "agent-a-v1-migration": ("DATABASE_MIGRATION", "DATABASE_MIGRATION"),
    "agent-a-v1-push": ("PUSH", "PUSH"),
    "agent-b-observability-local-commit": ("LOCAL_COMMIT", "LOCAL_COMMIT"),
    "agent-b-observability-push": ("PUSH", "PUSH"),
    "agent-a-v2-decisive-experiment": ("EXPERIMENT", "COMMAND"),
    "agent-a-v2-repair-local-commit": ("LOCAL_COMMIT", "LOCAL_COMMIT"),
    "agent-a-v2-migration": ("DATABASE_MIGRATION", "DATABASE_MIGRATION"),
    "agent-a-v2-targeted-test": ("TEST", "COMMAND"),
    "agent-a-v2-full-test": ("TEST", "COMMAND"),
    "agent-a-v2-push": ("PUSH", "PUSH"),
}


@dataclass(frozen=True)
class BundleVerification:
    valid: bool
    run_id: str
    case_id: str
    receipt_digest: str
    event_head_digest: str
    affected_effect_ids: tuple[str, ...]
    checked_requirements: tuple[str, ...]
    checks: Mapping[str, bool]


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read JSON proof artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"proof artifact must contain a JSON object: {path}")
    return value


def _string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IntegrityError(f"receipt {label} must be a string list")
    return tuple(value)


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise IntegrityError(
            f"Git proof check failed ({' '.join(args[:2])}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def _git_worktree_manifest(repository: Path, commit: str) -> dict[str, dict[str, Any]]:
    result = subprocess.run(
        ("git", "-C", str(repository), "ls-tree", "-r", "-z", "--full-tree", commit),
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise IntegrityError("cannot enumerate the decisive experiment Git tree")
    manifest: dict[str, dict[str, Any]] = {}
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError) as exc:
            raise IntegrityError("Git returned a malformed decisive experiment tree") from exc
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise IntegrityError("decisive experiment tree contains an unsupported entry")
        blob = subprocess.run(
            ("git", "-C", str(repository), "cat-file", "blob", object_id),
            check=False,
            capture_output=True,
            timeout=30,
        )
        if blob.returncode != 0:
            raise IntegrityError("cannot read a decisive experiment Git blob")
        manifest[path] = {
            "path": path,
            "sha256": sha256_digest(blob.stdout),
            "size": len(blob.stdout),
            "mode": 0o755 if mode == "100755" else 0o644,
        }
    if not manifest:
        raise IntegrityError("decisive experiment Git tree is empty")
    return manifest


def _relative_proof_file(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise IntegrityError(f"R-13 {label} must be a bundle-relative path")
    path = (root / value).resolve()
    if root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise IntegrityError(f"R-13 {label} is missing or unsafe")
    return path


def _proof_object_bytes(root: Path, value: object, *, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise IntegrityError(f"R-13 {label} artifact digest is malformed")
    path = root / "objects" / value[:2] / value[2:]
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"R-13 {label} artifact is missing or unsafe")
    payload = path.read_bytes()
    if sha256_digest(payload) != value:
        raise IntegrityError(f"R-13 {label} artifact digest changed")
    return payload


def _receipt_git_path(
    root: Path,
    value: object,
    *,
    label: str,
    portable_required: bool,
) -> Path:
    raw = str(value or "")
    candidate = Path(raw).expanduser()
    if portable_required and candidate.is_absolute():
        raise IntegrityError(f"strict release {label} must be bundle-relative")
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    if not candidate.is_absolute() and (resolved == root or root not in resolved.parents):
        raise IntegrityError(f"receipt {label} escapes the artifact bundle")
    if not resolved.is_dir() or resolved.is_symlink():
        raise IntegrityError(f"receipt {label} path is missing")
    return resolved


def _required_ids(manifest: Mapping[str, Any], *, strict: bool) -> tuple[str, ...]:
    if strict:
        return DEFAULT_REQUIREMENT_IDS
    requirements = manifest.get("requirements")
    if not isinstance(requirements, Mapping):
        raise IntegrityError("proof manifest requirements are missing")
    present = tuple(
        sorted(
            str(key)
            for key, entries in requirements.items()
            if str(key) in CORE_REQUIREMENT_IDS and isinstance(entries, list) and entries
        )
    )
    missing_core = sorted(set(CORE_REQUIREMENT_IDS) - set(present))
    if missing_core:
        raise IntegrityError(f"core proof requirements missing: {', '.join(missing_core)}")
    r01_entries = requirements.get("R-01")
    if isinstance(r01_entries, list) and r01_entries:
        present = tuple(sorted((*present, "R-01")))
    return present


def _select_proof_files(
    root: Path,
    *,
    strict: bool,
    required_requirement_ids: Iterable[str] | None,
) -> tuple[Path, Path, Path, str | None]:
    requested = set(required_requirement_ids or ())
    release = root / "release-attestation.json"
    if release.is_file() and (strict or "R-20" in requested):
        return (
            release,
            root / "release-proof-manifest.json",
            root / "release-attestation.sha256",
            "release-r01-r20",
        )
    portable = root / "portable-receipt.json"
    if portable.is_file():
        return (
            portable,
            root / "portable-proof-manifest.json",
            root / "portable-receipt.sha256",
            "portable-run",
        )
    return root / "receipt.json", root / "proof-manifest.json", root / "receipt.sha256", None


def _verify_durable_canonical_receipt(
    root: Path,
    *,
    store: Store,
    selected_receipt: Mapping[str, Any],
    attestation_kind: str | None,
) -> bool:
    canonical_path = root / "receipt.json"
    canonical_manifest_path = root / "proof-manifest.json"
    canonical = _load_object(canonical_path)
    canonical_manifest = _load_object(canonical_manifest_path)
    scope = canonical.get("proof_scope")
    if not isinstance(scope, list) or not scope or any(not isinstance(item, str) for item in scope):
        raise IntegrityError("canonical receipt proof scope is malformed")
    canonical_verification = StrictReceiptVerifier.verify(
        payload=canonical,
        proof_manifest=canonical_manifest,
        artifact_root=root,
        required_requirement_ids=tuple(scope),
    )
    if attestation_kind is not None:
        _verify_attestation_binding(
            root,
            selected_receipt=selected_receipt,
            canonical_receipt=canonical,
            expected_kind=attestation_kind,
        )
    elif selected_receipt != canonical:
        raise IntegrityError("selected canonical receipt bytes are inconsistent")

    run_id = str(canonical.get("run_id", ""))
    case_id = str(canonical.get("case_id", ""))
    rows = store.list_receipts(run_id, case_id=case_id)
    if len(rows) != 1:
        raise IntegrityError("durable state must contain exactly one canonical receipt row")
    row = rows[0]
    integrity = canonical.get("integrity")
    if not isinstance(integrity, Mapping):
        raise IntegrityError("canonical receipt integrity is missing")
    expected = (
        row.state == ReceiptState.VERIFIED
        and row.canonical_digest == canonical_verification.receipt_digest
        and row.manifest_digest == canonical_verification.manifest_digest
        and row.event_head_digest == integrity.get("event_head_digest")
        and row.artifact_digest == sha256_digest(canonical_path.read_bytes())
    )
    if not expected or row.artifact_digest is None:
        raise IntegrityError("durable receipt row differs from canonical receipt bytes")
    artifact_path = root / "objects" / row.artifact_digest[:2] / row.artifact_digest[2:]
    if (
        not artifact_path.is_file()
        or artifact_path.is_symlink()
        or artifact_path.read_bytes() != canonical_path.read_bytes()
    ):
        raise IntegrityError("durable canonical receipt artifact is missing or changed")
    if attestation_kind is not None:
        _verify_durable_attestation_receipts(
            root,
            canonical_receipt=canonical,
            selected_kind=attestation_kind,
        )
    return True


def _verify_attestation_binding(
    root: Path,
    *,
    selected_receipt: Mapping[str, Any],
    canonical_receipt: Mapping[str, Any],
    expected_kind: str,
) -> None:
    attestation = selected_receipt.get("attestation")
    if not isinstance(attestation, Mapping) or set(attestation) != {
        "kind",
        "canonical_receipt_path",
        "canonical_receipt_sha256",
        "canonical_manifest_path",
        "canonical_manifest_sha256",
        "receipt_row_database_path",
    }:
        raise IntegrityError("portable receipt attestation binding is malformed")
    if attestation.get("kind") != expected_kind:
        raise IntegrityError("portable receipt attestation kind is incorrect")
    if attestation.get("receipt_row_database_path") != "attestation-state.sqlite":
        raise IntegrityError("portable receipt row database binding is incorrect")
    expected_paths = {
        "canonical_receipt_path": root / "receipt.json",
        "canonical_manifest_path": root / "proof-manifest.json",
    }
    for path_key, path in expected_paths.items():
        if attestation.get(path_key) != path.name:
            raise IntegrityError("portable receipt canonical path binding is incorrect")
        digest_key = path_key.replace("_path", "_sha256")
        if attestation.get(digest_key) != sha256_digest(path.read_bytes()):
            raise IntegrityError("portable receipt canonical digest binding changed")
    if _receipt_semantic_body(selected_receipt) != _receipt_semantic_body(canonical_receipt):
        raise IntegrityError("portable receipt changes canonical run semantics")


def _verify_durable_attestation_receipts(
    root: Path,
    *,
    canonical_receipt: Mapping[str, Any],
    selected_kind: str,
) -> None:
    database_path = root / "attestation-state.sqlite"
    if not database_path.is_file() or database_path.is_symlink():
        raise IntegrityError("attestation receipt row database is missing")
    records: list[tuple[str, Mapping[str, Any], Mapping[str, Any], Path]] = []
    portable_receipt = _load_object(root / "portable-receipt.json")
    portable_manifest = _load_object(root / "portable-proof-manifest.json")
    portable_scope = _string_list(portable_receipt.get("proof_scope"), label="proof scope")
    StrictReceiptVerifier.verify(
        payload=portable_receipt,
        proof_manifest=portable_manifest,
        artifact_root=root,
        required_requirement_ids=portable_scope,
    )
    _verify_attestation_binding(
        root,
        selected_receipt=portable_receipt,
        canonical_receipt=canonical_receipt,
        expected_kind="portable-run",
    )
    records.append(
        (
            "portable-run",
            portable_receipt,
            portable_manifest,
            root / "portable-receipt.json",
        )
    )
    if selected_kind == "release-r01-r20":
        release_receipt = _load_object(root / "release-attestation.json")
        release_manifest = _load_object(root / "release-proof-manifest.json")
        records.append(
            (
                "release-r01-r20",
                release_receipt,
                release_manifest,
                root / "release-attestation.json",
            )
        )
    elif selected_kind != "portable-run":
        raise IntegrityError("unsupported durable attestation receipt kind")

    store = Store(database_path)
    run_id = str(canonical_receipt.get("run_id", ""))
    case_id = str(canonical_receipt.get("case_id", ""))
    rows = store.list_receipts(run_id, case_id=case_id)
    expected_kinds = {kind for kind, _, _, _ in records}
    attestation_rows = [
        row
        for row in rows
        if row.metadata.get("kind") in {"portable-run", "release-r01-r20"}
    ]
    if {str(row.metadata.get("kind")) for row in attestation_rows} != expected_kinds or len(
        attestation_rows
    ) != len(expected_kinds):
        raise IntegrityError("durable attestation receipt rows are missing or duplicated")
    for kind, payload, manifest, receipt_path in records:
        _verify_attestation_receipt_row(
            root,
            store=store,
            rows=attestation_rows,
            kind=kind,
            payload=payload,
            manifest=manifest,
            receipt_path=receipt_path,
        )
    if len({row.id for row in attestation_rows}) != len(attestation_rows) or len(
        {row.canonical_digest for row in attestation_rows}
    ) != len(attestation_rows):
        raise IntegrityError("portable and release attestations are not distinct receipts")


def _verify_attestation_receipt_row(
    root: Path,
    *,
    store: Store,
    rows: Iterable[Any],
    kind: str,
    payload: Mapping[str, Any],
    manifest: Mapping[str, Any],
    receipt_path: Path,
) -> None:
    matches = [row for row in rows if row.metadata.get("kind") == kind]
    if len(matches) != 1:
        raise IntegrityError(f"durable {kind} receipt row is missing or duplicated")
    row = matches[0]
    integrity = payload.get("integrity")
    proof_scope = payload.get("proof_scope")
    if not isinstance(integrity, Mapping) or not isinstance(proof_scope, list):
        raise IntegrityError(f"{kind} receipt integrity is malformed")
    manifest_name = (
        "portable-proof-manifest.json"
        if kind == "portable-run"
        else "release-proof-manifest.json"
    )
    expected_metadata = {
        "kind": kind,
        "receipt_path": receipt_path.name,
        "manifest_path": manifest_name,
        "proof_scope": proof_scope,
        "database_excluded_from_manifest": True,
    }
    raw = receipt_path.read_bytes()
    artifact_digest = sha256_digest(raw)
    if (
        row.id != f"{row.run_id}:attestation:{kind}"
        or row.run_id != payload.get("run_id")
        or row.case_id != payload.get("case_id")
        or row.state != ReceiptState.VERIFIED
        or row.verified_at != row.created_at
        or row.artifact_digest != artifact_digest
        or row.canonical_digest != integrity.get("receipt_digest")
        or row.event_head_digest != integrity.get("event_head_digest")
        or row.manifest_digest != canonical_digest(manifest)
        or row.metadata != expected_metadata
    ):
        raise IntegrityError(f"durable {kind} receipt row differs from attestation bytes")
    artifact = store.get_artifact(artifact_digest)
    object_path = root / "objects" / artifact_digest[:2] / artifact_digest[2:]
    if (
        artifact is None
        or artifact.size != len(raw)
        or artifact.media_type != "application/json"
        or artifact.relative_path != f"{artifact_digest[:2]}/{artifact_digest[2:]}"
        or not object_path.is_file()
        or object_path.is_symlink()
        or object_path.read_bytes() != raw
    ):
        raise IntegrityError(f"durable {kind} receipt artifact is missing or changed")
    event_hashes = {event.event_hash for event in store.journal.list_events(row.run_id)}
    if row.event_head_digest not in event_hashes:
        raise IntegrityError(f"durable {kind} event head is absent from its journal")
    requirements = manifest.get("requirements")
    if not isinstance(requirements, Mapping) or any(
        isinstance(entry, Mapping) and entry.get("path") == "attestation-state.sqlite"
        for entries in requirements.values()
        if isinstance(entries, list)
        for entry in entries
    ):
        raise IntegrityError("attestation sidecar must be excluded from its own manifest")


def _receipt_semantic_body(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    body = dict(receipt)
    for key in ("integrity", "attestation", "release_attestation", "proof_scope", "limitations"):
        body.pop(key, None)
    verification = body.get("verification")
    if isinstance(verification, Mapping):
        cleaned_verification = dict(verification)
        cleaned_verification.pop("proof_scope", None)
        body["verification"] = cleaned_verification
    quarantine = body.get("quarantine")
    if isinstance(quarantine, Mapping):
        cleaned_quarantine = dict(quarantine)
        cleaned_quarantine.pop("repository", None)
        body["quarantine"] = cleaned_quarantine
    resume = body.get("resume")
    if isinstance(resume, Mapping):
        cleaned_resume = dict(resume)
        cleaned_resume.pop("remote", None)
        body["resume"] = cleaned_resume
    experiment = body.get("experiment")
    if isinstance(experiment, Mapping):
        cleaned_experiment = dict(experiment)
        attempts = cleaned_experiment.get("live_proposal_attempts")
        if isinstance(attempts, list):
            cleaned_attempts: list[object] = []
            for attempt in attempts:
                if not isinstance(attempt, Mapping):
                    cleaned_attempts.append(attempt)
                    continue
                cleaned = dict(attempt)
                for key in ("manifest_path", "events_path", "event_observations_path"):
                    cleaned.pop(key, None)
                cleaned_attempts.append(cleaned)
            cleaned_experiment["live_proposal_attempts"] = cleaned_attempts
        body["experiment"] = cleaned_experiment
    return body


def _verify_authorization_coverage(
    *,
    store: Store,
    receipt: Mapping[str, Any],
    run_id: str,
    case_id: str,
) -> bool:
    """Prove every consequential canonical action crossed the effect gateway."""

    raw_entries = receipt.get("authorizations")
    if not isinstance(raw_entries, list) or any(
        not isinstance(entry, Mapping) for entry in raw_entries
    ):
        raise IntegrityError("receipt authorization coverage is malformed")
    entries = [entry for entry in raw_entries if isinstance(entry, Mapping)]
    stages = [str(entry.get("stage", "")) for entry in entries]
    if len(stages) != len(set(stages)) or set(stages) != set(
        _CANONICAL_AUTHORIZATION_TYPES
    ):
        raise IntegrityError("receipt does not cover the exact canonical authorization stages")

    actions = {action.id: action for action in store.list_actions(run_id)}
    effects = {effect.id: effect for effect in store.list_effects(run_id)}
    leases = {lease.id: lease for lease in store.list_leases(run_id)}
    if not actions or len(actions) != len(entries):
        raise IntegrityError("durable consequential action inventory is not fully attested")
    covered_actions: set[str] = set()
    covered_effects: set[str] = set()
    covered_leases: set[str] = set()
    events = store.journal.list_events(run_id)

    for entry in entries:
        stage = str(entry.get("stage", ""))
        expected_action_type, expected_effect_type = _CANONICAL_AUTHORIZATION_TYPES[stage]
        action_payload = entry.get("action")
        effect_payload = entry.get("effect")
        warrant_payload = entry.get("warrant")
        lease_payload = entry.get("lease")
        event_payload = entry.get("event_sequences")
        premise_payload = entry.get("premise_bindings")
        if not all(
            isinstance(value, Mapping)
            for value in (
                action_payload,
                effect_payload,
                warrant_payload,
                lease_payload,
                event_payload,
            )
        ) or not isinstance(premise_payload, list):
            raise IntegrityError(f"authorization entry is incomplete for {stage}")

        action_id = str(action_payload.get("id", ""))  # type: ignore[union-attr]
        effect_id = str(effect_payload.get("id", ""))  # type: ignore[union-attr]
        warrant_id = str(warrant_payload.get("id", ""))  # type: ignore[union-attr]
        lease_id = str(lease_payload.get("id", ""))  # type: ignore[union-attr]
        action = actions.get(action_id)
        effect = effects.get(effect_id)
        warrant = store.get_warrant(warrant_id)
        lease = leases.get(lease_id)
        if action is None or effect is None or warrant is None or lease is None:
            raise IntegrityError(f"authorization entry names missing durable state for {stage}")
        if (
            action.model_dump(mode="json") != action_payload
            or effect.model_dump(mode="json") != effect_payload
            or warrant.model_dump(mode="json") != warrant_payload
            or lease.model_dump(mode="json") != lease_payload
        ):
            raise IntegrityError(f"authorization entry differs from durable state for {stage}")
        if (
            action.action_type.value != expected_action_type
            or effect.effect_type.value != expected_effect_type
            or action.warrant_id != warrant.id
            or effect.action_id != action.id
            or lease.action_id != action.id
            or lease.effect_id != effect.id
            or lease.warrant_id != warrant.id
            or action.scope != warrant.scope
            or effect.scope != action.scope
            or effect.target != action.target
            or action.target not in warrant.authorized_targets
            or dict(action.artifact_vector) != dict(warrant.artifact_hashes)
            or warrant.metadata.get("binding_stage") != stage
        ):
            raise IntegrityError(f"authorization identity or scope binding failed for {stage}")
        durable_premises = [
            binding.model_dump(mode="json")
            for binding in store.list_warrant_premises(warrant.id)
        ]
        if premise_payload != durable_premises or not durable_premises:
            raise IntegrityError(f"authorization premise binding failed for {stage}")

        transitions = {
            str(event.payload.get("to")): event.sequence
            for event in events
            if event.aggregate_type == "effect"
            and event.aggregate_id == effect.id
            and event.kind == "effect.transitioned"
        }
        expected_sequences = {
            "authorized": transitions.get(EffectState.AUTHORIZED.value),
            "dispatching": transitions.get(EffectState.DISPATCHING.value),
            "executed": transitions.get(EffectState.EXECUTED.value),
        }
        if dict(event_payload) != expected_sequences:  # type: ignore[arg-type]
            raise IntegrityError(f"authorization event binding failed for {stage}")
        authorized = expected_sequences["authorized"]
        dispatching = expected_sequences["dispatching"]
        executed = expected_sequences["executed"]
        if authorized is None:
            raise IntegrityError(f"authorization event is missing for {stage}")
        if stage == "agent-a-v1-push":
            if dispatching is not None or executed is not None or lease.state != LeaseState.REVOKED:
                raise IntegrityError("revoked v1 push was dispatched or retained a live lease")
        elif (
            dispatching is None
            or executed is None
            or not authorized < dispatching < executed
            or lease.state != LeaseState.CONSUMED
        ):
            raise IntegrityError(f"effect did not execute behind its gateway lease for {stage}")
        if expected_effect_type == "PUSH":
            metadata = effect.metadata
            required_push_metadata = {
                "repository",
                "remote",
                "remote_url",
                "destination",
                "refspec",
                "source_oid",
            }
            if not required_push_metadata.issubset(metadata) or any(
                not isinstance(metadata[key], str) or not metadata[key]
                for key in required_push_metadata
            ):
                raise IntegrityError(f"push recovery binding is incomplete for {stage}")
        if expected_effect_type == "COMMAND" and not {
            "command:argv",
            "command:cwd",
            "command:executable",
        }.issubset(warrant.artifact_hashes):
            raise IntegrityError(f"command input binding is incomplete for {stage}")
        covered_actions.add(action.id)
        covered_effects.add(effect.id)
        covered_leases.add(lease.id)

    if covered_actions != set(actions) or covered_effects != set(effects) or covered_leases != set(
        leases
    ):
        raise IntegrityError("receipt authorization inventory omits or invents durable effects")
    experiment_runs = store.list_experiment_runs(case_id)
    if len(experiment_runs) != 1 or experiment_runs[0].action_id not in covered_actions:
        raise IntegrityError("decisive experiment is not linked to an authorized action")
    test_runs = store.list_test_runs(run_id, case_id=case_id)
    if len(test_runs) != 2 or any(test.action_id not in covered_actions for test in test_runs):
        raise IntegrityError("verification process is not linked to an authorized action")
    return True


def _verify_decisive_experiment(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    store: Store,
    receipt: Mapping[str, Any],
    case_id: str,
) -> bool:
    """Recompute R-12 selection and bind R-13 to durable execution evidence."""

    candidate_paths = [
        path for path in requirement_paths(root, manifest, "R-12") if path.name == "candidates.json"
    ]
    run_paths = [
        path for path in requirement_paths(root, manifest, "R-13") if path.name == "run.json"
    ]
    if len(candidate_paths) != 1 or len(run_paths) != 1:
        raise IntegrityError("decisive experiment requires one candidate and one run proof")
    candidate_proof = _load_object(candidate_paths[0])
    run_proof = _load_object(run_paths[0])
    if set(run_proof) != {
        "experiment_run",
        "argv",
        "supervisor_argv",
        "cwd",
        "commit",
        "tree",
        "environment",
        "environment_digest",
        "sandbox",
        "sandbox_profile_path",
        "sandbox_profile_sha256",
        "worktree_pre_manifest_path",
        "worktree_post_manifest_path",
        "worktree_pre_digest",
        "worktree_post_digest",
        "workspace_unchanged",
        "exit_code",
        "stdout_artifact_digest",
        "stderr_artifact_digest",
        "observed_outcome",
        "evidence_hypothesis_id",
        "resolved_hypothesis_id",
        "disagreement_confirmed",
    }:
        raise IntegrityError("R-13 run proof has unexpected fields")
    experiment_cwd_raw = run_proof.get("cwd")
    if not isinstance(experiment_cwd_raw, str) or not Path(experiment_cwd_raw).is_absolute():
        raise IntegrityError("R-13 experiment cwd is not an absolute path")
    experiment_cwd = Path(experiment_cwd_raw)
    if set(candidate_proof) != {
        "candidates",
        "decisions",
        "selected_candidate_id",
        "selected_score",
    }:
        raise IntegrityError("R-12 candidate proof has unexpected fields")
    candidate_rows = candidate_proof.get("candidates")
    if not isinstance(candidate_rows, list) or any(
        not isinstance(row, Mapping) for row in candidate_rows
    ):
        raise IntegrityError("R-12 candidate proof is malformed")
    durable_candidates = store.list_experiment_candidates(case_id)
    durable_by_id = {candidate.id: candidate for candidate in durable_candidates}
    row_ids = [str(row.get("id", "")) for row in candidate_rows]
    if (
        len(candidate_rows) < 3
        or len(row_ids) != len(set(row_ids))
        or set(row_ids) != set(durable_by_id)
    ):
        raise IntegrityError("R-12 candidate proof differs from durable candidates")
    ordered_candidates: list[ExperimentCandidate] = []
    for row, candidate_id in zip(candidate_rows, row_ids, strict=True):
        candidate = durable_by_id[candidate_id]
        if dict(row) != candidate.model_dump(mode="json"):
            raise IntegrityError("R-12 candidate row differs from durable state")
        executable = Path(candidate.argv[0])
        metadata = candidate.metadata
        resolution = metadata.get("executable_resolution")
        proposed_argv = metadata.get("proposed_argv")
        if (
            not executable.is_absolute()
            or not is_python_executable(executable)
            or not isinstance(proposed_argv, list)
            or not proposed_argv
            or any(not isinstance(item, str) or not item for item in proposed_argv)
            or not is_python_executable(proposed_argv[0])
            or not isinstance(resolution, Mapping)
            or resolution.get("kind") != "scenario-python-runtime"
            or resolution.get("resolved_path") != candidate.argv[0]
            or list(candidate.argv[1:]) != proposed_argv[1:]
        ):
            raise IntegrityError("R-12 executable resolution is incomplete or inconsistent")
        ordered_candidates.append(candidate)

    selector = ExperimentSelector(
        allowed_roots=(experiment_cwd,),
        allowed_executables={Path(candidate.argv[0]).name for candidate in ordered_candidates},
        maximum_risk_rank=1,
    )
    selection = selector.select(
        ordered_candidates,
        live_hypothesis_ids=ordered_candidates[0].hypotheses,
        minimum_candidates=3,
    )
    expected_decisions = [
        {
            "candidate_id": decision.candidate_id,
            "accepted": decision.accepted,
            "reasons": list(decision.reasons),
            "score": list(decision.score) if decision.score is not None else None,
        }
        for decision in selection.decisions
    ]
    if candidate_proof.get("decisions") != expected_decisions:
        raise IntegrityError("R-12 candidate decisions do not recompute")
    selected = cast(ExperimentCandidate, selection.candidate)
    if (
        candidate_proof.get("selected_candidate_id") != selected.id
        or candidate_proof.get("selected_score") != list(selection.score)
        or selected.state != ExperimentState.SELECTED
    ):
        raise IntegrityError("R-12 smallest safe experiment was not selected")
    for candidate, decision in zip(ordered_candidates, selection.decisions, strict=True):
        expected_state = (
            ExperimentState.SELECTED
            if candidate.id == selected.id
            else ExperimentState.ACCEPTED
            if decision.accepted
            else ExperimentState.REJECTED
        )
        expected_score = decision.score if decision.accepted else None
        expected_rejection = None if decision.accepted else ",".join(decision.reasons)
        if (
            candidate.state != expected_state
            or candidate.score != expected_score
            or candidate.rejection_reason != expected_rejection
        ):
            raise IntegrityError("R-12 durable candidate lifecycle differs from policy decisions")

    runs = store.list_experiment_runs(case_id)
    if len(runs) != 1 or runs[0].candidate_id != selected.id:
        raise IntegrityError("R-13 durable experiment run differs from R-12 selection")
    run = runs[0]
    environment = run_proof.get("environment")
    expected_environment = dict(EXPERIMENT_ENVIRONMENT)
    expected_environment_digest = canonical_digest(expected_environment)
    sandbox = run_proof.get("sandbox")
    expected_sandbox_fields = {
        "backend",
        "executable",
        "executable_sha256",
        "executable_artifact_digest",
        "profile_sha256",
        "logical_argv",
        "supervisor_argv",
        "environment",
        "environment_digest",
        "process_executables",
        "read_subpaths",
        "read_literals",
        "dynamic_libraries",
        "python_invocation_path",
        "python_resolved_path",
        "python_sha256",
        "python_artifact_digest",
    }
    if not isinstance(sandbox, Mapping) or set(sandbox) != expected_sandbox_fields:
        raise IntegrityError("R-13 sandbox record is malformed")
    process_executables_raw = sandbox.get("process_executables")
    read_subpaths_raw = sandbox.get("read_subpaths")
    read_literals_raw = sandbox.get("read_literals")
    dynamic_libraries_raw = sandbox.get("dynamic_libraries")
    if (
        not isinstance(process_executables_raw, list)
        or not process_executables_raw
        or not isinstance(read_subpaths_raw, list)
        or not read_subpaths_raw
        or not isinstance(read_literals_raw, list)
        or not read_literals_raw
        or any(
            not isinstance(item, str) or not Path(item).is_absolute()
            for item in (*process_executables_raw, *read_subpaths_raw, *read_literals_raw)
        )
        or process_executables_raw != sorted(set(process_executables_raw))
        or read_subpaths_raw != sorted(set(read_subpaths_raw))
        or read_literals_raw != sorted(set(read_literals_raw))
        or experiment_cwd_raw not in read_subpaths_raw
        or not isinstance(dynamic_libraries_raw, list)
        or any(not isinstance(item, Mapping) for item in dynamic_libraries_raw)
    ):
        raise IntegrityError("R-13 sandbox allow-only policy is incomplete")
    for dependency in dynamic_libraries_raw:
        if set(dependency) != {"path", "resolved_path", "sha256", "artifact_digest"}:
            raise IntegrityError("R-13 sandbox loader input is malformed")
        dependency_path = Path(str(dependency.get("path", "")))
        dependency_resolved = Path(str(dependency.get("resolved_path", "")))
        dependency_bytes = _proof_object_bytes(
            root,
            dependency.get("artifact_digest"),
            label="sandbox loader input",
        )
        if (
            not dependency_path.is_absolute()
            or not dependency_resolved.is_absolute()
            or sha256_digest(dependency_bytes) != dependency.get("sha256")
            or str(dependency_path) not in read_literals_raw
            or str(dependency_resolved) not in read_literals_raw
        ):
            raise IntegrityError("R-13 sandbox loader input changed or is not allowed")
    profile = render_macos_profile(
        process_executables=tuple(process_executables_raw),
        read_subpaths=tuple(read_subpaths_raw),
        read_literals=tuple(read_literals_raw),
    )
    profile_path = _relative_proof_file(
        root,
        run_proof.get("sandbox_profile_path"),
        label="sandbox profile",
    )
    profile_sha256 = sha256_digest(profile.encode("utf-8"))
    sandbox_executable = Path(str(sandbox.get("executable", ""))).expanduser()
    sandbox_executable_bytes = _proof_object_bytes(
        root,
        sandbox.get("executable_artifact_digest"),
        label="sandbox executable",
    )
    python_executable_bytes = _proof_object_bytes(
        root,
        sandbox.get("python_artifact_digest"),
        label="Python executable",
    )
    if (
        sandbox.get("backend") != SANDBOX_BACKEND
        or sandbox_executable != Path("/usr/bin/sandbox-exec")
        or sandbox.get("executable_sha256")
        != sha256_digest(sandbox_executable_bytes)
        or profile_path.read_text(encoding="utf-8") != profile
        or sandbox.get("profile_sha256") != profile_sha256
        or run_proof.get("sandbox_profile_sha256") != profile_sha256
        or process_executables_raw
        != sorted({selected.argv[0], str(sandbox.get("python_resolved_path"))})
        or sandbox.get("logical_argv") != list(selected.argv)
        or sandbox.get("environment") != expected_environment
        or sandbox.get("environment_digest") != expected_environment_digest
        or sandbox.get("python_invocation_path") != selected.argv[0]
        or not Path(str(sandbox.get("python_resolved_path", ""))).is_absolute()
        or sandbox.get("python_sha256") != sha256_digest(python_executable_bytes)
    ):
        raise IntegrityError("R-13 sandbox policy does not bind the selected experiment")
    expected_supervisor_argv = [
        str(sandbox_executable),
        "-p",
        profile,
        "--",
        *selected.argv,
    ]
    if (
        sandbox.get("supervisor_argv") != expected_supervisor_argv
        or run_proof.get("supervisor_argv") != expected_supervisor_argv
    ):
        raise IntegrityError("R-13 sandbox supervisor argv is not exact")

    pre_manifest_path = _relative_proof_file(
        root,
        run_proof.get("worktree_pre_manifest_path"),
        label="pre-experiment worktree manifest",
    )
    post_manifest_path = _relative_proof_file(
        root,
        run_proof.get("worktree_post_manifest_path"),
        label="post-experiment worktree manifest",
    )
    pre_manifest = _load_object(pre_manifest_path)
    post_manifest = _load_object(post_manifest_path)
    for worktree_manifest in (pre_manifest, post_manifest):
        claimed_digest = worktree_manifest.get("canonical_digest")
        unsigned_manifest = dict(worktree_manifest)
        unsigned_manifest.pop("canonical_digest", None)
        if (
            worktree_manifest.get("protocol") != "tars.experiment-worktree/v1"
            or worktree_manifest.get("root") != experiment_cwd_raw
            or claimed_digest != canonical_digest(unsigned_manifest)
        ):
            raise IntegrityError("R-13 worktree manifest is malformed")
    if (
        pre_manifest != post_manifest
        or run_proof.get("workspace_unchanged") is not True
        or run_proof.get("worktree_pre_digest") != pre_manifest.get("canonical_digest")
        or run_proof.get("worktree_post_digest") != post_manifest.get("canonical_digest")
    ):
        raise IntegrityError("R-13 decisive experiment changed its read-only worktree")

    quarantine = receipt.get("quarantine")
    if not isinstance(quarantine, Mapping):
        raise IntegrityError("R-13 quarantine receipt is missing")
    invalid_commit = str(quarantine.get("invalid_commit", ""))
    repository = _receipt_git_path(
        root,
        quarantine.get("repository"),
        label="decisive experiment repository",
        portable_required=False,
    )
    if _git(repository, "rev-parse", f"{invalid_commit}^{{commit}}") != invalid_commit:
        raise IntegrityError("R-13 invalid commit is absent from the proof repository")
    invalid_tree = _git(repository, "show", "-s", "--format=%T", invalid_commit)
    manifest_entries = pre_manifest.get("entries")
    if not isinstance(manifest_entries, list) or any(
        not isinstance(item, Mapping) for item in manifest_entries
    ):
        raise IntegrityError("R-13 worktree manifest entries are malformed")
    manifest_by_path = {
        str(item.get("path", "")): dict(item)
        for item in manifest_entries
        if item.get("path") != ".git"
    }
    if (
        len(manifest_by_path) != len(manifest_entries) - 1
        or ".git" not in {str(item.get("path", "")) for item in manifest_entries}
        or manifest_by_path != _git_worktree_manifest(repository, invalid_commit)
    ):
        raise IntegrityError("R-13 experiment worktree differs from the quarantined Git tree")

    if (
        run.state != ExperimentState.PASSED
        or run.exit_code != 0
        or run.environment_digest != expected_environment_digest
        or environment != expected_environment
        or run_proof.get("environment_digest") != expected_environment_digest
        or run_proof.get("experiment_run") != run.model_dump(mode="json")
        or run_proof.get("argv") != list(selected.argv)
        or run_proof.get("argv") != run.metadata.get("argv")
        or run.metadata.get("supervisor_argv") != expected_supervisor_argv
        or run.metadata.get("sandbox") != dict(sandbox)
        or run.metadata.get("environment") != expected_environment
        or run.metadata.get("commit") != invalid_commit
        or run.metadata.get("tree") != invalid_tree
        or run.metadata.get("worktree_pre_digest") != pre_manifest.get("canonical_digest")
        or run_proof.get("commit") != invalid_commit
        or run_proof.get("tree") != invalid_tree
        or run.metadata.get("selection_score") != list(selection.score)
        or run_proof.get("exit_code") != run.exit_code
        or run_proof.get("stdout_artifact_digest") != run.stdout_artifact_digest
        or run_proof.get("stderr_artifact_digest") != run.stderr_artifact_digest
        or run_proof.get("observed_outcome") != run.observed_outcome
    ):
        raise IntegrityError("R-13 run proof differs from durable execution")
    output_bytes: dict[str, bytes] = {}
    for label, digest in (
        ("stdout", run.stdout_artifact_digest),
        ("stderr", run.stderr_artifact_digest),
    ):
        if not isinstance(digest, str):
            raise IntegrityError("R-13 experiment output digest is missing")
        object_path = root / "objects" / digest[:2] / digest[2:]
        if (
            not object_path.is_file()
            or object_path.is_symlink()
            or sha256_digest(object_path.read_bytes()) != digest
        ):
            raise IntegrityError("R-13 experiment output artifact is missing or changed")
        output_bytes[label] = object_path.read_bytes()
    try:
        captured_outcome = json.loads(output_bytes["stdout"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("R-13 decisive experiment stdout is not JSON") from exc
    if captured_outcome != run.observed_outcome:
        raise IntegrityError("R-13 observed outcome differs from captured stdout")
    resolved_hypotheses = matching_hypotheses(dict(selected.predictions), captured_outcome)
    if (
        resolved_hypotheses != (HYPOTHESES[0],)
        or run_proof.get("resolved_hypothesis_id") != HYPOTHESES[0]
        or run_proof.get("evidence_hypothesis_id") != HYPOTHESES[1]
        or run_proof.get("disagreement_confirmed") is not True
    ):
        raise IntegrityError("R-13 outcome does not prove the implementation/evidence disagreement")

    action = store.get_action(run.action_id) if run.action_id is not None else None
    effect_id = run.metadata.get("effect_id")
    effect = store.get_effect(effect_id) if isinstance(effect_id, str) else None
    warrant = store.get_warrant(action.warrant_id) if action is not None else None
    expected_payload = {
        "case_id": case_id,
        "candidate_id": selected.id,
        "argv": list(selected.argv),
        "cwd": experiment_cwd_raw,
        "commit": invalid_commit,
        "tree": invalid_tree,
        "environment": expected_environment,
        "environment_digest": expected_environment_digest,
        "sandbox": dict(sandbox),
    }
    expected_effect_metadata = {
        "case_id": case_id,
        "candidate_id": selected.id,
        "argv": list(selected.argv),
        "cwd": experiment_cwd_raw,
        "commit": invalid_commit,
        "tree": invalid_tree,
        "environment": expected_environment,
        "environment_digest": expected_environment_digest,
        "sandbox": dict(sandbox),
        "worktree_pre_digest": pre_manifest.get("canonical_digest"),
    }
    effect_observation = {
        "exit_code": run.exit_code,
        "stdout_artifact_digest": run.stdout_artifact_digest,
        "stderr_artifact_digest": run.stderr_artifact_digest,
        "observed_outcome": run.observed_outcome,
        "sandbox_profile_sha256": profile_sha256,
        "environment_digest": expected_environment_digest,
        "worktree_pre_digest": pre_manifest.get("canonical_digest"),
        "worktree_post_digest": post_manifest.get("canonical_digest"),
        "workspace_unchanged": True,
    }
    command_target_digest = canonical_digest(
        {"cwd": experiment_cwd_raw, "argv": list(selected.argv)}
    )
    expected_command_target = f"command:{command_target_digest}"
    expected_warrant_bindings = {
        "command:argv": canonical_digest(list(selected.argv)),
        "command:cwd": canonical_digest(experiment_cwd_raw),
        "command:executable": str(sandbox.get("python_sha256")),
        "git:commit-oid": sha256_digest(invalid_commit),
        "git:tree-oid": sha256_digest(invalid_tree),
        "sandbox:executable": str(sandbox.get("executable_sha256")),
        "sandbox:profile": profile_sha256,
        "sandbox:environment": expected_environment_digest,
        "sandbox:supervisor-argv": canonical_digest(expected_supervisor_argv),
        "sandbox:worktree-pre": str(pre_manifest.get("canonical_digest")),
        "python:resolved-executable": str(sandbox.get("python_sha256")),
    }
    if (
        action is None
        or effect is None
        or warrant is None
        or effect.action_id != action.id
        or action.target != expected_command_target
        or action.payload_digest != canonical_digest(expected_payload)
        or any(effect.metadata.get(key) != value for key, value in expected_effect_metadata.items())
        or dict(action.artifact_vector) != dict(warrant.artifact_hashes)
        or any(
            warrant.artifact_hashes.get(key) != value
            for key, value in expected_warrant_bindings.items()
        )
        or effect.before_hash != canonical_digest(dict(warrant.artifact_hashes))
        or effect.state != EffectState.EXECUTED
        or effect.after_hash != canonical_digest(effect_observation)
        or not isinstance(effect.forward_artifact_digest, str)
    ):
        raise IntegrityError("R-13 execution is not bound to its authorized action and effect")
    effect_object = (
        root
        / "objects"
        / effect.forward_artifact_digest[:2]
        / effect.forward_artifact_digest[2:]
    )
    if (
        not effect_object.is_file()
        or effect_object.is_symlink()
        or effect_object.read_bytes() != canonical_json(effect_observation).encode("utf-8")
        or sha256_digest(effect_object.read_bytes()) != effect.forward_artifact_digest
    ):
        raise IntegrityError("R-13 execution effect artifact is missing or changed")
    receipt_experiment = receipt.get("experiment")
    if not isinstance(receipt_experiment, Mapping) or (
        receipt_experiment.get("candidate_count") != len(ordered_candidates)
        or receipt_experiment.get("selected_candidate_id") != selected.id
        or receipt_experiment.get("selected_score") != list(selection.score)
        or receipt_experiment.get("argv") != list(selected.argv)
        or receipt_experiment.get("exit_code") != run.exit_code
        or receipt_experiment.get("stdout_artifact_digest") != run.stdout_artifact_digest
        or receipt_experiment.get("stderr_artifact_digest") != run.stderr_artifact_digest
        or receipt_experiment.get("observed_outcome") != run.observed_outcome
        or receipt_experiment.get("environment") != expected_environment
        or receipt_experiment.get("environment_digest") != expected_environment_digest
        or receipt_experiment.get("sandbox") != dict(sandbox)
        or receipt_experiment.get("commit") != invalid_commit
        or receipt_experiment.get("tree") != invalid_tree
        or receipt_experiment.get("workspace_unchanged") is not True
        or receipt_experiment.get("resolved_hypothesis_id") != HYPOTHESES[0]
        or receipt_experiment.get("evidence_hypothesis_id") != HYPOTHESES[1]
        or receipt_experiment.get("disagreement_confirmed") is not True
    ):
        raise IntegrityError("receipt experiment proof differs from R-12/R-13 evidence")
    return True


def verify_bundle(
    artifact_root: str | Path,
    *,
    strict: bool = True,
    required_requirement_ids: Iterable[str] | None = None,
) -> BundleVerification:
    root = Path(artifact_root).expanduser().resolve()
    receipt_path, manifest_path, digest_path, attestation_kind = _select_proof_files(
        root,
        strict=strict,
        required_requirement_ids=required_requirement_ids,
    )
    state_path = root / "state.sqlite"
    for path in (receipt_path, manifest_path, state_path):
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"required proof artifact is missing: {path}")

    receipt = _load_object(receipt_path)
    manifest = _load_object(manifest_path)
    required = (
        tuple(sorted(set(required_requirement_ids)))
        if required_requirement_ids is not None
        else _required_ids(manifest, strict=strict)
    )
    cryptographic = StrictReceiptVerifier.verify(
        payload=receipt,
        proof_manifest=manifest,
        artifact_root=root,
        required_requirement_ids=required,
    )

    run_id = str(receipt.get("run_id", ""))
    case_id = str(receipt.get("case_id", ""))
    if not run_id or not case_id:
        raise IntegrityError("receipt run_id and case_id are required")
    store = Store(state_path)
    case = store.get_revocation_case(case_id)
    if case is None or case.run_id != run_id:
        raise IntegrityError("receipt revocation case does not match durable state")
    canonical_bound = _verify_durable_canonical_receipt(
        root,
        store=store,
        selected_receipt=receipt,
        attestation_kind=attestation_kind,
    )
    authorization_coverage = _verify_authorization_coverage(
        store=store,
        receipt=receipt,
        run_id=run_id,
        case_id=case_id,
    )
    decisive_experiment = _verify_decisive_experiment(
        root,
        manifest,
        store=store,
        receipt=receipt,
        case_id=case_id,
    )

    concurrency_valid = False
    if "R-01" in required:
        concurrency_path = root / "agents" / "concurrent-codex-proof.json"
        concurrency = _load_object(concurrency_path)
        if receipt.get("concurrency") != concurrency:
            raise IntegrityError("receipt concurrency proof differs from its durable artifact")
        concurrency_verification = verify_concurrent_codex_proof(
            concurrency,
            artifact_root=root,
            expected_run_id=run_id,
        )
        sessions = {
            session.id: session for session in store.list_agent_sessions(run_id)
        }
        proof_rows = concurrency.get("sessions")
        if not isinstance(proof_rows, list):
            raise IntegrityError("concurrent Codex session rows are missing")
        for row in proof_rows:
            if not isinstance(row, Mapping):
                raise IntegrityError("concurrent Codex session row is malformed")
            record = sessions.get(str(row.get("session_record_id", "")))
            interval = row.get("process_interval")
            if record is None or not isinstance(interval, Mapping):
                raise IntegrityError("concurrent Codex session is absent from durable state")
            if (
                record.state != SessionState.COMPLETED
                or record.provider != "live-codex"
                or record.external_session_id != row.get("external_session_id")
                or record.agent_id != row.get("agent_id")
                or record.process_id != row.get("pid")
                or str(record.metadata.get("worktree")) != row.get("worktree")
                or str(record.metadata.get("process_handle_id"))
                != row.get("process_handle_id")
                or record.metadata.get("process_started_monotonic")
                != interval.get("started_monotonic")
                or record.metadata.get("process_finished_monotonic")
                != interval.get("ended_monotonic")
            ):
                raise IntegrityError(
                    "concurrent Codex proof differs from its durable session record"
                )
        if set(concurrency_verification.session_record_ids) != set(sessions):
            raise IntegrityError("durable run has unexpected concurrent Codex session records")
        concurrency_valid = concurrency_verification.valid

    durable_head = store.journal.verify_chain(run_id)
    integrity = receipt.get("integrity")
    if not isinstance(integrity, Mapping):
        raise IntegrityError("receipt integrity section is missing")
    event_sequences = receipt.get("event_sequences")
    if not isinstance(event_sequences, Mapping):
        raise IntegrityError("receipt event sequence anchors are missing")
    try:
        event_anchor = int(event_sequences["event_anchor"])
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("receipt event anchor is invalid") from exc
    anchored_event = next(
        (event for event in store.journal.list_events(run_id) if event.sequence == event_anchor),
        None,
    )
    if anchored_event is None:
        raise IntegrityError("receipt event anchor is absent from the durable journal")
    if anchored_event.event_hash != integrity.get("event_head_digest"):
        raise IntegrityError("receipt event head does not match its durable journal anchor")
    try:
        frozen_sequence = int(event_sequences["frozen"])
        agent_b_push_sequence = int(event_sequences["agent_b_push"])
        resumed_sequence = int(event_sequences["resumed"])
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("receipt selective-execution event ordering is invalid") from exc
    if not (
        frozen_sequence < agent_b_push_sequence < resumed_sequence <= event_anchor
    ):
        raise IntegrityError("Agent B did not push strictly between FROZEN and RESUMED")

    members = store.list_revocation_members(case_id)
    affected = tuple(
        sorted(
            member.entity_id
            for member in members
            if member.member_kind == RevocationMemberKind.EFFECT
        )
    )
    if len(affected) != 3:
        raise IntegrityError(
            f"canonical revocation must contain exactly 3 effects, got {len(affected)}"
        )
    receipt_affected = tuple(
        sorted(_string_list(receipt.get("affected_effects"), label="affected_effects"))
    )
    if receipt_affected != affected:
        raise IntegrityError("receipt affected effects differ from the persisted causal closure")

    unaffected = set(_string_list(receipt.get("unaffected_effects"), label="unaffected_effects"))
    if not unaffected or unaffected.intersection(affected):
        raise IntegrityError("negative-reachability proof is missing or overlaps the closure")

    affected_records = [store.get_effect(effect_id) for effect_id in affected]
    if any(effect is None for effect in affected_records):
        raise IntegrityError("revocation closure names a missing effect")
    states = {effect.state for effect in affected_records if effect is not None}
    if EffectState.ROLLED_BACK not in states or EffectState.QUARANTINED not in states:
        raise IntegrityError("affected effects were not both restored and quarantined")

    tests = store.list_test_runs(run_id, case_id=case_id)
    passed_kinds = {test.kind.value for test in tests if test.state == TestState.PASSED}
    if not {"TARGETED", "FULL"}.issubset(passed_kinds):
        raise IntegrityError("targeted and full verification did not both pass")

    quarantine = receipt.get("quarantine")
    repair = receipt.get("repair")
    resume = receipt.get("resume")
    if not isinstance(quarantine, Mapping):
        raise IntegrityError("receipt quarantine proof is incomplete")
    if not isinstance(repair, Mapping):
        raise IntegrityError("receipt repair proof is incomplete")
    if not isinstance(resume, Mapping):
        raise IntegrityError("receipt Git proof sections are incomplete")
    portable_required = attestation_kind is not None
    repository = _receipt_git_path(
        root,
        quarantine.get("repository"),
        label="Git repository",
        portable_required=portable_required,
    )
    remote = _receipt_git_path(
        root,
        resume.get("remote"),
        label="Git remote",
        portable_required=portable_required,
    )
    quarantine_ref = str(quarantine.get("ref", ""))
    invalid_commit = str(quarantine.get("invalid_commit", ""))
    replacement_ref = str(resume.get("ref", ""))
    replacement_commit = str(resume.get("commit", ""))
    agent_b_ref = str(resume.get("agent_b_ref", ""))
    agent_b_commit = str(resume.get("agent_b_commit", ""))
    if _git(repository, "rev-parse", quarantine_ref) != invalid_commit:
        raise IntegrityError("quarantine ref does not preserve the invalid commit")
    remote_commits = set(_git(remote, "rev-list", "--all").splitlines())
    if invalid_commit in remote_commits:
        raise IntegrityError("invalid commit reached the remote")
    if _git(remote, "rev-parse", replacement_ref) != replacement_commit:
        raise IntegrityError("replacement commit is absent from its remote ref")
    if _git(remote, "rev-parse", agent_b_ref) != agent_b_commit:
        raise IntegrityError("unrelated Agent B commit is absent from its remote ref")

    receipt_sha_path = digest_path
    if receipt_sha_path.is_file():
        expected = receipt_sha_path.read_text(encoding="utf-8").strip().split()[0]
        actual = sha256_digest(receipt_path.read_bytes())
        if expected != actual:
            raise IntegrityError("receipt.sha256 does not match receipt.json")

    checks = {
        "receipt_integrity": cryptographic.valid,
        "event_chain": True,
        "agent_b_continued_during_freeze": True,
        "exactly_three_effects": True,
        "negative_reachability": True,
        "restored_and_quarantined": True,
        "targeted_and_full_tests": True,
        "invalid_commit_not_remote": True,
        "unrelated_agent_pushed": True,
        "replacement_pushed": True,
        "complete_gateway_authorization_coverage": authorization_coverage,
        "smallest_decisive_experiment": decisive_experiment,
        "durable_canonical_receipt": canonical_bound,
    }
    if "R-01" in required:
        checks["two_live_codex_agents_concurrent"] = concurrency_valid
    if "R-14" in required:
        checks["live_codex_repair"] = verify_live_codex_repair(root, receipt, manifest).valid
    release_proof = None
    if "R-20" in required:
        release_proof = verify_release_runs(
            root,
            manifest,
            verify_bundle=verify_bundle,
        )
        checks["three_consecutive_live_runs"] = release_proof.valid
    if "R-18" in required:
        checks["crash_recovery"] = verify_crash_recovery(
            root,
            manifest,
            expected_source_commit=(
                release_proof.qualification.source_commit if release_proof else None
            ),
            source_repository=(
                release_proof.qualification.source_repository if release_proof else None
            ),
        ).valid
    if "R-19" in required:
        checks["revokebench"] = verify_revokebench(
            root,
            manifest,
            expected_source_commit=(
                release_proof.qualification.source_commit if release_proof else None
            ),
            source_repository=(
                release_proof.qualification.source_repository if release_proof else None
            ),
        ).valid
    return BundleVerification(
        valid=all(checks.values()),
        run_id=run_id,
        case_id=case_id,
        receipt_digest=cryptographic.receipt_digest,
        event_head_digest=durable_head,
        affected_effect_ids=affected,
        checked_requirements=cryptographic.verified_requirements,
        checks=checks,
    )


def find_artifact_root(receipt_or_root: str | Path) -> Path:
    path = Path(receipt_or_root).expanduser().resolve()
    if path.is_dir():
        return path
    receipt_names = {
        "receipt.json",
        "portable-receipt.json",
        "release-attestation.json",
    }
    if path.name not in receipt_names:
        raise ValidationError(
            "verification target must be an artifact directory or attestation receipt"
        )
    return path.parent
