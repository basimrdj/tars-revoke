from __future__ import annotations

import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.errors import IntegrityError, ValidationError

REQUIRED_RECEIPT_SECTIONS = (
    "agents",
    "trigger",
    "premise_delta",
    "dependency_paths",
    "affected_effects",
    "unaffected_effects",
    "compensation",
    "quarantine",
    "experiment",
    "repair",
    "verification",
    "resume",
    "timeline",
    "failures",
    "limitations",
)

DEFAULT_REQUIREMENT_IDS = tuple(f"R-{index:02d}" for index in range(1, 21))
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True)
class BuiltReceipt:
    payload: Mapping[str, Any]
    canonical_digest: str
    proof_manifest: Mapping[str, Any]
    manifest_digest: str


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    receipt_digest: str
    manifest_digest: str
    verified_requirements: tuple[str, ...]


class ReceiptBuilder:
    """Build deterministic receipts and content-addressed proof manifests."""

    @staticmethod
    def build_manifest(
        *,
        artifact_root: str | Path,
        requirement_artifacts: Mapping[str, Iterable[str | Path]],
        required_requirement_ids: Iterable[str] = DEFAULT_REQUIREMENT_IDS,
    ) -> Mapping[str, Any]:
        root = Path(artifact_root).resolve()
        required_ids = tuple(sorted(set(required_requirement_ids)))
        missing = [item for item in required_ids if item not in requirement_artifacts]
        if missing:
            raise ValidationError(f"proof manifest is missing requirements: {', '.join(missing)}")

        requirements: dict[str, list[dict[str, Any]]] = {}
        for requirement_id in sorted(requirement_artifacts):
            entries: list[dict[str, Any]] = []
            paths = sorted(
                (Path(path) for path in requirement_artifacts[requirement_id]),
                key=lambda path: path.as_posix(),
            )
            if requirement_id in required_ids and not paths:
                raise ValidationError(f"requirement {requirement_id} has no proof artifacts")
            for path in paths:
                resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
                if resolved != root and root not in resolved.parents:
                    raise ValidationError(f"proof artifact escapes root: {path}")
                if not resolved.is_file() or resolved.is_symlink():
                    raise ValidationError(f"proof artifact is not a regular file: {path}")
                content = resolved.read_bytes()
                entries.append(
                    {
                        "path": resolved.relative_to(root).as_posix(),
                        "sha256": sha256_digest(content),
                        "size": len(content),
                    }
                )
            requirements[requirement_id] = entries
        return {"manifest_version": 1, "requirements": requirements}

    @staticmethod
    def build(
        *,
        receipt_fields: Mapping[str, Any],
        proof_manifest: Mapping[str, Any],
        event_head_digest: str,
    ) -> BuiltReceipt:
        missing_sections = [
            section for section in REQUIRED_RECEIPT_SECTIONS if section not in receipt_fields
        ]
        if missing_sections:
            raise ValidationError(
                f"receipt is missing sections: {', '.join(missing_sections)}"
            )
        if not _is_sha256(event_head_digest):
            raise ValidationError("event head must be a SHA-256 digest")
        manifest_digest = canonical_digest(proof_manifest)
        unsigned = dict(receipt_fields)
        unsigned["integrity"] = {
            "event_head_digest": event_head_digest,
            "manifest_digest": manifest_digest,
        }
        receipt_digest = canonical_digest(unsigned)
        payload = dict(unsigned)
        payload["integrity"] = {
            **unsigned["integrity"],
            "receipt_digest": receipt_digest,
        }
        # Force normalization now so unsupported values cannot leak into a
        # receipt that appears successfully built.
        canonical_json(payload)
        return BuiltReceipt(
            payload=payload,
            canonical_digest=receipt_digest,
            proof_manifest=proof_manifest,
            manifest_digest=manifest_digest,
        )


class StrictReceiptVerifier:
    @staticmethod
    def verify(
        *,
        payload: Mapping[str, Any],
        proof_manifest: Mapping[str, Any],
        artifact_root: str | Path,
        required_requirement_ids: Iterable[str] = DEFAULT_REQUIREMENT_IDS,
    ) -> ReceiptVerification:
        for section in REQUIRED_RECEIPT_SECTIONS:
            if section not in payload:
                raise IntegrityError(f"receipt section missing: {section}")
        integrity = payload.get("integrity")
        if not isinstance(integrity, Mapping):
            raise IntegrityError("receipt integrity section is missing")
        expected_integrity_keys = {
            "event_head_digest",
            "manifest_digest",
            "receipt_digest",
        }
        if set(integrity) != expected_integrity_keys:
            raise IntegrityError("receipt integrity section has unexpected fields")

        expected_receipt_digest = str(integrity.get("receipt_digest", ""))
        expected_manifest_digest = str(integrity.get("manifest_digest", ""))
        event_head_digest = integrity.get("event_head_digest")
        if not _is_sha256(expected_receipt_digest):
            raise IntegrityError("receipt canonical digest is malformed")
        if not _is_sha256(expected_manifest_digest):
            raise IntegrityError("receipt proof-manifest digest is malformed")
        if not _is_sha256(event_head_digest):
            raise IntegrityError("receipt event-head digest is malformed")
        unsigned = dict(payload)
        unsigned["integrity"] = {
            "event_head_digest": event_head_digest,
            "manifest_digest": expected_manifest_digest,
        }
        actual_receipt_digest = canonical_digest(unsigned)
        if not hmac.compare_digest(actual_receipt_digest, expected_receipt_digest):
            raise IntegrityError("receipt canonical digest is invalid")

        actual_manifest_digest = canonical_digest(proof_manifest)
        if not hmac.compare_digest(actual_manifest_digest, expected_manifest_digest):
            raise IntegrityError("receipt proof-manifest digest is invalid")

        root = Path(artifact_root).resolve()
        if proof_manifest.get("manifest_version") != 1:
            raise IntegrityError("unsupported proof manifest version")
        requirements = proof_manifest.get("requirements")
        if not isinstance(requirements, Mapping):
            raise IntegrityError("proof manifest requirements are missing")
        required_ids = tuple(sorted(set(required_requirement_ids)))
        for requirement_id in required_ids:
            entries = requirements.get(requirement_id)
            if not isinstance(entries, list) or not entries:
                raise IntegrityError(f"proof missing for requirement {requirement_id}")
            for entry in entries:
                if not isinstance(entry, Mapping):
                    raise IntegrityError(f"invalid proof entry for {requirement_id}")
                path = (root / str(entry.get("path", ""))).resolve()
                if path != root and root not in path.parents:
                    raise IntegrityError("proof path escapes artifact root")
                if not path.is_file() or path.is_symlink():
                    raise IntegrityError(f"proof artifact missing: {path}")
                content = path.read_bytes()
                expected_size = entry.get("size")
                if (
                    not isinstance(expected_size, int)
                    or isinstance(expected_size, bool)
                    or expected_size < 0
                ):
                    raise IntegrityError(f"invalid proof artifact size: {path}")
                if len(content) != expected_size:
                    raise IntegrityError(f"proof artifact size changed: {path}")
                if not hmac.compare_digest(
                    sha256_digest(content), str(entry.get("sha256", ""))
                ):
                    raise IntegrityError(f"proof artifact digest changed: {path}")

        return ReceiptVerification(
            valid=True,
            receipt_digest=actual_receipt_digest,
            manifest_digest=actual_manifest_digest,
            verified_requirements=required_ids,
        )
