from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tars_revoke.domain.canonical import canonical_bytes, sha256_digest
from tars_revoke.errors import IntegrityError, ValidationError


@dataclass(frozen=True)
class EvidenceVerification:
    source_version: int
    artifact_digest: str
    canonical_manifest_digest: str
    signature_valid: bool
    accepted: bool
    reason: str | None = None


class EvidenceVerifier:
    """Verify pinned, monotonic, content-addressed evidence manifests.

    The detached signature is over the canonical manifest without a
    ``signature`` member.  Evidence is data; no manifest field is interpreted
    as an instruction for an agent.
    """

    def verify(
        self,
        *,
        manifest: Mapping[str, Any],
        artifact: bytes,
        detached_signature: str | bytes,
        public_key: str | bytes,
        pinned_identity: str,
        latest_source_version: int | None = None,
        known_artifact_digests: frozenset[str] = frozenset(),
    ) -> EvidenceVerification:
        clean_manifest = dict(manifest)
        embedded_signature = clean_manifest.pop("signature", None)
        signature_value = detached_signature or embedded_signature
        source_identity = str(clean_manifest.get("source_identity", ""))
        if not source_identity or source_identity != pinned_identity:
            return self._rejected(clean_manifest, artifact, "source_identity_mismatch")

        try:
            raw_source_version = clean_manifest["source_version"]
            if not isinstance(raw_source_version, int) or isinstance(
                raw_source_version, bool
            ):
                raise TypeError
            source_version = raw_source_version
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("manifest source_version must be an integer") from exc
        if source_version < 0:
            raise ValidationError("manifest source_version must be non-negative")
        if latest_source_version is not None and source_version <= latest_source_version:
            return self._rejected(clean_manifest, artifact, "non_monotonic_source_version")

        artifact_digest = sha256_digest(artifact)
        expected_digest = str(clean_manifest.get("artifact_digest", ""))
        if not expected_digest or expected_digest != artifact_digest:
            return self._rejected(clean_manifest, artifact, "artifact_digest_mismatch")
        if artifact_digest in known_artifact_digests:
            return self._rejected(clean_manifest, artifact, "artifact_replay")

        try:
            key = self._load_public_key(public_key)
            signature = self._decode_signature(signature_value)
            key.verify(signature, canonical_bytes(clean_manifest))
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            return self._rejected(clean_manifest, artifact, "invalid_signature")

        return EvidenceVerification(
            source_version=source_version,
            artifact_digest=artifact_digest,
            canonical_manifest_digest=sha256_digest(canonical_bytes(clean_manifest)),
            signature_valid=True,
            accepted=True,
        )

    @staticmethod
    def require_accepted(result: EvidenceVerification) -> None:
        if not result.accepted:
            raise IntegrityError(result.reason or "evidence verification rejected")

    @staticmethod
    def _load_public_key(value: str | bytes) -> Ed25519PublicKey:
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if raw.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_public_key(raw)
            if not isinstance(loaded, Ed25519PublicKey):
                raise ValueError("evidence key is not Ed25519")
            return loaded
        if isinstance(value, bytes) and len(raw) == 32:
            decoded = raw
        else:
            try:
                decoded = base64.b64decode(raw, validate=True)
            except binascii.Error:
                decoded = raw
        return Ed25519PublicKey.from_public_bytes(decoded)

    @staticmethod
    def _decode_signature(value: str | bytes | None) -> bytes:
        if value is None:
            raise ValueError("missing signature")
        if isinstance(value, bytes) and len(value) == 64:
            return value
        raw = value.encode("ascii") if isinstance(value, str) else value
        return base64.b64decode(raw, validate=True)

    @staticmethod
    def _rejected(
        manifest: Mapping[str, Any], artifact: bytes, reason: str
    ) -> EvidenceVerification:
        try:
            source_version = int(manifest.get("source_version", -1))
        except (TypeError, ValueError):
            source_version = -1
        return EvidenceVerification(
            source_version=source_version,
            artifact_digest=sha256_digest(artifact),
            canonical_manifest_digest=sha256_digest(canonical_bytes(dict(manifest))),
            signature_valid=False,
            accepted=False,
            reason=reason,
        )
