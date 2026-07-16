from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tars_revoke.adapters.schema_registry import (
    Ed25519SchemaSigner,
    PublishSchemaRequest,
    SchemaArtifactVerifier,
    SchemaRegistryAuthError,
    SchemaReplayError,
    SchemaVerificationError,
    VersionedSchemaRegistry,
)
from tars_revoke.errors import AdapterError


def _schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {"api_key": {"type": "string"}},
        "required": ["api_key"],
        "additionalProperties": False,
    }


def test_signer_and_pinned_verifier_detect_content_and_source_tampering() -> None:
    signer = Ed25519SchemaSigner.generate(source_id="registry-prod", key_id="key-1")
    verifier = SchemaArtifactVerifier(
        expected_source_id="registry-prod",
        public_keys={"key-1": signer.public_bytes()},
    )
    artifact = signer.sign(schema_name="evidence", version=1, content=_schema())

    assert verifier.verify(artifact) is artifact
    assert artifact.digest
    assert artifact.signature
    with pytest.raises(SchemaVerificationError, match="digest mismatch"):
        verifier.verify(artifact.model_copy(update={"content": {"type": "array"}}))
    wrong_source = SchemaArtifactVerifier(
        expected_source_id="registry-staging",
        public_keys={"key-1": signer.public_bytes()},
    )
    with pytest.raises(SchemaVerificationError, match="source identity"):
        wrong_source.verify(artifact)


def test_schema_may_describe_secret_fields_but_not_embed_secret_values() -> None:
    signer = Ed25519SchemaSigner.generate(source_id="registry", key_id="key-1")
    assert signer.sign(schema_name="credentials", version=1, content=_schema())

    with pytest.raises(AdapterError, match="secret-looking value"):
        signer.sign(
            schema_name="credentials",
            version=2,
            content={"default": "sk-1234567890abcdefghijkl"},
        )


def test_registry_requires_auth_and_monotonic_versions() -> None:
    signer = Ed25519SchemaSigner.generate(source_id="registry", key_id="key-1")
    registry = VersionedSchemaRegistry(signer=signer, publish_token="p" * 32)
    request = PublishSchemaRequest(version=1, content=_schema())

    with pytest.raises(SchemaRegistryAuthError, match="missing"):
        registry.publish("evidence", request, authorization=None)
    artifact = registry.publish(
        "evidence",
        request,
        authorization=f"Bearer {'p' * 32}",
    )
    assert registry.latest("evidence") == artifact
    assert registry.get_version("evidence", 1) == artifact
    with pytest.raises(SchemaReplayError, match="increase monotonically"):
        registry.publish(
            "evidence",
            request,
            authorization=f"Bearer {'p' * 32}",
        )


def test_signed_artifact_requires_timezone_aware_issue_time() -> None:
    signer = Ed25519SchemaSigner.generate(source_id="registry", key_id="key-1")
    with pytest.raises(ValueError, match="timezone"):
        signer.sign(
            schema_name="evidence",
            version=1,
            content=_schema(),
            issued_at=datetime.now(),
        )
    aware = signer.sign(
        schema_name="evidence",
        version=1,
        content=_schema(),
        issued_at=datetime.now(timezone.utc),
    )
    assert aware.issued_at.utcoffset() is not None
