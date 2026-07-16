from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tars_revoke.adapters.schema_registry import (
    Ed25519SchemaSigner,
    SchemaArtifactVerifier,
    SchemaRegistryAuthError,
    SchemaRegistryClient,
    SchemaReplayError,
    SchemaVerificationError,
    VersionedSchemaRegistry,
    create_schema_registry_app,
)


def _content(version: int) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "version": {"const": version},
            "api_key": {"type": "string"},
        },
        "required": ["version"],
        "additionalProperties": False,
    }


def _client(
    registry: VersionedSchemaRegistry,
    signer: Ed25519SchemaSigner,
    *,
    token: str | None = None,
    max_age: float | None = None,
) -> SchemaRegistryClient:
    transport = httpx.ASGITransport(app=create_schema_registry_app(registry))
    http_client = httpx.AsyncClient(transport=transport, base_url="http://registry.test")
    verifier = SchemaArtifactVerifier(
        expected_source_id=signer.source_id,
        public_keys={signer.key_id: signer.public_bytes()},
    )
    return SchemaRegistryClient(
        base_url="http://registry.test",
        verifier=verifier,
        client=http_client,
        publish_token=token,
        max_artifact_age_seconds=max_age,
    )


@pytest.mark.asyncio
async def test_signed_registry_round_trip_headers_auth_and_replay_defense() -> None:
    token = "publish-token-0123456789abcdef"
    signer = Ed25519SchemaSigner.generate(source_id="registry-prod", key_id="key-1")
    registry = VersionedSchemaRegistry(signer=signer, publish_token=token)
    client = _client(registry, signer, token=token)
    try:
        first = await client.publish("evidence", version=1, content=_content(1))
        assert first.artifact.version == 1
        assert first.etag == f'"sha256:{first.artifact.digest}"'
        second = await client.publish("evidence", version=2, content=_content(2))
        latest = await client.latest("evidence")
        assert latest.artifact == second.artifact

        with pytest.raises(SchemaReplayError, match="older schema artifact"):
            await client.get_version("evidence", 1)
    finally:
        assert client.client is not None
        await client.client.aclose()

    unauthenticated = _client(registry, signer, token="wrong-token-that-is-long-enough")
    try:
        with pytest.raises(SchemaRegistryAuthError, match="authentication failed"):
            await unauthenticated.publish("evidence", version=3, content=_content(3))
    finally:
        assert unauthenticated.client is not None
        await unauthenticated.client.aclose()


@pytest.mark.asyncio
async def test_registry_client_enforces_signed_artifact_freshness() -> None:
    token = "publish-token-0123456789abcdef"
    signer = Ed25519SchemaSigner.generate(source_id="registry-prod", key_id="key-1")
    registry = VersionedSchemaRegistry(signer=signer, publish_token=token)
    client = _client(registry, signer, token=token, max_age=60)
    try:
        with pytest.raises(SchemaVerificationError, match="older than"):
            await client.publish(
                "evidence",
                version=1,
                content=_content(1),
                issued_at=datetime.now(timezone.utc) - timedelta(hours=1),
            )
    finally:
        assert client.client is not None
        await client.client.aclose()


@pytest.mark.asyncio
async def test_client_rejects_tampered_signed_http_envelope() -> None:
    signer = Ed25519SchemaSigner.generate(source_id="registry-prod", key_id="key-1")
    artifact = signer.sign(schema_name="evidence", version=1, content=_content(1))
    tampered = artifact.model_copy(update={"content": _content(99)})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            json=tampered.model_dump(mode="json"),
            headers={
                "ETag": f'"sha256:{artifact.digest}"',
                "X-TARS-Schema-Version": "1",
                "X-TARS-Source-ID": "registry-prod",
            },
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = SchemaRegistryClient(
        base_url="http://registry.test",
        verifier=SchemaArtifactVerifier(
            expected_source_id="registry-prod",
            public_keys={"key-1": signer.public_bytes()},
        ),
        client=http_client,
    )
    try:
        with pytest.raises(SchemaVerificationError, match="digest mismatch"):
            await client.latest("evidence")
    finally:
        await http_client.aclose()
