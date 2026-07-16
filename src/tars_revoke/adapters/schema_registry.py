from __future__ import annotations

import base64
import hmac
import re
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tars_revoke.errors import AdapterError, AuthorizationError, IntegrityError, ValidationError

from ._safety import canonical_json, require_no_secret_values, sha256_bytes


class SchemaRegistryError(AdapterError):
    pass


class SchemaRegistryAuthError(AuthorizationError):
    pass


class SchemaVerificationError(IntegrityError):
    pass


class SchemaReplayError(IntegrityError):
    pass


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROTOCOL_VERSION = "tars.schema-registry/v1"


def _utc_text(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SignedSchemaArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: str = PROTOCOL_VERSION
    source_id: str
    schema_name: str
    version: int = Field(ge=1)
    issued_at: datetime
    media_type: str = "application/schema+json"
    content: dict[str, Any]
    digest: str
    key_id: str
    signature: str

    @field_validator("source_id", "schema_name", "key_id")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not _NAME.fullmatch(value):
            raise ValueError("must be a safe registry identifier")
        return value

    @field_validator("digest")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("digest must be lowercase SHA-256")
        return value

    @field_validator("issued_at")
    @classmethod
    def aware_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must include a timezone")
        return value

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "protocol": self.protocol,
                "source_id": self.source_id,
                "schema_name": self.schema_name,
                "version": self.version,
                "issued_at": _utc_text(self.issued_at),
                "media_type": self.media_type,
                "content": self.content,
                "digest": self.digest,
                "key_id": self.key_id,
            }
        )


class PublishSchemaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    content: dict[str, Any]
    issued_at: datetime | None = None


class Ed25519SchemaSigner:
    def __init__(self, *, source_id: str, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not _NAME.fullmatch(source_id) or not _NAME.fullmatch(key_id):
            raise ValidationError("invalid signer source_id or key_id")
        self.source_id = source_id
        self.key_id = key_id
        self.private_key = private_key

    @classmethod
    def generate(cls, *, source_id: str, key_id: str) -> Ed25519SchemaSigner:
        return cls(source_id=source_id, key_id=key_id, private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(
        cls,
        *,
        source_id: str,
        key_id: str,
        private_key: bytes,
    ) -> Ed25519SchemaSigner:
        return cls(
            source_id=source_id,
            key_id=key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
        )

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(
        self,
        *,
        schema_name: str,
        version: int,
        content: Mapping[str, Any],
        issued_at: datetime | None = None,
    ) -> SignedSchemaArtifact:
        if not _NAME.fullmatch(schema_name) or version < 1:
            raise ValidationError("invalid schema name or version")
        normalized_content = dict(content)
        require_no_secret_values(normalized_content, path="schema")
        try:
            digest = sha256_bytes(canonical_json(normalized_content))
        except (TypeError, ValueError) as exc:
            raise ValidationError("schema content must be finite JSON data") from exc
        unsigned = SignedSchemaArtifact(
            source_id=self.source_id,
            schema_name=schema_name,
            version=version,
            issued_at=issued_at or datetime.now(timezone.utc),
            content=normalized_content,
            digest=digest,
            key_id=self.key_id,
            signature="pending",
        )
        signature = base64.b64encode(self.private_key.sign(unsigned.signing_payload())).decode(
            "ascii"
        )
        return unsigned.model_copy(update={"signature": signature})


class SchemaArtifactVerifier:
    def __init__(
        self,
        *,
        expected_source_id: str,
        public_keys: Mapping[str, bytes | Ed25519PublicKey],
    ) -> None:
        if not _NAME.fullmatch(expected_source_id):
            raise ValidationError("invalid expected source ID")
        self.expected_source_id = expected_source_id
        self.public_keys = {
            key_id: (
                key
                if isinstance(key, Ed25519PublicKey)
                else Ed25519PublicKey.from_public_bytes(key)
            )
            for key_id, key in public_keys.items()
        }
        if not self.public_keys:
            raise ValidationError("at least one pinned registry key is required")
        if any(not _NAME.fullmatch(key_id) for key_id in self.public_keys):
            raise ValidationError("invalid pinned registry key ID")

    def verify(self, artifact: SignedSchemaArtifact) -> SignedSchemaArtifact:
        if artifact.protocol != PROTOCOL_VERSION:
            raise SchemaVerificationError("unsupported schema registry protocol")
        if artifact.source_id != self.expected_source_id:
            raise SchemaVerificationError("schema source identity mismatch")
        key = self.public_keys.get(artifact.key_id)
        if key is None:
            raise SchemaVerificationError("schema artifact uses an unpinned signing key")
        expected_digest = sha256_bytes(canonical_json(artifact.content))
        if not hmac.compare_digest(expected_digest, artifact.digest):
            raise SchemaVerificationError("schema content digest mismatch")
        try:
            signature = base64.b64decode(artifact.signature, validate=True)
            key.verify(signature, artifact.signing_payload())
        except (ValueError, InvalidSignature) as exc:
            raise SchemaVerificationError("invalid schema artifact signature") from exc
        return artifact


class VersionedSchemaRegistry:
    def __init__(self, *, signer: Ed25519SchemaSigner, publish_token: str) -> None:
        if len(publish_token) < 24:
            raise ValidationError("registry publish token must be at least 24 characters")
        self.signer = signer
        self._publish_token = publish_token
        self._artifacts: dict[str, dict[int, SignedSchemaArtifact]] = {}

    def authenticate(self, authorization: str | None) -> None:
        prefix = "Bearer "
        if not authorization or not authorization.startswith(prefix):
            raise SchemaRegistryAuthError("missing registry bearer token")
        if not hmac.compare_digest(authorization[len(prefix) :], self._publish_token):
            raise SchemaRegistryAuthError("invalid registry bearer token")

    def publish(
        self,
        schema_name: str,
        request: PublishSchemaRequest,
        *,
        authorization: str | None,
    ) -> SignedSchemaArtifact:
        self.authenticate(authorization)
        if not _NAME.fullmatch(schema_name):
            raise ValidationError("invalid schema name")
        versions = self._artifacts.setdefault(schema_name, {})
        latest = max(versions, default=0)
        if request.version <= latest:
            raise SchemaReplayError(
                f"schema version must increase monotonically; latest is {latest}"
            )
        artifact = self.signer.sign(
            schema_name=schema_name,
            version=request.version,
            content=request.content,
            issued_at=request.issued_at,
        )
        versions[request.version] = artifact
        return artifact

    def latest(self, schema_name: str) -> SignedSchemaArtifact:
        versions = self._artifacts.get(schema_name, {})
        if not versions:
            raise KeyError(schema_name)
        return versions[max(versions)]

    def get_version(self, schema_name: str, version: int) -> SignedSchemaArtifact:
        try:
            return self._artifacts[schema_name][version]
        except KeyError as exc:
            raise KeyError(f"{schema_name}@{version}") from exc


def create_schema_registry_app(registry: VersionedSchemaRegistry) -> FastAPI:
    app = FastAPI(title="TARS signed schema registry", version="1")

    def artifact_response(artifact: SignedSchemaArtifact) -> Response:
        return Response(
            content=artifact.model_dump_json(),
            media_type="application/json",
            headers={
                "ETag": f'"sha256:{artifact.digest}"',
                "Cache-Control": "no-cache",
                "X-TARS-Schema-Version": str(artifact.version),
                "X-TARS-Source-ID": artifact.source_id,
            },
        )

    @app.post("/v1/schemas/{schema_name}", status_code=201)
    async def publish(
        schema_name: str,
        request: PublishSchemaRequest,
        authorization: str | None = Header(default=None),
    ) -> Response:
        try:
            return artifact_response(
                registry.publish(schema_name, request, authorization=authorization)
            )
        except SchemaRegistryAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except SchemaReplayError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ValidationError, AdapterError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/v1/schemas/{schema_name}/latest")
    async def latest(schema_name: str) -> Response:
        try:
            return artifact_response(registry.latest(schema_name))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="schema not found") from exc

    @app.get("/v1/schemas/{schema_name}/versions/{version}")
    async def version(schema_name: str, version: int) -> Response:
        try:
            return artifact_response(registry.get_version(schema_name, version))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="schema version not found") from exc

    return app


class FetchedSchema(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    artifact: SignedSchemaArtifact
    url: str
    etag: str
    fetched_unix: float


class SchemaRegistryClient:
    def __init__(
        self,
        *,
        base_url: str,
        verifier: SchemaArtifactVerifier,
        client: httpx.AsyncClient | None = None,
        publish_token: str | None = None,
        timeout_seconds: float = 10.0,
        max_artifact_age_seconds: float | None = None,
        future_skew_seconds: float = 30.0,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValidationError("schema registry URL must use HTTP or HTTPS")
        self.base_url = base_url.rstrip("/")
        self.verifier = verifier
        self.client = client
        self.publish_token = publish_token
        if timeout_seconds <= 0:
            raise ValidationError("schema registry timeout must be positive")
        if max_artifact_age_seconds is not None and max_artifact_age_seconds <= 0:
            raise ValidationError("schema artifact maximum age must be positive")
        if future_skew_seconds < 0:
            raise ValidationError("schema artifact future skew must be non-negative")
        self.timeout_seconds = timeout_seconds
        self.max_artifact_age_seconds = max_artifact_age_seconds
        self.future_skew_seconds = future_skew_seconds
        self._last_seen: dict[tuple[str, str], tuple[int, str]] = {}

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        owned = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.timeout_seconds)
        try:
            response = await client.request(method, f"{self.base_url}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise SchemaRegistryError(f"schema registry request failed: {exc}") from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code in (401, 403):
            raise SchemaRegistryAuthError("schema registry authentication failed")
        if response.status_code == 409:
            raise SchemaReplayError("schema registry rejected a non-monotonic version")
        if response.status_code >= 400:
            raise SchemaRegistryError(
                f"schema registry returned HTTP {response.status_code}: {response.text[:500]}"
            )
        return response

    def _verify_response(self, response: httpx.Response) -> FetchedSchema:
        try:
            artifact = SignedSchemaArtifact.model_validate(response.json())
        except (ValueError, TypeError) as exc:
            raise SchemaVerificationError("registry returned an invalid artifact envelope") from exc
        self.verifier.verify(artifact)
        issued_unix = artifact.issued_at.timestamp()
        now = time.time()
        if issued_unix > now + self.future_skew_seconds:
            raise SchemaVerificationError("schema artifact was issued in the future")
        if (
            self.max_artifact_age_seconds is not None
            and issued_unix < now - self.max_artifact_age_seconds
        ):
            raise SchemaVerificationError("schema artifact is older than the freshness policy")
        etag = response.headers.get("ETag", "")
        if etag != f'"sha256:{artifact.digest}"':
            raise SchemaVerificationError("registry ETag does not match artifact digest")
        if response.headers.get("X-TARS-Schema-Version") != str(artifact.version):
            raise SchemaVerificationError("registry version header mismatch")
        if response.headers.get("X-TARS-Source-ID") != artifact.source_id:
            raise SchemaVerificationError("registry source header mismatch")
        key = (artifact.source_id, artifact.schema_name)
        previous = self._last_seen.get(key)
        if previous is not None:
            previous_version, previous_digest = previous
            if artifact.version < previous_version:
                raise SchemaReplayError("older schema artifact replayed after a newer version")
            if artifact.version == previous_version and artifact.digest != previous_digest:
                raise SchemaReplayError("schema version was rewritten with different content")
        self._last_seen[key] = (artifact.version, artifact.digest)
        return FetchedSchema(
            artifact=artifact,
            url=str(response.request.url),
            etag=etag,
            fetched_unix=time.time(),
        )

    async def latest(self, schema_name: str) -> FetchedSchema:
        if not _NAME.fullmatch(schema_name):
            raise ValidationError("invalid schema name")
        return self._verify_response(
            await self._request("GET", f"/v1/schemas/{schema_name}/latest")
        )

    async def get_version(self, schema_name: str, version: int) -> FetchedSchema:
        if not _NAME.fullmatch(schema_name) or version < 1:
            raise ValidationError("invalid schema name or version")
        return self._verify_response(
            await self._request(
                "GET",
                f"/v1/schemas/{schema_name}/versions/{version}",
            )
        )

    async def publish(
        self,
        schema_name: str,
        *,
        version: int,
        content: Mapping[str, Any],
        issued_at: datetime | None = None,
    ) -> FetchedSchema:
        if self.publish_token is None:
            raise SchemaRegistryAuthError("no schema registry publish token configured")
        request = PublishSchemaRequest(
            version=version,
            content=dict(content),
            issued_at=issued_at,
        )
        response = await self._request(
            "POST",
            f"/v1/schemas/{schema_name}",
            headers={"Authorization": f"Bearer {self.publish_token}"},
            json=request.model_dump(mode="json", exclude_none=True),
        )
        return self._verify_response(response)
