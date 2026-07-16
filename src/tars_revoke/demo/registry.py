from __future__ import annotations

import argparse
import asyncio
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

from tars_revoke.adapters._safety import PYTHON_SUBPROCESS_ENV_KEYS
from tars_revoke.adapters.processes import AsyncProcessRunner, ProcessHandle, ProcessSpec
from tars_revoke.adapters.schema_registry import (
    Ed25519SchemaSigner,
    SchemaArtifactVerifier,
    SchemaRegistryClient,
    VersionedSchemaRegistry,
    create_schema_registry_app,
)
from tars_revoke.errors import AdapterError

from .fixture import DemoFixture


@dataclass
class SchemaRegistryProcess:
    fixture: DemoFixture
    runner: AsyncProcessRunner
    handle: ProcessHandle
    client: SchemaRegistryClient
    base_url: str

    @classmethod
    async def start(
        cls,
        fixture: DemoFixture,
        *,
        runner: AsyncProcessRunner,
        python_executable: Path | None = None,
        startup_timeout_seconds: float = 10.0,
    ) -> SchemaRegistryProcess:
        port = _available_port()
        base_url = f"http://127.0.0.1:{port}"
        executable = str(python_executable or Path(sys.executable))
        package_root = Path(__file__).resolve().parents[2]
        spec = ProcessSpec.build(
            (
                executable,
                "-m",
                "tars_revoke.demo.registry",
                "--private-key-file",
                str(fixture.registry_private_key_file),
                "--token-file",
                str(fixture.registry_token_file),
                "--source-id",
                fixture.registry_source_id,
                "--key-id",
                fixture.registry_key_id,
                "--port",
                str(port),
            ),
            cwd=fixture.root,
            env={"PYTHONPATH": str(package_root)},
            inherited_env_keys=PYTHON_SUBPROCESS_ENV_KEYS,
        )
        handle = await runner.start(spec)
        deadline = asyncio.get_running_loop().time() + startup_timeout_seconds
        async with httpx.AsyncClient(timeout=0.5) as probe:
            while True:
                if handle.process.returncode is not None:
                    result = await handle.wait()
                    raise AdapterError(
                        "schema registry exited during startup: "
                        f"{result.stderr.strip() or result.stdout.strip()}"
                    )
                try:
                    response = await probe.get(f"{base_url}/openapi.json")
                    if response.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if asyncio.get_running_loop().time() >= deadline:
                    await handle.cancel(reason="registry_start_timeout")
                    await handle.wait()
                    raise AdapterError("schema registry did not become ready")
                await asyncio.sleep(0.05)

        verifier = SchemaArtifactVerifier(
            expected_source_id=fixture.registry_source_id,
            public_keys={fixture.registry_key_id: fixture.registry_public_key_file.read_bytes()},
        )
        client = SchemaRegistryClient(
            base_url=base_url,
            verifier=verifier,
            publish_token=fixture.registry_token_file.read_text(encoding="utf-8").strip(),
            max_artifact_age_seconds=3600,
        )
        return cls(fixture, runner, handle, client, base_url)

    async def close(self) -> None:
        await self.handle.cancel(reason="registry_shutdown")
        await self.handle.wait()

    async def __aenter__(self) -> SchemaRegistryProcess:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def build_registry_app(
    *,
    private_key_file: Path,
    token_file: Path,
    source_id: str,
    key_id: str,
) -> FastAPI:
    signer = Ed25519SchemaSigner.from_private_bytes(
        source_id=source_id,
        key_id=key_id,
        private_key=private_key_file.read_bytes(),
    )
    registry = VersionedSchemaRegistry(
        signer=signer,
        publish_token=token_file.read_text(encoding="utf-8").strip(),
    )
    return create_schema_registry_app(registry)


def main() -> int:
    parser = argparse.ArgumentParser(description="TARS REVOKE signed schema registry")
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    app = build_registry_app(
        private_key_file=args.private_key_file.resolve(strict=True),
        token_file=args.token_file.resolve(strict=True),
        source_id=args.source_id,
        key_id=args.key_id,
    )
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
