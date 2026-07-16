from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class AdapterHealth:
    healthy: bool
    adapter: str
    version: str | None = None
    detail: str | None = None


@runtime_checkable
class ProcessAdapter(Protocol):
    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        stdin: bytes | None = None,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Any: ...

    async def cancel(self, process_id: str, *, reason: str = "revoked") -> bool: ...


@runtime_checkable
class GitEffectAdapter(Protocol):
    async def create_worktree(
        self,
        repository: Path,
        worktree: Path,
        *,
        branch: str,
        start_point: str = "HEAD",
    ) -> Any: ...

    async def diff(
        self,
        repository: Path,
        *,
        base: str | None = None,
        head: str | None = None,
        paths: Sequence[str] = (),
    ) -> str: ...

    async def push(
        self,
        repository: Path,
        *,
        remote: str,
        refspec: str,
        capability_token: str,
        action_id: str,
        epoch: int,
    ) -> Any: ...


@runtime_checkable
class MigrationEffectAdapter(Protocol):
    async def snapshot(self, database: Path, *, action_id: str) -> Any: ...

    async def apply(self, database: Path, sql: str, *, action_id: str) -> Any: ...

    async def restore(
        self,
        snapshot: Any,
        *,
        expected_current_hash: str | None = None,
    ) -> Any: ...


@runtime_checkable
class EvidenceSourceAdapter(Protocol):
    async def latest(self, schema_name: str) -> Any: ...

    async def get_version(self, schema_name: str, version: int) -> Any: ...


EventCallback = Callable[[Any], Awaitable[None] | None]


@runtime_checkable
class AgentAdapter(Protocol):
    async def execute(
        self,
        prompt: str,
        *,
        cwd: Path,
        sandbox: str,
        output_schema: Mapping[str, Any] | Path | None = None,
        model: str | None = None,
        thread_id: str | None = None,
        on_event: EventCallback | None = None,
    ) -> Any: ...

    async def health(self) -> AdapterHealth: ...
