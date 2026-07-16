from __future__ import annotations

import asyncio
import inspect
import os
import secrets
import signal
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tars_revoke.errors import AdapterError, ValidationError

from ._safety import (
    MINIMAL_SUBPROCESS_ENV_KEYS,
    normalize_roots,
    redact_mapping,
    redact_text,
    resolve_under_roots,
    sanitized_environment,
    validate_argv,
)


class ProcessExecutionError(AdapterError):
    """The process could not be started or violated its declared contract."""


@dataclass(frozen=True)
class ProcessEvent:
    process_id: str
    sequence: int
    channel: str
    text: str
    monotonic_at: float


StreamCallback = Callable[[ProcessEvent], Awaitable[None] | None]


@dataclass(frozen=True)
class ProcessSpec:
    argv: tuple[str, ...]
    cwd: Path
    stdin: bytes | None = None
    timeout_seconds: float | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    inherited_env_keys: frozenset[str] = MINIMAL_SUBPROCESS_ENV_KEYS
    allowed_exit_codes: frozenset[int] = frozenset({0})

    @classmethod
    def build(
        cls,
        argv: Sequence[str],
        *,
        cwd: Path,
        stdin: bytes | None = None,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
        inherited_env_keys: Iterable[str] = MINIMAL_SUBPROCESS_ENV_KEYS,
        inherit_env: bool | None = None,
        allowed_exit_codes: Sequence[int] = (0,),
    ) -> ProcessSpec:
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValidationError("timeout_seconds must be positive")
        if stdin is not None and not isinstance(stdin, bytes):
            raise ValidationError("stdin must be bytes")
        exits = frozenset(int(code) for code in allowed_exit_codes)
        if not exits:
            raise ValidationError("at least one allowed exit code is required")
        if inherit_env is True:
            raise ValidationError(
                "broad environment inheritance is forbidden; use inherited_env_keys"
            )
        inherited_keys = frozenset() if inherit_env is False else frozenset(inherited_env_keys)
        sanitized_environment(env, inherited_keys=inherited_keys)
        return cls(
            argv=validate_argv(argv),
            cwd=Path(cwd),
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            env=dict(env or {}),
            inherited_env_keys=inherited_keys,
            allowed_exit_codes=exits,
        )


@dataclass(frozen=True)
class ProcessResult:
    process_id: str
    argv: tuple[str, ...]
    cwd: Path
    pid: int
    process_group_id: int | None
    exit_code: int
    stdout: str
    stderr: str
    started_monotonic: float
    finished_monotonic: float
    cancelled: bool
    cancellation_reason: str | None
    timed_out: bool
    output_truncated: bool
    environment: Mapping[str, str]
    allowed_exit_codes: frozenset[int]

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.finished_monotonic - self.started_monotonic)

    @property
    def succeeded(self) -> bool:
        return (
            not self.cancelled and not self.timed_out and self.exit_code in self.allowed_exit_codes
        )


class ProcessHandle:
    def __init__(
        self,
        *,
        process_id: str,
        spec: ProcessSpec,
        process: asyncio.subprocess.Process,
        started_monotonic: float,
        process_group_id: int | None,
        max_capture_bytes: int,
        terminate_grace_seconds: float,
        on_event: StreamCallback | None,
        on_finished: Callable[[str], None],
        environment_record: Mapping[str, str],
    ) -> None:
        self.process_id = process_id
        self.spec = spec
        self.process = process
        self.started_monotonic = started_monotonic
        self.process_group_id = process_group_id
        self.max_capture_bytes = max_capture_bytes
        self.terminate_grace_seconds = terminate_grace_seconds
        self.on_event = on_event
        self.environment_record = dict(environment_record)
        self._on_finished = on_finished
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._sequence = 0
        self._output_truncated = False
        self._cancelled = False
        self._timed_out = False
        self._cancellation_reason: str | None = None
        self._result: ProcessResult | None = None
        self._callback_error: Exception | None = None
        self._wait_lock = asyncio.Lock()
        self._drainers = (
            asyncio.create_task(self._drain(process.stdout, "stdout")),
            asyncio.create_task(self._drain(process.stderr, "stderr")),
        )

    async def _drain(
        self,
        stream: asyncio.StreamReader | None,
        channel: str,
    ) -> None:
        if stream is None:
            return
        target = self._stdout if channel == "stdout" else self._stderr
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            remaining = self.max_capture_bytes - len(target)
            captured = chunk[: max(0, remaining)]
            if captured:
                target.extend(captured)
            if len(captured) < len(chunk):
                self._output_truncated = True
            if self.on_event is not None and self._callback_error is None:
                self._sequence += 1
                event = ProcessEvent(
                    process_id=self.process_id,
                    sequence=self._sequence,
                    channel=channel,
                    text=redact_text(chunk.decode("utf-8", errors="replace")),
                    monotonic_at=time.monotonic(),
                )
                try:
                    callback_result = self.on_event(event)
                    if inspect.isawaitable(callback_result):
                        await callback_result
                except Exception as exc:  # callbacks must never block pipe draining
                    self._callback_error = exc

    async def cancel(self, *, reason: str = "revoked") -> bool:
        if self.process.returncode is not None:
            return False
        self._cancelled = True
        self._cancellation_reason = redact_text(reason)[:500]
        await self._terminate_group()
        return True

    async def _terminate_group(self) -> None:
        if self.process.returncode is not None:
            return
        try:
            if os.name == "posix" and self.process_group_id is not None:
                os.killpg(self.process_group_id, signal.SIGTERM)
            else:
                self.process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(self.process.wait(), timeout=self.terminate_grace_seconds)
            return
        except asyncio.TimeoutError:
            pass
        try:
            if os.name == "posix" and self.process_group_id is not None:
                os.killpg(self.process_group_id, signal.SIGKILL)
            else:
                self.process.kill()
        except ProcessLookupError:
            return
        await self.process.wait()

    async def wait(self) -> ProcessResult:
        async with self._wait_lock:
            if self._result is not None:
                return self._result
            try:
                if self.spec.timeout_seconds is None:
                    await self.process.wait()
                else:
                    await asyncio.wait_for(
                        self.process.wait(),
                        timeout=self.spec.timeout_seconds,
                    )
            except asyncio.TimeoutError:
                self._timed_out = True
                self._cancellation_reason = "timeout"
                await self._terminate_group()
            except asyncio.CancelledError:
                self._cancelled = True
                self._cancellation_reason = "caller_cancelled"
                await asyncio.shield(self._terminate_group())
                raise
            finally:
                drain_results = await asyncio.gather(*self._drainers, return_exceptions=True)
                self._on_finished(self.process_id)

            drain_error = next(
                (item for item in drain_results if isinstance(item, BaseException)),
                None,
            )
            if drain_error is not None:
                raise ProcessExecutionError(
                    "failed while capturing process output"
                ) from drain_error
            if self._callback_error is not None:
                raise ProcessExecutionError(
                    "process stream callback failed"
                ) from self._callback_error

            exit_code = self.process.returncode
            if exit_code is None:
                raise ProcessExecutionError("process ended without an exit status")
            finished = time.monotonic()
            sanitized_argv = tuple(redact_text(item) for item in self.spec.argv)
            self._result = ProcessResult(
                process_id=self.process_id,
                argv=sanitized_argv,
                cwd=self.spec.cwd,
                pid=self.process.pid,
                process_group_id=self.process_group_id,
                exit_code=exit_code,
                stdout=redact_text(self._stdout.decode("utf-8", errors="replace")),
                stderr=redact_text(self._stderr.decode("utf-8", errors="replace")),
                started_monotonic=self.started_monotonic,
                finished_monotonic=finished,
                cancelled=self._cancelled,
                cancellation_reason=self._cancellation_reason,
                timed_out=self._timed_out,
                output_truncated=self._output_truncated,
                environment=dict(self.environment_record),
                allowed_exit_codes=self.spec.allowed_exit_codes,
            )
            return self._result


class AsyncProcessRunner:
    """Runs argv-only subprocesses in isolated process groups.

    The registry gives revocation logic a narrow cancellation handle.  It does
    not grant authorization; callers must already have passed the gateway.
    """

    def __init__(
        self,
        allowed_roots: Sequence[Path],
        *,
        max_capture_bytes: int = 2 * 1024 * 1024,
        terminate_grace_seconds: float = 2.0,
    ) -> None:
        if max_capture_bytes < 1024:
            raise ValidationError("max_capture_bytes must be at least 1024")
        if terminate_grace_seconds <= 0:
            raise ValidationError("terminate_grace_seconds must be positive")
        self.allowed_roots = normalize_roots(allowed_roots)
        self.max_capture_bytes = max_capture_bytes
        self.terminate_grace_seconds = terminate_grace_seconds
        self._running: dict[str, ProcessHandle] = {}

    @property
    def running_process_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._running))

    def _remove_finished(self, process_id: str) -> None:
        self._running.pop(process_id, None)

    async def start(
        self,
        spec: ProcessSpec,
        *,
        on_event: StreamCallback | None = None,
    ) -> ProcessHandle:
        argv = validate_argv(spec.argv)
        cwd = resolve_under_roots(
            spec.cwd,
            self.allowed_roots,
            require_directory=True,
        )
        env = sanitized_environment(
            spec.env,
            inherited_keys=spec.inherited_env_keys,
        )
        stdin_target = (
            asyncio.subprocess.PIPE if spec.stdin is not None else asyncio.subprocess.DEVNULL
        )
        try:
            if os.name == "posix":
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=str(cwd),
                    env=env,
                    stdin=stdin_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
            elif os.name == "nt":  # pragma: no cover - exercised on Windows CI
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=str(cwd),
                    env=env,
                    stdin=stdin_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=0x00000200,  # CREATE_NEW_PROCESS_GROUP
                )
            else:  # pragma: no cover - defensive portability fallback
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=str(cwd),
                    env=env,
                    stdin=stdin_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
        except (OSError, ValueError) as exc:
            raise ProcessExecutionError(
                f"failed to start executable {redact_text(argv[0])!r}: {exc}"
            ) from exc

        normalized_spec = ProcessSpec(
            argv=argv,
            cwd=cwd,
            stdin=spec.stdin,
            timeout_seconds=spec.timeout_seconds,
            env=dict(spec.env),
            inherited_env_keys=spec.inherited_env_keys,
            allowed_exit_codes=spec.allowed_exit_codes,
        )
        process_id = f"proc_{secrets.token_hex(12)}"
        pgid: int | None = None
        if os.name == "posix":
            try:
                pgid = os.getpgid(process.pid)
            except ProcessLookupError:
                pgid = None
        handle = ProcessHandle(
            process_id=process_id,
            spec=normalized_spec,
            process=process,
            started_monotonic=time.monotonic(),
            process_group_id=pgid,
            max_capture_bytes=self.max_capture_bytes,
            terminate_grace_seconds=self.terminate_grace_seconds,
            on_event=on_event,
            on_finished=self._remove_finished,
            environment_record=redact_mapping(env),
        )
        self._running[process_id] = handle
        if spec.stdin is not None and process.stdin is not None:
            try:
                process.stdin.write(spec.stdin)
                await process.stdin.drain()
                process.stdin.close()
            except (BrokenPipeError, ConnectionResetError) as exc:
                await handle.cancel(reason="stdin_write_failed")
                await handle.wait()
                raise ProcessExecutionError("process closed stdin before input was sent") from exc
        return handle

    async def run_spec(
        self,
        spec: ProcessSpec,
        *,
        on_event: StreamCallback | None = None,
        check: bool = False,
    ) -> ProcessResult:
        handle = await self.start(spec, on_event=on_event)
        result = await handle.wait()
        if check and result.exit_code not in spec.allowed_exit_codes:
            raise ProcessExecutionError(
                f"command exited {result.exit_code}: {result.stderr or result.stdout}"
            )
        return result

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        stdin: bytes | None = None,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
        inherited_env_keys: Iterable[str] = MINIMAL_SUBPROCESS_ENV_KEYS,
        inherit_env: bool | None = None,
        allowed_exit_codes: Sequence[int] = (0,),
        on_event: StreamCallback | None = None,
        check: bool = False,
    ) -> ProcessResult:
        spec = ProcessSpec.build(
            argv,
            cwd=cwd,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            env=env,
            inherited_env_keys=inherited_env_keys,
            inherit_env=inherit_env,
            allowed_exit_codes=allowed_exit_codes,
        )
        return await self.run_spec(spec, on_event=on_event, check=check)

    async def cancel(self, process_id: str, *, reason: str = "revoked") -> bool:
        handle = self._running.get(process_id)
        if handle is None:
            return False
        return await handle.cancel(reason=reason)
