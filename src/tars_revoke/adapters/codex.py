from __future__ import annotations

import inspect
import json
import os
import re
import secrets
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from tars_revoke.errors import AdapterError, AuthorizationError, IntegrityError, ValidationError

from ._safety import (
    CODEX_RUNTIME_ENV_KEYS,
    CODEX_SUBPROCESS_ENV_KEYS,
    canonical_json,
    normalize_roots,
    redact_text,
    require_no_secret_values,
    require_non_secret_payload,
    resolve_under_roots,
    sha256_bytes,
)
from .base import AdapterHealth, EventCallback
from .processes import (
    AsyncProcessRunner,
    ProcessEvent,
    ProcessHandle,
    ProcessResult,
    ProcessSpec,
)


class CodexError(AdapterError):
    pass


class CodexDiscoveryError(CodexError):
    pass


class CodexAuthenticationError(AuthorizationError):
    pass


class CodexModelError(CodexError):
    pass


class CodexQuotaError(CodexError):
    pass


class CodexProtocolError(IntegrityError):
    pass


class CodexTimeoutError(CodexError):
    pass


class CodexCancelledError(CodexError):
    pass


class CodexSandbox(str, Enum):
    READ_ONLY = "read-only"
    WORKSPACE_WRITE = "workspace-write"


@dataclass(frozen=True)
class CodexExecutable:
    path: Path
    version: str
    failed_candidates: tuple[str, ...] = ()


@dataclass(frozen=True)
class CodexEvent:
    sequence: int
    event_type: str
    raw: Mapping[str, Any]
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None


@dataclass(frozen=True)
class CodexRequest:
    prompt: str
    cwd: Path
    sandbox: CodexSandbox
    output_schema: Mapping[str, Any] | Path | None = None
    model: str | None = None
    timeout_seconds: float = 900.0
    thread_id: str | None = None
    skip_git_repo_check: bool = False


@dataclass(frozen=True)
class CodexRunResult:
    process: ProcessResult
    executable: CodexExecutable
    sandbox: CodexSandbox
    model: str | None
    thread_id: str
    turn_ids: tuple[str, ...]
    item_ids: tuple[str, ...]
    events: tuple[CodexEvent, ...]
    final_message: str
    structured_output: Any | None
    output_schema_digest: str | None


_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}\Z")
_THREAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_AUTH_PATTERNS = (
    "not logged in",
    "authentication required",
    "authentication failed",
    "unauthorized",
    "missing api key",
    "invalid api key",
    "http 401",
    "status 401",
)
_MODEL_PATTERNS = (
    "model_not_found",
    "model not found",
    "unsupported model",
    "invalid model",
    "model is not available",
    "does not have access to model",
)
_QUOTA_PATTERNS = (
    "you've hit your usage limit",
    "you have hit your usage limit",
    "usage limit reached",
    "quota exceeded",
    "insufficient_quota",
    "rate limit exceeded",
)


def _nested_identifier(value: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    for container in ("thread", "turn", "item", "payload"):
        nested = value.get(container)
        if isinstance(nested, Mapping):
            found = _nested_identifier(nested, *keys)
            if found:
                return found
    return None


def _event_from_raw(sequence: int, raw: Mapping[str, Any]) -> CodexEvent:
    event_type = str(raw.get("type") or raw.get("event") or "unknown")
    top_level_id = raw.get("id")
    return CodexEvent(
        sequence=sequence,
        event_type=event_type,
        raw=dict(raw),
        thread_id=(
            str(top_level_id)
            if event_type.startswith("thread.") and isinstance(top_level_id, str)
            else _nested_identifier(raw, "thread_id", "threadId")
        ),
        turn_id=(
            str(top_level_id)
            if event_type.startswith("turn.") and isinstance(top_level_id, str)
            else _nested_identifier(raw, "turn_id", "turnId")
        ),
        item_id=_nested_identifier(raw, "item_id", "itemId", "id")
        if event_type.startswith("item.")
        else _nested_identifier(raw, "item_id", "itemId"),
    )


def parse_codex_jsonl(text: str) -> tuple[CodexEvent, ...]:
    events: list[CodexEvent] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CodexProtocolError(
                f"Codex emitted non-JSON output on JSONL stream at line {line_number}"
            ) from exc
        if not isinstance(raw, dict):
            raise CodexProtocolError(f"Codex JSONL line {line_number} is not an object")
        events.append(_event_from_raw(len(events) + 1, raw))
    if not events:
        raise CodexProtocolError("Codex emitted no JSONL events")
    return tuple(events)


def _validate_schema(instance: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    if "$ref" in schema:
        raise CodexProtocolError("output schemas containing $ref are not supported by this adapter")
    if "allOf" in schema:
        for child in schema["allOf"]:
            _validate_schema(instance, child, path)
    if "anyOf" in schema:
        failures = 0
        for child in schema["anyOf"]:
            try:
                _validate_schema(instance, child, path)
                break
            except CodexProtocolError:
                failures += 1
        if failures == len(schema["anyOf"]):
            raise CodexProtocolError(f"structured output at {path} matches no anyOf branch")
    if "oneOf" in schema:
        matches = 0
        for child in schema["oneOf"]:
            try:
                _validate_schema(instance, child, path)
                matches += 1
            except CodexProtocolError:
                pass
        if matches != 1:
            raise CodexProtocolError(f"structured output at {path} must match exactly one branch")
    if "const" in schema and instance != schema["const"]:
        raise CodexProtocolError(f"structured output at {path} violates const")
    if "enum" in schema and instance not in schema["enum"]:
        raise CodexProtocolError(f"structured output at {path} is outside enum")

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        candidates = [{**schema, "type": item} for item in expected_type]
        for candidate in candidates:
            try:
                _validate_schema(instance, candidate, path)
                return
            except CodexProtocolError:
                pass
        raise CodexProtocolError(f"structured output at {path} has the wrong type")
    type_checks: dict[str, Callable[[Any], bool]] = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda value: isinstance(value, int | float) and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
        "null": lambda value: value is None,
    }
    if expected_type in type_checks and not type_checks[expected_type](instance):
        raise CodexProtocolError(f"structured output at {path} must be {expected_type}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in instance]
        if missing:
            raise CodexProtocolError(f"structured output at {path} is missing {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = sorted(set(instance) - set(properties))
            if extra:
                raise CodexProtocolError(f"structured output at {path} has extra fields {extra}")
        for key, child in properties.items():
            if key in instance:
                _validate_schema(instance[key], child, f"{path}.{key}")
    elif isinstance(instance, list):
        if len(instance) < int(schema.get("minItems", 0)):
            raise CodexProtocolError(f"structured output at {path} has too few items")
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            raise CodexProtocolError(f"structured output at {path} has too many items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(instance):
                _validate_schema(item, item_schema, f"{path}[{index}]")
    elif isinstance(instance, str):
        if len(instance) < int(schema.get("minLength", 0)):
            raise CodexProtocolError(f"structured output at {path} is too short")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise CodexProtocolError(f"structured output at {path} is too long")
        if "pattern" in schema and re.search(str(schema["pattern"]), instance) is None:
            raise CodexProtocolError(f"structured output at {path} does not match pattern")
    elif isinstance(instance, int | float) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise CodexProtocolError(f"structured output at {path} is below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise CodexProtocolError(f"structured output at {path} exceeds maximum")


class _StreamingJsonl:
    def __init__(self, callback: EventCallback | None) -> None:
        self.callback = callback
        self.buffer = ""
        self.sequence = 0

    async def feed(self, event: ProcessEvent) -> None:
        if event.channel != "stdout":
            return
        self.buffer += event.text
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            await self._emit(line)

    async def flush(self) -> None:
        if self.buffer.strip():
            await self._emit(self.buffer)
        self.buffer = ""

    async def _emit(self, line: str) -> None:
        if not line.strip() or self.callback is None:
            return
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(raw, dict):
            return
        self.sequence += 1
        result = self.callback(_event_from_raw(self.sequence, raw))
        if inspect.isawaitable(result):
            await result


class CodexRunHandle:
    def __init__(
        self,
        *,
        adapter: CodexCLIAdapter,
        request: CodexRequest,
        process: ProcessHandle,
        schema: Mapping[str, Any] | None,
        schema_digest: str | None,
        last_message_path: Path,
        stream: _StreamingJsonl,
    ) -> None:
        self.adapter = adapter
        self.request = request
        self.process = process
        self.schema = schema
        self.schema_digest = schema_digest
        self.last_message_path = last_message_path
        self.stream = stream

    @property
    def process_id(self) -> str:
        return self.process.process_id

    async def cancel(self, *, reason: str = "revoked") -> bool:
        return await self.process.cancel(reason=reason)

    async def wait(self) -> CodexRunResult:
        result = await self.process.wait()
        await self.stream.flush()
        return self.adapter._finish(
            request=self.request,
            process=result,
            schema=self.schema,
            schema_digest=self.schema_digest,
            last_message_path=self.last_message_path,
        )


class CodexCLIAdapter:
    OFFICIAL_CANDIDATES = (
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path.home() / "Applications/ChatGPT.app/Contents/Resources/codex",
        Path("/Applications/Codex.app/Contents/Resources/codex"),
        Path.home() / "Applications/Codex.app/Contents/Resources/codex",
        Path("/Applications/Codex.app/Contents/MacOS/codex"),
    )

    def __init__(
        self,
        *,
        process_runner: AsyncProcessRunner,
        executable: CodexExecutable,
        artifacts_root: Path,
        allowed_roots: Sequence[Path],
        default_model: str | None = None,
    ) -> None:
        self.runner = process_runner
        self.executable = executable
        self.allowed_roots = normalize_roots(allowed_roots)
        self.artifacts_root = resolve_under_roots(
            artifacts_root,
            self.allowed_roots,
            must_exist=False,
        )
        self.artifacts_root.mkdir(parents=True, exist_ok=True)
        if default_model is not None and not _MODEL.fullmatch(default_model):
            raise ValidationError("invalid default Codex model")
        self.default_model = default_model

    @classmethod
    async def discover_executable(
        cls,
        *,
        process_runner: AsyncProcessRunner,
        probe_cwd: Path,
        explicit_bin: Path | None = None,
        official_candidates: Sequence[Path] | None = None,
    ) -> CodexExecutable:
        candidates: list[Path] = []
        if explicit_bin is not None:
            candidates.append(Path(explicit_bin).expanduser())
        candidates.extend(official_candidates or cls.OFFICIAL_CANDIDATES)
        path_candidate = shutil.which("codex")
        if path_candidate:
            candidates.append(Path(path_candidate))
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            text = str(candidate)
            if text not in seen:
                seen.add(text)
                unique.append(candidate)
        failures: list[str] = []
        for candidate in unique:
            try:
                resolved = candidate.resolve(strict=True)
                if not resolved.is_file() or not os.access(resolved, os.X_OK):
                    failures.append(f"{candidate}: not executable")
                    continue
                result = await process_runner.run(
                    (str(resolved), "--version"),
                    cwd=probe_cwd,
                    timeout_seconds=10,
                    inherited_env_keys=CODEX_RUNTIME_ENV_KEYS,
                )
                version = (result.stdout or result.stderr).strip().splitlines()[0]
                if result.exit_code != 0 or "codex" not in version.lower():
                    failures.append(f"{candidate}: verification failed")
                    continue
                return CodexExecutable(resolved, version, tuple(failures))
            except (OSError, AdapterError, IndexError) as exc:
                failures.append(f"{candidate}: {redact_text(str(exc))}")
        detail = "; ".join(failures) or "no candidates found"
        raise CodexDiscoveryError(f"no working Codex executable: {detail}")

    async def health(self) -> AdapterHealth:
        try:
            result = await self.runner.run(
                (str(self.executable.path), "--version"),
                cwd=self.artifacts_root,
                timeout_seconds=10,
                inherited_env_keys=CODEX_RUNTIME_ENV_KEYS,
            )
        except AdapterError as exc:
            return AdapterHealth(False, "codex", detail=redact_text(str(exc)))
        return AdapterHealth(
            result.exit_code == 0,
            "codex",
            version=(result.stdout or result.stderr).strip(),
            detail=None if result.exit_code == 0 else "version probe failed",
        )

    def _schema_file(
        self,
        output_schema: Mapping[str, Any] | Path | None,
    ) -> tuple[Path | None, Mapping[str, Any] | None, str | None]:
        if output_schema is None:
            return None, None, None
        if isinstance(output_schema, Path):
            schema_path = resolve_under_roots(
                output_schema,
                self.allowed_roots,
                require_directory=False,
            )
            try:
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValidationError("invalid output schema file") from exc
            if not isinstance(schema, dict):
                raise ValidationError("output schema root must be an object")
        else:
            schema = dict(output_schema)
            require_no_secret_values(schema, path="output_schema")
            encoded = canonical_json(schema)
            digest = sha256_bytes(encoded)
            schema_path = self.artifacts_root / f"output-schema-{digest}.json"
            if not schema_path.exists():
                temporary = schema_path.with_name(f".{schema_path.name}.{secrets.token_hex(6)}.tmp")
                temporary.write_bytes(encoded)
                temporary.chmod(0o600)
                os.replace(temporary, schema_path)
        digest = sha256_bytes(canonical_json(schema))
        return schema_path, schema, digest

    async def start(
        self,
        request: CodexRequest,
        *,
        on_event: EventCallback | None = None,
    ) -> CodexRunHandle:
        cwd = resolve_under_roots(
            request.cwd,
            self.allowed_roots,
            require_directory=True,
        )
        if not request.prompt.strip() or "\x00" in request.prompt:
            raise ValidationError("Codex prompt must be non-empty and NUL-free")
        if redact_text(request.prompt) != request.prompt:
            raise ValidationError("Codex prompt contains secret-looking material")
        model = request.model or self.default_model
        if model is not None and not _MODEL.fullmatch(model):
            raise ValidationError("invalid Codex model")
        if request.thread_id is not None and not _THREAD.fullmatch(request.thread_id):
            raise ValidationError("invalid Codex thread ID")
        if request.timeout_seconds <= 0:
            raise ValidationError("Codex timeout must be positive")
        schema_path, schema, schema_digest = self._schema_file(request.output_schema)
        last_message = self.artifacts_root / f"codex-last-{secrets.token_hex(12)}.txt"
        argv: list[str] = [str(self.executable.path), "exec"]
        if request.thread_id is None:
            argv.extend(
                [
                    "--ignore-user-config",
                    "--json",
                    "--color",
                    "never",
                    "--sandbox",
                    request.sandbox.value,
                    "--cd",
                    str(cwd),
                ]
            )
            if request.skip_git_repo_check:
                argv.append("--skip-git-repo-check")
        else:
            argv.extend(
                [
                    "resume",
                    "--ignore-user-config",
                    "--json",
                    "-c",
                    f'sandbox_mode="{request.sandbox.value}"',
                ]
            )
            if request.skip_git_repo_check:
                argv.append("--skip-git-repo-check")
        if model is not None:
            argv.extend(("--model", model))
        if schema_path is not None:
            argv.extend(("--output-schema", str(schema_path)))
        argv.extend(("--output-last-message", str(last_message)))
        if request.thread_id is not None:
            argv.append(request.thread_id)
        argv.append("-")

        stream = _StreamingJsonl(on_event)
        spec = ProcessSpec.build(
            argv,
            cwd=cwd,
            stdin=(request.prompt + "\n").encode("utf-8"),
            timeout_seconds=request.timeout_seconds,
            inherited_env_keys=CODEX_SUBPROCESS_ENV_KEYS,
        )
        process = await self.runner.start(spec, on_event=stream.feed)
        return CodexRunHandle(
            adapter=self,
            request=CodexRequest(
                prompt=request.prompt,
                cwd=cwd,
                sandbox=request.sandbox,
                output_schema=request.output_schema,
                model=model,
                timeout_seconds=request.timeout_seconds,
                thread_id=request.thread_id,
                skip_git_repo_check=request.skip_git_repo_check,
            ),
            process=process,
            schema=schema,
            schema_digest=schema_digest,
            last_message_path=last_message,
            stream=stream,
        )

    async def execute(
        self,
        prompt: str,
        *,
        cwd: Path,
        sandbox: CodexSandbox | str,
        output_schema: Mapping[str, Any] | Path | None = None,
        model: str | None = None,
        thread_id: str | None = None,
        timeout_seconds: float = 900.0,
        on_event: EventCallback | None = None,
        skip_git_repo_check: bool = False,
    ) -> CodexRunResult:
        try:
            sandbox_value = sandbox if isinstance(sandbox, CodexSandbox) else CodexSandbox(sandbox)
        except ValueError as exc:
            raise ValidationError("Codex sandbox must be read-only or workspace-write") from exc
        handle = await self.start(
            CodexRequest(
                prompt=prompt,
                cwd=cwd,
                sandbox=sandbox_value,
                output_schema=output_schema,
                model=model,
                thread_id=thread_id,
                timeout_seconds=timeout_seconds,
                skip_git_repo_check=skip_git_repo_check,
            ),
            on_event=on_event,
        )
        return await handle.wait()

    def _finish(
        self,
        *,
        request: CodexRequest,
        process: ProcessResult,
        schema: Mapping[str, Any] | None,
        schema_digest: str | None,
        last_message_path: Path,
    ) -> CodexRunResult:
        final_message = ""
        if last_message_path.exists():
            final_message = redact_text(
                last_message_path.read_text(encoding="utf-8", errors="replace")
            )
            last_message_path.write_text(final_message, encoding="utf-8")
            last_message_path.chmod(0o600)
        if process.timed_out:
            raise CodexTimeoutError("Codex execution timed out")
        if process.cancelled:
            raise CodexCancelledError(
                f"Codex execution cancelled: {process.cancellation_reason or 'revoked'}"
            )
        combined = f"{process.stderr}\n{process.stdout}".lower()
        if process.exit_code != 0:
            if any(pattern in combined for pattern in _AUTH_PATTERNS):
                raise CodexAuthenticationError("Codex authentication failed")
            if any(pattern in combined for pattern in _MODEL_PATTERNS):
                raise CodexModelError(f"Codex rejected model {request.model or '<default>'}")
            if any(pattern in combined for pattern in _QUOTA_PATTERNS):
                raise CodexQuotaError("Codex usage quota is exhausted")
            detail = "\n".join(
                item.strip() for item in (process.stdout, process.stderr) if item.strip()
            )
            raise CodexError(
                f"Codex exited {process.exit_code}: {detail[:1000]}"
            )
        if process.output_truncated:
            raise CodexProtocolError("Codex JSONL output was truncated")
        events = parse_codex_jsonl(process.stdout)
        failed_events = tuple(
            event
            for event in events
            if "error" in event.event_type.lower() or "failed" in event.event_type.lower()
        )
        if failed_events:
            event_text = redact_text(
                " ".join(json.dumps(event.raw, sort_keys=True) for event in failed_events)
            ).lower()
            if any(pattern in event_text for pattern in _AUTH_PATTERNS):
                raise CodexAuthenticationError("Codex authentication failed")
            if any(pattern in event_text for pattern in _MODEL_PATTERNS):
                raise CodexModelError(f"Codex rejected model {request.model or '<default>'}")
            if any(pattern in event_text for pattern in _QUOTA_PATTERNS):
                raise CodexQuotaError("Codex usage quota is exhausted")
            raise CodexError("Codex reported a failed execution event")
        thread_ids = [event.thread_id for event in events if event.thread_id]
        thread_id = thread_ids[0] if thread_ids else request.thread_id
        if not thread_id:
            raise CodexProtocolError("Codex did not report a thread ID")
        if any(item != thread_id for item in thread_ids):
            raise CodexProtocolError("Codex JSONL contains multiple thread IDs")

        if not final_message.strip():
            for event in reversed(events):
                item = event.raw.get("item")
                if isinstance(item, Mapping) and item.get("type") == "agent_message":
                    text = item.get("text")
                    if isinstance(text, str):
                        final_message = text
                        break
        if not final_message.strip():
            raise CodexProtocolError("Codex completed without a final message")

        structured_output: Any | None = None
        if schema is not None:
            try:
                structured_output = json.loads(final_message)
            except json.JSONDecodeError as exc:
                raise CodexProtocolError(
                    "Codex final response is not valid structured JSON"
                ) from exc
            _validate_schema(structured_output, schema)
            require_non_secret_payload(structured_output, path="codex_output")

        turn_ids = tuple(dict.fromkeys(event.turn_id for event in events if event.turn_id))
        item_ids = tuple(dict.fromkeys(event.item_id for event in events if event.item_id))
        return CodexRunResult(
            process=process,
            executable=self.executable,
            sandbox=request.sandbox,
            model=request.model,
            thread_id=thread_id,
            turn_ids=turn_ids,
            item_ids=item_ids,
            events=events,
            final_message=final_message,
            structured_output=structured_output,
            output_schema_digest=schema_digest,
        )
