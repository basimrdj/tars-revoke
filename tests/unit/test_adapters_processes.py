from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tars_revoke.adapters._safety import MINIMAL_SUBPROCESS_ENV_KEYS
from tars_revoke.adapters.processes import (
    AsyncProcessRunner,
    ProcessExecutionError,
    ProcessSpec,
)
from tars_revoke.errors import ValidationError


@pytest.mark.asyncio
async def test_runner_uses_argv_stdin_and_redacts_capture(tmp_path: Path) -> None:
    runner = AsyncProcessRunner([tmp_path])
    marker = tmp_path / "must-not-exist"
    literal = f"$(touch {marker})"
    code = (
        "import os,sys; "
        "data=sys.stdin.read(); "
        "print(data, end=''); "
        "print(os.environ['API_KEY'], file=sys.stderr); "
        "raise SystemExit(3)"
    )

    result = await runner.run(
        (sys.executable, "-c", code),
        cwd=tmp_path,
        stdin=literal.encode(),
        env={"API_KEY": "sk-1234567890abcdefghijkl"},
        allowed_exit_codes=(3,),
    )

    assert result.exit_code == 3
    assert result.succeeded
    assert literal in result.stdout
    assert not marker.exists()
    assert "sk-1234567890abcdefghijkl" not in result.stderr
    assert "<redacted>" in result.stderr
    assert result.environment["API_KEY"] == "<redacted>"
    assert set(result.environment) <= MINIMAL_SUBPROCESS_ENV_KEYS | {"API_KEY"}
    assert runner.running_process_ids == ()


def test_process_spec_rejects_shell_strings_and_invalid_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="argv sequences"):
        ProcessSpec.build("echo unsafe", cwd=tmp_path)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="positive"):
        ProcessSpec.build(("echo", "ok"), cwd=tmp_path, timeout_seconds=0)
    with pytest.raises(ValidationError, match="broad environment inheritance"):
        ProcessSpec.build(("echo", "ok"), cwd=tmp_path, inherit_env=True)
    with pytest.raises(ValidationError, match="portable names"):
        ProcessSpec.build(("echo", "ok"), cwd=tmp_path, env={"BAD=NAME": "value"})


@pytest.mark.asyncio
async def test_default_environment_excludes_ambient_credentials_and_records_actual_child_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "sk-sentinel-environment-credential-123456"
    monkeypatch.setenv("OPENAI_API_KEY", sentinel)
    monkeypatch.setenv("GITHUB_TOKEN", sentinel)
    monkeypatch.setenv("SENTINEL_CREDENTIAL", sentinel)
    runner = AsyncProcessRunner([tmp_path])
    code = (
        "import os; "
        "names=('OPENAI_API_KEY','GITHUB_TOKEN','SENTINEL_CREDENTIAL'); "
        "raise SystemExit(9 if any(name in os.environ for name in names) else 0)"
    )

    result = await runner.run((sys.executable, "-c", code), cwd=tmp_path)

    assert result.succeeded
    assert set(result.environment) <= MINIMAL_SUBPROCESS_ENV_KEYS
    assert "OPENAI_API_KEY" not in result.environment
    assert "GITHUB_TOKEN" not in result.environment
    assert "SENTINEL_CREDENTIAL" not in result.environment


@pytest.mark.asyncio
async def test_explicit_inherited_environment_is_recorded_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "sk-explicit-codex-credential-123456"
    monkeypatch.setenv("OPENAI_API_KEY", sentinel)
    runner = AsyncProcessRunner([tmp_path])
    result = await runner.run(
        (sys.executable, "-c", "import os; assert os.environ['OPENAI_API_KEY']"),
        cwd=tmp_path,
        inherited_env_keys=("OPENAI_API_KEY",),
    )

    assert result.succeeded
    assert result.environment == {"OPENAI_API_KEY": "<redacted>"}


@pytest.mark.asyncio
async def test_runner_rejects_cwd_outside_registered_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    runner = AsyncProcessRunner([root])

    with pytest.raises(ValidationError, match="escapes registered roots"):
        await runner.run((sys.executable, "-c", "pass"), cwd=outside)


@pytest.mark.asyncio
async def test_stream_callback_failure_does_not_leak_or_deadlock(tmp_path: Path) -> None:
    runner = AsyncProcessRunner([tmp_path], max_capture_bytes=1024)

    async def broken_callback(_event: object) -> None:
        raise RuntimeError("consumer failed")

    with pytest.raises(ProcessExecutionError, match="callback failed"):
        await runner.run(
            (sys.executable, "-c", "print('x' * 100_000)"),
            cwd=tmp_path,
            on_event=broken_callback,
        )

    assert runner.running_process_ids == ()


@pytest.mark.asyncio
async def test_timeout_and_explicit_cancel_terminate_process_group(tmp_path: Path) -> None:
    runner = AsyncProcessRunner([tmp_path], terminate_grace_seconds=0.2)
    code = "import time; time.sleep(60)"

    timed_out = await runner.run(
        (sys.executable, "-c", code),
        cwd=tmp_path,
        timeout_seconds=0.05,
    )
    assert timed_out.timed_out
    assert not timed_out.succeeded

    handle = await runner.start(ProcessSpec.build((sys.executable, "-c", code), cwd=tmp_path))
    assert handle.process_id in runner.running_process_ids
    assert await runner.cancel(handle.process_id, reason="warrant revoked")
    cancelled = await handle.wait()
    assert cancelled.cancelled
    assert cancelled.cancellation_reason == "warrant revoked"
    assert runner.running_process_ids == ()
    if os.name == "posix":
        assert cancelled.process_group_id is not None


@pytest.mark.asyncio
async def test_capture_is_bounded_and_reported(tmp_path: Path) -> None:
    runner = AsyncProcessRunner([tmp_path], max_capture_bytes=1024)
    result = await runner.run(
        (sys.executable, "-c", "print('a' * 5000)"),
        cwd=tmp_path,
    )

    assert result.output_truncated
    assert len(result.stdout.encode()) <= 1024
