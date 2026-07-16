from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from tars_revoke.adapters.codex import (
    CodexAuthenticationError,
    CodexCLIAdapter,
    CodexExecutable,
    CodexModelError,
    CodexProtocolError,
    CodexQuotaError,
    CodexSandbox,
    CodexTimeoutError,
)
from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.errors import ValidationError


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def _fake_codex(path: Path) -> Path:
    return _executable(
        path,
        r"""
import json
import os
import pathlib
import sys
import time

args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 999.1-test")
    raise SystemExit(0)

pathlib.Path("argv-capture.json").write_text(json.dumps(args), encoding="utf-8")
pathlib.Path("env-capture.json").write_text(json.dumps({
    "openai_auth": "OPENAI_API_KEY" in os.environ,
    "codex_auth": "CODEX_API_KEY" in os.environ,
    "unrelated_credential": "SENTINEL_CREDENTIAL" in os.environ,
}), encoding="utf-8")
prompt = sys.stdin.read().strip()

def option(name):
    if name not in args:
        return None
    return args[args.index(name) + 1]

last_message = pathlib.Path(option("--output-last-message"))
model = option("--model")
if model == "auth-model":
    last_message.write_text("api_key=sk-1234567890abcdefghijkl", encoding="utf-8")
    print("not logged in", file=sys.stderr)
    raise SystemExit(2)
if model == "bad-model":
    print("model_not_found", file=sys.stderr)
    raise SystemExit(2)
if model == "quota-model":
    print("unrelated plugin sync warning", file=sys.stderr)
    print("You've hit your usage limit; try again later.")
    raise SystemExit(1)
if prompt == "event-auth":
    last_message.write_text("api_key=sk-1234567890abcdefghijkl", encoding="utf-8")
    print(json.dumps({
        "type": "turn.failed",
        "thread_id": "thread-event-auth",
        "error": {"message": "Authentication required"},
    }))
    raise SystemExit(0)
if prompt == "sleep":
    time.sleep(2)

thread_id = "thread-new"
if "resume" in args:
    thread_id = next(value for value in args if value.startswith("thread-"))
turn_id = "turn-1"
schema = option("--output-schema")
if schema:
    final = '{"answer": 7}' if prompt == "invalid-output" else '{"answer": "ok"}'
else:
    final = "done: " + prompt
last_message.write_text(final, encoding="utf-8")
print(json.dumps({"type": "thread.started", "thread_id": thread_id}))
print(json.dumps({"type": "turn.started", "id": turn_id, "thread_id": thread_id}))
print(json.dumps({
    "type": "item.completed",
    "thread_id": thread_id,
    "turn_id": turn_id,
    "item": {"id": "item-1", "type": "agent_message", "text": final},
}))
""",
    )


def test_default_discovery_prefers_current_chatgpt_app_bundle() -> None:
    assert CodexCLIAdapter.OFFICIAL_CANDIDATES[:2] == (
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path.home() / "Applications/ChatGPT.app/Contents/Resources/codex",
    )


async def _adapter(tmp_path: Path) -> CodexCLIAdapter:
    executable = _fake_codex(tmp_path / "codex-fake")
    runner = AsyncProcessRunner([tmp_path])
    discovered = await CodexCLIAdapter.discover_executable(
        process_runner=runner,
        probe_cwd=tmp_path,
        explicit_bin=executable,
        official_candidates=(),
    )
    return CodexCLIAdapter(
        process_runner=runner,
        executable=discovered,
        artifacts_root=tmp_path / "artifacts",
        allowed_roots=[tmp_path],
    )


@pytest.mark.asyncio
async def test_discovery_skips_unverified_candidate(tmp_path: Path) -> None:
    broken = _executable(
        tmp_path / "not-codex",
        "import sys\nprint('different tool')\n",
    )
    working = _fake_codex(tmp_path / "codex-fake")
    runner = AsyncProcessRunner([tmp_path])

    found = await CodexCLIAdapter.discover_executable(
        process_runner=runner,
        probe_cwd=tmp_path,
        explicit_bin=broken,
        official_candidates=(working,),
    )

    assert found.path == working.resolve()
    assert found.version == "codex-cli 999.1-test"
    assert found.failed_candidates


@pytest.mark.asyncio
async def test_jsonl_schema_thread_capture_and_stdin_only_prompt(tmp_path: Path) -> None:
    adapter = await _adapter(tmp_path)
    seen: list[object] = []
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
        "additionalProperties": False,
    }
    prompt = "literal $(touch should-never-run)"
    result = await adapter.execute(
        prompt,
        cwd=tmp_path,
        sandbox=CodexSandbox.READ_ONLY,
        output_schema=schema,
        on_event=seen.append,
        skip_git_repo_check=True,
    )

    assert result.thread_id == "thread-new"
    assert result.turn_ids == ("turn-1",)
    assert result.item_ids == ("item-1",)
    assert result.structured_output == {"answer": "ok"}
    assert result.output_schema_digest
    assert len(seen) == 3
    argv = json.loads((tmp_path / "argv-capture.json").read_text(encoding="utf-8"))
    assert prompt not in argv
    assert argv[-1] == "-"
    assert "--ignore-user-config" in argv
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "--skip-git-repo-check" in argv
    schema_files = tuple((tmp_path / "artifacts").glob("output-schema-*.json"))
    assert len(schema_files) == 1
    assert json.loads(schema_files[0].read_text(encoding="utf-8")) == schema
    assert stat.S_IMODE(schema_files[0].stat().st_mode) == 0o600
    assert not (tmp_path / "should-never-run").exists()


@pytest.mark.asyncio
async def test_resume_uses_workspace_write_and_captures_requested_thread(tmp_path: Path) -> None:
    adapter = await _adapter(tmp_path)
    result = await adapter.execute(
        "continue",
        cwd=tmp_path,
        sandbox="workspace-write",
        thread_id="thread-existing",
    )

    assert result.thread_id == "thread-existing"
    argv = json.loads((tmp_path / "argv-capture.json").read_text(encoding="utf-8"))
    assert argv[:2] == ["exec", "resume"]
    assert "--ignore-user-config" in argv
    assert 'sandbox_mode="workspace-write"' in argv
    assert "thread-existing" in argv


@pytest.mark.asyncio
async def test_codex_child_alone_receives_allowlisted_auth_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-codex-only-environment-credential-123456")
    monkeypatch.setenv("CODEX_API_KEY", "sk-codex-alternate-credential-123456")
    monkeypatch.setenv("SENTINEL_CREDENTIAL", "sk-never-inherit-this-credential-123456")
    adapter = await _adapter(tmp_path)

    result = await adapter.execute("hello", cwd=tmp_path, sandbox="read-only")

    captured = json.loads((tmp_path / "env-capture.json").read_text(encoding="utf-8"))
    assert captured == {
        "openai_auth": True,
        "codex_auth": True,
        "unrelated_credential": False,
    }
    assert result.process.environment["OPENAI_API_KEY"] == "<redacted>"
    assert result.process.environment["CODEX_API_KEY"] == "<redacted>"
    assert "SENTINEL_CREDENTIAL" not in result.process.environment


@pytest.mark.asyncio
async def test_auth_model_and_success_event_failures_are_explicit_and_sanitized(
    tmp_path: Path,
) -> None:
    adapter = await _adapter(tmp_path)

    with pytest.raises(CodexAuthenticationError, match="authentication failed"):
        await adapter.execute(
            "hello",
            cwd=tmp_path,
            sandbox="read-only",
            model="auth-model",
        )
    last_files = tuple((tmp_path / "artifacts").glob("codex-last-*.txt"))
    assert last_files
    assert "sk-1234567890abcdefghijkl" not in last_files[-1].read_text(encoding="utf-8")

    with pytest.raises(CodexModelError, match="rejected model"):
        await adapter.execute(
            "hello",
            cwd=tmp_path,
            sandbox="read-only",
            model="bad-model",
        )
    with pytest.raises(CodexQuotaError, match="quota is exhausted"):
        await adapter.execute(
            "hello",
            cwd=tmp_path,
            sandbox="read-only",
            model="quota-model",
        )
    with pytest.raises(CodexAuthenticationError, match="authentication failed"):
        await adapter.execute("event-auth", cwd=tmp_path, sandbox="read-only")


@pytest.mark.asyncio
async def test_timeout_schema_mismatch_and_invalid_input_are_explicit(tmp_path: Path) -> None:
    adapter = await _adapter(tmp_path)
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
    }

    with pytest.raises(CodexProtocolError, match="must be string"):
        await adapter.execute(
            "invalid-output",
            cwd=tmp_path,
            sandbox="read-only",
            output_schema=schema,
        )
    with pytest.raises(CodexTimeoutError, match="timed out"):
        await adapter.execute(
            "sleep",
            cwd=tmp_path,
            sandbox="read-only",
            timeout_seconds=0.05,
        )
    with pytest.raises(ValidationError, match="secret-looking"):
        await adapter.execute(
            "api_key=sk-1234567890abcdefghijkl",
            cwd=tmp_path,
            sandbox="read-only",
        )
    with pytest.raises(ValidationError, match="read-only or workspace-write"):
        await adapter.execute("hello", cwd=tmp_path, sandbox="danger-full-access")


@pytest.mark.asyncio
async def test_health_reprobes_verified_executable(tmp_path: Path) -> None:
    adapter = await _adapter(tmp_path)
    health = await adapter.health()
    assert health.healthy
    assert health.version == "codex-cli 999.1-test"
    assert isinstance(adapter.executable, CodexExecutable)
