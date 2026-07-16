from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.demo.fixture import FixtureBuilder
from tars_revoke.demo.registry import SchemaRegistryProcess


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", "-C", str(cwd), *args),
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.asyncio
async def test_fixture_is_real_isolated_git_and_denies_raw_agent_push(tmp_path: Path) -> None:
    fixture = await FixtureBuilder(tmp_path).build("run-fixture")

    assert fixture.agent_a_worktree.is_dir()
    assert fixture.agent_b_worktree.is_dir()
    assert fixture.remote.is_dir()
    assert fixture.state_database.parent == fixture.artifacts_root
    assert fixture.registry_private_key_file.stat().st_mode & 0o077 == 0
    assert fixture.registry_token_file.stat().st_mode & 0o077 == 0
    assert _git("rev-parse", "HEAD", cwd=fixture.agent_a_worktree).stdout.strip() == (
        fixture.baseline_commit
    )
    assert _git("rev-parse", "HEAD", cwd=fixture.agent_b_worktree).stdout.strip() == (
        fixture.baseline_commit
    )

    raw = _git(
        "push",
        "origin",
        "HEAD:refs/heads/agent-a-raw",
        cwd=fixture.agent_a_worktree,
    )
    assert raw.returncode != 0
    assert "missing gateway capability" in raw.stderr
    assert (
        _git(
            "show-ref",
            "--verify",
            "--quiet",
            "refs/heads/agent-a-raw",
            cwd=fixture.remote,
        ).returncode
        != 0
    )


@pytest.mark.asyncio
async def test_fixture_registry_is_a_separate_signed_monotonic_http_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-must-not-reach-registry-child-123456")
    monkeypatch.setenv("SENTINEL_CREDENTIAL", "sk-must-not-reach-registry-child-654321")
    fixture = await FixtureBuilder(tmp_path).build("run-registry")
    runner = AsyncProcessRunner([fixture.root])
    registry = await SchemaRegistryProcess.start(fixture, runner=runner)
    try:
        schema_v1 = json.loads(
            (fixture.repository / "schemas" / "billing-v1.json").read_text(encoding="utf-8")
        )
        schema_v2 = json.loads(
            (fixture.repository / "schemas" / "billing-v2.json").read_text(encoding="utf-8")
        )
        first = await registry.client.publish("billing-customer", version=1, content=schema_v1)
        second = await registry.client.publish("billing-customer", version=2, content=schema_v2)
        latest = await registry.client.latest("billing-customer")

        assert first.artifact.version == 1
        assert second.artifact.version == 2
        assert latest.artifact.digest == second.artifact.digest
        assert latest.artifact.source_id == fixture.registry_source_id
        assert latest.artifact.content["properties"]["customer_id"]["pattern"].startswith("^cus_")
    finally:
        await registry.close()
    process = await registry.handle.wait()
    assert "OPENAI_API_KEY" not in process.environment
    assert "SENTINEL_CREDENTIAL" not in process.environment
