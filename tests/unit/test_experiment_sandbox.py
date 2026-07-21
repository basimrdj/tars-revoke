from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.demo.experiment_sandbox import build_experiment_sandbox

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="release-grade experiment isolation uses macOS sandbox-exec",
)


async def _run(tmp_path: Path, code: str):
    python = str(Path(sys.executable).absolute())
    plan = build_experiment_sandbox(
        logical_argv=(python, "-B", "-c", code),
        worktree=tmp_path,
    )
    return await AsyncProcessRunner([tmp_path]).run(
        plan.supervisor_argv,
        cwd=tmp_path,
        env=plan.environment,
        inherited_env_keys=(),
        timeout_seconds=10,
        allowed_exit_codes=(0, 1),
    )


@pytest.mark.asyncio
async def test_allow_only_sandbox_runs_the_bound_python(tmp_path: Path) -> None:
    result = await _run(tmp_path, "import json; print(json.dumps({'ok': True}))")

    assert result.exit_code == 0
    assert result.stdout.strip() == '{"ok": true}'
    assert result.environment == {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code",
    (
        "from pathlib import Path; Path('escaped').write_text('bad')",
        "import socket; socket.create_connection(('1.1.1.1', 80), timeout=1)",
        "import subprocess; subprocess.run(('/bin/sh', '-c', 'true'), check=True)",
        "from pathlib import Path; Path('/etc/hosts').read_text()",
    ),
)
async def test_allow_only_sandbox_denies_external_capabilities(
    tmp_path: Path,
    code: str,
) -> None:
    result = await _run(tmp_path, code)

    assert result.exit_code != 0
    assert not (tmp_path / "escaped").exists()


def test_profile_contains_no_broad_capability_rules(tmp_path: Path) -> None:
    python = str(Path(sys.executable).absolute())
    plan = build_experiment_sandbox(
        logical_argv=(python, "-B", "-c", "print('ok')"),
        worktree=tmp_path,
    )

    assert "(deny default)" in plan.profile
    assert "(allow process*)" not in plan.profile
    assert "(allow file-read*)\n" not in plan.profile
    assert "network" not in plan.profile
    assert "file-write" not in plan.profile
