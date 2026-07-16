from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tars_revoke.cli import app
from tars_revoke.demo import crashbench


def test_bench_cli_routes_crashbench_without_invoking_revokebench(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    async def fake_run_crashbench_suite(
        output_root: Path,
        suite: str,
    ) -> dict[str, Any]:
        observed.update(output_root=output_root, suite=suite)
        return {"suite": suite, "passed": True, "artifact_root": str(output_root)}

    monkeypatch.setattr(crashbench, "run_crashbench_suite", fake_run_crashbench_suite)
    result = CliRunner().invoke(
        app,
        [
            "bench",
            "--suite",
            "CrashBench-11",
            "--output-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "artifact_root": str(tmp_path.resolve()),
        "passed": True,
        "suite": "CrashBench-11",
    }
    assert observed == {
        "output_root": tmp_path.resolve(),
        "suite": "CrashBench-11",
    }


def test_bench_cli_rejects_an_unknown_suite_before_execution(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["bench", "--suite", "CrashBench-12", "--output-root", str(tmp_path)],
    )

    assert result.exit_code == 2
    assert "unknown benchmark suite" in result.output


def test_bench_cli_exits_nonzero_when_report_targets_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_report(
        output_root: Path,
        suite: str,
    ) -> dict[str, Any]:
        return {"suite": suite, "passed": False, "artifact_root": str(output_root)}

    monkeypatch.setattr(crashbench, "run_crashbench_suite", failing_report)

    result = CliRunner().invoke(
        app,
        [
            "bench",
            "--suite",
            "CrashBench-11",
            "--output-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["passed"] is False
