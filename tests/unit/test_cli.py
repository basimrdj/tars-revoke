from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from tars_revoke.cli import _frontend_distribution, app
from tars_revoke.demo.failures import load_failure_receipt
from tars_revoke.demo.scenario import CanonicalScenario
from tars_revoke.domain.enums import RunState
from tars_revoke.domain.models import Run
from tars_revoke.errors import ValidationError
from tars_revoke.persistence.store import Store


def test_frontend_distribution_prefers_packaged_build(tmp_path: Path) -> None:
    package_root = tmp_path / "src" / "tars_revoke"
    packaged = package_root / "web_dist"
    source = tmp_path / "web" / "dist"
    packaged.mkdir(parents=True)
    source.mkdir(parents=True)
    (packaged / "index.html").write_text("packaged", encoding="utf-8")
    (source / "index.html").write_text("source", encoding="utf-8")

    assert _frontend_distribution(package_root) == packaged


def test_frontend_distribution_falls_back_to_source_build(tmp_path: Path) -> None:
    package_root = tmp_path / "src" / "tars_revoke"
    package_root.mkdir(parents=True)

    assert _frontend_distribution(package_root) == tmp_path / "web" / "dist"


def test_demo_cli_finalizes_failure_even_when_no_revocation_case_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "fake-run" / "artifacts" / "run-cli-failure"
    artifact_root.mkdir(parents=True)
    store = Store(artifact_root / "state.sqlite")
    now = store.clock.utc_now()
    store.create_run(
        Run(
            id="run-cli-failure",
            name="CLI failure",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=now,
            updated_at=now,
        )
    )
    secret = "cli-never-print-this-secret"
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    class FailingHandle:
        fixture = SimpleNamespace(run_id="run-cli-failure", artifacts_root=artifact_root)
        proof_requirements: tuple[str, ...] = ()

        def __init__(self) -> None:
            self.store = store
            self.closed = False

        async def run(self) -> object:
            raise ValidationError(f"candidate rejected OPENAI_API_KEY={secret}")

        async def close(self) -> None:
            self.closed = True

    handle = FailingHandle()

    async def prepare(*args: object, **kwargs: object) -> FailingHandle:
        del args, kwargs
        return handle

    monkeypatch.setattr(CanonicalScenario, "prepare", prepare)
    result = CliRunner().invoke(
        app,
        ["demo", "--scripted", "--output-root", str(tmp_path / "ignored")],
    )

    assert result.exit_code == 1
    assert "candidate rejected" in result.output
    assert secret not in result.output
    assert handle.closed
    failure = load_failure_receipt(artifact_root, run_id="run-cli-failure")
    assert secret not in failure.message
    assert store.get_run("run-cli-failure").state == RunState.FAILED  # type: ignore[union-attr]
    receipt = store.get_receipt("run-cli-failure:failure-receipt")
    assert receipt is not None and receipt.case_id is None
