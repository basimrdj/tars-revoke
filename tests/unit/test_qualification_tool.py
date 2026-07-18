from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tars_revoke.demo.release_proofs import _PINNED_CODEX_RELEASES as VERIFIER_CODEX_RELEASES


def _tool() -> ModuleType:
    path = Path(__file__).parents[2] / "tools" / "qualify_release.py"
    specification = importlib.util.spec_from_file_location("qualify_release", path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_qualification_and_verifier_share_the_pinned_codex_catalog() -> None:
    assert _tool()._PINNED_CODEX_RELEASES == VERIFIER_CODEX_RELEASES


def test_source_manifest_is_bound_to_git_blob_bytes(tmp_path: Path) -> None:
    tool = _tool()
    repository = tmp_path / "source"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.email", "qualification@example.invalid")
    _git(repository, "config", "user.name", "Qualification Test")
    content = b"tracked source\n"
    (repository / "tracked.txt").write_bytes(content)
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", "fixture")
    commit = _git(repository, "rev-parse", "HEAD")

    manifest = tool._source_manifest(repository, commit)

    assert manifest == {
        "protocol": "tars.source-tree/v1",
        "source_commit": commit,
        "files": [
            {
                "path": "tracked.txt",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        ],
    }


def test_persisted_journal_digest_covers_unsigned_payload(tmp_path: Path) -> None:
    tool = _tool()
    journal = {
        "protocol": "tars.qualification-journal/v2",
        "source": {"source_commit": "a" * 40},
        "setup_steps": [],
        "attempts": [],
        "result": "running",
    }
    path = tmp_path / "journal.json"

    tool._persist_journal(path, journal)

    persisted = json.loads(path.read_text(encoding="utf-8"))
    unsigned = dict(persisted)
    integrity = unsigned.pop("integrity")
    assert integrity == {"canonical_digest": tool._canonical_digest(unsigned)}


def test_execute_captures_both_streams() -> None:
    tool = _tool()
    exit_code, stdout, stderr = tool._execute(
        (
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ),
        cwd=Path.cwd(),
        timeout_seconds=30,
        environment=dict(os.environ),
    )

    assert exit_code == 0
    assert stdout == b"out\n"
    assert stderr == b"err\n"


def test_codex_signing_record_requires_openai_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    executable = tmp_path / "Codex.app" / "Contents" / "Resources" / "codex"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"official-codex-fixture")
    journal_root = tmp_path / "journal"

    def fake_execute(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        timeout_seconds: int,
        environment: dict[str, str],
    ) -> tuple[int, bytes, bytes]:
        del cwd, timeout_seconds, environment
        if "-d" in argv:
            return 0, b"", b"Identifier=com.openai.codex\nTeamIdentifier=2DC432GLL2\n"
        return 0, b"", b"Codex.app: valid on disk\n"

    monkeypatch.setattr(tool, "_execute", fake_execute)
    record = tool._codex_signing_record(
        journal_root,
        executable,
        cwd=tmp_path,
        environment={},
    )
    assert record["bundle_identifier"] == "com.openai.codex"
    assert record["team_identifier"] == "2DC432GLL2"
    assert record["verify_exit_code"] == 0
    assert record["display_exit_code"] == 0


def test_codex_signing_record_rejects_another_team(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    executable = tmp_path / "Codex.app" / "Contents" / "Resources" / "codex"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"lookalike-codex-fixture")

    def fake_execute(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        timeout_seconds: int,
        environment: dict[str, str],
    ) -> tuple[int, bytes, bytes]:
        del cwd, timeout_seconds, environment
        if "-d" in argv:
            return 0, b"", b"Identifier=com.openai.codex\nTeamIdentifier=ATTACKER123\n"
        return 0, b"", b"Codex.app: valid on disk\n"

    monkeypatch.setattr(tool, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="expected OpenAI team"):
        tool._codex_signing_record(
            tmp_path / "journal",
            executable,
            cwd=tmp_path,
            environment={},
        )


def test_codex_discovery_rejects_relative_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    monkeypatch.setenv("TARS_CODEX_BIN", "relative/ChatGPT.app/Contents/Resources/codex")

    with pytest.raises(RuntimeError, match="must be an absolute path"):
        tool._discover_official_codex()


def test_qualification_writer_records_exactly_three_runs(
    tmp_path: Path, monkeypatch: object
) -> None:
    tool = _tool()
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--initial-branch=main")
    _git(source, "config", "user.email", "qualification@example.invalid")
    _git(source, "config", "user.name", "Qualification Test")
    (source / "tracked.txt").write_text("release source\n", encoding="utf-8")
    (source / ".gitignore").write_text(".tars/\n.venv/\n", encoding="utf-8")
    _git(source, "add", "tracked.txt", ".gitignore")
    _git(source, "commit", "-m", "release fixture")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_make = fake_bin / "make"
    fake_make.write_text(
        """#!/usr/bin/env python3
import pathlib
import os
import sys

if sys.argv[1] == "test-python-offline" and "TARS_RUN_LIVE_CODEX" in os.environ:
    raise SystemExit(9)

if sys.argv[1] == "setup":
    target = pathlib.Path.cwd() / ".venv" / "bin" / "tars-revoke"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('''#!/usr/bin/env python3
import json
import pathlib
import sys

args = sys.argv[1:]
log = pathlib.Path.cwd() / ".tars" / "fake-tars-invocations.jsonl"
log.parent.mkdir(parents=True, exist_ok=True)
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\\\n")

def option(name):
    return args[args.index(name) + 1]

if args[0] == "demo":
    root = pathlib.Path(option("--output-root"))
    index = len([path for path in root.iterdir() if path.is_dir()]) + 1
    bundle = root / f"run-{index}" / "artifacts" / f"qualified-{index}"
    bundle.mkdir(parents=True)
    (bundle / "receipt.json").write_text(
        json.dumps({"run_id": f"qualified-{index}"}),
        encoding="utf-8",
    )
elif args[0] == "bench":
    suite = option("--suite")
    root = pathlib.Path(option("--output-root"))
    report_root = root / suite.lower()
    report_root.mkdir(parents=True)
    (report_root / "report.json").write_text(
        json.dumps({"protocol": "fake-benchmark/v1", "suite": suite}, sort_keys=True),
        encoding="utf-8",
    )
elif args[0] == "attest-release":
    qualification = pathlib.Path(option("--qualification-journal"))
    crash = pathlib.Path(option("--crash-report"))
    benchmark = pathlib.Path(option("--benchmark-report"))
    if not all(path.is_file() for path in (qualification, crash, benchmark)):
        raise SystemExit(3)
    root = pathlib.Path(option("--output-root"))
    root.mkdir()
    (root / "release-attestation.json").write_text(
        json.dumps({"protocol": "fake-release-attestation/v1"}, sort_keys=True),
        encoding="utf-8",
    )
elif args[0] == "verify":
    target = pathlib.Path(args[1])
    if args[2:] != ["--strict"] or not target.is_file():
        raise SystemExit(4)
else:
    raise SystemExit(2)
''')
    target.chmod(0o755)
print(f"fake make {sys.argv[1]}")
""",
        encoding="utf-8",
    )
    fake_make.chmod(0o755)
    fake_codex = fake_bin / "codex"
    fake_codex.write_text(
        "#!/bin/sh\nprintf 'codex-cli qualification-test\\n'\n",
        encoding="utf-8",
    )
    fake_codex.chmod(0o755)
    monkeypatch.setattr(tool, "_discover_official_codex", lambda: fake_codex)
    monkeypatch.setattr(
        tool,
        "_codex_signing_record",
        lambda *_args, **_kwargs: {
            "protocol": "tars.codex-codesign/v1",
            "bundle_path": str(fake_bin / "Codex.app"),
            "bundle_identifier": "com.openai.codex",
            "team_identifier": "2DC432GLL2",
            "verify_argv": [],
            "verify_exit_code": 0,
            "strict_verification_passed": True,
            "verify_stdout_path": "",
            "verify_stdout_sha256": "",
            "verify_stderr_path": "",
            "verify_stderr_sha256": "",
            "display_argv": [],
            "display_exit_code": 0,
            "display_stdout_path": "",
            "display_stdout_sha256": "",
            "display_stderr_path": "",
            "display_stderr_sha256": "",
        },
    )
    monkeypatch.setattr(
        tool,
        "_PINNED_CODEX_RELEASES",
        {"codex-cli qualification-test": hashlib.sha256(fake_codex.read_bytes()).hexdigest()},
    )
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("TARS_RUN_LIVE_CODEX", "1")

    workspace = tmp_path / "qualified-clone"
    journal_path = tool.qualify(source=source, workspace=workspace, timeout_seconds=30)

    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["result"] == "passed"
    assert [step["name"] for step in journal["setup_steps"]] == [
        "setup",
        "doctor",
        "python-tests",
        "web-tests",
        "build",
        "release-check",
    ]
    assert [attempt["attempt_index"] for attempt in journal["attempts"]] == [1, 2, 3]
    assert [attempt["discovered_run_id"] for attempt in journal["attempts"]] == [
        "qualified-1",
        "qualified-2",
        "qualified-3",
    ]
    assert sorted(path.name for path in (journal_path.parent / "runs").iterdir()) == [
        "run-1",
        "run-2",
        "run-3",
    ]
    assert journal["clone"]["argv"] == [
        "git",
        "clone",
        "--no-local",
        str(source.resolve()),
        str(workspace.resolve()),
    ]
    assert journal["source"]["tars_revoke_executable"] == str(
        journal_path.parent / "evidence" / "executables" / "tars-revoke"
    )
    assert journal["environment_policy"] == {
        "protocol": "tars.qualification-environment/v1",
        "blocked_keys": ["TARS_RUN_LIVE_CODEX"],
    }
    assert journal["source"]["codex_executable_version"] == (
        "codex-cli qualification-test"
    )
    assert journal["source"]["codex_signing"]["strict_verification_passed"] is True
    for step in journal["setup_steps"]:
        assert step["cwd"] == str(workspace)
        assert (journal_path.parent / step["pre_git_status_path"]).read_bytes() == b""
        assert (journal_path.parent / step["post_git_status_path"]).read_bytes() == b""
        assert (journal_path.parent / step["pre_git_head_path"]).read_text().strip() == _git(
            workspace, "rev-parse", "HEAD"
        )
        assert (journal_path.parent / step["post_git_head_path"]).read_text().strip() == _git(
            workspace, "rev-parse", "HEAD"
        )
    for attempt in journal["attempts"]:
        assert attempt["cwd"] == str(workspace)
        assert attempt["recorded_output_root"] == str(journal_path.parent / "runs")
        assert (journal_path.parent / attempt["artifact_root"] / "receipt.json").is_file()
        assert (journal_path.parent / attempt["pre_git_status_path"]).read_bytes() == b""
        assert (journal_path.parent / attempt["post_git_status_path"]).read_bytes() == b""
        assert (journal_path.parent / attempt["pre_git_head_path"]).read_text().strip() == _git(
            workspace, "rev-parse", "HEAD"
        )
        assert (journal_path.parent / attempt["post_git_head_path"]).read_text().strip() == _git(
            workspace, "rev-parse", "HEAD"
        )
        assert hashlib.sha256(
            (journal_path.parent / attempt["pre_tars_revoke_path"]).read_bytes()
        ).hexdigest() == journal["source"]["tars_revoke_executable_sha256"]
        assert hashlib.sha256(
            (journal_path.parent / attempt["post_tars_revoke_path"]).read_bytes()
        ).hexdigest() == journal["source"]["tars_revoke_executable_sha256"]

    workflow_path = workspace / ".tars" / "release-workflow" / "workflow.json"
    workflow = json.loads(workflow_path.read_text(encoding="utf-8"))
    assert workflow["result"] == "passed"
    assert [step["name"] for step in workflow["steps"]] == [
        "crashbench-11",
        "revokebench-20",
        "attest-release",
        "verify-release",
    ]
    assert all(step["passed"] is True for step in workflow["steps"])
    assert workflow["qualification_journal"] == str(journal_path)
    assert workflow["qualification_journal_sha256"] == hashlib.sha256(
        journal_path.read_bytes()
    ).hexdigest()

    expected_outputs = {
        "crash_report": workspace
        / ".tars"
        / "release-workflow"
        / "inputs"
        / "crash"
        / "crashbench-11"
        / "report.json",
        "benchmark_report": workspace
        / ".tars"
        / "release-workflow"
        / "inputs"
        / "revoke"
        / "revokebench-20"
        / "report.json",
        "release_attestation": workspace
        / ".tars"
        / "release-proof"
        / "release-attestation.json",
    }
    for name, path in expected_outputs.items():
        assert workflow["outputs"][name] == {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        assert workflow[name] == str(path)
        assert workflow[f"{name}_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()

    invocations = [
        json.loads(line)
        for line in (workspace / ".tars" / "fake-tars-invocations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [invocation[0] for invocation in invocations] == [
        "demo",
        "demo",
        "demo",
        "bench",
        "bench",
        "attest-release",
        "verify",
    ]
    assert invocations[3][2] == "CrashBench-11"
    assert invocations[4][2] == "RevokeBench-20"
    assert invocations[-1][-1] == "--strict"
    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""
