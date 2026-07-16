from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sys
from pathlib import Path

import pytest

from tars_revoke.adapters.codex import (
    CodexCLIAdapter,
    CodexExecutable,
    CodexProtocolError,
    CodexSandbox,
)
from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.demo.fixture import FixtureBuilder
from tars_revoke.demo.live_codex import (
    _EXPERIMENT_SCHEMA,
    ContradictionAnalysis,
    LiveCodexPath,
)
from tars_revoke.services.repair import RevocationPacket

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _bundled_codex() -> Path:
    configured = os.environ.get("TARS_CODEX_BIN", "").strip()
    candidates = (
        *([Path(configured).expanduser()] if configured else []),
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path.home() / "Applications/ChatGPT.app/Contents/Resources/codex",
        Path("/Applications/Codex.app/Contents/Resources/codex"),
        Path.home() / "Applications/Codex.app/Contents/Resources/codex",
    )
    return next((path for path in candidates if path.is_file()), candidates[0])


BUNDLED_CODEX = _bundled_codex()


pytestmark = pytest.mark.live


def _fake_correction_codex(path: Path) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        + r"""
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 999.2-correction-test")
    raise SystemExit(0)

def option(name):
    return args[args.index(name) + 1]

prompt = sys.stdin.read()
last_message = pathlib.Path(option("--output-last-message"))
artifact_root = last_message.parent
with (artifact_root / "fake-resume-argv.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")

if "independent evidence analyst" in prompt:
    final_value = {
        "contradiction": True,
        "invalidated_assumption": "customer_id remains UUID-shaped",
        "replacement_fact": "customer_id is opaque and cus_-prefixed",
        "evidence_version_from": 1,
        "evidence_version_to": 2,
        "confidence": 1.0,
        "reasoning_summary": "signed v2 replaces the UUID constraint",
        "affected_paths": [
            "billing/models.py",
            "migrations/002_customer_id_contract.sql",
        ],
    }
    item_id = "item-analysis"
else:
    counter_path = artifact_root / "fake-correction-count"
    count = int(counter_path.read_text(encoding="utf-8")) if counter_path.exists() else 0
    counter_path.write_text(str(count + 1), encoding="utf-8")
    always_invalid = (artifact_root / "always-invalid.flag").exists()

    def candidate(candidate_id, argv):
        return {
            "id": candidate_id,
            "hypotheses": ["contract_v1_uuid", "contract_v2_opaque"],
            "predictions": {
                "contract_v1_uuid": "accepted=false",
                "contract_v2_opaque": "accepted=true",
            },
            "argv": argv,
            "touched_files": [],
            "risk": "low",
            "estimated_runtime_ms": 20,
            "command_count": 1,
        }

    invalid_argv = [
        "python",
        "-B",
        "-c",
        "import json; from pathlib import import Path; from scripts.contract_probe import probe; "
        "print(json.dumps(probe(Path('examples/customer-v2.json')), sort_keys=True))",
    ]
    observer_argv = [
        "python",
        "-B",
        "-c",
        "import json; from pathlib import Path; from scripts.contract_probe import probe; "
        "print(json.dumps(probe(Path('examples/customer-v2.json')), sort_keys=True))",
    ]
    v1_argv = [
        "python", "-B", "scripts/contract_probe.py", "--example",
        "examples/customer-v1.json", "--expect", "accept",
    ]
    v2_argv = [
        "python", "-B", "scripts/contract_probe.py", "--example",
        "examples/customer-v2.json", "--expect", "reject",
    ]
    if count == 0 or always_invalid:
        candidates = [
            candidate("invalid-one", invalid_argv),
            candidate("invalid-two", invalid_argv),
            candidate("invalid-three", invalid_argv),
        ]
    else:
        candidates = [
            candidate("observe-v2", observer_argv),
            candidate("expect-v1", v1_argv),
            candidate("expect-v2", v2_argv),
        ]
    final_value = {"candidates": candidates}
    item_id = f"item-proposal-{count}"

final = json.dumps(final_value, separators=(",", ":"), sort_keys=True)
last_message.write_text(final, encoding="utf-8")
thread_id = "thread-analysis"
print(json.dumps({"type": "thread.started", "thread_id": thread_id}))
print(json.dumps({"type": "turn.started"}))
print(json.dumps({
    "type": "item.completed",
    "item": {"id": item_id, "type": "agent_message", "text": final},
}))
print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}}))
""",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


async def _fake_live_analysis(
    tmp_path: Path,
) -> tuple[LiveCodexPath, ContradictionAnalysis, Path]:
    fixture = await FixtureBuilder(tmp_path / "runs").build(f"correction-{secrets.token_hex(4)}")
    executable_path = _fake_correction_codex(fixture.root / "fake-codex")
    runner = AsyncProcessRunner([fixture.root])
    artifacts_root = fixture.artifacts_root / "agents" / "fake-live-codex"
    adapter = CodexCLIAdapter(
        process_runner=runner,
        executable=CodexExecutable(
            executable_path.resolve(),
            "codex-cli 999.2-correction-test",
        ),
        artifacts_root=artifacts_root,
        allowed_roots=[fixture.root],
    )
    live = LiveCodexPath(
        fixture=fixture,
        runner=runner,
        adapter=adapter,
        timeout_seconds=30,
    )
    analysis = await live.analyze_contradiction(
        v1_evidence={"version": 1, "digest": "v1"},
        v2_evidence={"version": 2, "digest": "v2"},
        worktree=fixture.agent_b_worktree,
    )
    return live, analysis, artifacts_root / "fake-resume-argv.jsonl"


def test_experiment_output_schema_closes_prediction_object() -> None:
    candidates = _EXPERIMENT_SCHEMA["properties"]["candidates"]
    predictions = candidates["items"]["properties"]["predictions"]

    assert predictions == {
        "type": "object",
        "properties": {
            "contract_v1_uuid": {"type": "string"},
            "contract_v2_opaque": {"type": "string"},
        },
        "required": ["contract_v1_uuid", "contract_v2_opaque"],
        "additionalProperties": False,
    }


def test_experiment_candidate_separates_domain_outcome_from_process_failure() -> None:
    base = {
        "id": "observe-v2",
        "hypotheses": ["contract_v1_uuid", "contract_v2_opaque"],
        "predictions": {
            "contract_v1_uuid": "accepted=false",
            "contract_v2_opaque": "accepted=true",
        },
        "touched_files": [],
        "risk": "low",
        "estimated_runtime_ms": 25,
        "command_count": 1,
    }
    valid_argv = (
        "python",
        "-B",
        "scripts/contract_probe.py",
        "--example",
        "examples/customer-v2.json",
        "--expect",
        "reject",
    )
    valid = {
        **base,
        "argv": list(valid_argv),
    }
    assert LiveCodexPath._experiment_candidate(valid).argv == valid_argv

    path_observer = {
        **base,
        "id": "observe-v2-path",
        "argv": [
            "python",
            "-B",
            "-c",
            (
                "import json; from pathlib import Path; "
                "from scripts.contract_probe import probe; "
                "print(json.dumps(probe(Path('examples/customer-v2.json')), "
                "sort_keys=True))"
            ),
        ],
    }
    assert LiveCodexPath._experiment_candidate(path_observer).id == "observe-v2-path"

    string_observer = {
        **base,
        "id": "observe-v2-string",
        "argv": [
            "python",
            "-B",
            "-c",
            (
                "import json; from pathlib import Path; "
                "from scripts.contract_probe import probe; "
                "print(json.dumps(probe('examples/customer-v2.json'), sort_keys=True))"
            ),
        ],
    }
    with pytest.raises(CodexProtocolError, match=r"pathlib\.Path fixture"):
        LiveCodexPath._experiment_candidate(string_observer)

    positional = {
        **base,
        "argv": [
            "python",
            "-B",
            "scripts/contract_probe.py",
            "examples/customer-v2.json",
            "reject",
        ],
    }
    with pytest.raises(CodexProtocolError, match="invalid contract_probe argv"):
        LiveCodexPath._experiment_candidate(positional)

    pytest_failure_channel = {
        **base,
        "argv": ["python", "-B", "-m", "pytest", "-q", "tests/test_contract.py"],
    }
    with pytest.raises(CodexProtocolError, match="invalid contract_probe argv"):
        LiveCodexPath._experiment_candidate(pytest_failure_channel)


@pytest.mark.asyncio
async def test_proposal_validation_resumes_same_real_adapter_thread(
    tmp_path: Path,
) -> None:
    live, analysis, argv_capture = await _fake_live_analysis(tmp_path)

    proposal = await live.propose_experiments(
        case_id="case-correction-success",
        analysis=analysis,
        worktree=live.fixture.agent_b_worktree,
    )

    assert proposal.correction_count == 1
    assert len(proposal.attempts) == 2
    assert len(proposal.validation_errors) == 1
    assert "probe result as JSON" in proposal.validation_errors[0]
    assert {candidate.id for candidate in proposal.candidates} == {
        "expect-v1",
        "expect-v2",
        "observe-v2",
    }
    assert all(attempt.thread_id == analysis.run.thread_id for attempt in proposal.attempts)
    assert proposal.run is proposal.attempts[-1]

    correction_prompt = proposal.attempts[1].artifacts.prompt_path.read_text(encoding="utf-8")
    assert "Exact validation error:" in correction_prompt
    assert proposal.validation_errors[0] in correction_prompt
    assert "from pathlib import Path" in correction_prompt
    assert "scripts/contract_probe.py" in correction_prompt
    assert "correction turn 1 of 2" in correction_prompt

    roots = {attempt.artifacts.root for attempt in proposal.attempts}
    assert len(roots) == 2
    for attempt in proposal.attempts:
        assert attempt.artifacts.manifest_path.is_file()
        assert attempt.pid > 0
        assert attempt.duration_seconds >= 0
        assert attempt.process_started_monotonic <= attempt.process_finished_monotonic
        assert attempt.started_at_utc <= attempt.finished_at_utc
        assert attempt.worktree == live.fixture.agent_b_worktree.resolve()
        assert attempt.event_observations
        assert attempt.artifacts.event_observations_path.is_file()
        manifest = json.loads(attempt.artifacts.manifest_path.read_text(encoding="utf-8"))
        assert manifest["pid"] == attempt.pid
        assert manifest["worktree"] == str(attempt.worktree)

    argv_rows = [json.loads(line) for line in argv_capture.read_text(encoding="utf-8").splitlines()]
    resume_rows = [row for row in argv_rows if row[:2] == ["exec", "resume"]]
    assert len(resume_rows) == 2
    assert all(analysis.run.thread_id in row for row in resume_rows)


@pytest.mark.asyncio
async def test_proposal_validation_fails_closed_after_two_resume_turns(
    tmp_path: Path,
) -> None:
    live, analysis, argv_capture = await _fake_live_analysis(tmp_path)
    (live.adapter.artifacts_root / "always-invalid.flag").write_text("1", encoding="utf-8")

    with pytest.raises(
        CodexProtocolError,
        match="remained invalid after 2 correction turns",
    ):
        await live.propose_experiments(
            case_id="case-correction-exhausted",
            analysis=analysis,
            worktree=live.fixture.agent_b_worktree,
        )

    attempt_roots = sorted(
        live.session_artifacts_root.glob("agent-b-experiments*"),
        key=lambda path: path.name,
    )
    assert len(attempt_roots) == 3
    assert all((root / "manifest.json").is_file() for root in attempt_roots)
    correction_prompts = sorted(
        (root / "prompt.txt").read_text(encoding="utf-8")
        for root in attempt_roots
        if "correction" in root.name
    )
    assert len(correction_prompts) == 2
    assert any("correction turn 1 of 2" in prompt for prompt in correction_prompts)
    assert any("correction turn 2 of 2" in prompt for prompt in correction_prompts)

    argv_rows = [json.loads(line) for line in argv_capture.read_text(encoding="utf-8").splitlines()]
    resume_rows = [row for row in argv_rows if row[:2] == ["exec", "resume"]]
    assert len(resume_rows) == 3
    assert all(analysis.run.thread_id in row for row in resume_rows)


@pytest.mark.skipif(
    os.environ.get("TARS_RUN_LIVE_CODEX") != "1",
    reason="set TARS_RUN_LIVE_CODEX=1 to exercise the authenticated bundled Codex CLI",
)
@pytest.mark.asyncio
async def test_real_codex_repairs_randomized_fixture_and_runs_its_tests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not BUNDLED_CODEX.is_file() or not os.access(BUNDLED_CODEX, os.X_OK):
        pytest.skip("official app-bundled Codex executable is not installed")

    monkeypatch.delenv("TARS_CODEX_MODEL", raising=False)
    suffix = secrets.token_hex(5)
    function_name = f"render_contract_{suffix}"
    expected_marker = f"contract_{suffix}"
    implementation_path = "billing/dynamic_contract.py"
    test_path = "tests/test_dynamic_contract.py"

    template = tmp_path / "template"
    shutil.copytree(PROJECT_ROOT / "demo" / "billing-repo", template)
    (template / implementation_path).write_text(
        "from __future__ import annotations\n\n\n"
        f"def {function_name}() -> str:\n"
        '    return "legacy-contract"\n',
        encoding="utf-8",
    )
    (template / test_path).write_text(
        "from __future__ import annotations\n\n"
        f"from billing.dynamic_contract import {function_name}\n\n\n"
        "def test_live_repair_marker() -> None:\n"
        f'    assert {function_name}() == "{expected_marker}"\n',
        encoding="utf-8",
    )

    fixture = await FixtureBuilder(
        tmp_path / "runs",
        template_root=template,
        python_executable=Path(sys.executable),
    ).build(f"live-{suffix}")
    test_argv = (
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        test_path,
    )
    verifier = AsyncProcessRunner([fixture.root])
    failing = await verifier.run(
        test_argv,
        cwd=fixture.agent_b_worktree,
        timeout_seconds=60,
        allowed_exit_codes=(0, 1),
    )
    assert failing.exit_code == 1, "the generated repair challenge must fail before Codex runs"

    packet = RevocationPacket(
        original_goal=(
            f"Make {function_name} return the active contract marker {expected_marker}."
        ),
        revocation_case_id=f"case-{suffix}",
        invalidated_premise={
            "id": f"premise-old-{suffix}",
            "value": "the legacy contract marker remains active",
        },
        replacement_evidence={
            "id": f"evidence-new-{suffix}",
            "expected_marker": expected_marker,
            "source": "signed-test-authority",
        },
        evidence_diff={
            "before": "legacy-contract",
            "after": expected_marker,
        },
        affected_effects=(
            {
                "id": f"effect-invalid-{suffix}",
                "path": implementation_path,
            },
        ),
        quarantine_ref=f"refs/tars/quarantine/{suffix}",
        selected_experiment={
            "id": f"experiment-{suffix}",
            "argv": list(test_argv),
        },
        experiment_result={
            "exit_code": failing.exit_code,
            "observed": "legacy implementation fails the randomized contract test",
        },
        allowed_repair_scope=(implementation_path,),
        targeted_test_argv=test_argv,
        full_test_argv=test_argv,
        active_premise_revisions={
            f"contract-marker-{suffix}": f"premise-new-{suffix}",
        },
    )

    live = await LiveCodexPath.create(
        fixture,
        timeout_seconds=float(os.environ.get("TARS_CODEX_LIVE_TIMEOUT", "600")),
        codex_bin=BUNDLED_CODEX,
    )
    result = await live.repair(packet, replacement_worktree=fixture.agent_b_worktree)

    assert result.executable == BUNDLED_CODEX.resolve()
    assert result.executable_version.startswith("codex-cli ")
    assert result.model is None, "unset TARS_CODEX_MODEL must preserve the account default"
    assert result.sandbox is CodexSandbox.WORKSPACE_WRITE
    assert result.thread_id
    assert result.item_ids
    assert result.changed_paths == (implementation_path,)
    assert expected_marker in result.diff
    assert function_name in result.diff
    repaired_source = (fixture.agent_b_worktree / implementation_path).read_text(encoding="utf-8")
    assert f'return "{expected_marker}"' in repaired_source

    test_commands = [
        evidence
        for evidence in result.command_evidence
        if test_path in evidence.command and evidence.exit_code == 0
    ]
    assert test_commands, "Codex JSONL must prove it executed the randomized repair test"

    passing = await verifier.run(
        test_argv,
        cwd=fixture.agent_b_worktree,
        timeout_seconds=60,
    )
    assert passing.exit_code == 0

    artifact = result.artifacts
    event_rows = [
        json.loads(line) for line in artifact.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(row.get("type") == "thread.started" for row in event_rows)
    assert any(
        isinstance(row.get("item"), dict) and row["item"].get("type") == "command_execution"
        for row in event_rows
    )
    assert hashlib.sha256(artifact.stdout_path.read_bytes()).hexdigest() == artifact.stdout_digest
    assert hashlib.sha256(artifact.stderr_path.read_bytes()).hexdigest() == artifact.stderr_digest
    assert artifact.stdout_digest_path.read_text(encoding="ascii").strip() == (
        artifact.stdout_digest
    )
    assert artifact.stderr_digest_path.read_text(encoding="ascii").strip() == (
        artifact.stderr_digest
    )
    manifest_bytes = artifact.manifest_path.read_bytes()
    assert hashlib.sha256(manifest_bytes).hexdigest() == artifact.manifest_digest
    assert artifact.manifest_digest_path.read_text(encoding="ascii").strip() == (
        artifact.manifest_digest
    )
