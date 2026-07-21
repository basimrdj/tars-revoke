from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from tars_revoke.demo.crashbench import run_crashbench_suite
from tars_revoke.demo.experiment_contract import CANONICAL_EXPERIMENT_SPECS, HYPOTHESES
from tars_revoke.demo.release import _copy_crash_evidence
from tars_revoke.demo.release_proofs import (
    CODEX_SIGNATURE_LIMITATION,
    FRESH_CLONE_STEPS,
    QUALIFICATION_FIXED_ENVIRONMENT,
    QUALIFICATION_FORBIDDEN_ENVIRONMENT_KEYS,
    QUALIFICATION_INHERITED_ENVIRONMENT_KEYS,
    QUALIFICATION_TRUST_LIMITATION,
    _verify_release_limitations,
    verify_crash_recovery,
    verify_live_codex_repair,
    verify_qualification_journal,
)
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.errors import IntegrityError


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value), encoding="utf-8")


def test_release_limitations_match_codex_signature_result() -> None:
    _verify_release_limitations(
        [QUALIFICATION_TRUST_LIMITATION],
        codex_strict_signature_valid=True,
    )
    _verify_release_limitations(
        [QUALIFICATION_TRUST_LIMITATION, CODEX_SIGNATURE_LIMITATION],
        codex_strict_signature_valid=False,
    )
    with pytest.raises(IntegrityError, match="differs from qualification evidence"):
        _verify_release_limitations(
            [QUALIFICATION_TRUST_LIMITATION],
            codex_strict_signature_valid=False,
        )
    with pytest.raises(IntegrityError, match="differs from qualification evidence"):
        _verify_release_limitations(
            [QUALIFICATION_TRUST_LIMITATION, CODEX_SIGNATURE_LIMITATION],
            codex_strict_signature_valid=True,
        )


def _manifest_for(requirement: str, root: Path, paths: list[Path]) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "requirements": {
            requirement: [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_digest(path.read_bytes()),
                    "size": path.stat().st_size,
                }
                for path in paths
            ]
        },
    }


def _live_session(
    root: Path,
    *,
    stage: str,
    thread_id: str,
    changed_paths: list[str],
    schema_digest: str,
    before_head: str,
    message_text: str = "{}",
) -> Path:
    session_root = root / "agents" / "live-codex" / "sessions" / f"{stage}-{thread_id[-4:]}"
    session_root.mkdir(parents=True)
    item_id = f"item-{stage}"
    events = [
        {"type": "thread.started", "thread_id": thread_id},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {"id": item_id, "type": "agent_message", "text": message_text},
        },
        {"type": "turn.completed"},
    ]
    (session_root / "events.jsonl").write_text(
        "".join(f"{json.dumps(item, sort_keys=True)}\n" for item in events),
        encoding="utf-8",
    )
    _write_json(session_root / "changed-paths.json", changed_paths)
    (session_root / "last-message.txt").write_text(message_text, encoding="utf-8")
    (session_root / "event-observations.jsonl").write_text(
        '{"event_type":"turn.completed","sequence":4}\n',
        encoding="utf-8",
    )
    (session_root / "stderr.log").write_bytes(b"")
    (session_root / "stdout.log").write_text("live Codex output\n", encoding="utf-8")
    diff = "".join(
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"
        for path in changed_paths
    )
    (session_root / "workspace.diff").write_text(diff, encoding="utf-8")
    files = {}
    for name in (
        "changed-paths.json",
        "event-observations.jsonl",
        "events.jsonl",
        "last-message.txt",
        "stderr.log",
        "stdout.log",
        "workspace.diff",
    ):
        content = (session_root / name).read_bytes()
        files[name] = {"path": name, "sha256": sha256_digest(content), "size": len(content)}
    sandbox = (
        "read-only"
        if stage == "agent-b-contradiction" or stage.startswith("agent-b-experiments")
        else "workspace-write"
    )
    executable = "/Applications/Codex.app/Contents/Resources/codex"
    executable_path = Path(executable)
    executable_digest = (
        sha256_digest(executable_path.read_bytes()) if executable_path.is_file() else "a" * 64
    )
    worktree = str(root / "worktrees" / stage)
    workspace_digest = sha256_digest(f"{stage}:{before_head}".encode())
    schema_path = root / "agents" / "live-codex" / f"output-schema-{schema_digest}.json"
    if stage.startswith("agent-b-experiments"):
        supervisor_argv = [
            executable,
            "exec",
            "resume",
            "--ignore-user-config",
            "--json",
            "-c",
            f'sandbox_mode="{sandbox}"',
        ]
    else:
        supervisor_argv = [
            executable,
            "exec",
            "--ignore-user-config",
            "--json",
            "--color",
            "never",
            "--sandbox",
            sandbox,
            "--cd",
            worktree,
        ]
    supervisor_argv.extend(
        [
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(root / "agents" / "live-codex" / f"codex-last-{stage}"),
        ]
    )
    if stage.startswith("agent-b-experiments"):
        supervisor_argv.append(thread_id)
    supervisor_argv.append("-")
    manifest = {
        "protocol": "tars.live-codex/v1",
        "stage": stage,
        "thread_id": thread_id,
        "process_id": f"process-{stage}",
        "executable": executable,
        "executable_version": "codex-cli 9.9.9",
        "executable_sha256": executable_digest,
        "supervisor_argv": supervisor_argv,
        "sandbox": sandbox,
        "worktree": worktree,
        "before_head": before_head,
        "after_head": before_head,
        "before_workspace_digest": workspace_digest,
        "after_workspace_digest": workspace_digest,
        "changed_paths": changed_paths,
        "item_ids": [item_id],
        "output_schema_digest": schema_digest,
        "files": files,
    }
    manifest_path = session_root / "manifest.json"
    _write_json(manifest_path, manifest)
    (session_root / "manifest.sha256").write_text(
        sha256_digest(manifest_path.read_bytes()),
        encoding="ascii",
    )
    return manifest_path


def _live_proof(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], list[Path]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "proof@example.test")
    _git(repository, "config", "user.name", "Proof")
    for relative in ("billing/models.py", "migrations/001_initial.sql"):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "base")
    base_commit = _git(repository, "rev-parse", "HEAD")
    schema = b'{"type":"object"}'
    schema_digest = sha256_digest(schema)
    schema_path = (
        tmp_path / "agents" / "live-codex" / f"output-schema-{schema_digest}.json"
    )
    schema_path.parent.mkdir(parents=True)
    schema_path.write_bytes(schema)
    initial = _live_session(
        tmp_path,
        stage="agent-a-initial-uuid",
        thread_id="thread-initial",
        changed_paths=["billing/models.py"],
        schema_digest=schema_digest,
        before_head=base_commit,
    )
    analysis = _live_session(
        tmp_path,
        stage="agent-b-contradiction",
        thread_id="thread-analysis",
        changed_paths=[],
        schema_digest=schema_digest,
        before_head=base_commit,
    )
    observability = _live_session(
        tmp_path,
        stage="agent-b-observability",
        thread_id="thread-observability",
        changed_paths=["docs/observability.md"],
        schema_digest=schema_digest,
        before_head=base_commit,
    )
    proposed_candidates = [
        {
            "id": f"candidate-{index}",
            "hypotheses": list(HYPOTHESES),
            "predictions": spec.prediction_map,
            "argv": list(spec.portable_argv),
            "touched_files": [],
            "risk": "low",
            "estimated_runtime_ms": spec.estimated_runtime_ms,
            "command_count": 1,
        }
        for index, spec in enumerate(CANONICAL_EXPERIMENT_SPECS, start=1)
    ]
    proposal = _live_session(
        tmp_path,
        stage="agent-b-experiments",
        thread_id="thread-analysis",
        changed_paths=[],
        schema_digest=schema_digest,
        before_head=base_commit,
        message_text=canonical_json({"candidates": proposed_candidates}),
    )
    proposal_observations = proposal.parent / "event-observations.jsonl"
    proposal_observations.write_text(
        '{"event_type":"turn.completed","sequence":4}\n',
        encoding="utf-8",
    )
    repair_paths = ["billing/models.py", "migrations/001_initial.sql"]
    repair = _live_session(
        tmp_path,
        stage="codex-bounded-repair",
        thread_id="thread-repair",
        changed_paths=repair_paths,
        schema_digest=schema_digest,
        before_head=base_commit,
    )
    for relative in repair_paths:
        (repository / relative).write_text("new\n", encoding="utf-8")
    _git(repository, "add", *repair_paths)
    _git(repository, "commit", "-qm", "repair")
    repaired_commit = _git(repository, "rev-parse", "HEAD")
    manifests = [initial, observability, analysis, proposal, repair]
    r14_paths = [
        path
        for manifest_path in manifests
        for path in (manifest_path, manifest_path.parent / "events.jsonl")
    ]
    r14_paths.append(repair.parent / "workspace.diff")
    r14_paths.append(proposal_observations)
    manifest = _manifest_for("R-14", tmp_path, r14_paths)
    durable_candidates = [
        {
            **candidate,
            "argv": ["/usr/bin/python3", *candidate["argv"][1:]],
            "risk": "LOW",
            "metadata": {
                "proposed_by": "live-codex",
                "proposed_argv": candidate["argv"],
                "executable_resolution": {
                    "kind": "scenario-python-runtime",
                    "resolved_path": "/usr/bin/python3",
                },
            },
        }
        for candidate in proposed_candidates
    ]
    candidates_path = tmp_path / "experiments" / "candidates.json"
    _write_json(
        candidates_path,
        {
            "candidates": durable_candidates,
            "decisions": [],
            "selected_candidate_id": "candidate-1",
            "selected_score": [0, 0, 50, 1],
        },
    )
    manifest["requirements"]["R-12"] = _manifest_for(
        "R-12",
        tmp_path,
        [candidates_path],
    )["requirements"]["R-12"]
    repair_manifest = json.loads(repair.read_text(encoding="utf-8"))
    receipt = {
        "proof_scope": ["R-14"],
        "experiment": {
            "selected_candidate_id": "candidate-1",
            "live_proposal_attempts": [
                {
                    "attempt_index": 0,
                    "stage": "agent-b-experiments",
                    "thread_id": "thread-analysis",
                    "session_id": "thread-analysis",
                    "manifest_path": proposal.relative_to(tmp_path).as_posix(),
                    "manifest_digest": sha256_digest(proposal.read_bytes()),
                    "events_path": (proposal.parent / "events.jsonl")
                    .relative_to(tmp_path)
                    .as_posix(),
                    "events_sha256": sha256_digest(
                        (proposal.parent / "events.jsonl").read_bytes()
                    ),
                    "event_observations_path": proposal_observations.relative_to(
                        tmp_path
                    ).as_posix(),
                    "event_observations_sha256": sha256_digest(
                        proposal_observations.read_bytes()
                    ),
                    "validation_error": None,
                }
            ],
            "live_proposal_validation_errors": [],
        },
        "repair": {
            "live_codex": True,
            "provider": "live-codex",
            "session_id": "thread-repair",
            "response_ids": repair_manifest["item_ids"],
            "changed_paths": repair_paths,
            "repaired_commit": repaired_commit,
            "live_session_lineage": {
                "agent_a_initial": "thread-initial",
                "agent_b_observability": "thread-observability",
                "agent_b_analysis": "thread-analysis",
                "agent_b_experiments": "thread-analysis",
                "repair": "thread-repair",
            },
        },
        "quarantine": {"repository": "repository"},
    }
    return receipt, manifest, manifests


def test_r14_verifies_raw_codex_lineage_and_rejects_arbitrary_relabel(
    tmp_path: Path,
) -> None:
    receipt, manifest, manifests = _live_proof(tmp_path)
    assert verify_live_codex_repair(tmp_path, receipt, manifest).valid

    missing_attempts = dict(receipt)
    missing_attempts["experiment"] = {}
    with pytest.raises(IntegrityError, match="missing or empty"):
        verify_live_codex_repair(tmp_path, missing_attempts, manifest)

    failed_final = json.loads(json.dumps(receipt))
    failed_final["experiment"]["live_proposal_attempts"][0]["validation_error"] = "bad"
    failed_final["experiment"]["live_proposal_validation_errors"] = ["bad"]
    with pytest.raises(IntegrityError, match="final successful proposal"):
        verify_live_codex_repair(tmp_path, failed_final, manifest)

    fake = tmp_path / "agents" / "live-codex" / "sessions" / "fake" / "manifest.json"
    _write_json(fake, {"protocol": "tars.live-codex/v1", "provider": "live-codex"})
    fake_manifest = _manifest_for("R-14", tmp_path, [fake])
    with pytest.raises(IntegrityError, match="missing stage"):
        verify_live_codex_repair(tmp_path, receipt, fake_manifest)

    repair_diff = manifests[-1].parent / "workspace.diff"
    repair_diff.write_text(
        "".join(
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+forged\n"
            for path in ("billing/models.py", "migrations/001_initial.sql")
        ),
        encoding="utf-8",
    )
    payload = json.loads(manifests[-1].read_text(encoding="utf-8"))
    content = repair_diff.read_bytes()
    payload["files"]["workspace.diff"] = {
        "path": "workspace.diff",
        "sha256": sha256_digest(content),
        "size": len(content),
    }
    _write_json(manifests[-1], payload)
    (manifests[-1].parent / "manifest.sha256").write_text(
        sha256_digest(manifests[-1].read_bytes()),
        encoding="ascii",
    )
    with pytest.raises(IntegrityError, match="reproduce the repaired commit"):
        verify_live_codex_repair(tmp_path, receipt, manifest)

    repair_diff.write_text("diff --git a/other.py b/other.py\n", encoding="utf-8")
    files = json.loads(manifests[-1].read_text(encoding="utf-8"))["files"]
    content = repair_diff.read_bytes()
    files["workspace.diff"] = {
        "path": "workspace.diff",
        "sha256": sha256_digest(content),
        "size": len(content),
    }
    payload = json.loads(manifests[-1].read_text(encoding="utf-8"))
    payload["files"] = files
    _write_json(manifests[-1], payload)
    (manifests[-1].parent / "manifest.sha256").write_text(
        sha256_digest(manifests[-1].read_bytes()),
        encoding="ascii",
    )
    with pytest.raises(IntegrityError, match="workspace diff"):
        verify_live_codex_repair(tmp_path, receipt, manifest)


@pytest.mark.asyncio
async def test_r18_requires_semantic_crashbench_snapshots_and_rejects_relabel(
    tmp_path: Path,
) -> None:
    report = dict(await run_crashbench_suite(tmp_path))
    report_path = Path(str(report["report_path"]))
    crash_root = Path(str(report["artifact_root"]))
    paths = [path for path in crash_root.rglob("*") if path.is_file()]
    manifest = _manifest_for("R-18", tmp_path, paths)
    assert verify_crash_recovery(tmp_path, manifest).valid
    release_root = tmp_path / "portable-release"
    release_root.mkdir()
    copied = list(_copy_crash_evidence(release_root, report_path=report_path))
    copied_manifest = _manifest_for("R-18", release_root, copied)
    assert verify_crash_recovery(release_root, copied_manifest).valid

    report["stages"][0]["recovery"]["first"]["expired_lease_count"] = 0
    report.pop("report_digest")
    report["report_digest"] = canonical_digest(report)
    _write_json(report_path, report)
    with pytest.raises(IntegrityError, match="differ from durable snapshots"):
        verify_crash_recovery(tmp_path, manifest)


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_r20_journal_binds_clean_source_mirror_and_exact_attempt_sequence(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "fresh-clone"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "proof@example.test")
    _git(repository, "config", "user.name", "Proof")
    tracked = repository / "README.md"
    tracked.write_text("qualified source\n", encoding="utf-8")
    package_init = repository / "src" / "tars_revoke" / "__init__.py"
    package_cli = repository / "src" / "tars_revoke" / "cli.py"
    package_cli.parent.mkdir(parents=True)
    package_init.write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    package_cli.write_text("def main() -> None:\n    pass\n", encoding="utf-8")
    _git(repository, "add", "README.md", "src/tars_revoke/__init__.py", "src/tars_revoke/cli.py")
    _git(repository, "commit", "-qm", "source")
    commit = _git(repository, "rev-parse", "HEAD")

    proof_root = repository / ".qualification"
    evidence_root = proof_root / "evidence"
    log_root = proof_root / "logs"
    runs_root = proof_root / "runs"
    evidence_root.mkdir(parents=True)
    log_root.mkdir()
    runs_root.mkdir()
    (evidence_root / "git-head.txt").write_text(f"{commit}\n", encoding="utf-8")
    (evidence_root / "git-status.txt").write_bytes(b"")
    (evidence_root / "clean-status.txt").write_bytes(b"")
    python_launcher = repository / ".venv" / "bin" / "python"
    python_launcher.parent.mkdir(parents=True)
    resolved_python = repository / "fixture-runtime" / "python"
    resolved_python.parent.mkdir(parents=True)
    resolved_python.write_bytes(b"qualified-python-runtime")
    os.symlink(resolved_python, python_launcher)
    installed_entrypoint = repository / ".venv" / "bin" / "tars-revoke"
    installed_entrypoint.write_text(f"#!{python_launcher}\n", encoding="utf-8")
    (evidence_root / "tars-revoke").write_bytes(installed_entrypoint.read_bytes())
    python_evidence = evidence_root / "python-runtime.bin"
    python_evidence.write_bytes(resolved_python.read_bytes())
    codex_path = tmp_path / "vendor" / "ChatGPT.app" / "Contents" / "Resources" / "codex"
    codex_bundle = codex_path.parents[2]
    codex_digest = "bdcb530615d44fcc7b35d12fe00f30c3025c25fc22a21193591dcdb064304385"
    (evidence_root / "codex-version.stdout.log").write_text(
        "codex-cli 0.144.5\n",
        encoding="utf-8",
    )
    (evidence_root / "codex-version.stderr.log").write_bytes(b"")
    (evidence_root / "codex-codesign-verify.stdout.log").write_bytes(b"")
    (evidence_root / "codex-codesign-verify.stderr.log").write_text(
        f"{codex_bundle}: valid on disk\n",
        encoding="utf-8",
    )
    (evidence_root / "codex-codesign-display.stdout.log").write_bytes(b"")
    (evidence_root / "codex-codesign-display.stderr.log").write_text(
        "Identifier=com.openai.codex\nTeamIdentifier=2DC432GLL2\n",
        encoding="utf-8",
    )
    source_manifest = {
        "protocol": "tars.source-tree/v1",
        "source_commit": commit,
        "files": [
            {
                "path": path.relative_to(repository).as_posix(),
                "sha256": sha256_digest(path.read_bytes()),
                "size": path.stat().st_size,
            }
            for path in (tracked, package_init, package_cli)
        ],
    }
    _write_json(evidence_root / "source-manifest.json", source_manifest)
    direct_url = json.dumps(
        {"url": repository.as_uri(), "dir_info": {"editable": True}},
        separators=(",", ":"),
    )
    site_packages = repository / ".venv" / "lib" / "site-packages"
    record_path = site_packages / "tars_revoke-0.1.0.dist-info" / "RECORD"
    record_path.parent.mkdir(parents=True)
    record_path.write_text("tars_revoke/__init__.py,,\n", encoding="utf-8")
    base_prefix = repository / "fixture-runtime"
    stdlib_path = base_prefix / "lib" / "python3.10"
    stdlib_path.mkdir(parents=True)
    inventory = {
        "protocol": "tars.python-runtime-inventory/v1",
        "roots": [],
        "entries": [
            {
                "root": str(repository / ".venv"),
                "path": str(python_launcher),
                "mode": 0o777,
                "kind": "symlink",
                "target": str(resolved_python),
            },
            {
                "root": str(resolved_python),
                "path": str(resolved_python),
                "mode": 0o644,
                "kind": "file",
                "sha256": sha256_digest(resolved_python.read_bytes()),
                "size": resolved_python.stat().st_size,
            },
            {
                "root": str(repository / ".venv"),
                "path": str(installed_entrypoint),
                "mode": 0o644,
                "kind": "file",
                "sha256": sha256_digest(installed_entrypoint.read_bytes()),
                "size": installed_entrypoint.stat().st_size,
            },
            {
                "root": str(repository / ".venv"),
                "path": str(record_path),
                "mode": 0o644,
                "kind": "file",
                "sha256": sha256_digest(record_path.read_bytes()),
                "size": record_path.stat().st_size,
            },
        ],
    }
    inventory["canonical_digest"] = canonical_digest(inventory)
    _write_json(evidence_root / "python-runtime-inventory.json", inventory)
    runtime_payload = {
        "protocol": "tars.python-runtime/v1",
        "sys_executable": str(python_launcher),
        "sys_prefix": str(repository / ".venv"),
        "sys_base_prefix": str(base_prefix),
        "python_version": "3.10.11 (qualification fixture)",
        "site_packages": [str(site_packages)],
        "stdlib_path": str(stdlib_path),
        "sys_path": [str(repository / "src")],
        "package_file": str(package_init),
        "package_file_sha256": sha256_digest(package_init.read_bytes()),
        "distribution_name": "tars-revoke",
        "distribution_version": "0.1.0",
        "distribution_direct_url": direct_url,
        "distribution_entry_points": [
            {
                "group": "console_scripts",
                "name": "tars-revoke",
                "value": "tars_revoke.cli:app",
            }
        ],
        "loaded_modules": [
            {
                "name": "tars_revoke",
                "path": str(package_init),
                "source_relative": "src/tars_revoke/__init__.py",
                "sha256": sha256_digest(package_init.read_bytes()),
                "size": package_init.stat().st_size,
            },
            {
                "name": "tars_revoke.cli",
                "path": str(package_cli),
                "source_relative": "src/tars_revoke/cli.py",
                "sha256": sha256_digest(package_cli.read_bytes()),
                "size": package_cli.stat().st_size,
            },
        ],
        "distributions": [
            {
                "name": "tars-revoke",
                "version": "0.1.0",
                "record_path": str(record_path),
                "record_sha256": sha256_digest(record_path.read_bytes()),
                "direct_url": direct_url,
            }
        ],
        "entrypoint_path": str(installed_entrypoint),
        "entrypoint_sha256": sha256_digest(installed_entrypoint.read_bytes()),
        "entrypoint_format": "direct-shebang",
        "python_invocation_path": str(python_launcher),
        "resolved_executable": str(resolved_python),
        "resolved_executable_sha256": sha256_digest(python_evidence.read_bytes()),
        "runtime_inventory_path": "evidence/python-runtime-inventory.json",
        "runtime_inventory_digest": inventory["canonical_digest"],
    }
    _write_json(evidence_root / "python-runtime.json", runtime_payload)
    source_mirror = proof_root / "source" / "repository.git"
    source_mirror.parent.mkdir()
    subprocess.run(
        ("git", "clone", "--mirror", "--no-hardlinks", str(repository), str(source_mirror)),
        check=True,
        capture_output=True,
    )

    setup_steps = []
    targets = (
        "setup",
        "doctor",
        "test-python-offline",
        "test-web",
        "build",
        "release-check",
    )
    for name, target in zip(FRESH_CLONE_STEPS, targets, strict=True):
        stdout = log_root / f"{name}.stdout.log"
        stderr = log_root / f"{name}.stderr.log"
        stdout.write_text(f"{name} passed\n", encoding="utf-8")
        stderr.write_bytes(b"")
        setup_steps.append(
            {
                "name": name,
                "argv": ["make", target],
                "cwd": str(repository),
                "exit_code": 0,
                "stdout_path": stdout.relative_to(proof_root).as_posix(),
                "stdout_sha256": sha256_digest(stdout.read_bytes()),
                "stderr_path": stderr.relative_to(proof_root).as_posix(),
                "stderr_sha256": sha256_digest(stderr.read_bytes()),
                "pre_git_status_path": "evidence/clean-status.txt",
                "pre_git_status_sha256": sha256_digest(
                    (evidence_root / "clean-status.txt").read_bytes()
                ),
                "post_git_status_path": "evidence/clean-status.txt",
                "post_git_status_sha256": sha256_digest(
                    (evidence_root / "clean-status.txt").read_bytes()
                ),
                "pre_git_head_path": "evidence/git-head.txt",
                "pre_git_head_sha256": sha256_digest(
                    (evidence_root / "git-head.txt").read_bytes()
                ),
                "post_git_head_path": "evidence/git-head.txt",
                "post_git_head_sha256": sha256_digest(
                    (evidence_root / "git-head.txt").read_bytes()
                ),
            }
        )

    now = datetime(2026, 7, 15, tzinfo=timezone.utc)
    attempts = []
    for index in range(1, 4):
        bundle = runs_root / f"run-{index}" / "artifacts" / f"live-{index}"
        bundle.mkdir(parents=True)
        receipt = bundle / "receipt.json"
        _write_json(receipt, {"run_id": f"live-{index}"})
        selected_argv = [str(resolved_python), "-B", "-c", "print('probe')"]
        _write_json(
            bundle / "experiments" / "candidates.json",
            {
                "selected_candidate_id": "candidate-1",
                "candidates": [
                    {"id": f"candidate-{candidate}", "argv": selected_argv}
                    for candidate in range(1, 4)
                ],
            },
        )
        _write_json(
            bundle / "experiments" / "run.json",
            {
                "argv": selected_argv,
                "experiment_run": {"metadata": {"argv": selected_argv}},
                "sandbox": {
                    "python_invocation_path": str(resolved_python),
                    "python_resolved_path": str(resolved_python),
                    "python_sha256": sha256_digest(python_evidence.read_bytes()),
                },
            },
        )
        stdout = log_root / f"attempt-{index}.stdout.log"
        stderr = log_root / f"attempt-{index}.stderr.log"
        stdout.write_text(f"attempt {index} passed\n", encoding="utf-8")
        stderr.write_bytes(b"")
        started = now + timedelta(minutes=index * 2)
        recorded_attempt_output = runs_root
        snapshot_records: dict[str, str] = {}
        for phase in ("pre", "post"):
            snapshot = {
                "protocol": "tars.python-runtime-snapshot/v1",
                "phase": phase,
                "baseline_digest": inventory["canonical_digest"],
                "observed_digest": inventory["canonical_digest"],
                "matches_baseline": True,
            }
            snapshot_path = evidence_root / f"attempt-{index}.{phase}.python.json"
            _write_json(snapshot_path, snapshot)
            snapshot_records.update(
                {
                    f"{phase}_python_runtime_path": snapshot_path.relative_to(
                        proof_root
                    ).as_posix(),
                    f"{phase}_python_runtime_sha256": sha256_digest(
                        snapshot_path.read_bytes()
                    ),
                    f"{phase}_python_runtime_digest": inventory["canonical_digest"],
                }
            )
        attempts.append(
            {
                "attempt_index": index,
                "started_at": started.isoformat(),
                "finished_at": (started + timedelta(minutes=1)).isoformat(),
                "argv": [
                    str(python_launcher),
                    "-I",
                    "-B",
                    "-m",
                    "tars_revoke.cli",
                    "demo",
                    "--scenario",
                    "external-schema-v2",
                    "--live-codex",
                    "--output-root",
                    str(recorded_attempt_output),
                ],
                "cwd": str(repository),
                "exit_code": 0,
                "stdout_path": stdout.relative_to(proof_root).as_posix(),
                "stdout_sha256": sha256_digest(stdout.read_bytes()),
                "stderr_path": stderr.relative_to(proof_root).as_posix(),
                "stderr_sha256": sha256_digest(stderr.read_bytes()),
                "pre_git_status_path": "evidence/clean-status.txt",
                "pre_git_status_sha256": sha256_digest(
                    (evidence_root / "clean-status.txt").read_bytes()
                ),
                "post_git_status_path": "evidence/clean-status.txt",
                "post_git_status_sha256": sha256_digest(
                    (evidence_root / "clean-status.txt").read_bytes()
                ),
                "pre_git_head_path": "evidence/git-head.txt",
                "pre_git_head_sha256": sha256_digest(
                    (evidence_root / "git-head.txt").read_bytes()
                ),
                "post_git_head_path": "evidence/git-head.txt",
                "post_git_head_sha256": sha256_digest(
                    (evidence_root / "git-head.txt").read_bytes()
                ),
                "pre_tars_revoke_path": "evidence/tars-revoke",
                "pre_tars_revoke_sha256": sha256_digest(
                    (evidence_root / "tars-revoke").read_bytes()
                ),
                "post_tars_revoke_path": "evidence/tars-revoke",
                "post_tars_revoke_sha256": sha256_digest(
                    (evidence_root / "tars-revoke").read_bytes()
                ),
                **snapshot_records,
                "artifact_root": bundle.relative_to(proof_root).as_posix(),
                "recorded_output_root": str(recorded_attempt_output),
                "recorded_artifact_root": str(bundle),
                "discovered_run_id": f"live-{index}",
                "receipt_sha256": sha256_digest(receipt.read_bytes()),
            }
        )

    source = {
        "recorded_workspace_root": str(repository),
        "recorded_qualification_output_root": str(runs_root),
        "qualification_output_root": "runs",
        "source_commit": commit,
        "source_tree_digest": canonical_digest(source_manifest),
        "source_manifest_path": "evidence/source-manifest.json",
        "source_manifest_sha256": sha256_digest(
            (evidence_root / "source-manifest.json").read_bytes()
        ),
        "git_head_path": "evidence/git-head.txt",
        "git_head_sha256": sha256_digest((evidence_root / "git-head.txt").read_bytes()),
        "git_status_path": "evidence/git-status.txt",
        "git_status_sha256": sha256_digest((evidence_root / "git-status.txt").read_bytes()),
        "clone_directory_was_empty": True,
        "tars_revoke_executable": str(
            repository
            / ".tars"
            / "qualification"
            / "evidence"
            / "executables"
            / "tars-revoke"
        ),
        "tars_revoke_executable_sha256": sha256_digest(
            (evidence_root / "tars-revoke").read_bytes()
        ),
        "tars_revoke_executable_evidence_path": "evidence/tars-revoke",
        "tars_revoke_installed_entrypoint": str(installed_entrypoint),
        "python_runtime_path": "evidence/python-runtime.json",
        "python_runtime_sha256": sha256_digest(
            (evidence_root / "python-runtime.json").read_bytes()
        ),
        "python_executable_evidence_path": "evidence/python-runtime.bin",
        "python_executable_sha256": sha256_digest(python_evidence.read_bytes()),
        "python_invocation_path": str(python_launcher),
        "python_resolved_path": str(resolved_python),
        "python_runtime_inventory_path": "evidence/python-runtime-inventory.json",
        "python_runtime_inventory_sha256": sha256_digest(
            (evidence_root / "python-runtime-inventory.json").read_bytes()
        ),
        "python_runtime_inventory_digest": inventory["canonical_digest"],
        "codex_executable": str(codex_path),
        "codex_executable_sha256": codex_digest,
        "codex_executable_version": "codex-cli 0.144.5",
        "codex_signing": {
            "protocol": "tars.codex-codesign/v1",
            "bundle_path": str(codex_bundle),
            "bundle_identifier": "com.openai.codex",
            "team_identifier": "2DC432GLL2",
            "verify_argv": [
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict",
                "--verbose=2",
                str(codex_bundle),
            ],
            "verify_exit_code": 0,
            "strict_verification_passed": True,
            "verify_stdout_path": "evidence/codex-codesign-verify.stdout.log",
            "verify_stdout_sha256": sha256_digest(
                (evidence_root / "codex-codesign-verify.stdout.log").read_bytes()
            ),
            "verify_stderr_path": "evidence/codex-codesign-verify.stderr.log",
            "verify_stderr_sha256": sha256_digest(
                (evidence_root / "codex-codesign-verify.stderr.log").read_bytes()
            ),
            "display_argv": [
                "/usr/bin/codesign",
                "-d",
                "--verbose=4",
                str(codex_bundle),
            ],
            "display_exit_code": 0,
            "display_stdout_path": "evidence/codex-codesign-display.stdout.log",
            "display_stdout_sha256": sha256_digest(
                (evidence_root / "codex-codesign-display.stdout.log").read_bytes()
            ),
            "display_stderr_path": "evidence/codex-codesign-display.stderr.log",
            "display_stderr_sha256": sha256_digest(
                (evidence_root / "codex-codesign-display.stderr.log").read_bytes()
            ),
        },
        "codex_version_stdout_path": "evidence/codex-version.stdout.log",
        "codex_version_stdout_sha256": sha256_digest(
            (evidence_root / "codex-version.stdout.log").read_bytes()
        ),
        "codex_version_stderr_path": "evidence/codex-version.stderr.log",
        "codex_version_stderr_sha256": sha256_digest(
            (evidence_root / "codex-version.stderr.log").read_bytes()
        ),
        "source_repository": "source/repository.git",
    }
    clone_stdout = log_root / "clone.stdout.log"
    clone_stderr = log_root / "clone.stderr.log"
    clone_stdout.write_text("cloned\n", encoding="utf-8")
    clone_stderr.write_bytes(b"")
    journal: dict[str, Any] = {
        "protocol": "tars.qualification-journal/v2",
        "source": source,
        "clone": {
            "started_at": now.isoformat(),
            "finished_at": (now + timedelta(seconds=1)).isoformat(),
            "argv": ["git", "clone", "--no-local", str(tmp_path / "source"), str(repository)],
            "cwd": str(repository.parent),
            "exit_code": 0,
            "stdout_path": clone_stdout.relative_to(proof_root).as_posix(),
            "stdout_sha256": sha256_digest(clone_stdout.read_bytes()),
            "stderr_path": clone_stderr.relative_to(proof_root).as_posix(),
            "stderr_sha256": sha256_digest(clone_stderr.read_bytes()),
        },
        "setup_steps": setup_steps,
        "attempts": attempts,
        "environment_policy": {
            "protocol": "tars.qualification-environment/v3",
            "inherited_allowlist": list(QUALIFICATION_INHERITED_ENVIRONMENT_KEYS),
            "present_inherited_keys": ["PATH"],
            "live_only_allowlist": [
                "CODEX_API_KEY",
                "CODEX_HOME",
                "HOME",
                "OPENAI_API_KEY",
                "OPENAI_ORGANIZATION",
                "OPENAI_ORG_ID",
                "OPENAI_PROJECT",
                "OPENAI_PROJECT_ID",
            ],
            "live_present_keys": ["CODEX_HOME", "OPENAI_API_KEY"],
            "fixed_values": QUALIFICATION_FIXED_ENVIRONMENT,
            "gate_injected_keys": ["HOME"],
            "runtime_injected_keys": ["TARS_CODEX_BIN"],
            "forbidden_keys": list(QUALIFICATION_FORBIDDEN_ENVIRONMENT_KEYS),
            "auth_key_names_present": ["OPENAI_API_KEY"],
            "non_live_auth_keys_present": [],
            "live_auth_sources": ["CODEX_HOME", "OPENAI_API_KEY"],
            "gate_home_sha256": "3" * 64,
            "path_sha256": "2" * 64,
        },
        "result": "passed",
    }
    journal["integrity"] = {"canonical_digest": canonical_digest(journal)}
    journal_path = proof_root / "journal.json"
    _write_json(journal_path, journal)
    assert verify_qualification_journal(journal_path).codex_strict_signature_valid is True

    non_strict = json.loads(json.dumps(journal))
    non_strict.pop("integrity")
    non_strict["source"]["codex_signing"]["verify_exit_code"] = 1
    non_strict["source"]["codex_signing"]["strict_verification_passed"] = False
    non_strict["integrity"] = {"canonical_digest": canonical_digest(non_strict)}
    _write_json(journal_path, non_strict)
    assert verify_qualification_journal(journal_path).codex_strict_signature_valid is False

    inconsistent_signature = json.loads(json.dumps(non_strict))
    inconsistent_signature.pop("integrity")
    inconsistent_signature["source"]["codex_signing"][
        "strict_verification_passed"
    ] = True
    inconsistent_signature["integrity"] = {
        "canonical_digest": canonical_digest(inconsistent_signature)
    }
    _write_json(journal_path, inconsistent_signature)
    with pytest.raises(IntegrityError, match="strict signature status is inconsistent"):
        verify_qualification_journal(journal_path)

    malformed_display_exit = json.loads(json.dumps(journal))
    malformed_display_exit.pop("integrity")
    malformed_display_exit["source"]["codex_signing"]["display_exit_code"] = False
    malformed_display_exit["integrity"] = {
        "canonical_digest": canonical_digest(malformed_display_exit)
    }
    _write_json(journal_path, malformed_display_exit)
    with pytest.raises(IntegrityError, match="identity exit status is malformed"):
        verify_qualification_journal(journal_path)

    _write_json(journal_path, journal)

    drift_head = evidence_root / "drift-head.txt"
    drift_head.write_text(f"{'f' * 40}\n", encoding="utf-8")
    drifted = json.loads(json.dumps(journal))
    drifted.pop("integrity")
    drifted["attempts"][0]["pre_git_head_path"] = "evidence/drift-head.txt"
    drifted["attempts"][0]["pre_git_head_sha256"] = sha256_digest(drift_head.read_bytes())
    drifted["integrity"] = {"canonical_digest": canonical_digest(drifted)}
    _write_json(journal_path, drifted)
    with pytest.raises(IntegrityError, match="changed the qualified source commit"):
        verify_qualification_journal(journal_path)

    changed_entrypoint = evidence_root / "changed-tars-revoke"
    changed_entrypoint.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    changed = json.loads(json.dumps(journal))
    changed.pop("integrity")
    changed["attempts"][0]["pre_tars_revoke_path"] = "evidence/changed-tars-revoke"
    changed["attempts"][0]["pre_tars_revoke_sha256"] = sha256_digest(
        changed_entrypoint.read_bytes()
    )
    changed["integrity"] = {"canonical_digest": canonical_digest(changed)}
    _write_json(journal_path, changed)
    with pytest.raises(IntegrityError, match="changed the qualified entry point"):
        verify_qualification_journal(journal_path)

    unsafe_environment = json.loads(json.dumps(journal))
    unsafe_environment.pop("integrity")
    unsafe_environment["environment_policy"]["forbidden_keys"] = []
    unsafe_environment["integrity"] = {
        "canonical_digest": canonical_digest(unsafe_environment)
    }
    _write_json(journal_path, unsafe_environment)
    with pytest.raises(IntegrityError, match="environment policy"):
        verify_qualification_journal(journal_path)

    runtime_path = evidence_root / "python-runtime.json"
    original_runtime = runtime_path.read_bytes()
    runtime_payload = json.loads(original_runtime)
    runtime_payload["package_file_sha256"] = "0" * 64
    _write_json(runtime_path, runtime_payload)
    forged_runtime = json.loads(json.dumps(journal))
    forged_runtime.pop("integrity")
    forged_runtime["source"]["python_runtime_sha256"] = sha256_digest(
        runtime_path.read_bytes()
    )
    forged_runtime["integrity"] = {"canonical_digest": canonical_digest(forged_runtime)}
    _write_json(journal_path, forged_runtime)
    with pytest.raises(IntegrityError, match="imported tars-revoke package"):
        verify_qualification_journal(journal_path)
    runtime_path.write_bytes(original_runtime)

    wrong_identity = json.loads(json.dumps(journal))
    wrong_identity.pop("integrity")
    wrong_identity["source"]["codex_signing"]["team_identifier"] = "NOT-OPENAI"
    wrong_identity["integrity"] = {"canonical_digest": canonical_digest(wrong_identity)}
    _write_json(journal_path, wrong_identity)
    with pytest.raises(IntegrityError, match="code-signing identity is not OpenAI"):
        verify_qualification_journal(journal_path)

    _write_json(journal_path, journal)

    (runs_root / "unreported-attempt").mkdir()
    with pytest.raises(IntegrityError, match="omitted or intervening"):
        verify_qualification_journal(journal_path)
