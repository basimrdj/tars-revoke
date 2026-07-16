from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from tars_revoke.demo.crashbench import run_crashbench_suite
from tars_revoke.demo.release import _copy_crash_evidence
from tars_revoke.demo.release_proofs import (
    CODEX_SIGNATURE_LIMITATION,
    FRESH_CLONE_STEPS,
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
) -> Path:
    session_root = root / "agents" / "live-codex" / "sessions" / f"{stage}-{thread_id[-4:]}"
    session_root.mkdir(parents=True)
    item_id = f"item-{stage}"
    events = [
        {"type": "thread.started", "thread_id": thread_id},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": item_id, "type": "agent_message"}},
        {"type": "turn.completed"},
    ]
    (session_root / "events.jsonl").write_text(
        "".join(f"{json.dumps(item, sort_keys=True)}\n" for item in events),
        encoding="utf-8",
    )
    _write_json(session_root / "changed-paths.json", changed_paths)
    (session_root / "last-message.txt").write_text("{}", encoding="utf-8")
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
    proposal = _live_session(
        tmp_path,
        stage="agent-b-experiments",
        thread_id="thread-analysis",
        changed_paths=[],
        schema_digest=schema_digest,
        before_head=base_commit,
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
    repair_manifest = json.loads(repair.read_text(encoding="utf-8"))
    receipt = {
        "proof_scope": ["R-14"],
        "experiment": {
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
    _git(repository, "add", "README.md")
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
    (evidence_root / "tars-revoke").write_text("#!/bin/sh\n", encoding="utf-8")
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
                "path": "README.md",
                "sha256": sha256_digest(tracked.read_bytes()),
                "size": tracked.stat().st_size,
            }
        ],
    }
    _write_json(evidence_root / "source-manifest.json", source_manifest)
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
        stdout = log_root / f"attempt-{index}.stdout.log"
        stderr = log_root / f"attempt-{index}.stderr.log"
        stdout.write_text(f"attempt {index} passed\n", encoding="utf-8")
        stderr.write_bytes(b"")
        started = now + timedelta(minutes=index * 2)
        recorded_attempt_output = runs_root
        attempts.append(
            {
                "attempt_index": index,
                "started_at": started.isoformat(),
                "finished_at": (started + timedelta(minutes=1)).isoformat(),
                "argv": [
                    str(
                        repository
                        / ".tars"
                        / "qualification"
                        / "evidence"
                        / "executables"
                        / "tars-revoke"
                    ),
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
            "protocol": "tars.qualification-environment/v1",
            "blocked_keys": ["TARS_RUN_LIVE_CODEX"],
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
    unsafe_environment["environment_policy"]["blocked_keys"] = []
    unsafe_environment["integrity"] = {
        "canonical_digest": canonical_digest(unsafe_environment)
    }
    _write_json(journal_path, unsafe_environment)
    with pytest.raises(IntegrityError, match="environment policy"):
        verify_qualification_journal(journal_path)

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
