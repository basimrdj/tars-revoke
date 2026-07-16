from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tars_revoke.adapters.git import (
    GitAdapter,
    GitPushAuthorizationError,
    GitPushTokenIssuer,
    create_push_secret,
)
from tars_revoke.adapters.processes import AsyncProcessRunner


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository_fixture(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    remote = tmp_path / "remote.git"
    repository.mkdir()
    _git("init", "--initial-branch=main", cwd=repository)
    _git("config", "user.email", "tars@example.test", cwd=repository)
    _git("config", "user.name", "TARS Test", cwd=repository)
    (repository / "README.md").write_text("before\n", encoding="utf-8")
    _git("add", "README.md", cwd=repository)
    _git("commit", "-m", "initial", cwd=repository)
    _git("init", "--bare", str(remote))
    _git("remote", "add", "origin", str(remote), cwd=repository)
    return repository, remote


def _git_succeeds(*args: str, cwd: Path | None = None) -> bool:
    return (
        subprocess.run(
            ("git", *args),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )


@pytest.mark.asyncio
async def test_gateway_hook_denies_raw_push_and_allows_bound_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-must-not-reach-git-child-123456")
    monkeypatch.setenv("SENTINEL_CREDENTIAL", "sk-must-not-reach-git-child-654321")
    repository, remote = _repository_fixture(tmp_path)
    secret_file = tmp_path / "secrets" / "push.key"
    create_push_secret(secret_file)
    issuer = GitPushTokenIssuer.from_file(secret_file)
    runner = AsyncProcessRunner([tmp_path])
    adapter = GitAdapter([tmp_path], process_runner=runner, push_tokens=issuer)
    hook = await adapter.install_push_hook(repository, secret_file=secret_file)
    assert hook.is_file()

    raw = await runner.run(
        ("git", "-C", str(repository), "push", "origin", "HEAD:refs/heads/main"),
        cwd=repository,
    )
    assert raw.exit_code != 0
    assert "missing gateway capability" in raw.stderr
    assert not _git_succeeds(
        "show-ref",
        "--verify",
        "--quiet",
        "refs/heads/main",
        cwd=remote,
    )
    server_bypass = await runner.run(
        (
            "git",
            "-C",
            str(repository),
            "push",
            "--no-verify",
            "origin",
            "HEAD:refs/heads/main",
        ),
        cwd=repository,
    )
    assert server_bypass.exit_code != 0
    assert "TARS remote denied: missing gateway capability" in server_bypass.stderr

    refspec = "HEAD:refs/heads/main"
    authorized_source = _git("rev-parse", "HEAD", cwd=repository)
    token = issuer.issue(
        action_id="action-1",
        epoch=3,
        repository=repository,
        remote_url=str(remote),
        refspec=refspec,
        source_oid=authorized_source,
    )
    wrong_ref = await runner.run(
        (
            "git",
            "-C",
            str(repository),
            "push",
            "--no-verify",
            "origin",
            "HEAD:refs/heads/wrong-target",
        ),
        cwd=repository,
        env={
            "TARS_PUSH_TOKEN": token,
            "TARS_ACTION_ID": "action-1",
            "TARS_ACTION_EPOCH": "3",
            "TARS_REFSPEC": refspec,
            "TARS_SOURCE_WORKTREE": str(repository.resolve()),
            "TARS_REMOTE_URL": str(remote.resolve()),
        },
    )
    assert wrong_ref.exit_code != 0
    assert "received refs do not match capability" in wrong_ref.stderr
    pushed = await adapter.push(
        repository,
        remote="origin",
        refspec=refspec,
        capability_token=token,
        action_id="action-1",
        epoch=3,
    )
    assert pushed.before_remote_head is None
    assert pushed.after_remote_head == _git("rev-parse", "HEAD", cwd=repository)
    assert pushed.process.environment["TARS_PUSH_TOKEN"] == "<redacted>"
    assert "OPENAI_API_KEY" not in pushed.process.environment
    assert "SENTINEL_CREDENTIAL" not in pushed.process.environment

    # A restarted coordinator reconciles durable intent against remote truth;
    # it does not replay an ambiguous post-dispatch push.
    restarted_adapter = GitAdapter([tmp_path], process_runner=AsyncProcessRunner([tmp_path]))
    applied = await restarted_adapter.reconcile_push(
        repository,
        remote="origin",
        destination="refs/heads/main",
        expected_source_oid=authorized_source,
    )
    assert applied.state == "APPLIED"
    assert applied.remote_head == authorized_source
    missing = await restarted_adapter.reconcile_push(
        repository,
        remote="origin",
        destination="refs/heads/not-pushed",
        expected_source_oid=authorized_source,
    )
    assert missing.state == "NOT_APPLIED"
    conflict = await restarted_adapter.reconcile_push(
        repository,
        remote="origin",
        destination="refs/heads/main",
        expected_source_oid="0" * len(authorized_source),
    )
    assert conflict.state == "CONFLICT"
    assert conflict.remote_head == authorized_source

    with pytest.raises(GitPushAuthorizationError, match="already consumed"):
        await adapter.push(
            repository,
            remote="origin",
            refspec=refspec,
            capability_token=token,
            action_id="action-1",
            epoch=3,
        )
    _git("update-ref", "-d", "refs/heads/main", cwd=remote)
    server_replay = await runner.run(
        (
            "git",
            "-C",
            str(repository),
            "push",
            "--no-verify",
            "origin",
            refspec,
        ),
        cwd=repository,
        env={
            "TARS_PUSH_TOKEN": token,
            "TARS_ACTION_ID": "action-1",
            "TARS_ACTION_EPOCH": "3",
            "TARS_REFSPEC": refspec,
            "TARS_SOURCE_WORKTREE": str(repository.resolve()),
            "TARS_REMOTE_URL": str(remote.resolve()),
        },
    )
    assert server_replay.exit_code != 0
    assert "capability already consumed" in server_replay.stderr
    assert not _git_succeeds(
        "show-ref",
        "--verify",
        "--quiet",
        "refs/heads/main",
        cwd=remote,
    )


@pytest.mark.asyncio
async def test_push_capability_rejects_head_changed_after_authorization(
    tmp_path: Path,
) -> None:
    repository, remote = _repository_fixture(tmp_path)
    secret_file = tmp_path / "secrets" / "push.key"
    create_push_secret(secret_file)
    issuer = GitPushTokenIssuer.from_file(secret_file)
    runner = AsyncProcessRunner([tmp_path])
    adapter = GitAdapter([tmp_path], process_runner=runner, push_tokens=issuer)
    await adapter.install_push_hook(repository, secret_file=secret_file)

    refspec = "HEAD:refs/heads/main"
    authorized_source = _git("rev-parse", "HEAD", cwd=repository)
    stale_token = issuer.issue(
        action_id="action-head-swap",
        epoch=4,
        repository=repository,
        remote_url=str(remote),
        refspec=refspec,
        source_oid=authorized_source,
    )
    (repository / "README.md").write_text("changed after authorization\n", encoding="utf-8")
    _git("add", "README.md", cwd=repository)
    _git("commit", "-m", "unauthorized replacement", cwd=repository)
    replacement_source = _git("rev-parse", "HEAD", cwd=repository)
    assert replacement_source != authorized_source

    with pytest.raises(GitPushAuthorizationError, match="source_oid mismatch"):
        await adapter.push(
            repository,
            remote="origin",
            refspec=refspec,
            capability_token=stale_token,
            action_id="action-head-swap",
            epoch=4,
        )
    hook_attempt = await runner.run(
        ("git", "-C", str(repository), "push", "--no-verify", "origin", refspec),
        cwd=repository,
        env={
            "TARS_PUSH_TOKEN": stale_token,
            "TARS_ACTION_ID": "action-head-swap",
            "TARS_ACTION_EPOCH": "4",
            "TARS_REFSPEC": refspec,
            "TARS_SOURCE_WORKTREE": str(repository.resolve()),
            "TARS_REMOTE_URL": str(remote.resolve()),
        },
    )
    assert hook_attempt.exit_code != 0
    assert "source worktree object mismatch" in hook_attempt.stderr
    assert not _git_succeeds(
        "show-ref",
        "--verify",
        "--quiet",
        "refs/heads/main",
        cwd=remote,
    )


@pytest.mark.asyncio
async def test_server_rejects_capability_replayed_to_another_remote(
    tmp_path: Path,
) -> None:
    repository, authorized_remote = _repository_fixture(tmp_path)
    other_remote = tmp_path / "other-remote.git"
    _git("init", "--bare", str(other_remote))
    _git("remote", "add", "other", str(other_remote), cwd=repository)
    secret_file = tmp_path / "secrets" / "push.key"
    create_push_secret(secret_file)
    issuer = GitPushTokenIssuer.from_file(secret_file)
    runner = AsyncProcessRunner([tmp_path])
    adapter = GitAdapter([tmp_path], process_runner=runner, push_tokens=issuer)
    await adapter.install_push_hook(
        repository,
        secret_file=secret_file,
        remote_repository=authorized_remote,
        remote="origin",
    )
    await adapter.install_push_hook(
        repository,
        secret_file=secret_file,
        remote_repository=other_remote,
        remote="other",
    )
    refspec = "HEAD:refs/heads/main"
    source_oid = _git("rev-parse", "HEAD", cwd=repository)
    token = issuer.issue(
        action_id="action-remote-bound",
        epoch=5,
        repository=repository,
        remote_url=str(authorized_remote),
        refspec=refspec,
        source_oid=source_oid,
    )

    result = await runner.run(
        (
            "git",
            "-C",
            str(repository),
            "push",
            "--no-verify",
            "other",
            refspec,
        ),
        cwd=repository,
        env={
            "TARS_PUSH_TOKEN": token,
            "TARS_ACTION_ID": "action-remote-bound",
            "TARS_ACTION_EPOCH": "5",
            "TARS_REFSPEC": refspec,
            "TARS_SOURCE_WORKTREE": str(repository.resolve()),
            "TARS_REMOTE_URL": str(authorized_remote.resolve()),
        },
    )

    assert result.exit_code != 0
    assert "TARS remote denied: remote mismatch" in result.stderr
    assert not _git_succeeds(
        "show-ref",
        "--verify",
        "--quiet",
        "refs/heads/main",
        cwd=other_remote,
    )


@pytest.mark.asyncio
async def test_worktree_ref_diff_and_explicit_path_commit(tmp_path: Path) -> None:
    repository, _remote = _repository_fixture(tmp_path)
    adapter = GitAdapter([tmp_path])
    worktree_path = tmp_path / "worktree"
    worktree = await adapter.create_worktree(
        repository,
        worktree_path,
        branch="revoke/action-2",
    )
    assert worktree.worktree == worktree_path.resolve()

    (worktree_path / "README.md").write_text("after\n", encoding="utf-8")
    (worktree_path / "ignored.txt").write_text("not committed\n", encoding="utf-8")
    patch = await adapter.diff(worktree_path, paths=("README.md",))
    assert "after" in patch
    commit = await adapter.commit(
        worktree_path,
        message="replacement",
        paths=("README.md",),
    )
    assert commit.parent == worktree.head
    assert _git("status", "--porcelain", cwd=worktree_path) == "?? ignored.txt"

    quarantine = await adapter.create_ref(
        repository,
        "refs/tars/quarantine/action-2",
        commit.commit,
    )
    assert quarantine == commit.commit
    await adapter.remove_worktree(repository, worktree_path, force=True)
    assert not worktree_path.exists()


@pytest.mark.asyncio
async def test_common_hook_accepts_capability_bound_to_linked_worktree(tmp_path: Path) -> None:
    repository, remote = _repository_fixture(tmp_path)
    _git("push", "origin", "HEAD:refs/heads/main", cwd=repository)
    secret_file = tmp_path / "secrets" / "push.key"
    create_push_secret(secret_file)
    issuer = GitPushTokenIssuer.from_file(secret_file)
    runner = AsyncProcessRunner([tmp_path])
    adapter = GitAdapter([tmp_path], process_runner=runner, push_tokens=issuer)
    await adapter.install_push_hook(repository, secret_file=secret_file)
    worktree = tmp_path / "linked-agent"
    await adapter.create_worktree(
        repository,
        worktree,
        branch="agent/linked",
    )
    (worktree / "README.md").write_text("linked worktree\n", encoding="utf-8")
    commit = await adapter.commit(
        worktree,
        message="linked worktree change",
        paths=("README.md",),
    )
    refspec = "HEAD:refs/heads/linked-agent"
    token = issuer.issue(
        action_id="action-linked",
        epoch=7,
        repository=worktree,
        remote_url=str(remote),
        refspec=refspec,
        source_oid=commit.commit,
    )

    pushed = await adapter.push(
        worktree,
        remote="origin",
        refspec=refspec,
        capability_token=token,
        action_id="action-linked",
        epoch=7,
    )

    assert pushed.after_remote_head == commit.commit
    assert _git("rev-parse", "refs/heads/linked-agent", cwd=remote) == commit.commit
