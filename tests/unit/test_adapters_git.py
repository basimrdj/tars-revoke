from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tars_revoke.adapters.git import (
    GitPushAuthorizationError,
    GitPushTokenIssuer,
    create_push_secret,
    validate_branch,
    validate_git_ref,
    validate_refspec,
    validate_relative_path,
    validate_remote_url,
    validate_revision,
)
from tars_revoke.errors import ValidationError


@pytest.mark.parametrize(
    "value",
    [
        "refs/heads/main..evil",
        "refs/heads/.hidden",
        "refs/heads/main.lock",
        "refs/heads/main~1",
        "refs/heads/main@{1}",
        "main",
    ],
)
def test_git_ref_validation_is_fail_closed(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_git_ref(value)


def test_git_revision_path_and_refspec_validation() -> None:
    assert validate_branch("revoke/action-1") == "revoke/action-1"
    assert validate_revision("HEAD") == "HEAD"
    assert validate_revision("a" * 40) == "a" * 40
    assert validate_relative_path("src/example.py") == "src/example.py"
    assert validate_refspec("HEAD:refs/heads/main") == "HEAD:refs/heads/main"

    for value in ("../escape", "/absolute", "-option"):
        with pytest.raises(ValidationError):
            validate_relative_path(value)
    for value in (
        "+HEAD:refs/heads/main",
        ":refs/heads/main",
        "HEAD:refs/tags/release",
        "HEAD:refs/heads/a:refs/heads/b",
    ):
        with pytest.raises(ValidationError):
            validate_refspec(value)


def test_remote_url_rejects_embedded_credentials_or_secrets() -> None:
    assert validate_remote_url("git@github.com:owner/repo.git")
    assert validate_remote_url("/tmp/remote.git")
    with pytest.raises(ValidationError, match="credential-bearing"):
        validate_remote_url("https://user:password@example.test/repo.git")
    with pytest.raises(ValidationError, match="secret-looking"):
        validate_remote_url("https://example.test/repo.git?token=abcdef0123456789")


def test_push_capability_is_bound_and_client_verification_does_not_consume(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    now = [1_000.0]
    issuer = GitPushTokenIssuer(b"x" * 32, clock=lambda: now[0])
    refspec = "HEAD:refs/heads/main"
    token = issuer.issue(
        action_id="action-1",
        epoch=7,
        repository=repository,
        remote_url="/tmp/remote.git",
        refspec=refspec,
        source_oid="a" * 40,
        ttl_seconds=10,
    )

    claims = issuer.verify(
        token,
        action_id="action-1",
        epoch=7,
        repository=repository,
        remote_url="/tmp/remote.git",
        refspec=refspec,
        source_oid="a" * 40,
        consume=True,
    )
    assert claims.action_id == "action-1"
    assert claims.epoch == 7
    assert claims.source_oid == "a" * 40

    repeated = issuer.verify(
        token,
        action_id="action-1",
        epoch=7,
        repository=repository,
        remote_url="/tmp/remote.git",
        refspec=refspec,
        source_oid="a" * 40,
    )
    assert repeated.nonce == claims.nonce
    with pytest.raises(GitPushAuthorizationError, match="epoch mismatch"):
        GitPushTokenIssuer(b"x" * 32, clock=lambda: now[0]).verify(
            token,
            action_id="action-1",
            epoch=8,
            repository=repository,
            remote_url="/tmp/remote.git",
            refspec=refspec,
            source_oid="a" * 40,
        )

    now[0] = 1_011.0
    with pytest.raises(GitPushAuthorizationError, match="expired"):
        GitPushTokenIssuer(b"x" * 32, clock=lambda: now[0]).verify(
            token,
            action_id="action-1",
            epoch=7,
            repository=repository,
            remote_url="/tmp/remote.git",
            refspec=refspec,
            source_oid="a" * 40,
        )


def test_push_capability_rejects_tampering_and_secret_file_permissions(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    issuer = GitPushTokenIssuer(b"x" * 32)
    token = issuer.issue(
        action_id="action-1",
        epoch=1,
        repository=repository,
        remote_url="/tmp/remote.git",
        refspec="HEAD:refs/heads/main",
        source_oid="b" * 40,
    )
    body, signature = token.split(".", 1)
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{body}.{replacement}{signature[1:]}"
    with pytest.raises(GitPushAuthorizationError):
        issuer.verify(
            tampered,
            action_id="action-1",
            epoch=1,
            repository=repository,
            remote_url="/tmp/remote.git",
            refspec="HEAD:refs/heads/main",
            source_oid="b" * 40,
        )

    secret_file = tmp_path / "private" / "push.key"
    secret = create_push_secret(secret_file)
    assert len(secret) == 32
    if os.name == "posix":
        assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        create_push_secret(secret_file)
