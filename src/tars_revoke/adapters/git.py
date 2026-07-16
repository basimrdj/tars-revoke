from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from tars_revoke.errors import AdapterError, AuthorizationError, IntegrityError, ValidationError

from ._safety import (
    GIT_SUBPROCESS_ENV_KEYS,
    canonical_json,
    normalize_roots,
    redact_text,
    resolve_under_roots,
)
from .processes import AsyncProcessRunner, ProcessResult


class GitAdapterError(AdapterError):
    pass


class GitPushAuthorizationError(AuthorizationError):
    pass


class GitIntegrityError(IntegrityError):
    pass


_INVALID_REF = re.compile(r"[\x00-\x20\x7f ~^:?*\\[]")
_REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_HOOK_MARKER = "# TARS_REVOKE_PRE_PUSH_V3"
_SERVER_HOOK_MARKER = "# TARS_REVOKE_PRE_RECEIVE_V3"
_NONCE_DATABASE_SUFFIX = ".nonces.sqlite3"
_NONCE = re.compile(r"[0-9a-f]{32}\Z")


def validate_git_ref(ref: str, *, full: bool = True) -> str:
    if not isinstance(ref, str) or not ref or len(ref) > 1024:
        raise ValidationError("invalid Git ref")
    if full and not ref.startswith("refs/"):
        raise ValidationError("a fully qualified refs/... name is required")
    if (
        _INVALID_REF.search(ref)
        or ".." in ref
        or "@{" in ref
        or ref.endswith(("/", ".", ".lock"))
        or ref.startswith("/")
        or "//" in ref
        or any(part.startswith(".") or part.endswith(".") for part in ref.split("/"))
    ):
        raise ValidationError(f"unsafe Git ref: {ref!r}")
    return ref


def validate_branch(branch: str) -> str:
    return validate_git_ref(f"refs/heads/{branch}")[len("refs/heads/") :]


def validate_relative_path(path: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("-"):
        raise ValidationError("unsafe Git path")
    pure = PurePosixPath(path.replace(os.sep, "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValidationError(f"Git path escapes repository: {path!r}")
    return str(pure)


def validate_refspec(refspec: str) -> str:
    if not isinstance(refspec, str) or refspec.count(":") != 1:
        raise ValidationError("push refspec must be one source:destination pair")
    if refspec.startswith(("+", ":", "-")):
        raise ValidationError("force, delete, and option refspecs are forbidden")
    source, destination = refspec.split(":", 1)
    if source != "HEAD":
        validate_git_ref(source)
    validate_git_ref(destination)
    if not destination.startswith("refs/heads/"):
        raise ValidationError("push destination must be under refs/heads/")
    return refspec


def validate_revision(revision: str) -> str:
    if revision == "HEAD" or _OBJECT_ID.fullmatch(revision):
        return revision
    return validate_git_ref(revision)


def validate_remote_url(remote_url: str) -> str:
    if not isinstance(remote_url, str) or not remote_url or "\x00" in remote_url:
        raise ValidationError("invalid Git remote URL")
    if any(character in remote_url for character in "\r\n"):
        raise ValidationError("invalid Git remote URL")
    parsed = urlsplit(remote_url)
    if parsed.scheme in {"http", "https", "ssh"} and (
        parsed.username is not None or parsed.password is not None
    ):
        raise ValidationError("credential-bearing Git remote URLs are forbidden")
    if redact_text(remote_url) != remote_url:
        raise ValidationError("secret-looking Git remote URLs are forbidden")
    return remote_url


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class PushCapabilityClaims:
    protocol: str
    action_id: str
    epoch: int
    repository: str
    remote_url: str
    refspec: str
    destination: str
    source_oid: str
    issued_at: int
    expires_at: int
    nonce: str


class GitPushTokenIssuer:
    """Issue and validate short-lived capabilities without consuming them.

    Capability consumption belongs exclusively to the protected bare remote's
    receive hook.  A file-backed issuer also reads that durable ledger so a
    restarted client fails before attempting an already-consumed push.
    """

    protocol = "tars.git-push/v2"

    def __init__(
        self,
        secret: bytes,
        *,
        clock: Callable[[], float] = time.time,
        nonce_database: Path | None = None,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValidationError("Git push token secret must contain at least 32 bytes")
        self._secret = secret
        self._clock = clock
        self._nonce_database = (
            Path(nonce_database).expanduser().resolve(strict=False)
            if nonce_database is not None
            else None
        )

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> GitPushTokenIssuer:
        secret_path = Path(path).expanduser().resolve(strict=True)
        mode = stat.S_IMODE(secret_path.stat().st_mode)
        if mode & 0o077:
            raise ValidationError("Git push token secret must not be group/world accessible")
        return cls(
            secret_path.read_bytes(),
            clock=clock,
            nonce_database=_nonce_database_path(secret_path),
        )

    def issue(
        self,
        *,
        action_id: str,
        epoch: int,
        repository: Path,
        remote_url: str,
        refspec: str,
        source_oid: str,
        ttl_seconds: int = 30,
    ) -> str:
        if not _ACTION_ID.fullmatch(action_id):
            raise ValidationError("invalid action_id")
        if epoch < 0:
            raise ValidationError("epoch must be non-negative")
        if not 1 <= ttl_seconds <= 300:
            raise ValidationError("push token TTL must be between 1 and 300 seconds")
        normalized_refspec = validate_refspec(refspec)
        normalized_remote = _canonical_remote_url(remote_url, repository=repository)
        if not _OBJECT_ID.fullmatch(source_oid):
            raise ValidationError("invalid Git source object ID")
        now = int(self._clock())
        claims = PushCapabilityClaims(
            protocol=self.protocol,
            action_id=action_id,
            epoch=epoch,
            repository=str(Path(repository).expanduser().resolve(strict=True)),
            remote_url=normalized_remote,
            refspec=normalized_refspec,
            destination=normalized_refspec.split(":", 1)[1],
            source_oid=source_oid.lower(),
            issued_at=now,
            expires_at=now + ttl_seconds,
            nonce=secrets.token_hex(16),
        )
        body = canonical_json(asdict(claims))
        signature = hmac.new(self._secret, body, hashlib.sha256).digest()
        return f"{_b64encode(body)}.{_b64encode(signature)}"

    def verify(
        self,
        token: str,
        *,
        action_id: str,
        epoch: int,
        repository: Path,
        remote_url: str,
        refspec: str,
        source_oid: str,
        consume: bool = False,
    ) -> PushCapabilityClaims:
        try:
            body_encoded, signature_encoded = token.split(".", 1)
            body = _b64decode(body_encoded)
            signature = _b64decode(signature_encoded)
            payload = json.loads(body)
            if not isinstance(payload, Mapping):
                raise TypeError("capability payload must be an object")
            claims = PushCapabilityClaims(**payload)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error) as exc:
            raise GitPushAuthorizationError("malformed Git push capability") from exc
        if (
            not isinstance(claims.protocol, str)
            or not isinstance(claims.action_id, str)
            or type(claims.epoch) is not int
            or not isinstance(claims.repository, str)
            or not isinstance(claims.remote_url, str)
            or not isinstance(claims.refspec, str)
            or not isinstance(claims.destination, str)
            or not isinstance(claims.source_oid, str)
            or type(claims.issued_at) is not int
            or type(claims.expires_at) is not int
            or not isinstance(claims.nonce, str)
        ):
            raise GitPushAuthorizationError("malformed Git push capability claims")
        expected_signature = hmac.new(self._secret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise GitPushAuthorizationError("invalid Git push capability signature")
        if not _ACTION_ID.fullmatch(action_id) or epoch < 0:
            raise GitPushAuthorizationError("invalid expected Git push authorization context")
        if not _OBJECT_ID.fullmatch(source_oid):
            raise GitPushAuthorizationError("invalid expected Git source object ID")
        normalized_remote = _canonical_remote_url(remote_url, repository=repository)
        now = int(self._clock())
        if claims.protocol != self.protocol:
            raise GitPushAuthorizationError("unsupported Git push capability protocol")
        if (
            claims.issued_at > now + 5
            or claims.expires_at < now
            or claims.expires_at <= claims.issued_at
            or claims.expires_at - claims.issued_at > 300
        ):
            raise GitPushAuthorizationError("expired or not-yet-valid Git push capability")
        if not _NONCE.fullmatch(claims.nonce):
            raise GitPushAuthorizationError("invalid Git push capability nonce")
        normalized_refspec = validate_refspec(refspec)
        expected = {
            "action_id": action_id,
            "epoch": epoch,
            "repository": str(Path(repository).expanduser().resolve(strict=True)),
            "remote_url": normalized_remote,
            "refspec": normalized_refspec,
            "destination": normalized_refspec.split(":", 1)[1],
            "source_oid": source_oid.lower(),
        }
        for key, value in expected.items():
            if getattr(claims, key) != value:
                raise GitPushAuthorizationError(f"Git push capability {key} mismatch")
        if self._nonce_was_consumed(claims.nonce):
            raise GitPushAuthorizationError("Git push capability was already consumed")
        # `consume` remains source-compatible with the v2 API, but deliberately
        # does not mutate state.  Only the server-side receive hook may burn a
        # capability, after it has validated the exact proposed ref update.
        del consume
        return claims

    def _nonce_was_consumed(self, nonce: str) -> bool:
        database = self._nonce_database
        if database is None or not database.exists():
            return False
        if stat.S_IMODE(database.stat().st_mode) & 0o077:
            raise GitPushAuthorizationError("Git push capability nonce ledger is insecure")
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro",
                uri=True,
                timeout=5,
            )
            try:
                row = connection.execute(
                    "SELECT 1 FROM consumed_push_nonces WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise GitPushAuthorizationError(
                "Git push capability nonce ledger is unavailable"
            ) from exc
        return row is not None


def _nonce_database_path(secret_file: Path) -> Path:
    secret = Path(secret_file).expanduser().resolve(strict=False)
    return secret.with_name(secret.name + _NONCE_DATABASE_SUFFIX)


def _canonical_remote_url(remote_url: str, *, repository: Path) -> str:
    """Return the exact local remote identity used by both sides of a push."""

    validated = validate_remote_url(remote_url)
    parsed = urlsplit(validated)
    if parsed.scheme == "file":
        if parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
            raise ValidationError("unsupported file Git remote URL")
        candidate = Path(unquote(parsed.path))
    elif not parsed.scheme and not re.match(r"^[^/]+@?[^/:]*:", validated):
        candidate = Path(validated).expanduser()
        if not candidate.is_absolute():
            candidate = Path(repository).expanduser().resolve(strict=True) / candidate
    else:
        return validated
    return str(candidate.resolve(strict=False))


def _initialize_nonce_database(path: Path) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise ValidationError("Git push capability directory must be private")
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValidationError("Git push capability nonce ledger must be private")
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_push_nonces (
                nonce TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL UNIQUE,
                action_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                source_worktree TEXT NOT NULL,
                remote_url TEXT NOT NULL,
                refspec TEXT NOT NULL,
                source_oid TEXT NOT NULL,
                consumed_at INTEGER NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


def create_push_secret(path: Path) -> bytes:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if stat.S_IMODE(target.parent.stat().st_mode) & 0o077:
        raise ValidationError("Git push capability directory must be private")
    secret = secrets.token_bytes(32)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, secret)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return secret


@dataclass(frozen=True)
class WorktreeResult:
    repository: Path
    worktree: Path
    branch: str
    head: str


@dataclass(frozen=True)
class CommitResult:
    repository: Path
    commit: str
    parent: str | None
    paths: tuple[str, ...]


@dataclass(frozen=True)
class PushResult:
    repository: Path
    remote: str
    remote_url: str
    refspec: str
    before_remote_head: str | None
    after_remote_head: str
    process: ProcessResult


@dataclass(frozen=True)
class PushReconciliation:
    destination: str
    expected_source_oid: str
    remote_head: str | None
    state: str


class GitAdapter:
    def __init__(
        self,
        allowed_roots: Sequence[Path],
        *,
        process_runner: AsyncProcessRunner | None = None,
        git_binary: str = "git",
        push_tokens: GitPushTokenIssuer | None = None,
        quarantine_prefix: str = "refs/tars/quarantine/",
    ) -> None:
        self.allowed_roots = normalize_roots(allowed_roots)
        self.runner = process_runner or AsyncProcessRunner(self.allowed_roots)
        self.git_binary = git_binary
        self.push_tokens = push_tokens
        if not quarantine_prefix.startswith("refs/"):
            raise ValidationError("quarantine prefix must be fully qualified")
        self.quarantine_prefix = quarantine_prefix

    def _repo(self, repository: Path) -> Path:
        return resolve_under_roots(
            repository,
            self.allowed_roots,
            require_directory=True,
        )

    async def _git(
        self,
        repository: Path,
        args: Sequence[str],
        *,
        env: dict[str, str] | None = None,
        allowed_exit_codes: Sequence[int] = (0,),
    ) -> ProcessResult:
        repo = self._repo(repository)
        result = await self.runner.run(
            (self.git_binary, "-C", str(repo), *args),
            cwd=repo,
            env=env,
            inherited_env_keys=GIT_SUBPROCESS_ENV_KEYS,
            timeout_seconds=60,
            allowed_exit_codes=allowed_exit_codes,
        )
        if result.exit_code not in allowed_exit_codes:
            raise GitAdapterError(
                f"git {redact_text(' '.join(args[:2]))} failed with exit {result.exit_code}: "
                f"{redact_text(result.stderr.strip() or result.stdout.strip())}"
            )
        if result.output_truncated:
            raise GitIntegrityError("Git output exceeded the capture limit")
        return result

    async def assert_repository(self, repository: Path) -> Path:
        repo = self._repo(repository)
        result = await self._git(repo, ("rev-parse", "--is-inside-work-tree"))
        if result.stdout.strip() != "true":
            raise GitAdapterError(f"not a Git worktree: {repo}")
        top = await self._git(repo, ("rev-parse", "--show-toplevel"))
        resolved_top = Path(top.stdout.strip()).resolve(strict=True)
        if resolved_top != repo:
            raise GitAdapterError(f"repository root mismatch: expected {repo}, got {resolved_top}")
        return repo

    async def create_worktree(
        self,
        repository: Path,
        worktree: Path,
        *,
        branch: str,
        start_point: str = "HEAD",
    ) -> WorktreeResult:
        repo = await self.assert_repository(repository)
        branch = validate_branch(branch)
        target = resolve_under_roots(worktree, self.allowed_roots, must_exist=False)
        if target.exists():
            raise GitAdapterError(f"worktree target already exists: {target}")
        validate_revision(start_point)
        await self._git(repo, ("worktree", "add", "-b", branch, str(target), start_point))
        created = resolve_under_roots(target, self.allowed_roots, require_directory=True)
        head = (await self._git(created, ("rev-parse", "HEAD"))).stdout.strip()
        return WorktreeResult(repo, created, branch, head)

    async def remove_worktree(
        self,
        repository: Path,
        worktree: Path,
        *,
        force: bool = False,
    ) -> None:
        repo = await self.assert_repository(repository)
        target = resolve_under_roots(worktree, self.allowed_roots, require_directory=True)
        args = ["worktree", "remove"]
        if force:
            args.append("--force")
        args.append(str(target))
        await self._git(repo, tuple(args))

    async def create_ref(self, repository: Path, ref: str, target: str = "HEAD") -> str:
        repo = await self.assert_repository(repository)
        validate_git_ref(ref)
        if not ref.startswith(self.quarantine_prefix) and not ref.startswith(
            "refs/tars/replacements/"
        ):
            raise ValidationError("TARS-managed refs must use quarantine or replacements namespace")
        validate_revision(target)
        # A full zero old object ID makes update-ref a create-only CAS.  Detect
        # the repository storage format so this is safe for SHA-1 and SHA-256.
        object_format = (
            await self._git(repo, ("rev-parse", "--show-object-format=storage"))
        ).stdout.strip()
        zero_oid = {"sha1": "0" * 40, "sha256": "0" * 64}.get(object_format)
        if zero_oid is None:
            raise GitIntegrityError(f"unsupported Git object format: {object_format!r}")
        await self._git(repo, ("update-ref", ref, target, zero_oid))
        return (await self._git(repo, ("rev-parse", ref))).stdout.strip()

    async def diff(
        self,
        repository: Path,
        *,
        base: str | None = None,
        head: str | None = None,
        paths: Sequence[str] = (),
    ) -> str:
        repo = await self.assert_repository(repository)
        args: list[str] = ["diff", "--binary", "--no-ext-diff", "--no-color"]
        if base is not None:
            validate_revision(base)
            args.append(base)
        if head is not None:
            validate_revision(head)
            args.append(head)
        args.append("--")
        args.extend(validate_relative_path(path) for path in paths)
        return (await self._git(repo, tuple(args))).stdout

    async def commit(
        self,
        repository: Path,
        *,
        message: str,
        paths: Sequence[str],
    ) -> CommitResult:
        repo = await self.assert_repository(repository)
        if not message.strip() or "\x00" in message or len(message) > 4096:
            raise ValidationError("invalid commit message")
        normalized_paths = tuple(validate_relative_path(path) for path in paths)
        if not normalized_paths:
            raise ValidationError("commit requires an explicit non-empty path set")
        parent_result = await self._git(repo, ("rev-parse", "HEAD"), allowed_exit_codes=(0, 128))
        parent = parent_result.stdout.strip() if parent_result.exit_code == 0 else None
        await self._git(repo, ("add", "--", *normalized_paths))
        await self._git(repo, ("commit", "--no-gpg-sign", "-m", message, "--", *normalized_paths))
        commit = (await self._git(repo, ("rev-parse", "HEAD"))).stdout.strip()
        return CommitResult(repo, commit, parent, normalized_paths)

    async def remote_url(self, repository: Path, remote: str) -> str:
        if not _REMOTE_NAME.fullmatch(remote):
            raise ValidationError("invalid remote name")
        repo = await self.assert_repository(repository)
        url = (await self._git(repo, ("remote", "get-url", "--push", remote))).stdout.strip()
        return _canonical_remote_url(url, repository=repo)

    async def _remote_ref_head(
        self,
        repository: Path,
        remote: str,
        destination: str,
    ) -> str | None:
        result = await self._git(
            repository,
            ("ls-remote", "--refs", remote, destination),
            allowed_exit_codes=(0,),
        )
        line = result.stdout.strip().splitlines()
        return line[0].split()[0] if line else None

    async def reconcile_push(
        self,
        repository: Path,
        *,
        remote: str,
        destination: str,
        expected_source_oid: str,
    ) -> PushReconciliation:
        """Read remote truth after a crash without replaying the push."""

        if not _REMOTE_NAME.fullmatch(remote):
            raise ValidationError("invalid remote name")
        validate_git_ref(destination)
        if not destination.startswith("refs/heads/"):
            raise ValidationError("push reconciliation destination must be a branch ref")
        if not _OBJECT_ID.fullmatch(expected_source_oid):
            raise ValidationError("invalid expected Git source object ID")
        remote_head = await self._remote_ref_head(repository, remote, destination)
        if remote_head is None:
            state = "NOT_APPLIED"
        elif hmac.compare_digest(remote_head.lower(), expected_source_oid.lower()):
            state = "APPLIED"
        else:
            state = "CONFLICT"
        return PushReconciliation(
            destination=destination,
            expected_source_oid=expected_source_oid.lower(),
            remote_head=remote_head,
            state=state,
        )

    async def push(
        self,
        repository: Path,
        *,
        remote: str,
        refspec: str,
        capability_token: str,
        action_id: str,
        epoch: int,
    ) -> PushResult:
        repo = await self.assert_repository(repository)
        if self.push_tokens is None:
            raise GitPushAuthorizationError("Git push adapter has no capability verifier")
        if not _REMOTE_NAME.fullmatch(remote):
            raise ValidationError("invalid remote name")
        refspec = validate_refspec(refspec)
        remote_url = await self.remote_url(repo, remote)
        source = refspec.split(":", 1)[0]
        local_oid = (await self._git(repo, ("rev-parse", source))).stdout.strip()
        claims = self.push_tokens.verify(
            capability_token,
            action_id=action_id,
            epoch=epoch,
            repository=repo,
            remote_url=remote_url,
            refspec=refspec,
            source_oid=local_oid,
        )
        destination = refspec.split(":", 1)[1]
        before = await self._remote_ref_head(repo, remote, destination)
        result = await self._git(
            repo,
            ("push", "--porcelain", remote, refspec),
            env={
                "TARS_PUSH_TOKEN": capability_token,
                "TARS_ACTION_ID": action_id,
                "TARS_ACTION_EPOCH": str(epoch),
                "TARS_REFSPEC": refspec,
                "TARS_SOURCE_WORKTREE": str(repo),
                "TARS_REMOTE_URL": remote_url,
            },
        )
        after = await self._remote_ref_head(repo, remote, destination)
        if after is None:
            raise GitIntegrityError("push reported success but destination ref is missing")
        if claims.source_oid != after:
            raise GitIntegrityError("remote ref does not match the authorized source commit")
        return PushResult(repo, remote, remote_url, refspec, before, after, result)

    async def install_push_hook(
        self,
        repository: Path,
        *,
        secret_file: Path,
        remote_repository: Path | None = None,
        remote: str = "origin",
        force: bool = False,
    ) -> Path:
        repo = await self.assert_repository(repository)
        secret = resolve_under_roots(secret_file, self.allowed_roots, require_directory=False)
        if stat.S_IMODE(secret.stat().st_mode) & 0o077:
            raise ValidationError("push-hook secret must not be group/world accessible")
        if stat.S_IMODE(secret.parent.stat().st_mode) & 0o077:
            raise ValidationError("push-hook secret directory must not be group/world accessible")
        nonce_database = _nonce_database_path(secret)
        _initialize_nonce_database(nonce_database)

        if remote_repository is None:
            if not _REMOTE_NAME.fullmatch(remote):
                raise ValidationError("invalid remote name")
            configured_remote = await self.remote_url(repo, remote)
            parsed_remote = urlsplit(configured_remote)
            if parsed_remote.scheme or re.match(r"^[^/]+@?[^/:]*:", configured_remote):
                raise GitAdapterError(
                    "server-side push enforcement requires a registered local bare remote"
                )
            remote_repo = resolve_under_roots(
                Path(configured_remote),
                self.allowed_roots,
                require_directory=True,
            )
        else:
            remote_repo = resolve_under_roots(
                remote_repository,
                self.allowed_roots,
                require_directory=True,
            )
            configured_remote = await self.remote_url(repo, remote)
            if configured_remote != str(remote_repo):
                raise ValidationError("registered bare remote does not match the exact push URL")

        bare_check = await self.runner.run(
            (
                self.git_binary,
                "--git-dir",
                str(remote_repo),
                "rev-parse",
                "--is-bare-repository",
            ),
            cwd=remote_repo,
            inherited_env_keys=GIT_SUBPROCESS_ENV_KEYS,
            timeout_seconds=30,
        )
        if not bare_check.succeeded or bare_check.stdout.strip() != "true":
            raise GitAdapterError("registered push target is not a bare Git repository")

        hooks_result = await self._git(repo, ("rev-parse", "--git-path", "hooks"))
        hooks_path = Path(hooks_result.stdout.strip())
        if not hooks_path.is_absolute():
            hooks_path = repo / hooks_path
        hooks_path = resolve_under_roots(hooks_path, self.allowed_roots, must_exist=False)
        hooks_path.mkdir(parents=True, exist_ok=True)
        hook = hooks_path / "pre-push"
        if hook.exists() and not force and _HOOK_MARKER not in hook.read_text(errors="replace"):
            raise GitAdapterError("refusing to overwrite an unmanaged pre-push hook")
        _write_hook_atomically(hook, _render_pre_push_hook(secret, nonce_database))

        server_hooks = resolve_under_roots(
            remote_repo / "hooks",
            self.allowed_roots,
            require_directory=True,
        )
        receive_hook = server_hooks / "pre-receive"
        if (
            receive_hook.exists()
            and not force
            and _SERVER_HOOK_MARKER not in receive_hook.read_text(errors="replace")
        ):
            raise GitAdapterError("refusing to overwrite an unmanaged pre-receive hook")
        _write_hook_atomically(
            receive_hook,
            _render_pre_receive_hook(
                secret,
                nonce_database,
                remote_repository=remote_repo,
                remote_url=configured_remote,
            ),
        )
        return hook


def _write_hook_atomically(path: Path, source: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(source)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _render_pre_push_hook(secret_file: Path, nonce_database: Path) -> str:
    # Standalone Python avoids shell interpolation and works even when the
    # package itself is not importable from Git's hook environment.
    return f"""#!/usr/bin/env python3
{_HOOK_MARKER}
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.parse

SECRET_FILE = pathlib.Path({str(secret_file)!r})
NONCE_DATABASE = pathlib.Path({str(nonce_database)!r})
CLAIM_KEYS = {{
    "protocol", "action_id", "epoch", "repository", "remote_url", "refspec",
    "destination", "source_oid", "issued_at", "expires_at", "nonce",
}}
ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{{0,191}}\\Z")
NONCE = re.compile(r"[0-9a-f]{{32}}\\Z")
OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{{40}}|[0-9a-fA-F]{{64}})\\Z")

def decode(value):
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )

def deny(message):
    print("TARS push denied: " + message, file=sys.stderr)
    raise SystemExit(1)

def canonical_remote(value, repository):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme == "file":
        if parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
            deny("unsupported file remote")
        candidate = pathlib.Path(urllib.parse.unquote(parsed.path))
    elif not parsed.scheme and not re.match(r"^[^/]+@?[^/:]*:", value):
        candidate = pathlib.Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = repository / candidate
    else:
        return value
    return str(candidate.resolve(strict=False))

token = os.environ.get("TARS_PUSH_TOKEN", "")
action_id = os.environ.get("TARS_ACTION_ID", "")
epoch = os.environ.get("TARS_ACTION_EPOCH", "")
refspec = os.environ.get("TARS_REFSPEC", "")
source_worktree = os.environ.get("TARS_SOURCE_WORKTREE", "")
remote_url = os.environ.get("TARS_REMOTE_URL", "")
if not all((token, action_id, epoch, refspec, source_worktree, remote_url)):
    deny("missing gateway capability")
try:
    body64, signature64 = token.split(".", 1)
    body = decode(body64)
    signature = decode(signature64)
    payload = json.loads(body)
    secret = SECRET_FILE.read_bytes()
except Exception:
    deny("malformed gateway capability")
if not isinstance(payload, dict) or set(payload) != CLAIM_KEYS:
    deny("malformed gateway capability claims")
expected = hmac.new(secret, body, hashlib.sha256).digest()
if not hmac.compare_digest(signature, expected):
    deny("bad gateway signature")
if payload.get("protocol") != "tars.git-push/v2":
    deny("unsupported capability protocol")
if not ACTION_ID.fullmatch(action_id):
    deny("invalid action")
if (
    payload.get("action_id") != action_id
    or type(payload.get("epoch")) is not int
    or str(payload.get("epoch")) != epoch
):
    deny("action or epoch mismatch")
try:
    current_repository = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    current_repository = str(pathlib.Path(current_repository).resolve(strict=True))
except Exception:
    deny("cannot identify current worktree")
if payload.get("repository") != current_repository or source_worktree != current_repository:
    deny("repository mismatch")
if len(sys.argv) != 3:
    deny("invalid hook invocation")
normalized_remote = canonical_remote(sys.argv[2], pathlib.Path(current_repository))
if (
    payload.get("remote_url") != normalized_remote
    or remote_url != normalized_remote
    or payload.get("refspec") != refspec
):
    deny("remote or refspec mismatch")
now = int(time.time())
issued_at = payload.get("issued_at")
expires_at = payload.get("expires_at")
if (
    type(issued_at) is not int
    or type(expires_at) is not int
    or issued_at > now + 5
    or expires_at < now
    or expires_at <= issued_at
    or expires_at - issued_at > 300
):
    deny("expired capability")
destination = refspec.split(":", 1)[1] if refspec.count(":") == 1 else ""
if not destination.startswith("refs/heads/") or payload.get("destination") != destination:
    deny("invalid push destination")
nonce = payload.get("nonce")
if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
    deny("invalid capability nonce")
try:
    if stat.S_IMODE(NONCE_DATABASE.stat().st_mode) & 0o077:
        deny("insecure capability ledger")
    connection = sqlite3.connect(
        "file:" + str(NONCE_DATABASE) + "?mode=ro", uri=True, timeout=5
    )
    try:
        consumed = connection.execute(
            "SELECT 1 FROM consumed_push_nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
    finally:
        connection.close()
except SystemExit:
    raise
except Exception:
    deny("capability ledger unavailable")
if consumed is not None:
    deny("capability already consumed")
updates = [line.split() for line in sys.stdin.read().splitlines() if line.strip()]
if len(updates) != 1 or len(updates[0]) != 4 or updates[0][2] != destination:
    deny("pushed refs do not match capability")
source_oid = payload.get("source_oid")
if not isinstance(source_oid, str) or not OBJECT_ID.fullmatch(source_oid):
    deny("invalid authorized source object")
if updates[0][1].lower() != source_oid.lower():
    deny("pushed source object does not match capability")
raise SystemExit(0)
"""


def _render_pre_receive_hook(
    secret_file: Path,
    nonce_database: Path,
    *,
    remote_repository: Path,
    remote_url: str,
) -> str:
    """Render the authority boundary that cannot be skipped with --no-verify."""

    return f"""#!/usr/bin/env python3
{_SERVER_HOOK_MARKER}
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import sys
import time

SECRET_FILE = pathlib.Path({str(secret_file)!r})
NONCE_DATABASE = pathlib.Path({str(nonce_database)!r})
REMOTE_REPOSITORY = pathlib.Path({str(remote_repository)!r})
REMOTE_URL = {remote_url!r}
CLAIM_KEYS = {{
    "protocol", "action_id", "epoch", "repository", "remote_url", "refspec",
    "destination", "source_oid", "issued_at", "expires_at", "nonce",
}}
ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{{0,191}}\\Z")
NONCE = re.compile(r"[0-9a-f]{{32}}\\Z")
OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{{40}}|[0-9a-fA-F]{{64}})\\Z")

def decode(value):
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )

def deny(message):
    print("TARS remote denied: " + message, file=sys.stderr)
    raise SystemExit(1)

token = os.environ.get("TARS_PUSH_TOKEN", "")
action_id = os.environ.get("TARS_ACTION_ID", "")
epoch = os.environ.get("TARS_ACTION_EPOCH", "")
refspec = os.environ.get("TARS_REFSPEC", "")
source_worktree = os.environ.get("TARS_SOURCE_WORKTREE", "")
remote_url = os.environ.get("TARS_REMOTE_URL", "")
if not all((token, action_id, epoch, refspec, source_worktree, remote_url)):
    deny("missing gateway capability")
try:
    body64, signature64 = token.split(".", 1)
    body = decode(body64)
    signature = decode(signature64)
    payload = json.loads(body)
    secret = SECRET_FILE.read_bytes()
except Exception:
    deny("malformed gateway capability")
if not isinstance(payload, dict) or set(payload) != CLAIM_KEYS:
    deny("malformed gateway capability claims")
expected = hmac.new(secret, body, hashlib.sha256).digest()
if not hmac.compare_digest(signature, expected):
    deny("bad gateway signature")
if payload.get("protocol") != "tars.git-push/v2":
    deny("unsupported capability protocol")
if not ACTION_ID.fullmatch(action_id):
    deny("invalid action")
if (
    payload.get("action_id") != action_id
    or type(payload.get("epoch")) is not int
    or str(payload.get("epoch")) != epoch
):
    deny("action or epoch mismatch")
try:
    current_remote = pathlib.Path.cwd().resolve(strict=True)
    expected_remote = REMOTE_REPOSITORY.resolve(strict=True)
except Exception:
    deny("cannot identify protected remote")
if current_remote != expected_remote or remote_url != REMOTE_URL:
    deny("remote mismatch")
if payload.get("remote_url") != REMOTE_URL or payload.get("refspec") != refspec:
    deny("remote or refspec mismatch")
try:
    source_path = pathlib.Path(source_worktree).resolve(strict=True)
    git_environment = os.environ.copy()
    for inherited_key in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_PREFIX"
    ):
        git_environment.pop(inherited_key, None)
    source_top = subprocess.run(
        ["git", "-C", str(source_path), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env=git_environment,
    ).stdout.strip()
    source_top = str(pathlib.Path(source_top).resolve(strict=True))
except Exception:
    deny("cannot identify authorized source worktree")
if payload.get("repository") != source_top or source_worktree != source_top:
    deny("source worktree mismatch")
now = int(time.time())
issued_at = payload.get("issued_at")
expires_at = payload.get("expires_at")
if (
    type(issued_at) is not int
    or type(expires_at) is not int
    or issued_at > now + 5
    or expires_at < now
    or expires_at <= issued_at
    or expires_at - issued_at > 300
):
    deny("expired capability")
destination = refspec.split(":", 1)[1] if refspec.count(":") == 1 else ""
if not destination.startswith("refs/heads/") or payload.get("destination") != destination:
    deny("invalid push destination")
source_revision = refspec.split(":", 1)[0] if refspec.count(":") == 1 else ""
source_oid = payload.get("source_oid")
if not isinstance(source_oid, str) or not OBJECT_ID.fullmatch(source_oid):
    deny("invalid authorized source object")
try:
    worktree_oid = subprocess.run(
        ["git", "-C", source_top, "rev-parse", source_revision],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env=git_environment,
    ).stdout.strip()
except Exception:
    deny("cannot resolve authorized source revision")
if worktree_oid.lower() != source_oid.lower():
    deny("source worktree object mismatch")
updates = [line.split() for line in sys.stdin.read().splitlines() if line.strip()]
if len(updates) != 1 or len(updates[0]) != 3 or updates[0][2] != destination:
    deny("received refs do not match capability")
if updates[0][1].lower() != source_oid.lower():
    deny("received source object does not match capability")
nonce = payload.get("nonce")
if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
    deny("invalid capability nonce")
try:
    if stat.S_IMODE(SECRET_FILE.stat().st_mode) & 0o077:
        deny("insecure capability secret")
    if stat.S_IMODE(NONCE_DATABASE.stat().st_mode) & 0o077:
        deny("insecure capability ledger")
    connection = sqlite3.connect(NONCE_DATABASE, timeout=5, isolation_level=None)
    try:
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO consumed_push_nonces ("
            "nonce, token_sha256, action_id, epoch, source_worktree, "
            "remote_url, refspec, source_oid, consumed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                nonce,
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
                action_id,
                int(epoch),
                source_top,
                REMOTE_URL,
                refspec,
                source_oid.lower(),
                now,
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError:
        connection.execute("ROLLBACK")
        deny("capability already consumed")
    except Exception:
        connection.execute("ROLLBACK")
        deny("capability ledger unavailable")
    finally:
        connection.close()
except SystemExit:
    raise
except Exception:
    deny("capability ledger unavailable")
raise SystemExit(0)
"""
