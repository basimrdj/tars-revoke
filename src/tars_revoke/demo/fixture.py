from __future__ import annotations

import secrets
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tars_revoke.adapters.git import GitAdapter, create_push_secret
from tars_revoke.adapters.processes import AsyncProcessRunner, ProcessResult
from tars_revoke.adapters.schema_registry import Ed25519SchemaSigner
from tars_revoke.errors import IntegrityError, ValidationError


@dataclass(frozen=True)
class DemoFixture:
    run_id: str
    root: Path
    repository: Path
    remote: Path
    agent_a_worktree: Path
    agent_b_worktree: Path
    service_database: Path
    artifacts_root: Path
    state_database: Path
    push_secret_file: Path
    push_nonce_database_file: Path
    registry_private_key_file: Path
    registry_public_key_file: Path
    registry_token_file: Path
    registry_source_id: str
    registry_key_id: str
    baseline_commit: str


class FixtureBuilder:
    """Build a new isolated real-Git demo fixture without touching the source tree."""

    def __init__(
        self,
        output_root: Path,
        *,
        template_root: Path | None = None,
        python_executable: Path | None = None,
    ) -> None:
        self.output_root = output_root.expanduser().resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)
        source_template = Path(__file__).resolve().parents[3] / "demo" / "billing-repo"
        packaged_template = Path(__file__).resolve().parent / "fixture_template"
        default_template = source_template if source_template.is_dir() else packaged_template
        self.template_root = (template_root or default_template).expanduser().resolve()
        if not self.template_root.is_dir():
            raise ValidationError(f"billing demo template was not found: {self.template_root}")
        self.python_executable = python_executable

    async def build(self, run_id: str) -> DemoFixture:
        if not run_id or any(char in run_id for char in ("/", "\\", "\x00")):
            raise ValidationError("invalid fixture run ID")
        root = (self.output_root / run_id).resolve()
        if root.exists():
            raise ValidationError(f"run fixture already exists: {root}")
        root.mkdir(mode=0o700)

        repository = root / "repository"
        shutil.copytree(self.template_root, repository)
        remote = root / "remote.git"
        worktrees = root / "worktrees"
        worktrees.mkdir()
        agent_a = worktrees / "agent-a"
        agent_b = worktrees / "agent-b"
        artifacts = root / "artifacts" / run_id
        artifacts.mkdir(parents=True)
        for child in (
            "evidence",
            "git",
            "experiments",
            "tests",
            "agents",
            "logs",
        ):
            (artifacts / child).mkdir()

        service_database = root / "billing.sqlite"
        self._initialize_service_database(service_database, repository)

        runner = AsyncProcessRunner([root])
        await self._run_git(runner, root, ("git", "init", "--bare", str(remote)))
        await self._run_git(runner, repository, ("git", "init", "-b", "main"))
        await self._run_git(
            runner,
            repository,
            ("git", "config", "user.name", "TARS REVOKE Demo"),
        )
        await self._run_git(
            runner,
            repository,
            ("git", "config", "user.email", "demo@tars.local"),
        )
        await self._run_git(runner, repository, ("git", "add", "--all"))
        await self._run_git(
            runner,
            repository,
            ("git", "commit", "--no-gpg-sign", "-m", "billing v1 baseline"),
        )
        await self._run_git(
            runner,
            repository,
            ("git", "remote", "add", "origin", str(remote)),
        )
        await self._run_git(
            runner,
            repository,
            ("git", "push", "origin", "HEAD:refs/heads/main"),
        )
        baseline = (
            await self._run_git(runner, repository, ("git", "rev-parse", "HEAD"))
        ).stdout.strip()
        if len(baseline) not in (40, 64):
            raise IntegrityError("fixture baseline did not resolve to a Git object ID")

        secrets_dir = root / "secrets"
        secrets_dir.mkdir(mode=0o700)
        push_secret = secrets_dir / "push-capability.key"
        create_push_secret(push_secret)
        git = GitAdapter([root], process_runner=runner)
        await git.install_push_hook(
            repository,
            secret_file=push_secret,
            remote_repository=remote,
        )
        await git.create_worktree(
            repository,
            agent_a,
            branch="agent-a/uuid-migration",
            start_point=baseline,
        )
        await git.create_worktree(
            repository,
            agent_b,
            branch="agent-b/observability",
            start_point=baseline,
        )
        for worktree in (agent_a, agent_b):
            await self._run_git(
                runner,
                worktree,
                ("git", "config", "user.name", "TARS REVOKE Demo"),
            )
            await self._run_git(
                runner,
                worktree,
                ("git", "config", "user.email", "demo@tars.local"),
            )

        signer = Ed25519SchemaSigner.generate(
            source_id="billing-authority",
            key_id="billing-ed25519-1",
        )
        private_key_file = secrets_dir / "registry-private.key"
        public_key_file = root / "registry-public.key"
        token_file = secrets_dir / "registry-publish.token"
        self._write_private(private_key_file, signer.private_bytes())
        public_key_file.write_bytes(signer.public_bytes())
        token = secrets.token_urlsafe(32)
        self._write_private(token_file, token.encode("utf-8"))

        return DemoFixture(
            run_id=run_id,
            root=root,
            repository=repository,
            remote=remote,
            agent_a_worktree=agent_a,
            agent_b_worktree=agent_b,
            service_database=service_database,
            artifacts_root=artifacts,
            state_database=artifacts / "state.sqlite",
            push_secret_file=push_secret,
            push_nonce_database_file=push_secret.with_name(
                push_secret.name + ".nonces.sqlite3"
            ),
            registry_private_key_file=private_key_file,
            registry_public_key_file=public_key_file,
            registry_token_file=token_file,
            registry_source_id="billing-authority",
            registry_key_id="billing-ed25519-1",
            baseline_commit=baseline,
        )

    @staticmethod
    async def _run_git(
        runner: AsyncProcessRunner,
        cwd: Path,
        argv: tuple[str, ...],
    ) -> ProcessResult:
        result = await runner.run(argv, cwd=cwd, timeout_seconds=60)
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise IntegrityError(f"fixture command failed: {argv[0]} {argv[1]}: {detail}")
        return result

    @staticmethod
    def _initialize_service_database(database: Path, repository: Path) -> None:
        sql = (repository / "migrations" / "001_initial.sql").read_text(encoding="utf-8")
        connection = sqlite3.connect(database)
        try:
            connection.executescript(sql)
            connection.execute("PRAGMA user_version=1")
            connection.commit()
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise IntegrityError("fixture service database failed SQLite quick_check")
        finally:
            connection.close()
        database.chmod(0o600)

    @staticmethod
    def _write_private(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o600)
