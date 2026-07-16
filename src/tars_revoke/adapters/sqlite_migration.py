from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import sqlite3
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from tars_revoke.errors import AdapterError, IntegrityError, ValidationError

from ._safety import normalize_roots, resolve_under_roots, sha256_file


class SQLiteMigrationError(AdapterError):
    pass


class SQLiteRestoreConflict(IntegrityError):
    pass


_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_FORBIDDEN_SQL = re.compile(
    r"\b(?:BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|ATTACH|DETACH|VACUUM|"
    r"load_extension)\b|\bPRAGMA\s+journal_mode\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SQLiteSnapshot:
    action_id: str
    database_path: Path
    snapshot_path: Path
    sha256: str
    size_bytes: int
    user_version: int
    created_unix: float


@dataclass(frozen=True)
class SQLiteMigrationResult:
    action_id: str
    database_path: Path
    snapshot: SQLiteSnapshot
    before_hash: str
    after_hash: str
    before_user_version: int
    after_user_version: int
    applied_unix: float


@dataclass(frozen=True)
class SQLiteRestoreResult:
    action_id: str
    database_path: Path
    replaced_hash: str
    restored_hash: str
    restored_unix: float


def _strip_sql_comments(sql: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"--[^\r\n]*", " ", without_blocks)


def _validate_sql(sql: str) -> str:
    if not isinstance(sql, str) or not sql.strip() or "\x00" in sql:
        raise ValidationError("migration SQL must be a non-empty NUL-free string")
    if len(sql.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValidationError("migration SQL exceeds 4 MiB")
    if _FORBIDDEN_SQL.search(_strip_sql_comments(sql)):
        raise ValidationError("migration SQL contains transaction or unsafe database control")
    return sql


def _validate_action_id(action_id: str) -> str:
    if not _ACTION_ID.fullmatch(action_id):
        raise ValidationError("invalid migration action_id")
    return action_id


class SQLiteMigrationAdapter:
    """Creates exact before-images and refuses destructive hash mismatches."""

    def __init__(self, allowed_roots: Sequence[Path], *, snapshot_dir: Path) -> None:
        self.allowed_roots = normalize_roots(allowed_roots)
        self.snapshot_dir = resolve_under_roots(
            snapshot_dir,
            self.allowed_roots,
            must_exist=False,
        )
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.chmod(0o700)

    def _database(self, database: Path) -> Path:
        return resolve_under_roots(
            database,
            self.allowed_roots,
            require_directory=False,
        )

    @staticmethod
    def _verify_database(database: Path, *, checkpoint: bool) -> int:
        try:
            connection = sqlite3.connect(str(database), timeout=10, isolation_level=None)
            try:
                connection.execute("PRAGMA foreign_keys=ON")
                result = connection.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise SQLiteMigrationError(f"SQLite quick_check failed: {result}")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if checkpoint:
                    checkpoint_result = connection.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    ).fetchone()
                    if checkpoint_result is not None and int(checkpoint_result[0]) != 0:
                        raise SQLiteMigrationError(
                            f"SQLite WAL checkpoint remained busy: {checkpoint_result}"
                        )
                return version
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SQLiteMigrationError(f"SQLite verification failed for {database}: {exc}") from exc

    async def snapshot(self, database: Path, *, action_id: str) -> SQLiteSnapshot:
        database_path = self._database(database)
        action_id = _validate_action_id(action_id)
        return await asyncio.to_thread(self._snapshot_sync, database_path, action_id)

    def _snapshot_sync(self, database: Path, action_id: str) -> SQLiteSnapshot:
        version = self._verify_database(database, checkpoint=True)
        digest = sha256_file(database)
        safe_action = re.sub(r"[^A-Za-z0-9._-]", "_", action_id)
        target = self.snapshot_dir / f"{safe_action}.{digest}.sqlite"
        if target.exists():
            if sha256_file(target) != digest:
                raise SQLiteMigrationError("existing snapshot has an unexpected digest")
        else:
            temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
            try:
                shutil.copyfile(database, temporary)
                temporary.chmod(0o600)
                with temporary.open("rb") as handle:
                    os.fsync(handle.fileno())
                if sha256_file(temporary) != digest:
                    raise SQLiteMigrationError("snapshot digest differs from source database")
                os.replace(temporary, target)
                _fsync_directory(target.parent)
            finally:
                temporary.unlink(missing_ok=True)
        return SQLiteSnapshot(
            action_id=action_id,
            database_path=database,
            snapshot_path=target,
            sha256=digest,
            size_bytes=target.stat().st_size,
            user_version=version,
            created_unix=time.time(),
        )

    async def apply(
        self,
        database: Path,
        sql: str,
        *,
        action_id: str,
    ) -> SQLiteMigrationResult:
        database_path = self._database(database)
        action_id = _validate_action_id(action_id)
        migration = _validate_sql(sql)
        snapshot = await self.snapshot(database_path, action_id=action_id)
        return await asyncio.to_thread(
            self._apply_sync,
            database_path,
            migration,
            snapshot,
            action_id,
        )

    def _apply_sync(
        self,
        database: Path,
        sql: str,
        snapshot: SQLiteSnapshot,
        action_id: str,
    ) -> SQLiteMigrationResult:
        if sha256_file(database) != snapshot.sha256:
            raise SQLiteRestoreConflict(
                "database changed after snapshot capture; refusing to apply migration"
            )
        try:
            connection = sqlite3.connect(str(database), timeout=10, isolation_level=None)
            try:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.executescript(f"BEGIN IMMEDIATE;\n{sql}\nCOMMIT;")
            except Exception:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SQLiteMigrationError(f"migration failed for action {action_id}: {exc}") from exc
        after_version = self._verify_database(database, checkpoint=True)
        after_hash = sha256_file(database)
        if after_hash == snapshot.sha256:
            raise SQLiteMigrationError("migration produced no durable database change")
        return SQLiteMigrationResult(
            action_id=action_id,
            database_path=database,
            snapshot=snapshot,
            before_hash=snapshot.sha256,
            after_hash=after_hash,
            before_user_version=snapshot.user_version,
            after_user_version=after_version,
            applied_unix=time.time(),
        )

    async def restore(
        self,
        snapshot: SQLiteSnapshot,
        *,
        expected_current_hash: str | None = None,
    ) -> SQLiteRestoreResult:
        if expected_current_hash is None:
            raise ValidationError("restore requires the exact expected current database hash")
        database = self._database(snapshot.database_path)
        snapshot_path = resolve_under_roots(
            snapshot.snapshot_path,
            self.allowed_roots,
            require_directory=False,
        )
        return await asyncio.to_thread(
            self._restore_sync,
            database,
            snapshot_path,
            snapshot,
            expected_current_hash,
        )

    def _restore_sync(
        self,
        database: Path,
        snapshot_path: Path,
        snapshot: SQLiteSnapshot,
        expected_current_hash: str,
    ) -> SQLiteRestoreResult:
        if sha256_file(snapshot_path) != snapshot.sha256:
            raise SQLiteRestoreConflict("snapshot was modified after capture")
        self._verify_database(database, checkpoint=True)
        current_hash = sha256_file(database)
        if current_hash != expected_current_hash:
            raise SQLiteRestoreConflict(
                "database changed after the recorded effect; refusing to overwrite it"
            )
        temporary = database.with_name(f".{database.name}.{secrets.token_hex(8)}.restore")
        try:
            shutil.copyfile(snapshot_path, temporary)
            temporary.chmod(stat_mode(database))
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            if sha256_file(temporary) != snapshot.sha256:
                raise SQLiteRestoreConflict("restore staging file failed digest verification")
            os.replace(temporary, database)
            _fsync_directory(database.parent)
            for suffix in ("-wal", "-shm"):
                database.with_name(database.name + suffix).unlink(missing_ok=True)
        finally:
            temporary.unlink(missing_ok=True)
        self._verify_database(database, checkpoint=False)
        restored_hash = sha256_file(database)
        if restored_hash != snapshot.sha256:
            raise SQLiteRestoreConflict("restored database does not match its before-image")
        return SQLiteRestoreResult(
            action_id=snapshot.action_id,
            database_path=database,
            replaced_hash=current_hash,
            restored_hash=restored_hash,
            restored_unix=time.time(),
        )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - platform-specific durability
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
