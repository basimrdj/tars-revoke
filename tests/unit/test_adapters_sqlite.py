from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from tars_revoke.adapters.sqlite_migration import (
    SQLiteMigrationAdapter,
    SQLiteRestoreConflict,
)
from tars_revoke.errors import ValidationError


def _database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            INSERT INTO widgets(name) VALUES ('before');
            PRAGMA user_version=1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _columns(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [str(row[1]) for row in connection.execute("PRAGMA table_info(widgets)")]
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_snapshot_migrate_and_exact_hash_restore(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    snapshots = tmp_path / "snapshots"
    _database(database)
    adapter = SQLiteMigrationAdapter([tmp_path], snapshot_dir=snapshots)

    result = await adapter.apply(
        database,
        """
        ALTER TABLE widgets ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
        UPDATE widgets SET name='after';
        PRAGMA user_version=2;
        """,
        action_id="action-1",
    )

    assert result.before_hash == result.snapshot.sha256
    assert result.after_hash != result.before_hash
    assert result.before_user_version == 1
    assert result.after_user_version == 2
    assert _columns(database) == ["id", "name", "enabled"]
    assert result.snapshot.snapshot_path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(result.snapshot.snapshot_path.stat().st_mode) == 0o600

    restored = await adapter.restore(
        result.snapshot,
        expected_current_hash=result.after_hash,
    )
    assert restored.restored_hash == result.before_hash
    assert _columns(database) == ["id", "name"]
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT name FROM widgets").fetchone() == ("before",)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_restore_refuses_database_changed_after_effect(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    _database(database)
    adapter = SQLiteMigrationAdapter([tmp_path], snapshot_dir=tmp_path / "snapshots")
    result = await adapter.apply(
        database,
        "UPDATE widgets SET name='after';",
        action_id="action-2",
    )
    connection = sqlite3.connect(database)
    try:
        connection.execute("INSERT INTO widgets(name) VALUES ('concurrent')")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteRestoreConflict, match="changed after the recorded effect"):
        await adapter.restore(result.snapshot, expected_current_hash=result.after_hash)


@pytest.mark.asyncio
async def test_apply_refuses_changed_preimage_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "state.sqlite"
    _database(database)
    adapter = SQLiteMigrationAdapter([tmp_path], snapshot_dir=tmp_path / "snapshots")
    original_snapshot = adapter.snapshot

    async def snapshot_then_mutate(path: Path, *, action_id: str):  # type: ignore[no-untyped-def]
        snapshot = await original_snapshot(path, action_id=action_id)
        connection = sqlite3.connect(path)
        try:
            connection.execute("INSERT INTO widgets(name) VALUES ('racer')")
            connection.commit()
        finally:
            connection.close()
        return snapshot

    monkeypatch.setattr(adapter, "snapshot", snapshot_then_mutate)
    with pytest.raises(SQLiteRestoreConflict, match="changed after snapshot"):
        await adapter.apply(
            database,
            "UPDATE widgets SET name='should-not-run';",
            action_id="action-3",
        )


@pytest.mark.asyncio
async def test_migration_rejects_transaction_and_database_control(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    _database(database)
    adapter = SQLiteMigrationAdapter([tmp_path], snapshot_dir=tmp_path / "snapshots")

    for sql in (
        "BEGIN; UPDATE widgets SET name='x'; COMMIT;",
        "ATTACH DATABASE '/tmp/other.sqlite' AS other;",
        "PRAGMA journal_mode=WAL;",
        "VACUUM;",
    ):
        with pytest.raises(ValidationError, match="unsafe database control"):
            await adapter.apply(database, sql, action_id="action-4")

    with pytest.raises(ValidationError, match="exact expected current"):
        snapshot = await adapter.snapshot(database, action_id="action-5")
        await adapter.restore(snapshot)
