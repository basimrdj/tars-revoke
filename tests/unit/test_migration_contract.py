from __future__ import annotations

from pathlib import Path

import pytest

from tars_revoke.demo.migration_contract import (
    MIGRATION_SOURCE_PATH,
    OPAQUE_CONTRACT_SQL,
    UUID_CONTRACT_SQL,
    validate_migration_source,
)
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.errors import IntegrityError


def _worktree(tmp_path: Path, sql: str) -> Path:
    path = tmp_path / MIGRATION_SOURCE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(sql, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("contract", "sql", "version"),
    (("uuid", UUID_CONTRACT_SQL, 2), ("opaque", OPAQUE_CONTRACT_SQL, 3)),
)
def test_validator_returns_exact_agent_authored_bytes(
    tmp_path: Path,
    contract: str,
    sql: str,
    version: int,
) -> None:
    source = validate_migration_source(
        _worktree(tmp_path, sql),
        expected_contract=contract,
    )

    assert source.payload == sql.encode()
    assert source.sql == sql
    assert source.sha256 == sha256_digest(sql)
    assert source.relative_path == MIGRATION_SOURCE_PATH
    assert source.user_version == version


@pytest.mark.parametrize(
    "mutation",
    (
        "-- comment\n" + UUID_CONTRACT_SQL,
        UUID_CONTRACT_SQL.replace("'uuid'", "'opaque'"),
        UUID_CONTRACT_SQL + "SELECT 1;\n",
        UUID_CONTRACT_SQL.replace("user_version=2", "user_version = 2"),
        UUID_CONTRACT_SQL.replace("\n", "\r\n"),
    ),
)
def test_validator_rejects_every_noncanonical_sql_shape(
    tmp_path: Path,
    mutation: str,
) -> None:
    worktree = _worktree(tmp_path, mutation)

    with pytest.raises(IntegrityError, match="strict uuid grammar"):
        validate_migration_source(worktree, expected_contract="uuid")


def test_validator_rejects_a_symlinked_migration(tmp_path: Path) -> None:
    outside = tmp_path / "outside.sql"
    outside.write_text(UUID_CONTRACT_SQL, encoding="utf-8")
    worktree = tmp_path / "worktree"
    migration = worktree / MIGRATION_SOURCE_PATH
    migration.parent.mkdir(parents=True)
    migration.symlink_to(outside)

    with pytest.raises(IntegrityError, match="symlink"):
        validate_migration_source(worktree, expected_contract="uuid")


def test_validator_reads_only_the_bounded_canonical_grammar(tmp_path: Path) -> None:
    worktree = _worktree(tmp_path, UUID_CONTRACT_SQL + ("X" * 2_000_000))

    with pytest.raises(IntegrityError, match="strict uuid grammar"):
        validate_migration_source(worktree, expected_contract="uuid")
