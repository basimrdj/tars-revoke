from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.errors import IntegrityError, ValidationError

MIGRATION_SOURCE_PATH = "migrations/002_customer_id_contract.sql"
UUID_CONTRACT_SQL = (
    "ALTER TABLE customers ADD COLUMN customer_id_format TEXT NOT NULL DEFAULT 'uuid';\n"
    "PRAGMA user_version=2;\n"
)
OPAQUE_CONTRACT_SQL = (
    "ALTER TABLE customers ADD COLUMN customer_id_format TEXT NOT NULL DEFAULT 'opaque';\n"
    "PRAGMA user_version=3;\n"
)
_EXPECTED_SQL = {
    "uuid": UUID_CONTRACT_SQL,
    "opaque": OPAQUE_CONTRACT_SQL,
}


@dataclass(frozen=True)
class ValidatedMigrationSource:
    contract: str
    relative_path: str
    path: Path
    payload: bytes
    sql: str
    sha256: str
    user_version: int


def validate_migration_source(
    worktree: Path,
    *,
    expected_contract: str,
) -> ValidatedMigrationSource:
    """Read and strictly validate the exact agent-authored migration bytes.

    Canonical demo migrations are intentionally a tiny whitelist rather than a
    general SQL parser.  The gateway therefore executes the exact regular-file
    bytes produced in the bounded worktree, and no comments, extra statements,
    alternative PRAGMAs, transaction control, or path substitution are accepted.
    """

    expected_sql = _EXPECTED_SQL.get(expected_contract)
    if expected_sql is None:
        raise ValidationError("unknown canonical migration contract")
    root = worktree.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValidationError("migration worktree must be a directory")
    candidate = root / MIGRATION_SOURCE_PATH
    if candidate.is_symlink():
        raise IntegrityError("agent-authored migration source cannot be a symlink")
    try:
        path = candidate.resolve(strict=True)
    except OSError as exc:
        raise IntegrityError("agent-authored migration source is missing") from exc
    if root not in path.parents or path.relative_to(root).as_posix() != MIGRATION_SOURCE_PATH:
        raise IntegrityError("agent-authored migration source escaped its bounded path")
    if not path.is_file():
        raise IntegrityError("agent-authored migration source must be a regular file")
    expected = expected_sql.encode("utf-8")
    # Read no more than one byte beyond the only accepted grammar. This keeps
    # the proof boundary bounded even if an untrusted agent replaces the file
    # with a very large regular file between workspace inspection and parsing.
    with path.open("rb") as stream:
        payload = stream.read(len(expected) + 1)
    if not hmac.compare_digest(payload, expected):
        raise IntegrityError(
            f"agent-authored migration does not match the strict {expected_contract} grammar"
        )
    return ValidatedMigrationSource(
        contract=expected_contract,
        relative_path=MIGRATION_SOURCE_PATH,
        path=path,
        payload=payload,
        sql=payload.decode("utf-8"),
        sha256=sha256_digest(payload),
        user_version=2 if expected_contract == "uuid" else 3,
    )
