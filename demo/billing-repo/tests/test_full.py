from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from billing.models import parse_customer


ROOT = Path(__file__).resolve().parents[1]


def test_initial_migration_creates_customer_table() -> None:
    database = sqlite3.connect(":memory:")
    database.executescript((ROOT / "migrations/001_initial.sql").read_text(encoding="utf-8"))
    columns = database.execute("PRAGMA table_info(customers)").fetchall()
    assert [column[1] for column in columns] == ["customer_id", "email"]


def test_invalid_email_is_rejected() -> None:
    with pytest.raises(ValueError, match="email"):
        parse_customer({"customer_id": "customer", "email": "invalid"})
