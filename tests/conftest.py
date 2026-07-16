from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tars_revoke.clock import FakeClock
from tars_revoke.persistence import Store

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(NOW)


@pytest.fixture
def store(tmp_path, clock: FakeClock) -> Store:
    return Store(tmp_path / "tars.sqlite3", clock=clock)
