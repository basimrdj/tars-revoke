from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from tars_revoke.demo.crashbench import _run_suite
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.services.coordinator import RecoverySnapshot, RevocationCoordinator


def test_crashbench_fails_closed_when_production_recovery_breaks_an_invariant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = RevocationCoordinator.recover

    def misreport_expiration(
        coordinator: RevocationCoordinator,
        run_id: str,
    ) -> RecoverySnapshot:
        recovered = original(coordinator, run_id)
        return replace(recovered, expired_lease_count=0)

    monkeypatch.setattr(RevocationCoordinator, "recover", misreport_expiration)

    with pytest.raises(IntegrityError, match="failed closed"):
        _run_suite(tmp_path, "CrashBench-11")
    assert not tuple(tmp_path.rglob("report.json"))


def test_crashbench_rejects_unknown_suite_before_allocating_artifacts(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="unknown benchmark suite"):
        _run_suite(tmp_path, "CrashBench-12")
    assert not tuple(tmp_path.iterdir())
