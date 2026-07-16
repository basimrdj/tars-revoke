from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tars_revoke.domain.enums import EffectState, EffectType, Reversibility
from tars_revoke.domain.models import EffectRecord
from tars_revoke.errors import IntegrityError
from tars_revoke.services.compensation import CompensationService
from tars_revoke.services.inventory import EffectInventory

NOW = datetime(2026, 7, 14, tzinfo=timezone.utc)


class FakeAdapter:
    def __init__(self, current: str | None, restored: str | None = None) -> None:
        self.current = current
        self.restored = restored
        self.rollback_calls = 0
        self.quarantine_calls = 0
        self.contain_calls = 0

    def current_hash(self, effect: EffectRecord) -> str | None:
        return self.current

    def rollback(self, effect: EffectRecord) -> str | None:
        self.rollback_calls += 1
        self.current = self.restored
        return self.restored

    def quarantine(self, effect: EffectRecord) -> None:
        self.quarantine_calls += 1

    def contain(self, effect: EffectRecord) -> None:
        self.contain_calls += 1


def _effect(
    *,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
    state: EffectState = EffectState.REVOKED,
    dispatched: bool = False,
) -> EffectRecord:
    return EffectRecord(
        id="effect-1",
        run_id="run-1",
        action_id="action-1",
        scope="repo:billing",
        target="billing/models.py",
        effect_type=(
            EffectType.FILE_EDIT if reversibility != Reversibility.IRREVERSIBLE else EffectType.PUSH
        ),
        before_hash="a" * 64,
        after_hash="b" * 64,
        reversibility=reversibility,
        compensation_handler="git-blob" if reversibility == Reversibility.REVERSIBLE else None,
        state=state,
        created_at=NOW,
        updated_at=NOW,
        dispatched_at=NOW if dispatched else None,
        idempotency_key="effect-key",
    )


def test_reversible_effect_restores_exact_before_image_once() -> None:
    adapter = FakeAdapter("b" * 64, "a" * 64)

    first = CompensationService.handle(_effect(), adapter=adapter, now=NOW)
    second = CompensationService.handle(first.effect, adapter=adapter, now=NOW)

    assert first.disposition == EffectState.ROLLED_BACK
    assert first.effect.compensated_at == NOW
    assert second.effect == first.effect
    assert not second.changed
    assert adapter.rollback_calls == 1


def test_hash_mismatch_escalates_without_overwriting_unknown_work() -> None:
    adapter = FakeAdapter("c" * 64, "a" * 64)

    outcome = CompensationService.handle(_effect(), adapter=adapter, now=NOW)

    assert outcome.disposition == EffectState.CONTAINMENT_REQUIRED
    assert adapter.rollback_calls == 0
    assert adapter.contain_calls == 1


def test_undispatched_irreversible_effect_is_quarantined_idempotently() -> None:
    adapter = FakeAdapter(None)

    first = CompensationService.handle(
        _effect(reversibility=Reversibility.IRREVERSIBLE),
        adapter=adapter,
        now=NOW,
    )
    second = CompensationService.handle(first.effect, adapter=adapter, now=NOW)

    assert first.disposition == EffectState.QUARANTINED
    assert second.effect == first.effect
    assert adapter.quarantine_calls == 1


def test_dispatched_irreversible_effect_requires_honest_containment() -> None:
    adapter = FakeAdapter(None)

    outcome = CompensationService.handle(
        _effect(
            reversibility=Reversibility.IRREVERSIBLE,
            state=EffectState.EXECUTED,
            dispatched=True,
        ),
        adapter=adapter,
        now=NOW,
    )

    assert outcome.disposition == EffectState.CONTAINMENT_REQUIRED
    assert adapter.contain_calls == 1
    assert adapter.quarantine_calls == 0


def test_inventory_fails_closed_on_an_unattributed_durable_change() -> None:
    reconciliation = EffectInventory.reconcile(
        {"tracked.py": "a" * 64},
        {"tracked.py": "b" * 64, "surprise.py": "c" * 64},
        attributed_paths={"tracked.py"},
    )

    assert reconciliation.unattributed_paths == ("surprise.py",)
    with pytest.raises(IntegrityError, match="unattributed durable effects"):
        reconciliation.require_complete()
