from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tars_revoke.domain.enums import EffectState, Reversibility
from tars_revoke.domain.models import EffectRecord, ensure_aware
from tars_revoke.errors import CompensationError, TransitionError


class CompensationAdapter(Protocol):
    def current_hash(self, effect: EffectRecord) -> str | None: ...

    def rollback(self, effect: EffectRecord) -> str | None: ...

    def quarantine(self, effect: EffectRecord) -> None: ...

    def contain(self, effect: EffectRecord) -> None: ...


@dataclass(frozen=True)
class CompensationOutcome:
    effect: EffectRecord
    disposition: EffectState
    changed: bool
    reason: str


_TERMINAL = {
    EffectState.ROLLED_BACK,
    EffectState.QUARANTINED,
    EffectState.CONTAINMENT_REQUIRED,
}


class CompensationService:
    """Idempotently compensate or contain one inventoried effect."""

    @staticmethod
    def handle(
        effect: EffectRecord,
        *,
        adapter: CompensationAdapter,
        now: datetime,
    ) -> CompensationOutcome:
        ensure_aware(now)
        if effect.state in _TERMINAL:
            return CompensationOutcome(
                effect=effect,
                disposition=effect.state,
                changed=False,
                reason="already_terminal",
            )
        if effect.state not in {
            EffectState.EXECUTED,
            EffectState.REVOKE_PENDING,
            EffectState.REVOKED,
        }:
            raise TransitionError(f"cannot compensate effect from {effect.state.value}")

        if effect.reversibility == Reversibility.REVERSIBLE:
            return CompensationService._rollback(effect, adapter=adapter, now=now)

        if effect.reversibility == Reversibility.CONDITIONAL and effect.compensation_handler:
            return CompensationService._rollback(effect, adapter=adapter, now=now)

        # An irreversible operation that reached dispatch may already be visible
        # to the outside world.  Quarantine is honest only before dispatch.
        dispatched = effect.dispatched_at is not None or effect.state == EffectState.EXECUTED
        if dispatched:
            adapter.contain(effect)
            contained = effect.model_copy(
                update={
                    "state": EffectState.CONTAINMENT_REQUIRED,
                    "updated_at": now,
                    "compensation_attempts": effect.compensation_attempts + 1,
                }
            )
            return CompensationOutcome(
                effect=contained,
                disposition=EffectState.CONTAINMENT_REQUIRED,
                changed=True,
                reason="irreversible_effect_already_dispatched",
            )

        adapter.quarantine(effect)
        quarantined = effect.model_copy(
            update={
                "state": EffectState.QUARANTINED,
                "updated_at": now,
                "compensation_attempts": effect.compensation_attempts + 1,
            }
        )
        return CompensationOutcome(
            effect=quarantined,
            disposition=EffectState.QUARANTINED,
            changed=True,
            reason="irreversible_effect_prevented",
        )

    @staticmethod
    def _rollback(
        effect: EffectRecord,
        *,
        adapter: CompensationAdapter,
        now: datetime,
    ) -> CompensationOutcome:
        if not effect.compensation_handler:
            raise CompensationError("reversible effect has no compensation handler")
        current_hash = adapter.current_hash(effect)
        if current_hash == effect.before_hash:
            rolled_back = effect.model_copy(
                update={
                    "state": EffectState.ROLLED_BACK,
                    "updated_at": now,
                    "compensated_at": now,
                }
            )
            return CompensationOutcome(
                effect=rolled_back,
                disposition=EffectState.ROLLED_BACK,
                changed=False,
                reason="before_image_already_restored",
            )
        if current_hash != effect.after_hash:
            adapter.contain(effect)
            contained = effect.model_copy(
                update={
                    "state": EffectState.CONTAINMENT_REQUIRED,
                    "updated_at": now,
                    "compensation_attempts": effect.compensation_attempts + 1,
                }
            )
            return CompensationOutcome(
                effect=contained,
                disposition=EffectState.CONTAINMENT_REQUIRED,
                changed=True,
                reason="current_hash_does_not_match_recorded_after_hash",
            )

        restored_hash = adapter.rollback(effect)
        if restored_hash != effect.before_hash:
            raise CompensationError(
                "compensator did not restore the recorded before-image hash"
            )
        rolled_back = effect.model_copy(
            update={
                "state": EffectState.ROLLED_BACK,
                "updated_at": now,
                "compensated_at": now,
                "compensation_attempts": effect.compensation_attempts + 1,
            }
        )
        return CompensationOutcome(
            effect=rolled_back,
            disposition=EffectState.ROLLED_BACK,
            changed=True,
            reason="before_image_restored",
        )
