from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.enums import ActionState, EffectState, RevocationCaseState
from tars_revoke.domain.models import EffectRecord, RevocationCase, RevocationMember
from tars_revoke.errors import IntegrityError, TransitionError, ValidationError
from tars_revoke.persistence.store import Store

_NEXT_STAGE: dict[RevocationCaseState, RevocationCaseState] = {
    RevocationCaseState.FROZEN: RevocationCaseState.INVENTORIED,
    RevocationCaseState.INVENTORIED: RevocationCaseState.COMPENSATING,
    RevocationCaseState.COMPENSATING: RevocationCaseState.EXPERIMENTING,
    RevocationCaseState.EXPERIMENTING: RevocationCaseState.REPAIRING,
    RevocationCaseState.REPAIRING: RevocationCaseState.VERIFYING,
    RevocationCaseState.VERIFYING: RevocationCaseState.RESUMED,
    RevocationCaseState.RESUMED: RevocationCaseState.ATTESTED,
    RevocationCaseState.ATTESTED: RevocationCaseState.CLOSED,
}


class CaseStageWorker(Protocol):
    """Idempotent implementation of one durable revocation-case stage.

    The worker must persist its own artifacts before returning. If it raises,
    the case state is deliberately left unchanged so restart recovery can retry
    the same idempotency keys.
    """

    def run_stage(
        self,
        *,
        case: RevocationCase,
        members: tuple[RevocationMember, ...],
        target_state: RevocationCaseState,
    ) -> Mapping[str, object] | None: ...


@dataclass(frozen=True)
class StageAdvance:
    before: RevocationCase
    after: RevocationCase
    outcome: Mapping[str, object]


@dataclass(frozen=True)
class DispatchReconciliation:
    action_id: str
    effect_id: str
    effect_type: str
    target: str
    idempotency_key: str
    metadata: Mapping[str, object]

    @classmethod
    def from_effect(cls, effect: EffectRecord) -> DispatchReconciliation:
        return cls(
            action_id=effect.action_id,
            effect_id=effect.id,
            effect_type=effect.effect_type.value,
            target=effect.target,
            idempotency_key=effect.idempotency_key,
            metadata=dict(effect.metadata),
        )


@dataclass(frozen=True)
class RecoverySnapshot:
    run_id: str
    schema_version: int
    event_head_digest: str
    expired_lease_count: int
    dispatching_action_ids: tuple[str, ...]
    dispatching_effect_ids: tuple[str, ...]
    dispatch_reconciliations: tuple[DispatchReconciliation, ...]
    incomplete_case_ids: tuple[str, ...]
    compensation_effect_ids: tuple[str, ...]
    receipt_rebuild_case_ids: tuple[str, ...]

    @property
    def requires_dispatch_reconciliation(self) -> bool:
        return bool(self.dispatching_effect_ids)


class RevocationCoordinator:
    """Restart-safe coordinator for the persisted revocation state machine.

    Enforcement-time freezing remains exclusively in ``SelectiveRevoker``;
    this coordinator starts after a case has atomically reached ``FROZEN``.
    It advances only one stage at a time and only after the stage worker has
    successfully persisted its evidence.
    """

    def __init__(self, store: Store, *, clock: Clock | None = None) -> None:
        self.store = store
        self.clock = clock or SystemClock()

    def next_stage(self, case_id: str) -> RevocationCaseState | None:
        case = self._require_case(case_id)
        if case.state == RevocationCaseState.OPEN:
            raise TransitionError(
                "an OPEN case must be frozen atomically by SelectiveRevoker"
            )
        return _NEXT_STAGE.get(case.state)

    def run_next(self, case_id: str, *, worker: CaseStageWorker) -> StageAdvance:
        before = self._require_case(case_id)
        if before.state == RevocationCaseState.OPEN:
            raise TransitionError(
                "an OPEN case must be frozen atomically by SelectiveRevoker"
            )
        target = _NEXT_STAGE.get(before.state)
        if target is None:
            raise TransitionError(f"case {case_id} has no automatic next stage")
        members = tuple(self.store.list_revocation_members(case_id))
        outcome = worker.run_stage(
            case=before,
            members=members,
            target_state=target,
        )
        after = self.store.transition_revocation_case(
            case_id,
            target,
            at=self.clock.utc_now(),
        )
        return StageAdvance(before=before, after=after, outcome=dict(outcome or {}))

    def escalate(self, case_id: str) -> RevocationCase:
        case = self._require_case(case_id)
        if case.state in {RevocationCaseState.CLOSED, RevocationCaseState.ESCALATED}:
            return case
        return self.store.transition_revocation_case(
            case_id,
            RevocationCaseState.ESCALATED,
            at=self.clock.utc_now(),
        )

    def recover(self, run_id: str) -> RecoverySnapshot:
        """Verify durable truth and return explicit work; never retry a dispatch.

        Consumers must reconcile every ``DISPATCHING`` action with its adapter
        before deciding whether the external effect occurred. This method only
        expires safe orphan leases and reports outstanding work.
        """

        if self.store.get_run(run_id) is None:
            raise ValidationError(f"run {run_id} does not exist")
        self.store.database.integrity_check()
        self.store.journal.verify_chain(run_id)
        expired_lease_count = self.store.expire_leases(
            at=self.clock.utc_now(),
            run_id=run_id,
        )
        event_head_digest = self.store.journal.verify_chain(run_id)
        dispatching_action_ids = tuple(
            sorted(
                action.id
                for action in self.store.list_actions(
                    run_id,
                    state=ActionState.DISPATCHING,
                )
            )
        )
        dispatching_effects = sorted(
            self.store.list_effects(run_id, state=EffectState.DISPATCHING),
            key=lambda effect: effect.id,
        )
        dispatching_effect_ids = tuple(effect.id for effect in dispatching_effects)
        dispatching_effects_by_action = {
            effect.action_id: effect.id
            for effect in dispatching_effects
        }
        if set(dispatching_effects_by_action) != set(dispatching_action_ids):
            raise IntegrityError(
                "dispatch recovery found an action/effect intent mismatch"
            )
        cases = self.store.list_revocation_cases(run_id)
        incomplete_case_ids = tuple(
            sorted(case.id for case in cases if case.state != RevocationCaseState.CLOSED)
        )
        compensation_effect_ids = tuple(
            sorted(
                effect.id
                for effect in self.store.list_effects(run_id)
                if effect.state in {EffectState.REVOKE_PENDING, EffectState.REVOKED}
            )
        )
        receipt_rebuild_case_ids = tuple(
            sorted(
                case.id
                for case in cases
                if case.state
                in {
                    RevocationCaseState.ATTESTED,
                    RevocationCaseState.CLOSED,
                    RevocationCaseState.ESCALATED,
                }
                and not self.store.list_receipts(run_id, case_id=case.id)
            )
        )
        return RecoverySnapshot(
            run_id=run_id,
            schema_version=self.store.database.schema_version(),
            event_head_digest=event_head_digest,
            expired_lease_count=expired_lease_count,
            dispatching_action_ids=dispatching_action_ids,
            dispatching_effect_ids=dispatching_effect_ids,
            dispatch_reconciliations=tuple(
                DispatchReconciliation.from_effect(effect)
                for effect in dispatching_effects
            ),
            incomplete_case_ids=incomplete_case_ids,
            compensation_effect_ids=compensation_effect_ids,
            receipt_rebuild_case_ids=receipt_rebuild_case_ids,
        )

    def _require_case(self, case_id: str) -> RevocationCase:
        case = self.store.get_revocation_case(case_id)
        if case is None:
            raise ValidationError(f"revocation case {case_id} does not exist")
        return case
