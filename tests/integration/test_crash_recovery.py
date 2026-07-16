from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tars_revoke.clock import FakeClock
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    EffectState,
    EffectType,
    LeaseState,
    PremiseState,
    Reversibility,
    RevocationCaseState,
    RiskLevel,
    RunState,
    SignatureStatus,
    ValueSemantics,
    VerificationStatus,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    EffectRecord,
    EvidenceRecord,
    EvidenceSource,
    Premise,
    RevocationCase,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.persistence.store import Store
from tars_revoke.services.coordinator import RevocationCoordinator
from tars_revoke.services.gateway import EffectGateway

NOW = datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc)
RECOVERY_TIME = NOW + timedelta(seconds=2)
NORMAL_CASE_STAGES = (
    RevocationCaseState.OPEN,
    RevocationCaseState.FROZEN,
    RevocationCaseState.INVENTORIED,
    RevocationCaseState.COMPENSATING,
    RevocationCaseState.EXPERIMENTING,
    RevocationCaseState.REPAIRING,
    RevocationCaseState.VERIFYING,
    RevocationCaseState.RESUMED,
    RevocationCaseState.ATTESTED,
    RevocationCaseState.CLOSED,
)


def _create_warrant(
    store: Store,
    *,
    run_id: str,
    agent_id: str,
    premise: Premise,
    suffix: str,
) -> Warrant:
    warrant = Warrant(
        id=f"warrant-{suffix}",
        run_id=run_id,
        agent_id=agent_id,
        scope=premise.scope,
        authorized_targets=(f"target-{suffix}",),
        state=WarrantState.AUTHORIZED,
        risk=RiskLevel.CRITICAL,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )
    store.create_warrant(warrant)
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=NOW,
        )
    )
    return warrant


def _create_action(
    store: Store,
    *,
    run_id: str,
    agent_id: str,
    warrant: Warrant,
    premise: Premise,
    suffix: str,
    state: ActionState,
    action_type: ActionType,
    reversibility: Reversibility,
) -> ActionIntent:
    action = ActionIntent(
        id=f"action-{suffix}",
        run_id=run_id,
        agent_id=agent_id,
        warrant_id=warrant.id,
        scope=premise.scope,
        action_type=action_type,
        target=f"target-{suffix}",
        payload_digest=sha256_digest(f"payload-{suffix}"),
        premise_vector={premise.id: premise.value_digest},
        risk=RiskLevel.CRITICAL,
        reversibility=reversibility,
        state=state,
        idempotency_key=f"action-key-{suffix}",
        created_at=NOW,
        updated_at=NOW,
    )
    return store.create_action(action)


def _create_effect_intent(
    store: Store,
    *,
    action: ActionIntent,
    suffix: str,
    effect_type: EffectType,
) -> EffectRecord:
    return store.create_effect(
        EffectRecord(
            id=f"effect-{suffix}",
            run_id=action.run_id,
            action_id=action.id,
            scope=action.scope,
            target=action.target,
            effect_type=effect_type,
            reversibility=action.reversibility,
            state=EffectState.PREPARED,
            created_at=NOW,
            updated_at=NOW,
            idempotency_key=f"effect-key-{suffix}",
            metadata={"adapter_idempotency_key": f"adapter-{suffix}"},
        )
    )


def _advance_case_to(store: Store, case_id: str, target: RevocationCaseState) -> None:
    if target == RevocationCaseState.ESCALATED:
        store.transition_revocation_case(case_id, target, at=NOW)
        return
    target_index = NORMAL_CASE_STAGES.index(target)
    for state in NORMAL_CASE_STAGES[1 : target_index + 1]:
        store.transition_revocation_case(case_id, state, at=NOW)


def _seed_recovery_database(
    database_path: Path,
    *,
    target_stage: RevocationCaseState,
) -> tuple[str, str, tuple[str, str], str, str, str]:
    suffix = target_stage.value.lower()
    run_id = f"run-recovery-{suffix}"
    agent_id = f"agent-recovery-{suffix}"
    premise_id = f"premise-recovery-{suffix}"
    evidence_id = f"evidence-recovery-{suffix}"
    case_id = f"case-recovery-{suffix}"
    store = Store(database_path, clock=FakeClock(NOW))
    store.create_run(
        Run(
            id=run_id,
            name="crash recovery",
            state=RunState.RUNNING,
            root_path=str(database_path.parent),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=run_id,
            name="recovery agent",
            role="builder",
            worktree_path=str(database_path.parent),
            state=AgentState.RUNNING,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_evidence_source(
        EvidenceSource(
            id=f"source-{suffix}",
            run_id=run_id,
            name="registry",
            uri="https://registry.test",
            issuer="registry.test",
            pinned_identity="registry-prod",
            created_at=NOW,
        )
    )
    store.create_evidence_record(
        EvidenceRecord(
            id=evidence_id,
            run_id=run_id,
            source_id=f"source-{suffix}",
            source_uri="https://registry.test/schema/2",
            source_version=2,
            observed_at=NOW,
            valid_at=NOW,
            digest=sha256_digest(f"evidence-{suffix}"),
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
        )
    )
    premise = Premise(
        id=premise_id,
        run_id=run_id,
        scope="repository",
        subject="schema",
        relation="version",
        value=1,
        semantics=ValueSemantics.SINGLE,
        state=PremiseState.ACTIVE,
        valid_at=NOW - timedelta(minutes=1),
        created_at=NOW - timedelta(minutes=1),
    )
    store.create_premise(premise)

    dispatch_warrant = _create_warrant(
        store,
        run_id=run_id,
        agent_id=agent_id,
        premise=premise,
        suffix=f"dispatch-{suffix}",
    )
    dispatch_action = _create_action(
        store,
        run_id=run_id,
        agent_id=agent_id,
        warrant=dispatch_warrant,
        premise=premise,
        suffix=f"dispatch-{suffix}",
        state=ActionState.PREPARED,
        action_type=ActionType.PUSH,
        reversibility=Reversibility.IRREVERSIBLE,
    )
    dispatch_effect = _create_effect_intent(
        store,
        action=dispatch_action,
        suffix=f"dispatch-{suffix}",
        effect_type=EffectType.PUSH,
    )
    gateway = EffectGateway(store, clock=FakeClock(NOW))
    gateway.authorize(
        dispatch_action.id,
        effect_id=dispatch_effect.id,
        current_artifact_hashes={},
        passed_test_ids=(),
        capability_token=f"dispatch-token-{suffix}",
    )
    gateway.dispatch(
        dispatch_action.id,
        effect_id=dispatch_effect.id,
        capability_token=f"dispatch-token-{suffix}",
        current_artifact_hashes={},
        passed_test_ids=(),
    )

    orphan_warrant = _create_warrant(
        store,
        run_id=run_id,
        agent_id=agent_id,
        premise=premise,
        suffix=f"orphan-{suffix}",
    )
    orphan_action = _create_action(
        store,
        run_id=run_id,
        agent_id=agent_id,
        warrant=orphan_warrant,
        premise=premise,
        suffix=f"orphan-{suffix}",
        state=ActionState.PREPARED,
        action_type=ActionType.EXTERNAL,
        reversibility=Reversibility.CONDITIONAL,
    )
    orphan_effect = _create_effect_intent(
        store,
        action=orphan_action,
        suffix=f"orphan-{suffix}",
        effect_type=EffectType.EXTERNAL,
    )
    orphan_authorization = gateway.authorize(
        orphan_action.id,
        effect_id=orphan_effect.id,
        current_artifact_hashes={},
        passed_test_ids=(),
        lease_ttl=timedelta(seconds=1),
        capability_token=f"orphan-token-{suffix}",
    )

    compensation_warrant = _create_warrant(
        store,
        run_id=run_id,
        agent_id=agent_id,
        premise=premise,
        suffix=f"compensation-{suffix}",
    )
    compensation_action = _create_action(
        store,
        run_id=run_id,
        agent_id=agent_id,
        warrant=compensation_warrant,
        premise=premise,
        suffix=f"compensation-{suffix}",
        state=ActionState.REVOKE_PENDING,
        action_type=ActionType.FILE_EDIT,
        reversibility=Reversibility.REVERSIBLE,
    )
    compensation_effect_ids = (
        f"effect-pending-{suffix}",
        f"effect-revoked-{suffix}",
    )
    for effect_id, state in zip(
        compensation_effect_ids,
        (EffectState.REVOKE_PENDING, EffectState.REVOKED),
        strict=True,
    ):
        store.create_effect(
            EffectRecord(
                id=effect_id,
                run_id=run_id,
                action_id=compensation_action.id,
                scope=compensation_action.scope,
                target=f"{effect_id}.txt",
                effect_type=EffectType.FILE_EDIT,
                before_hash=sha256_digest(f"before-{effect_id}"),
                after_hash=sha256_digest(f"after-{effect_id}"),
                reversibility=Reversibility.REVERSIBLE,
                compensation_handler="git.restore_path",
                state=state,
                created_at=NOW,
                updated_at=NOW,
                idempotency_key=f"effect-key-{effect_id}",
            )
        )

    store.create_revocation_case(
        RevocationCase(
            id=case_id,
            run_id=run_id,
            premise_id=premise.id,
            trigger_evidence_id=evidence_id,
            state=RevocationCaseState.OPEN,
            reason="restart recovery proof",
            opened_at=NOW,
            updated_at=NOW,
        )
    )
    _advance_case_to(store, case_id, target_stage)
    store.journal.verify_chain(run_id)
    return (
        run_id,
        case_id,
        compensation_effect_ids,
        dispatch_action.id,
        dispatch_effect.id,
        orphan_authorization.lease.id,
    )


@pytest.mark.parametrize("target_stage", tuple(RevocationCaseState))
def test_restart_recovery_is_stage_independent_and_never_retries_dispatch(
    tmp_path: Path,
    target_stage: RevocationCaseState,
) -> None:
    database_path = tmp_path / f"recovery-{target_stage.value.lower()}.sqlite3"
    run_id, case_id, compensation_ids, dispatch_action_id, dispatch_effect_id, orphan_lease_id = (
        _seed_recovery_database(database_path, target_stage=target_stage)
    )

    reopened = Store(database_path, clock=FakeClock(RECOVERY_TIME))
    dispatch_events_before = [
        event
        for event in reopened.journal.list_events(run_id)
        if event.aggregate_id == dispatch_action_id
        and event.kind == "action.transitioned"
        and event.payload.get("to") == ActionState.DISPATCHING.value
    ]
    assert len(dispatch_events_before) == 1

    first = RevocationCoordinator(reopened, clock=FakeClock(RECOVERY_TIME)).recover(run_id)
    assert first.schema_version == reopened.database.schema_version()
    assert first.event_head_digest == reopened.journal.verify_chain(run_id)
    assert first.expired_lease_count == 1
    assert reopened.get_lease(orphan_lease_id).state == LeaseState.EXPIRED  # type: ignore[union-attr]
    assert first.dispatching_action_ids == (dispatch_action_id,)
    assert first.dispatching_effect_ids == (dispatch_effect_id,)
    assert len(first.dispatch_reconciliations) == 1
    obligation = first.dispatch_reconciliations[0]
    assert obligation.action_id == dispatch_action_id
    assert obligation.effect_id == dispatch_effect_id
    assert obligation.effect_type == EffectType.PUSH.value
    assert obligation.idempotency_key == f"effect-key-dispatch-{target_stage.value.lower()}"
    assert first.compensation_effect_ids == tuple(sorted(compensation_ids))
    expected_incomplete = () if target_stage == RevocationCaseState.CLOSED else (case_id,)
    assert first.incomplete_case_ids == expected_incomplete
    if target_stage in {
        RevocationCaseState.ATTESTED,
        RevocationCaseState.CLOSED,
        RevocationCaseState.ESCALATED,
    }:
        assert first.receipt_rebuild_case_ids == (case_id,)
    else:
        assert first.receipt_rebuild_case_ids == ()

    # A second process sees the same durable obligations. Recovery does not
    # replay an irreversible dispatch or duplicate the already-expired lease.
    reopened_again = Store(database_path, clock=FakeClock(RECOVERY_TIME))
    second = RevocationCoordinator(
        reopened_again,
        clock=FakeClock(RECOVERY_TIME),
    ).recover(run_id)
    assert second.expired_lease_count == 0
    assert second.event_head_digest == first.event_head_digest
    assert second.dispatching_action_ids == first.dispatching_action_ids
    assert second.dispatching_effect_ids == first.dispatching_effect_ids
    assert second.incomplete_case_ids == first.incomplete_case_ids
    assert second.compensation_effect_ids == first.compensation_effect_ids
    assert second.receipt_rebuild_case_ids == first.receipt_rebuild_case_ids
    assert reopened_again.get_action(dispatch_action_id).state == ActionState.DISPATCHING  # type: ignore[union-attr]
    recovered_effect = reopened_again.get_effect(dispatch_effect_id)
    assert recovered_effect is not None
    assert recovered_effect.state == EffectState.DISPATCHING
    assert recovered_effect.metadata["adapter_idempotency_key"] == (
        f"adapter-dispatch-{target_stage.value.lower()}"
    )
    dispatch_events_after = [
        event
        for event in reopened_again.journal.list_events(run_id)
        if event.aggregate_id == dispatch_action_id
        and event.kind == "action.transitioned"
        and event.payload.get("to") == ActionState.DISPATCHING.value
    ]
    assert len(dispatch_events_after) == 1
