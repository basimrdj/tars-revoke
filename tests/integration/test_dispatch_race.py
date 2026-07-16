from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

from tars_revoke.clock import FakeClock
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    LeaseState,
    NodeKind,
    PremiseState,
    Reversibility,
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
    DependencyEdge,
    EffectRecord,
    EvidenceRecord,
    EvidenceSource,
    GraphNode,
    Premise,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import AuthorizationError
from tars_revoke.persistence.store import Store
from tars_revoke.services.gateway import EffectGateway
from tars_revoke.services.revocation import SelectiveRevoker

NOW = datetime(2026, 7, 14, 14, 0, tzinfo=timezone.utc)


def _race_dispatch(
    barrier: Barrier,
    gateway: EffectGateway,
    action_id: str,
    effect_id: str,
    token: str,
) -> bool:
    barrier.wait()
    try:
        gateway.dispatch(
            action_id,
            effect_id=effect_id,
            capability_token=token,
            current_artifact_hashes={},
            passed_test_ids=(),
        )
    except AuthorizationError:
        return False
    return True


def _race_invalidate(
    barrier: Barrier,
    revoker: SelectiveRevoker,
    premise_id: str,
    evidence_id: str,
    case_id: str,
) -> None:
    barrier.wait()
    revoker.invalidate_and_fence(
        premise_id,
        invalidating_evidence_id=evidence_id,
        reason="new signed schema invalidates dispatch authority",
        case_id=case_id,
    )


def _authorized_race_fixture(
    tmp_path: Path,
    iteration: int,
) -> tuple[Store, FakeClock, EffectGateway, SelectiveRevoker, str, str, str, str]:
    suffix = str(iteration)
    run_id = f"run-race-{suffix}"
    premise_id = f"premise-race-{suffix}"
    evidence_id = f"evidence-race-{suffix}"
    warrant_id = f"warrant-race-{suffix}"
    action_id = f"action-race-{suffix}"
    effect_id = f"effect-race-{suffix}"
    scope = "repository"
    clock = FakeClock(NOW)
    store = Store(tmp_path / f"race-{suffix}.sqlite3", clock=clock)
    store.create_run(
        Run(
            id=run_id,
            name="dispatch race",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_agent(
        Agent(
            id=f"agent-{suffix}",
            run_id=run_id,
            name="racing agent",
            role="builder",
            worktree_path=str(tmp_path),
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
        scope=scope,
        subject="schema",
        relation="version",
        value=1,
        semantics=ValueSemantics.SINGLE,
        state=PremiseState.ACTIVE,
        valid_at=NOW - timedelta(minutes=1),
        created_at=NOW - timedelta(minutes=1),
    )
    store.create_premise(premise)
    store.create_warrant(
        Warrant(
            id=warrant_id,
            run_id=run_id,
            agent_id=f"agent-{suffix}",
            scope=scope,
            authorized_targets=("origin/main",),
            state=WarrantState.AUTHORIZED,
            risk=RiskLevel.CRITICAL,
            revision_epoch=4,
            issued_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant_id,
            premise_id=premise_id,
            premise_digest=premise.value_digest,
            created_at=NOW,
        )
    )
    store.create_action(
        ActionIntent(
            id=action_id,
            run_id=run_id,
            agent_id=f"agent-{suffix}",
            warrant_id=warrant_id,
            scope=scope,
            action_type=ActionType.PUSH,
            target="origin/main",
            payload_digest=sha256_digest(f"push-{suffix}"),
            premise_vector={premise_id: premise.value_digest},
            risk=RiskLevel.CRITICAL,
            reversibility=Reversibility.CONDITIONAL,
            state=ActionState.PREPARED,
            idempotency_key=f"race-key-{suffix}",
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_effect(
        EffectRecord(
            id=effect_id,
            run_id=run_id,
            action_id=action_id,
            scope=scope,
            target="origin/main",
            effect_type=EffectType.PUSH,
            reversibility=Reversibility.CONDITIONAL,
            state=EffectState.PREPARED,
            created_at=NOW,
            updated_at=NOW,
            idempotency_key=f"effect-key-{suffix}",
            metadata={"expected_remote_ref": "refs/heads/main"},
        )
    )
    for node in (
        GraphNode(
            id=f"node-premise-{suffix}",
            run_id=run_id,
            kind=NodeKind.PREMISE,
            entity_id=premise_id,
            scope=scope,
            created_at=NOW,
        ),
        GraphNode(
            id=f"node-warrant-{suffix}",
            run_id=run_id,
            kind=NodeKind.WARRANT,
            entity_id=warrant_id,
            scope=scope,
            created_at=NOW,
        ),
        GraphNode(
            id=f"node-action-{suffix}",
            run_id=run_id,
            kind=NodeKind.ACTION,
            entity_id=action_id,
            scope=scope,
            created_at=NOW,
        ),
    ):
        store.create_graph_node(node)
    for edge_id, source, target in (
        (
            f"edge-premise-warrant-{suffix}",
            f"node-premise-{suffix}",
            f"node-warrant-{suffix}",
        ),
        (
            f"edge-warrant-action-{suffix}",
            f"node-warrant-{suffix}",
            f"node-action-{suffix}",
        ),
    ):
        store.create_dependency_edge(
            DependencyEdge(
                id=edge_id,
                run_id=run_id,
                source_node_id=source,
                target_node_id=target,
                edge_type=EdgeType.REQUIRES,
                strength=EdgeStrength.HARD,
                scope=scope,
                declared_by="orchestrator",
                confidence=1.0,
                created_at=NOW,
            )
        )
    gateway = EffectGateway(store, clock=clock)
    gateway.authorize(
        action_id,
        effect_id=effect_id,
        current_artifact_hashes={},
        passed_test_ids=(),
        capability_token=f"token-{suffix}",
    )
    return (
        store,
        clock,
        gateway,
        SelectiveRevoker(store, clock=clock),
        run_id,
        premise_id,
        evidence_id,
        effect_id,
    )


@pytest.mark.slow
def test_dispatch_and_invalidation_have_one_linearizable_boundary(tmp_path: Path) -> None:
    for iteration in range(20):
        store, _clock, gateway, revoker, run_id, premise_id, evidence_id, effect_id = (
            _authorized_race_fixture(tmp_path, iteration)
        )
        action_id = f"action-race-{iteration}"
        barrier = Barrier(2)

        with ThreadPoolExecutor(max_workers=2) as executor:
            # Alternate submission order without sleeps or timing assumptions.
            if iteration % 2:
                invalidation_future = executor.submit(
                    _race_invalidate,
                    barrier,
                    revoker,
                    premise_id,
                    evidence_id,
                    f"case-race-{iteration}",
                )
                dispatch_future = executor.submit(
                    _race_dispatch,
                    barrier,
                    gateway,
                    action_id,
                    effect_id,
                    f"token-{iteration}",
                )
            else:
                dispatch_future = executor.submit(
                    _race_dispatch,
                    barrier,
                    gateway,
                    action_id,
                    effect_id,
                    f"token-{iteration}",
                )
                invalidation_future = executor.submit(
                    _race_invalidate,
                    barrier,
                    revoker,
                    premise_id,
                    evidence_id,
                    f"case-race-{iteration}",
                )
            dispatched = dispatch_future.result(timeout=10)
            invalidation_future.result(timeout=10)

        events = store.journal.list_events(run_id)
        invalidated_sequence = next(
            event.sequence
            for event in events
            if event.aggregate_type == "premise"
            and event.aggregate_id == premise_id
            and event.kind == "premise.transitioned"
            and event.payload.get("to") == PremiseState.INVALIDATED.value
        )
        dispatch_sequences = [
            event.sequence
            for event in events
            if event.aggregate_type == "action"
            and event.aggregate_id == action_id
            and event.kind == "action.transitioned"
            and event.payload.get("to") == ActionState.DISPATCHING.value
        ]
        if dispatched:
            assert len(dispatch_sequences) == 1
            assert dispatch_sequences[0] < invalidated_sequence
        else:
            assert dispatch_sequences == []

        assert store.get_action(action_id).state == ActionState.REVOKE_PENDING  # type: ignore[union-attr]
        lease = store.get_lease(store.get_action(action_id).lease_id)  # type: ignore[union-attr]
        assert lease.state in {LeaseState.CONSUMED, LeaseState.REVOKED}  # type: ignore[union-attr]
        assert store.journal.verify_chain(run_id) == store.journal.head(run_id).event_hash  # type: ignore[union-attr]


def test_dispatch_is_denied_when_invalidation_commits_first(tmp_path: Path) -> None:
    store, _clock, gateway, revoker, _run_id, premise_id, evidence_id, effect_id = (
        _authorized_race_fixture(tmp_path, 100)
    )
    revoker.invalidate_and_fence(
        premise_id,
        invalidating_evidence_id=evidence_id,
        reason="new signed schema invalidates dispatch authority",
        case_id="case-race-100",
    )

    with pytest.raises(AuthorizationError, match="active authorization"):
        gateway.dispatch(
            "action-race-100",
            effect_id=effect_id,
            capability_token="token-100",
            current_artifact_hashes={},
            passed_test_ids=(),
        )
    assert store.get_action("action-race-100").state == ActionState.REVOKE_PENDING  # type: ignore[union-attr]
