from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    NodeKind,
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
from tars_revoke.persistence.store import Store
from tars_revoke.services.coordinator import RevocationCoordinator
from tars_revoke.services.revocation import SelectiveRevoker

NOW = datetime(2026, 7, 14, 13, 0, tzinfo=timezone.utc)
SCOPE = "repository"


def _digest(label: str) -> str:
    return sha256_digest(label)


def _create_agent(store: Store, tmp_path: Path, run_id: str, agent_id: str) -> None:
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=run_id,
            name=agent_id,
            role="builder",
            worktree_path=str(tmp_path / agent_id),
            state=AgentState.RUNNING,
            created_at=NOW,
            updated_at=NOW,
        )
    )


def _create_warrant_action(
    store: Store,
    *,
    run_id: str,
    agent_id: str,
    premise: Premise,
    prefix: str,
) -> tuple[Warrant, ActionIntent]:
    warrant = Warrant(
        id=f"warrant-{prefix}",
        run_id=run_id,
        agent_id=agent_id,
        scope=premise.scope,
        authorized_targets=(f"worktree-{prefix}",),
        state=WarrantState.AUTHORIZED,
        risk=RiskLevel.HIGH,
        revision_epoch=2,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    store.create_warrant(warrant)
    if prefix == "a":
        store.link_warrant_premise(
            WarrantPremise(
                warrant_id=warrant.id,
                premise_id=premise.id,
                premise_digest=premise.value_digest,
                created_at=NOW,
            )
        )
        premise_vector = {premise.id: premise.value_digest}
    else:
        premise_vector = {}
    action = ActionIntent(
        id=f"action-{prefix}",
        run_id=run_id,
        agent_id=agent_id,
        warrant_id=warrant.id,
        scope=premise.scope,
        action_type=ActionType.FILE_EDIT,
        target=f"worktree-{prefix}",
        payload_digest=_digest(f"payload-{prefix}"),
        premise_vector=premise_vector,
        risk=RiskLevel.HIGH,
        reversibility=Reversibility.REVERSIBLE,
        state=ActionState.EXECUTED,
        idempotency_key=f"action-key-{prefix}",
        created_at=NOW,
        updated_at=NOW,
        completed_at=NOW,
    )
    store.create_action(action)
    return warrant, action


def _effect(
    *,
    effect_id: str,
    run_id: str,
    action_id: str,
    target: str,
    effect_type: EffectType = EffectType.FILE_EDIT,
    state: EffectState = EffectState.EXECUTED,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
) -> EffectRecord:
    return EffectRecord(
        id=effect_id,
        run_id=run_id,
        action_id=action_id,
        scope=SCOPE,
        target=target,
        effect_type=effect_type,
        before_hash=_digest(f"before-{effect_id}"),
        after_hash=_digest(f"after-{effect_id}"),
        reversibility=reversibility,
        compensation_handler=(
            "git.restore_path" if reversibility == Reversibility.REVERSIBLE else None
        ),
        state=state,
        created_at=NOW,
        updated_at=NOW,
        dispatched_at=NOW if state == EffectState.EXECUTED else None,
        idempotency_key=f"effect-key-{effect_id}",
    )


def _node(store: Store, run_id: str, node_id: str, kind: NodeKind, entity_id: str) -> None:
    store.create_graph_node(
        GraphNode(
            id=node_id,
            run_id=run_id,
            kind=kind,
            entity_id=entity_id,
            scope=SCOPE,
            created_at=NOW,
        )
    )


def _edge(store: Store, run_id: str, edge_id: str, source: str, target: str) -> None:
    store.create_dependency_edge(
        DependencyEdge(
            id=edge_id,
            run_id=run_id,
            source_node_id=source,
            target_node_id=target,
            edge_type=EdgeType.REQUIRES,
            strength=EdgeStrength.HARD,
            scope=SCOPE,
            declared_by="orchestrator",
            confidence=1.0,
            created_at=NOW,
        )
    )


def test_invalidation_revokes_exactly_the_hard_dependent_effects(tmp_path: Path) -> None:
    clock = FakeClock(NOW)
    store = Store(tmp_path / "selective.sqlite3", clock=clock)
    run_id = "run-selective"
    store.create_run(
        Run(
            id=run_id,
            name="selective revoke",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    _create_agent(store, tmp_path, run_id, "agent-a")
    _create_agent(store, tmp_path, run_id, "agent-b")
    store.create_evidence_source(
        EvidenceSource(
            id="schema-registry",
            run_id=run_id,
            name="schema registry",
            uri="https://registry.test/schemas/orders",
            issuer="registry.test",
            pinned_identity="registry-prod",
            created_at=NOW,
        )
    )
    evidence = EvidenceRecord(
        id="evidence-v2",
        run_id=run_id,
        source_id="schema-registry",
        source_uri="https://registry.test/schemas/orders/2",
        source_version=2,
        observed_at=NOW,
        valid_at=NOW,
        digest=_digest("signed-evidence-v2"),
        signature_status=SignatureStatus.VALID,
        verification_status=VerificationStatus.VERIFIED,
    )
    store.create_evidence_record(evidence)
    premise = Premise(
        id="premise-schema-v1",
        run_id=run_id,
        scope=SCOPE,
        subject="orders-schema",
        relation="version",
        value=1,
        semantics=ValueSemantics.SINGLE,
        state=PremiseState.ACTIVE,
        valid_at=NOW - timedelta(minutes=1),
        created_at=NOW - timedelta(minutes=1),
    )
    store.create_premise(premise)

    warrant_a, action_a = _create_warrant_action(
        store,
        run_id=run_id,
        agent_id="agent-a",
        premise=premise,
        prefix="a",
    )
    warrant_b, action_b = _create_warrant_action(
        store,
        run_id=run_id,
        agent_id="agent-b",
        premise=premise,
        prefix="b",
    )
    affected = (
        _effect(
            effect_id="effect-schema-file",
            run_id=run_id,
            action_id=action_a.id,
            target="schema.json",
        ),
        _effect(
            effect_id="effect-client-file",
            run_id=run_id,
            action_id=action_a.id,
            target="client.py",
        ),
        _effect(
            effect_id="effect-push-intent",
            run_id=run_id,
            action_id=action_a.id,
            target="origin/main",
            effect_type=EffectType.PUSH,
            state=EffectState.PREPARED,
            reversibility=Reversibility.CONDITIONAL,
        ),
    )
    unrelated = _effect(
        effect_id="effect-agent-b",
        run_id=run_id,
        action_id=action_b.id,
        target="README.md",
    )
    for effect in (*affected, unrelated):
        store.create_effect(effect)

    _node(store, run_id, "node-premise", NodeKind.PREMISE, premise.id)
    _node(store, run_id, "node-warrant-a", NodeKind.WARRANT, warrant_a.id)
    _node(store, run_id, "node-action-a", NodeKind.ACTION, action_a.id)
    for effect in affected:
        _node(store, run_id, f"node-{effect.id}", NodeKind.EFFECT, effect.id)
    _node(store, run_id, "node-warrant-b", NodeKind.WARRANT, warrant_b.id)
    _node(store, run_id, "node-action-b", NodeKind.ACTION, action_b.id)
    _node(store, run_id, "node-effect-agent-b", NodeKind.EFFECT, unrelated.id)

    _edge(store, run_id, "edge-premise-warrant", "node-premise", "node-warrant-a")
    _edge(store, run_id, "edge-warrant-action", "node-warrant-a", "node-action-a")
    for index, effect in enumerate(affected):
        _edge(
            store,
            run_id,
            f"edge-action-effect-{index}",
            "node-action-a",
            f"node-{effect.id}",
        )
    _edge(store, run_id, "edge-b-warrant-action", "node-warrant-b", "node-action-b")
    _edge(store, run_id, "edge-b-action-effect", "node-action-b", "node-effect-agent-b")

    result = SelectiveRevoker(store, clock=clock).invalidate_and_fence(
        premise.id,
        invalidating_evidence_id=evidence.id,
        reason="signed schema version 2 invalidates version 1",
        case_id="case-selective",
    )

    assert result.case.state == RevocationCaseState.FROZEN
    assert result.premise.state == PremiseState.INVALIDATED
    assert result.affected_effect_ids == tuple(sorted(effect.id for effect in affected))
    assert len(result.members) == 5  # warrant + action + exactly three effects
    assert not result.contains_entity(unrelated.id)
    assert store.get_warrant(warrant_a.id).state == WarrantState.REVOKE_PENDING  # type: ignore[union-attr]
    assert store.get_warrant(warrant_a.id).revision_epoch == 3  # type: ignore[union-attr]
    assert store.get_action(action_a.id).state == ActionState.REVOKE_PENDING  # type: ignore[union-attr]
    for effect in affected:
        assert store.get_effect(effect.id).state == EffectState.REVOKE_PENDING  # type: ignore[union-attr]

    assert store.get_warrant(warrant_b.id).state == WarrantState.AUTHORIZED  # type: ignore[union-attr]
    assert store.get_action(action_b.id).state == ActionState.EXECUTED  # type: ignore[union-attr]
    assert store.get_effect(unrelated.id).state == EffectState.EXECUTED  # type: ignore[union-attr]
    assert store.journal.verify_chain(run_id) == store.journal.head(run_id).event_hash  # type: ignore[union-attr]

    coordinator = RevocationCoordinator(store, clock=clock)
    recovery = coordinator.recover(run_id)
    assert recovery.incomplete_case_ids == ("case-selective",)
    assert recovery.dispatching_action_ids == ()
    assert recovery.compensation_effect_ids == tuple(sorted(effect.id for effect in affected))

    class InventoryWorker:
        def run_stage(self, *, case, members, target_state):  # type: ignore[no-untyped-def]
            assert case.id == "case-selective"
            assert len(members) == 5
            assert target_state == RevocationCaseState.INVENTORIED
            return {"effect_count": 3}

    advance = coordinator.run_next("case-selective", worker=InventoryWorker())
    assert advance.before.state == RevocationCaseState.FROZEN
    assert advance.after.state == RevocationCaseState.INVENTORIED
    assert advance.outcome == {"effect_count": 3}
