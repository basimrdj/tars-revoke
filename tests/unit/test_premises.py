from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    LeaseState,
    NodeKind,
    PremiseState,
    Reversibility,
    RevocationCaseState,
    RiskLevel,
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
    ExecutionLease,
    GraphNode,
    Premise,
    RevocationCase,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import AuthorizationError, IntegrityError, ValidationError
from tars_revoke.persistence import Store


def _run(now: datetime) -> Run:
    return Run(
        id="run-1",
        name="demo",
        root_path="/tmp/demo",
        created_at=now,
        updated_at=now,
    )


def _agent(now: datetime) -> Agent:
    return Agent(
        id="agent-a",
        run_id="run-1",
        name="agent-a",
        role="builder",
        worktree_path="/tmp/demo/a",
        created_at=now,
        updated_at=now,
    )


def _premise(
    now: datetime,
    *,
    premise_id: str = "premise-1",
    value: str = "uuid",
    semantics: ValueSemantics = ValueSemantics.SINGLE,
    valid_at: datetime | None = None,
) -> Premise:
    return Premise(
        id=premise_id,
        run_id="run-1",
        scope="repo:billing",
        subject="Customer.id",
        relation="serialization",
        value=value,
        semantics=semantics,
        state=PremiseState.ACTIVE,
        valid_at=valid_at or now,
        created_at=now,
    )


def _warrant(
    now: datetime,
    *,
    warrant_id: str = "warrant-1",
    state: WarrantState = WarrantState.AUTHORIZED,
) -> Warrant:
    return Warrant(
        id=warrant_id,
        run_id="run-1",
        agent_id="agent-a",
        scope="repo:billing",
        authorized_targets=("origin/main",),
        state=state,
        risk=RiskLevel.HIGH,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )


def _action(
    now: datetime,
    warrant: Warrant,
    premise: Premise,
    *,
    action_id: str = "action-1",
    state: ActionState = ActionState.PREPARED,
    lease_id: str | None = None,
) -> ActionIntent:
    return ActionIntent(
        id=action_id,
        run_id="run-1",
        agent_id="agent-a",
        warrant_id=warrant.id,
        scope=premise.scope,
        action_type=ActionType.PUSH,
        target="origin/main",
        payload_digest="1" * 64,
        premise_vector={premise.id: premise.value_digest},
        risk=RiskLevel.HIGH,
        reversibility=Reversibility.IRREVERSIBLE,
        state=state,
        lease_id=lease_id,
        idempotency_key=f"idem-{action_id}",
        created_at=now,
        updated_at=now,
    )


def _seed_identity(store: Store, now: datetime) -> tuple[Run, Agent]:
    run = store.create_run(_run(now))
    agent = store.create_agent(_agent(now))
    return run, agent


def _seed_evidence(store: Store, now: datetime) -> tuple[EvidenceRecord, EvidenceRecord]:
    store.create_evidence_source(
        EvidenceSource(
            id="source-1",
            run_id="run-1",
            name="schema registry",
            uri="schema://billing/customer",
            issuer="registry",
            pinned_identity="registry-key-1",
            created_at=now,
        )
    )
    first = store.create_evidence_record(
        EvidenceRecord(
            id="evidence-v1",
            run_id="run-1",
            source_id="source-1",
            source_uri="schema://billing/customer",
            source_version=1,
            observed_at=now,
            valid_at=now,
            digest="a" * 64,
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
        )
    )
    invalidator = store.create_evidence_record(
        EvidenceRecord(
            id="evidence-v2",
            run_id="run-1",
            source_id="source-1",
            source_uri="schema://billing/customer",
            source_version=2,
            observed_at=now + timedelta(seconds=1),
            valid_at=now + timedelta(seconds=1),
            digest="b" * 64,
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
        )
    )
    return first, invalidator


def test_single_and_temporal_revisions_are_replaced_atomically(store: Store, now: datetime) -> None:
    _seed_identity(store, now)
    original = store.create_premise(_premise(now))
    changed_at = now + timedelta(hours=1)
    replacement = store.replace_active_premise(
        _premise(now, premise_id="premise-2", value="opaque", valid_at=changed_at)
    )

    old = store.get_premise(original.id)
    assert old is not None
    assert old.state == PremiseState.SUPERSEDED
    assert old.invalid_at == changed_at
    assert replacement.replaces_premise_id == original.id
    assert [
        item.id
        for item in store.premises_at(
            run_id="run-1",
            scope="repo:billing",
            subject="Customer.id",
            relation="serialization",
            at=now + timedelta(minutes=30),
        )
    ] == [original.id]
    assert [
        item.id
        for item in store.premises_at(
            run_id="run-1",
            scope="repo:billing",
            subject="Customer.id",
            relation="serialization",
            at=changed_at,
        )
    ] == [replacement.id]


def test_set_semantics_allow_distinct_values_but_reject_duplicate_active_value(
    store: Store, now: datetime
) -> None:
    _seed_identity(store, now)
    store.create_premise(
        _premise(now, premise_id="member-a", value="a", semantics=ValueSemantics.SET)
    )
    store.create_premise(
        _premise(now, premise_id="member-b", value="b", semantics=ValueSemantics.SET)
    )
    assert (
        len(
            store.find_active_premises(
                run_id="run-1",
                scope="repo:billing",
                subject="Customer.id",
                relation="serialization",
            )
        )
        == 2
    )
    with pytest.raises(IntegrityError, match="cannot insert premises"):
        store.create_premise(
            _premise(now, premise_id="member-a-copy", value="a", semantics=ValueSemantics.SET)
        )


def test_lease_authorization_dispatch_and_effect_completion_are_atomic(
    store: Store, now: datetime
) -> None:
    _seed_identity(store, now)
    premise = store.create_premise(_premise(now))
    warrant = store.create_warrant(_warrant(now))
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=now,
        )
    )
    action = store.create_action(_action(now, warrant, premise))
    effect_intent = store.create_effect(
        EffectRecord(
            id="effect-1",
            run_id="run-1",
            action_id=action.id,
            scope=action.scope,
            target="origin/main",
            effect_type=EffectType.PUSH,
            reversibility=Reversibility.IRREVERSIBLE,
            state=EffectState.PREPARED,
            created_at=now,
            updated_at=now,
            idempotency_key="effect-idem-1",
        )
    )
    token = "one-shot-capability"
    lease = ExecutionLease(
        id="lease-1",
        run_id="run-1",
        action_id=action.id,
        effect_id=effect_intent.id,
        warrant_id=warrant.id,
        epoch=warrant.revision_epoch,
        token_digest=sha256_digest(token),
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        idempotency_key=action.idempotency_key,
    )
    authorized, authorized_effect = store.authorize_action_with_lease(
        action.id,
        effect_intent.id,
        lease,
        expected_warrant_epoch=warrant.revision_epoch,
        at=now,
    )
    assert authorized.state == ActionState.AUTHORIZED
    assert authorized_effect.state == EffectState.AUTHORIZED
    with pytest.raises(AuthorizationError, match="token"):
        store.begin_action_dispatch(
            action.id,
            effect_intent.id,
            "0" * 64,
            expected_warrant_epoch=warrant.revision_epoch,
            at=now,
        )
    assert store.get_lease(lease.id).state == LeaseState.ACTIVE  # type: ignore[union-attr]
    dispatched, dispatching_effect = store.begin_action_dispatch(
        action.id,
        effect_intent.id,
        sha256_digest(token),
        expected_warrant_epoch=warrant.revision_epoch,
        at=now,
    )
    assert dispatched.state == ActionState.DISPATCHING
    assert store.get_lease(lease.id).state == LeaseState.CONSUMED  # type: ignore[union-attr]

    effect = EffectRecord.model_validate(
        dispatching_effect.model_copy(
            update={"after_hash": "commit-abc", "state": EffectState.EXECUTED}
        ).model_dump()
    )
    stored_effect, completed = store.record_effect_and_complete_action(effect, at=now)
    assert stored_effect == effect
    assert completed.state == ActionState.EXECUTED
    assert store.journal.verify_chain("run-1") == store.journal.head("run-1").event_hash  # type: ignore[union-attr]


def test_invalidation_computes_closure_and_fences_only_reachable_entities(
    store: Store, now: datetime
) -> None:
    _seed_identity(store, now)
    _, invalidator = _seed_evidence(store, now)
    premise = store.create_premise(_premise(now))
    warrant = store.create_warrant(_warrant(now))
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=now,
        )
    )
    action = store.create_action(
        _action(
            now,
            warrant,
            premise,
            state=ActionState.AUTHORIZED,
            lease_id="lease-1",
        )
    )
    effect = store.create_effect(
        EffectRecord(
            id="effect-1",
            run_id="run-1",
            action_id=action.id,
            scope=action.scope,
            target="origin/main",
            effect_type=EffectType.PUSH,
            reversibility=Reversibility.IRREVERSIBLE,
            state=EffectState.DECLARED,
            created_at=now,
            updated_at=now,
            idempotency_key="effect-idem-1",
        )
    )
    lease = store.create_lease(
        ExecutionLease(
            id="lease-1",
            run_id="run-1",
            action_id=action.id,
            effect_id=effect.id,
            warrant_id=warrant.id,
            epoch=0,
            token_digest="c" * 64,
            issued_at=now,
            expires_at=now + timedelta(minutes=1),
            idempotency_key=action.idempotency_key,
        )
    )
    unrelated_warrant = store.create_warrant(
        _warrant(now, warrant_id="warrant-unrelated", state=WarrantState.DECLARED)
    )
    unrelated_action = store.create_action(
        _action(
            now,
            unrelated_warrant,
            premise,
            action_id="action-unrelated",
            state=ActionState.PREPARED,
        )
    )

    nodes = {
        "premise": GraphNode(
            id="node-premise",
            run_id="run-1",
            kind=NodeKind.PREMISE,
            entity_id=premise.id,
            scope=premise.scope,
            created_at=now,
        ),
        "warrant": GraphNode(
            id="node-warrant",
            run_id="run-1",
            kind=NodeKind.WARRANT,
            entity_id=warrant.id,
            scope=premise.scope,
            created_at=now,
        ),
        "action": GraphNode(
            id="node-action",
            run_id="run-1",
            kind=NodeKind.ACTION,
            entity_id=action.id,
            scope=premise.scope,
            created_at=now,
        ),
        "effect": GraphNode(
            id="node-effect",
            run_id="run-1",
            kind=NodeKind.EFFECT,
            entity_id=effect.id,
            scope=premise.scope,
            created_at=now,
        ),
        "unrelated": GraphNode(
            id="node-unrelated",
            run_id="run-1",
            kind=NodeKind.ACTION,
            entity_id=unrelated_action.id,
            scope=premise.scope,
            created_at=now,
        ),
    }
    for node in nodes.values():
        store.create_graph_node(node)
    chain = (("premise", "warrant"), ("warrant", "action"), ("action", "effect"))
    for index, (source, target) in enumerate(chain):
        store.create_dependency_edge(
            DependencyEdge(
                id=f"edge-{index}",
                run_id="run-1",
                source_node_id=nodes[source].id,
                target_node_id=nodes[target].id,
                edge_type=EdgeType.REQUIRES,
                strength=EdgeStrength.HARD,
                scope=premise.scope,
                declared_by="agent-a",
                confidence=1.0,
                created_at=now,
            )
        )

    invalidated, case, members = store.invalidate_premise_and_fence(
        premise.id,
        invalidator.id,
        RevocationCase(
            id="case-1",
            run_id="run-1",
            premise_id=premise.id,
            trigger_evidence_id=invalidator.id,
            reason="registry contradicted UUID assumption",
            opened_at=now,
            updated_at=now,
        ),
        at=now + timedelta(seconds=2),
    )

    assert invalidated.state == PremiseState.INVALIDATED
    assert case.state == RevocationCaseState.FROZEN
    assert {member.entity_id for member in members} == {warrant.id, action.id, effect.id}
    assert store.get_warrant(warrant.id).revision_epoch == 1  # type: ignore[union-attr]
    assert store.get_warrant(warrant.id).state == WarrantState.REVOKE_PENDING  # type: ignore[union-attr]
    assert store.get_action(action.id).state == ActionState.REVOKE_PENDING  # type: ignore[union-attr]
    assert store.get_effect(effect.id).state == EffectState.REVOKE_PENDING  # type: ignore[union-attr]
    assert store.get_lease(lease.id).state == LeaseState.REVOKED  # type: ignore[union-attr]
    assert store.get_action(unrelated_action.id).state == ActionState.PREPARED  # type: ignore[union-attr]
    with pytest.raises(AuthorizationError, match="not authorized"):
        store.begin_action_dispatch(
            action.id,
            effect.id,
            lease.token_digest,
            expected_warrant_epoch=0,
            at=now + timedelta(seconds=3),
        )


def test_invalidation_derives_complete_closure_without_manual_graph_wiring(
    store: Store,
    now: datetime,
) -> None:
    _seed_identity(store, now)
    _, invalidator = _seed_evidence(store, now)
    premise = store.create_premise(_premise(now))
    warrant = store.create_warrant(_warrant(now))
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=premise.id,
            premise_digest=premise.value_digest,
            created_at=now,
        )
    )
    action = store.create_action(_action(now, warrant, premise))
    effect = store.create_effect(
        EffectRecord(
            id="effect-derived",
            run_id=action.run_id,
            action_id=action.id,
            scope=action.scope,
            target=action.target,
            effect_type=EffectType.PUSH,
            reversibility=action.reversibility,
            state=EffectState.PREPARED,
            created_at=now,
            updated_at=now,
            idempotency_key="effect-derived-key",
        )
    )
    assert store.list_graph_nodes(action.run_id) == []
    assert store.list_dependency_edges(action.run_id) == []

    _, _, members = store.invalidate_premise_and_fence(
        premise.id,
        invalidator.id,
        RevocationCase(
            id="case-derived",
            run_id=action.run_id,
            premise_id=premise.id,
            trigger_evidence_id=invalidator.id,
            reason="authoritative relation closure",
            opened_at=now,
            updated_at=now,
        ),
        at=now + timedelta(seconds=1),
    )

    assert {member.entity_id for member in members} == {warrant.id, action.id, effect.id}
    assert store.get_action(action.id).state == ActionState.REVOKE_PENDING  # type: ignore[union-attr]
    assert store.get_effect(effect.id).state == EffectState.REVOKE_PENDING  # type: ignore[union-attr]


def test_warrant_rejects_cross_scope_premise_binding_at_link_time(
    store: Store,
    now: datetime,
) -> None:
    _seed_identity(store, now)
    first = store.create_premise(_premise(now))
    second = store.create_premise(
        Premise.model_validate(
            _premise(now, premise_id="premise-other-scope")
            .model_copy(update={"scope": "repo:observability"})
            .model_dump()
        )
    )
    warrant = store.create_warrant(_warrant(now))
    store.link_warrant_premise(
        WarrantPremise(
            warrant_id=warrant.id,
            premise_id=first.id,
            premise_digest=first.value_digest,
            created_at=now,
        )
    )

    with pytest.raises(
        ValidationError, match="warrant and premise must belong to the same causal scope"
    ):
        store.link_warrant_premise(
            WarrantPremise(
                warrant_id=warrant.id,
                premise_id=second.id,
                premise_digest=second.value_digest,
                created_at=now,
            )
        )
    assert [link.premise_id for link in store.list_warrant_premises(warrant.id)] == [first.id]
    store.database.integrity_check()
