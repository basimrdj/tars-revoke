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
    NodeKind,
    PremiseState,
    Reversibility,
    RiskLevel,
    RunState,
    ValueSemantics,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    EffectRecord,
    GraphNode,
    Premise,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import AuthorizationError, IntegrityError
from tars_revoke.persistence.store import Store
from tars_revoke.services.gateway import EffectGateway

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
ARTIFACT_DIGEST = sha256_digest(b"artifact-v1")


def _prepared_action_store(tmp_path: Path, *, suffix: str = "1") -> tuple[Store, FakeClock]:
    clock = FakeClock(NOW)
    store = Store(tmp_path / f"gateway-{suffix}.sqlite3", clock=clock)
    run_id = f"run-{suffix}"
    agent_id = f"agent-{suffix}"
    premise_id = f"premise-{suffix}"
    warrant_id = f"warrant-{suffix}"
    action_id = f"action-{suffix}"
    store.create_run(
        Run(
            id=run_id,
            name="gateway test",
            state=RunState.RUNNING,
            root_path=str(tmp_path),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_agent(
        Agent(
            id=agent_id,
            run_id=run_id,
            name="agent",
            role="builder",
            worktree_path=str(tmp_path),
            state=AgentState.RUNNING,
            created_at=NOW,
            updated_at=NOW,
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
        valid_at=NOW,
        created_at=NOW,
    )
    store.create_premise(premise)
    store.create_warrant(
        Warrant(
            id=warrant_id,
            run_id=run_id,
            agent_id=agent_id,
            scope=premise.scope,
            authorized_targets=("origin/main",),
            state=WarrantState.AUTHORIZED,
            risk=RiskLevel.HIGH,
            revision_epoch=7,
            artifact_hashes={"schema.json": ARTIFACT_DIGEST},
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
            agent_id=agent_id,
            warrant_id=warrant_id,
            scope=premise.scope,
            action_type=ActionType.PUSH,
            target="origin/main",
            payload_digest=sha256_digest(b"push payload"),
            premise_vector={premise_id: premise.value_digest},
            artifact_vector={"schema.json": ARTIFACT_DIGEST},
            risk=RiskLevel.HIGH,
            reversibility=Reversibility.CONDITIONAL,
            state=ActionState.PREPARED,
            idempotency_key=f"dispatch-{suffix}",
            created_at=NOW,
            updated_at=NOW,
        )
    )
    store.create_effect(
        EffectRecord(
            id=f"effect-{suffix}",
            run_id=run_id,
            action_id=action_id,
            scope=premise.scope,
            target="origin/main",
            effect_type=EffectType.PUSH,
            reversibility=Reversibility.CONDITIONAL,
            state=EffectState.PREPARED,
            created_at=NOW,
            updated_at=NOW,
            idempotency_key=f"effect-{suffix}",
        )
    )
    return store, clock


def test_gateway_issues_one_shot_epoch_bound_lease_and_completes_atomically(
    tmp_path: Path,
) -> None:
    store, clock = _prepared_action_store(tmp_path)
    gateway = EffectGateway(store, clock=clock)

    authorization = gateway.authorize(
        "action-1",
        effect_id="effect-1",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
        lease_ttl=timedelta(minutes=10),
        capability_token="one-shot-secret",
    )
    assert authorization.action.state == ActionState.AUTHORIZED
    assert authorization.effect.state == EffectState.AUTHORIZED
    assert authorization.lease.state == LeaseState.ACTIVE
    assert authorization.lease.effect_id == "effect-1"
    assert authorization.lease.epoch == 7
    assert authorization.lease.expires_at == NOW + timedelta(minutes=5)
    assert authorization.lease.token_digest == sha256_digest("one-shot-secret")
    assert "one-shot-secret" not in repr(authorization.lease)
    assert "one-shot-secret" not in repr(authorization)
    nodes = store.list_graph_nodes("run-1")
    assert {(node.kind, node.entity_id) for node in nodes} >= {
        (NodeKind.PREMISE, "premise-1"),
        (NodeKind.WARRANT, "warrant-1"),
        (NodeKind.ACTION, "action-1"),
        (NodeKind.EFFECT, "effect-1"),
    }

    grant = gateway.dispatch(
        "action-1",
        effect_id="effect-1",
        capability_token="one-shot-secret",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
    )
    assert grant.action.state == ActionState.DISPATCHING
    assert grant.effect.state == EffectState.DISPATCHING
    assert store.get_lease(grant.lease_id).state == LeaseState.CONSUMED  # type: ignore[union-attr]
    with pytest.raises(AuthorizationError, match="active authorization"):
        gateway.dispatch(
            "action-1",
            effect_id="effect-1",
            capability_token="one-shot-secret",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=(),
        )

    effect = EffectRecord.model_validate(
        grant.effect.model_copy(
            update={
                "before_hash": sha256_digest(b"before"),
                "after_hash": sha256_digest(b"after"),
                "state": EffectState.EXECUTED,
            }
        ).model_dump()
    )
    stored_effect, completed = gateway.complete(effect)
    assert stored_effect == effect
    assert completed.state == ActionState.EXECUTED
    assert store.get_action("action-1").state == ActionState.EXECUTED  # type: ignore[union-attr]


def test_gateway_rejects_post_authorization_effect_substitution(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="substitute")
    gateway = EffectGateway(store, clock=clock)
    authorization = gateway.authorize(
        "action-substitute",
        effect_id="effect-substitute",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
        capability_token="effect-bound-secret",
    )
    substituted = store.create_effect(
        EffectRecord(
            id="effect-unreviewed",
            run_id="run-substitute",
            action_id="action-substitute",
            scope="repository",
            target="origin/main",
            effect_type=EffectType.PUSH,
            after_hash=sha256_digest(b"unreviewed-payload"),
            reversibility=Reversibility.CONDITIONAL,
            state=EffectState.AUTHORIZED,
            created_at=NOW,
            updated_at=NOW,
            idempotency_key="effect-unreviewed",
            metadata={"reviewed": False},
        )
    )

    with pytest.raises(AuthorizationError, match="another effect intent"):
        gateway.dispatch(
            "action-substitute",
            effect_id=substituted.id,
            capability_token="effect-bound-secret",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=(),
        )

    assert store.get_lease(authorization.lease.id).state == LeaseState.ACTIVE  # type: ignore[union-attr]
    assert store.get_effect("effect-substitute").state == EffectState.AUTHORIZED  # type: ignore[union-attr]
    grant = gateway.dispatch(
        "action-substitute",
        effect_id="effect-substitute",
        capability_token="effect-bound-secret",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
    )
    assert grant.effect.id == "effect-substitute"


def test_effect_privileged_transitions_require_atomic_intents(tmp_path: Path) -> None:
    store, _clock = _prepared_action_store(tmp_path, suffix="transition")

    with pytest.raises(AuthorizationError, match="atomic Store intents"):
        store.transition_effect("effect-transition", EffectState.AUTHORIZED)


def test_gateway_rejects_wrong_or_expired_capability(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="wrong")
    gateway = EffectGateway(store, clock=clock)
    gateway.authorize(
        "action-wrong",
        effect_id="effect-wrong",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
        lease_ttl=timedelta(seconds=1),
        capability_token="correct",
    )

    with pytest.raises(AuthorizationError, match="token does not match"):
        gateway.dispatch(
            "action-wrong",
            effect_id="effect-wrong",
            capability_token="incorrect",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=(),
        )

    clock.now = NOW + timedelta(seconds=2)
    with pytest.raises(AuthorizationError, match="expired"):
        gateway.dispatch(
            "action-wrong",
            effect_id="effect-wrong",
            capability_token="correct",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=(),
        )


def test_gateway_rechecks_artifact_vector_before_authorization(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="stale")
    gateway = EffectGateway(store, clock=clock)

    with pytest.raises(AuthorizationError, match="artifact_hash_mismatch"):
        gateway.authorize(
            "action-stale",
            effect_id="effect-stale",
            current_artifact_hashes={"schema.json": sha256_digest(b"tampered")},
            passed_test_ids=(),
        )
    assert store.get_action("action-stale").state == ActionState.PREPARED  # type: ignore[union-attr]
    assert store.list_leases("run-stale") == []


def test_gateway_rejects_claimed_test_without_durable_pass_record(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="fake-test")
    gateway = EffectGateway(store, clock=clock)

    with pytest.raises(AuthorizationError, match="claimed passed test does not exist"):
        gateway.authorize(
            "action-fake-test",
            effect_id="effect-fake-test",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=("invented-pass",),
        )


def test_gateway_rechecks_artifact_vector_at_dispatch(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="dispatch-stale")
    gateway = EffectGateway(store, clock=clock)
    gateway.authorize(
        "action-dispatch-stale",
        effect_id="effect-dispatch-stale",
        current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
        passed_test_ids=(),
        capability_token="dispatch-secret",
    )

    with pytest.raises(AuthorizationError, match="artifact_hash_mismatch"):
        gateway.dispatch(
            "action-dispatch-stale",
            effect_id="effect-dispatch-stale",
            capability_token="dispatch-secret",
            current_artifact_hashes={"schema.json": sha256_digest(b"changed-after-auth")},
            passed_test_ids=(),
        )
    assert store.get_action("action-dispatch-stale").state == ActionState.AUTHORIZED  # type: ignore[union-attr]


def test_gateway_fails_closed_on_mismatched_authoritative_graph_scope(tmp_path: Path) -> None:
    store, clock = _prepared_action_store(tmp_path, suffix="wrong-scope")
    store.create_graph_node(
        GraphNode(
            id="forged-premise-node",
            run_id="run-wrong-scope",
            kind=NodeKind.PREMISE,
            entity_id="premise-wrong-scope",
            scope="forged-scope",
            created_at=NOW,
        )
    )

    with pytest.raises(IntegrityError, match="mismatched scope"):
        EffectGateway(store, clock=clock).authorize(
            "action-wrong-scope",
            effect_id="effect-wrong-scope",
            current_artifact_hashes={"schema.json": ARTIFACT_DIGEST},
            passed_test_ids=(),
        )
    assert store.get_action("action-wrong-scope").state == ActionState.PREPARED  # type: ignore[union-attr]
    assert store.get_effect("effect-wrong-scope").state == EffectState.PREPARED  # type: ignore[union-attr]
    assert store.list_leases("run-wrong-scope") == []
