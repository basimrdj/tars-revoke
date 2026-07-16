from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any, TypeVar, cast

from tars_revoke.errors import TransitionError

from .enums import (
    ActionState,
    AgentState,
    EffectState,
    ExperimentState,
    LeaseState,
    PremiseState,
    ReceiptState,
    RevocationCaseState,
    RunState,
    SessionState,
    TestState,
    WarrantState,
)

StateT = TypeVar("StateT", bound=Enum)
TransitionTable = Mapping[StateT, frozenset[StateT]]


RUN_TRANSITIONS: TransitionTable[RunState] = {
    RunState.DECLARED: frozenset({RunState.RUNNING, RunState.CANCELLED}),
    RunState.RUNNING: frozenset(
        {RunState.PAUSED, RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
    ),
    RunState.PAUSED: frozenset({RunState.RUNNING, RunState.FAILED, RunState.CANCELLED}),
    RunState.COMPLETED: frozenset(),
    RunState.FAILED: frozenset(),
    RunState.CANCELLED: frozenset(),
}

AGENT_TRANSITIONS: TransitionTable[AgentState] = {
    AgentState.DECLARED: frozenset({AgentState.RUNNING, AgentState.CANCELLED}),
    AgentState.RUNNING: frozenset(
        {AgentState.PAUSED, AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED}
    ),
    AgentState.PAUSED: frozenset({AgentState.RUNNING, AgentState.FAILED, AgentState.CANCELLED}),
    AgentState.COMPLETED: frozenset(),
    AgentState.FAILED: frozenset(),
    AgentState.CANCELLED: frozenset(),
}

SESSION_TRANSITIONS: TransitionTable[SessionState] = {
    SessionState.DECLARED: frozenset({SessionState.RUNNING, SessionState.CANCELLED}),
    SessionState.RUNNING: frozenset(
        {SessionState.PAUSED, SessionState.COMPLETED, SessionState.FAILED, SessionState.CANCELLED}
    ),
    SessionState.PAUSED: frozenset(
        {SessionState.RUNNING, SessionState.FAILED, SessionState.CANCELLED}
    ),
    SessionState.COMPLETED: frozenset(),
    SessionState.FAILED: frozenset(),
    SessionState.CANCELLED: frozenset(),
}

PREMISE_TRANSITIONS: TransitionTable[PremiseState] = {
    PremiseState.PROPOSED: frozenset({PremiseState.ACTIVE}),
    PremiseState.ACTIVE: frozenset(
        {PremiseState.DISPUTED, PremiseState.INVALIDATED, PremiseState.SUPERSEDED}
    ),
    PremiseState.DISPUTED: frozenset({PremiseState.ACTIVE, PremiseState.INVALIDATED}),
    PremiseState.INVALIDATED: frozenset(),
    PremiseState.SUPERSEDED: frozenset(),
}

WARRANT_TRANSITIONS: TransitionTable[WarrantState] = {
    WarrantState.DECLARED: frozenset(
        {WarrantState.PREPARED, WarrantState.REVOKE_PENDING, WarrantState.EXPIRED}
    ),
    WarrantState.PREPARED: frozenset(
        {WarrantState.AUTHORIZED, WarrantState.REVOKE_PENDING, WarrantState.EXPIRED}
    ),
    WarrantState.AUTHORIZED: frozenset({WarrantState.REVOKE_PENDING, WarrantState.EXPIRED}),
    WarrantState.REVOKE_PENDING: frozenset({WarrantState.REVOKED}),
    WarrantState.REVOKED: frozenset(),
    WarrantState.EXPIRED: frozenset(),
}

ACTION_TRANSITIONS: TransitionTable[ActionState] = {
    ActionState.DECLARED: frozenset(
        {ActionState.PREPARED, ActionState.REVOKE_PENDING, ActionState.FAILED}
    ),
    ActionState.PREPARED: frozenset(
        {ActionState.AUTHORIZED, ActionState.REVOKE_PENDING, ActionState.FAILED}
    ),
    ActionState.AUTHORIZED: frozenset(
        {ActionState.DISPATCHING, ActionState.REVOKE_PENDING, ActionState.FAILED}
    ),
    ActionState.DISPATCHING: frozenset(
        {ActionState.EXECUTED, ActionState.REVOKE_PENDING, ActionState.FAILED}
    ),
    ActionState.EXECUTED: frozenset({ActionState.REVOKE_PENDING}),
    ActionState.REVOKE_PENDING: frozenset({ActionState.REVOKED}),
    ActionState.REVOKED: frozenset(
        {
            ActionState.ROLLED_BACK,
            ActionState.QUARANTINED,
            ActionState.CONTAINMENT_REQUIRED,
        }
    ),
    ActionState.ROLLED_BACK: frozenset(),
    ActionState.QUARANTINED: frozenset(),
    ActionState.CONTAINMENT_REQUIRED: frozenset(),
    ActionState.FAILED: frozenset(),
}

EFFECT_TRANSITIONS: TransitionTable[EffectState] = {
    EffectState.DECLARED: frozenset(
        {EffectState.PREPARED, EffectState.REVOKE_PENDING, EffectState.FAILED}
    ),
    EffectState.PREPARED: frozenset(
        {EffectState.AUTHORIZED, EffectState.REVOKE_PENDING, EffectState.FAILED}
    ),
    EffectState.AUTHORIZED: frozenset(
        {EffectState.DISPATCHING, EffectState.REVOKE_PENDING, EffectState.FAILED}
    ),
    EffectState.DISPATCHING: frozenset(
        {EffectState.EXECUTED, EffectState.REVOKE_PENDING, EffectState.FAILED}
    ),
    EffectState.EXECUTED: frozenset({EffectState.REVOKE_PENDING}),
    EffectState.REVOKE_PENDING: frozenset({EffectState.REVOKED}),
    EffectState.REVOKED: frozenset(
        {
            EffectState.ROLLED_BACK,
            EffectState.QUARANTINED,
            EffectState.CONTAINMENT_REQUIRED,
        }
    ),
    EffectState.ROLLED_BACK: frozenset(),
    EffectState.QUARANTINED: frozenset(),
    EffectState.CONTAINMENT_REQUIRED: frozenset(),
    EffectState.FAILED: frozenset(),
}

LEASE_TRANSITIONS: TransitionTable[LeaseState] = {
    LeaseState.ACTIVE: frozenset({LeaseState.CONSUMED, LeaseState.REVOKED, LeaseState.EXPIRED}),
    LeaseState.CONSUMED: frozenset(),
    LeaseState.REVOKED: frozenset(),
    LeaseState.EXPIRED: frozenset(),
}

REVOCATION_CASE_TRANSITIONS: TransitionTable[RevocationCaseState] = {
    RevocationCaseState.OPEN: frozenset(
        {RevocationCaseState.FROZEN, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.FROZEN: frozenset(
        {RevocationCaseState.INVENTORIED, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.INVENTORIED: frozenset(
        {RevocationCaseState.COMPENSATING, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.COMPENSATING: frozenset(
        {RevocationCaseState.EXPERIMENTING, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.EXPERIMENTING: frozenset(
        {RevocationCaseState.REPAIRING, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.REPAIRING: frozenset(
        {RevocationCaseState.VERIFYING, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.VERIFYING: frozenset(
        {RevocationCaseState.RESUMED, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.RESUMED: frozenset(
        {RevocationCaseState.ATTESTED, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.ATTESTED: frozenset(
        {RevocationCaseState.CLOSED, RevocationCaseState.ESCALATED}
    ),
    RevocationCaseState.CLOSED: frozenset(),
    RevocationCaseState.ESCALATED: frozenset(
        {RevocationCaseState.ATTESTED, RevocationCaseState.CLOSED}
    ),
}

EXPERIMENT_TRANSITIONS: TransitionTable[ExperimentState] = {
    ExperimentState.PROPOSED: frozenset({ExperimentState.ACCEPTED, ExperimentState.REJECTED}),
    ExperimentState.ACCEPTED: frozenset({ExperimentState.SELECTED}),
    ExperimentState.REJECTED: frozenset(),
    ExperimentState.SELECTED: frozenset({ExperimentState.RUNNING}),
    ExperimentState.RUNNING: frozenset({ExperimentState.PASSED, ExperimentState.FAILED}),
    ExperimentState.PASSED: frozenset(),
    ExperimentState.FAILED: frozenset(),
}

TEST_TRANSITIONS: TransitionTable[TestState] = {
    TestState.PENDING: frozenset({TestState.RUNNING, TestState.CANCELLED}),
    TestState.RUNNING: frozenset(
        {TestState.PASSED, TestState.FAILED, TestState.ERROR, TestState.CANCELLED}
    ),
    TestState.PASSED: frozenset(),
    TestState.FAILED: frozenset(),
    TestState.ERROR: frozenset(),
    TestState.CANCELLED: frozenset(),
}

RECEIPT_TRANSITIONS: TransitionTable[ReceiptState] = {
    ReceiptState.DRAFT: frozenset({ReceiptState.FINAL, ReceiptState.INVALID}),
    ReceiptState.FINAL: frozenset({ReceiptState.VERIFIED, ReceiptState.INVALID}),
    ReceiptState.VERIFIED: frozenset(),
    ReceiptState.INVALID: frozenset(),
}


TRANSITION_TABLES: dict[type[Enum], TransitionTable[Any]] = {
    RunState: RUN_TRANSITIONS,
    AgentState: AGENT_TRANSITIONS,
    SessionState: SESSION_TRANSITIONS,
    PremiseState: PREMISE_TRANSITIONS,
    WarrantState: WARRANT_TRANSITIONS,
    ActionState: ACTION_TRANSITIONS,
    EffectState: EFFECT_TRANSITIONS,
    LeaseState: LEASE_TRANSITIONS,
    RevocationCaseState: REVOCATION_CASE_TRANSITIONS,
    ExperimentState: EXPERIMENT_TRANSITIONS,
    TestState: TEST_TRANSITIONS,
    ReceiptState: RECEIPT_TRANSITIONS,
}


def transition_table_for(state: StateT) -> TransitionTable[StateT]:
    table = TRANSITION_TABLES.get(type(state))
    if table is None:
        raise TransitionError(f"no transition table registered for {type(state).__name__}")
    return cast(TransitionTable[StateT], table)


def can_transition(current: StateT, target: StateT, *, allow_same: bool = False) -> bool:
    if type(current) is not type(target):
        return False
    if current == target:
        return allow_same
    return target in transition_table_for(current).get(current, frozenset())


def ensure_transition(current: StateT, target: StateT, *, allow_same: bool = False) -> None:
    if can_transition(current, target, allow_same=allow_same):
        return
    raise TransitionError(
        f"illegal {type(current).__name__} transition: {current.value} -> {target.value}"
    )


def terminal_states(table: TransitionTable[StateT]) -> frozenset[StateT]:
    return frozenset(state for state, targets in table.items() if not targets)
