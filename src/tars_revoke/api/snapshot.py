from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Literal

from tars_revoke.domain.enums import NodeKind, ReceiptState, RunState
from tars_revoke.domain.models import EventRecord, GraphNode, Receipt, Run
from tars_revoke.persistence.store import Store

from .schemas import (
    AgentSnapshot,
    CausalEdgeSnapshot,
    CausalGraphSnapshot,
    CausalNodeSnapshot,
    EffectSnapshot,
    EventSnapshot,
    ExperimentCandidateSnapshot,
    ExperimentSnapshot,
    FailureSummary,
    ReceiptSummary,
    RunInfo,
    RunSnapshot,
    WarrantSnapshot,
)

_RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _parse_datetime(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def _failure_summary(
    store: Store,
    run: Run,
    receipts: list[Receipt],
) -> FailureSummary | None:
    for receipt in reversed(receipts):
        metadata = receipt.metadata
        if receipt.state != ReceiptState.INVALID or metadata.get("kind") != "failure":
            continue
        status = str(metadata.get("status", run.state.value))
        if status not in {RunState.FAILED.value, RunState.CANCELLED.value}:
            status = RunState.FAILED.value
        occurred_raw = metadata.get("occurred_at", receipt.created_at)
        occurred_at = (
            _parse_datetime(occurred_raw)
            if isinstance(occurred_raw, str)
            else occurred_raw
        )
        return FailureSummary(
            status=status,  # type: ignore[arg-type]
            error_type=str(metadata.get("error_type", "UnknownFailure")),
            message=str(metadata.get("message", "run failed without a recorded reason")),
            stage=str(metadata.get("stage", "UNKNOWN")),
            occurred_at=occurred_at,
            receipt_digest=str(metadata.get("receipt_sha256") or receipt.canonical_digest),
            finalization_errors=tuple(
                str(item) for item in metadata.get("finalization_errors", ())
            ),
        )
    for event in reversed(store.journal.list_events(run.id)):
        if event.kind != "run.failure_recorded":
            continue
        status = str(event.payload.get("status", run.state.value))
        if status not in {RunState.FAILED.value, RunState.CANCELLED.value}:
            status = RunState.FAILED.value
        occurred_raw = event.payload.get("occurred_at", event.created_at)
        occurred_at = (
            _parse_datetime(occurred_raw)
            if isinstance(occurred_raw, str)
            else occurred_raw
        )
        return FailureSummary(
            status=status,  # type: ignore[arg-type]
            error_type=str(event.payload.get("error_type", "UnknownFailure")),
            message=str(
                event.payload.get("message", "run failed without a recorded reason")
            ),
            stage=str(event.payload.get("stage", "UNKNOWN")),
            occurred_at=occurred_at,
        )
    if run.state in {RunState.FAILED, RunState.CANCELLED}:
        return FailureSummary(
            status=run.state.value,  # type: ignore[arg-type]
            error_type="UnknownFailure",
            message="terminal run has no durable failure reason",
            stage="UNKNOWN",
            occurred_at=run.updated_at,
        )
    return None


def _event_summary(event: EventRecord) -> str:
    explicit = event.payload.get("summary")
    if isinstance(explicit, str) and explicit:
        return explicit
    return f"{event.kind.replace('.', ' ')} · {event.aggregate_id}"


def _event_status(event: EventRecord) -> str | None:
    for key in ("state", "status", "target_state", "to"):
        value = event.payload.get(key)
        if isinstance(value, str):
            return value
    return None


def _node_state(store: Store, node: GraphNode) -> tuple[str, str, str | None]:
    """Return a stable label, lifecycle state, and useful detail for a graph node."""

    kind = node.kind
    entity: Any | None = None
    if kind == NodeKind.PREMISE:
        entity = store.get_premise(node.entity_id)
        if entity:
            return entity.subject, entity.state.value, f"{entity.relation}: {entity.value}"
    elif kind == NodeKind.WARRANT:
        entity = store.get_warrant(node.entity_id)
    elif kind == NodeKind.ACTION:
        entity = store.get_action(node.entity_id)
        if entity:
            return entity.target, entity.state.value, entity.action_type.value
    elif kind == NodeKind.EFFECT:
        entity = store.get_effect(node.entity_id)
        if entity:
            return entity.target, entity.state.value, entity.effect_type.value
    elif kind == NodeKind.EXPERIMENT:
        entity = store.get_experiment_candidate(node.entity_id)
    elif kind == NodeKind.TEST:
        entity = store.get_test_run(node.entity_id)
    elif kind == NodeKind.RECEIPT:
        entity = store.get_receipt(node.entity_id)
    elif kind == NodeKind.EVIDENCE:
        entity = store.get_evidence_record(node.entity_id)
        if entity:
            return (
                f"Schema v{entity.source_version}",
                entity.verification_status.value,
                entity.source_uri,
            )
    if entity is not None:
        state = getattr(entity, "state", "ACTIVE")
        return node.entity_id, getattr(state, "value", str(state)), kind.value
    return node.entity_id, "UNKNOWN", kind.value


def _node_layout(nodes: list[GraphNode], edges: list[Any]) -> dict[str, tuple[int, int]]:
    """Small deterministic DAG-ish layout used only for presentation metadata."""

    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    node_ids = {node.id for node in nodes}
    for edge in edges:
        if edge.source_node_id in node_ids and edge.target_node_id in node_ids:
            incoming[edge.target_node_id].add(edge.source_node_id)
            outgoing[edge.source_node_id].add(edge.target_node_id)

    depths = {node.id: 0 for node in nodes}
    frontier = sorted(node_id for node_id in node_ids if not incoming[node_id])
    visited: set[str] = set()
    while frontier:
        current = frontier.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for target in sorted(outgoing[current]):
            depths[target] = max(depths[target], depths[current] + 1)
            if incoming[target].issubset(visited):
                frontier.append(target)

    lanes: dict[int, int] = defaultdict(int)
    layout: dict[str, tuple[int, int]] = {}
    for node in sorted(nodes, key=lambda item: (depths[item.id], item.created_at, item.id)):
        depth = depths[node.id]
        layout[node.id] = (depth, lanes[depth])
        lanes[depth] += 1
    return layout


def build_snapshot(
    store: Store,
    run_id: str,
    *,
    scenario: str = "external-schema-v2",
) -> RunSnapshot:
    run = store.get_run(run_id)
    if run is None:
        raise KeyError(run_id)
    provider = run.metadata.get("repair_provider")
    execution_mode: Literal["live-codex", "scripted", "unknown"] = "unknown"
    if provider == "live-codex":
        execution_mode = "live-codex"
    elif provider == "scripted":
        execution_mode = "scripted"

    events = store.journal.list_events(run_id)
    head_sequence = events[-1].sequence if events else 0
    actions = store.list_actions(run_id)
    actions_by_id = {item.id: item for item in actions}
    warrants = store.list_warrants(run_id)
    warrant_by_agent = {item.agent_id: item for item in warrants if item.agent_id}
    effects = store.list_effects(run_id)
    sessions = store.list_agent_sessions(run_id)
    session_by_agent = {item.agent_id: item for item in sessions}

    cases = store.list_revocation_cases(run_id)
    current_case = cases[-1] if cases else None
    affected_nodes: set[str] = set()
    if current_case is not None:
        affected_nodes = {item.node_id for item in store.list_revocation_members(current_case.id)}

    graph_nodes = store.list_graph_nodes(run_id)
    graph_edges = store.list_dependency_edges(run_id)
    layout = _node_layout(graph_nodes, graph_edges)

    agent_snapshots: list[AgentSnapshot] = []
    for agent in store.list_agents(run_id):
        session = session_by_agent.get(agent.id)
        warrant = warrant_by_agent.get(agent.id)
        agent_actions = [item for item in actions if item.agent_id == agent.id]
        pushed_at = next(
            (
                item.completed_at
                for item in reversed(agent_actions)
                if item.action_type.value == "PUSH" and item.completed_at is not None
            ),
            None,
        )
        agent_snapshots.append(
            AgentSnapshot(
                id=agent.id,
                name=agent.name,
                task=agent.role,
                status=agent.state.value,
                thread_id=session.external_session_id if session else None,
                worktree=agent.worktree_path,
                warrant_id=warrant.id if warrant else None,
                lease_id=next(
                    (item.lease_id for item in reversed(agent_actions) if item.lease_id), None
                ),
                last_heartbeat_at=session.updated_at if session else agent.updated_at,
                pushed_at=pushed_at,
            )
        )

    warrant_snapshots: list[WarrantSnapshot] = []
    for warrant in warrants:
        bindings = store.list_warrant_premises(warrant.id)
        evidence_ids: set[str] = set()
        for binding in bindings:
            evidence_ids.update(
                item.evidence_id for item in store.list_premise_evidence(binding.premise_id)
            )
        warrant_snapshots.append(
            WarrantSnapshot(
                id=warrant.id,
                agent_id=warrant.agent_id or "unbound",
                status=warrant.state.value,
                issued_at=warrant.issued_at,
                expires_at=warrant.expires_at,
                lease_epoch=warrant.revision_epoch,
                premise_ids=tuple(item.premise_id for item in bindings),
                evidence_ids=tuple(sorted(evidence_ids)),
                artifact_hashes=warrant.artifact_hashes,
                required_tests=warrant.required_tests,
                revoked_reason=warrant.revoke_cause,
            )
        )

    effect_snapshots: list[EffectSnapshot] = []
    for effect in effects:
        action = actions_by_id.get(effect.action_id)
        effect_snapshots.append(
            EffectSnapshot(
                id=effect.id,
                agent_id=action.agent_id if action else "unknown",
                action_id=effect.action_id,
                label=str(effect.metadata.get("label") or effect.target),
                effect_type=effect.effect_type.value,
                target=effect.target,
                state=effect.state.value,
                reversibility=effect.reversibility.value,
                before_hash=effect.before_hash,
                after_hash=effect.after_hash,
                compensated_at=effect.compensated_at,
            )
        )

    candidate_snapshots: list[ExperimentCandidateSnapshot] = []
    experiment_snapshot: ExperimentSnapshot | None = None
    if current_case is not None:
        candidates = store.list_experiment_candidates(current_case.id)
        for candidate in candidates:
            candidate_snapshots.append(
                ExperimentCandidateSnapshot(
                    id=candidate.id,
                    label=str(candidate.metadata.get("label") or candidate.id),
                    command=candidate.argv,
                    risk_rank=_RISK_RANK[candidate.risk.value],
                    touched_files=len(candidate.touched_files),
                    estimated_runtime_ms=candidate.estimated_runtime_ms,
                    command_count=candidate.command_count,
                    validation_status=candidate.state.value,
                    selected=candidate.state.value == "SELECTED",
                    predictions=candidate.predictions,
                )
            )
        experiment_runs = store.list_experiment_runs(current_case.id)
        latest_experiment = experiment_runs[-1] if experiment_runs else None
        if candidate_snapshots or latest_experiment:
            experiment_snapshot = ExperimentSnapshot(
                status=(
                    latest_experiment.state.value if latest_experiment else current_case.state.value
                ),
                candidates=tuple(candidate_snapshots),
                chosen_id=latest_experiment.candidate_id
                if latest_experiment
                else next((item.id for item in candidate_snapshots if item.selected), None),
                exit_code=latest_experiment.exit_code if latest_experiment else None,
                result_digest=(
                    latest_experiment.stdout_artifact_digest if latest_experiment else None
                ),
            )

    receipts = store.list_receipts(run_id)
    failure_summary = _failure_summary(store, run, receipts)
    failure_receipts = [
        item
        for item in receipts
        if item.state == ReceiptState.INVALID and item.metadata.get("kind") == "failure"
    ]
    if run.state in {RunState.FAILED, RunState.CANCELLED}:
        receipt = failure_receipts[-1] if failure_receipts else None
    else:
        receipt = receipts[-1] if receipts else None
    receipt_summary = None
    if receipt is not None:
        receipt_summary = ReceiptSummary(
            id=receipt.id,
            status=receipt.state.value,
            digest=receipt.canonical_digest,
            event_count=head_sequence,
            proof_scope=tuple(
                str(requirement)
                for requirement in receipt.metadata.get("proof_scope", ())
            ),
            verified_at=receipt.verified_at,
            path=str(receipt.metadata.get("path")) if receipt.metadata.get("path") else None,
        )

    return RunSnapshot(
        run=RunInfo(
            id=run.id,
            scenario=str(run.metadata.get("scenario") or scenario),
            execution_mode=execution_mode,
            status=run.state.value,
            revocation_status=current_case.state.value if current_case else None,
            started_at=run.created_at,
            closed_at=(
                failure_summary.occurred_at
                if failure_summary is not None
                else (current_case.closed_at if current_case else None)
            ),
            sequence=head_sequence,
        ),
        agents=tuple(agent_snapshots),
        graph=CausalGraphSnapshot(
            nodes=tuple(_snapshot_node(store, node, layout[node.id]) for node in graph_nodes),
            edges=tuple(
                CausalEdgeSnapshot(
                    id=edge.id,
                    source=edge.source_node_id,
                    target=edge.target_node_id,
                    kind=edge.edge_type.value.lower(),
                    strength=edge.strength.value.lower(),
                    affected=edge.source_node_id in affected_nodes
                    or edge.target_node_id in affected_nodes,
                )
                for edge in graph_edges
            ),
        ),
        warrants=tuple(warrant_snapshots),
        effects=tuple(effect_snapshots),
        experiment=experiment_snapshot,
        events=tuple(
            EventSnapshot(
                sequence=event.sequence,
                type=event.kind,
                occurred_at=event.created_at,
                summary=_event_summary(event),
                status=_event_status(event),
            )
            for event in events
        ),
        receipt=receipt_summary,
        failure=failure_summary,
        selected_warrant_id=next(
            (item.id for item in warrant_snapshots if item.status == "REVOKED"),
            warrant_snapshots[0].id if warrant_snapshots else None,
        ),
    )


def _snapshot_node(
    store: Store,
    node: GraphNode,
    layout: tuple[int, int],
) -> CausalNodeSnapshot:
    label, state, detail = _node_state(store, node)
    return CausalNodeSnapshot(
        id=node.id,
        kind=node.kind.value.lower(),
        label=label,
        detail=detail,
        status=state,
        depth=layout[0],
        lane=layout[1],
    )
