from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.canonical import canonical_json
from tars_revoke.domain.enums import (
    ActionState,
    AgentState,
    DispatchReconciliationOutcome,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    ExperimentState,
    LeaseState,
    NodeKind,
    PremiseState,
    ReceiptState,
    RevocationCaseState,
    RevocationMemberKind,
    RunState,
    SessionState,
    TestState,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    AgentSession,
    ArtifactRef,
    DependencyEdge,
    DispatchReconciliationRecord,
    EffectRecord,
    EvidenceRecord,
    EvidenceSource,
    ExecutionLease,
    ExperimentCandidate,
    ExperimentRun,
    GraphNode,
    Premise,
    PremiseEvidence,
    Receipt,
    RevocationCase,
    RevocationMember,
    Run,
    TestRun,
    Warrant,
    WarrantPremise,
)
from tars_revoke.domain.transitions import ensure_transition
from tars_revoke.errors import (
    AuthorizationError,
    IntegrityError,
    StaleWarrantError,
    ValidationError,
)

from .database import Database
from .event_journal import EventJournal

ModelT = TypeVar("ModelT", bound=BaseModel)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="microseconds") if value is not None else None


def _loads(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _event_payload(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude_none=False)


class Store:
    """Intent-based durable repository used by the service layer.

    Every mutating public method owns a transaction and writes its event/outbox
    entry in that same transaction. The four ``*_atomic`` methods are the
    linearization boundaries for authorization, dispatch, invalidation, and
    effect completion.
    """

    def __init__(
        self,
        database: Database | str | Path,
        *,
        journal: EventJournal | None = None,
        clock: Clock | None = None,
    ):
        self.database = database if isinstance(database, Database) else Database(database)
        self.database.initialize()
        self.clock = clock or SystemClock()
        self.journal = journal or EventJournal(self.database, clock=self.clock)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.database.transaction() as connection:
            yield connection

    @staticmethod
    def _insert(connection: sqlite3.Connection, table: str, values: Mapping[str, Any]) -> None:
        columns = tuple(values)
        placeholders = ",".join("?" for _ in columns)
        sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
        try:
            connection.execute(sql, tuple(values[column] for column in columns))
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(f"cannot insert {table}: {exc}") from exc

    def _create(
        self,
        *,
        table: str,
        values: Mapping[str, Any],
        model: ModelT,
        run_id: str | None,
        event_kind: str,
        aggregate_type: str,
        connection: sqlite3.Connection | None = None,
    ) -> ModelT:
        if connection is None:
            with self.database.transaction() as transaction:
                return self._create(
                    table=table,
                    values=values,
                    model=model,
                    run_id=run_id,
                    event_kind=event_kind,
                    aggregate_type=aggregate_type,
                    connection=transaction,
                )
        self._insert(connection, table, values)
        if run_id is not None:
            aggregate_id = next(
                (
                    str(value)
                    for name in ("id", "digest", "case_id", "premise_id", "warrant_id")
                    if (value := getattr(model, name, None))
                ),
                aggregate_type,
            )
            self.journal.append(
                run_id=run_id,
                kind=event_kind,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                payload=_event_payload(model),
                connection=connection,
            )
        return model

    def _one(
        self,
        sql: str,
        args: Sequence[Any],
        reader: Callable[[sqlite3.Row], ModelT],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> ModelT | None:
        if connection is not None:
            row = connection.execute(sql, args).fetchone()
        else:
            with self.database.connection(readonly=True) as read:
                row = read.execute(sql, args).fetchone()
        return reader(row) if row is not None else None

    def _many(
        self,
        sql: str,
        args: Sequence[Any],
        reader: Callable[[sqlite3.Row], ModelT],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[ModelT]:
        if connection is not None:
            rows = connection.execute(sql, args).fetchall()
        else:
            with self.database.connection(readonly=True) as read:
                rows = read.execute(sql, args).fetchall()
        return [reader(row) for row in rows]

    # Runs and agents -----------------------------------------------------

    def create_run(self, run: Run) -> Run:
        return self._create(
            table="runs",
            values={
                "id": run.id,
                "name": run.name,
                "state": run.state.value,
                "root_path": run.root_path,
                "created_at": _iso(run.created_at),
                "updated_at": _iso(run.updated_at),
                "metadata_json": canonical_json(run.metadata),
            },
            model=run,
            run_id=run.id,
            event_kind="run.created",
            aggregate_type="run",
        )

    def get_run(self, run_id: str, *, connection: sqlite3.Connection | None = None) -> Run | None:
        return self._one(
            "SELECT * FROM runs WHERE id = ?", (run_id,), self._run_from_row, connection=connection
        )

    def list_runs(self) -> list[Run]:
        return self._many("SELECT * FROM runs ORDER BY created_at, id", (), self._run_from_row)

    def transition_run(self, run_id: str, state: RunState, *, at: datetime | None = None) -> Run:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            run = self._require(self.get_run(run_id, connection=connection), "run", run_id)
            if run.state == state:
                return run
            ensure_transition(run.state, state)
            connection.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE id = ?",
                (state.value, _iso(at), run_id),
            )
            updated = run.model_copy(update={"state": state, "updated_at": at})
            self._append_transition(connection, run_id, "run", run_id, run.state, state)
            return updated

    def create_agent(self, agent: Agent) -> Agent:
        return self._create(
            table="agents",
            values={
                "id": agent.id,
                "run_id": agent.run_id,
                "name": agent.name,
                "role": agent.role,
                "worktree_path": agent.worktree_path,
                "state": agent.state.value,
                "created_at": _iso(agent.created_at),
                "updated_at": _iso(agent.updated_at),
                "metadata_json": canonical_json(agent.metadata),
            },
            model=agent,
            run_id=agent.run_id,
            event_kind="agent.created",
            aggregate_type="agent",
        )

    def get_agent(
        self, agent_id: str, *, connection: sqlite3.Connection | None = None
    ) -> Agent | None:
        return self._one(
            "SELECT * FROM agents WHERE id = ?",
            (agent_id,),
            self._agent_from_row,
            connection=connection,
        )

    def list_agents(self, run_id: str) -> list[Agent]:
        return self._many(
            "SELECT * FROM agents WHERE run_id = ? ORDER BY created_at, id",
            (run_id,),
            self._agent_from_row,
        )

    def transition_agent(
        self, agent_id: str, state: AgentState, *, at: datetime | None = None
    ) -> Agent:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            agent = self._require(
                self.get_agent(agent_id, connection=connection), "agent", agent_id
            )
            if agent.state == state:
                return agent
            ensure_transition(agent.state, state)
            connection.execute(
                "UPDATE agents SET state = ?, updated_at = ? WHERE id = ?",
                (state.value, _iso(at), agent_id),
            )
            updated = agent.model_copy(update={"state": state, "updated_at": at})
            self._append_transition(connection, agent.run_id, "agent", agent_id, agent.state, state)
            return updated

    def create_agent_session(self, session: AgentSession) -> AgentSession:
        return self._create(
            table="agent_sessions",
            values={
                "id": session.id,
                "run_id": session.run_id,
                "agent_id": session.agent_id,
                "provider": session.provider,
                "external_session_id": session.external_session_id,
                "state": session.state.value,
                "started_at": _iso(session.started_at),
                "updated_at": _iso(session.updated_at),
                "ended_at": _iso(session.ended_at),
                "process_id": session.process_id,
                "metadata_json": canonical_json(session.metadata),
            },
            model=session,
            run_id=session.run_id,
            event_kind="agent_session.created",
            aggregate_type="agent_session",
        )

    def get_agent_session(
        self, session_id: str, *, connection: sqlite3.Connection | None = None
    ) -> AgentSession | None:
        return self._one(
            "SELECT * FROM agent_sessions WHERE id = ?",
            (session_id,),
            self._session_from_row,
            connection=connection,
        )

    def list_agent_sessions(
        self, run_id: str, *, agent_id: str | None = None
    ) -> list[AgentSession]:
        if agent_id:
            return self._many(
                """
                SELECT * FROM agent_sessions
                 WHERE run_id = ? AND agent_id = ? ORDER BY started_at
                """,
                (run_id, agent_id),
                self._session_from_row,
            )
        return self._many(
            "SELECT * FROM agent_sessions WHERE run_id = ? ORDER BY started_at",
            (run_id,),
            self._session_from_row,
        )

    def transition_agent_session(
        self,
        session_id: str,
        state: SessionState,
        *,
        at: datetime | None = None,
    ) -> AgentSession:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            session = self._require(
                self.get_agent_session(session_id, connection=connection),
                "agent session",
                session_id,
            )
            if session.state == state:
                return session
            ensure_transition(session.state, state)
            ended = (
                at
                if state in {SessionState.COMPLETED, SessionState.FAILED, SessionState.CANCELLED}
                else None
            )
            connection.execute(
                """
                UPDATE agent_sessions
                   SET state = ?, updated_at = ?, ended_at = COALESCE(?, ended_at)
                 WHERE id = ?
                """,
                (state.value, _iso(at), _iso(ended), session_id),
            )
            updated = session.model_copy(
                update={"state": state, "updated_at": at, "ended_at": ended}
            )
            self._append_transition(
                connection, session.run_id, "agent_session", session_id, session.state, state
            )
            return updated

    # Evidence and premises ----------------------------------------------

    def create_evidence_source(self, source: EvidenceSource) -> EvidenceSource:
        return self._create(
            table="evidence_sources",
            values={
                "id": source.id,
                "run_id": source.run_id,
                "name": source.name,
                "uri": source.uri,
                "issuer": source.issuer,
                "public_key": source.public_key,
                "signature_algorithm": source.signature_algorithm,
                "pinned_identity": source.pinned_identity,
                "created_at": _iso(source.created_at),
                "metadata_json": canonical_json(source.metadata),
            },
            model=source,
            run_id=source.run_id,
            event_kind="evidence_source.created",
            aggregate_type="evidence_source",
        )

    def get_evidence_source(
        self, source_id: str, *, connection: sqlite3.Connection | None = None
    ) -> EvidenceSource | None:
        return self._one(
            "SELECT * FROM evidence_sources WHERE id = ?",
            (source_id,),
            self._evidence_source_from_row,
            connection=connection,
        )

    def list_evidence_sources(self, run_id: str) -> list[EvidenceSource]:
        return self._many(
            "SELECT * FROM evidence_sources WHERE run_id = ? ORDER BY created_at, id",
            (run_id,),
            self._evidence_source_from_row,
        )

    def create_artifact(self, artifact: ArtifactRef) -> ArtifactRef:
        return self._create(
            table="artifacts",
            values={
                "digest": artifact.digest,
                "size": artifact.size,
                "media_type": artifact.media_type,
                "relative_path": artifact.relative_path,
                "created_at": _iso(artifact.created_at),
                "metadata_json": canonical_json(artifact.metadata),
            },
            model=artifact,
            run_id=None,
            event_kind="artifact.created",
            aggregate_type="artifact",
        )

    def get_artifact(self, digest: str) -> ArtifactRef | None:
        return self._one(
            "SELECT * FROM artifacts WHERE digest = ?", (digest,), self._artifact_from_row
        )

    def create_evidence_record(self, evidence: EvidenceRecord) -> EvidenceRecord:
        return self._create(
            table="evidence_records",
            values={
                "id": evidence.id,
                "run_id": evidence.run_id,
                "source_id": evidence.source_id,
                "source_uri": evidence.source_uri,
                "source_version": evidence.source_version,
                "observed_at": _iso(evidence.observed_at),
                "valid_at": _iso(evidence.valid_at),
                "digest": evidence.digest,
                "signature_status": evidence.signature_status.value,
                "verification_status": evidence.verification_status.value,
                "artifact_digest": evidence.artifact_digest,
                "normalized_premises_json": canonical_json(evidence.normalized_premises),
                "metadata_json": canonical_json(evidence.metadata),
            },
            model=evidence,
            run_id=evidence.run_id,
            event_kind="evidence.created",
            aggregate_type="evidence",
        )

    def get_evidence_record(
        self, evidence_id: str, *, connection: sqlite3.Connection | None = None
    ) -> EvidenceRecord | None:
        return self._one(
            "SELECT * FROM evidence_records WHERE id = ?",
            (evidence_id,),
            self._evidence_from_row,
            connection=connection,
        )

    def list_evidence_records(
        self, run_id: str, *, source_id: str | None = None
    ) -> list[EvidenceRecord]:
        if source_id:
            return self._many(
                """
                SELECT * FROM evidence_records
                 WHERE run_id = ? AND source_id = ? ORDER BY source_version, id
                """,
                (run_id, source_id),
                self._evidence_from_row,
            )
        return self._many(
            "SELECT * FROM evidence_records WHERE run_id = ? ORDER BY observed_at, id",
            (run_id,),
            self._evidence_from_row,
        )

    def create_premise(self, premise: Premise) -> Premise:
        return self._create(
            table="premises",
            values={
                "id": premise.id,
                "run_id": premise.run_id,
                "scope": premise.scope,
                "subject": premise.subject,
                "relation": premise.relation,
                "value_json": canonical_json(premise.value),
                "value_digest": premise.value_digest,
                "semantics": premise.semantics.value,
                "state": premise.state.value,
                "valid_at": _iso(premise.valid_at),
                "invalid_at": _iso(premise.invalid_at),
                "invalidated_by_evidence_id": premise.invalidated_by_evidence_id,
                "replaces_premise_id": premise.replaces_premise_id,
                "created_at": _iso(premise.created_at),
                "metadata_json": canonical_json(premise.metadata),
            },
            model=premise,
            run_id=premise.run_id,
            event_kind="premise.created",
            aggregate_type="premise",
        )

    def get_premise(
        self, premise_id: str, *, connection: sqlite3.Connection | None = None
    ) -> Premise | None:
        return self._one(
            "SELECT * FROM premises WHERE id = ?",
            (premise_id,),
            self._premise_from_row,
            connection=connection,
        )

    def list_premises(
        self,
        run_id: str,
        *,
        scope: str | None = None,
        state: PremiseState | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[Premise]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        if scope is not None:
            clauses.append("scope = ?")
            args.append(scope)
        if state is not None:
            clauses.append("state = ?")
            args.append(state.value)
        return self._many(
            f"SELECT * FROM premises WHERE {' AND '.join(clauses)} ORDER BY valid_at, id",
            args,
            self._premise_from_row,
            connection=connection,
        )

    def find_active_premises(
        self,
        *,
        run_id: str,
        scope: str,
        subject: str,
        relation: str,
        connection: sqlite3.Connection | None = None,
    ) -> list[Premise]:
        return self._many(
            """
            SELECT * FROM premises
             WHERE run_id = ? AND scope = ? AND subject = ? AND relation = ? AND state = 'ACTIVE'
             ORDER BY valid_at, id
            """,
            (run_id, scope, subject, relation),
            self._premise_from_row,
            connection=connection,
        )

    def premises_at(
        self,
        *,
        run_id: str,
        scope: str,
        subject: str,
        relation: str,
        at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> list[Premise]:
        """Return the immutable premise revisions that were valid at ``at``."""

        return self._many(
            """
            SELECT * FROM premises
             WHERE run_id = ? AND scope = ? AND subject = ? AND relation = ?
               AND state != 'PROPOSED' AND valid_at <= ?
               AND (invalid_at IS NULL OR invalid_at > ?)
             ORDER BY valid_at, id
            """,
            (run_id, scope, subject, relation, _iso(at), _iso(at)),
            self._premise_from_row,
            connection=connection,
        )

    active_premises_at = premises_at

    def replace_active_premise(self, premise: Premise) -> Premise:
        """Atomically supersede the current single/temporal value and insert its successor."""

        if premise.state != PremiseState.ACTIVE:
            raise ValidationError("replacement premise must be ACTIVE")
        if premise.semantics.value == "SET":
            return self.create_premise(premise)
        with self.database.transaction() as connection:
            current = self.find_active_premises(
                run_id=premise.run_id,
                scope=premise.scope,
                subject=premise.subject,
                relation=premise.relation,
                connection=connection,
            )
            if len(current) > 1:
                raise IntegrityError(
                    "single/temporal premise lineage has multiple active revisions"
                )
            prior = current[0] if current else None
            if premise.replaces_premise_id and (
                prior is None or premise.replaces_premise_id != prior.id
            ):
                raise ValidationError("replacement does not name the current active premise")
            replacement = premise
            if prior is not None:
                if prior.semantics != premise.semantics:
                    raise ValidationError("replacement premise semantics cannot change")
                if premise.valid_at < prior.valid_at:
                    raise ValidationError("replacement cannot predate the current premise")
                connection.execute(
                    "UPDATE premises SET state = 'SUPERSEDED', invalid_at = ? WHERE id = ?",
                    (_iso(premise.valid_at), prior.id),
                )
                self._append_transition(
                    connection,
                    prior.run_id,
                    "premise",
                    prior.id,
                    prior.state,
                    PremiseState.SUPERSEDED,
                )
                if replacement.replaces_premise_id is None:
                    replacement = Premise.model_validate(
                        replacement.model_copy(
                            update={"replaces_premise_id": prior.id}
                        ).model_dump()
                    )
            return self._create(
                table="premises",
                values=self._premise_values(replacement),
                model=replacement,
                run_id=replacement.run_id,
                event_kind="premise.created",
                aggregate_type="premise",
                connection=connection,
            )

    def link_premise_evidence(self, link: PremiseEvidence) -> PremiseEvidence:
        premise = self.get_premise(link.premise_id)
        if premise is None:
            raise ValidationError(f"premise {link.premise_id} does not exist")
        return self._create(
            table="premise_evidence",
            values={
                "premise_id": link.premise_id,
                "evidence_id": link.evidence_id,
                "role": link.role.value,
                "confidence": link.confidence,
                "created_at": _iso(link.created_at),
            },
            model=link,
            run_id=premise.run_id,
            event_kind="premise.evidence_linked",
            aggregate_type="premise",
        )

    def list_premise_evidence(self, premise_id: str) -> list[PremiseEvidence]:
        return self._many(
            "SELECT * FROM premise_evidence WHERE premise_id = ? ORDER BY created_at, evidence_id",
            (premise_id,),
            self._premise_evidence_from_row,
        )

    def transition_premise(
        self,
        premise_id: str,
        state: PremiseState,
        *,
        at: datetime | None = None,
        invalidated_by_evidence_id: str | None = None,
    ) -> Premise:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            premise = self._require(
                self.get_premise(premise_id, connection=connection), "premise", premise_id
            )
            if premise.state == state:
                return premise
            ensure_transition(premise.state, state)
            terminal = state in {PremiseState.INVALIDATED, PremiseState.SUPERSEDED}
            if state == PremiseState.INVALIDATED and not invalidated_by_evidence_id:
                raise ValidationError("invalidating evidence is required")
            connection.execute(
                """
                UPDATE premises
                   SET state = ?, invalid_at = ?, invalidated_by_evidence_id = ?
                 WHERE id = ?
                """,
                (
                    state.value,
                    _iso(at) if terminal else None,
                    invalidated_by_evidence_id,
                    premise_id,
                ),
            )
            updated = premise.model_copy(
                update={
                    "state": state,
                    "invalid_at": at if terminal else None,
                    "invalidated_by_evidence_id": invalidated_by_evidence_id,
                }
            )
            self._append_transition(
                connection, premise.run_id, "premise", premise_id, premise.state, state
            )
            return Premise.model_validate(updated.model_dump())

    # Graph ---------------------------------------------------------------

    def create_graph_node(self, node: GraphNode) -> GraphNode:
        return self._create(
            table="graph_nodes",
            values={
                "id": node.id,
                "run_id": node.run_id,
                "kind": node.kind.value,
                "entity_id": node.entity_id,
                "scope": node.scope,
                "created_at": _iso(node.created_at),
                "metadata_json": canonical_json(node.metadata),
            },
            model=node,
            run_id=node.run_id,
            event_kind="graph.node_created",
            aggregate_type="graph_node",
        )

    def get_graph_node(
        self, node_id: str, *, connection: sqlite3.Connection | None = None
    ) -> GraphNode | None:
        return self._one(
            "SELECT * FROM graph_nodes WHERE id = ?",
            (node_id,),
            self._graph_node_from_row,
            connection=connection,
        )

    def find_graph_node(
        self,
        run_id: str,
        kind: str,
        entity_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> GraphNode | None:
        return self._one(
            "SELECT * FROM graph_nodes WHERE run_id = ? AND kind = ? AND entity_id = ?",
            (run_id, kind, entity_id),
            self._graph_node_from_row,
            connection=connection,
        )

    def list_graph_nodes(
        self, run_id: str, *, connection: sqlite3.Connection | None = None
    ) -> list[GraphNode]:
        return self._many(
            "SELECT * FROM graph_nodes WHERE run_id = ? ORDER BY created_at, id",
            (run_id,),
            self._graph_node_from_row,
            connection=connection,
        )

    def create_dependency_edge(self, edge: DependencyEdge) -> DependencyEdge:
        source = self.get_graph_node(edge.source_node_id)
        target = self.get_graph_node(edge.target_node_id)
        if source is None or target is None:
            raise ValidationError("dependency edge endpoints must exist")
        if source.run_id != edge.run_id or target.run_id != edge.run_id:
            raise ValidationError("dependency edge endpoints must belong to its run")
        if source.scope != edge.scope or target.scope != edge.scope:
            raise ValidationError("dependency edge scope must match both endpoints")
        return self._create(
            table="dependency_edges",
            values={
                "id": edge.id,
                "run_id": edge.run_id,
                "source_node_id": edge.source_node_id,
                "target_node_id": edge.target_node_id,
                "edge_type": edge.edge_type.value,
                "strength": edge.strength.value,
                "scope": edge.scope,
                "declared_by": edge.declared_by,
                "confidence": edge.confidence,
                "created_at": _iso(edge.created_at),
                "metadata_json": canonical_json(edge.metadata),
            },
            model=edge,
            run_id=edge.run_id,
            event_kind="graph.edge_created",
            aggregate_type="dependency_edge",
        )

    def get_dependency_edge(self, edge_id: str) -> DependencyEdge | None:
        return self._one(
            "SELECT * FROM dependency_edges WHERE id = ?",
            (edge_id,),
            self._edge_from_row,
        )

    def list_dependency_edges(
        self,
        run_id: str,
        *,
        source_node_id: str | None = None,
        target_node_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[DependencyEdge]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        if source_node_id is not None:
            clauses.append("source_node_id = ?")
            args.append(source_node_id)
        if target_node_id is not None:
            clauses.append("target_node_id = ?")
            args.append(target_node_id)
        return self._many(
            f"SELECT * FROM dependency_edges WHERE {' AND '.join(clauses)} ORDER BY created_at, id",
            args,
            self._edge_from_row,
            connection=connection,
        )

    # Warrants -----------------------------------------------------------

    def create_warrant(self, warrant: Warrant) -> Warrant:
        return self._create(
            table="warrants",
            values=self._warrant_values(warrant),
            model=warrant,
            run_id=warrant.run_id,
            event_kind="warrant.created",
            aggregate_type="warrant",
        )

    def get_warrant(
        self, warrant_id: str, *, connection: sqlite3.Connection | None = None
    ) -> Warrant | None:
        return self._one(
            "SELECT * FROM warrants WHERE id = ?",
            (warrant_id,),
            self._warrant_from_row,
            connection=connection,
        )

    def list_warrants(
        self,
        run_id: str,
        *,
        state: WarrantState | None = None,
        agent_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[Warrant]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        if state is not None:
            clauses.append("state = ?")
            args.append(state.value)
        if agent_id is not None:
            clauses.append("agent_id = ?")
            args.append(agent_id)
        return self._many(
            f"SELECT * FROM warrants WHERE {' AND '.join(clauses)} ORDER BY issued_at, id",
            args,
            self._warrant_from_row,
            connection=connection,
        )

    def link_warrant_premise(self, link: WarrantPremise) -> WarrantPremise:
        with self.database.transaction() as connection:
            warrant = self._require(
                self.get_warrant(link.warrant_id, connection=connection),
                "warrant",
                link.warrant_id,
            )
            premise = self._require(
                self.get_premise(link.premise_id, connection=connection),
                "premise",
                link.premise_id,
            )
            if warrant.run_id != premise.run_id:
                raise ValidationError("warrant and premise must belong to the same run")
            if warrant.scope != premise.scope:
                raise ValidationError("warrant and premise must belong to the same causal scope")
            if link.premise_digest != premise.value_digest:
                raise StaleWarrantError("warrant premise digest does not match the premise")
            existing_scopes = {
                str(row["scope"])
                for row in connection.execute(
                    """
                    SELECT DISTINCT p.scope
                      FROM warrant_premises AS wp
                      JOIN premises AS p ON p.id = wp.premise_id
                     WHERE wp.warrant_id = ?
                    """,
                    (warrant.id,),
                ).fetchall()
            }
            if existing_scopes and existing_scopes != {premise.scope}:
                raise ValidationError("one warrant cannot span multiple causal scopes")
            return self._create(
                table="warrant_premises",
                values={
                    "warrant_id": link.warrant_id,
                    "premise_id": link.premise_id,
                    "premise_digest": link.premise_digest,
                    "created_at": _iso(link.created_at),
                },
                model=link,
                run_id=warrant.run_id,
                event_kind="warrant.premise_linked",
                aggregate_type="warrant",
                connection=connection,
            )

    def list_warrant_premises(
        self,
        warrant_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[WarrantPremise]:
        return self._many(
            "SELECT * FROM warrant_premises WHERE warrant_id = ? ORDER BY created_at, premise_id",
            (warrant_id,),
            self._warrant_premise_from_row,
            connection=connection,
        )

    def transition_warrant(
        self,
        warrant_id: str,
        state: WarrantState,
        *,
        at: datetime | None = None,
        revoke_cause: str | None = None,
    ) -> Warrant:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            warrant = self._require(
                self.get_warrant(warrant_id, connection=connection), "warrant", warrant_id
            )
            if warrant.state == state:
                return warrant
            ensure_transition(warrant.state, state)
            revoked_at = at if state == WarrantState.REVOKED else warrant.revoked_at
            if state == WarrantState.REVOKED and not revoke_cause:
                raise ValidationError("revoking a warrant requires a cause")
            connection.execute(
                "UPDATE warrants SET state = ?, revoked_at = ?, revoke_cause = ? WHERE id = ?",
                (state.value, _iso(revoked_at), revoke_cause or warrant.revoke_cause, warrant_id),
            )
            updated = Warrant.model_validate(
                warrant.model_copy(
                    update={
                        "state": state,
                        "revoked_at": revoked_at,
                        "revoke_cause": revoke_cause or warrant.revoke_cause,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection, warrant.run_id, "warrant", warrant_id, warrant.state, state
            )
            return updated

    # Actions ------------------------------------------------------------

    def create_action(self, action: ActionIntent) -> ActionIntent:
        return self._create(
            table="action_intents",
            values=self._action_values(action),
            model=action,
            run_id=action.run_id,
            event_kind="action.created",
            aggregate_type="action",
        )

    create_action_intent = create_action

    def get_action(
        self, action_id: str, *, connection: sqlite3.Connection | None = None
    ) -> ActionIntent | None:
        return self._one(
            "SELECT * FROM action_intents WHERE id = ?",
            (action_id,),
            self._action_from_row,
            connection=connection,
        )

    get_action_intent = get_action

    def list_actions(
        self,
        run_id: str,
        *,
        state: ActionState | None = None,
        warrant_id: str | None = None,
        agent_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[ActionIntent]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        for column, value in (
            ("state", state.value if state else None),
            ("warrant_id", warrant_id),
            ("agent_id", agent_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                args.append(value)
        return self._many(
            f"SELECT * FROM action_intents WHERE {' AND '.join(clauses)} ORDER BY created_at, id",
            args,
            self._action_from_row,
            connection=connection,
        )

    list_action_intents = list_actions

    def transition_action(
        self,
        action_id: str,
        state: ActionState,
        *,
        at: datetime | None = None,
        failure_reason: str | None = None,
    ) -> ActionIntent:
        if state in {ActionState.AUTHORIZED, ActionState.DISPATCHING, ActionState.EXECUTED}:
            raise AuthorizationError(
                "authorization, dispatch, and completion require their atomic Store intents"
            )
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            action = self._require(
                self.get_action(action_id, connection=connection), "action", action_id
            )
            if action.state == state:
                return action
            ensure_transition(action.state, state)
            if state == ActionState.FAILED and not failure_reason:
                raise ValidationError("failed action requires a failure reason")
            connection.execute(
                """
                UPDATE action_intents
                   SET state = ?, updated_at = ?, failure_reason = ?
                 WHERE id = ?
                """,
                (state.value, _iso(at), failure_reason or action.failure_reason, action_id),
            )
            updated = ActionIntent.model_validate(
                action.model_copy(
                    update={
                        "state": state,
                        "updated_at": at,
                        "failure_reason": failure_reason or action.failure_reason,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection, action.run_id, "action", action_id, action.state, state
            )
            return updated

    # Effects ------------------------------------------------------------

    def create_effect(self, effect: EffectRecord) -> EffectRecord:
        return self._create(
            table="effects",
            values=self._effect_values(effect),
            model=effect,
            run_id=effect.run_id,
            event_kind="effect.created",
            aggregate_type="effect",
        )

    def get_effect(
        self, effect_id: str, *, connection: sqlite3.Connection | None = None
    ) -> EffectRecord | None:
        return self._one(
            "SELECT * FROM effects WHERE id = ?",
            (effect_id,),
            self._effect_from_row,
            connection=connection,
        )

    def list_effects(
        self,
        run_id: str,
        *,
        state: EffectState | None = None,
        action_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[EffectRecord]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        if state is not None:
            clauses.append("state = ?")
            args.append(state.value)
        if action_id is not None:
            clauses.append("action_id = ?")
            args.append(action_id)
        return self._many(
            f"SELECT * FROM effects WHERE {' AND '.join(clauses)} ORDER BY created_at, id",
            args,
            self._effect_from_row,
            connection=connection,
        )

    def transition_effect(
        self,
        effect_id: str,
        state: EffectState,
        *,
        at: datetime | None = None,
        compensation_attempts: int | None = None,
    ) -> EffectRecord:
        if state in {EffectState.AUTHORIZED, EffectState.DISPATCHING, EffectState.EXECUTED}:
            raise AuthorizationError(
                "authorization, dispatch, and completion require their atomic Store intents"
            )
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            effect = self._require(
                self.get_effect(effect_id, connection=connection), "effect", effect_id
            )
            if effect.state == state:
                return effect
            ensure_transition(effect.state, state)
            compensated_at = at if state == EffectState.ROLLED_BACK else effect.compensated_at
            dispatched_at = at if state == EffectState.DISPATCHING else effect.dispatched_at
            attempts = (
                compensation_attempts
                if compensation_attempts is not None
                else effect.compensation_attempts
            )
            connection.execute(
                """
                UPDATE effects
                   SET state = ?, updated_at = ?, dispatched_at = ?, compensated_at = ?,
                       compensation_attempts = ?
                 WHERE id = ?
                """,
                (
                    state.value,
                    _iso(at),
                    _iso(dispatched_at),
                    _iso(compensated_at),
                    attempts,
                    effect_id,
                ),
            )
            updated = EffectRecord.model_validate(
                effect.model_copy(
                    update={
                        "state": state,
                        "updated_at": at,
                        "dispatched_at": dispatched_at,
                        "compensated_at": compensated_at,
                        "compensation_attempts": attempts,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection, effect.run_id, "effect", effect_id, effect.state, state
            )
            return updated

    # Execution leases ---------------------------------------------------

    def create_lease(self, lease: ExecutionLease) -> ExecutionLease:
        return self._create(
            table="execution_leases",
            values=self._lease_values(lease),
            model=lease,
            run_id=lease.run_id,
            event_kind="lease.created",
            aggregate_type="lease",
        )

    create_execution_lease = create_lease

    def get_lease(
        self, lease_id: str, *, connection: sqlite3.Connection | None = None
    ) -> ExecutionLease | None:
        return self._one(
            "SELECT * FROM execution_leases WHERE id = ?",
            (lease_id,),
            self._lease_from_row,
            connection=connection,
        )

    get_execution_lease = get_lease

    def get_lease_for_action(
        self, action_id: str, *, connection: sqlite3.Connection | None = None
    ) -> ExecutionLease | None:
        return self._one(
            "SELECT * FROM execution_leases WHERE action_id = ?",
            (action_id,),
            self._lease_from_row,
            connection=connection,
        )

    def list_leases(
        self,
        run_id: str,
        *,
        state: LeaseState | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[ExecutionLease]:
        if state is None:
            return self._many(
                "SELECT * FROM execution_leases WHERE run_id = ? ORDER BY issued_at, id",
                (run_id,),
                self._lease_from_row,
                connection=connection,
            )
        return self._many(
            "SELECT * FROM execution_leases WHERE run_id = ? AND state = ? ORDER BY issued_at, id",
            (run_id, state.value),
            self._lease_from_row,
            connection=connection,
        )

    def transition_lease(
        self,
        lease_id: str,
        state: LeaseState,
        *,
        at: datetime | None = None,
    ) -> ExecutionLease:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            lease = self._require(
                self.get_lease(lease_id, connection=connection), "lease", lease_id
            )
            if lease.state == state:
                return lease
            ensure_transition(lease.state, state)
            consumed_at = at if state == LeaseState.CONSUMED else lease.consumed_at
            revoked_at = at if state == LeaseState.REVOKED else lease.revoked_at
            connection.execute(
                """
                UPDATE execution_leases
                   SET state = ?, consumed_at = ?, revoked_at = ?
                 WHERE id = ?
                """,
                (state.value, _iso(consumed_at), _iso(revoked_at), lease_id),
            )
            updated = ExecutionLease.model_validate(
                lease.model_copy(
                    update={
                        "state": state,
                        "consumed_at": consumed_at,
                        "revoked_at": revoked_at,
                    }
                ).model_dump()
            )
            self._append_transition(connection, lease.run_id, "lease", lease_id, lease.state, state)
            return updated

    def expire_leases(self, *, at: datetime | None = None, run_id: str | None = None) -> int:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            clauses = ["state = 'ACTIVE'", "expires_at <= ?"]
            args: list[Any] = [_iso(at)]
            if run_id is not None:
                clauses.append("run_id = ?")
                args.append(run_id)
            rows = connection.execute(
                f"SELECT * FROM execution_leases WHERE {' AND '.join(clauses)} ORDER BY id",
                args,
            ).fetchall()
            for row in rows:
                lease = self._lease_from_row(row)
                connection.execute(
                    "UPDATE execution_leases SET state = 'EXPIRED' WHERE id = ?", (lease.id,)
                )
                self._append_transition(
                    connection,
                    lease.run_id,
                    "lease",
                    lease.id,
                    lease.state,
                    LeaseState.EXPIRED,
                )
            return len(rows)

    # Revocation cases ---------------------------------------------------

    def create_revocation_case(self, case: RevocationCase) -> RevocationCase:
        return self._create(
            table="revocation_cases",
            values=self._case_values(case),
            model=case,
            run_id=case.run_id,
            event_kind="revocation_case.created",
            aggregate_type="revocation_case",
        )

    def get_revocation_case(
        self, case_id: str, *, connection: sqlite3.Connection | None = None
    ) -> RevocationCase | None:
        return self._one(
            "SELECT * FROM revocation_cases WHERE id = ?",
            (case_id,),
            self._case_from_row,
            connection=connection,
        )

    def list_revocation_cases(
        self,
        run_id: str,
        *,
        state: RevocationCaseState | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[RevocationCase]:
        if state is None:
            return self._many(
                "SELECT * FROM revocation_cases WHERE run_id = ? ORDER BY opened_at, id",
                (run_id,),
                self._case_from_row,
                connection=connection,
            )
        return self._many(
            "SELECT * FROM revocation_cases WHERE run_id = ? AND state = ? ORDER BY opened_at, id",
            (run_id, state.value),
            self._case_from_row,
            connection=connection,
        )

    def transition_revocation_case(
        self,
        case_id: str,
        state: RevocationCaseState,
        *,
        at: datetime | None = None,
    ) -> RevocationCase:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            case = self._require(
                self.get_revocation_case(case_id, connection=connection),
                "revocation case",
                case_id,
            )
            if case.state == state:
                return case
            ensure_transition(case.state, state)
            closed_at = at if state == RevocationCaseState.CLOSED else case.closed_at
            connection.execute(
                "UPDATE revocation_cases SET state = ?, updated_at = ?, closed_at = ? WHERE id = ?",
                (state.value, _iso(at), _iso(closed_at), case_id),
            )
            updated = RevocationCase.model_validate(
                case.model_copy(
                    update={"state": state, "updated_at": at, "closed_at": closed_at}
                ).model_dump()
            )
            self._append_transition(
                connection, case.run_id, "revocation_case", case_id, case.state, state
            )
            return updated

    def add_revocation_member(self, member: RevocationMember) -> RevocationMember:
        with self.database.transaction() as connection:
            case = self._require(
                self.get_revocation_case(member.case_id, connection=connection),
                "revocation case",
                member.case_id,
            )
            return self._create(
                table="revocation_members",
                values=self._member_values(member),
                model=member,
                run_id=case.run_id,
                event_kind="revocation_case.member_added",
                aggregate_type="revocation_case",
                connection=connection,
            )

    def list_revocation_members(
        self,
        case_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[RevocationMember]:
        return self._many(
            "SELECT * FROM revocation_members WHERE case_id = ? ORDER BY created_at, node_id",
            (case_id,),
            self._member_from_row,
            connection=connection,
        )

    # Experiments --------------------------------------------------------

    def create_experiment_candidate(self, candidate: ExperimentCandidate) -> ExperimentCandidate:
        return self._create(
            table="experiment_candidates",
            values=self._candidate_values(candidate),
            model=candidate,
            run_id=candidate.run_id,
            event_kind="experiment_candidate.created",
            aggregate_type="experiment_candidate",
        )

    def get_experiment_candidate(
        self, candidate_id: str, *, connection: sqlite3.Connection | None = None
    ) -> ExperimentCandidate | None:
        return self._one(
            "SELECT * FROM experiment_candidates WHERE id = ?",
            (candidate_id,),
            self._candidate_from_row,
            connection=connection,
        )

    def list_experiment_candidates(
        self,
        case_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[ExperimentCandidate]:
        return self._many(
            "SELECT * FROM experiment_candidates WHERE case_id = ? ORDER BY created_at, id",
            (case_id,),
            self._candidate_from_row,
            connection=connection,
        )

    def transition_experiment_candidate(
        self,
        candidate_id: str,
        state: ExperimentState,
        *,
        rejection_reason: str | None = None,
        score: tuple[int, int, int, int] | None = None,
    ) -> ExperimentCandidate:
        with self.database.transaction() as connection:
            candidate = self._require(
                self.get_experiment_candidate(candidate_id, connection=connection),
                "experiment candidate",
                candidate_id,
            )
            if candidate.state == state:
                return candidate
            ensure_transition(candidate.state, state)
            if state == ExperimentState.REJECTED and not rejection_reason:
                raise ValidationError("rejected candidate requires a reason")
            connection.execute(
                """
                UPDATE experiment_candidates
                   SET state = ?, rejection_reason = ?, score_json = ?
                 WHERE id = ?
                """,
                (
                    state.value,
                    rejection_reason or candidate.rejection_reason,
                    canonical_json(score if score is not None else candidate.score)
                    if (score is not None or candidate.score is not None)
                    else None,
                    candidate_id,
                ),
            )
            updated = ExperimentCandidate.model_validate(
                candidate.model_copy(
                    update={
                        "state": state,
                        "rejection_reason": rejection_reason or candidate.rejection_reason,
                        "score": score if score is not None else candidate.score,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                candidate.run_id,
                "experiment_candidate",
                candidate_id,
                candidate.state,
                state,
            )
            return updated

    def create_experiment_run(self, experiment: ExperimentRun) -> ExperimentRun:
        return self._create(
            table="experiment_runs",
            values=self._experiment_values(experiment),
            model=experiment,
            run_id=experiment.run_id,
            event_kind="experiment_run.created",
            aggregate_type="experiment_run",
        )

    def get_experiment_run(
        self, experiment_id: str, *, connection: sqlite3.Connection | None = None
    ) -> ExperimentRun | None:
        return self._one(
            "SELECT * FROM experiment_runs WHERE id = ?",
            (experiment_id,),
            self._experiment_from_row,
            connection=connection,
        )

    def list_experiment_runs(
        self,
        case_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[ExperimentRun]:
        return self._many(
            "SELECT * FROM experiment_runs WHERE case_id = ? ORDER BY started_at, id",
            (case_id,),
            self._experiment_from_row,
            connection=connection,
        )

    def transition_experiment_run(
        self,
        experiment_id: str,
        state: ExperimentState,
        *,
        at: datetime | None = None,
        exit_code: int | None = None,
        observed_outcome: Any | None = None,
        stdout_artifact_digest: str | None = None,
        stderr_artifact_digest: str | None = None,
    ) -> ExperimentRun:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            experiment = self._require(
                self.get_experiment_run(experiment_id, connection=connection),
                "experiment run",
                experiment_id,
            )
            if experiment.state == state:
                return experiment
            ensure_transition(experiment.state, state)
            finished_at = (
                at
                if state in {ExperimentState.PASSED, ExperimentState.FAILED}
                else experiment.finished_at
            )
            connection.execute(
                """
                UPDATE experiment_runs
                   SET state = ?, finished_at = ?, exit_code = ?,
                       stdout_artifact_digest = ?, stderr_artifact_digest = ?,
                       observed_outcome_json = ?
                 WHERE id = ?
                """,
                (
                    state.value,
                    _iso(finished_at),
                    exit_code if exit_code is not None else experiment.exit_code,
                    stdout_artifact_digest or experiment.stdout_artifact_digest,
                    stderr_artifact_digest or experiment.stderr_artifact_digest,
                    canonical_json(observed_outcome)
                    if observed_outcome is not None
                    else (
                        canonical_json(experiment.observed_outcome)
                        if experiment.observed_outcome is not None
                        else None
                    ),
                    experiment_id,
                ),
            )
            updated = ExperimentRun.model_validate(
                experiment.model_copy(
                    update={
                        "state": state,
                        "finished_at": finished_at,
                        "exit_code": exit_code if exit_code is not None else experiment.exit_code,
                        "observed_outcome": observed_outcome
                        if observed_outcome is not None
                        else experiment.observed_outcome,
                        "stdout_artifact_digest": stdout_artifact_digest
                        or experiment.stdout_artifact_digest,
                        "stderr_artifact_digest": stderr_artifact_digest
                        or experiment.stderr_artifact_digest,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                experiment.run_id,
                "experiment_run",
                experiment_id,
                experiment.state,
                state,
            )
            return updated

    # Tests and receipts -------------------------------------------------

    def create_test_run(self, test: TestRun) -> TestRun:
        return self._create(
            table="test_runs",
            values=self._test_values(test),
            model=test,
            run_id=test.run_id,
            event_kind="test_run.created",
            aggregate_type="test_run",
        )

    def get_test_run(
        self, test_id: str, *, connection: sqlite3.Connection | None = None
    ) -> TestRun | None:
        return self._one(
            "SELECT * FROM test_runs WHERE id = ?",
            (test_id,),
            self._test_from_row,
            connection=connection,
        )

    def list_test_runs(
        self,
        run_id: str,
        *,
        case_id: str | None = None,
        action_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[TestRun]:
        clauses = ["run_id = ?"]
        args: list[Any] = [run_id]
        if case_id is not None:
            clauses.append("case_id = ?")
            args.append(case_id)
        if action_id is not None:
            clauses.append("action_id = ?")
            args.append(action_id)
        return self._many(
            f"SELECT * FROM test_runs WHERE {' AND '.join(clauses)} ORDER BY started_at, id",
            args,
            self._test_from_row,
            connection=connection,
        )

    def transition_test_run(
        self,
        test_id: str,
        state: TestState,
        *,
        at: datetime | None = None,
        exit_code: int | None = None,
        stdout_artifact_digest: str | None = None,
        stderr_artifact_digest: str | None = None,
    ) -> TestRun:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            test = self._require(
                self.get_test_run(test_id, connection=connection), "test run", test_id
            )
            if test.state == state:
                return test
            ensure_transition(test.state, state)
            terminal = {
                TestState.PASSED,
                TestState.FAILED,
                TestState.ERROR,
                TestState.CANCELLED,
            }
            finished_at = at if state in terminal else test.finished_at
            connection.execute(
                """
                UPDATE test_runs
                   SET state = ?, finished_at = ?, exit_code = ?,
                       stdout_artifact_digest = ?, stderr_artifact_digest = ?
                 WHERE id = ?
                """,
                (
                    state.value,
                    _iso(finished_at),
                    exit_code if exit_code is not None else test.exit_code,
                    stdout_artifact_digest or test.stdout_artifact_digest,
                    stderr_artifact_digest or test.stderr_artifact_digest,
                    test_id,
                ),
            )
            updated = TestRun.model_validate(
                test.model_copy(
                    update={
                        "state": state,
                        "finished_at": finished_at,
                        "exit_code": exit_code if exit_code is not None else test.exit_code,
                        "stdout_artifact_digest": stdout_artifact_digest
                        or test.stdout_artifact_digest,
                        "stderr_artifact_digest": stderr_artifact_digest
                        or test.stderr_artifact_digest,
                    }
                ).model_dump()
            )
            self._append_transition(connection, test.run_id, "test_run", test_id, test.state, state)
            return updated

    def create_receipt(self, receipt: Receipt) -> Receipt:
        return self._create(
            table="receipts",
            values=self._receipt_values(receipt),
            model=receipt,
            run_id=receipt.run_id,
            event_kind="receipt.created",
            aggregate_type="receipt",
        )

    def get_receipt(
        self, receipt_id: str, *, connection: sqlite3.Connection | None = None
    ) -> Receipt | None:
        return self._one(
            "SELECT * FROM receipts WHERE id = ?",
            (receipt_id,),
            self._receipt_from_row,
            connection=connection,
        )

    def list_receipts(
        self,
        run_id: str,
        *,
        case_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[Receipt]:
        if case_id is None:
            return self._many(
                "SELECT * FROM receipts WHERE run_id = ? ORDER BY created_at, id",
                (run_id,),
                self._receipt_from_row,
                connection=connection,
            )
        return self._many(
            "SELECT * FROM receipts WHERE run_id = ? AND case_id = ? ORDER BY created_at, id",
            (run_id, case_id),
            self._receipt_from_row,
            connection=connection,
        )

    def transition_receipt(
        self,
        receipt_id: str,
        state: ReceiptState,
        *,
        at: datetime | None = None,
        artifact_digest: str | None = None,
    ) -> Receipt:
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            receipt = self._require(
                self.get_receipt(receipt_id, connection=connection), "receipt", receipt_id
            )
            if receipt.state == state:
                return receipt
            ensure_transition(receipt.state, state)
            verified_at = at if state == ReceiptState.VERIFIED else receipt.verified_at
            connection.execute(
                "UPDATE receipts SET state = ?, artifact_digest = ?, verified_at = ? WHERE id = ?",
                (
                    state.value,
                    artifact_digest or receipt.artifact_digest,
                    _iso(verified_at),
                    receipt_id,
                ),
            )
            updated = Receipt.model_validate(
                receipt.model_copy(
                    update={
                        "state": state,
                        "artifact_digest": artifact_digest or receipt.artifact_digest,
                        "verified_at": verified_at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection, receipt.run_id, "receipt", receipt_id, receipt.state, state
            )
            return updated

    # Atomic enforcement intents ----------------------------------------

    def authorize_action_with_lease(
        self,
        action_id: str,
        effect_id: str,
        lease: ExecutionLease,
        *,
        expected_warrant_epoch: int,
        at: datetime | None = None,
    ) -> tuple[ActionIntent, EffectRecord]:
        """Authorize one prepared action/effect intent and its lease atomically."""

        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            action = self._require(
                self.get_action(action_id, connection=connection), "action", action_id
            )
            if action.state != ActionState.PREPARED:
                raise AuthorizationError("only a prepared action can be authorized")
            effect = self._require(
                self.get_effect(effect_id, connection=connection), "effect", effect_id
            )
            self._assert_prepared_effect_locked(connection, action, effect)
            warrant = self._require(
                self.get_warrant(action.warrant_id, connection=connection),
                "warrant",
                action.warrant_id,
            )
            self._assert_action_warrant_locked(
                connection,
                action,
                warrant,
                expected_warrant_epoch=expected_warrant_epoch,
                at=at,
            )
            self._reconcile_authoritative_graph_locked(action.run_id, at=at, connection=connection)
            self._assert_authoritative_path_locked(
                connection,
                action=action,
                effect=effect,
            )
            if lease.state != LeaseState.ACTIVE:
                raise AuthorizationError("new execution lease must be active")
            if (
                lease.action_id != action.id
                or lease.effect_id != effect.id
                or lease.warrant_id != warrant.id
                or lease.run_id != action.run_id
            ):
                raise AuthorizationError("lease is not bound to this action and warrant")
            if lease.epoch != expected_warrant_epoch:
                raise StaleWarrantError("lease epoch does not match the authorized warrant")
            if lease.issued_at > at or lease.expires_at <= at:
                raise AuthorizationError("lease is not currently valid")
            if lease.idempotency_key != action.idempotency_key:
                raise AuthorizationError("lease idempotency key does not match the action")
            self._create(
                table="execution_leases",
                values=self._lease_values(lease),
                model=lease,
                run_id=lease.run_id,
                event_kind="lease.created",
                aggregate_type="lease",
                connection=connection,
            )
            ensure_transition(action.state, ActionState.AUTHORIZED)
            ensure_transition(effect.state, EffectState.AUTHORIZED)
            connection.execute(
                """
                UPDATE action_intents
                   SET state = 'AUTHORIZED', lease_id = ?, updated_at = ?
                 WHERE id = ?
                """,
                (lease.id, _iso(at), action.id),
            )
            connection.execute(
                "UPDATE effects SET state = 'AUTHORIZED', updated_at = ? WHERE id = ?",
                (_iso(at), effect.id),
            )
            updated = ActionIntent.model_validate(
                action.model_copy(
                    update={
                        "state": ActionState.AUTHORIZED,
                        "lease_id": lease.id,
                        "updated_at": at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                action.run_id,
                "action",
                action.id,
                action.state,
                ActionState.AUTHORIZED,
            )
            authorized_effect = EffectRecord.model_validate(
                effect.model_copy(
                    update={"state": EffectState.AUTHORIZED, "updated_at": at}
                ).model_dump()
            )
            self._append_transition(
                connection,
                effect.run_id,
                "effect",
                effect.id,
                effect.state,
                EffectState.AUTHORIZED,
            )
            return updated, authorized_effect

    authorize_action_with_lease_atomic = authorize_action_with_lease

    def begin_action_dispatch(
        self,
        action_id: str,
        effect_id: str,
        token_digest: str,
        *,
        expected_warrant_epoch: int | None = None,
        expected_epoch: int | None = None,
        at: datetime | None = None,
    ) -> tuple[ActionIntent, EffectRecord]:
        """Consume a lease and mark the same action/effect intent dispatching atomically."""

        epoch = expected_warrant_epoch if expected_warrant_epoch is not None else expected_epoch
        if epoch is None:
            raise ValidationError("expected warrant epoch is required")
        if (
            expected_warrant_epoch is not None
            and expected_epoch is not None
            and expected_warrant_epoch != expected_epoch
        ):
            raise ValidationError("conflicting expected warrant epochs")
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            action = self._require(
                self.get_action(action_id, connection=connection), "action", action_id
            )
            if action.state != ActionState.AUTHORIZED or action.lease_id is None:
                raise AuthorizationError("action is not authorized for dispatch")
            effect = self._require(
                self.get_effect(effect_id, connection=connection), "effect", effect_id
            )
            if effect.action_id != action.id or effect.run_id != action.run_id:
                raise AuthorizationError("effect intent is not bound to this action")
            if effect.state != EffectState.AUTHORIZED:
                raise AuthorizationError("effect intent is not authorized for dispatch")
            lease = self._require(
                self.get_lease(action.lease_id, connection=connection), "lease", action.lease_id
            )
            warrant = self._require(
                self.get_warrant(action.warrant_id, connection=connection),
                "warrant",
                action.warrant_id,
            )
            self._assert_action_warrant_locked(
                connection,
                action,
                warrant,
                expected_warrant_epoch=epoch,
                at=at,
            )
            if lease.state != LeaseState.ACTIVE:
                raise AuthorizationError("execution lease is not active")
            if lease.effect_id != effect.id:
                raise AuthorizationError("execution lease is bound to another effect intent")
            if lease.epoch != epoch:
                raise StaleWarrantError("execution lease epoch is stale")
            if lease.expires_at <= at or lease.issued_at > at:
                raise AuthorizationError("execution lease is expired or not yet valid")
            if not hmac.compare_digest(lease.token_digest, token_digest):
                raise AuthorizationError("execution lease token does not match")
            if action.not_before is not None and at < action.not_before:
                raise AuthorizationError("action is not dispatchable yet")
            ensure_transition(action.state, ActionState.DISPATCHING)
            ensure_transition(effect.state, EffectState.DISPATCHING)
            ensure_transition(lease.state, LeaseState.CONSUMED)
            connection.execute(
                """
                UPDATE action_intents
                   SET state = 'DISPATCHING', dispatched_at = ?, updated_at = ?
                 WHERE id = ?
                """,
                (_iso(at), _iso(at), action.id),
            )
            connection.execute(
                """
                UPDATE effects
                   SET state = 'DISPATCHING', dispatched_at = ?, updated_at = ?
                 WHERE id = ?
                """,
                (_iso(at), _iso(at), effect.id),
            )
            connection.execute(
                """
                UPDATE execution_leases
                   SET state = 'CONSUMED', consumed_at = ?
                 WHERE id = ?
                """,
                (_iso(at), lease.id),
            )
            updated = ActionIntent.model_validate(
                action.model_copy(
                    update={
                        "state": ActionState.DISPATCHING,
                        "dispatched_at": at,
                        "updated_at": at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                action.run_id,
                "lease",
                lease.id,
                lease.state,
                LeaseState.CONSUMED,
            )
            self._append_transition(
                connection,
                action.run_id,
                "action",
                action.id,
                action.state,
                ActionState.DISPATCHING,
            )
            dispatching_effect = EffectRecord.model_validate(
                effect.model_copy(
                    update={
                        "state": EffectState.DISPATCHING,
                        "dispatched_at": at,
                        "updated_at": at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                effect.run_id,
                "effect",
                effect.id,
                effect.state,
                EffectState.DISPATCHING,
            )
            return updated, dispatching_effect

    begin_action_dispatch_atomic = begin_action_dispatch

    def record_effect_and_complete_action(
        self,
        effect: EffectRecord,
        *,
        at: datetime | None = None,
    ) -> tuple[EffectRecord, ActionIntent]:
        """Reconcile a dispatched intent and complete its action atomically."""

        if effect.state != EffectState.EXECUTED:
            raise ValidationError("completed action requires an EXECUTED effect record")
        at = at or self.clock.utc_now()
        with self.database.transaction() as connection:
            action = self._require(
                self.get_action(effect.action_id, connection=connection),
                "action",
                effect.action_id,
            )
            if action.state != ActionState.DISPATCHING:
                raise ValidationError("only a dispatching action can record an executed effect")
            if action.run_id != effect.run_id:
                raise ValidationError("effect and action must belong to the same run")
            intent = self._require(
                self.get_effect(effect.id, connection=connection), "effect intent", effect.id
            )
            if intent.state != EffectState.DISPATCHING:
                raise ValidationError("only a dispatching effect intent can be reconciled")
            self._assert_effect_observation_matches_intent(intent, effect)
            ensure_transition(intent.state, EffectState.EXECUTED)
            connection.execute(
                """
                UPDATE effects
                   SET before_hash = ?, after_hash = ?, forward_artifact_digest = ?,
                       reverse_artifact_digest = ?, state = 'EXECUTED', updated_at = ?,
                       dispatched_at = ?, metadata_json = ?
                 WHERE id = ?
                """,
                (
                    effect.before_hash,
                    effect.after_hash,
                    effect.forward_artifact_digest,
                    effect.reverse_artifact_digest,
                    _iso(at),
                    _iso(intent.dispatched_at),
                    canonical_json(effect.metadata),
                    intent.id,
                ),
            )
            stored_effect = EffectRecord.model_validate(
                effect.model_copy(
                    update={
                        "state": EffectState.EXECUTED,
                        "updated_at": at,
                        "dispatched_at": intent.dispatched_at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                intent.run_id,
                "effect",
                intent.id,
                intent.state,
                EffectState.EXECUTED,
            )
            ensure_transition(action.state, ActionState.EXECUTED)
            connection.execute(
                """
                UPDATE action_intents
                   SET state = 'EXECUTED', completed_at = ?, updated_at = ?
                 WHERE id = ?
                """,
                (_iso(at), _iso(at), action.id),
            )
            completed = ActionIntent.model_validate(
                action.model_copy(
                    update={
                        "state": ActionState.EXECUTED,
                        "completed_at": at,
                        "updated_at": at,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                action.run_id,
                "action",
                action.id,
                action.state,
                ActionState.EXECUTED,
            )
            return stored_effect, completed

    record_effect_and_complete_action_atomic = record_effect_and_complete_action

    # Startup dispatch reconciliation -----------------------------------

    def get_dispatch_reconciliation(
        self,
        effect_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> DispatchReconciliationRecord | None:
        return self._one(
            "SELECT * FROM dispatch_reconciliations WHERE effect_id = ?",
            (effect_id,),
            self._dispatch_reconciliation_from_row,
            connection=connection,
        )

    def list_dispatch_reconciliations(
        self,
        run_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[DispatchReconciliationRecord]:
        return self._many(
            """
            SELECT * FROM dispatch_reconciliations
             WHERE run_id = ? ORDER BY reconciled_at, id
            """,
            (run_id,),
            self._dispatch_reconciliation_from_row,
            connection=connection,
        )

    def record_dispatch_reconciliation(
        self,
        record: DispatchReconciliationRecord,
        *,
        executed_effect: EffectRecord | None = None,
    ) -> tuple[DispatchReconciliationRecord, EffectRecord, ActionIntent]:
        """Persist one restart observation and resolve its dispatch atomically.

        A reconciliation is append-only and unique per effect.  ``APPLIED``
        completes the recorded intent from adapter evidence; ``NOT_APPLIED``
        fails it without retrying; ambiguous outcomes walk both entities into
        ``CONTAINMENT_REQUIRED``.  State and evidence commit together so a
        second process can only observe the whole resolution or none of it.
        """

        with self.database.transaction() as connection:
            existing = self.get_dispatch_reconciliation(
                record.effect_id,
                connection=connection,
            )
            if existing is not None:
                if existing != record:
                    raise IntegrityError(
                        f"dispatch reconciliation for {record.effect_id} is immutable"
                    )
                effect = self._require(
                    self.get_effect(record.effect_id, connection=connection),
                    "effect",
                    record.effect_id,
                )
                action = self._require(
                    self.get_action(record.action_id, connection=connection),
                    "action",
                    record.action_id,
                )
                return existing, effect, action

            action = self._require(
                self.get_action(record.action_id, connection=connection),
                "action",
                record.action_id,
            )
            effect = self._require(
                self.get_effect(record.effect_id, connection=connection),
                "effect",
                record.effect_id,
            )
            if (
                action.run_id != record.run_id
                or effect.run_id != record.run_id
                or effect.action_id != action.id
            ):
                raise IntegrityError("dispatch reconciliation identity does not match intent")
            if action.state != ActionState.DISPATCHING or effect.state != EffectState.DISPATCHING:
                raise IntegrityError("only a matched DISPATCHING action/effect can be reconciled")

            if record.outcome == DispatchReconciliationOutcome.APPLIED:
                if executed_effect is None or executed_effect.state != EffectState.EXECUTED:
                    raise ValidationError("APPLIED reconciliation requires an executed effect")
                self._assert_effect_observation_matches_intent(effect, executed_effect)
                ensure_transition(effect.state, EffectState.EXECUTED)
                connection.execute(
                    """
                    UPDATE effects
                       SET before_hash = ?, after_hash = ?, forward_artifact_digest = ?,
                           reverse_artifact_digest = ?, state = 'EXECUTED', updated_at = ?,
                           metadata_json = ?
                     WHERE id = ?
                    """,
                    (
                        executed_effect.before_hash,
                        executed_effect.after_hash,
                        executed_effect.forward_artifact_digest,
                        executed_effect.reverse_artifact_digest,
                        _iso(record.reconciled_at),
                        canonical_json(executed_effect.metadata),
                        effect.id,
                    ),
                )
                effect = EffectRecord.model_validate(
                    executed_effect.model_copy(
                        update={
                            "state": EffectState.EXECUTED,
                            "updated_at": record.reconciled_at,
                            "dispatched_at": effect.dispatched_at,
                        }
                    ).model_dump()
                )
                self._append_transition(
                    connection,
                    effect.run_id,
                    "effect",
                    effect.id,
                    EffectState.DISPATCHING,
                    EffectState.EXECUTED,
                )
                ensure_transition(action.state, ActionState.EXECUTED)
                connection.execute(
                    """
                    UPDATE action_intents
                       SET state = 'EXECUTED', completed_at = ?, updated_at = ?
                     WHERE id = ?
                    """,
                    (_iso(record.reconciled_at), _iso(record.reconciled_at), action.id),
                )
                action = ActionIntent.model_validate(
                    action.model_copy(
                        update={
                            "state": ActionState.EXECUTED,
                            "completed_at": record.reconciled_at,
                            "updated_at": record.reconciled_at,
                        }
                    ).model_dump()
                )
                self._append_transition(
                    connection,
                    action.run_id,
                    "action",
                    action.id,
                    ActionState.DISPATCHING,
                    ActionState.EXECUTED,
                )
            elif record.outcome == DispatchReconciliationOutcome.NOT_APPLIED:
                ensure_transition(effect.state, EffectState.FAILED)
                connection.execute(
                    "UPDATE effects SET state = 'FAILED', updated_at = ? WHERE id = ?",
                    (_iso(record.reconciled_at), effect.id),
                )
                effect = EffectRecord.model_validate(
                    effect.model_copy(
                        update={
                            "state": EffectState.FAILED,
                            "updated_at": record.reconciled_at,
                        }
                    ).model_dump()
                )
                self._append_transition(
                    connection,
                    effect.run_id,
                    "effect",
                    effect.id,
                    EffectState.DISPATCHING,
                    EffectState.FAILED,
                )
                ensure_transition(action.state, ActionState.FAILED)
                connection.execute(
                    """
                    UPDATE action_intents
                       SET state = 'FAILED', updated_at = ?, failure_reason = ?
                     WHERE id = ?
                    """,
                    (_iso(record.reconciled_at), record.reason, action.id),
                )
                action = ActionIntent.model_validate(
                    action.model_copy(
                        update={
                            "state": ActionState.FAILED,
                            "updated_at": record.reconciled_at,
                            "failure_reason": record.reason,
                        }
                    ).model_dump()
                )
                self._append_transition(
                    connection,
                    action.run_id,
                    "action",
                    action.id,
                    ActionState.DISPATCHING,
                    ActionState.FAILED,
                )
            else:
                for effect_current, effect_target in (
                    (EffectState.DISPATCHING, EffectState.REVOKE_PENDING),
                    (EffectState.REVOKE_PENDING, EffectState.REVOKED),
                    (EffectState.REVOKED, EffectState.CONTAINMENT_REQUIRED),
                ):
                    ensure_transition(effect_current, effect_target)
                    connection.execute(
                        "UPDATE effects SET state = ?, updated_at = ? WHERE id = ?",
                        (effect_target.value, _iso(record.reconciled_at), effect.id),
                    )
                    self._append_transition(
                        connection,
                        effect.run_id,
                        "effect",
                        effect.id,
                        effect_current,
                        effect_target,
                    )
                effect = EffectRecord.model_validate(
                    effect.model_copy(
                        update={
                            "state": EffectState.CONTAINMENT_REQUIRED,
                            "updated_at": record.reconciled_at,
                        }
                    ).model_dump()
                )
                for action_current, action_target in (
                    (ActionState.DISPATCHING, ActionState.REVOKE_PENDING),
                    (ActionState.REVOKE_PENDING, ActionState.REVOKED),
                    (ActionState.REVOKED, ActionState.CONTAINMENT_REQUIRED),
                ):
                    ensure_transition(action_current, action_target)
                    connection.execute(
                        """
                        UPDATE action_intents
                           SET state = ?, updated_at = ?, failure_reason = ?
                         WHERE id = ?
                        """,
                        (
                            action_target.value,
                            _iso(record.reconciled_at),
                            record.reason,
                            action.id,
                        ),
                    )
                    self._append_transition(
                        connection,
                        action.run_id,
                        "action",
                        action.id,
                        action_current,
                        action_target,
                    )
                action = ActionIntent.model_validate(
                    action.model_copy(
                        update={
                            "state": ActionState.CONTAINMENT_REQUIRED,
                            "updated_at": record.reconciled_at,
                            "failure_reason": record.reason,
                        }
                    ).model_dump()
                )

            self._insert(
                connection,
                "dispatch_reconciliations",
                self._dispatch_reconciliation_values(record),
            )
            self.journal.append(
                run_id=record.run_id,
                kind="dispatch.reconciled",
                aggregate_type="dispatch_reconciliation",
                aggregate_id=record.id,
                payload=_event_payload(record),
                connection=connection,
            )
            return record, effect, action

    def hard_dependency_closure(
        self,
        *,
        run_id: str,
        root_node_id: str,
        scope: str,
        connection: sqlite3.Connection | None = None,
    ) -> list[tuple[GraphNode, tuple[str, ...]]]:
        """Compute deterministic outgoing scoped hard ``requires`` reachability."""

        if connection is None:
            with self.database.connection(readonly=True) as read:
                return self.hard_dependency_closure(
                    run_id=run_id,
                    root_node_id=root_node_id,
                    scope=scope,
                    connection=read,
                )
        nodes = {node.id: node for node in self.list_graph_nodes(run_id, connection=connection)}
        root = nodes.get(root_node_id)
        if root is None:
            raise ValidationError(f"graph node {root_node_id} does not exist")
        if root.scope != scope:
            raise ValidationError("root graph node does not belong to the requested scope")
        edges = connection.execute(
            """
            SELECT source_node_id, target_node_id
              FROM dependency_edges
             WHERE run_id = ? AND scope = ? AND strength = 'HARD' AND edge_type = 'REQUIRES'
             ORDER BY source_node_id, target_node_id, id
            """,
            (run_id, scope),
        ).fetchall()
        outgoing: dict[str, list[str]] = {}
        for edge in edges:
            outgoing.setdefault(edge["source_node_id"], []).append(edge["target_node_id"])
        paths: dict[str, tuple[str, ...]] = {root_node_id: (root_node_id,)}
        queue = [root_node_id]
        while queue:
            source_id = queue.pop(0)
            for target_id in outgoing.get(source_id, []):
                if target_id not in nodes:
                    raise IntegrityError(f"dependency target {target_id} has no graph node")
                if target_id in paths:
                    continue
                paths[target_id] = (*paths[source_id], target_id)
                queue.append(target_id)
        return [(nodes[node_id], paths[node_id]) for node_id in paths]

    def invalidate_premise_and_fence(
        self,
        premise_id: str,
        invalidating_evidence_id: str,
        case: RevocationCase,
        *,
        at: datetime | None = None,
    ) -> tuple[Premise, RevocationCase, list[RevocationMember]]:
        """Invalidate truth and fence its exact hard-dependency closure atomically."""

        at = at or self.clock.utc_now()
        if case.state != RevocationCaseState.OPEN:
            raise ValidationError("new revocation case must be OPEN")
        with self.database.transaction() as connection:
            premise = self._require(
                self.get_premise(premise_id, connection=connection), "premise", premise_id
            )
            evidence = self._require(
                self.get_evidence_record(invalidating_evidence_id, connection=connection),
                "evidence",
                invalidating_evidence_id,
            )
            if premise.state not in {PremiseState.ACTIVE, PremiseState.DISPUTED}:
                raise ValidationError("only an active or disputed premise can be invalidated")
            if evidence.run_id != premise.run_id:
                raise ValidationError("invalidating evidence belongs to another run")
            if (
                case.run_id != premise.run_id
                or case.premise_id != premise.id
                or case.trigger_evidence_id != evidence.id
            ):
                raise ValidationError("revocation case does not match premise and evidence")
            self._reconcile_authoritative_graph_locked(
                premise.run_id,
                at=at,
                connection=connection,
            )
            self._ensure_authoritative_node_locked(
                connection,
                run_id=premise.run_id,
                kind=NodeKind.PREMISE,
                entity_id=premise.id,
                scope=premise.scope,
                at=at,
            )
            root = self.find_graph_node(
                premise.run_id,
                NodeKind.PREMISE.value,
                premise.id,
                connection=connection,
            )
            if root is None:
                raise ValidationError("premise has no persisted graph node")
            closure = self.hard_dependency_closure(
                run_id=premise.run_id,
                root_node_id=root.id,
                scope=premise.scope,
                connection=connection,
            )
            self._create(
                table="revocation_cases",
                values=self._case_values(case),
                model=case,
                run_id=case.run_id,
                event_kind="revocation_case.created",
                aggregate_type="revocation_case",
                connection=connection,
            )
            ensure_transition(premise.state, PremiseState.INVALIDATED)
            connection.execute(
                """
                UPDATE premises
                   SET state = 'INVALIDATED', invalid_at = ?, invalidated_by_evidence_id = ?
                 WHERE id = ?
                """,
                (_iso(at), evidence.id, premise.id),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO premise_evidence(
                    premise_id, evidence_id, role, confidence, created_at
                ) VALUES (?, ?, 'INVALIDATES', 1.0, ?)
                """,
                (premise.id, evidence.id, _iso(at)),
            )
            invalidated = Premise.model_validate(
                premise.model_copy(
                    update={
                        "state": PremiseState.INVALIDATED,
                        "invalid_at": at,
                        "invalidated_by_evidence_id": evidence.id,
                    }
                ).model_dump()
            )
            self._append_transition(
                connection,
                premise.run_id,
                "premise",
                premise.id,
                premise.state,
                PremiseState.INVALIDATED,
            )

            members: list[RevocationMember] = []
            member_kinds = {
                NodeKind.WARRANT: RevocationMemberKind.WARRANT,
                NodeKind.ACTION: RevocationMemberKind.ACTION,
                NodeKind.EFFECT: RevocationMemberKind.EFFECT,
                NodeKind.EXPERIMENT: RevocationMemberKind.EXPERIMENT,
                NodeKind.TEST: RevocationMemberKind.TEST,
            }
            for node, path in closure:
                member_kind = member_kinds.get(node.kind)
                if member_kind is None:
                    continue
                member = RevocationMember(
                    case_id=case.id,
                    node_id=node.id,
                    member_kind=member_kind,
                    entity_id=node.entity_id,
                    dependency_path=path,
                    created_at=at,
                )
                self._insert(connection, "revocation_members", self._member_values(member))
                members.append(member)

            affected_warrants = {
                member.entity_id
                for member in members
                if member.member_kind == RevocationMemberKind.WARRANT
            }
            affected_actions = {
                member.entity_id
                for member in members
                if member.member_kind == RevocationMemberKind.ACTION
            }
            affected_effects = {
                member.entity_id
                for member in members
                if member.member_kind == RevocationMemberKind.EFFECT
            }
            self._fence_warrants_locked(connection, affected_warrants, at=at)
            self._fence_actions_locked(connection, affected_actions, at=at)
            self._fence_effects_locked(connection, affected_effects, at=at)
            self._revoke_leases_locked(
                connection,
                warrant_ids=affected_warrants,
                action_ids=affected_actions,
                at=at,
            )
            ensure_transition(case.state, RevocationCaseState.FROZEN)
            connection.execute(
                "UPDATE revocation_cases SET state = 'FROZEN', updated_at = ? WHERE id = ?",
                (_iso(at), case.id),
            )
            frozen = RevocationCase.model_validate(
                case.model_copy(
                    update={"state": RevocationCaseState.FROZEN, "updated_at": at}
                ).model_dump()
            )
            self._append_transition(
                connection,
                case.run_id,
                "revocation_case",
                case.id,
                case.state,
                RevocationCaseState.FROZEN,
            )
            return invalidated, frozen, members

    invalidate_premise_and_fence_atomic = invalidate_premise_and_fence

    # Internal enforcement helpers --------------------------------------

    def _assert_prepared_effect_locked(
        self,
        connection: sqlite3.Connection,
        action: ActionIntent,
        effect: EffectRecord,
    ) -> None:
        effects = self.list_effects(
            action.run_id,
            action_id=action.id,
            connection=connection,
        )
        if len(effects) != 1 or effects[0].id != effect.id:
            raise AuthorizationError(
                "an action must have exactly one explicitly selected effect intent"
            )
        if effect.state != EffectState.PREPARED:
            raise AuthorizationError("effect intent must be PREPARED before authorization")
        if effect.action_id != action.id or effect.run_id != action.run_id:
            raise AuthorizationError("effect intent is not bound to this action")
        if effect.scope != action.scope:
            raise AuthorizationError("effect scope does not match the action scope")
        if effect.target != action.target:
            raise AuthorizationError("effect target does not match the action target")
        if effect.reversibility != action.reversibility:
            raise AuthorizationError("effect reversibility does not match the action")
        expected_effect_types = {
            "FILE_EDIT": EffectType.FILE_EDIT,
            "REPAIR": EffectType.FILE_EDIT,
            "LOCAL_COMMIT": EffectType.LOCAL_COMMIT,
            "COMMAND": EffectType.COMMAND,
            "EXPERIMENT": EffectType.COMMAND,
            "TEST": EffectType.COMMAND,
            "DATABASE_MIGRATION": EffectType.DATABASE_MIGRATION,
            "PUSH": EffectType.PUSH,
            "EXTERNAL": EffectType.EXTERNAL,
        }
        expected_effect_type = expected_effect_types[action.action_type.value]
        if effect.effect_type != expected_effect_type:
            raise AuthorizationError("effect type does not match the action type")

    @staticmethod
    def _assert_effect_observation_matches_intent(
        intent: EffectRecord,
        observation: EffectRecord,
    ) -> None:
        immutable_fields = (
            "id",
            "run_id",
            "action_id",
            "scope",
            "target",
            "effect_type",
            "reversibility",
            "compensation_handler",
            "idempotency_key",
            "created_at",
        )
        for field_name in immutable_fields:
            if getattr(intent, field_name) != getattr(observation, field_name):
                raise IntegrityError(f"effect observation changed immutable {field_name}")
        for field_name in (
            "before_hash",
            "after_hash",
            "forward_artifact_digest",
            "reverse_artifact_digest",
        ):
            expected = getattr(intent, field_name)
            observed = getattr(observation, field_name)
            if expected is not None and expected != observed:
                raise IntegrityError(f"effect observation contradicts planned {field_name}")
        for key, value in intent.metadata.items():
            if observation.metadata.get(key) != value:
                raise IntegrityError(f"effect observation changed planned metadata key {key}")
        if intent.dispatched_at is None:
            raise IntegrityError("dispatching effect intent has no dispatch timestamp")

    def _reconcile_authoritative_graph_locked(
        self,
        run_id: str,
        *,
        at: datetime,
        connection: sqlite3.Connection,
    ) -> None:
        """Project relational premise/warrant/action/effect bindings into hard graph edges."""

        bindings = connection.execute(
            """
            SELECT wp.warrant_id, wp.premise_id, p.scope, w.scope AS warrant_scope
              FROM warrant_premises AS wp
              JOIN warrants AS w ON w.id = wp.warrant_id
              JOIN premises AS p ON p.id = wp.premise_id
             WHERE w.run_id = ? AND p.run_id = ?
             ORDER BY wp.warrant_id, wp.premise_id
            """,
            (run_id, run_id),
        ).fetchall()
        scopes_by_warrant: dict[str, str] = {}
        for row in bindings:
            warrant_id = str(row["warrant_id"])
            premise_id = str(row["premise_id"])
            scope = str(row["scope"])
            if str(row["warrant_scope"]) != scope:
                raise IntegrityError("warrant scope differs from its authoritative premise")
            existing_scope = scopes_by_warrant.setdefault(warrant_id, scope)
            if existing_scope != scope:
                raise IntegrityError("one warrant cannot span multiple causal scopes")
            premise_node = self._ensure_authoritative_node_locked(
                connection,
                run_id=run_id,
                kind=NodeKind.PREMISE,
                entity_id=premise_id,
                scope=scope,
                at=at,
            )
            warrant_node = self._ensure_authoritative_node_locked(
                connection,
                run_id=run_id,
                kind=NodeKind.WARRANT,
                entity_id=warrant_id,
                scope=scope,
                at=at,
            )
            self._ensure_authoritative_edge_locked(
                connection,
                run_id=run_id,
                source=premise_node,
                target=warrant_node,
                scope=scope,
                at=at,
            )

        actions = self.list_actions(run_id, connection=connection)
        action_nodes: dict[str, GraphNode] = {}
        for action in actions:
            action_scope = scopes_by_warrant.get(action.warrant_id)
            if action_scope is None:
                continue
            if action.scope != action_scope:
                raise IntegrityError("action scope differs from its authoritative warrant")
            warrant_node = self._require(
                self.find_graph_node(
                    run_id,
                    NodeKind.WARRANT.value,
                    action.warrant_id,
                    connection=connection,
                ),
                "warrant graph node",
                action.warrant_id,
            )
            action_node = self._ensure_authoritative_node_locked(
                connection,
                run_id=run_id,
                kind=NodeKind.ACTION,
                entity_id=action.id,
                scope=action_scope,
                at=at,
            )
            action_nodes[action.id] = action_node
            self._ensure_authoritative_edge_locked(
                connection,
                run_id=run_id,
                source=warrant_node,
                target=action_node,
                scope=action_scope,
                at=at,
            )

        for effect in self.list_effects(run_id, connection=connection):
            effect_action_node = action_nodes.get(effect.action_id)
            if effect_action_node is None:
                continue
            if effect.scope != effect_action_node.scope:
                raise IntegrityError("effect scope differs from its authoritative action")
            effect_node = self._ensure_authoritative_node_locked(
                connection,
                run_id=run_id,
                kind=NodeKind.EFFECT,
                entity_id=effect.id,
                scope=effect_action_node.scope,
                at=at,
            )
            self._ensure_authoritative_edge_locked(
                connection,
                run_id=run_id,
                source=effect_action_node,
                target=effect_node,
                scope=effect_action_node.scope,
                at=at,
            )

    def _ensure_authoritative_node_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        kind: NodeKind,
        entity_id: str,
        scope: str,
        at: datetime,
    ) -> GraphNode:
        existing = self.find_graph_node(
            run_id,
            kind.value,
            entity_id,
            connection=connection,
        )
        if existing is not None:
            if existing.scope != scope:
                raise IntegrityError(
                    f"authoritative {kind.value} graph node has mismatched scope"
                )
            return existing
        digest = hashlib.sha256(f"{run_id}\0{kind.value}\0{entity_id}".encode()).hexdigest()
        node = GraphNode(
            id=f"node:auto:{digest}",
            run_id=run_id,
            kind=kind,
            entity_id=entity_id,
            scope=scope,
            created_at=at,
            metadata={"derived_from": "authoritative-relational-binding"},
        )
        return self._create(
            table="graph_nodes",
            values={
                "id": node.id,
                "run_id": node.run_id,
                "kind": node.kind.value,
                "entity_id": node.entity_id,
                "scope": node.scope,
                "created_at": _iso(node.created_at),
                "metadata_json": canonical_json(node.metadata),
            },
            model=node,
            run_id=run_id,
            event_kind="graph.node_derived",
            aggregate_type="graph_node",
            connection=connection,
        )

    def _ensure_authoritative_edge_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        source: GraphNode,
        target: GraphNode,
        scope: str,
        at: datetime,
    ) -> DependencyEdge:
        row = connection.execute(
            """
            SELECT * FROM dependency_edges
             WHERE run_id = ? AND source_node_id = ? AND target_node_id = ?
               AND edge_type = 'REQUIRES' AND scope = ?
            """,
            (run_id, source.id, target.id, scope),
        ).fetchone()
        if row is not None:
            existing = self._edge_from_row(row)
            if existing.strength != EdgeStrength.HARD:
                raise IntegrityError("authoritative causal edge was weakened")
            return existing
        digest = hashlib.sha256(
            f"{run_id}\0{source.id}\0{target.id}\0REQUIRES\0{scope}".encode()
        ).hexdigest()
        edge = DependencyEdge(
            id=f"edge:auto:{digest}",
            run_id=run_id,
            source_node_id=source.id,
            target_node_id=target.id,
            edge_type=EdgeType.REQUIRES,
            strength=EdgeStrength.HARD,
            scope=scope,
            declared_by="store.authoritative-relations",
            confidence=1.0,
            created_at=at,
            metadata={"derived_from": "authoritative-relational-binding"},
        )
        return self._create(
            table="dependency_edges",
            values={
                "id": edge.id,
                "run_id": edge.run_id,
                "source_node_id": edge.source_node_id,
                "target_node_id": edge.target_node_id,
                "edge_type": edge.edge_type.value,
                "strength": edge.strength.value,
                "scope": edge.scope,
                "declared_by": edge.declared_by,
                "confidence": edge.confidence,
                "created_at": _iso(edge.created_at),
                "metadata_json": canonical_json(edge.metadata),
            },
            model=edge,
            run_id=run_id,
            event_kind="graph.edge_derived",
            aggregate_type="dependency_edge",
            connection=connection,
        )

    def _assert_authoritative_path_locked(
        self,
        connection: sqlite3.Connection,
        *,
        action: ActionIntent,
        effect: EffectRecord,
    ) -> None:
        links = self.list_warrant_premises(action.warrant_id, connection=connection)
        if not links:
            raise AuthorizationError("warrant has no authoritative premise binding")
        for link in links:
            premise = self._require(
                self.get_premise(link.premise_id, connection=connection),
                "premise",
                link.premise_id,
            )
            root = self._require(
                self.find_graph_node(
                    action.run_id,
                    NodeKind.PREMISE.value,
                    premise.id,
                    connection=connection,
                ),
                "premise graph node",
                premise.id,
            )
            closure = self.hard_dependency_closure(
                run_id=action.run_id,
                root_node_id=root.id,
                scope=premise.scope,
                connection=connection,
            )
            reachable = {(node.kind, node.entity_id) for node, _ in closure}
            if (NodeKind.WARRANT, action.warrant_id) not in reachable:
                raise AuthorizationError("authoritative premise-to-warrant path is missing")
            if (NodeKind.ACTION, action.id) not in reachable:
                raise AuthorizationError("authoritative warrant-to-action path is missing")
            if (NodeKind.EFFECT, effect.id) not in reachable:
                raise AuthorizationError("authoritative action-to-effect path is missing")

    def _assert_action_warrant_locked(
        self,
        connection: sqlite3.Connection,
        action: ActionIntent,
        warrant: Warrant,
        *,
        expected_warrant_epoch: int,
        at: datetime,
    ) -> None:
        if warrant.id != action.warrant_id or warrant.run_id != action.run_id:
            raise AuthorizationError("action is not bound to this warrant")
        if action.scope != warrant.scope:
            raise AuthorizationError("action scope does not match its warrant")
        if action.target not in warrant.authorized_targets:
            raise AuthorizationError("action target is not authorized by its warrant")
        if warrant.agent_id is not None and warrant.agent_id != action.agent_id:
            raise AuthorizationError("warrant belongs to another agent")
        if warrant.state != WarrantState.AUTHORIZED:
            raise AuthorizationError("warrant is not authorized")
        if warrant.revision_epoch != expected_warrant_epoch:
            raise StaleWarrantError(
                f"warrant epoch is {warrant.revision_epoch}, expected {expected_warrant_epoch}"
            )
        if warrant.issued_at > at or warrant.expires_at <= at:
            raise AuthorizationError("warrant is expired or not yet valid")
        links = self.list_warrant_premises(warrant.id, connection=connection)
        if not links:
            raise AuthorizationError("warrant must bind at least one authoritative premise")
        expected_vector = {link.premise_id: link.premise_digest for link in links}
        if dict(action.premise_vector) != expected_vector:
            raise StaleWarrantError("action premise vector is not the exact warrant vector")
        for link in links:
            premise = self._require(
                self.get_premise(link.premise_id, connection=connection),
                "premise",
                link.premise_id,
            )
            if premise.state != PremiseState.ACTIVE:
                raise StaleWarrantError(f"premise {premise.id} is no longer active")
            if premise.value_digest != link.premise_digest:
                raise StaleWarrantError(f"premise {premise.id} digest changed")
        if dict(action.artifact_vector) != dict(warrant.artifact_hashes):
            raise AuthorizationError("action artifact vector does not match its warrant")
        for test_id in warrant.required_tests:
            test = self.get_test_run(test_id, connection=connection)
            if test is None or test.state != TestState.PASSED:
                raise AuthorizationError(f"required test {test_id} has not passed")

    def _fence_warrants_locked(
        self,
        connection: sqlite3.Connection,
        warrant_ids: Iterable[str],
        *,
        at: datetime,
    ) -> None:
        eligible = {
            WarrantState.DECLARED,
            WarrantState.PREPARED,
            WarrantState.AUTHORIZED,
        }
        for warrant_id in sorted(set(warrant_ids)):
            warrant = self._require(
                self.get_warrant(warrant_id, connection=connection), "warrant", warrant_id
            )
            new_epoch = warrant.revision_epoch + 1
            target = WarrantState.REVOKE_PENDING if warrant.state in eligible else warrant.state
            if target != warrant.state:
                ensure_transition(warrant.state, target)
            connection.execute(
                "UPDATE warrants SET revision_epoch = ?, state = ? WHERE id = ?",
                (new_epoch, target.value, warrant.id),
            )
            self.journal.append(
                run_id=warrant.run_id,
                kind="warrant.fenced",
                aggregate_type="warrant",
                aggregate_id=warrant.id,
                payload={
                    "from_state": warrant.state.value,
                    "to_state": target.value,
                    "from_epoch": warrant.revision_epoch,
                    "to_epoch": new_epoch,
                    "at": at,
                },
                connection=connection,
            )

    def _fence_actions_locked(
        self,
        connection: sqlite3.Connection,
        action_ids: Iterable[str],
        *,
        at: datetime,
    ) -> None:
        eligible = {
            ActionState.DECLARED,
            ActionState.PREPARED,
            ActionState.AUTHORIZED,
            ActionState.DISPATCHING,
            ActionState.EXECUTED,
        }
        for action_id in sorted(set(action_ids)):
            action = self._require(
                self.get_action(action_id, connection=connection), "action", action_id
            )
            if action.state not in eligible:
                continue
            ensure_transition(action.state, ActionState.REVOKE_PENDING)
            connection.execute(
                "UPDATE action_intents SET state = 'REVOKE_PENDING', updated_at = ? WHERE id = ?",
                (_iso(at), action.id),
            )
            self._append_transition(
                connection,
                action.run_id,
                "action",
                action.id,
                action.state,
                ActionState.REVOKE_PENDING,
            )

    def _fence_effects_locked(
        self,
        connection: sqlite3.Connection,
        effect_ids: Iterable[str],
        *,
        at: datetime,
    ) -> None:
        eligible = {
            EffectState.DECLARED,
            EffectState.PREPARED,
            EffectState.AUTHORIZED,
            EffectState.DISPATCHING,
            EffectState.EXECUTED,
        }
        for effect_id in sorted(set(effect_ids)):
            effect = self._require(
                self.get_effect(effect_id, connection=connection), "effect", effect_id
            )
            if effect.state not in eligible:
                continue
            ensure_transition(effect.state, EffectState.REVOKE_PENDING)
            connection.execute(
                "UPDATE effects SET state = 'REVOKE_PENDING', updated_at = ? WHERE id = ?",
                (_iso(at), effect.id),
            )
            self._append_transition(
                connection,
                effect.run_id,
                "effect",
                effect.id,
                effect.state,
                EffectState.REVOKE_PENDING,
            )

    def _revoke_leases_locked(
        self,
        connection: sqlite3.Connection,
        *,
        warrant_ids: Iterable[str],
        action_ids: Iterable[str],
        at: datetime,
    ) -> None:
        warrant_ids = sorted(set(warrant_ids))
        action_ids = sorted(set(action_ids))
        conditions: list[str] = []
        args: list[Any] = []
        if warrant_ids:
            conditions.append(f"warrant_id IN ({','.join('?' for _ in warrant_ids)})")
            args.extend(warrant_ids)
        if action_ids:
            conditions.append(f"action_id IN ({','.join('?' for _ in action_ids)})")
            args.extend(action_ids)
        if not conditions:
            return
        condition_sql = " OR ".join(conditions)
        rows = connection.execute(
            f"""
            SELECT * FROM execution_leases
             WHERE state = 'ACTIVE' AND ({condition_sql}) ORDER BY id
            """,
            args,
        ).fetchall()
        for row in rows:
            lease = self._lease_from_row(row)
            ensure_transition(lease.state, LeaseState.REVOKED)
            connection.execute(
                "UPDATE execution_leases SET state = 'REVOKED', revoked_at = ? WHERE id = ?",
                (_iso(at), lease.id),
            )
            self._append_transition(
                connection,
                lease.run_id,
                "lease",
                lease.id,
                lease.state,
                LeaseState.REVOKED,
            )

    def _append_transition(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        aggregate_type: str,
        aggregate_id: str,
        current: Any,
        target: Any,
    ) -> None:
        current_value = current.value if hasattr(current, "value") else str(current)
        target_value = target.value if hasattr(target, "value") else str(target)
        self.journal.append(
            run_id=run_id,
            kind=f"{aggregate_type}.transitioned",
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload={"from": current_value, "to": target_value},
            connection=connection,
        )

    @staticmethod
    def _require(value: ModelT | None, kind: str, identifier: str) -> ModelT:
        if value is None:
            raise ValidationError(f"{kind} {identifier} does not exist")
        return value

    # SQL value serializers ---------------------------------------------

    @staticmethod
    def _premise_values(premise: Premise) -> dict[str, Any]:
        return {
            "id": premise.id,
            "run_id": premise.run_id,
            "scope": premise.scope,
            "subject": premise.subject,
            "relation": premise.relation,
            "value_json": canonical_json(premise.value),
            "value_digest": premise.value_digest,
            "semantics": premise.semantics.value,
            "state": premise.state.value,
            "valid_at": _iso(premise.valid_at),
            "invalid_at": _iso(premise.invalid_at),
            "invalidated_by_evidence_id": premise.invalidated_by_evidence_id,
            "replaces_premise_id": premise.replaces_premise_id,
            "created_at": _iso(premise.created_at),
            "metadata_json": canonical_json(premise.metadata),
        }

    @staticmethod
    def _warrant_values(warrant: Warrant) -> dict[str, Any]:
        return {
            "id": warrant.id,
            "run_id": warrant.run_id,
            "agent_id": warrant.agent_id,
            "scope": warrant.scope,
            "authorized_targets_json": canonical_json(warrant.authorized_targets),
            "state": warrant.state.value,
            "risk": warrant.risk.value,
            "revision_epoch": warrant.revision_epoch,
            "artifact_hashes_json": canonical_json(warrant.artifact_hashes),
            "required_tests_json": canonical_json(warrant.required_tests),
            "issued_at": _iso(warrant.issued_at),
            "expires_at": _iso(warrant.expires_at),
            "revoked_at": _iso(warrant.revoked_at),
            "revoke_cause": warrant.revoke_cause,
            "replaces_warrant_id": warrant.replaces_warrant_id,
            "metadata_json": canonical_json(warrant.metadata),
        }

    @staticmethod
    def _action_values(action: ActionIntent) -> dict[str, Any]:
        return {
            "id": action.id,
            "run_id": action.run_id,
            "agent_id": action.agent_id,
            "warrant_id": action.warrant_id,
            "scope": action.scope,
            "action_type": action.action_type.value,
            "target": action.target,
            "payload_digest": action.payload_digest,
            "premise_vector_json": canonical_json(action.premise_vector),
            "artifact_vector_json": canonical_json(action.artifact_vector),
            "risk": action.risk.value,
            "reversibility": action.reversibility.value,
            "state": action.state.value,
            "not_before": _iso(action.not_before),
            "lease_id": action.lease_id,
            "idempotency_key": action.idempotency_key,
            "replaces_action_id": action.replaces_action_id,
            "created_at": _iso(action.created_at),
            "updated_at": _iso(action.updated_at),
            "dispatched_at": _iso(action.dispatched_at),
            "completed_at": _iso(action.completed_at),
            "failure_reason": action.failure_reason,
            "metadata_json": canonical_json(action.metadata),
        }

    @staticmethod
    def _effect_values(effect: EffectRecord) -> dict[str, Any]:
        return {
            "id": effect.id,
            "run_id": effect.run_id,
            "action_id": effect.action_id,
            "scope": effect.scope,
            "target": effect.target,
            "effect_type": effect.effect_type.value,
            "before_hash": effect.before_hash,
            "after_hash": effect.after_hash,
            "forward_artifact_digest": effect.forward_artifact_digest,
            "reverse_artifact_digest": effect.reverse_artifact_digest,
            "reversibility": effect.reversibility.value,
            "compensation_handler": effect.compensation_handler,
            "state": effect.state.value,
            "created_at": _iso(effect.created_at),
            "updated_at": _iso(effect.updated_at),
            "dispatched_at": _iso(effect.dispatched_at),
            "compensated_at": _iso(effect.compensated_at),
            "compensation_attempts": effect.compensation_attempts,
            "idempotency_key": effect.idempotency_key,
            "metadata_json": canonical_json(effect.metadata),
        }

    @staticmethod
    def _lease_values(lease: ExecutionLease) -> dict[str, Any]:
        return {
            "id": lease.id,
            "run_id": lease.run_id,
            "action_id": lease.action_id,
            "effect_id": lease.effect_id,
            "warrant_id": lease.warrant_id,
            "epoch": lease.epoch,
            "token_digest": lease.token_digest,
            "state": lease.state.value,
            "issued_at": _iso(lease.issued_at),
            "expires_at": _iso(lease.expires_at),
            "consumed_at": _iso(lease.consumed_at),
            "revoked_at": _iso(lease.revoked_at),
            "idempotency_key": lease.idempotency_key,
            "metadata_json": canonical_json(lease.metadata),
        }

    @staticmethod
    def _dispatch_reconciliation_values(
        record: DispatchReconciliationRecord,
    ) -> dict[str, Any]:
        return {
            "id": record.id,
            "run_id": record.run_id,
            "action_id": record.action_id,
            "effect_id": record.effect_id,
            "adapter": record.adapter,
            "outcome": record.outcome.value,
            "expected_json": canonical_json(record.expected),
            "observed_json": canonical_json(record.observed),
            "reason": record.reason,
            "reconciled_at": _iso(record.reconciled_at),
            "metadata_json": canonical_json(record.metadata),
        }

    @staticmethod
    def _case_values(case: RevocationCase) -> dict[str, Any]:
        return {
            "id": case.id,
            "run_id": case.run_id,
            "premise_id": case.premise_id,
            "trigger_evidence_id": case.trigger_evidence_id,
            "state": case.state.value,
            "reason": case.reason,
            "opened_at": _iso(case.opened_at),
            "updated_at": _iso(case.updated_at),
            "closed_at": _iso(case.closed_at),
            "metadata_json": canonical_json(case.metadata),
        }

    @staticmethod
    def _member_values(member: RevocationMember) -> dict[str, Any]:
        return {
            "case_id": member.case_id,
            "node_id": member.node_id,
            "member_kind": member.member_kind.value,
            "entity_id": member.entity_id,
            "dependency_path_json": canonical_json(member.dependency_path),
            "created_at": _iso(member.created_at),
        }

    @staticmethod
    def _candidate_values(candidate: ExperimentCandidate) -> dict[str, Any]:
        return {
            "id": candidate.id,
            "run_id": candidate.run_id,
            "case_id": candidate.case_id,
            "hypotheses_json": canonical_json(candidate.hypotheses),
            "predictions_json": canonical_json(candidate.predictions),
            "argv_json": canonical_json(candidate.argv),
            "fixture_refs_json": canonical_json(candidate.fixture_refs),
            "touched_files_json": canonical_json(candidate.touched_files),
            "risk": candidate.risk.value,
            "estimated_runtime_ms": candidate.estimated_runtime_ms,
            "command_count": candidate.command_count,
            "state": candidate.state.value,
            "rejection_reason": candidate.rejection_reason,
            "score_json": canonical_json(candidate.score) if candidate.score is not None else None,
            "created_at": _iso(candidate.created_at),
            "metadata_json": canonical_json(candidate.metadata),
        }

    @staticmethod
    def _experiment_values(experiment: ExperimentRun) -> dict[str, Any]:
        return {
            "id": experiment.id,
            "run_id": experiment.run_id,
            "case_id": experiment.case_id,
            "candidate_id": experiment.candidate_id,
            "action_id": experiment.action_id,
            "state": experiment.state.value,
            "started_at": _iso(experiment.started_at),
            "finished_at": _iso(experiment.finished_at),
            "exit_code": experiment.exit_code,
            "stdout_artifact_digest": experiment.stdout_artifact_digest,
            "stderr_artifact_digest": experiment.stderr_artifact_digest,
            "environment_digest": experiment.environment_digest,
            "observed_outcome_json": canonical_json(experiment.observed_outcome)
            if experiment.observed_outcome is not None
            else None,
            "metadata_json": canonical_json(experiment.metadata),
        }

    @staticmethod
    def _test_values(test: TestRun) -> dict[str, Any]:
        return {
            "id": test.id,
            "run_id": test.run_id,
            "case_id": test.case_id,
            "action_id": test.action_id,
            "kind": test.kind.value,
            "argv_json": canonical_json(test.argv),
            "state": test.state.value,
            "started_at": _iso(test.started_at),
            "finished_at": _iso(test.finished_at),
            "exit_code": test.exit_code,
            "stdout_artifact_digest": test.stdout_artifact_digest,
            "stderr_artifact_digest": test.stderr_artifact_digest,
            "environment_digest": test.environment_digest,
            "metadata_json": canonical_json(test.metadata),
        }

    @staticmethod
    def _receipt_values(receipt: Receipt) -> dict[str, Any]:
        return {
            "id": receipt.id,
            "run_id": receipt.run_id,
            "case_id": receipt.case_id,
            "state": receipt.state.value,
            "artifact_digest": receipt.artifact_digest,
            "canonical_digest": receipt.canonical_digest,
            "event_head_digest": receipt.event_head_digest,
            "manifest_digest": receipt.manifest_digest,
            "created_at": _iso(receipt.created_at),
            "verified_at": _iso(receipt.verified_at),
            "metadata_json": canonical_json(receipt.metadata),
        }

    # SQL row decoders ---------------------------------------------------

    @staticmethod
    def _decode_row(
        row: sqlite3.Row,
        *json_fields: tuple[str, str, Any],
    ) -> dict[str, Any]:
        values = dict(row)
        for column, field, default in json_fields:
            values[field] = _loads(values.pop(column), default)
        return values

    @classmethod
    def _run_from_row(cls, row: sqlite3.Row) -> Run:
        return Run.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _agent_from_row(cls, row: sqlite3.Row) -> Agent:
        return Agent.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _session_from_row(cls, row: sqlite3.Row) -> AgentSession:
        return AgentSession.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _evidence_source_from_row(cls, row: sqlite3.Row) -> EvidenceSource:
        return EvidenceSource.model_validate(
            cls._decode_row(row, ("metadata_json", "metadata", {}))
        )

    @classmethod
    def _artifact_from_row(cls, row: sqlite3.Row) -> ArtifactRef:
        return ArtifactRef.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _evidence_from_row(cls, row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord.model_validate(
            cls._decode_row(
                row,
                ("normalized_premises_json", "normalized_premises", []),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _premise_from_row(cls, row: sqlite3.Row) -> Premise:
        return Premise.model_validate(
            cls._decode_row(
                row,
                ("value_json", "value", None),
                ("metadata_json", "metadata", {}),
            )
        )

    @staticmethod
    def _premise_evidence_from_row(row: sqlite3.Row) -> PremiseEvidence:
        return PremiseEvidence.model_validate(dict(row))

    @classmethod
    def _graph_node_from_row(cls, row: sqlite3.Row) -> GraphNode:
        return GraphNode.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _edge_from_row(cls, row: sqlite3.Row) -> DependencyEdge:
        return DependencyEdge.model_validate(
            cls._decode_row(row, ("metadata_json", "metadata", {}))
        )

    @classmethod
    def _warrant_from_row(cls, row: sqlite3.Row) -> Warrant:
        return Warrant.model_validate(
            cls._decode_row(
                row,
                ("authorized_targets_json", "authorized_targets", []),
                ("artifact_hashes_json", "artifact_hashes", {}),
                ("required_tests_json", "required_tests", []),
                ("metadata_json", "metadata", {}),
            )
        )

    @staticmethod
    def _warrant_premise_from_row(row: sqlite3.Row) -> WarrantPremise:
        return WarrantPremise.model_validate(dict(row))

    @classmethod
    def _action_from_row(cls, row: sqlite3.Row) -> ActionIntent:
        return ActionIntent.model_validate(
            cls._decode_row(
                row,
                ("premise_vector_json", "premise_vector", {}),
                ("artifact_vector_json", "artifact_vector", {}),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _effect_from_row(cls, row: sqlite3.Row) -> EffectRecord:
        return EffectRecord.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))

    @classmethod
    def _lease_from_row(cls, row: sqlite3.Row) -> ExecutionLease:
        return ExecutionLease.model_validate(
            cls._decode_row(row, ("metadata_json", "metadata", {}))
        )

    @classmethod
    def _dispatch_reconciliation_from_row(
        cls,
        row: sqlite3.Row,
    ) -> DispatchReconciliationRecord:
        return DispatchReconciliationRecord.model_validate(
            cls._decode_row(
                row,
                ("expected_json", "expected", {}),
                ("observed_json", "observed", {}),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _case_from_row(cls, row: sqlite3.Row) -> RevocationCase:
        return RevocationCase.model_validate(
            cls._decode_row(row, ("metadata_json", "metadata", {}))
        )

    @classmethod
    def _member_from_row(cls, row: sqlite3.Row) -> RevocationMember:
        return RevocationMember.model_validate(
            cls._decode_row(row, ("dependency_path_json", "dependency_path", []))
        )

    @classmethod
    def _candidate_from_row(cls, row: sqlite3.Row) -> ExperimentCandidate:
        return ExperimentCandidate.model_validate(
            cls._decode_row(
                row,
                ("hypotheses_json", "hypotheses", []),
                ("predictions_json", "predictions", {}),
                ("argv_json", "argv", []),
                ("fixture_refs_json", "fixture_refs", []),
                ("touched_files_json", "touched_files", []),
                ("score_json", "score", None),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _experiment_from_row(cls, row: sqlite3.Row) -> ExperimentRun:
        return ExperimentRun.model_validate(
            cls._decode_row(
                row,
                ("observed_outcome_json", "observed_outcome", None),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _test_from_row(cls, row: sqlite3.Row) -> TestRun:
        return TestRun.model_validate(
            cls._decode_row(
                row,
                ("argv_json", "argv", []),
                ("metadata_json", "metadata", {}),
            )
        )

    @classmethod
    def _receipt_from_row(cls, row: sqlite3.Row) -> Receipt:
        return Receipt.model_validate(cls._decode_row(row, ("metadata_json", "metadata", {})))


SQLiteStore = Store
