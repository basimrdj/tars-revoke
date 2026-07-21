from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from tars_revoke.domain.canonical import (
    canonical_digest,
    canonical_json,
    verify_digest,
)
from tars_revoke.domain.enums import ExperimentState, PremiseState, RiskLevel, ValueSemantics
from tars_revoke.domain.models import ExperimentCandidate, Premise, Run
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence import ArtifactStore, Database, Store


def test_canonical_json_is_stable_across_order_timezone_and_sets() -> None:
    left = {
        "z": {"beta", "alpha"},
        "when": datetime(2026, 7, 14, 17, 0, tzinfo=timezone(timedelta(hours=5))),
        "a": -0.0,
    }
    right = {
        "a": 0.0,
        "when": datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
        "z": {"alpha", "beta"},
    }

    assert canonical_json(left) == canonical_json(right)
    assert canonical_digest(left) == canonical_digest(right)
    verify_digest(left, canonical_digest(right))


def test_canonicalization_rejects_ambiguous_values() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        canonical_json(datetime(2026, 7, 14))
    with pytest.raises(ValidationError, match="finite"):
        canonical_json(float("nan"))
    with pytest.raises(ValidationError, match="keys must be strings"):
        canonical_json({1: "ambiguous"})
    with pytest.raises(IntegrityError, match="digest mismatch"):
        verify_digest({"a": 1}, "0" * 64)


def test_premise_digest_is_computed_validated_and_model_is_frozen(now: datetime) -> None:
    premise = Premise(
        id="premise-1",
        run_id="run-1",
        scope="repo:billing",
        subject="Customer.id",
        relation="serialization",
        value={"kind": "uuid"},
        semantics=ValueSemantics.SINGLE,
        state=PremiseState.ACTIVE,
        valid_at=now,
        created_at=now,
    )

    assert premise.value_digest == canonical_digest({"kind": "uuid"})
    with pytest.raises(PydanticValidationError, match="value_digest"):
        premise.model_copy(update={"value_digest": "f" * 64}).model_validate(
            {**premise.model_dump(), "value_digest": "f" * 64}
        )
    with pytest.raises(PydanticValidationError, match="frozen"):
        premise.state = PremiseState.INVALIDATED  # type: ignore[misc]


def test_experiment_argv_preserves_opaque_argument_whitespace(now: datetime) -> None:
    observer = "print('probe')\n"
    candidate = ExperimentCandidate(
        id="candidate-1",
        run_id="run-1",
        case_id="case-1",
        hypotheses=("uuid", "opaque"),
        predictions={"uuid": "reject", "opaque": "accept"},
        argv=("python", "-c", observer),
        risk=RiskLevel.LOW,
        estimated_runtime_ms=10,
        state=ExperimentState.PROPOSED,
        created_at=now,
    )

    assert candidate.argv[2] == observer


def test_content_addressed_artifacts_are_idempotent_and_tamper_evident(
    tmp_path, now: datetime
) -> None:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    first = artifacts.put_json({"b": 2, "a": 1})
    second = artifacts.put_json({"a": 1, "b": 2})

    assert first.digest == second.digest
    assert artifacts.get_bytes(first.digest) == b'{"a":1,"b":2}'
    path = artifacts.path_for(first.digest)
    os.chmod(path, 0o640)
    path.write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="modified"):
        artifacts.verify(first.digest)


def test_schema_is_complete_and_every_mutation_has_event_and_outbox(
    store: Store, now: datetime
) -> None:
    expected_tables = {
        "runs",
        "agents",
        "agent_sessions",
        "artifacts",
        "evidence_sources",
        "evidence_records",
        "premises",
        "premise_evidence",
        "graph_nodes",
        "dependency_edges",
        "warrants",
        "warrant_premises",
        "action_intents",
        "effects",
        "execution_leases",
        "revocation_cases",
        "revocation_members",
        "experiment_candidates",
        "experiment_runs",
        "test_runs",
        "events",
        "outbox",
        "receipts",
    }
    with store.database.connection(readonly=True) as connection:
        actual = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert expected_tables <= actual

    run = Run(
        id="run-1",
        name="demo",
        root_path="/tmp/demo",
        created_at=now,
        updated_at=now,
    )
    store.create_run(run)
    events = store.journal.list_events(run.id)
    assert [event.kind for event in events] == ["run.created"]
    assert store.journal.verify_chain(run.id) == events[-1].event_hash
    claimed = store.journal.claim_outbox()
    assert len(claimed) == 1
    assert claimed[0].event_id == events[0].id
    store.journal.mark_outbox_published(claimed[0].id)
    store.database.integrity_check()


def test_database_uses_wal_and_immediate_transactions(tmp_path) -> None:
    database = Database(tmp_path / "db.sqlite3")
    database.initialize()
    with database.connection() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert database.schema_version() == 1
