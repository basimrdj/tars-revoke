from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from tars_revoke.clock import FakeClock
from tars_revoke.demo.crashbench import (
    CRASH_STAGES,
    PRODUCER_PROTOCOL,
    RECOVERY_TIME,
    REPORT_PROTOCOL,
    run_crashbench_suite,
)
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import ActionState, EffectState, LeaseState, RevocationCaseState
from tars_revoke.persistence.database import Database
from tars_revoke.persistence.event_journal import EventJournal

MappingRecord = dict[str, Any]


def _state(path: Path, table: str, identifier: str) -> str:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        row = connection.execute(
            f"SELECT state FROM {table} WHERE id = ?", (identifier,)
        ).fetchone()
    assert row is not None
    return str(row[0])


async def test_crashbench_executes_all_stages_and_emits_self_verifying_databases(
    tmp_path: Path,
) -> None:
    report = dict(await run_crashbench_suite(tmp_path))

    assert set(report) == {
        "protocol",
        "schema_version",
        "suite",
        "stage_count",
        "generated_at",
        "passed",
        "artifact_root",
        "report_path",
        "producer",
        "methodology",
        "stages",
        "report_digest",
    }
    assert report["protocol"] == REPORT_PROTOCOL
    assert report["schema_version"] == 1
    assert report["suite"] == "CrashBench-11"
    assert report["stage_count"] == 11
    assert report["passed"] is True
    unsigned = dict(report)
    report_digest = unsigned.pop("report_digest")
    assert report_digest == canonical_digest(unsigned)

    artifact_root = Path(report["artifact_root"])
    report_path = Path(report["report_path"])
    assert report_path == artifact_root / "report.json"
    assert report_path.read_bytes() == f"{canonical_json(report)}\n".encode()
    assert json.loads(report_path.read_text(encoding="utf-8")) == report

    producer = report["producer"]
    assert producer["protocol"] == PRODUCER_PROTOCOL
    assert producer["entrypoint"] == "tars_revoke.demo.crashbench:run_crashbench_suite"
    assert producer["command"]["canonical_argv"] == [
        "tars-revoke",
        "bench",
        "--suite",
        "CrashBench-11",
        "--output-root",
        "<OUTPUT_ROOT>",
    ]
    assert producer["command"]["observed_argv_sha256"] == canonical_digest(
        producer["command"]["observed_argv"]
    )
    source = producer["source"]
    assert source["path"] == "src/tars_revoke/demo/crashbench.py"
    assert source["artifact_path"] == "producer/source/crashbench.py"
    source_artifact = artifact_root / source["artifact_path"]
    source_bytes = source_artifact.read_bytes()
    assert source_bytes == Path(__file__).parents[2].joinpath(source["path"]).read_bytes()
    assert source["sha256"] == sha256_digest(source_bytes)
    assert source["size"] == len(source_bytes)

    rows: list[dict[str, Any]] = report["stages"]
    assert [row["stage_index"] for row in rows] == list(range(11))
    assert [row["stage"] for row in rows] == [stage.value for stage in CRASH_STAGES]
    expected_files = {"report.json", source["artifact_path"]}
    for stage, row in zip(CRASH_STAGES, rows, strict=True):
        assert set(row) == {
            "stage_index",
            "stage",
            "run_id",
            "case_id",
            "entities",
            "snapshots",
            "recovery",
            "invariants",
            "passed",
        }
        assert row["passed"] is True
        assert row["invariants"] and all(row["invariants"].values())
        entities = row["entities"]
        assert set(entities) == {
            "dispatch_action_id",
            "dispatch_effect_id",
            "orphan_lease_id",
            "compensation_effect_ids",
        }
        observations: dict[str, tuple[Path, MappingRecord]] = {}
        for phase in ("pre_restart", "after_first_recovery", "after_second_recovery"):
            snapshot = row["snapshots"][phase]
            assert set(snapshot) == {"path", "sha256", "size", "event_head", "event_count"}
            expected_files.add(snapshot["path"])
            path = artifact_root / snapshot["path"]
            payload = path.read_bytes()
            assert snapshot["sha256"] == sha256_digest(payload)
            assert snapshot["size"] == len(payload)
            assert not path.with_name(f"{path.name}-wal").exists()
            assert not path.with_name(f"{path.name}-shm").exists()
            database = Database(path)
            database.integrity_check()
            journal = EventJournal(database, clock=FakeClock(RECOVERY_TIME))
            events = journal.list_events(row["run_id"])
            assert snapshot["event_count"] == len(events)
            assert snapshot["event_head"] == journal.verify_chain(row["run_id"])
            assert _state(path, "revocation_cases", row["case_id"]) == stage.value
            assert (
                _state(path, "action_intents", entities["dispatch_action_id"])
                == ActionState.DISPATCHING.value
            )
            assert (
                _state(path, "effects", entities["dispatch_effect_id"])
                == EffectState.DISPATCHING.value
            )
            action_dispatches = [
                event
                for event in events
                if event.aggregate_type == "action"
                and event.aggregate_id == entities["dispatch_action_id"]
                and event.kind == "action.transitioned"
                and event.payload.get("to") == ActionState.DISPATCHING.value
            ]
            effect_dispatches = [
                event
                for event in events
                if event.aggregate_type == "effect"
                and event.aggregate_id == entities["dispatch_effect_id"]
                and event.kind == "effect.transitioned"
                and event.payload.get("to") == EffectState.DISPATCHING.value
            ]
            assert len(action_dispatches) == len(effect_dispatches) == 1
            observations[phase] = (path, snapshot)

        pre_path, pre = observations["pre_restart"]
        first_path, first = observations["after_first_recovery"]
        second_path, second = observations["after_second_recovery"]
        assert (
            _state(pre_path, "execution_leases", entities["orphan_lease_id"]) == LeaseState.ACTIVE
        )
        assert (
            _state(first_path, "execution_leases", entities["orphan_lease_id"])
            == LeaseState.EXPIRED
        )
        assert (
            _state(second_path, "execution_leases", entities["orphan_lease_id"])
            == LeaseState.EXPIRED
        )
        assert first["event_count"] == pre["event_count"] + 1
        assert second["event_count"] == first["event_count"]
        assert second["event_head"] == first["event_head"]
        assert second["sha256"] == first["sha256"]

        recovery = row["recovery"]
        assert recovery["first"]["expired_lease_count"] == 1
        assert recovery["second"]["expired_lease_count"] == 0
        for result in recovery.values():
            assert set(result) == {
                "schema_version",
                "event_head_digest",
                "expired_lease_count",
                "dispatching_action_ids",
                "dispatching_effect_ids",
                "dispatch_reconciliations",
                "incomplete_case_ids",
                "compensation_effect_ids",
                "receipt_rebuild_case_ids",
            }
            assert result["dispatching_action_ids"] == [entities["dispatch_action_id"]]
            assert result["dispatching_effect_ids"] == [entities["dispatch_effect_id"]]
            assert len(result["dispatch_reconciliations"]) == 1
            assert result["compensation_effect_ids"] == sorted(entities["compensation_effect_ids"])
        expected_incomplete = [] if stage == RevocationCaseState.CLOSED else [row["case_id"]]
        assert recovery["first"]["incomplete_case_ids"] == expected_incomplete
        expected_receipt = (
            [row["case_id"]]
            if stage
            in {
                RevocationCaseState.ATTESTED,
                RevocationCaseState.CLOSED,
                RevocationCaseState.ESCALATED,
            }
            else []
        )
        assert recovery["first"]["receipt_rebuild_case_ids"] == expected_receipt

    actual_files = {
        path.relative_to(artifact_root).as_posix()
        for path in artifact_root.rglob("*")
        if path.is_file()
    }
    assert actual_files == expected_files
    assert len(actual_files) == 35
