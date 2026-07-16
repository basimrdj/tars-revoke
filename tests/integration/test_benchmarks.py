from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from tars_revoke.demo.benchmarks import (
    BENCHMARK_OPERATIONS,
    PRODUCER_PROTOCOL,
    SCHEDULE_PROTOCOL,
    WORKER_TRACE_PROTOCOL,
    _run_trial,
    _validate_trial_record,
    derive_submission_order,
    run_benchmark_suite,
)
from tars_revoke.demo.release import _copy_benchmark_evidence
from tars_revoke.demo.release_proofs import verify_revokebench
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import ActionState, EffectState, PremiseState
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence.store import Store


@pytest.mark.slow
async def test_revoke_bench_executes_twenty_persisted_race_schedules(tmp_path: Path) -> None:
    report = dict(await run_benchmark_suite(tmp_path))

    assert report["suite"] == "RevokeBench-20"
    assert report["schema_version"] == 2
    assert report["trial_count"] == 20
    report_path = Path(report["report_path"])
    assert report_path.is_file()
    assert report_path.is_relative_to(tmp_path)
    assert json.loads(report_path.read_text(encoding="utf-8")) == report

    metrics = report["metrics"]
    assert metrics["unsafe_post_invalidation_dispatch_count"] == 0
    assert metrics["race_invariant_violation_count"] == 0
    assert metrics["revocation_set_precision_percent"] == 100.0
    assert metrics["revocation_set_recall_percent"] == 100.0
    assert metrics["unrelated_task_completion_percent"] == 100.0
    assert metrics["latency_ms"]["dispatch_p95"] >= 0.0
    assert metrics["latency_ms"]["invalidation_p95"] > 0.0

    targets = report["targets"]
    for name in (
        "unsafe_post_invalidation_dispatch",
        "revocation_set_precision",
        "revocation_set_recall",
        "canonical_subset_precision",
        "canonical_subset_recall",
        "unrelated_task_completion",
        "randomized_race_invariant_violations",
    ):
        assert targets[name]["passed"], name
    latency_target = targets["unrelated_task_p95_added_latency"]
    assert latency_target["passed"] == (latency_target["actual"] < latency_target["target"])
    assert report["passed"] == all(target["passed"] for target in targets.values())
    submission_orders = {trial["submission_order"] for trial in report["trials"]}
    assert len(submission_orders) >= 4
    assert len({trial["schedule_seed"] for trial in report["trials"]}) == 20
    assert "seeded randomized" in report["methodology"]["schedule"]
    assert report["methodology"]["schedule_protocol"] == SCHEDULE_PROTOCOL
    assert report["methodology"]["schedule_operations"] == list(BENCHMARK_OPERATIONS)
    assert report["methodology"]["worker_trace_protocol"] == WORKER_TRACE_PROTOCOL

    producer = report["producer"]
    assert producer["protocol"] == PRODUCER_PROTOCOL
    assert producer["entrypoint"] == "tars_revoke.demo.benchmarks:run_benchmark_suite"
    assert producer["source"]["path"] == "src/tars_revoke/demo/benchmarks.py"
    assert producer["source"]["artifact_path"] == "producer/benchmarks.py"
    assert len(producer["source"]["sha256"]) == 64
    assert producer["command"]["canonical_argv"] == [
        "tars-revoke",
        "bench",
        "--suite",
        "RevokeBench-20",
        "--output-root",
        "<OUTPUT_ROOT>",
    ]

    artifact_root = Path(report["artifact_root"])
    producer_source = artifact_root / producer["source"]["artifact_path"]
    assert producer_source.is_file()
    assert sha256_digest(producer_source.read_bytes()) == producer["source"]["sha256"]
    for trial in report["trials"]:
        expected_order = derive_submission_order(trial["schedule_seed"])
        assert trial["submission_order"] == "-".join(expected_order)
        trace = trial["worker_trace"]
        assert trace["protocol"] == WORKER_TRACE_PROTOCOL
        assert trace["participant_count"] == 3
        assert [worker["operation"] for worker in trace["workers"]] == list(expected_order)
        assert {worker["submission_ordinal"] for worker in trace["workers"]} == {0, 1, 2}
        assert {worker["barrier_ordinal"] for worker in trace["workers"]} == {0, 1, 2}
        assert len(
            {(worker["thread_name"], worker["thread_ident"]) for worker in trace["workers"]}
        ) == 3
        for worker in trace["workers"]:
            assert (
                0
                <= worker["ready_ns"]
                <= worker["released_ns"]
                == trace["barrier_release_ns"]
                <= worker["started_ns"]
                <= worker["ended_ns"]
            )
        database_path = artifact_root / trial["state_database"]
        assert database_path.is_file()
        store = Store(database_path)
        events = store.journal.list_events(trial["run_id"])
        invalidated_sequence = next(
            event.sequence
            for event in events
            if event.aggregate_type == "premise"
            and event.aggregate_id == trial["premise_id"]
            and event.kind == "premise.transitioned"
            and event.payload.get("to") == PremiseState.INVALIDATED.value
        )
        dispatch_sequences = [
            event.sequence
            for event in events
            if event.aggregate_type == "action"
            and event.aggregate_id == trial["race_action_id"]
            and event.kind == "action.transitioned"
            and event.payload.get("to") == ActionState.DISPATCHING.value
        ]
        assert all(sequence < invalidated_sequence for sequence in dispatch_sequences)
        assert trial["dispatch_sequences"] == dispatch_sequences
        assert trial["invalidation_sequence"] == invalidated_sequence
        assert store.get_action(trial["unrelated_action_id"]).state == ActionState.EXECUTED  # type: ignore[union-attr]
        assert store.get_effect(trial["unrelated_effect_id"]).state == EffectState.EXECUTED  # type: ignore[union-attr]
        assert store.journal.verify_chain(trial["run_id"]) == trial["event_head"]

        dispatch_worker = next(
            worker for worker in trace["workers"] if worker["operation"] == "dispatch"
        )
        dispatch_outcome = dispatch_worker["outcome"]
        assert (dispatch_outcome["status"] == "DISPATCHED") == trial[
            "dispatch_succeeded"
        ]
        assert dispatch_outcome["durable"]["observed_final_state"] == "REVOKE_PENDING"
        assert dispatch_outcome["durable"]["effect_observed_final_state"] == "REVOKE_PENDING"
        assert bool(trial["dispatch_sequences"]) == trial["dispatch_succeeded"]

    r19_paths = [
        report_path,
        producer_source,
        *(artifact_root / trial["state_database"] for trial in report["trials"]),
    ]
    manifest = {
        "manifest_version": 1,
        "requirements": {
            "R-19": [
                {
                    "path": path.relative_to(tmp_path).as_posix(),
                    "sha256": "0" * 64,
                    "size": path.stat().st_size,
                }
                for path in r19_paths
            ]
        },
    }
    assert verify_revokebench(tmp_path, manifest).valid
    release_root = tmp_path / "portable-release"
    release_root.mkdir()
    copied = _copy_benchmark_evidence(release_root, report_path=report_path)
    copied_manifest = {
        "manifest_version": 1,
        "requirements": {
            "R-19": [
                {
                    "path": path.relative_to(release_root).as_posix(),
                    "sha256": sha256_digest(path.read_bytes()),
                    "size": path.stat().st_size,
                }
                for path in copied
            ]
        },
    }
    assert verify_revokebench(release_root, copied_manifest).valid


@pytest.mark.slow
def test_revoke_bench_trial_evidence_rejects_schedule_trace_and_outcome_tampering(
    tmp_path: Path,
) -> None:
    (tmp_path / "state").mkdir()
    trial = _run_trial(tmp_path, 0)

    wrong_order = deepcopy(trial)
    wrong_order["submission_order"] = "dispatch-invalidate-unrelated"

    wrong_ordinal = deepcopy(trial)
    wrong_ordinal["worker_trace"]["workers"][0]["submission_ordinal"] = 2

    duplicate_worker = deepcopy(trial)
    duplicate_worker["worker_trace"]["workers"][1]["thread_name"] = duplicate_worker[
        "worker_trace"
    ]["workers"][0]["thread_name"]
    duplicate_worker["worker_trace"]["workers"][1]["thread_ident"] = duplicate_worker[
        "worker_trace"
    ]["workers"][0]["thread_ident"]

    backwards_clock = deepcopy(trial)
    backwards_clock["worker_trace"]["workers"][0]["ready_ns"] = (
        backwards_clock["worker_trace"]["barrier_release_ns"] + 1
    )

    forged_dispatch = deepcopy(trial)
    forged_dispatch["dispatch_succeeded"] = not forged_dispatch["dispatch_succeeded"]

    unfenced_effect = deepcopy(trial)
    dispatch_worker = next(
        worker
        for worker in unfenced_effect["worker_trace"]["workers"]
        if worker["operation"] == "dispatch"
    )
    dispatch_worker["outcome"]["durable"]["effect_observed_final_state"] = "EXECUTED"

    for tampered in (
        wrong_order,
        wrong_ordinal,
        duplicate_worker,
        backwards_clock,
        forged_dispatch,
        unfenced_effect,
    ):
        with pytest.raises(IntegrityError):
            _validate_trial_record(tampered)


async def test_revoke_bench_rejects_an_unknown_suite_without_writing(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="unknown benchmark suite"):
        await run_benchmark_suite(tmp_path, suite="not-a-suite")
    assert list(tmp_path.iterdir()) == []
