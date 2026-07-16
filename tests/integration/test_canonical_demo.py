from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from tars_revoke.demo.migration_contract import OPAQUE_CONTRACT_SQL, UUID_CONTRACT_SQL
from tars_revoke.demo.release import (
    _initialize_attestation_database,
    _manifest_path_map,
    _rebuild_bundle_receipt,
    _register_attestation_receipt,
)
from tars_revoke.demo.scenario import SCENARIO_PROOF_REQUIREMENTS, CanonicalScenario
from tars_revoke.demo.verifier import _verify_durable_attestation_receipts, verify_bundle
from tars_revoke.domain.enums import EffectState, LeaseState, RunState
from tars_revoke.domain.enums import TestState as DomainTestState
from tars_revoke.errors import IntegrityError
from tars_revoke.services.receipts import StrictReceiptVerifier


def _git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", "-C", str(repository), *args),
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.asyncio
async def test_canonical_demo_proves_selective_revoke_repair_and_resume(
    tmp_path: Path,
) -> None:
    scenario = await CanonicalScenario.prepare(tmp_path, run_id="canonical-deterministic")
    try:
        result = await scenario.run()
    finally:
        await scenario.close()

    assert result.strict_verification_valid
    assert len(result.affected_effect_ids) == 3
    assert set(result.affected_effect_ids) == {
        "canonical-deterministic:effect-agent-a-db-v1",
        "canonical-deterministic:effect-agent-a-model-v1",
        "canonical-deterministic:effect-agent-a-push-v1",
    }
    assert result.unaffected_effect_id not in result.affected_effect_ids
    assert scenario.store.get_run(result.run_id).state == RunState.COMPLETED  # type: ignore[union-attr]

    affected = [scenario.store.get_effect(effect_id) for effect_id in result.affected_effect_ids]
    assert all(effect is not None for effect in affected)
    assert [effect.state for effect in affected if effect is not None].count(
        EffectState.ROLLED_BACK
    ) == 2
    assert [effect.state for effect in affected if effect is not None].count(
        EffectState.QUARANTINED
    ) == 1
    unaffected = scenario.store.get_effect(result.unaffected_effect_id)
    assert unaffected is not None and unaffected.state == EffectState.EXECUTED

    pending_action = scenario.store.get_action("canonical-deterministic:action-agent-a-push-v1")
    assert pending_action is not None and pending_action.dispatched_at is None
    pending_lease = scenario.store.get_lease_for_action(pending_action.id)
    assert pending_lease is not None and pending_lease.state == LeaseState.REVOKED

    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    frozen = receipt["event_sequences"]["frozen"]
    agent_b_push = receipt["event_sequences"]["agent_b_push"]
    resumed = receipt["event_sequences"]["resumed"]
    assert frozen < agent_b_push < resumed
    assert receipt["affected_effects"] == list(result.affected_effect_ids)
    assert set(receipt["unaffected_effects"]) == {
        "canonical-deterministic:effect-agent-b-local-commit",
        result.unaffected_effect_id,
    }
    assert receipt["experiment"]["candidate_count"] >= 3
    assert receipt["experiment"]["exit_code"] == 0
    assert receipt["repair"]["live_codex"] is False
    assert "not R-14 live Codex proof" in (
        result.artifact_root / "agents" / "scripted-repair.json"
    ).read_text(encoding="utf-8")

    authorizations = receipt["authorizations"]
    assert {entry["stage"] for entry in authorizations} == {
        "agent-a-v1-local-commit",
        "agent-a-v1-migration",
        "agent-a-v1-push",
        "agent-b-observability-local-commit",
        "agent-b-observability-push",
        "agent-a-v2-decisive-experiment",
        "agent-a-v2-repair-local-commit",
        "agent-a-v2-migration",
        "agent-a-v2-targeted-test",
        "agent-a-v2-full-test",
        "agent-a-v2-push",
    }
    for entry in authorizations:
        warrant = entry["warrant"]
        action = entry["action"]
        assert warrant["artifact_hashes"]
        assert action["artifact_vector"] == warrant["artifact_hashes"]
        assert action["premise_vector"]
        assert entry["premise_bindings"]
        assert warrant["metadata"]["binding_stage"] == entry["stage"]
        assert entry["effect"]["action_id"] == action["id"]
        assert entry["effect"]["scope"] == action["scope"] == warrant["scope"]
        assert entry["effect"]["target"] == action["target"]
        assert entry["lease"]["effect_id"] == entry["effect"]["id"]
        assert entry["event_sequences"]["authorized"] > 0
        if entry["stage"] == "agent-a-v1-push":
            assert entry["event_sequences"]["dispatching"] is None
            assert entry["event_sequences"]["executed"] is None
        else:
            assert (
                entry["event_sequences"]["authorized"]
                < entry["event_sequences"]["dispatching"]
                < entry["event_sequences"]["executed"]
            )

    by_stage = {entry["stage"]: entry for entry in authorizations}
    for stage in (
        "agent-a-v1-local-commit",
        "agent-a-v1-migration",
        "agent-a-v1-push",
    ):
        assert by_stage[stage]["warrant"]["metadata"]["evidence_ids"] == [
            "canonical-deterministic:schema-evidence-v1"
        ]
    for stage in (
        "agent-a-v2-decisive-experiment",
        "agent-a-v2-repair-local-commit",
        "agent-a-v2-migration",
        "agent-a-v2-targeted-test",
        "agent-a-v2-full-test",
        "agent-a-v2-push",
    ):
        assert by_stage[stage]["warrant"]["metadata"]["evidence_ids"] == [
            "canonical-deterministic:schema-evidence-v2"
        ]
    assert set(by_stage["agent-a-v1-local-commit"]["warrant"]["artifact_hashes"]) >= {
        "file:billing/models.py",
        "file:migrations/002_customer_id_contract.sql",
        "evidence:canonical-deterministic:schema-evidence-v1",
    }
    assert by_stage["agent-a-v1-local-commit"]["action"]["action_type"] == "LOCAL_COMMIT"
    assert (
        by_stage["agent-a-v2-repair-local-commit"]["action"]["action_type"]
        == "LOCAL_COMMIT"
    )
    for stage in (
        "agent-b-observability-local-commit",
        "agent-b-observability-push",
    ):
        assert by_stage[stage]["warrant"]["metadata"]["evidence_ids"] == []
    invalid_push = by_stage["agent-a-v1-push"]
    assert invalid_push["bound_values"] == {
        "commit": result.invalid_commit,
        "tree": _git(
            result.fixture.repository,
            "rev-parse",
            f"{result.invalid_commit}^{{tree}}",
        ).stdout.strip(),
    }
    assert set(invalid_push["warrant"]["artifact_hashes"]) >= {
        "git:commit-oid",
        "git:tree-oid",
    }
    final_push = by_stage["agent-a-v2-push"]
    assert final_push["bound_values"]["commit"] == result.repaired_commit
    assert final_push["bound_values"]["tree"] == _git(
        result.fixture.repository,
        "rev-parse",
        f"{result.repaired_commit}^{{tree}}",
    ).stdout.strip()
    required_test_ids = final_push["bound_values"]["required_test_ids"]
    assert final_push["warrant"]["required_tests"] == required_test_ids
    assert len(required_test_ids) == 2

    migration_sources = receipt["migration_sources"]
    invalid_sql = result.artifact_root / migration_sources["invalid_v1"]["executed_sql_path"]
    repair_sql = result.artifact_root / migration_sources["repair_v2"]["executed_sql_path"]
    assert invalid_sql.read_bytes() == UUID_CONTRACT_SQL.encode("utf-8")
    assert repair_sql.read_bytes() == OPAQUE_CONTRACT_SQL.encode("utf-8")
    assert hashlib.sha256(invalid_sql.read_bytes()).hexdigest() == (
        migration_sources["invalid_v1"]["source_sha256"]
    )
    assert hashlib.sha256(repair_sql.read_bytes()).hexdigest() == (
        migration_sources["repair_v2"]["source_sha256"]
    )

    quarantine = receipt["quarantine"]
    assert (
        _git(result.fixture.repository, "rev-parse", quarantine["ref"]).stdout.strip()
        == result.invalid_commit
    )
    remote_commits = set(
        _git(result.fixture.remote, "rev-list", "--all").stdout.strip().splitlines()
    )
    assert result.invalid_commit not in remote_commits
    assert (
        _git(result.fixture.remote, "rev-parse", receipt["resume"]["ref"]).stdout.strip()
        == result.repaired_commit
    )
    assert (
        _git(
            result.fixture.remote,
            "show-ref",
            "--verify",
            "refs/heads/agent-a-invalid",
            check=False,
        ).returncode
        != 0
    )

    test_runs = scenario.store.list_test_runs(result.run_id, case_id=result.case_id)
    assert {(test.kind.value, test.state) for test in test_runs} == {
        ("TARGETED", DomainTestState.PASSED),
        ("FULL", DomainTestState.PASSED),
    }
    connection = sqlite3.connect(result.fixture.service_database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        columns = connection.execute("PRAGMA table_info(customers)").fetchall()
        customer_format = next(column for column in columns if column[1] == "customer_id_format")
        assert customer_format[4] == "'opaque'"
    finally:
        connection.close()

    manifest = json.loads(result.proof_manifest_path.read_text(encoding="utf-8"))
    scoped = StrictReceiptVerifier.verify(
        payload=receipt,
        proof_manifest=manifest,
        artifact_root=result.artifact_root,
        required_requirement_ids=SCENARIO_PROOF_REQUIREMENTS,
    )
    assert scoped.valid
    independent = verify_bundle(result.artifact_root, strict=False)
    assert independent.valid
    assert independent.affected_effect_ids == result.affected_effect_ids
    assert (
        result.receipt_digest_path.read_text(encoding="ascii").strip()
        == hashlib.sha256(result.receipt_path.read_bytes()).hexdigest()
    )

    state = sqlite3.connect(result.artifact_root / "state.sqlite")
    try:
        state.execute("UPDATE receipts SET canonical_digest = ?", ("0" * 64,))
        state.commit()
    finally:
        state.close()
    with pytest.raises(IntegrityError, match="durable receipt row"):
        verify_bundle(result.artifact_root, strict=False)


@pytest.mark.asyncio
async def test_portable_and_release_receipts_require_distinct_exact_durable_rows(
    tmp_path: Path,
) -> None:
    scenario = await CanonicalScenario.prepare(tmp_path, run_id="attestation-row-proof")
    try:
        result = await scenario.run()
    finally:
        await scenario.close()
    root = result.artifact_root
    canonical_receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    canonical_manifest = json.loads(result.proof_manifest_path.read_text(encoding="utf-8"))
    base_state_digest = hashlib.sha256((root / "state.sqlite").read_bytes()).hexdigest()
    requirements = _manifest_path_map(canonical_manifest)
    _rebuild_bundle_receipt(
        root,
        receipt=canonical_receipt,
        requirements=requirements,
        required_ids=SCENARIO_PROOF_REQUIREMENTS,
        receipt_name="portable-receipt.json",
        manifest_name="portable-proof-manifest.json",
        digest_name="portable-receipt.sha256",
        attestation_kind="portable-run",
    )
    _initialize_attestation_database(root)
    _register_attestation_receipt(
        root,
        receipt_name="portable-receipt.json",
        manifest_name="portable-proof-manifest.json",
        attestation_kind="portable-run",
    )
    portable_receipt = json.loads(
        (root / "portable-receipt.json").read_text(encoding="utf-8")
    )
    _rebuild_bundle_receipt(
        root,
        receipt=portable_receipt,
        requirements=requirements,
        required_ids=SCENARIO_PROOF_REQUIREMENTS,
        receipt_name="release-attestation.json",
        manifest_name="release-proof-manifest.json",
        digest_name="release-attestation.sha256",
        attestation_kind="release-r01-r20",
    )
    _register_attestation_receipt(
        root,
        receipt_name="release-attestation.json",
        manifest_name="release-proof-manifest.json",
        attestation_kind="release-r01-r20",
    )
    _verify_durable_attestation_receipts(
        root,
        canonical_receipt=canonical_receipt,
        selected_kind="release-r01-r20",
    )
    assert hashlib.sha256((root / "state.sqlite").read_bytes()).hexdigest() == base_state_digest

    database = root / "attestation-state.sqlite"
    connection = sqlite3.connect(database)
    release_id = f"{result.run_id}:attestation:release-r01-r20"
    portable_id = f"{result.run_id}:attestation:portable-run"
    try:
        original_manifest_digest = connection.execute(
            "SELECT manifest_digest FROM receipts WHERE id = ?", (release_id,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE receipts SET manifest_digest = ? WHERE id = ?",
            ("0" * 64, release_id),
        )
        connection.commit()
        with pytest.raises(IntegrityError, match="differs from attestation bytes"):
            _verify_durable_attestation_receipts(
                root,
                canonical_receipt=canonical_receipt,
                selected_kind="release-r01-r20",
            )
        connection.execute(
            "UPDATE receipts SET manifest_digest = ? WHERE id = ?",
            (original_manifest_digest, release_id),
        )
        connection.execute("DELETE FROM receipts WHERE id = ?", (portable_id,))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(IntegrityError, match="missing or duplicated"):
        _verify_durable_attestation_receipts(
            root,
            canonical_receipt=canonical_receipt,
            selected_kind="release-r01-r20",
        )
