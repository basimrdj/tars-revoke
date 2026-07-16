from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.services.receipts import ReceiptBuilder, StrictReceiptVerifier


def _fields() -> dict[str, object]:
    return {
        "receipt_version": 1,
        "run_id": "run-1",
        "case_id": "case-1",
        "agents": [{"id": "agent-a"}, {"id": "agent-b"}],
        "trigger": {"evidence_id": "evidence-v2"},
        "premise_delta": {"invalidated": "premise-v1", "replacement": "premise-v2"},
        "dependency_paths": [["premise-v1", "effect-1"]],
        "affected_effects": ["effect-1", "effect-2", "effect-3"],
        "unaffected_effects": ["effect-b"],
        "compensation": {"rolled_back": ["effect-1", "effect-2"]},
        "quarantine": {"effects": ["effect-3"]},
        "experiment": {"selected": "probe"},
        "repair": {"commit": "repaired"},
        "verification": {"targeted": "passed", "full": "passed"},
        "resume": {"push": "replacement"},
        "timeline": [1, 2, 3],
        "failures": [],
        "limitations": [],
    }


def _manifest(tmp_path: Path) -> dict[str, object]:
    proof = tmp_path / "proof.txt"
    proof.write_text("authoritative proof", encoding="utf-8")
    return dict(
        ReceiptBuilder.build_manifest(
            artifact_root=tmp_path,
            requirement_artifacts={"R-01": [proof]},
            required_requirement_ids=("R-01",),
        )
    )


def test_receipt_is_deterministic_and_strictly_verifiable(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    first = ReceiptBuilder.build(
        receipt_fields=_fields(),
        proof_manifest=manifest,
        event_head_digest="a" * 64,
    )
    second = ReceiptBuilder.build(
        receipt_fields=deepcopy(_fields()),
        proof_manifest=deepcopy(manifest),
        event_head_digest="a" * 64,
    )

    assert first.canonical_digest == second.canonical_digest
    assert first.payload == second.payload
    result = StrictReceiptVerifier.verify(
        payload=first.payload,
        proof_manifest=manifest,
        artifact_root=tmp_path,
        required_requirement_ids=("R-01",),
    )
    assert result.valid


def test_tampered_receipt_or_artifact_fails_closed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    built = ReceiptBuilder.build(
        receipt_fields=_fields(),
        proof_manifest=manifest,
        event_head_digest="b" * 64,
    )
    tampered = deepcopy(dict(built.payload))
    tampered["repair"] = {"commit": "malicious"}

    with pytest.raises(IntegrityError, match="canonical digest"):
        StrictReceiptVerifier.verify(
            payload=tampered,
            proof_manifest=manifest,
            artifact_root=tmp_path,
            required_requirement_ids=("R-01",),
        )

    (tmp_path / "proof.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(IntegrityError, match="artifact"):
        StrictReceiptVerifier.verify(
            payload=built.payload,
            proof_manifest=manifest,
            artifact_root=tmp_path,
            required_requirement_ids=("R-01",),
        )


def test_missing_section_or_requirement_cannot_build(tmp_path: Path) -> None:
    fields = _fields()
    del fields["experiment"]
    with pytest.raises(ValidationError, match="missing sections"):
        ReceiptBuilder.build(
            receipt_fields=fields,
            proof_manifest={"requirements": {}},
            event_head_digest="c" * 64,
        )

    with pytest.raises(ValidationError, match="missing requirements"):
        ReceiptBuilder.build_manifest(
            artifact_root=tmp_path,
            requirement_artifacts={},
            required_requirement_ids=("R-01",),
        )


def test_strict_receipt_rejects_malformed_hashes_and_extra_integrity_fields(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    with pytest.raises(ValidationError, match="SHA-256"):
        ReceiptBuilder.build(
            receipt_fields=_fields(),
            proof_manifest=manifest,
            event_head_digest="z" * 64,
        )

    built = ReceiptBuilder.build(
        receipt_fields=_fields(),
        proof_manifest=manifest,
        event_head_digest="d" * 64,
    )
    tampered = deepcopy(dict(built.payload))
    tampered["integrity"] = {**dict(tampered["integrity"]), "ignored": True}
    with pytest.raises(IntegrityError, match="unexpected fields"):
        StrictReceiptVerifier.verify(
            payload=tampered,
            proof_manifest=manifest,
            artifact_root=tmp_path,
            required_requirement_ids=("R-01",),
        )
