from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tars_revoke.domain.canonical import canonical_bytes, canonical_digest, sha256_digest
from tars_revoke.domain.enums import (
    PremiseState,
    RiskLevel,
    ValueSemantics,
    WarrantState,
)
from tars_revoke.domain.models import Premise, Warrant, WarrantPremise
from tars_revoke.services.evidence import EvidenceVerifier
from tars_revoke.services.warrants import WarrantService

NOW = datetime(2026, 7, 14, tzinfo=timezone.utc)
DIGEST_A = "a" * 64


def _premise(*, state: PremiseState = PremiseState.ACTIVE, value: str = "uuid") -> Premise:
    return Premise(
        id="premise-1",
        run_id="run-1",
        scope="repo:billing",
        subject="billing.Customer.customer_id",
        relation="serialization",
        value=value,
        semantics=ValueSemantics.SINGLE,
        state=state,
        valid_at=NOW,
        invalid_at=NOW if state in {PremiseState.INVALIDATED, PremiseState.SUPERSEDED} else None,
        invalidated_by_evidence_id="evidence-v2" if state == PremiseState.INVALIDATED else None,
        created_at=NOW,
    )


def _warrant() -> Warrant:
    return Warrant(
        id="warrant-1",
        run_id="run-1",
        agent_id="agent-a",
        scope="repo:billing",
        authorized_targets=("billing/models.py",),
        state=WarrantState.PREPARED,
        risk=RiskLevel.HIGH,
        artifact_hashes={"billing/models.py": DIGEST_A},
        required_tests=("preflight",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _binding(premise: Premise) -> WarrantPremise:
    return WarrantPremise(
        warrant_id="warrant-1",
        premise_id=premise.id,
        premise_digest=premise.value_digest,
        created_at=NOW,
    )


def test_authorizes_only_exact_active_premise_artifact_and_test_vector() -> None:
    premise = _premise()
    warrant = _warrant()

    decision = WarrantService.evaluate(
        warrant,
        premise_bindings=[_binding(premise)],
        current_premises={premise.id: premise},
        current_artifact_hashes={"billing/models.py": DIGEST_A},
        passed_test_ids={"preflight"},
        now=NOW + timedelta(seconds=1),
    )

    assert decision.allowed
    assert WarrantService.authorize(warrant, decision).state == WarrantState.AUTHORIZED


def test_invalidated_premise_or_changed_artifact_fences_authorization() -> None:
    active = _premise()
    invalidated = _premise(state=PremiseState.INVALIDATED)

    decision = WarrantService.evaluate(
        _warrant(),
        premise_bindings=[_binding(active)],
        current_premises={active.id: invalidated},
        current_artifact_hashes={"billing/models.py": "b" * 64},
        passed_test_ids=set(),
        now=NOW + timedelta(seconds=1),
    )

    assert not decision.allowed
    assert "premise_not_active:premise-1" in decision.reasons
    assert "artifact_hash_mismatch:billing/models.py" in decision.reasons
    assert "required_test_not_passed:preflight" in decision.reasons


def test_premise_value_digest_is_the_revision_fence() -> None:
    old = _premise(value="uuid")
    replacement = _premise(value="opaque-string")
    binding = WarrantPremise(
        warrant_id="warrant-1",
        premise_id=old.id,
        premise_digest=canonical_digest("uuid"),
        created_at=NOW,
    )

    decision = WarrantService.evaluate(
        _warrant(),
        premise_bindings=[binding],
        current_premises={old.id: replacement},
        current_artifact_hashes={"billing/models.py": DIGEST_A},
        passed_test_ids={"preflight"},
        now=NOW + timedelta(seconds=1),
    )

    assert not decision.allowed
    assert "premise_revision_mismatch:premise-1" in decision.reasons


def test_revocation_is_idempotent_and_increments_epoch_once() -> None:
    revoked = WarrantService.revoke(_warrant(), now=NOW + timedelta(seconds=2), cause="v2")
    repeated = WarrantService.revoke(revoked, now=NOW + timedelta(seconds=3), cause="v2")

    assert revoked.state == WarrantState.REVOKED
    assert revoked.revision_epoch == 1
    assert repeated == revoked


def test_future_issued_warrant_is_not_authorizable() -> None:
    premise = _premise()
    warrant = _warrant().model_copy(
        update={
            "issued_at": NOW + timedelta(minutes=1),
            "expires_at": NOW + timedelta(minutes=2),
        }
    )

    decision = WarrantService.evaluate(
        warrant,
        premise_bindings=[_binding(premise)],
        current_premises={premise.id: premise},
        current_artifact_hashes={"billing/models.py": DIGEST_A},
        passed_test_ids={"preflight"},
        now=NOW,
    )

    assert not decision.allowed
    assert "warrant_not_yet_valid" in decision.reasons


def test_evidence_verifier_accepts_raw_ed25519_key_and_signature_bytes() -> None:
    artifact = b'{"customer_id":"opaque"}'
    manifest = {
        "source_identity": "registry-prod",
        "source_version": 2,
        "artifact_digest": sha256_digest(artifact),
    }
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(canonical_bytes(manifest))

    result = EvidenceVerifier().verify(
        manifest=manifest,
        artifact=artifact,
        detached_signature=signature,
        public_key=public_key,
        pinned_identity="registry-prod",
        latest_source_version=1,
    )

    assert result.accepted
    assert result.signature_valid
