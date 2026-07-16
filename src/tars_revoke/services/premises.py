from __future__ import annotations

from datetime import datetime
from typing import Any

from tars_revoke.domain.canonical import canonical_digest
from tars_revoke.domain.enums import (
    PremiseState,
    SignatureStatus,
    ValueSemantics,
    VerificationStatus,
)
from tars_revoke.domain.models import EvidenceRecord, Premise, ensure_aware
from tars_revoke.errors import IntegrityError, TransitionError, ValidationError


class PremiseService:
    """Pure lifecycle operations for immutable premise revisions."""

    @staticmethod
    def require_authoritative(evidence: EvidenceRecord) -> None:
        if evidence.signature_status != SignatureStatus.VALID:
            raise IntegrityError("evidence signature is not valid")
        if evidence.verification_status != VerificationStatus.VERIFIED:
            raise IntegrityError("evidence has not been verified")

    @staticmethod
    def invalidate(
        premise: Premise,
        *,
        evidence: EvidenceRecord,
        at: datetime,
    ) -> Premise:
        ensure_aware(at)
        PremiseService.require_authoritative(evidence)
        if evidence.run_id != premise.run_id:
            raise ValidationError("evidence and premise must belong to the same run")
        if evidence.valid_at > at:
            raise ValidationError("evidence is not valid yet")
        if at < premise.valid_at:
            raise ValidationError("invalidation cannot precede premise validity")
        if premise.state == PremiseState.INVALIDATED:
            if premise.invalidated_by_evidence_id == evidence.id:
                return premise
            raise TransitionError("invalidated premise history is terminal")
        if premise.state not in {PremiseState.ACTIVE, PremiseState.DISPUTED}:
            raise TransitionError(f"cannot invalidate premise from {premise.state.value}")
        return Premise.model_validate(
            premise.model_copy(
                update={
                    "state": PremiseState.INVALIDATED,
                    "invalid_at": at,
                    "invalidated_by_evidence_id": evidence.id,
                }
            ).model_dump()
        )

    @staticmethod
    def replacement(
        invalidated: Premise,
        *,
        new_id: str,
        new_value: Any,
        evidence: EvidenceRecord,
        created_at: datetime,
    ) -> Premise:
        ensure_aware(created_at)
        PremiseService.require_authoritative(evidence)
        if invalidated.state != PremiseState.INVALIDATED:
            raise TransitionError("replacement requires a terminally invalidated premise")
        if invalidated.semantics == ValueSemantics.SET:
            raise ValidationError(
                "set-valued premises require explicit member-level invalidation; "
                "a different value is not automatically a replacement"
            )
        if evidence.run_id != invalidated.run_id:
            raise ValidationError("evidence and premise must belong to the same run")
        return Premise(
            id=new_id,
            run_id=invalidated.run_id,
            scope=invalidated.scope,
            subject=invalidated.subject,
            relation=invalidated.relation,
            value=new_value,
            value_digest=canonical_digest(new_value),
            semantics=invalidated.semantics,
            state=PremiseState.ACTIVE,
            valid_at=max(created_at, evidence.valid_at),
            replaces_premise_id=invalidated.id,
            created_at=created_at,
            metadata={
                **dict(invalidated.metadata),
                "supporting_evidence_id": evidence.id,
            },
        )
