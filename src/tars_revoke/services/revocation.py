from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.enums import RevocationCaseState, RevocationMemberKind
from tars_revoke.domain.models import Premise, RevocationCase, RevocationMember
from tars_revoke.errors import ValidationError
from tars_revoke.ids import new_id
from tars_revoke.persistence.store import Store

from .premises import PremiseService


@dataclass(frozen=True)
class RevocationResult:
    premise: Premise
    case: RevocationCase
    members: tuple[RevocationMember, ...]

    @property
    def affected_effect_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                member.entity_id
                for member in self.members
                if member.member_kind == RevocationMemberKind.EFFECT
            )
        )

    def contains_entity(self, entity_id: str) -> bool:
        return any(member.entity_id == entity_id for member in self.members)


class SelectiveRevoker:
    """Open a case and atomically invalidate/fence its hard causal closure."""

    def __init__(self, store: Store, *, clock: Clock | None = None) -> None:
        self.store = store
        self.clock = clock or SystemClock()

    def invalidate_and_fence(
        self,
        premise_id: str,
        *,
        invalidating_evidence_id: str,
        reason: str,
        at: datetime | None = None,
        case_id: str | None = None,
    ) -> RevocationResult:
        now = at or self.clock.utc_now()
        if not reason.strip():
            raise ValidationError("revocation reason is required")
        premise = self.store.get_premise(premise_id)
        evidence = self.store.get_evidence_record(invalidating_evidence_id)
        if premise is None:
            raise ValidationError(f"premise {premise_id} does not exist")
        if evidence is None:
            raise ValidationError(f"evidence {invalidating_evidence_id} does not exist")
        # Validate evidence authority, run binding, and temporal validity before
        # entering the atomic persistence boundary. Store repeats the mutable
        # lifecycle checks under BEGIN IMMEDIATE.
        PremiseService.invalidate(premise, evidence=evidence, at=now)
        case = RevocationCase(
            id=case_id or new_id("case"),
            run_id=premise.run_id,
            premise_id=premise.id,
            trigger_evidence_id=evidence.id,
            state=RevocationCaseState.OPEN,
            reason=reason,
            opened_at=now,
            updated_at=now,
        )
        invalidated, frozen, members = self.store.invalidate_premise_and_fence(
            premise.id,
            evidence.id,
            case,
            at=now,
        )
        return RevocationResult(
            premise=invalidated,
            case=frozen,
            members=tuple(members),
        )
