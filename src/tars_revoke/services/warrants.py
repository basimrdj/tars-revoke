from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from tars_revoke.domain.enums import PremiseState, WarrantState
from tars_revoke.domain.models import Premise, Warrant, WarrantPremise, ensure_aware
from tars_revoke.errors import AuthorizationError, TransitionError


@dataclass(frozen=True)
class WarrantDecision:
    allowed: bool
    reasons: tuple[str, ...]

    def require_allowed(self) -> None:
        if not self.allowed:
            raise AuthorizationError("; ".join(self.reasons))


class WarrantService:
    """Deterministic warrant evaluation over exact revisions and hashes."""

    @staticmethod
    def evaluate(
        warrant: Warrant,
        *,
        premise_bindings: Iterable[WarrantPremise],
        current_premises: Mapping[str, Premise],
        current_artifact_hashes: Mapping[str, str],
        passed_test_ids: Iterable[str],
        now: datetime,
        require_premises: bool = True,
    ) -> WarrantDecision:
        ensure_aware(now)
        reasons: list[str] = []
        if warrant.state not in {WarrantState.PREPARED, WarrantState.AUTHORIZED}:
            reasons.append(f"warrant_state_not_authorizable:{warrant.state.value}")
        if now < warrant.issued_at:
            reasons.append("warrant_not_yet_valid")
        if now >= warrant.expires_at:
            reasons.append("warrant_expired")

        bindings = tuple(premise_bindings)
        if require_premises and not bindings:
            reasons.append("missing_premise_bindings")
        for binding in bindings:
            if binding.warrant_id != warrant.id:
                reasons.append(f"foreign_premise_binding:{binding.premise_id}")
                continue
            premise = current_premises.get(binding.premise_id)
            if premise is None:
                reasons.append(f"premise_missing:{binding.premise_id}")
                continue
            if premise.run_id != warrant.run_id:
                reasons.append(f"premise_run_mismatch:{binding.premise_id}")
            if premise.state != PremiseState.ACTIVE:
                reasons.append(f"premise_not_active:{binding.premise_id}")
            if premise.value_digest != binding.premise_digest:
                reasons.append(f"premise_revision_mismatch:{binding.premise_id}")

        for path, expected_digest in warrant.artifact_hashes.items():
            actual_digest = current_artifact_hashes.get(path)
            if actual_digest is None:
                reasons.append(f"artifact_missing:{path}")
            elif actual_digest != expected_digest:
                reasons.append(f"artifact_hash_mismatch:{path}")

        passed = set(passed_test_ids)
        for test_id in warrant.required_tests:
            if test_id not in passed:
                reasons.append(f"required_test_not_passed:{test_id}")

        unique_reasons = tuple(sorted(set(reasons)))
        return WarrantDecision(allowed=not unique_reasons, reasons=unique_reasons)

    @staticmethod
    def authorize(warrant: Warrant, decision: WarrantDecision) -> Warrant:
        decision.require_allowed()
        if warrant.state not in {WarrantState.PREPARED, WarrantState.AUTHORIZED}:
            raise TransitionError(f"cannot authorize warrant from {warrant.state.value}")
        return warrant.model_copy(update={"state": WarrantState.AUTHORIZED})

    @staticmethod
    def revoke(warrant: Warrant, *, now: datetime, cause: str) -> Warrant:
        ensure_aware(now)
        if warrant.state in {WarrantState.REVOKED, WarrantState.EXPIRED}:
            if warrant.state == WarrantState.REVOKED:
                return warrant
            raise TransitionError("an expired warrant cannot be revived or revoked")
        if not cause.strip():
            raise ValueError("revocation cause is required")
        return warrant.model_copy(
            update={
                "state": WarrantState.REVOKED,
                "revision_epoch": warrant.revision_epoch + 1,
                "revoked_at": now,
                "revoke_cause": cause,
            }
        )

    @staticmethod
    def expire(warrant: Warrant, *, now: datetime) -> Warrant:
        ensure_aware(now)
        if now < warrant.expires_at:
            raise TransitionError("warrant has not expired")
        if warrant.state == WarrantState.REVOKED:
            return warrant
        return warrant.model_copy(update={"state": WarrantState.EXPIRED})
