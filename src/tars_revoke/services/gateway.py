from __future__ import annotations

import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.canonical import sha256_digest
from tars_revoke.domain.enums import ActionState, EffectState, LeaseState, TestState
from tars_revoke.domain.models import ActionIntent, EffectRecord, ExecutionLease
from tars_revoke.errors import AuthorizationError, StaleWarrantError, ValidationError
from tars_revoke.ids import new_id
from tars_revoke.persistence.store import Store

from .warrants import WarrantService


@dataclass(frozen=True)
class GatewayAuthorization:
    action: ActionIntent
    effect: EffectRecord
    lease: ExecutionLease
    capability_token: str = field(repr=False)


@dataclass(frozen=True)
class DispatchGrant:
    action: ActionIntent
    effect: EffectRecord
    lease_id: str
    epoch: int


class EffectGateway:
    """The sole admission path for consequential and external effects."""

    def __init__(self, store: Store, *, clock: Clock | None = None) -> None:
        self.store = store
        self.clock = clock or SystemClock()

    def authorize(
        self,
        action_id: str,
        *,
        effect_id: str,
        current_artifact_hashes: Mapping[str, str],
        passed_test_ids: Iterable[str],
        lease_ttl: timedelta = timedelta(seconds=30),
        capability_token: str | None = None,
        at: datetime | None = None,
    ) -> GatewayAuthorization:
        now = at or self.clock.utc_now()
        if lease_ttl.total_seconds() <= 0:
            raise ValidationError("lease TTL must be positive")
        action = self._require_action(action_id)
        if action.state != ActionState.PREPARED:
            raise AuthorizationError("only a prepared action can be authorized")
        effect = self._require_effect(effect_id)
        if effect.state != EffectState.PREPARED:
            raise AuthorizationError("effect intent must be prepared before authorization")
        if effect.action_id != action.id:
            raise AuthorizationError("effect intent belongs to another action")
        warrant = self.store.get_warrant(action.warrant_id)
        if warrant is None:
            raise AuthorizationError(f"warrant {action.warrant_id} does not exist")
        bindings = self.store.list_warrant_premises(warrant.id)
        premises = {}
        for binding in bindings:
            premise = self.store.get_premise(binding.premise_id)
            if premise is not None:
                premises[premise.id] = premise

        verified_test_ids = self._verified_test_ids(action.run_id, passed_test_ids)
        decision = WarrantService.evaluate(
            warrant,
            premise_bindings=bindings,
            current_premises=premises,
            current_artifact_hashes=current_artifact_hashes,
            passed_test_ids=verified_test_ids,
            now=now,
        )
        decision.require_allowed()

        expected_premise_vector = {
            binding.premise_id: binding.premise_digest for binding in bindings
        }
        if dict(action.premise_vector) != expected_premise_vector:
            raise StaleWarrantError("action premise vector does not match its warrant")
        for path, expected_digest in action.artifact_vector.items():
            if current_artifact_hashes.get(path) != expected_digest:
                raise StaleWarrantError(f"action artifact vector is stale: {path}")

        token = capability_token or secrets.token_urlsafe(32)
        if not token:
            raise ValidationError("capability token must not be empty")
        token_digest = sha256_digest(token)
        lease = ExecutionLease(
            id=new_id("lease"),
            run_id=action.run_id,
            action_id=action.id,
            effect_id=effect.id,
            warrant_id=warrant.id,
            epoch=warrant.revision_epoch,
            token_digest=token_digest,
            state=LeaseState.ACTIVE,
            issued_at=now,
            expires_at=min(now + lease_ttl, warrant.expires_at),
            idempotency_key=action.idempotency_key,
        )
        authorized, authorized_effect = self.store.authorize_action_with_lease(
            action.id,
            effect.id,
            lease,
            expected_warrant_epoch=warrant.revision_epoch,
            at=now,
        )
        return GatewayAuthorization(
            action=authorized,
            effect=authorized_effect,
            lease=lease,
            capability_token=token,
        )

    def dispatch(
        self,
        action_id: str,
        *,
        effect_id: str,
        capability_token: str,
        current_artifact_hashes: Mapping[str, str],
        passed_test_ids: Iterable[str],
        at: datetime | None = None,
    ) -> DispatchGrant:
        now = at or self.clock.utc_now()
        if not capability_token:
            raise ValidationError("capability token must not be empty")
        action = self._require_action(action_id)
        if action.state != ActionState.AUTHORIZED or action.lease_id is None:
            raise AuthorizationError("action has no active authorization")
        effect = self._require_effect(effect_id)
        if effect.action_id != action.id or effect.state != EffectState.AUTHORIZED:
            raise AuthorizationError("action has no matching authorized effect intent")
        lease = self.store.get_lease(action.lease_id)
        if lease is None:
            raise AuthorizationError("action execution lease is missing")
        if lease.effect_id != effect.id:
            raise AuthorizationError("execution lease is bound to another effect intent")
        warrant = self.store.get_warrant(action.warrant_id)
        if warrant is None:
            raise AuthorizationError("action warrant is missing")
        bindings = self.store.list_warrant_premises(warrant.id)
        premises = {}
        for binding in bindings:
            premise = self.store.get_premise(binding.premise_id)
            if premise is not None:
                premises[premise.id] = premise
        verified_test_ids = self._verified_test_ids(action.run_id, passed_test_ids)
        decision = WarrantService.evaluate(
            warrant,
            premise_bindings=bindings,
            current_premises=premises,
            current_artifact_hashes=current_artifact_hashes,
            passed_test_ids=verified_test_ids,
            now=now,
        )
        decision.require_allowed()
        for path, expected_digest in action.artifact_vector.items():
            if current_artifact_hashes.get(path) != expected_digest:
                raise StaleWarrantError(f"action artifact vector is stale at dispatch: {path}")
        dispatched, dispatching_effect = self.store.begin_action_dispatch(
            action.id,
            effect.id,
            sha256_digest(capability_token),
            expected_warrant_epoch=lease.epoch,
            at=now,
        )
        return DispatchGrant(
            action=dispatched,
            effect=dispatching_effect,
            lease_id=lease.id,
            epoch=lease.epoch,
        )

    def complete(
        self,
        effect: EffectRecord,
        *,
        at: datetime | None = None,
    ) -> tuple[EffectRecord, ActionIntent]:
        return self.store.record_effect_and_complete_action(
            effect,
            at=at or self.clock.utc_now(),
        )

    def _require_action(self, action_id: str) -> ActionIntent:
        action = self.store.get_action(action_id)
        if action is None:
            raise ValidationError(f"action {action_id} does not exist")
        return action

    def _require_effect(self, effect_id: str) -> EffectRecord:
        effect = self.store.get_effect(effect_id)
        if effect is None:
            raise ValidationError(f"effect intent {effect_id} does not exist")
        return effect

    def _verified_test_ids(self, run_id: str, test_ids: Iterable[str]) -> tuple[str, ...]:
        verified: list[str] = []
        for test_id in test_ids:
            record = self.store.get_test_run(test_id)
            if record is None:
                raise AuthorizationError(f"claimed passed test does not exist: {test_id}")
            if record.run_id != run_id:
                raise AuthorizationError(f"claimed passed test belongs to another run: {test_id}")
            if record.state != TestState.PASSED:
                raise AuthorizationError(f"claimed test is not passed: {test_id}")
            verified.append(test_id)
        return tuple(verified)
