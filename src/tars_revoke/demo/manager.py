from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from tars_revoke.adapters.git import GitAdapter, validate_refspec
from tars_revoke.config import Settings
from tars_revoke.domain.enums import (
    DispatchReconciliationOutcome,
    EffectState,
    EffectType,
    RunState,
)
from tars_revoke.domain.models import DispatchReconciliationRecord, EffectRecord
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.persistence.store import Store
from tars_revoke.services.coordinator import DispatchReconciliation, RevocationCoordinator

from .failures import (
    DurableFailure,
    RecoveredRunInterruption,
    finalize_without_masking,
    recover_failure,
    sanitize_failure_text,
)
from .scenario import CanonicalScenario, ScenarioResult
from .verifier import CORE_REQUIREMENT_IDS, BundleVerification, verify_bundle


@dataclass
class ManagedRun:
    scenario: CanonicalScenario | None
    live_codex: bool
    store: Store
    artifact_root: Path
    task: asyncio.Task[ScenarioResult] | None = None
    result: ScenarioResult | None = None
    error: BaseException | None = None
    failure: DurableFailure | None = None
    finalization_error: str | None = None


class RunManager:
    """Own background demo lifecycles while SQLite remains the source of truth."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = (settings.data_dir / "runs").expanduser().resolve()
        self._runs: dict[str, ManagedRun] = {}
        self._current_run_id: str | None = None
        self._lock = asyncio.Lock()

    @property
    def current_run_id(self) -> str | None:
        return self._current_run_id

    async def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        recovered: list[tuple[datetime, str]] = []
        for run_root in sorted(self.root.iterdir()):
            if not run_root.is_dir():
                continue
            artifact_container = run_root / "artifacts"
            candidates = [artifact_container / "state.sqlite"]
            candidates.extend(sorted(artifact_container.glob("*/state.sqlite")))
            for state_database in candidates:
                if not state_database.is_file():
                    continue
                store = Store(state_database)
                for run in store.list_runs():
                    artifact_root = state_database.parent
                    current = store.get_run(run.id)
                    if current is None:
                        continue
                    reconciliation_summaries: tuple[str, ...] = ()
                    reconciliation_error: str | None = None
                    if current.state in {RunState.DECLARED, RunState.RUNNING, RunState.PAUSED}:
                        try:
                            reconciliation_summaries = await self._reconcile_startup_dispatches(
                                store,
                                run.id,
                            )
                        except Exception as exc:
                            reconciliation_error = sanitize_failure_text(
                                f"startup reconciliation failed closed: "
                                f"{type(exc).__name__}: {exc}"
                            )
                    failure = recover_failure(store, run.id, artifact_root)
                    finalization_error: str | None = None
                    current = store.get_run(run.id)
                    if current is None:
                        continue
                    if current.state in {RunState.DECLARED, RunState.RUNNING, RunState.PAUSED}:
                        recovery_detail = "; ".join(reconciliation_summaries)
                        if reconciliation_error is not None:
                            recovery_detail = reconciliation_error
                        elif recovery_detail:
                            recovery_detail = f"startup dispatch reconciliation: {recovery_detail}"
                        interruption = RecoveredRunInterruption(
                            failure.message
                            if failure is not None
                            else "; ".join(
                                detail
                                for detail in (
                                    recovery_detail,
                                    "run executor disappeared before a terminal state was "
                                    "persisted",
                                )
                                if detail
                            )
                        )
                        failure, finalization_error = finalize_without_masking(
                            store=store,
                            run_id=run.id,
                            artifact_root=artifact_root,
                            error=interruption,
                        )
                    elif current.state in {RunState.FAILED, RunState.CANCELLED}:
                        recovery_reason = (
                            failure.message
                            if failure is not None
                            else f"recovered terminal {current.state.value.lower()} run without "
                            "a durable failure receipt"
                        )
                        recovery_error: BaseException = (
                            asyncio.CancelledError(recovery_reason)
                            if current.state == RunState.CANCELLED
                            else RecoveredRunInterruption(recovery_reason)
                        )
                        failure, finalization_error = finalize_without_masking(
                            store=store,
                            run_id=run.id,
                            artifact_root=artifact_root,
                            error=recovery_error,
                        )
                    provider = run.metadata.get("repair_provider")
                    self._runs[run.id] = ManagedRun(
                        scenario=None,
                        live_codex=provider == "live-codex",
                        store=store,
                        artifact_root=artifact_root,
                        failure=failure,
                        finalization_error=finalization_error,
                    )
                    recovered_run = store.get_run(run.id) or run
                    recovered.append((recovered_run.updated_at, run.id))
        if recovered:
            self._current_run_id = max(recovered)[1]

    async def _reconcile_startup_dispatches(
        self,
        store: Store,
        run_id: str,
    ) -> tuple[str, ...]:
        """Resolve every ambiguous dispatch from external truth without replay."""

        coordinator = RevocationCoordinator(store)
        snapshot = coordinator.recover(run_id)
        summaries: list[str] = []
        for obligation in snapshot.dispatch_reconciliations:
            record, executed_effect = await self._observe_startup_dispatch(store, obligation)
            try:
                store.record_dispatch_reconciliation(
                    record,
                    executed_effect=executed_effect,
                )
            except (IntegrityError, ValidationError) as exc:
                if record.outcome != DispatchReconciliationOutcome.APPLIED:
                    raise
                reason = sanitize_failure_text(
                    "adapter reported APPLIED but the observation contradicted the durable "
                    f"effect intent: {type(exc).__name__}: {exc}; containment required"
                )
                fallback = record.model_copy(
                    update={
                        "outcome": DispatchReconciliationOutcome.UNKNOWN,
                        "observed": {
                            **dict(record.observed),
                            "persistence_error_type": type(exc).__name__,
                        },
                        "reason": reason,
                    }
                )
                store.record_dispatch_reconciliation(fallback)
                record = fallback
            summaries.append(f"{obligation.effect_id}={record.outcome.value}")

        after = coordinator.recover(run_id)
        if after.requires_dispatch_reconciliation:
            raise IntegrityError(
                "startup reconciliation left unresolved dispatch obligations: "
                + ", ".join(after.dispatching_effect_ids)
            )
        return tuple(summaries)

    async def _observe_startup_dispatch(
        self,
        store: Store,
        obligation: DispatchReconciliation,
    ) -> tuple[DispatchReconciliationRecord, EffectRecord | None]:
        reconciled_at = store.clock.utc_now()
        effect = store.get_effect(obligation.effect_id)
        if effect is None:
            raise IntegrityError(f"dispatch effect {obligation.effect_id} disappeared")
        expected: dict[str, Any] = dict(obligation.metadata)
        observed: dict[str, Any] = {}
        outcome = DispatchReconciliationOutcome.UNKNOWN
        executed_effect: EffectRecord | None = None
        reason = (
            f"{obligation.effect_type} dispatch has no safe startup reconciler; "
            "external outcome is ambiguous and containment is required"
        )

        if obligation.effect_type == EffectType.PUSH.value:
            try:
                required = {
                    name: self._required_reconciliation_string(expected, name)
                    for name in (
                        "repository",
                        "remote",
                        "remote_url",
                        "destination",
                        "refspec",
                        "source_oid",
                    )
                }
                repository = Path(required["repository"])
                if not repository.is_absolute():
                    raise ValidationError("reconciliation repository must be an absolute path")
                repository = repository.resolve(strict=True)
                if str(repository) != required["repository"]:
                    raise ValidationError("reconciliation repository is not canonical")
                refspec = validate_refspec(required["refspec"])
                if refspec.split(":", 1)[1] != required["destination"]:
                    raise IntegrityError("reconciliation destination does not match refspec")
                adapter = GitAdapter([repository])
                actual_remote_url = await adapter.remote_url(repository, required["remote"])
                if actual_remote_url != required["remote_url"]:
                    raise IntegrityError("Git remote URL changed after dispatch")
                result = await adapter.reconcile_push(
                    repository,
                    remote=required["remote"],
                    destination=required["destination"],
                    expected_source_oid=required["source_oid"],
                )
                outcome = DispatchReconciliationOutcome(result.state)
                observed = {
                    "destination": result.destination,
                    "expected_source_oid": result.expected_source_oid,
                    "remote_head": result.remote_head,
                    "remote_url": actual_remote_url,
                    "state": result.state,
                }
                if outcome == DispatchReconciliationOutcome.APPLIED:
                    reason = (
                        "remote ref exactly matches the authorized source object; "
                        "startup marked the effect applied without replaying the push"
                    )
                    executed_effect = EffectRecord.model_validate(
                        effect.model_copy(
                            update={
                                "state": EffectState.EXECUTED,
                                "after_hash": effect.after_hash or result.remote_head,
                                "updated_at": reconciled_at,
                                "metadata": {
                                    **dict(effect.metadata),
                                    "startup_reconciliation": observed,
                                },
                            }
                        ).model_dump()
                    )
                elif outcome == DispatchReconciliationOutcome.NOT_APPLIED:
                    reason = (
                        "remote destination is absent; startup confirmed the push was not "
                        "applied and did not retry it"
                    )
                else:
                    reason = (
                        "remote destination differs from the authorized source object; "
                        "containment is required"
                    )
            except Exception as exc:
                outcome = DispatchReconciliationOutcome.UNKNOWN
                observed = {"error_type": type(exc).__name__}
                reason = sanitize_failure_text(
                    f"Git push outcome could not be proven at startup: "
                    f"{type(exc).__name__}: {exc}; containment is required"
                )

        record = DispatchReconciliationRecord(
            id=f"dispatch-reconciliation:{obligation.effect_id}",
            run_id=effect.run_id,
            action_id=obligation.action_id,
            effect_id=obligation.effect_id,
            adapter=(
                "git.push"
                if obligation.effect_type == EffectType.PUSH.value
                else "unsupported"
            ),
            outcome=outcome,
            expected=expected,
            observed=observed,
            reason=reason,
            reconciled_at=reconciled_at,
            metadata={
                "effect_type": obligation.effect_type,
                "idempotency_key": obligation.idempotency_key,
                "startup_policy": "observe-never-replay",
            },
        )
        return record, executed_effect

    @staticmethod
    def _required_reconciliation_string(metadata: dict[str, Any], name: str) -> str:
        value = metadata.get(name)
        if not isinstance(value, str) or not value:
            raise ValidationError(f"push dispatch metadata requires non-empty {name}")
        return value

    async def start_demo(self, *, scenario: str, live_codex: bool) -> str:
        if scenario != "external-schema-v2":
            raise ValidationError(f"unknown demo scenario: {scenario}")
        async with self._lock:
            if self._current_run_id is not None:
                current = self._runs[self._current_run_id]
                if current.task is not None and not current.task.done():
                    raise ValidationError("a canonical demo is already running")
            handle = await CanonicalScenario.prepare(
                self.root,
                live_codex=live_codex,
                codex_model=self.settings.codex_model,
                codex_bin=self.settings.codex_bin,
                codex_timeout_seconds=self.settings.codex_timeout_seconds,
            )
            managed = ManagedRun(
                scenario=handle,
                live_codex=live_codex,
                store=handle.store,
                artifact_root=handle.artifact_root,
            )
            self._runs[handle.fixture.run_id] = managed
            self._current_run_id = handle.fixture.run_id
            managed.task = asyncio.create_task(
                self._execute(handle.fixture.run_id, managed),
                name=f"tars-revoke-{handle.fixture.run_id}",
            )
            managed.task.add_done_callback(self._consume_task)
            return handle.fixture.run_id

    @staticmethod
    def _consume_task(task: asyncio.Task[ScenarioResult]) -> None:
        if not task.cancelled():
            task.exception()

    async def _execute(self, run_id: str, managed: ManagedRun) -> ScenarioResult:
        scenario = managed.scenario
        if scenario is None:
            raise ValidationError(f"recovered run {run_id} cannot be executed again")
        try:
            result = await scenario.run()
            managed.result = result
            return result
        except BaseException as exc:
            managed.error = exc
            managed.failure, managed.finalization_error = finalize_without_masking(
                store=managed.store,
                run_id=run_id,
                artifact_root=managed.artifact_root,
                error=exc,
            )
            raise
        finally:
            try:
                await scenario.close()
            except BaseException as close_error:
                if managed.error is None:
                    managed.error = close_error
                    managed.failure, managed.finalization_error = finalize_without_masking(
                        store=managed.store,
                        run_id=run_id,
                        artifact_root=managed.artifact_root,
                        error=close_error,
                    )
                    raise
                if managed.finalization_error is None:
                    managed.finalization_error = sanitize_failure_text(
                        f"scenario close failed: {type(close_error).__name__}: {close_error}"
                    )

    def store_for(self, run_id: str) -> Store:
        try:
            return self._runs[run_id].store
        except KeyError as exc:
            raise KeyError(f"run {run_id} was not found") from exc

    def artifact_root_for(self, run_id: str) -> Path:
        try:
            return self._runs[run_id].artifact_root
        except KeyError as exc:
            raise KeyError(f"run {run_id} was not found") from exc

    async def verify(self, run_id: str) -> BundleVerification:
        try:
            managed = self._runs[run_id]
        except KeyError as exc:
            raise KeyError(f"run {run_id} was not found") from exc
        if managed.task is not None and not managed.task.done():
            raise ValidationError("run is still active; no final receipt exists yet")
        run = managed.store.get_run(run_id)
        if managed.failure is not None or (
            run is not None and run.state in {RunState.FAILED, RunState.CANCELLED}
        ):
            status = run.state.value.lower() if run is not None else "failed"
            reason = (
                managed.failure.message
                if managed.failure is not None
                else sanitize_failure_text(managed.error or "durable failure reason unavailable")
            )
            raise ValidationError(f"run {status}: {reason}")
        required = (
            tuple(sorted((*CORE_REQUIREMENT_IDS, "R-01", "R-14")))
            if managed.live_codex
            else CORE_REQUIREMENT_IDS
        )
        return verify_bundle(managed.artifact_root, required_requirement_ids=required)

    async def close(self) -> None:
        tasks: list[asyncio.Task[ScenarioResult]] = []
        for managed in self._runs.values():
            if managed.task is not None and not managed.task.done():
                managed.task.cancel()
                tasks.append(managed.task)
            if managed.scenario is not None:
                await managed.scenario.close()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
