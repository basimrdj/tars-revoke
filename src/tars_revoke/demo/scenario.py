from __future__ import annotations

import asyncio
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from tars_revoke.adapters._safety import is_python_executable
from tars_revoke.adapters.git import GitAdapter, GitPushTokenIssuer
from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.adapters.sqlite_migration import SQLiteMigrationAdapter, SQLiteMigrationResult
from tars_revoke.domain.canonical import canonical_digest, canonical_json, sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    EdgeStrength,
    EdgeType,
    EffectState,
    EffectType,
    EvidenceRole,
    ExperimentState,
    NodeKind,
    PremiseState,
    ReceiptState,
    Reversibility,
    RevocationCaseState,
    RiskLevel,
    RunState,
    SessionState,
    SignatureStatus,
    TestKind,
    TestState,
    ValueSemantics,
    VerificationStatus,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    AgentSession,
    ArtifactRef,
    DependencyEdge,
    EffectRecord,
    EventRecord,
    EvidenceRecord,
    EvidenceSource,
    ExperimentCandidate,
    ExperimentRun,
    GraphNode,
    Premise,
    PremiseEvidence,
    Receipt,
    Run,
    TestRun,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.ids import new_id
from tars_revoke.persistence.artifacts import ArtifactStore
from tars_revoke.persistence.store import Store
from tars_revoke.services.experiments import ExperimentSelection, ExperimentSelector
from tars_revoke.services.gateway import EffectGateway
from tars_revoke.services.receipts import ReceiptBuilder, StrictReceiptVerifier
from tars_revoke.services.repair import RevocationPacket
from tars_revoke.services.revocation import RevocationResult, SelectiveRevoker

from .concurrency import (
    CodexSessionEvidence,
    LiveEventEvidence,
    build_concurrent_codex_proof,
    verify_concurrent_codex_proof,
)
from .experiment_contract import HYPOTHESES, matching_hypotheses
from .experiment_sandbox import build_experiment_sandbox, workspace_manifest
from .fixture import DemoFixture, FixtureBuilder
from .live_codex import (
    ContradictionAnalysis,
    ExperimentProposalResult,
    LiveCodexPath,
    LiveCodexResult,
)
from .migration_contract import (
    MIGRATION_SOURCE_PATH,
    ValidatedMigrationSource,
    validate_migration_source,
)
from .registry import SchemaRegistryProcess
from .scripted_codex import ScriptedCodex, ScriptedRepair

SCENARIO_PROOF_REQUIREMENTS = (
    "R-02",
    "R-03",
    "R-04",
    "R-05",
    "R-06",
    "R-07",
    "R-08",
    "R-09",
    "R-10",
    "R-11",
    "R-12",
    "R-13",
    "R-15",
    "R-16",
    "R-17",
)
ALL_REQUIREMENTS = tuple(f"R-{index:02d}" for index in range(1, 21))
SCHEMA_NAME = "billing-customer"
SCOPE = "billing-repository"


def _resolve_experiment_argv(
    argv: tuple[str, ...],
    *,
    python_executable: Path,
) -> tuple[str, ...]:
    """Bind Codex's portable ``python`` grammar to the interpreter in use."""

    if not argv or not is_python_executable(argv[0]):
        raise IntegrityError("decisive experiments must use the bounded Python runtime")
    executable = python_executable.expanduser().resolve(strict=True)
    if not executable.is_file():
        raise IntegrityError("decisive experiment Python runtime is not a regular file")
    return (str(executable), *argv[1:])


@dataclass(frozen=True)
class ScenarioResult:
    run_id: str
    case_id: str
    fixture: DemoFixture
    receipt_path: Path
    receipt_digest_path: Path
    proof_manifest_path: Path
    events_path: Path
    receipt: Mapping[str, Any]
    proof_manifest: Mapping[str, Any]
    affected_effect_ids: tuple[str, ...]
    unaffected_effect_id: str
    invalid_commit: str
    quarantine_ref: str
    repaired_commit: str
    replacement_remote_ref: str
    concurrency_proof_path: Path | None
    strict_verification_valid: bool
    proven_requirement_ids: tuple[str, ...]

    @property
    def artifact_root(self) -> Path:
        return self.fixture.artifacts_root


class CanonicalScenario:
    """Real isolated Git/SQLite/HTTP canonical revocation scenario.

    ``prepare`` creates the fixture and durable Run immediately. ``run`` owns
    the scenario lifecycle but intentionally leaves the registry process alive
    until ``close`` so API callers can inspect it. Failures close it eagerly.
    """

    def __init__(
        self,
        fixture: DemoFixture,
        store: Store,
        *,
        scripted_codex: ScriptedCodex | None,
        live_codex_path: LiveCodexPath | None,
        python_executable: Path,
    ) -> None:
        if (scripted_codex is None) == (live_codex_path is None):
            raise ValidationError("select exactly one scripted or live Codex provider")
        self.fixture = fixture
        self.store = store
        self.artifact_root = fixture.artifacts_root
        self.python_executable = python_executable.expanduser().resolve(strict=True)
        self.scripted_codex = scripted_codex
        self.live_codex = live_codex_path
        self.runner = AsyncProcessRunner([fixture.root])
        self.push_tokens = GitPushTokenIssuer.from_file(fixture.push_secret_file)
        self.git = GitAdapter(
            [fixture.root],
            process_runner=self.runner,
            push_tokens=self.push_tokens,
        )
        self.migrations = SQLiteMigrationAdapter(
            [fixture.root],
            snapshot_dir=fixture.artifacts_root / "database-snapshots",
        )
        self.artifacts = ArtifactStore(fixture.artifacts_root / "objects")
        self.registry: SchemaRegistryProcess | None = None
        self.replacement_worktree = fixture.root / "worktrees" / "agent-a-replacement"
        self.experiment_worktree = fixture.root / "worktrees" / "agent-a-quarantined-probe"
        self._prepared = False
        self._ran = False
        self._original_files: dict[str, bytes] = {}
        self._initial_migration: SQLiteMigrationResult | None = None
        self._signed_evidence: dict[int, Mapping[str, Any]] = {}
        self._live_initial: LiveCodexResult | None = None
        self._live_agent_b_initial: LiveCodexResult | None = None
        self._live_analysis: ContradictionAnalysis | None = None
        self._live_proposals: ExperimentProposalResult | None = None
        self._live_concurrency_path: Path | None = None

    @classmethod
    async def prepare(
        cls,
        output_root: Path,
        *,
        run_id: str | None = None,
        python_executable: Path | None = None,
        scripted_codex: ScriptedCodex | None = None,
        live_codex: bool = False,
        codex_model: str | None = None,
        codex_bin: Path | None = None,
        codex_timeout_seconds: float = 900.0,
    ) -> CanonicalScenario:
        executable = (python_executable or Path(sys.executable)).expanduser().resolve(strict=True)
        identifier = run_id or new_id("run")
        fixture = await FixtureBuilder(
            output_root,
            python_executable=executable,
        ).build(identifier)
        store = Store(fixture.state_database)
        if live_codex and scripted_codex is not None:
            raise ValidationError("live Codex cannot use a scripted fallback provider")
        live_path = (
            await LiveCodexPath.create(
                fixture,
                model=codex_model,
                timeout_seconds=codex_timeout_seconds,
                codex_bin=codex_bin,
            )
            if live_codex
            else None
        )
        scenario = cls(
            fixture,
            store,
            scripted_codex=(
                None
                if live_codex
                else scripted_codex or ScriptedCodex(python_executable=executable)
            ),
            live_codex_path=live_path,
            python_executable=executable,
        )
        scenario._declare_run()
        return scenario

    async def close(self) -> None:
        registry, self.registry = self.registry, None
        if registry is not None:
            await registry.close()
        for process_id in self.runner.running_process_ids:
            await self.runner.cancel(process_id, reason="canonical_scenario_close")
        if self.live_codex is not None:
            for process_id in self.live_codex.runner.running_process_ids:
                await self.live_codex.runner.cancel(
                    process_id,
                    reason="canonical_scenario_close",
                )

    async def run(self) -> ScenarioResult:
        if not self._prepared:
            raise ValidationError("canonical scenario must be prepared before run")
        if self._ran:
            raise ValidationError("canonical scenario handles are single-use")
        self._ran = True
        try:
            self.registry = await SchemaRegistryProcess.start(
                self.fixture,
                runner=self.runner,
                python_executable=self.python_executable,
            )
            return await self._run()
        except BaseException:
            await self.close()
            raise

    def _declare_run(self) -> None:
        if self._prepared:
            return
        now = self.store.clock.utc_now()
        self.store.create_run(
            Run(
                id=self.fixture.run_id,
                name="TARS REVOKE canonical external-schema-v2 scenario",
                state=RunState.RUNNING,
                root_path=str(self.fixture.root),
                created_at=now,
                updated_at=now,
                metadata={
                    "scenario": "external-schema-v2",
                    "repair_provider": "live-codex" if self.live_codex else "scripted",
                },
            )
        )
        for agent_id, name, role, worktree in (
            (self._id("agent-a"), "Agent A", "billing migration", self.fixture.agent_a_worktree),
            (
                self._id("agent-b"),
                "Agent B",
                "independent observability",
                self.fixture.agent_b_worktree,
            ),
        ):
            self.store.create_agent(
                Agent(
                    id=agent_id,
                    run_id=self.fixture.run_id,
                    name=name,
                    role=role,
                    worktree_path=str(worktree),
                    state=AgentState.RUNNING,
                    created_at=now,
                    updated_at=now,
                )
            )
        self._prepared = True

    async def _run(self) -> ScenarioResult:
        assert self.registry is not None
        schema_v1 = self._load_json(self.fixture.repository / "schemas" / "billing-v1.json")
        schema_v2 = self._load_json(self.fixture.repository / "schemas" / "billing-v2.json")
        fetched_v1 = await self.registry.client.publish(
            SCHEMA_NAME,
            version=1,
            content=schema_v1,
        )
        evidence_v1, premise_v1 = self._record_schema_revision(fetched_v1, replaces=None)
        independent_premise = self._create_independent_premise()
        agent_b = self._prepare_agent_b(independent_premise)
        initial = await self._execute_agent_a_v1(premise_v1)

        fetched_v2 = await self.registry.client.publish(
            SCHEMA_NAME,
            version=2,
            content=schema_v2,
        )
        evidence_v2, premise_v2 = self._record_schema_revision(
            fetched_v2,
            replaces=premise_v1.id,
        )
        if self.live_codex is not None:
            if self._live_initial is None:
                raise IntegrityError("live Agent A session evidence is missing")
            self._live_analysis = await self.live_codex.analyze_contradiction(
                v1_evidence=self._signed_evidence[1],
                v2_evidence=self._signed_evidence[2],
                initial_result=self._live_initial,
                worktree=self.fixture.agent_b_worktree,
            )
        revocation = SelectiveRevoker(self.store).invalidate_and_fence(
            premise_v1.id,
            invalidating_evidence_id=evidence_v2.id,
            reason="signed billing schema v2 replaces UUID with an opaque cus_ identifier",
            case_id=self._id("case-schema-v2"),
        )
        self._require_exact_affected_set(revocation, initial["effect_ids"])

        unrelated = await self._execute_agent_b(agent_b)
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.INVENTORIED,
        )
        inventory_path = self._write_inventory(revocation, unrelated)
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.COMPENSATING,
        )
        compensation = await self._compensate_agent_a(revocation, initial)
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.EXPERIMENTING,
        )
        experiment = await self._run_experiment(revocation.case.id, premise_v2)
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.REPAIRING,
        )
        repair = await self._repair_under_v2(
            revocation.case.id,
            premise_v2,
            initial,
            compensation,
            experiment,
        )
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.VERIFYING,
        )
        tests = await self._run_verification(
            revocation.case.id,
            premise_v2,
            repair,
        )
        replacement_push = await self._push_replacement(
            revocation.case.id,
            premise_v2,
            initial,
            repair,
            tests,
        )
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.RESUMED,
        )
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.ATTESTED,
        )

        result = self._build_receipt(
            revocation=revocation,
            evidence_v1=evidence_v1,
            evidence_v2=evidence_v2,
            premise_v1=premise_v1,
            premise_v2=premise_v2,
            initial=initial,
            unrelated=unrelated,
            inventory_path=inventory_path,
            compensation=compensation,
            experiment=experiment,
            repair=repair,
            tests=tests,
            replacement_push=replacement_push,
        )
        self.store.transition_revocation_case(
            revocation.case.id,
            RevocationCaseState.CLOSED,
        )
        for agent in self.store.list_agents(self.fixture.run_id):
            self.store.transition_agent(agent.id, AgentState.COMPLETED)
        self.store.transition_run(self.fixture.run_id, RunState.COMPLETED)
        return result

    def _id(self, suffix: str) -> str:
        compact = re.sub(r"[^A-Za-z0-9._-]", "-", self.fixture.run_id)
        return f"{compact}:{suffix}"

    @property
    def proof_requirements(self) -> tuple[str, ...]:
        requirements = set(SCENARIO_PROOF_REQUIREMENTS)
        if self.live_codex is not None:
            requirements.update(("R-01", "R-14"))
        return tuple(sorted(requirements))

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValidationError(f"expected JSON object: {path}")
        return value

    def _record_schema_revision(
        self,
        fetched: Any,
        *,
        replaces: str | None,
    ) -> tuple[EvidenceRecord, Premise]:
        artifact = fetched.artifact
        self._signed_evidence[artifact.version] = artifact.model_dump(mode="json")
        now = self.store.clock.utc_now()
        named_path = self.fixture.artifacts_root / "evidence" / f"schema-v{artifact.version}.json"
        self._write_json(named_path, artifact.model_dump(mode="json"))
        stored_artifact = self._store_artifact_json(
            artifact.model_dump(mode="json"),
            metadata={"kind": "signed-schema", "version": artifact.version},
        )
        source_id = self._id("schema-registry")
        if self.store.get_evidence_source(source_id) is None:
            self.store.create_evidence_source(
                EvidenceSource(
                    id=source_id,
                    run_id=self.fixture.run_id,
                    name="signed billing schema registry",
                    uri=self.registry.base_url if self.registry is not None else fetched.url,
                    issuer=artifact.source_id,
                    public_key=self.fixture.registry_public_key_file.read_bytes().hex(),
                    signature_algorithm="Ed25519",
                    pinned_identity=f"{artifact.source_id}:{artifact.key_id}",
                    created_at=now,
                    metadata={"transport": "separate-local-http-process"},
                )
            )
        evidence = EvidenceRecord(
            id=self._id(f"schema-evidence-v{artifact.version}"),
            run_id=self.fixture.run_id,
            source_id=source_id,
            source_uri=fetched.url,
            source_version=artifact.version,
            observed_at=now,
            valid_at=artifact.issued_at,
            digest=artifact.digest,
            signature_status=SignatureStatus.VALID,
            verification_status=VerificationStatus.VERIFIED,
            artifact_digest=stored_artifact.digest,
            normalized_premises=(
                {
                    "subject": SCHEMA_NAME,
                    "relation": "customer-id-contract",
                    "value": {
                        "version": artifact.version,
                        "schema_digest": artifact.digest,
                        "customer_id": artifact.content["properties"]["customer_id"],
                    },
                },
            ),
            metadata={
                "etag": fetched.etag,
                "key_id": artifact.key_id,
                "source_id": artifact.source_id,
            },
        )
        self.store.create_evidence_record(evidence)
        premise_value = {
            "version": artifact.version,
            "schema_digest": artifact.digest,
            "customer_id": artifact.content["properties"]["customer_id"],
        }
        premise = Premise(
            id=self._id(f"schema-premise-v{artifact.version}"),
            run_id=self.fixture.run_id,
            scope=SCOPE,
            subject=SCHEMA_NAME,
            relation="customer-id-contract",
            value=premise_value,
            value_digest=canonical_digest(premise_value),
            semantics=ValueSemantics.TEMPORAL,
            state=PremiseState.ACTIVE,
            valid_at=artifact.issued_at,
            replaces_premise_id=replaces,
            created_at=now,
        )
        self.store.create_premise(premise)
        self.store.link_premise_evidence(
            PremiseEvidence(
                premise_id=premise.id,
                evidence_id=evidence.id,
                role=EvidenceRole.SUPPORTS,
                confidence=1.0,
                created_at=now,
            )
        )
        self._create_node(NodeKind.EVIDENCE, evidence.id, scope=SCOPE)
        self._create_node(NodeKind.PREMISE, premise.id, scope=SCOPE)
        return evidence, premise

    def _create_independent_premise(self) -> Premise:
        now = self.store.clock.utc_now()
        premise_value = {"owner": "agent-b", "schema_independent": True}
        premise = Premise(
            id=self._id("observability-premise"),
            run_id=self.fixture.run_id,
            scope="observability-docs",
            subject="docs/observability.md",
            relation="ownership",
            value=premise_value,
            value_digest=canonical_digest(premise_value),
            semantics=ValueSemantics.SINGLE,
            state=PremiseState.ACTIVE,
            valid_at=now,
            created_at=now,
        )
        self.store.create_premise(premise)
        self._create_node(NodeKind.PREMISE, premise.id, scope="observability-docs")
        return premise

    def _create_warrant(
        self,
        *,
        suffix: str,
        agent_id: str,
        premise: Premise,
        risk: RiskLevel,
        binding_stage: str,
        authorized_targets: tuple[str, ...],
        artifact_hashes: Mapping[str, str],
        evidence_ids: tuple[str, ...] = (),
        required_tests: tuple[str, ...] = (),
        replaces_warrant_id: str | None = None,
    ) -> Warrant:
        if not binding_stage.strip():
            raise ValidationError("warrant binding stage is required")
        if not artifact_hashes:
            raise ValidationError("consequential scenario warrants require artifact bindings")
        now = self.store.clock.utc_now()
        warrant = Warrant(
            id=self._id(suffix),
            run_id=self.fixture.run_id,
            agent_id=agent_id,
            scope=premise.scope,
            authorized_targets=authorized_targets,
            state=WarrantState.AUTHORIZED,
            risk=risk,
            revision_epoch=1,
            artifact_hashes=dict(artifact_hashes),
            required_tests=required_tests,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(hours=1),
            replaces_warrant_id=replaces_warrant_id,
            metadata={
                "authority": "continuous-evidence-warrant",
                "binding_stage": binding_stage,
                "artifact_keys": sorted(artifact_hashes),
                "evidence_ids": list(evidence_ids),
                "required_test_ids": list(required_tests),
            },
        )
        self.store.create_warrant(warrant)
        self.store.link_warrant_premise(
            WarrantPremise(
                warrant_id=warrant.id,
                premise_id=premise.id,
                premise_digest=premise.value_digest,
                created_at=now,
            )
        )
        self._create_node(NodeKind.WARRANT, warrant.id, scope=premise.scope)
        premise_node = self._node_for(NodeKind.PREMISE, premise.id)
        warrant_node = self._node_for(NodeKind.WARRANT, warrant.id)
        self._create_edge(
            f"{suffix}-requires-premise",
            premise_node.id,
            warrant_node.id,
            scope=premise.scope,
        )
        return warrant

    def _premise_artifact_bindings(
        self,
        premise: Premise,
    ) -> tuple[dict[str, str], tuple[str, ...]]:
        """Bind a stage to the exact premise revision and supporting evidence bytes."""

        bindings = {f"premise:{premise.id}": premise.value_digest}
        evidence_ids: list[str] = []
        for link in self.store.list_premise_evidence(premise.id):
            evidence = self.store.get_evidence_record(link.evidence_id)
            if evidence is None:
                raise IntegrityError(f"premise evidence disappeared: {link.evidence_id}")
            bindings[f"evidence:{evidence.id}"] = evidence.artifact_digest or evidence.digest
            evidence_ids.append(evidence.id)
        return bindings, tuple(evidence_ids)

    @staticmethod
    def _regular_file_bindings(
        worktree: Path,
        paths: tuple[str, ...],
    ) -> dict[str, str]:
        root = worktree.expanduser().resolve(strict=True)
        bindings: dict[str, str] = {}
        for relative in paths:
            candidate = root / relative
            if candidate.is_symlink():
                raise IntegrityError(f"bound scenario artifact cannot be a symlink: {relative}")
            try:
                path = candidate.resolve(strict=True)
            except OSError as exc:
                raise IntegrityError(f"bound scenario artifact is missing: {relative}") from exc
            if root not in path.parents or path.relative_to(root).as_posix() != relative:
                raise IntegrityError(f"bound scenario artifact escaped its worktree: {relative}")
            if not path.is_file():
                raise IntegrityError(f"bound scenario artifact is not a regular file: {relative}")
            bindings[f"file:{relative}"] = sha256_digest(path.read_bytes())
        return bindings

    def _command_bindings(
        self,
        *,
        cwd: Path,
        argv: tuple[str, ...],
        required_paths: tuple[str, ...] = (),
    ) -> dict[str, str]:
        """Bind a command warrant to exact argv, cwd, executable, and file inputs."""

        if not argv or any(not argument for argument in argv):
            raise IntegrityError("command authorization requires a complete argv")
        root = cwd.expanduser().resolve(strict=True)
        executable = Path(argv[0]).expanduser().resolve(strict=True)
        if executable.is_symlink() or not executable.is_file():
            raise IntegrityError("command executable must be a regular file")
        bindings = {
            "command:argv": canonical_digest(list(argv)),
            "command:cwd": canonical_digest(str(root)),
            "command:executable": sha256_digest(executable.read_bytes()),
        }
        discovered_paths = set(required_paths)
        for argument in argv[1:]:
            if (
                not argument
                or argument.startswith(("-", "/"))
                or len(argument) > 512
                or re.fullmatch(r"[A-Za-z0-9_./-]+", argument) is None
            ):
                continue
            candidate = root / argument
            if candidate.exists():
                resolved = candidate.resolve(strict=True)
                if root in resolved.parents and resolved.is_file():
                    discovered_paths.add(resolved.relative_to(root).as_posix())
        bindings.update(self._regular_file_bindings(root, tuple(sorted(discovered_paths))))
        return bindings

    @staticmethod
    def _command_target(*, cwd: Path, argv: tuple[str, ...]) -> str:
        return f"command:{canonical_digest({'cwd': str(cwd.resolve()), 'argv': list(argv)})}"

    def _fail_dispatched_effect(
        self,
        *,
        action_id: str,
        effect_id: str,
        reason: str,
    ) -> None:
        self.store.transition_effect(effect_id, EffectState.FAILED)
        self.store.transition_action(
            action_id,
            ActionState.FAILED,
            failure_reason=reason,
        )

    @staticmethod
    def _git_object_bindings(*, commit: str, tree: str) -> dict[str, str]:
        object_pattern = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
        if not re.fullmatch(object_pattern, commit) or not re.fullmatch(object_pattern, tree):
            raise IntegrityError("Git authorization binding contains an invalid object ID")
        return {
            "git:commit-oid": sha256_digest(commit),
            "git:tree-oid": sha256_digest(tree),
        }

    async def _git_tree(self, repository: Path, commit: str) -> str:
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
            raise IntegrityError("cannot bind an invalid Git commit ID")
        result = await self.runner.run(
            ("git", "-C", str(repository), "rev-parse", f"{commit}^{{tree}}"),
            cwd=repository,
            timeout_seconds=30,
        )
        tree = result.stdout.strip()
        if not result.succeeded or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree):
            raise IntegrityError("failed to resolve exact Git tree for authorization")
        return tree

    def _create_action(
        self,
        *,
        suffix: str,
        agent_id: str,
        warrant: Warrant,
        premise: Premise,
        action_type: ActionType,
        target: str,
        payload: Any,
        risk: RiskLevel,
        reversibility: Reversibility,
        not_before: Any | None = None,
        replaces_action_id: str | None = None,
        scope: str | None = None,
    ) -> ActionIntent:
        now = self.store.clock.utc_now()
        action = ActionIntent(
            id=self._id(suffix),
            run_id=self.fixture.run_id,
            agent_id=agent_id,
            warrant_id=warrant.id,
            scope=scope or premise.scope,
            action_type=action_type,
            target=target,
            payload_digest=canonical_digest(payload),
            premise_vector={premise.id: premise.value_digest},
            artifact_vector=dict(warrant.artifact_hashes),
            risk=risk,
            reversibility=reversibility,
            state=ActionState.PREPARED,
            not_before=not_before,
            idempotency_key=self._id(f"idempotency-{suffix}"),
            replaces_action_id=replaces_action_id,
            created_at=now,
            updated_at=now,
        )
        self.store.create_action(action)
        action_scope = scope or premise.scope
        self._create_node(NodeKind.ACTION, action.id, scope=action_scope)
        self._create_edge(
            f"{suffix}-requires-warrant",
            self._node_for(NodeKind.WARRANT, warrant.id).id,
            self._node_for(NodeKind.ACTION, action.id).id,
            scope=action_scope,
        )
        return action

    def _create_effect_node(self, effect: EffectRecord, *, scope: str) -> None:
        self._create_node(NodeKind.EFFECT, effect.id, scope=scope)
        self._create_edge(
            f"{effect.id}-materializes-action",
            self._node_for(NodeKind.ACTION, effect.action_id).id,
            self._node_for(NodeKind.EFFECT, effect.id).id,
            scope=scope,
        )

    def _create_effect_intent(
        self,
        *,
        suffix: str,
        action: ActionIntent,
        effect_type: EffectType,
        before_hash: str | None = None,
        after_hash: str | None = None,
        forward_artifact_digest: str | None = None,
        reverse_artifact_digest: str | None = None,
        compensation_handler: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EffectRecord:
        now = self.store.clock.utc_now()
        return self.store.create_effect(
            EffectRecord(
                id=self._id(suffix),
                run_id=self.fixture.run_id,
                action_id=action.id,
                scope=action.scope,
                target=action.target,
                effect_type=effect_type,
                before_hash=before_hash,
                after_hash=after_hash,
                forward_artifact_digest=forward_artifact_digest,
                reverse_artifact_digest=reverse_artifact_digest,
                reversibility=action.reversibility,
                compensation_handler=compensation_handler,
                state=EffectState.PREPARED,
                created_at=now,
                updated_at=now,
                idempotency_key=self._id(f"effect-key-{suffix}"),
                metadata=dict(metadata or {}),
            )
        )

    def _create_node(self, kind: NodeKind, entity_id: str, *, scope: str) -> GraphNode:
        node = GraphNode(
            id=self._id(f"node-{kind.value.lower()}-{entity_id.rsplit(':', 1)[-1]}"),
            run_id=self.fixture.run_id,
            kind=kind,
            entity_id=entity_id,
            scope=scope,
            created_at=self.store.clock.utc_now(),
        )
        self.store.create_graph_node(node)
        return node

    def _node_for(self, kind: NodeKind, entity_id: str) -> GraphNode:
        node = self.store.find_graph_node(self.fixture.run_id, kind.value, entity_id)
        if node is None:
            raise IntegrityError(f"missing {kind.value} graph node for {entity_id}")
        return node

    def _create_edge(
        self,
        suffix: str,
        source_node_id: str,
        target_node_id: str,
        *,
        scope: str,
        edge_type: EdgeType = EdgeType.REQUIRES,
    ) -> DependencyEdge:
        edge = DependencyEdge(
            id=self._id(f"edge-{suffix}"),
            run_id=self.fixture.run_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            strength=EdgeStrength.HARD,
            scope=scope,
            declared_by="canonical-scenario",
            confidence=1.0,
            created_at=self.store.clock.utc_now(),
        )
        self.store.create_dependency_edge(edge)
        return edge

    async def _execute_agent_a_v1(self, premise: Premise) -> dict[str, Any]:
        agent_id = self._id("agent-a")
        gateway = EffectGateway(self.store)
        allowed_initial_paths = ("billing/models.py", MIGRATION_SOURCE_PATH)
        before_contents = {
            path: (self.fixture.agent_a_worktree / path).read_bytes()
            for path in allowed_initial_paths
        }
        before_files = {path: sha256_digest(content) for path, content in before_contents.items()}
        for path, content in before_contents.items():
            self._store_artifact_bytes(
                content,
                media_type="application/octet-stream",
                metadata={"kind": "before-image", "path": path},
            )
        reverse_manifest = self._store_artifact_json(before_files)
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise)
        edit_bindings = {
            **premise_bindings,
            **self._regular_file_bindings(
                self.fixture.agent_a_worktree,
                allowed_initial_paths,
            ),
        }
        model_warrant = self._create_warrant(
            suffix="warrant-agent-a-model-v1",
            agent_id=agent_id,
            premise=premise,
            risk=RiskLevel.HIGH,
            binding_stage="agent-a-v1-local-commit",
            authorized_targets=(",".join(allowed_initial_paths),),
            artifact_hashes=edit_bindings,
            evidence_ids=evidence_ids,
        )
        model_action = self._create_action(
            suffix="action-agent-a-model-v1",
            agent_id=agent_id,
            warrant=model_warrant,
            premise=premise,
            action_type=ActionType.LOCAL_COMMIT,
            target=",".join(allowed_initial_paths),
            payload={"contract": "UUID"},
            risk=RiskLevel.HIGH,
            reversibility=Reversibility.REVERSIBLE,
        )
        model_effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-model-v1",
            action=model_action,
            effect_type=EffectType.LOCAL_COMMIT,
            before_hash=canonical_digest(before_files),
            reverse_artifact_digest=reverse_manifest.digest,
            compensation_handler="git.restore_paths",
            metadata={
                "allowed_paths": list(allowed_initial_paths),
                "repository": str(self.fixture.agent_a_worktree),
            },
        )
        model_auth = gateway.authorize(
            model_action.id,
            effect_id=model_effect_intent.id,
            current_artifact_hashes=edit_bindings,
            passed_test_ids=(),
        )
        model_grant = gateway.dispatch(
            model_action.id,
            effect_id=model_effect_intent.id,
            capability_token=model_auth.capability_token,
            current_artifact_hashes=edit_bindings,
            passed_test_ids=(),
        )
        if self.live_codex is not None:
            self._live_initial, self._live_agent_b_initial = await self._run_live_initial_pair(
                allowed_initial_paths=allowed_initial_paths,
            )
            self._live_concurrency_path = self._persist_live_concurrency_proof(
                self._live_initial,
                self._live_agent_b_initial,
            )
            changed_paths = self._live_initial.changed_paths
        else:
            if self.scripted_codex is None:
                raise IntegrityError("scripted Codex provider is missing")
            changed_paths = self.scripted_codex.initial_uuid_change(self.fixture.agent_a_worktree)
        if set(changed_paths) != set(allowed_initial_paths):
            raise IntegrityError(
                "initial UUID change must modify exactly the model and managed migration"
            )
        migration_source = validate_migration_source(
            self.fixture.agent_a_worktree,
            expected_contract="uuid",
        )
        migration_proof = self._persist_migration_source(
            migration_source,
            stage="agent-a-v1",
        )
        migration_bindings = {
            **premise_bindings,
            f"file:{migration_source.relative_path}": migration_source.sha256,
        }
        migration_warrant = self._create_warrant(
            suffix="warrant-agent-a-db-v1",
            agent_id=agent_id,
            premise=premise,
            risk=RiskLevel.CRITICAL,
            binding_stage="agent-a-v1-migration",
            authorized_targets=(str(self.fixture.service_database),),
            artifact_hashes=migration_bindings,
            evidence_ids=evidence_ids,
        )
        migration_action = self._create_action(
            suffix="action-agent-a-db-v1",
            agent_id=agent_id,
            warrant=migration_warrant,
            premise=premise,
            action_type=ActionType.DATABASE_MIGRATION,
            target=str(self.fixture.service_database),
            payload={
                "source_path": migration_source.relative_path,
                "source_sha256": migration_source.sha256,
                "sql": migration_source.sql,
            },
            risk=RiskLevel.CRITICAL,
            reversibility=Reversibility.REVERSIBLE,
        )
        migration_snapshot = await self.migrations.snapshot(
            self.fixture.service_database,
            action_id=migration_action.id,
        )
        migration_effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-db-v1",
            action=migration_action,
            effect_type=EffectType.DATABASE_MIGRATION,
            before_hash=migration_snapshot.sha256,
            compensation_handler="sqlite.restore_snapshot",
            metadata={
                "snapshot_path": str(migration_snapshot.snapshot_path),
                "snapshot_sha256": migration_snapshot.sha256,
                "source_path": migration_source.relative_path,
                "source_sha256": migration_source.sha256,
            },
        )
        migration_auth = gateway.authorize(
            migration_action.id,
            effect_id=migration_effect_intent.id,
            current_artifact_hashes=migration_bindings,
            passed_test_ids=(),
        )
        migration_grant = gateway.dispatch(
            migration_action.id,
            effect_id=migration_effect_intent.id,
            capability_token=migration_auth.capability_token,
            current_artifact_hashes=migration_bindings,
            passed_test_ids=(),
        )
        migration_result = await self.migrations.apply(
            self.fixture.service_database,
            migration_source.sql,
            action_id=migration_action.id,
        )
        if migration_result.after_user_version != migration_source.user_version:
            raise IntegrityError("agent-authored UUID migration set the wrong user_version")
        self._initial_migration = migration_result
        migration_effect = EffectRecord.model_validate(
            migration_grant.effect.model_copy(
                update={
                    "after_hash": migration_result.after_hash,
                    "state": EffectState.EXECUTED,
                    "metadata": {
                        **dict(migration_grant.effect.metadata),
                        "before_user_version": migration_result.before_user_version,
                        "after_user_version": migration_result.after_user_version,
                        "source_artifact_digest": migration_proof["artifact_digest"],
                        "source_proof_path": str(migration_proof["proof_path"]),
                    },
                }
            ).model_dump()
        )
        gateway.complete(migration_effect)
        self._original_files = {path: before_contents[path] for path in changed_paths}
        invalid_commit = await self.git.commit(
            self.fixture.agent_a_worktree,
            message="migrate billing customer IDs to UUID",
            paths=changed_paths,
        )
        invalid_tree = await self._git_tree(
            self.fixture.agent_a_worktree,
            invalid_commit.commit,
        )
        before_files = {path: sha256_digest(self._original_files[path]) for path in changed_paths}
        after_contents = {
            path: (self.fixture.agent_a_worktree / path).read_bytes() for path in changed_paths
        }
        after_files = {path: sha256_digest(content) for path, content in after_contents.items()}
        for path, content in self._original_files.items():
            self._store_artifact_bytes(
                content,
                media_type="application/octet-stream",
                metadata={"kind": "before-image", "path": path},
            )
        for path, content in after_contents.items():
            self._store_artifact_bytes(
                content,
                media_type="application/octet-stream",
                metadata={"kind": "invalid-forward-image", "path": path},
            )
        model_effect = EffectRecord.model_validate(
            model_grant.effect.model_copy(
                update={
                    "after_hash": canonical_digest(after_files),
                    "forward_artifact_digest": self._store_artifact_json(after_files).digest,
                    "state": EffectState.EXECUTED,
                    "metadata": {
                        **dict(model_grant.effect.metadata),
                        "commit": invalid_commit.commit,
                        "parent": invalid_commit.parent,
                        "worktree": str(self.fixture.agent_a_worktree),
                        "changed_paths": changed_paths,
                    },
                }
            ).model_dump()
        )
        gateway.complete(model_effect)
        invalid_patch = await self.git.diff(
            self.fixture.agent_a_worktree,
            base=self.fixture.baseline_commit,
            head=invalid_commit.commit,
            paths=changed_paths,
        )
        (self.fixture.artifacts_root / "git" / "invalid.patch").write_text(
            invalid_patch,
            encoding="utf-8",
        )

        preflight_started = self.store.clock.utc_now()
        not_before = preflight_started + timedelta(seconds=3)
        push_bindings = {
            **premise_bindings,
            **self._git_object_bindings(
                commit=invalid_commit.commit,
                tree=invalid_tree,
            ),
        }
        push_warrant = self._create_warrant(
            suffix="warrant-agent-a-push-v1",
            agent_id=agent_id,
            premise=premise,
            risk=RiskLevel.CRITICAL,
            binding_stage="agent-a-v1-push",
            authorized_targets=("refs/heads/agent-a-invalid",),
            artifact_hashes=push_bindings,
            evidence_ids=evidence_ids,
        )
        push_action = self._create_action(
            suffix="action-agent-a-push-v1",
            agent_id=agent_id,
            warrant=push_warrant,
            premise=premise,
            action_type=ActionType.PUSH,
            target="refs/heads/agent-a-invalid",
            payload={
                "commit": invalid_commit.commit,
                "tree": invalid_tree,
                "refspec": "HEAD:refs/heads/agent-a-invalid",
            },
            risk=RiskLevel.CRITICAL,
            reversibility=Reversibility.IRREVERSIBLE,
            not_before=not_before,
        )
        remote_url = await self.git.remote_url(self.fixture.agent_a_worktree, "origin")
        refspec = "HEAD:refs/heads/agent-a-invalid"
        push_effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-push-v1",
            action=push_action,
            effect_type=EffectType.PUSH,
            after_hash=invalid_commit.commit,
            metadata={
                "dispatch_not_before": not_before,
                "repository": str(self.fixture.agent_a_worktree),
                "remote": "origin",
                "remote_url": remote_url,
                "destination": "refs/heads/agent-a-invalid",
                "refspec": refspec,
                "source_oid": invalid_commit.commit,
                "commit": invalid_commit.commit,
                "tree": invalid_tree,
            },
        )
        push_auth = gateway.authorize(
            push_action.id,
            effect_id=push_effect_intent.id,
            current_artifact_hashes=push_bindings,
            passed_test_ids=(),
        )
        push_effect = push_auth.effect
        preflight_path = self.fixture.artifacts_root / "logs" / "agent-a-push-preflight.json"
        self._write_json(
            preflight_path,
            {
                "action_id": push_action.id,
                "effect_id": push_effect.id,
                "state": "AUTHORIZED_NOT_DISPATCHED",
                "preflight_started_at": preflight_started,
                "dispatch_not_before": not_before,
                "preflight_seconds": 3,
                "commit": invalid_commit.commit,
                "tree": invalid_tree,
                "artifact_hashes": push_bindings,
            },
        )
        return {
            "warrant_id": model_warrant.id,
            "warrant_ids": (
                model_warrant.id,
                migration_warrant.id,
                push_warrant.id,
            ),
            "model_warrant_id": model_warrant.id,
            "migration_warrant_id": migration_warrant.id,
            "push_warrant_id": push_warrant.id,
            "migration_action_id": migration_action.id,
            "model_action_id": model_action.id,
            "push_action_id": push_action.id,
            "migration_effect_id": migration_effect.id,
            "model_effect_id": model_effect.id,
            "push_effect_id": push_effect.id,
            "effect_ids": (migration_effect.id, model_effect.id, push_effect.id),
            "invalid_commit": invalid_commit.commit,
            "invalid_parent": invalid_commit.parent,
            "invalid_tree": invalid_tree,
            "preflight_path": preflight_path,
            "preflight_started_at": preflight_started,
            "dispatch_not_before": not_before,
            "migration_source_proof_path": migration_proof["proof_path"],
            "migration_source_sql_path": migration_proof["sql_path"],
            "migration_source_sha256": migration_source.sha256,
        }

    async def _run_live_initial_pair(
        self,
        *,
        allowed_initial_paths: tuple[str, ...],
    ) -> tuple[LiveCodexResult, LiveCodexResult]:
        live = self.live_codex
        if live is None:
            raise IntegrityError("live Codex provider is missing")
        agent_a = asyncio.create_task(
            live.initial_uuid_change(
                "Migrate billing customer identifiers under the signed v1 UUID contract.",
                v1_evidence=self._signed_evidence[1],
                worktree=self.fixture.agent_a_worktree,
                allowed_paths=allowed_initial_paths,
            ),
            name=f"{self.fixture.run_id}:agent-a-initial",
        )
        agent_b = asyncio.create_task(
            live.unrelated_observability_change(
                worktree=self.fixture.agent_b_worktree,
                allowed_paths=("docs/observability.md",),
            ),
            name=f"{self.fixture.run_id}:agent-b-observability",
        )
        try:
            result_a, result_b = await asyncio.gather(agent_a, agent_b)
        except BaseException:
            for task in (agent_a, agent_b):
                if not task.done():
                    task.cancel()
            await asyncio.gather(agent_a, agent_b, return_exceptions=True)
            raise
        return result_a, result_b

    def _persist_live_concurrency_proof(
        self,
        agent_a: LiveCodexResult,
        agent_b: LiveCodexResult,
    ) -> Path:
        sessions = (
            self._persist_live_session("agent_a", self._id("agent-a"), agent_a),
            self._persist_live_session("agent_b", self._id("agent-b"), agent_b),
        )
        proof = build_concurrent_codex_proof(
            run_id=self.fixture.run_id,
            artifact_root=self.artifact_root,
            sessions=sessions,
        )
        path = self.artifact_root / "agents" / "concurrent-codex-proof.json"
        self._write_json(path, proof)
        verification = verify_concurrent_codex_proof(
            proof,
            artifact_root=self.artifact_root,
            expected_run_id=self.fixture.run_id,
        )
        if not verification.valid:
            raise IntegrityError("concurrent Codex proof verification failed")
        return path

    def _persist_live_session(
        self,
        lane: str,
        agent_id: str,
        result: LiveCodexResult,
    ) -> CodexSessionEvidence:
        suffix = "agent-a-initial" if lane == "agent_a" else "agent-b-observability"
        session_id = self._id(f"session-{suffix}")
        relative_manifest = result.artifacts.manifest_path.relative_to(self.artifact_root)
        relative_events = result.artifacts.events_path.relative_to(self.artifact_root)
        relative_observations = result.artifacts.event_observations_path.relative_to(
            self.artifact_root
        )
        session = AgentSession(
            id=session_id,
            run_id=self.fixture.run_id,
            agent_id=agent_id,
            provider="live-codex",
            external_session_id=result.thread_id,
            state=SessionState.RUNNING,
            started_at=result.started_at_utc,
            updated_at=result.started_at_utc,
            process_id=result.pid,
            metadata={
                "stage": result.stage,
                "worktree": str(result.worktree),
                "process_handle_id": result.process_id,
                "process_started_monotonic": result.process_started_monotonic,
                "process_finished_monotonic": result.process_finished_monotonic,
                "duration_seconds": result.duration_seconds,
                "manifest_path": relative_manifest.as_posix(),
                "manifest_digest": result.artifacts.manifest_digest,
                "events_path": relative_events.as_posix(),
                "event_observations_path": relative_observations.as_posix(),
            },
        )
        self.store.create_agent_session(session)
        self.store.transition_agent_session(
            session.id,
            SessionState.COMPLETED,
            at=result.finished_at_utc,
        )

        raw_lines = result.artifacts.events_path.read_bytes().splitlines()
        events: list[LiveEventEvidence] = []
        for observation in result.event_observations:
            if observation.sequence <= 0 or observation.sequence > len(raw_lines):
                raise IntegrityError("live Codex observation is absent from raw JSONL")
            events.append(
                LiveEventEvidence(
                    sequence=observation.sequence,
                    event_type=observation.event_type,
                    observed_at=observation.observed_at_utc,
                    observed_monotonic=observation.observed_monotonic,
                    raw_digest=sha256_digest(raw_lines[observation.sequence - 1]),
                    thread_id=observation.thread_id,
                    turn_id=observation.turn_id,
                    item_id=observation.item_id,
                )
            )
        return CodexSessionEvidence(
            lane=lane,
            agent_id=agent_id,
            session_record_id=session.id,
            external_session_id=result.thread_id,
            provider="live-codex",
            worktree=result.worktree,
            process_handle_id=result.process_id,
            pid=result.pid,
            started_at=result.started_at_utc,
            ended_at=result.finished_at_utc,
            started_monotonic=result.process_started_monotonic,
            ended_monotonic=result.process_finished_monotonic,
            manifest_path=result.artifacts.manifest_path,
            events_path=result.artifacts.events_path,
            event_observations_path=result.artifacts.event_observations_path,
            events=tuple(events),
        )

    def _persist_migration_source(
        self,
        source: ValidatedMigrationSource,
        *,
        stage: str,
    ) -> dict[str, Any]:
        root = self.artifact_root / "database-migrations"
        root.mkdir(parents=True, exist_ok=True)
        sql_path = root / f"{stage}.sql"
        sql_path.write_bytes(source.payload)
        if sha256_digest(sql_path.read_bytes()) != source.sha256:
            raise IntegrityError("named migration proof differs from validated source bytes")
        artifact = self._store_artifact_bytes(
            source.payload,
            media_type="application/sql",
            metadata={
                "kind": "agent-authored-migration",
                "stage": stage,
                "source_path": source.relative_path,
                "contract": source.contract,
                "user_version": source.user_version,
            },
        )
        proof_path = root / f"{stage}-source.json"
        self._write_json(
            proof_path,
            {
                "stage": stage,
                "contract": source.contract,
                "source_path": source.relative_path,
                "source_sha256": source.sha256,
                "source_size": len(source.payload),
                "user_version": source.user_version,
                "executed_sql_path": sql_path.relative_to(self.artifact_root).as_posix(),
                "artifact_digest": artifact.digest,
            },
        )
        return {
            "proof_path": proof_path,
            "sql_path": sql_path,
            "artifact_digest": artifact.digest,
        }

    def _prepare_agent_b(self, premise: Premise) -> dict[str, Any]:
        docs_relative = "docs/observability.md"
        docs_path = self.fixture.agent_b_worktree / docs_relative
        before_content = docs_path.read_bytes()
        before_files = {docs_relative: sha256_digest(before_content)}
        before_artifact = self._store_artifact_bytes(
            before_content,
            media_type="text/markdown; charset=utf-8",
            metadata={"kind": "agent-b-before-image", "path": docs_relative},
        )
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise)
        commit_bindings = {
            **premise_bindings,
            **self._regular_file_bindings(
                self.fixture.agent_b_worktree,
                (docs_relative,),
            ),
        }
        warrant = self._create_warrant(
            suffix="warrant-agent-b-observability-commit",
            agent_id=self._id("agent-b"),
            premise=premise,
            risk=RiskLevel.MEDIUM,
            binding_stage="agent-b-observability-local-commit",
            authorized_targets=(docs_relative,),
            artifact_hashes=commit_bindings,
            evidence_ids=evidence_ids,
        )
        action = self._create_action(
            suffix="action-agent-b-local-commit",
            agent_id=self._id("agent-b"),
            warrant=warrant,
            premise=premise,
            action_type=ActionType.LOCAL_COMMIT,
            target=docs_relative,
            payload={
                "path": docs_relative,
                "message": "document independent billing observability",
            },
            risk=RiskLevel.MEDIUM,
            reversibility=Reversibility.REVERSIBLE,
        )
        effect_intent = self._create_effect_intent(
            suffix="effect-agent-b-local-commit",
            action=action,
            effect_type=EffectType.LOCAL_COMMIT,
            before_hash=canonical_digest(before_files),
            reverse_artifact_digest=before_artifact.digest,
            compensation_handler="git.restore_paths",
            metadata={
                "allowed_paths": [docs_relative],
                "repository": str(self.fixture.agent_b_worktree),
            },
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action.id,
            effect_id=effect_intent.id,
            current_artifact_hashes=commit_bindings,
            passed_test_ids=(),
        )
        grant = gateway.dispatch(
            action.id,
            effect_id=effect_intent.id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=commit_bindings,
            passed_test_ids=(),
        )
        return {
            "premise": premise,
            "commit_warrant_id": warrant.id,
            "commit_action_id": action.id,
            "commit_effect_id": effect_intent.id,
            "commit_bindings": commit_bindings,
            "commit_grant": grant,
        }

    async def _execute_agent_b(self, prepared: Mapping[str, Any]) -> dict[str, Any]:
        premise = cast(Premise, prepared["premise"])
        docs_relative = "docs/observability.md"
        docs_path = self.fixture.agent_b_worktree / docs_relative
        if self.live_codex is not None:
            live_result = self._live_agent_b_initial
            if live_result is None:
                raise IntegrityError("live Agent B observability session evidence is missing")
            if live_result.changed_paths != ("docs/observability.md",):
                raise IntegrityError("live Agent B changed paths outside observability docs")
            if "billing_customer_id_rejections_total" not in docs_path.read_text(
                encoding="utf-8"
            ):
                raise IntegrityError("live Agent B omitted the authorized observability metric")
        else:
            docs_path.write_text(
                docs_path.read_text(encoding="utf-8")
                + "\nAgent B independently documents the customer-id rejection metric.\n",
                encoding="utf-8",
            )
        commit = await self.git.commit(
            self.fixture.agent_b_worktree,
            message="document independent billing observability",
            paths=("docs/observability.md",),
        )
        tree = await self._git_tree(self.fixture.agent_b_worktree, commit.commit)
        after_files = {docs_relative: sha256_digest(docs_path.read_bytes())}
        commit_grant = prepared["commit_grant"]
        commit_effect = EffectRecord.model_validate(
            commit_grant.effect.model_copy(
                update={
                    "after_hash": canonical_digest(after_files),
                    "forward_artifact_digest": self._store_artifact_json(after_files).digest,
                    "state": EffectState.EXECUTED,
                    "metadata": {
                        **dict(commit_grant.effect.metadata),
                        "commit": commit.commit,
                        "parent": commit.parent,
                        "tree": tree,
                        "changed_paths": [docs_relative],
                    },
                }
            ).model_dump()
        )
        EffectGateway(self.store).complete(commit_effect)
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise)
        push_bindings = {
            **premise_bindings,
            **self._regular_file_bindings(
                self.fixture.agent_b_worktree,
                ("docs/observability.md",),
            ),
            **self._git_object_bindings(commit=commit.commit, tree=tree),
        }
        warrant = self._create_warrant(
            suffix="warrant-agent-b-observability",
            agent_id=self._id("agent-b"),
            premise=premise,
            risk=RiskLevel.MEDIUM,
            binding_stage="agent-b-observability-push",
            authorized_targets=("refs/heads/agent-b-observability",),
            artifact_hashes=push_bindings,
            evidence_ids=evidence_ids,
        )
        action = self._create_action(
            suffix="action-agent-b-push",
            agent_id=self._id("agent-b"),
            warrant=warrant,
            premise=premise,
            action_type=ActionType.PUSH,
            target="refs/heads/agent-b-observability",
            payload={
                "path": "docs/observability.md",
                "commit": commit.commit,
                "tree": tree,
            },
            risk=RiskLevel.MEDIUM,
            reversibility=Reversibility.CONDITIONAL,
            scope=premise.scope,
        )
        refspec = "HEAD:refs/heads/agent-b-observability"
        remote_url = await self.git.remote_url(self.fixture.agent_b_worktree, "origin")
        effect_intent = self._create_effect_intent(
            suffix="effect-agent-b-push",
            action=action,
            effect_type=EffectType.PUSH,
            after_hash=commit.commit,
            metadata={
                "repository": str(self.fixture.agent_b_worktree),
                "remote": "origin",
                "remote_url": remote_url,
                "destination": "refs/heads/agent-b-observability",
                "refspec": refspec,
                "source_oid": commit.commit,
                "commit": commit.commit,
                "tree": tree,
            },
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action.id,
            effect_id=effect_intent.id,
            current_artifact_hashes=push_bindings,
            passed_test_ids=(),
        )
        grant = gateway.dispatch(
            action.id,
            effect_id=effect_intent.id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=push_bindings,
            passed_test_ids=(),
        )
        push_token = self.push_tokens.issue(
            action_id=action.id,
            epoch=grant.epoch,
            repository=self.fixture.agent_b_worktree,
            remote_url=remote_url,
            refspec=refspec,
            source_oid=commit.commit,
        )
        pushed = await self.git.push(
            self.fixture.agent_b_worktree,
            remote="origin",
            refspec=refspec,
            capability_token=push_token,
            action_id=action.id,
            epoch=grant.epoch,
        )
        effect = EffectRecord.model_validate(
            grant.effect.model_copy(
                update={
                    "before_hash": pushed.before_remote_head,
                    "after_hash": pushed.after_remote_head,
                    "state": EffectState.EXECUTED,
                }
            ).model_dump()
        )
        gateway.complete(effect)
        path = self.fixture.artifacts_root / "git" / "agent-b-push.json"
        self._write_json(
            path,
            {
                "commit_effect_id": commit_effect.id,
                "effect_id": effect.id,
                "commit": commit.commit,
                "tree": tree,
                "remote_ref": "refs/heads/agent-b-observability",
                "before": pushed.before_remote_head,
                "after": pushed.after_remote_head,
                "worktree": str(self.fixture.agent_b_worktree),
                "artifact_hashes": push_bindings,
            },
        )
        return {
            "commit_warrant_id": prepared["commit_warrant_id"],
            "commit_action_id": prepared["commit_action_id"],
            "commit_effect_id": commit_effect.id,
            "effect_id": effect.id,
            "effect_ids": (commit_effect.id, effect.id),
            "action_id": action.id,
            "warrant_id": warrant.id,
            "commit": commit.commit,
            "tree": tree,
            "remote_ref": "refs/heads/agent-b-observability",
            "before": pushed.before_remote_head,
            "after": pushed.after_remote_head,
            "proof_path": path,
        }

    @staticmethod
    def _require_exact_affected_set(
        revocation: RevocationResult,
        expected_effect_ids: tuple[str, ...],
    ) -> None:
        derived = revocation.affected_effect_ids
        if len(derived) != 3 or set(derived) != set(expected_effect_ids):
            raise IntegrityError(
                "canonical closure must derive exactly the three Agent A effects; "
                f"derived={derived}"
            )

    def _write_inventory(
        self,
        revocation: RevocationResult,
        unrelated: Mapping[str, Any],
    ) -> Path:
        affected = []
        for effect_id in revocation.affected_effect_ids:
            effect = self.store.get_effect(effect_id)
            if effect is None:
                raise IntegrityError(f"inventoried effect disappeared: {effect_id}")
            affected.append(effect.model_dump(mode="json"))
        unrelated_effect_ids = tuple(str(item) for item in unrelated["effect_ids"])
        if any(revocation.contains_entity(effect_id) for effect_id in unrelated_effect_ids):
            raise IntegrityError("negative-reachability violation: Agent B entered closure")
        path = self.fixture.artifacts_root / "effect-inventory.json"
        self._write_json(
            path,
            {
                "case_id": revocation.case.id,
                "affected_effect_count": len(affected),
                "affected_effects": affected,
                "members": [member.model_dump(mode="json") for member in revocation.members],
                "negative_reachability": {
                    "agent_b_effect_ids": list(unrelated_effect_ids),
                    "reachable": False,
                    "basis": "not present in persisted scoped hard closure",
                },
            },
        )
        negative_path = self.fixture.artifacts_root / "logs" / "negative-reachability.json"
        self._write_json(
            negative_path,
            {
                "case_id": revocation.case.id,
                "root_premise_id": revocation.premise.id,
                "unrelated_effect_ids": list(unrelated_effect_ids),
                "revocation_member_entity_ids": sorted(
                    member.entity_id for member in revocation.members
                ),
                "reachable": False,
            },
        )
        return path

    async def _compensate_agent_a(
        self,
        revocation: RevocationResult,
        initial: Mapping[str, Any],
    ) -> dict[str, Any]:
        migration = self._initial_migration
        if migration is None:
            raise IntegrityError("initial migration before-image is missing")
        quarantine_ref = "refs/tars/quarantine/agent-a-invalid"
        quarantined_commit = await self.git.create_ref(
            self.fixture.repository,
            quarantine_ref,
            str(initial["invalid_commit"]),
        )
        if quarantined_commit != initial["invalid_commit"]:
            raise IntegrityError("quarantine ref did not preserve the invalid commit")

        pending_remote_ref = "refs/heads/agent-a-invalid"
        pending_before = await self._remote_head(pending_remote_ref)
        if pending_before is not None:
            raise IntegrityError("undispatched Agent A ref unexpectedly exists remotely")

        database_effect = self._require_effect(str(initial["migration_effect_id"]))
        database_action = self._require_action(str(initial["migration_action_id"]))
        database_effect = self.store.transition_effect(database_effect.id, EffectState.REVOKED)
        database_action = self.store.transition_action(database_action.id, ActionState.REVOKED)
        restored = await self.migrations.restore(
            migration.snapshot,
            expected_current_hash=database_effect.after_hash,
        )
        if restored.restored_hash != database_effect.before_hash:
            raise IntegrityError("database compensation did not restore exact before-image")
        self.store.transition_effect(
            database_effect.id,
            EffectState.ROLLED_BACK,
            compensation_attempts=1,
        )
        self.store.transition_action(database_action.id, ActionState.ROLLED_BACK)

        model_effect = self._require_effect(str(initial["model_effect_id"]))
        model_action = self._require_action(str(initial["model_action_id"]))
        model_effect = self.store.transition_effect(model_effect.id, EffectState.REVOKED)
        model_action = self.store.transition_action(model_action.id, ActionState.REVOKED)
        changed_paths = tuple(str(path) for path in model_effect.metadata["changed_paths"])
        current_files = {
            path: sha256_digest((self.fixture.agent_a_worktree / path).read_bytes())
            for path in changed_paths
        }
        if canonical_digest(current_files) != model_effect.after_hash:
            raise IntegrityError("model changed after recorded effect; refusing compensation")
        for path in changed_paths:
            (self.fixture.agent_a_worktree / path).write_bytes(self._original_files[path])
        restored_files = {
            path: sha256_digest((self.fixture.agent_a_worktree / path).read_bytes())
            for path in changed_paths
        }
        if canonical_digest(restored_files) != model_effect.before_hash:
            raise IntegrityError("file compensation did not restore exact before-image")
        rollback_commit = await self.git.commit(
            self.fixture.agent_a_worktree,
            message="revoke UUID assumption and restore model before-image",
            paths=changed_paths,
        )
        self.store.transition_effect(
            model_effect.id,
            EffectState.ROLLED_BACK,
            compensation_attempts=1,
        )
        self.store.transition_action(model_action.id, ActionState.ROLLED_BACK)

        push_effect = self._require_effect(str(initial["push_effect_id"]))
        push_action = self._require_action(str(initial["push_action_id"]))
        push_effect = self.store.transition_effect(push_effect.id, EffectState.REVOKED)
        push_action = self.store.transition_action(push_action.id, ActionState.REVOKED)
        self.store.transition_effect(
            push_effect.id,
            EffectState.QUARANTINED,
            compensation_attempts=1,
        )
        self.store.transition_action(push_action.id, ActionState.QUARANTINED)
        for warrant_id in initial["warrant_ids"]:
            self.store.transition_warrant(
                str(warrant_id),
                WarrantState.REVOKED,
                revoke_cause="signed schema v2 invalidated v1 customer ID premise",
            )
        pending_after = await self._remote_head(pending_remote_ref)
        if pending_after is not None:
            raise IntegrityError("quarantined push became visible on the remote")
        revoked_lease = self.store.get_lease_for_action(str(initial["push_action_id"]))
        if revoked_lease is None:
            raise IntegrityError("quarantined push lost its execution lease record")
        experiment_worktree = await self.git.create_worktree(
            self.fixture.repository,
            self.experiment_worktree,
            branch="agent-a/quarantined-experiment",
            start_point=str(initial["invalid_commit"]),
        )
        if experiment_worktree.head != initial["invalid_commit"]:
            raise IntegrityError("experiment worktree did not preserve the invalid commit")
        replacement_worktree = await self.git.create_worktree(
            self.fixture.repository,
            self.replacement_worktree,
            branch="agent-a/replacement",
            start_point=self.fixture.baseline_commit,
        )
        if replacement_worktree.head != self.fixture.baseline_commit:
            raise IntegrityError("replacement worktree did not start from the clean baseline")

        quarantine_path = self.fixture.artifacts_root / "git" / "quarantine.json"
        self._write_json(
            quarantine_path,
            {
                "invalid_commit": initial["invalid_commit"],
                "quarantine_ref": quarantine_ref,
                "quarantine_ref_head": quarantined_commit,
                "repository": str(self.fixture.repository),
                "pending_remote_ref": pending_remote_ref,
                "pending_remote_before": pending_before,
                "pending_remote_after": pending_after,
                "lease_state": revoked_lease.state,
                "replacement_worktree": str(self.replacement_worktree),
                "experiment_worktree": str(self.experiment_worktree),
            },
        )
        compensation_path = self.fixture.artifacts_root / "compensation.json"
        self._write_json(
            compensation_path,
            {
                "database": {
                    "effect_id": database_effect.id,
                    "before_hash": database_effect.before_hash,
                    "applied_hash": database_effect.after_hash,
                    "restored_hash": restored.restored_hash,
                    "state": EffectState.ROLLED_BACK,
                },
                "model": {
                    "effect_id": model_effect.id,
                    "before_hash": model_effect.before_hash,
                    "applied_hash": model_effect.after_hash,
                    "restored_hash": canonical_digest(restored_files),
                    "rollback_commit": rollback_commit.commit,
                    "state": EffectState.ROLLED_BACK,
                },
                "push": {
                    "effect_id": push_effect.id,
                    "state": EffectState.QUARANTINED,
                    "remote_ref_absent": pending_after is None,
                },
            },
        )
        return {
            "quarantine_ref": quarantine_ref,
            "quarantined_commit": quarantined_commit,
            "rollback_commit": rollback_commit.commit,
            "database_restored_hash": restored.restored_hash,
            "model_restored_hash": canonical_digest(restored_files),
            "pending_remote_ref": pending_remote_ref,
            "pending_remote_head": pending_after,
            "quarantine_path": quarantine_path,
            "compensation_path": compensation_path,
        }

    async def _run_experiment(
        self,
        case_id: str,
        premise_v2: Premise,
    ) -> dict[str, Any]:
        if self.live_codex is not None:
            if self._live_analysis is None:
                raise IntegrityError("live contradiction analysis is missing")
            self._live_proposals = await self.live_codex.propose_experiments(
                case_id=case_id,
                analysis=self._live_analysis,
                worktree=self.fixture.agent_b_worktree,
            )
            proposal_values = self._live_proposals.candidate_mappings
            proposed_by = "live-codex"
        else:
            if self.scripted_codex is None:
                raise IntegrityError("scripted Codex provider is missing")
            scripted = self.scripted_codex.propose_experiments(
                self.fixture.agent_a_worktree,
                case_id=case_id,
            )
            proposal_values = tuple(
                {
                    "id": proposal.id,
                    "hypotheses": proposal.hypotheses,
                    "predictions": proposal.predictions,
                    "argv": proposal.argv,
                    "touched_files": proposal.touched_files,
                    "risk": proposal.risk,
                    "estimated_runtime_ms": proposal.estimated_runtime_ms,
                    "command_count": proposal.command_count,
                }
                for proposal in scripted
            )
            proposed_by = self.scripted_codex.provider
        if len(proposal_values) < 3:
            raise IntegrityError("Codex must propose at least three experiment candidates")
        created_at = self.store.clock.utc_now()
        candidate_records: list[ExperimentCandidate] = []
        for proposal in proposal_values:
            proposed_argv = tuple(str(item) for item in proposal["argv"])
            execution_argv = _resolve_experiment_argv(
                proposed_argv,
                python_executable=self.python_executable,
            )
            candidate_records.append(
                ExperimentCandidate(
                    id=str(proposal["id"]),
                    run_id=self.fixture.run_id,
                    case_id=case_id,
                    hypotheses=tuple(str(item) for item in proposal["hypotheses"]),
                    predictions=dict(proposal["predictions"]),
                    argv=execution_argv,
                    touched_files=tuple(str(item) for item in proposal["touched_files"]),
                    risk=RiskLevel(
                        str(getattr(proposal["risk"], "value", proposal["risk"])).upper()
                    ),
                    estimated_runtime_ms=int(proposal["estimated_runtime_ms"]),
                    command_count=int(proposal["command_count"]),
                    state=ExperimentState.PROPOSED,
                    created_at=created_at,
                    metadata={
                        "proposed_by": proposed_by,
                        "proposed_argv": list(proposed_argv),
                        "executable_resolution": {
                            "kind": "scenario-python-runtime",
                            "resolved_path": execution_argv[0],
                        },
                    },
                )
            )
        candidates = tuple(candidate_records)
        for candidate in candidates:
            self.store.create_experiment_candidate(candidate)
        selector = ExperimentSelector(
            allowed_roots=(self.experiment_worktree,),
            allowed_executables={Path(candidate.argv[0]).name for candidate in candidates},
            maximum_risk_rank=1,
        )
        selection: ExperimentSelection = selector.select(
            candidates,
            live_hypothesis_ids=candidates[0].hypotheses,
            minimum_candidates=3,
        )
        for candidate, decision in zip(candidates, selection.decisions, strict=True):
            if decision.accepted:
                self.store.transition_experiment_candidate(
                    candidate.id,
                    ExperimentState.ACCEPTED,
                    score=decision.score[:4] if decision.score is not None else None,
                )
            else:
                self.store.transition_experiment_candidate(
                    candidate.id,
                    ExperimentState.REJECTED,
                    rejection_reason=",".join(decision.reasons),
                )
        selected = cast(ExperimentCandidate, selection.candidate)
        self.store.transition_experiment_candidate(selected.id, ExperimentState.SELECTED)
        head_result = await self.runner.run(
            ("git", "-C", str(self.experiment_worktree), "rev-parse", "HEAD"),
            cwd=self.experiment_worktree,
            timeout_seconds=30,
        )
        experiment_head = head_result.stdout.strip()
        if not head_result.succeeded or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
            experiment_head,
        ):
            raise IntegrityError("experiment worktree HEAD could not be bound")
        experiment_tree = await self._git_tree(
            self.experiment_worktree,
            experiment_head,
        )
        sandbox_plan = build_experiment_sandbox(
            logical_argv=selected.argv,
            worktree=self.experiment_worktree,
        )
        profile_path = self.fixture.artifacts_root / "experiments" / "sandbox.sb"
        profile_path.write_text(sandbox_plan.profile, encoding="utf-8")
        pre_manifest = workspace_manifest(self.experiment_worktree)
        pre_manifest_path = (
            self.fixture.artifacts_root / "experiments" / "worktree.pre.json"
        )
        self._write_json(pre_manifest_path, pre_manifest)
        sandbox_executable_artifact = self._store_artifact_bytes(
            Path(sandbox_plan.executable).read_bytes(),
            media_type="application/octet-stream",
            metadata={"kind": "experiment-sandbox-executable"},
        )
        python_executable_artifact = self._store_artifact_bytes(
            Path(sandbox_plan.python_resolved_path).read_bytes(),
            media_type="application/octet-stream",
            metadata={"kind": "experiment-python-executable"},
        )
        dynamic_libraries: list[dict[str, str]] = []
        for dependency in sandbox_plan.dynamic_libraries:
            dependency_artifact = self._store_artifact_bytes(
                Path(dependency["resolved_path"]).read_bytes(),
                media_type="application/octet-stream",
                metadata={
                    "kind": "experiment-loader-input",
                    "path": dependency["path"],
                },
            )
            dynamic_libraries.append(
                {**dependency, "artifact_digest": dependency_artifact.digest}
            )
        sandbox_record = {
            **sandbox_plan.as_mapping(),
            "executable_artifact_digest": sandbox_executable_artifact.digest,
            "python_artifact_digest": python_executable_artifact.digest,
            "dynamic_libraries": dynamic_libraries,
        }
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise_v2)
        command_bindings = {
            **premise_bindings,
            **self._command_bindings(
                cwd=self.experiment_worktree,
                argv=selected.argv,
                required_paths=selected.touched_files,
            ),
            **self._git_object_bindings(
                commit=experiment_head,
                tree=experiment_tree,
            ),
            "sandbox:executable": sandbox_plan.executable_sha256,
            "sandbox:profile": sandbox_plan.profile_sha256,
            "sandbox:environment": sandbox_plan.environment_digest,
            "sandbox:supervisor-argv": canonical_digest(
                list(sandbox_plan.supervisor_argv)
            ),
            "sandbox:worktree-pre": str(pre_manifest["canonical_digest"]),
            "python:resolved-executable": sandbox_plan.python_sha256,
        }
        command_target = self._command_target(
            cwd=self.experiment_worktree,
            argv=selected.argv,
        )
        warrant = self._create_warrant(
            suffix="warrant-agent-a-v2-experiment",
            agent_id=self._id("agent-a"),
            premise=premise_v2,
            risk=selected.risk,
            binding_stage="agent-a-v2-decisive-experiment",
            authorized_targets=(command_target,),
            artifact_hashes=command_bindings,
            evidence_ids=evidence_ids,
        )
        action = self._create_action(
            suffix="action-agent-a-v2-experiment",
            agent_id=self._id("agent-a"),
            warrant=warrant,
            premise=premise_v2,
            action_type=ActionType.EXPERIMENT,
            target=command_target,
            payload={
                "case_id": case_id,
                "candidate_id": selected.id,
                "argv": list(selected.argv),
                "cwd": str(self.experiment_worktree),
                "commit": experiment_head,
                "tree": experiment_tree,
                "environment": dict(sandbox_plan.environment),
                "environment_digest": sandbox_plan.environment_digest,
                "sandbox": sandbox_record,
            },
            risk=selected.risk,
            reversibility=Reversibility.CONDITIONAL,
        )
        effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-v2-experiment",
            action=action,
            effect_type=EffectType.COMMAND,
            before_hash=canonical_digest(command_bindings),
            metadata={
                "case_id": case_id,
                "candidate_id": selected.id,
                "argv": list(selected.argv),
                "cwd": str(self.experiment_worktree),
                "commit": experiment_head,
                "tree": experiment_tree,
                "environment": dict(sandbox_plan.environment),
                "environment_digest": sandbox_plan.environment_digest,
                "sandbox": sandbox_record,
                "worktree_pre_digest": pre_manifest["canonical_digest"],
            },
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action.id,
            effect_id=effect_intent.id,
            current_artifact_hashes=command_bindings,
            passed_test_ids=(),
        )
        grant = gateway.dispatch(
            action.id,
            effect_id=effect_intent.id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=command_bindings,
            passed_test_ids=(),
        )
        environment_digest = sandbox_plan.environment_digest
        experiment_run = ExperimentRun(
            id=self._id("experiment-run-v2-probe"),
            run_id=self.fixture.run_id,
            case_id=case_id,
            candidate_id=selected.id,
            action_id=action.id,
            state=ExperimentState.SELECTED,
            started_at=self.store.clock.utc_now(),
            environment_digest=environment_digest,
            metadata={
                "selection_score": selection.score,
                "argv": list(selected.argv),
                "supervisor_argv": list(sandbox_plan.supervisor_argv),
                "sandbox": sandbox_record,
                "commit": experiment_head,
                "tree": experiment_tree,
                "environment": dict(sandbox_plan.environment),
                "worktree_pre_digest": pre_manifest["canonical_digest"],
                "effect_id": effect_intent.id,
            },
        )
        self.store.create_experiment_run(experiment_run)
        self.store.transition_experiment_run(experiment_run.id, ExperimentState.RUNNING)
        process = await self.runner.run(
            sandbox_plan.supervisor_argv,
            cwd=self.experiment_worktree,
            timeout_seconds=30,
            env=sandbox_plan.environment,
            inherited_env_keys=(),
            allowed_exit_codes=(0,),
        )
        post_manifest = workspace_manifest(self.experiment_worktree)
        post_manifest_path = (
            self.fixture.artifacts_root / "experiments" / "worktree.post.json"
        )
        self._write_json(post_manifest_path, post_manifest)
        stdout = self._store_artifact_bytes(
            process.stdout.encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            metadata={"kind": "experiment-stdout", "candidate_id": selected.id},
        )
        stderr = self._store_artifact_bytes(
            process.stderr.encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            metadata={"kind": "experiment-stderr", "candidate_id": selected.id},
        )
        workspace_unchanged = pre_manifest == post_manifest
        if not process.succeeded or not workspace_unchanged:
            failure_reason = (
                f"decisive experiment exited {process.exit_code}"
                if not process.succeeded
                else "decisive experiment changed its read-only worktree"
            )
            self._fail_dispatched_effect(
                action_id=action.id,
                effect_id=effect_intent.id,
                reason=failure_reason,
            )
            self.store.transition_experiment_run(
                experiment_run.id,
                ExperimentState.FAILED,
                exit_code=process.exit_code,
                stdout_artifact_digest=stdout.digest,
                stderr_artifact_digest=stderr.digest,
            )
            raise IntegrityError(failure_reason)
        semantic_failure: str | None = None
        try:
            observed_outcome: Any = json.loads(process.stdout)
        except json.JSONDecodeError:
            observed_outcome = {"raw_stdout_digest": stdout.digest}
            semantic_failure = "decisive experiment did not emit JSON"
        resolved_hypotheses = matching_hypotheses(
            dict(selected.predictions),
            observed_outcome,
        )
        if semantic_failure is None and len(resolved_hypotheses) != 1:
            semantic_failure = "decisive experiment did not resolve exactly one hypothesis"
        resolved_hypothesis_id = resolved_hypotheses[0] if len(resolved_hypotheses) == 1 else None
        if semantic_failure is None and resolved_hypothesis_id != HYPOTHESES[0]:
            semantic_failure = (
                "decisive experiment did not confirm that the quarantined "
                "implementation rejects the signed v2 example"
            )
        if semantic_failure is not None:
            self._fail_dispatched_effect(
                action_id=action.id,
                effect_id=effect_intent.id,
                reason=semantic_failure,
            )
            self.store.transition_experiment_run(
                experiment_run.id,
                ExperimentState.FAILED,
                exit_code=process.exit_code,
                observed_outcome=observed_outcome,
                stdout_artifact_digest=stdout.digest,
                stderr_artifact_digest=stderr.digest,
            )
            raise IntegrityError(semantic_failure)
        if resolved_hypothesis_id is None:
            raise IntegrityError("decisive experiment resolution disappeared")
        effect_observation = {
            "exit_code": process.exit_code,
            "stdout_artifact_digest": stdout.digest,
            "stderr_artifact_digest": stderr.digest,
            "observed_outcome": observed_outcome,
            "sandbox_profile_sha256": sandbox_plan.profile_sha256,
            "environment_digest": sandbox_plan.environment_digest,
            "worktree_pre_digest": pre_manifest["canonical_digest"],
            "worktree_post_digest": post_manifest["canonical_digest"],
            "workspace_unchanged": workspace_unchanged,
        }
        effect_artifact = self._store_artifact_json(effect_observation)
        completed_effect = EffectRecord.model_validate(
            grant.effect.model_copy(
                update={
                    "after_hash": canonical_digest(effect_observation),
                    "forward_artifact_digest": effect_artifact.digest,
                    "state": EffectState.EXECUTED,
                }
            ).model_dump()
        )
        gateway.complete(completed_effect)
        completed = self.store.transition_experiment_run(
            experiment_run.id,
            ExperimentState.PASSED,
            exit_code=process.exit_code,
            observed_outcome=observed_outcome,
            stdout_artifact_digest=stdout.digest,
            stderr_artifact_digest=stderr.digest,
        )
        persisted_candidates = [
            self.store.get_experiment_candidate(candidate.id) for candidate in candidates
        ]
        if any(candidate is None for candidate in persisted_candidates):
            raise IntegrityError("experiment candidate disappeared before proof generation")
        durable_candidates = tuple(
            cast(ExperimentCandidate, candidate) for candidate in persisted_candidates
        )
        durable_selected = next(
            candidate for candidate in durable_candidates if candidate.id == selected.id
        )
        durable_selection = ExperimentSelection(
            candidate=durable_selected,
            score=selection.score,
            decisions=selection.decisions,
        )
        candidates_path = self.fixture.artifacts_root / "experiments" / "candidates.json"
        self._write_json(
            candidates_path,
            {
                "candidates": [
                    candidate.model_dump(mode="json")
                    for candidate in durable_candidates
                ],
                "decisions": [
                    {
                        "candidate_id": decision.candidate_id,
                        "accepted": decision.accepted,
                        "reasons": decision.reasons,
                        "score": decision.score,
                    }
                    for decision in selection.decisions
                ],
                "selected_candidate_id": selected.id,
                "selected_score": selection.score,
            },
        )
        run_path = self.fixture.artifacts_root / "experiments" / "run.json"
        self._write_json(
            run_path,
            {
                "experiment_run": completed.model_dump(mode="json"),
                "argv": list(selected.argv),
                "supervisor_argv": list(process.argv),
                "cwd": process.cwd,
                "commit": experiment_head,
                "tree": experiment_tree,
                "environment": dict(sandbox_plan.environment),
                "environment_digest": sandbox_plan.environment_digest,
                "sandbox": sandbox_record,
                "sandbox_profile_path": profile_path.relative_to(
                    self.fixture.artifacts_root
                ).as_posix(),
                "sandbox_profile_sha256": sandbox_plan.profile_sha256,
                "worktree_pre_manifest_path": pre_manifest_path.relative_to(
                    self.fixture.artifacts_root
                ).as_posix(),
                "worktree_post_manifest_path": post_manifest_path.relative_to(
                    self.fixture.artifacts_root
                ).as_posix(),
                "worktree_pre_digest": pre_manifest["canonical_digest"],
                "worktree_post_digest": post_manifest["canonical_digest"],
                "workspace_unchanged": workspace_unchanged,
                "exit_code": process.exit_code,
                "stdout_artifact_digest": stdout.digest,
                "stderr_artifact_digest": stderr.digest,
                "observed_outcome": observed_outcome,
                "evidence_hypothesis_id": HYPOTHESES[1],
                "resolved_hypothesis_id": resolved_hypothesis_id,
                "disagreement_confirmed": True,
            },
        )
        return {
            "warrant_id": warrant.id,
            "action_id": action.id,
            "effect_id": completed_effect.id,
            "command_target": command_target,
            "candidate_count": len(candidates),
            "candidates": durable_candidates,
            "selection": durable_selection,
            "run": completed,
            "process": process,
            "stdout_digest": stdout.digest,
            "stderr_digest": stderr.digest,
            "evidence_hypothesis_id": HYPOTHESES[1],
            "resolved_hypothesis_id": resolved_hypothesis_id,
            "candidates_path": candidates_path,
            "run_path": run_path,
            "sandbox_profile_path": profile_path,
            "worktree_pre_manifest_path": pre_manifest_path,
            "worktree_post_manifest_path": post_manifest_path,
            "sandbox": sandbox_record,
            "environment": dict(sandbox_plan.environment),
            "commit": experiment_head,
            "tree": experiment_tree,
        }

    async def _repair_under_v2(
        self,
        case_id: str,
        premise_v2: Premise,
        initial: Mapping[str, Any],
        compensation: Mapping[str, Any],
        experiment: Mapping[str, Any],
    ) -> dict[str, Any]:
        agent_id = self._id("agent-a")
        gateway = EffectGateway(self.store)
        allowed_repair_paths = (
            "billing/models.py",
            MIGRATION_SOURCE_PATH,
            "tests/test_contract.py",
        )
        before_contents = {
            path: (self.replacement_worktree / path).read_bytes()
            for path in allowed_repair_paths
        }
        before_files = {path: sha256_digest(content) for path, content in before_contents.items()}
        for path, content in before_contents.items():
            self._store_artifact_bytes(
                content,
                media_type="application/octet-stream",
                metadata={"kind": "repair-before-image", "path": path},
            )
        reverse_manifest = self._store_artifact_json(before_files)
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise_v2)
        repair_bindings = {
            **premise_bindings,
            **self._regular_file_bindings(
                self.replacement_worktree,
                allowed_repair_paths,
            ),
            "experiment:stdout": str(experiment["stdout_digest"]),
            "experiment:stderr": str(experiment["stderr_digest"]),
            "experiment:run-proof": sha256_digest(
                Path(experiment["run_path"]).read_bytes()
            ),
        }
        model_warrant = self._create_warrant(
            suffix="warrant-agent-a-model-v2",
            agent_id=agent_id,
            premise=premise_v2,
            risk=RiskLevel.HIGH,
            binding_stage="agent-a-v2-repair-local-commit",
            authorized_targets=(",".join(allowed_repair_paths),),
            artifact_hashes=repair_bindings,
            evidence_ids=evidence_ids,
            replaces_warrant_id=str(initial["model_warrant_id"]),
        )
        model_action = self._create_action(
            suffix="action-agent-a-model-v2",
            agent_id=agent_id,
            warrant=model_warrant,
            premise=premise_v2,
            action_type=ActionType.LOCAL_COMMIT,
            target=",".join(allowed_repair_paths),
            payload={"allowed_paths": sorted(before_files), "contract": "opaque-cus-prefix"},
            risk=RiskLevel.HIGH,
            reversibility=Reversibility.REVERSIBLE,
            replaces_action_id=str(initial["model_action_id"]),
        )
        model_effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-model-v2",
            action=model_action,
            effect_type=EffectType.LOCAL_COMMIT,
            before_hash=canonical_digest(before_files),
            reverse_artifact_digest=reverse_manifest.digest,
            compensation_handler="git.restore_paths",
            metadata={
                "allowed_paths": list(allowed_repair_paths),
                "repository": str(self.replacement_worktree),
            },
        )
        model_auth = gateway.authorize(
            model_action.id,
            effect_id=model_effect_intent.id,
            current_artifact_hashes=repair_bindings,
            passed_test_ids=(),
        )
        model_grant = gateway.dispatch(
            model_action.id,
            effect_id=model_effect_intent.id,
            capability_token=model_auth.capability_token,
            current_artifact_hashes=repair_bindings,
            passed_test_ids=(),
        )
        if self.live_codex is not None:
            selected = cast(ExperimentCandidate, experiment["selection"].candidate)
            packet = RevocationPacket(
                original_goal=(
                    "Repair billing customer IDs for the signed v2 opaque cus_ contract."
                ),
                revocation_case_id=case_id,
                invalidated_premise=self._require_premise_from_warrant(
                    str(initial["warrant_id"])
                ).model_dump(mode="json"),
                replacement_evidence=self._signed_evidence[2],
                evidence_diff=(
                    self._live_analysis.as_mapping()
                    if self._live_analysis is not None
                    else {"from": self._signed_evidence[1], "to": self._signed_evidence[2]}
                ),
                affected_effects=tuple(
                    self._require_effect(str(effect_id)).model_dump(mode="json")
                    for effect_id in initial["effect_ids"]
                ),
                quarantine_ref=str(compensation["quarantine_ref"]),
                selected_experiment=selected.model_dump(mode="json"),
                experiment_result=experiment["run"].model_dump(mode="json"),
                allowed_repair_scope=allowed_repair_paths,
                targeted_test_argv=(
                    str(self.python_executable),
                    "scripts/contract_probe.py",
                    "--example",
                    "examples/customer-v2.json",
                    "--expect",
                    "accept",
                ),
                full_test_argv=(str(self.python_executable), "-m", "pytest", "-q"),
                active_premise_revisions={premise_v2.id: premise_v2.value_digest},
            )
            provider_result: ScriptedRepair | LiveCodexResult = await self.live_codex.repair(
                packet,
                replacement_worktree=self.replacement_worktree,
            )
        else:
            if self.scripted_codex is None:
                raise IntegrityError("scripted Codex provider is missing")
            provider_result = self.scripted_codex.repair(
                self.replacement_worktree,
                case_id=case_id,
            )
        changed_paths = tuple(provider_result.changed_paths)
        if set(changed_paths) != set(allowed_repair_paths):
            raise IntegrityError(
                "repair must modify exactly the model, managed migration, and contract test"
            )
        migration_source = validate_migration_source(
            self.replacement_worktree,
            expected_contract="opaque",
        )
        migration_proof = self._persist_migration_source(
            migration_source,
            stage="agent-a-v2-repair",
        )
        database_before_digest = sha256_digest(self.fixture.service_database.read_bytes())
        migration_bindings = {
            **premise_bindings,
            f"file:{migration_source.relative_path}": migration_source.sha256,
            "database:before-image": database_before_digest,
            "experiment:run-proof": repair_bindings["experiment:run-proof"],
        }
        migration_warrant = self._create_warrant(
            suffix="warrant-agent-a-db-v2",
            agent_id=agent_id,
            premise=premise_v2,
            risk=RiskLevel.HIGH,
            binding_stage="agent-a-v2-migration",
            authorized_targets=(str(self.fixture.service_database),),
            artifact_hashes=migration_bindings,
            evidence_ids=evidence_ids,
            replaces_warrant_id=str(initial["migration_warrant_id"]),
        )
        migration_action = self._create_action(
            suffix="action-agent-a-db-v2",
            agent_id=agent_id,
            warrant=migration_warrant,
            premise=premise_v2,
            action_type=ActionType.DATABASE_MIGRATION,
            target=str(self.fixture.service_database),
            payload={
                "source_path": migration_source.relative_path,
                "source_sha256": migration_source.sha256,
                "sql": migration_source.sql,
                "contract": "opaque-cus-prefix",
            },
            risk=RiskLevel.HIGH,
            reversibility=Reversibility.REVERSIBLE,
            replaces_action_id=str(initial["migration_action_id"]),
        )
        migration_snapshot = await self.migrations.snapshot(
            self.fixture.service_database,
            action_id=migration_action.id,
        )
        migration_effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-db-v2",
            action=migration_action,
            effect_type=EffectType.DATABASE_MIGRATION,
            before_hash=migration_snapshot.sha256,
            compensation_handler="sqlite.restore_snapshot",
            metadata={
                "snapshot_path": str(migration_snapshot.snapshot_path),
                "snapshot_sha256": migration_snapshot.sha256,
                "source_path": migration_source.relative_path,
                "source_sha256": migration_source.sha256,
            },
        )
        migration_auth = gateway.authorize(
            migration_action.id,
            effect_id=migration_effect_intent.id,
            current_artifact_hashes=migration_bindings,
            passed_test_ids=(),
        )
        migration_grant = gateway.dispatch(
            migration_action.id,
            effect_id=migration_effect_intent.id,
            capability_token=migration_auth.capability_token,
            current_artifact_hashes=migration_bindings,
            passed_test_ids=(),
        )
        migration_result = await self.migrations.apply(
            self.fixture.service_database,
            migration_source.sql,
            action_id=migration_action.id,
        )
        if migration_result.after_user_version != migration_source.user_version:
            raise IntegrityError("agent-authored opaque migration set the wrong user_version")
        if migration_result.before_hash != database_before_digest:
            raise IntegrityError("migration authorization did not bind the exact database input")
        migration_effect = EffectRecord.model_validate(
            migration_grant.effect.model_copy(
                update={
                    "after_hash": migration_result.after_hash,
                    "state": EffectState.EXECUTED,
                    "metadata": {
                        **dict(migration_grant.effect.metadata),
                        "replaces_effect_id": initial["migration_effect_id"],
                        "before_user_version": migration_result.before_user_version,
                        "after_user_version": migration_result.after_user_version,
                        "source_artifact_digest": migration_proof["artifact_digest"],
                        "source_proof_path": str(migration_proof["proof_path"]),
                    },
                }
            ).model_dump()
        )
        gateway.complete(migration_effect)
        self._create_replaces_edge(
            old_action_id=str(initial["migration_action_id"]),
            new_action_id=migration_action.id,
            suffix="db-v2-replaces-v1",
        )
        if isinstance(provider_result, LiveCodexResult):
            live = True
            provider_name = "live-codex"
            provider_summary = provider_result.final_message
            live_manifest: str | None = str(provider_result.artifacts.manifest_path)
        else:
            live = False
            provider_name = provider_result.provider
            provider_summary = provider_result.summary
            live_manifest = None
        repair_commit = await self.git.commit(
            self.replacement_worktree,
            message="repair billing customer IDs for signed schema v2",
            paths=tuple(sorted(changed_paths)),
        )
        repair_tree = await self._git_tree(self.replacement_worktree, repair_commit.commit)
        after_files = {
            path: sha256_digest((self.replacement_worktree / path).read_bytes())
            for path in changed_paths
        }
        model_effect = EffectRecord.model_validate(
            model_grant.effect.model_copy(
                update={
                    "after_hash": canonical_digest(after_files),
                    "forward_artifact_digest": self._store_artifact_json(after_files).digest,
                    "state": EffectState.EXECUTED,
                    "metadata": {
                        **dict(model_grant.effect.metadata),
                        "replaces_effect_id": initial["model_effect_id"],
                        "commit": repair_commit.commit,
                        "tree": repair_tree,
                        "changed_paths": changed_paths,
                        "provider": provider_name,
                    },
                }
            ).model_dump()
        )
        gateway.complete(model_effect)
        self._create_replaces_edge(
            old_action_id=str(initial["model_action_id"]),
            new_action_id=model_action.id,
            suffix="model-v2-replaces-v1",
        )
        repair_patch = await self.git.diff(
            self.replacement_worktree,
            base=str(initial["invalid_commit"]),
            head=repair_commit.commit,
            paths=tuple(sorted(changed_paths)),
        )
        repair_patch_path = self.fixture.artifacts_root / "git" / "repair.patch"
        repair_patch_path.write_text(repair_patch, encoding="utf-8")
        repair_path = (
            self.fixture.artifacts_root
            / "agents"
            / ("live-repair.json" if live else "scripted-repair.json")
        )
        self._write_json(
            repair_path,
            {
                "provider": provider_name,
                "live_codex": live,
                "proof_claim": (
                    "real fail-closed Codex CLI repair session"
                    if live
                    else "deterministic demo double only; not R-14 live Codex proof"
                ),
                "session_id": provider_result.session_id,
                "response_ids": provider_result.response_ids,
                "changed_paths": changed_paths,
                "summary": provider_summary,
                "commit": repair_commit.commit,
                "parent": repair_commit.parent,
                "live_artifact_manifest": live_manifest,
            },
        )
        return {
            "warrant_id": model_warrant.id,
            "model_warrant_id": model_warrant.id,
            "migration_warrant_id": migration_warrant.id,
            "migration_action_id": migration_action.id,
            "migration_effect_id": migration_effect.id,
            "model_action_id": model_action.id,
            "model_effect_id": model_effect.id,
            "commit": repair_commit.commit,
            "parent": repair_commit.parent,
            "tree": repair_tree,
            "provider_result": provider_result,
            "live_codex": live,
            "repair_path": repair_path,
            "repair_patch_path": repair_patch_path,
            "migration_source_proof_path": migration_proof["proof_path"],
            "migration_source_sql_path": migration_proof["sql_path"],
            "migration_source_sha256": migration_source.sha256,
        }

    def _create_replaces_edge(
        self,
        *,
        old_action_id: str,
        new_action_id: str,
        suffix: str,
    ) -> None:
        self._create_edge(
            suffix,
            self._node_for(NodeKind.ACTION, old_action_id).id,
            self._node_for(NodeKind.ACTION, new_action_id).id,
            scope=SCOPE,
            edge_type=EdgeType.REPLACES,
        )

    async def _run_verification(
        self,
        case_id: str,
        premise_v2: Premise,
        repair: Mapping[str, Any],
    ) -> dict[str, Any]:
        targeted = await self._execute_test(
            test_id=self._id("test-targeted-v2"),
            case_id=case_id,
            premise_v2=premise_v2,
            repair_commit=str(repair["commit"]),
            repair_tree=str(repair["tree"]),
            kind=TestKind.TARGETED,
            argv=(
                str(self.python_executable),
                "scripts/contract_probe.py",
                "--example",
                "examples/customer-v2.json",
                "--expect",
                "accept",
            ),
            output_name="targeted.json",
        )
        full = await self._execute_test(
            test_id=self._id("test-full-v2"),
            case_id=case_id,
            premise_v2=premise_v2,
            repair_commit=str(repair["commit"]),
            repair_tree=str(repair["tree"]),
            kind=TestKind.FULL,
            argv=(str(self.python_executable), "-m", "pytest", "-q"),
            output_name="full.json",
        )
        return {"targeted": targeted, "full": full}

    async def _execute_test(
        self,
        *,
        test_id: str,
        case_id: str,
        premise_v2: Premise,
        repair_commit: str,
        repair_tree: str,
        kind: TestKind,
        argv: tuple[str, ...],
        output_name: str,
    ) -> dict[str, Any]:
        command_bindings = {
            **self._premise_artifact_bindings(premise_v2)[0],
            **self._command_bindings(
                cwd=self.replacement_worktree,
                argv=argv,
            ),
            **self._git_object_bindings(
                commit=repair_commit,
                tree=repair_tree,
            ),
        }
        _premise_bindings, evidence_ids = self._premise_artifact_bindings(premise_v2)
        test_name = kind.value.lower()
        command_target = self._command_target(
            cwd=self.replacement_worktree,
            argv=argv,
        )
        warrant = self._create_warrant(
            suffix=f"warrant-agent-a-v2-{test_name}-test",
            agent_id=self._id("agent-a"),
            premise=premise_v2,
            risk=RiskLevel.LOW,
            binding_stage=f"agent-a-v2-{test_name}-test",
            authorized_targets=(command_target,),
            artifact_hashes=command_bindings,
            evidence_ids=evidence_ids,
        )
        action = self._create_action(
            suffix=f"action-agent-a-v2-{test_name}-test",
            agent_id=self._id("agent-a"),
            warrant=warrant,
            premise=premise_v2,
            action_type=ActionType.TEST,
            target=command_target,
            payload={
                "case_id": case_id,
                "test_id": test_id,
                "kind": kind.value,
                "argv": list(argv),
                "cwd": str(self.replacement_worktree),
            },
            risk=RiskLevel.LOW,
            reversibility=Reversibility.CONDITIONAL,
        )
        effect_intent = self._create_effect_intent(
            suffix=f"effect-agent-a-v2-{test_name}-test",
            action=action,
            effect_type=EffectType.COMMAND,
            before_hash=canonical_digest(command_bindings),
            metadata={
                "case_id": case_id,
                "test_id": test_id,
                "kind": kind.value,
                "argv": list(argv),
                "cwd": str(self.replacement_worktree),
                "commit": repair_commit,
                "tree": repair_tree,
            },
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action.id,
            effect_id=effect_intent.id,
            current_artifact_hashes=command_bindings,
            passed_test_ids=(),
        )
        grant = gateway.dispatch(
            action.id,
            effect_id=effect_intent.id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=command_bindings,
            passed_test_ids=(),
        )
        environment_digest = canonical_digest(
            {
                "cwd": str(self.replacement_worktree),
                "python": str(self.python_executable),
                "mode": "argv-only",
            }
        )
        test = TestRun(
            id=test_id,
            run_id=self.fixture.run_id,
            case_id=case_id,
            action_id=action.id,
            kind=kind,
            argv=argv,
            state=TestState.PENDING,
            started_at=self.store.clock.utc_now(),
            environment_digest=environment_digest,
            metadata={"effect_id": effect_intent.id},
        )
        self.store.create_test_run(test)
        self.store.transition_test_run(test.id, TestState.RUNNING)
        process = await self.runner.run(
            argv,
            cwd=self.replacement_worktree,
            timeout_seconds=120,
            allowed_exit_codes=(0, 1, 2, 3, 4, 5),
        )
        stdout = self._store_artifact_bytes(
            process.stdout.encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            metadata={"kind": f"{kind.value.lower()}-test-stdout"},
        )
        stderr = self._store_artifact_bytes(
            process.stderr.encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            metadata={"kind": f"{kind.value.lower()}-test-stderr"},
        )
        state = TestState.PASSED if process.exit_code == 0 else TestState.FAILED
        effect_observation = {
            "exit_code": process.exit_code,
            "stdout_artifact_digest": stdout.digest,
            "stderr_artifact_digest": stderr.digest,
        }
        completed_effect: EffectRecord | None = None
        if state == TestState.PASSED:
            effect_artifact = self._store_artifact_json(effect_observation)
            completed_effect = EffectRecord.model_validate(
                grant.effect.model_copy(
                    update={
                        "after_hash": canonical_digest(effect_observation),
                        "forward_artifact_digest": effect_artifact.digest,
                        "state": EffectState.EXECUTED,
                    }
                ).model_dump()
            )
            gateway.complete(completed_effect)
        else:
            self._fail_dispatched_effect(
                action_id=action.id,
                effect_id=effect_intent.id,
                reason=f"{test_name} verification exited {process.exit_code}",
            )
        completed = self.store.transition_test_run(
            test.id,
            state,
            exit_code=process.exit_code,
            stdout_artifact_digest=stdout.digest,
            stderr_artifact_digest=stderr.digest,
        )
        path = self.fixture.artifacts_root / "tests" / output_name
        self._write_json(
            path,
            {
                "test_run": completed.model_dump(mode="json"),
                "argv": process.argv,
                "cwd": process.cwd,
                "exit_code": process.exit_code,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "stdout_artifact_digest": stdout.digest,
                "stderr_artifact_digest": stderr.digest,
            },
        )
        if state != TestState.PASSED:
            raise IntegrityError(f"{kind.value.lower()} verification failed: {process.stderr}")
        return {
            "warrant_id": warrant.id,
            "action_id": action.id,
            "effect_id": (
                completed_effect.id if completed_effect is not None else effect_intent.id
            ),
            "command_target": command_target,
            "record": completed,
            "process": process,
            "stdout_digest": stdout.digest,
            "stderr_digest": stderr.digest,
            "proof_path": path,
        }

    async def _push_replacement(
        self,
        case_id: str,
        premise_v2: Premise,
        initial: Mapping[str, Any],
        repair: Mapping[str, Any],
        tests: Mapping[str, Any],
    ) -> dict[str, Any]:
        targeted_id = tests["targeted"]["record"].id
        full_id = tests["full"]["record"].id
        repair_tree = await self._git_tree(
            self.replacement_worktree,
            str(repair["commit"]),
        )
        if repair_tree != repair["tree"]:
            raise IntegrityError("repaired commit tree changed before push authorization")
        premise_bindings, evidence_ids = self._premise_artifact_bindings(premise_v2)
        push_bindings = {
            **premise_bindings,
            **self._git_object_bindings(
                commit=str(repair["commit"]),
                tree=repair_tree,
            ),
        }
        warrant = self._create_warrant(
            suffix="warrant-agent-a-v2-push",
            agent_id=self._id("agent-a"),
            premise=premise_v2,
            risk=RiskLevel.CRITICAL,
            binding_stage="agent-a-v2-push",
            authorized_targets=("refs/heads/agent-a-repaired",),
            artifact_hashes=push_bindings,
            evidence_ids=evidence_ids,
            required_tests=(targeted_id, full_id),
            replaces_warrant_id=str(initial["push_warrant_id"]),
        )
        refspec = "HEAD:refs/heads/agent-a-repaired"
        action = self._create_action(
            suffix="action-agent-a-push-v2",
            agent_id=self._id("agent-a"),
            warrant=warrant,
            premise=premise_v2,
            action_type=ActionType.PUSH,
            target="refs/heads/agent-a-repaired",
            payload={
                "commit": repair["commit"],
                "tree": repair_tree,
                "refspec": refspec,
                "required_test_ids": [targeted_id, full_id],
            },
            risk=RiskLevel.CRITICAL,
            reversibility=Reversibility.CONDITIONAL,
            replaces_action_id=str(initial["push_action_id"]),
        )
        remote_url = await self.git.remote_url(self.replacement_worktree, "origin")
        effect_intent = self._create_effect_intent(
            suffix="effect-agent-a-push-v2",
            action=action,
            effect_type=EffectType.PUSH,
            after_hash=str(repair["commit"]),
            metadata={
                "replaces_effect_id": initial["push_effect_id"],
                "repository": str(self.replacement_worktree),
                "remote": "origin",
                "remote_url": remote_url,
                "destination": "refs/heads/agent-a-repaired",
                "refspec": refspec,
                "source_oid": repair["commit"],
                "commit": repair["commit"],
                "tree": repair_tree,
                "targeted_test_id": targeted_id,
                "full_test_id": full_id,
            },
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action.id,
            effect_id=effect_intent.id,
            current_artifact_hashes=push_bindings,
            passed_test_ids=(targeted_id, full_id),
        )
        grant = gateway.dispatch(
            action.id,
            effect_id=effect_intent.id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=push_bindings,
            passed_test_ids=(targeted_id, full_id),
        )
        push_token = self.push_tokens.issue(
            action_id=action.id,
            epoch=grant.epoch,
            repository=self.replacement_worktree,
            remote_url=remote_url,
            refspec=refspec,
            source_oid=str(repair["commit"]),
        )
        pushed = await self.git.push(
            self.replacement_worktree,
            remote="origin",
            refspec=refspec,
            capability_token=push_token,
            action_id=action.id,
            epoch=grant.epoch,
        )
        effect = EffectRecord.model_validate(
            grant.effect.model_copy(
                update={
                    "before_hash": pushed.before_remote_head,
                    "after_hash": pushed.after_remote_head,
                    "state": EffectState.EXECUTED,
                }
            ).model_dump()
        )
        gateway.complete(effect)
        self._create_replaces_edge(
            old_action_id=str(initial["push_action_id"]),
            new_action_id=action.id,
            suffix="push-v2-replaces-v1",
        )
        proof_path = self.fixture.artifacts_root / "git" / "replacement-push.json"
        self._write_json(
            proof_path,
            {
                "case_id": case_id,
                "warrant_id": warrant.id,
                "action_id": action.id,
                "effect_id": effect.id,
                "replaces_action_id": initial["push_action_id"],
                "replaces_effect_id": initial["push_effect_id"],
                "remote": str(self.fixture.remote),
                "remote_ref": "refs/heads/agent-a-repaired",
                "before": pushed.before_remote_head,
                "after": pushed.after_remote_head,
                "commit": repair["commit"],
                "tree": repair_tree,
                "artifact_hashes": push_bindings,
                "required_test_ids": [targeted_id, full_id],
            },
        )
        lineage_path = self.fixture.artifacts_root / "lineage.json"
        self._write_json(
            lineage_path,
            {
                "warrants": [
                    {
                        "id": repair["model_warrant_id"],
                        "replaces": initial["model_warrant_id"],
                    },
                    {
                        "id": repair["migration_warrant_id"],
                        "replaces": initial["migration_warrant_id"],
                    },
                    {"id": warrant.id, "replaces": initial["push_warrant_id"]},
                ],
                "actions": [
                    {
                        "id": repair["migration_action_id"],
                        "replaces": initial["migration_action_id"],
                    },
                    {
                        "id": repair["model_action_id"],
                        "replaces": initial["model_action_id"],
                    },
                    {"id": action.id, "replaces": initial["push_action_id"]},
                ],
                "effects": [
                    {
                        "id": repair["migration_effect_id"],
                        "replaces": initial["migration_effect_id"],
                    },
                    {
                        "id": repair["model_effect_id"],
                        "replaces": initial["model_effect_id"],
                    },
                    {"id": effect.id, "replaces": initial["push_effect_id"]},
                ],
            },
        )
        return {
            "warrant_id": warrant.id,
            "action_id": action.id,
            "effect_id": effect.id,
            "remote_ref": "refs/heads/agent-a-repaired",
            "before": pushed.before_remote_head,
            "after": pushed.after_remote_head,
            "commit": repair["commit"],
            "tree": repair_tree,
            "proof_path": proof_path,
            "lineage_path": lineage_path,
        }

    def _build_receipt(
        self,
        *,
        revocation: RevocationResult,
        evidence_v1: EvidenceRecord,
        evidence_v2: EvidenceRecord,
        premise_v1: Premise,
        premise_v2: Premise,
        initial: Mapping[str, Any],
        unrelated: Mapping[str, Any],
        inventory_path: Path,
        compensation: Mapping[str, Any],
        experiment: Mapping[str, Any],
        repair: Mapping[str, Any],
        tests: Mapping[str, Any],
        replacement_push: Mapping[str, Any],
    ) -> ScenarioResult:
        events = self.store.journal.list_events(self.fixture.run_id)
        head_digest = self.store.journal.verify_chain(self.fixture.run_id)
        if not events or events[-1].event_hash != head_digest:
            raise IntegrityError("durable event journal head verification failed")
        frozen = self._transition_event(events, revocation.case.id, "FROZEN")
        agent_b_pushed = self._aggregate_event(events, str(unrelated["effect_id"]))
        resumed = self._transition_event(events, revocation.case.id, "RESUMED")
        if not frozen.sequence < agent_b_pushed.sequence < resumed.sequence:
            raise IntegrityError(
                "Agent B push must occur strictly between Agent A FROZEN and RESUMED"
            )

        timeline_path = self.fixture.artifacts_root / "logs" / "timeline.json"
        timeline = {
            "frozen": self._event_summary(frozen),
            "agent_b_push": self._event_summary(agent_b_pushed),
            "resumed": self._event_summary(resumed),
            "strict_order": [frozen.sequence, agent_b_pushed.sequence, resumed.sequence],
        }
        self._write_json(timeline_path, timeline)
        premise_delta_path = self.fixture.artifacts_root / "evidence" / "premise-delta.json"
        persisted_v1 = self.store.get_premise(premise_v1.id)
        persisted_v2 = self.store.get_premise(premise_v2.id)
        if persisted_v1 is None or persisted_v2 is None:
            raise IntegrityError("premise revisions disappeared before attestation")
        self._write_json(
            premise_delta_path,
            {
                "invalidated": persisted_v1.model_dump(mode="json"),
                "replacement": persisted_v2.model_dump(mode="json"),
                "invalidating_evidence_id": evidence_v2.id,
            },
        )
        events_path = self.fixture.artifacts_root / "events.jsonl"
        events_path.write_text(
            "".join(f"{canonical_json(event.model_dump(mode='python'))}\n" for event in events),
            encoding="utf-8",
        )

        authorization_entries = [
            self._authorization_entry(
                stage="agent-a-v1-local-commit",
                warrant_id=str(initial["model_warrant_id"]),
                action_id=str(initial["model_action_id"]),
                bound_values={
                    "paths": ["billing/models.py", MIGRATION_SOURCE_PATH],
                    "contract": "uuid-v1",
                },
            ),
            self._authorization_entry(
                stage="agent-a-v1-migration",
                warrant_id=str(initial["migration_warrant_id"]),
                action_id=str(initial["migration_action_id"]),
                bound_values={
                    "source_path": MIGRATION_SOURCE_PATH,
                    "source_sha256": initial["migration_source_sha256"],
                },
            ),
            self._authorization_entry(
                stage="agent-a-v1-push",
                warrant_id=str(initial["push_warrant_id"]),
                action_id=str(initial["push_action_id"]),
                bound_values={
                    "commit": initial["invalid_commit"],
                    "tree": initial["invalid_tree"],
                },
            ),
            self._authorization_entry(
                stage="agent-b-observability-local-commit",
                warrant_id=str(unrelated["commit_warrant_id"]),
                action_id=str(unrelated["commit_action_id"]),
                bound_values={
                    "path": "docs/observability.md",
                    "commit": unrelated["commit"],
                    "tree": unrelated["tree"],
                },
            ),
            self._authorization_entry(
                stage="agent-b-observability-push",
                warrant_id=str(unrelated["warrant_id"]),
                action_id=str(unrelated["action_id"]),
                bound_values={
                    "path": "docs/observability.md",
                    "commit": unrelated["commit"],
                    "tree": unrelated["tree"],
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-decisive-experiment",
                warrant_id=str(experiment["warrant_id"]),
                action_id=str(experiment["action_id"]),
                bound_values={
                    "candidate_id": experiment["selection"].candidate.id,
                    "command_target": experiment["command_target"],
                    "argv": list(experiment["selection"].candidate.argv),
                    "sandbox": experiment["sandbox"],
                    "environment": experiment["environment"],
                    "commit": experiment["commit"],
                    "tree": experiment["tree"],
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-repair-local-commit",
                warrant_id=str(repair["model_warrant_id"]),
                action_id=str(repair["model_action_id"]),
                bound_values={
                    "paths": list(repair["provider_result"].changed_paths),
                    "selected_experiment_id": experiment["selection"].candidate.id,
                    "contract": "opaque-v2",
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-migration",
                warrant_id=str(repair["migration_warrant_id"]),
                action_id=str(repair["migration_action_id"]),
                bound_values={
                    "source_path": MIGRATION_SOURCE_PATH,
                    "source_sha256": repair["migration_source_sha256"],
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-targeted-test",
                warrant_id=str(tests["targeted"]["warrant_id"]),
                action_id=str(tests["targeted"]["action_id"]),
                bound_values={
                    "test_id": tests["targeted"]["record"].id,
                    "command_target": tests["targeted"]["command_target"],
                    "argv": list(tests["targeted"]["record"].argv),
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-full-test",
                warrant_id=str(tests["full"]["warrant_id"]),
                action_id=str(tests["full"]["action_id"]),
                bound_values={
                    "test_id": tests["full"]["record"].id,
                    "command_target": tests["full"]["command_target"],
                    "argv": list(tests["full"]["record"].argv),
                },
            ),
            self._authorization_entry(
                stage="agent-a-v2-push",
                warrant_id=str(replacement_push["warrant_id"]),
                action_id=str(replacement_push["action_id"]),
                bound_values={
                    "commit": replacement_push["commit"],
                    "tree": replacement_push["tree"],
                    "required_test_ids": [
                        tests["targeted"]["record"].id,
                        tests["full"]["record"].id,
                    ],
                },
            ),
        ]
        authorization_path = self.fixture.artifacts_root / "authorization-bindings.json"
        self._write_json(
            authorization_path,
            {
                "run_id": self.fixture.run_id,
                "case_id": revocation.case.id,
                "authorizations": authorization_entries,
            },
        )

        requirement_artifacts: dict[str, list[Path]] = {
            requirement: [] for requirement in ALL_REQUIREMENTS
        }
        requirement_artifacts.update(
            {
                "R-02": [
                    Path(initial["preflight_path"]),
                    self.artifact_root / "git/invalid.patch",
                    authorization_path,
                ],
                "R-03": [
                    self.artifact_root / "evidence/schema-v1.json",
                    self.artifact_root / "evidence/schema-v2.json",
                ],
                "R-04": [premise_delta_path],
                "R-05": [inventory_path],
                "R-06": [self.artifact_root / "logs/negative-reachability.json"],
                "R-07": [Path(unrelated["proof_path"]), timeline_path, authorization_path],
                "R-08": [
                    inventory_path,
                    self.artifact_root / "git/invalid.patch",
                    Path(initial["migration_source_proof_path"]),
                    Path(initial["migration_source_sql_path"]),
                    authorization_path,
                ],
                "R-09": [Path(compensation["compensation_path"])],
                "R-10": [Path(compensation["quarantine_path"])],
                "R-11": [Path(compensation["quarantine_path"])],
                "R-12": [Path(experiment["candidates_path"])],
                "R-13": [
                    Path(experiment["run_path"]),
                    Path(experiment["sandbox_profile_path"]),
                    Path(experiment["worktree_pre_manifest_path"]),
                    Path(experiment["worktree_post_manifest_path"]),
                ],
                "R-15": [
                    Path(tests["targeted"]["proof_path"]),
                    Path(tests["full"]["proof_path"]),
                ],
                "R-16": [
                    Path(replacement_push["lineage_path"]),
                    Path(replacement_push["proof_path"]),
                    Path(repair["migration_source_proof_path"]),
                    Path(repair["migration_source_sql_path"]),
                    authorization_path,
                ],
                "R-17": [events_path, timeline_path],
            }
        )
        provider_result = repair["provider_result"]
        if isinstance(provider_result, LiveCodexResult):
            if (
                self._live_initial is None
                or self._live_agent_b_initial is None
                or self._live_concurrency_path is None
            ):
                raise IntegrityError("live concurrent Codex proof is incomplete")
            concurrent_results = (self._live_initial, self._live_agent_b_initial)
            requirement_artifacts["R-01"] = [
                self._live_concurrency_path,
                *(
                    path
                    for live_result in concurrent_results
                    for path in (
                        live_result.artifacts.manifest_path,
                        live_result.artifacts.events_path,
                        live_result.artifacts.event_observations_path,
                    )
                ),
            ]
            live_paths = [
                provider_result.artifacts.manifest_path,
                provider_result.artifacts.events_path,
                provider_result.artifacts.event_observations_path,
                provider_result.artifacts.diff_path,
            ]
            proposal_attempts = (
                self._live_proposals.attempts if self._live_proposals is not None else ()
            )
            for live_result in (
                self._live_initial,
                self._live_agent_b_initial,
                self._live_analysis.run if self._live_analysis is not None else None,
                *proposal_attempts,
            ):
                if live_result is not None:
                    live_paths.extend(
                        (
                            live_result.artifacts.manifest_path,
                            live_result.artifacts.events_path,
                            live_result.artifacts.event_observations_path,
                        )
                    )
            requirement_artifacts["R-14"] = live_paths
        proof_manifest = ReceiptBuilder.build_manifest(
            artifact_root=self.fixture.artifacts_root,
            requirement_artifacts=requirement_artifacts,
            required_requirement_ids=self.proof_requirements,
        )
        proof_manifest_path = self.fixture.artifacts_root / "proof-manifest.json"
        self._write_json(proof_manifest_path, proof_manifest)

        affected_effects = [
            self._require_effect(effect_id).model_dump(mode="json")
            for effect_id in revocation.affected_effect_ids
        ]
        unaffected_effects = [
            self._require_effect(str(effect_id)) for effect_id in unrelated["effect_ids"]
        ]
        selection = experiment["selection"]
        experiment_run = experiment["run"]
        targeted = tests["targeted"]["record"]
        full = tests["full"]["record"]
        receipt_fields: dict[str, Any] = {
            "receipt_version": 1,
            "run_id": self.fixture.run_id,
            "case_id": revocation.case.id,
            "scenario": "external-schema-v2",
            "proof_scope": self.proof_requirements,
            "concurrency": (
                self._load_json(self._live_concurrency_path)
                if self._live_concurrency_path is not None
                else None
            ),
            "migration_sources": {
                "invalid_v1": self._load_json(Path(initial["migration_source_proof_path"])),
                "repair_v2": self._load_json(Path(repair["migration_source_proof_path"])),
            },
            "authorizations": authorization_entries,
            "agents": [
                {
                    "id": self._id("agent-a"),
                    "worktree": str(self.fixture.agent_a_worktree),
                    "role": "schema-dependent billing migration",
                    "replacement_worktree": str(self.replacement_worktree),
                },
                {
                    "id": self._id("agent-b"),
                    "worktree": str(self.fixture.agent_b_worktree),
                    "role": "schema-independent observability",
                },
            ],
            "trigger": {
                "evidence_id": evidence_v2.id,
                "source_uri": evidence_v2.source_uri,
                "source_version": evidence_v2.source_version,
                "signature_status": evidence_v2.signature_status,
                "verification_status": evidence_v2.verification_status,
                "schema_digest": evidence_v2.digest,
                "prior_evidence_id": evidence_v1.id,
            },
            "premise_delta": {
                "invalidated": persisted_v1.model_dump(mode="json"),
                "replacement": persisted_v2.model_dump(mode="json"),
            },
            "dependency_paths": [
                {
                    "entity_id": member.entity_id,
                    "member_kind": member.member_kind,
                    "node_path": member.dependency_path,
                }
                for member in revocation.members
            ],
            "affected_effects": list(revocation.affected_effect_ids),
            "affected_effect_records": affected_effects,
            "affected_effect_ids": revocation.affected_effect_ids,
            "unaffected_effects": [effect.id for effect in unaffected_effects],
            "unaffected_effect_records": [
                effect.model_dump(mode="json") for effect in unaffected_effects
            ],
            "compensation": {
                "database_restored_hash": compensation["database_restored_hash"],
                "model_restored_hash": compensation["model_restored_hash"],
                "rollback_commit": compensation["rollback_commit"],
            },
            "quarantine": {
                "invalid_commit": initial["invalid_commit"],
                "quarantine_ref": compensation["quarantine_ref"],
                "ref": compensation["quarantine_ref"],
                "repository": str(self.fixture.repository),
                "pending_remote_ref": compensation["pending_remote_ref"],
                "pending_remote_head": compensation["pending_remote_head"],
            },
            "experiment": {
                "candidate_count": experiment["candidate_count"],
                "selected_candidate_id": selection.candidate.id,
                "selected_score": selection.score,
                "argv": experiment_run.metadata.get("argv", selection.candidate.argv),
                "exit_code": experiment_run.exit_code,
                "stdout_artifact_digest": experiment["stdout_digest"],
                "stderr_artifact_digest": experiment["stderr_digest"],
                "observed_outcome": experiment_run.observed_outcome,
                "environment": experiment["environment"],
                "environment_digest": experiment_run.environment_digest,
                "sandbox": experiment["sandbox"],
                "commit": experiment["commit"],
                "tree": experiment["tree"],
                "workspace_unchanged": True,
                "evidence_hypothesis_id": experiment["evidence_hypothesis_id"],
                "resolved_hypothesis_id": experiment["resolved_hypothesis_id"],
                "disagreement_confirmed": True,
                "live_proposal_attempts": (
                    [
                        {
                            "attempt_index": index,
                            "stage": attempt.stage,
                            "thread_id": attempt.thread_id,
                            "session_id": attempt.session_id,
                            "manifest_path": str(attempt.artifacts.manifest_path),
                            "manifest_digest": attempt.artifacts.manifest_digest,
                            "events_path": str(attempt.artifacts.events_path),
                            "events_sha256": sha256_digest(
                                attempt.artifacts.events_path.read_bytes()
                            ),
                            "event_observations_path": str(
                                attempt.artifacts.event_observations_path
                            ),
                            "event_observations_sha256": sha256_digest(
                                attempt.artifacts.event_observations_path.read_bytes()
                            ),
                            "validation_error": (
                                self._live_proposals.validation_errors[index]
                                if index < len(self._live_proposals.validation_errors)
                                else None
                            ),
                        }
                        for index, attempt in enumerate(self._live_proposals.attempts)
                    ]
                    if self._live_proposals is not None
                    else []
                ),
                "live_proposal_validation_errors": (
                    list(self._live_proposals.validation_errors)
                    if self._live_proposals is not None
                    else []
                ),
            },
            "repair": {
                "provider": (
                    "live-codex"
                    if isinstance(provider_result, LiveCodexResult)
                    else provider_result.provider
                ),
                "live_codex": isinstance(provider_result, LiveCodexResult),
                "session_id": provider_result.session_id,
                "response_ids": provider_result.response_ids,
                "changed_paths": provider_result.changed_paths,
                "live_session_lineage": (
                    {
                        "agent_a_initial": self._live_initial.session_id,
                        "agent_b_observability": self._live_agent_b_initial.session_id,
                        "agent_b_analysis": self._live_analysis.session_id,
                        "agent_b_experiments": self._live_proposals.run.session_id,
                        "repair": provider_result.session_id,
                    }
                    if isinstance(provider_result, LiveCodexResult)
                    and self._live_initial is not None
                    and self._live_agent_b_initial is not None
                    and self._live_analysis is not None
                    and self._live_proposals is not None
                    else None
                ),
                "invalid_commit": initial["invalid_commit"],
                "repaired_commit": repair["commit"],
                "replacement_action_ids": [
                    repair["migration_action_id"],
                    repair["model_action_id"],
                    replacement_push["action_id"],
                ],
                "replacement_effect_ids": [
                    repair["migration_effect_id"],
                    repair["model_effect_id"],
                    replacement_push["effect_id"],
                ],
            },
            "verification": {
                "proof_scope": self.proof_requirements,
                "targeted": targeted.model_dump(mode="json"),
                "full": full.model_dump(mode="json"),
            },
            "resume": {
                "remote": str(self.fixture.remote),
                "ref": replacement_push["remote_ref"],
                "commit": replacement_push["after"],
                "agent_b_ref": unrelated["remote_ref"],
                "agent_b_commit": unrelated["after"],
                "replacement_remote_ref": replacement_push["remote_ref"],
                "before_remote_sha": replacement_push["before"],
                "after_remote_sha": replacement_push["after"],
                "replacement_push_action_id": replacement_push["action_id"],
                "replacement_push_effect_id": replacement_push["effect_id"],
            },
            "timeline": timeline,
            "event_sequences": {
                "frozen": frozen.sequence,
                "agent_b_push": agent_b_pushed.sequence,
                "resumed": resumed.sequence,
                "event_anchor": events[-1].sequence,
            },
            "repositories": {
                "working_repository": str(self.fixture.repository),
                "bare_remote": str(self.fixture.remote),
                "baseline_commit": self.fixture.baseline_commit,
                "agent_b_remote_ref": unrelated["remote_ref"],
                "agent_b_remote_sha": unrelated["after"],
                "replacement_remote_ref": replacement_push["remote_ref"],
                "replacement_remote_sha": replacement_push["after"],
            },
            "failures": [],
            "limitations": [
                *(
                    []
                    if isinstance(provider_result, LiveCodexResult)
                    else [
                        (
                            "R-01 is not claimed: scripted mode does not launch two real "
                            "Codex processes or claim concurrent live-agent proof."
                        )
                    ]
                ),
                *(
                    []
                    if isinstance(provider_result, LiveCodexResult)
                    else [
                        (
                            "R-14 is not claimed: the repair provider is a clearly labelled "
                            "deterministic demo double."
                        )
                    ]
                ),
                (
                    "R-18 and R-19 are benchmark-suite proofs, not claims of this "
                    "canonical scenario run."
                ),
                "R-20 requires three independent live judge runs and is not claimed here.",
            ],
        }
        built = ReceiptBuilder.build(
            receipt_fields=receipt_fields,
            proof_manifest=proof_manifest,
            event_head_digest=head_digest,
        )
        receipt_path = self.fixture.artifacts_root / "receipt.json"
        self._write_json(receipt_path, built.payload)
        receipt_digest_path = self.fixture.artifacts_root / "receipt.sha256"
        receipt_digest_path.write_text(
            f"{sha256_digest(receipt_path.read_bytes())}\n",
            encoding="ascii",
        )
        verification = StrictReceiptVerifier.verify(
            payload=built.payload,
            proof_manifest=proof_manifest,
            artifact_root=self.fixture.artifacts_root,
            required_requirement_ids=self.proof_requirements,
        )
        receipt_artifact = self._store_artifact_bytes(
            receipt_path.read_bytes(),
            media_type="application/json",
            metadata={"kind": "canonical-receipt"},
        )
        receipt_record = Receipt(
            id=self._id("receipt"),
            run_id=self.fixture.run_id,
            case_id=revocation.case.id,
            state=ReceiptState.DRAFT,
            canonical_digest=built.canonical_digest,
            event_head_digest=head_digest,
            manifest_digest=built.manifest_digest,
            created_at=self.store.clock.utc_now(),
            metadata={"proof_scope": self.proof_requirements},
        )
        self.store.create_receipt(receipt_record)
        self.store.transition_receipt(
            receipt_record.id,
            ReceiptState.FINAL,
            artifact_digest=receipt_artifact.digest,
        )
        self.store.transition_receipt(receipt_record.id, ReceiptState.VERIFIED)
        self._write_json(
            self.fixture.artifacts_root / "logs" / "receipt-verification.json",
            {
                "valid": verification.valid,
                "receipt_digest": verification.receipt_digest,
                "manifest_digest": verification.manifest_digest,
                "verified_requirements": verification.verified_requirements,
            },
        )
        return ScenarioResult(
            run_id=self.fixture.run_id,
            case_id=revocation.case.id,
            fixture=self.fixture,
            receipt_path=receipt_path,
            receipt_digest_path=receipt_digest_path,
            proof_manifest_path=proof_manifest_path,
            events_path=events_path,
            receipt=built.payload,
            proof_manifest=proof_manifest,
            affected_effect_ids=revocation.affected_effect_ids,
            unaffected_effect_id=str(unrelated["effect_id"]),
            invalid_commit=str(initial["invalid_commit"]),
            quarantine_ref=str(compensation["quarantine_ref"]),
            repaired_commit=str(repair["commit"]),
            replacement_remote_ref=str(replacement_push["remote_ref"]),
            concurrency_proof_path=self._live_concurrency_path,
            strict_verification_valid=verification.valid,
            proven_requirement_ids=verification.verified_requirements,
        )

    def _store_artifact_bytes(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        artifact = self.artifacts.put_bytes(
            content,
            media_type=media_type,
            metadata=metadata,
        )
        existing = self.store.get_artifact(artifact.digest)
        return existing if existing is not None else self.store.create_artifact(artifact)

    def _store_artifact_json(
        self,
        value: Any,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        artifact = self.artifacts.put_json(value, metadata=metadata)
        existing = self.store.get_artifact(artifact.digest)
        return existing if existing is not None else self.store.create_artifact(artifact)

    def _authorization_entry(
        self,
        *,
        stage: str,
        warrant_id: str,
        action_id: str,
        bound_values: Mapping[str, Any],
    ) -> dict[str, Any]:
        warrant = self.store.get_warrant(warrant_id)
        action = self.store.get_action(action_id)
        if warrant is None or action is None:
            raise IntegrityError(f"authorization record disappeared for {stage}")
        effects = self.store.list_effects(self.fixture.run_id, action_id=action.id)
        if len(effects) != 1:
            raise IntegrityError(f"authorization must bind exactly one effect for {stage}")
        effect = effects[0]
        lease = self.store.get_lease_for_action(action.id)
        if lease is None or lease.effect_id != effect.id:
            raise IntegrityError(f"authorization lease/effect binding disappeared for {stage}")
        if not warrant.artifact_hashes or dict(action.artifact_vector) != dict(
            warrant.artifact_hashes
        ):
            raise IntegrityError(f"authorization artifact binding is incomplete for {stage}")
        if warrant.metadata.get("binding_stage") != stage:
            raise IntegrityError(f"authorization stage binding is inconsistent for {stage}")
        transitions = {
            str(event.payload.get("to")): event.sequence
            for event in self.store.journal.list_events(self.fixture.run_id)
            if event.aggregate_type == "effect"
            and event.aggregate_id == effect.id
            and event.kind == "effect.transitioned"
        }
        authorized_sequence = transitions.get(EffectState.AUTHORIZED.value)
        if authorized_sequence is None:
            raise IntegrityError(f"authorization event disappeared for {stage}")
        return {
            "stage": stage,
            "warrant": warrant.model_dump(mode="json"),
            "action": action.model_dump(mode="json"),
            "effect": effect.model_dump(mode="json"),
            "lease": lease.model_dump(mode="json"),
            "event_sequences": {
                "authorized": authorized_sequence,
                "dispatching": transitions.get(EffectState.DISPATCHING.value),
                "executed": transitions.get(EffectState.EXECUTED.value),
            },
            "premise_bindings": [
                binding.model_dump(mode="json")
                for binding in self.store.list_warrant_premises(warrant.id)
            ],
            "bound_values": dict(bound_values),
        }

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{canonical_json(value)}\n", encoding="utf-8")

    def _require_action(self, action_id: str) -> ActionIntent:
        action = self.store.get_action(action_id)
        if action is None:
            raise IntegrityError(f"action disappeared: {action_id}")
        return action

    def _require_premise_from_warrant(self, warrant_id: str) -> Premise:
        bindings = self.store.list_warrant_premises(warrant_id)
        if len(bindings) != 1:
            raise IntegrityError(
                f"warrant {warrant_id} must bind exactly one premise in the canonical demo"
            )
        premise = self.store.get_premise(bindings[0].premise_id)
        if premise is None:
            raise IntegrityError(f"warrant premise disappeared: {bindings[0].premise_id}")
        return premise

    def _require_effect(self, effect_id: str) -> EffectRecord:
        effect = self.store.get_effect(effect_id)
        if effect is None:
            raise IntegrityError(f"effect disappeared: {effect_id}")
        return effect

    async def _remote_head(self, ref: str) -> str | None:
        result = await self.runner.run(
            (
                "git",
                "-C",
                str(self.fixture.remote),
                "rev-parse",
                "--verify",
                "--quiet",
                ref,
            ),
            cwd=self.fixture.root,
            timeout_seconds=30,
            allowed_exit_codes=(0, 1),
        )
        if result.exit_code == 1:
            return None
        head = result.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
            raise IntegrityError(f"unexpected remote ref output for {ref}")
        return head

    @staticmethod
    def _transition_event(
        events: list[EventRecord],
        aggregate_id: str,
        target: str,
    ) -> EventRecord:
        matches = [
            event
            for event in events
            if event.aggregate_id == aggregate_id
            and event.kind.endswith(".transitioned")
            and event.payload.get("to") == target
        ]
        if len(matches) != 1:
            raise IntegrityError(
                f"expected one {aggregate_id} transition to {target}, found {len(matches)}"
            )
        return matches[0]

    @staticmethod
    def _aggregate_event(events: list[EventRecord], aggregate_id: str) -> EventRecord:
        matches = [event for event in events if event.aggregate_id == aggregate_id]
        if not matches:
            raise IntegrityError(f"no durable event found for {aggregate_id}")
        return matches[-1]

    @staticmethod
    def _event_summary(event: EventRecord) -> dict[str, Any]:
        return {
            "event_id": event.id,
            "sequence": event.sequence,
            "kind": event.kind,
            "aggregate_type": event.aggregate_type,
            "aggregate_id": event.aggregate_id,
            "created_at": event.created_at,
            "event_hash": event.event_hash,
        }


async def run_canonical_scenario(
    output_root: Path,
    *,
    run_id: str | None = None,
    python_executable: Path | None = None,
    live_codex: bool = False,
    codex_model: str | None = None,
    codex_bin: Path | None = None,
    codex_timeout_seconds: float = 900.0,
) -> ScenarioResult:
    scenario = await CanonicalScenario.prepare(
        output_root,
        run_id=run_id,
        python_executable=python_executable,
        live_codex=live_codex,
        codex_model=codex_model,
        codex_bin=codex_bin,
        codex_timeout_seconds=codex_timeout_seconds,
    )
    try:
        return await scenario.run()
    finally:
        await scenario.close()
