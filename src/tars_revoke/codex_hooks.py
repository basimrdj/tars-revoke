"""Cooperative Codex lifecycle integration; not a remote enforcement boundary."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from tars_revoke.adapters._safety import require_non_secret_payload, validate_argv
from tars_revoke.codex_recovery import discover_tests, repair_allowed, verify_recovery
from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.domain.enums import (
    ActionState,
    ActionType,
    AgentState,
    DispatchReconciliationOutcome,
    EffectState,
    EffectType,
    PremiseState,
    Reversibility,
    RiskLevel,
    RunState,
    TestState,
    ValueSemantics,
    WarrantState,
)
from tars_revoke.domain.models import (
    ActionIntent,
    Agent,
    DispatchReconciliationRecord,
    EffectRecord,
    Premise,
    Run,
    Warrant,
    WarrantPremise,
)
from tars_revoke.errors import AuthorizationError, IntegrityError, ValidationError
from tars_revoke.ids import new_id
from tars_revoke.persistence.store import Store
from tars_revoke.services.gateway import EffectGateway

DEFAULT_WATCH = ("AGENTS.md", "TARS.md", "SPEC.md")
EVENTS = frozenset({"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"})
CONTEXT = (
    "TARS local checks are active. Requirements file changes block pending tool calls. "
    "During recovery read with cat and repair with workspace-relative apply_patch, then stop "
    "so TARS independently runs the configured tests. This is cooperative hook protection: "
    "arbitrary shell/API effects cannot be automatically rolled back. "
    "Never treat hook admission as permission to bypass Codex approvals. "
    "Do not execute operator accept/contain commands yourself to escape a block."
)


def repo_root(cwd: Path) -> Path:
    """Find a project config or Git root without executing project code."""
    current = cwd.expanduser().resolve(strict=True)
    if not current.is_dir():
        raise ValidationError("hook cwd must be an existing directory")
    for candidate in (current, *current.parents):
        if (candidate / ".tars" / "codex.json").exists() or (candidate / ".git").exists():
            return candidate
    return current


def safe_file(root: Path, name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValidationError("watched files must be repository-relative paths")
    candidate = root / path
    if not candidate.resolve().is_relative_to(root) or any(
        parent.is_symlink() for parent in (candidate, *candidate.parents) if parent != root
    ):
        raise ValidationError("watched paths must not contain symlinks or escape the repository")
    if candidate.exists() and not candidate.is_file():
        raise ValidationError("watched inputs must be regular files")
    return candidate


def deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def context(event: str, message: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": message}}


class HookRuntime:
    """Persist per-session contracts and admit tools through the existing gateway.

    No tool is executed here. Codex runs it after hook admission. File changes
    between the hook and actual execution remain a documented native-mode gap.
    """

    dispatching_state = ActionState.DISPATCHING
    digest = staticmethod(sha256_digest)

    def __init__(self, root: Path):
        self.root = root.expanduser().resolve(strict=True)
        self.directory = self.root / ".tars"
        self.config_path = self.directory / "codex.json"
        if self.directory.is_symlink() or self.config_path.is_symlink():
            raise ValidationError("TARS configuration must not be a symlink")
        config = json.loads(self.config_path.read_text())
        if not isinstance(config, dict) or config.get("version") != 1:
            raise ValidationError("unsupported TARS Codex configuration")
        watch = config.get("watch")
        if not isinstance(watch, list) or not watch or not all(isinstance(x, str) for x in watch):
            raise ValidationError("watch must be a non-empty list of relative file paths")
        tests = config.get("tests", [])
        if not isinstance(tests, list) or any(not isinstance(command, list) for command in tests):
            raise ValidationError("tests must be arrays of argv arrays")
        if len(tests) > 1:
            raise ValidationError("native recovery supports one bounded test-suite command")
        require_non_secret_payload(tests)
        self.tests = [list(validate_argv(command)) for command in tests]
        self.watch = tuple(dict.fromkeys(watch))
        for name in self.watch:
            safe_file(self.root, name)
        state = self.directory / "codex.sqlite"
        if state.is_symlink():
            raise ValidationError("TARS state must not be a symlink")
        self.store = Store(state)
        with self.store.database.connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS codex_sessions (
                    session_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE,
                    prompt_digest TEXT, turn_id TEXT, baseline_json TEXT NOT NULL,
                    recovery_required INTEGER NOT NULL DEFAULT 0, recovery_json TEXT,
                    recovery_attempts INTEGER NOT NULL DEFAULT 0
                ) STRICT;
                CREATE TABLE IF NOT EXISTS codex_calls (
                    session_id TEXT NOT NULL, tool_use_id TEXT NOT NULL,
                    action_id TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL,
                    response_digest TEXT, PRIMARY KEY(session_id, tool_use_id)
                ) STRICT;
            """)

        with self.store.database.transaction() as connection:
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(codex_sessions)")
            }
            if "recovery_json" not in columns:
                connection.execute("ALTER TABLE codex_sessions ADD COLUMN recovery_json TEXT")
            if "recovery_attempts" not in columns:
                connection.execute(
                    "ALTER TABLE codex_sessions ADD COLUMN recovery_attempts "
                    "INTEGER NOT NULL DEFAULT 0"
                )

    @classmethod
    def enable(
        cls,
        root: Path,
        watch: Sequence[str] = DEFAULT_WATCH,
        tests: Sequence[Sequence[str]] | None = None,
    ) -> HookRuntime:
        root = root.expanduser().resolve(strict=True)
        if not watch:
            raise ValidationError("at least one requirements file must be watched")
        for name in watch:
            safe_file(root, name)
        directory = root / ".tars"
        if directory.is_symlink():
            raise ValidationError("TARS state must not be a symlink")
        directory.mkdir(exist_ok=True)
        config = directory / "codex.json"
        if not config.exists():
            with config.open("x") as stream:
                json.dump(
                    {
                        "version": 1,
                        "watch": list(watch),
                        "tests": [list(validate_argv(command)) for command in tests]
                        if tests is not None
                        else discover_tests(root),
                    },
                    stream,
                    indent=2,
                )
            (directory / ".gitignore").write_text("*\n")
        else:
            # Enabling twice cannot silently replace an existing watch policy.
            runtime = cls(root)
            if tuple(watch) != runtime.watch:
                raise ValidationError(
                    "existing watch policy differs; edit .tars/codex.json explicitly"
                )
        return cls(root)

    def fingerprints(self) -> dict[str, str]:
        result = {}
        for name in self.watch:
            path = safe_file(self.root, name)
            result[name] = sha256_digest(path.read_bytes()) if path.exists() else "missing"
        return result

    def _session(self, session_id: str) -> sqlite3.Row:
        if not session_id or len(session_id) > 256:
            raise ValidationError("a bounded session_id is required")
        with self.store.database.connection(readonly=True) as connection:
            row = connection.execute(
                "SELECT * FROM codex_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            raise AuthorizationError("TARS session is missing; start or resume Codex again")
        return cast(sqlite3.Row, row)

    def start(self, session_id: str) -> str:
        if not session_id or len(session_id) > 256:
            raise ValidationError("a bounded session_id is required")
        run_id = "codex_" + sha256_digest(session_id)[:32]
        baseline = self.fingerprints()
        # One SQLite writer serializes repeated startup hooks. Kernel creation
        # happens outside this extension transaction and uses deterministic IDs.
        if self.store.get_run(run_id) is None:
            now = self.store.clock.utc_now()
            try:
                self.store.create_run(
                    Run(
                        id=run_id,
                        name="Codex local session",
                        state=RunState.RUNNING,
                        root_path=str(self.root),
                        created_at=now,
                        updated_at=now,
                        metadata={"integration": "codex-hooks-v1"},
                    )
                )
            except IntegrityError:
                if self.store.get_run(run_id) is None:
                    raise
        if not self.store.list_agents(run_id):
            now = self.store.clock.utc_now()
            try:
                self.store.create_agent(
                    Agent(
                        id=run_id + ":agent",
                        run_id=run_id,
                        name="Codex",
                        role="coding",
                        worktree_path=str(self.root),
                        state=AgentState.RUNNING,
                        created_at=now,
                        updated_at=now,
                    )
                )
            except IntegrityError:
                if not self.store.list_agents(run_id):
                    raise
        with self.store.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO codex_sessions(session_id,run_id,baseline_json) "
                "VALUES(?,?,?)",
                (session_id, run_id, json.dumps(baseline, sort_keys=True)),
            )
        return run_id

    def prompt(self, session_id: str, turn_id: str, prompt: str) -> None:
        session = self._session(session_id)
        if not turn_id or len(turn_id) > 256 or not prompt.strip():
            raise ValidationError("prompt hooks require a turn_id and non-empty prompt")
        digest = sha256_digest(prompt)
        now = self.store.clock.utc_now()
        premise = Premise(
            id=session["run_id"] + ":task:" + sha256_digest(turn_id)[:32],
            run_id=session["run_id"],
            scope="codex-session",
            subject="task",
            relation="revision",
            value={"turn_id": turn_id, "prompt_sha256": digest},
            value_digest=canonical_digest({"turn_id": turn_id, "prompt_sha256": digest}),
            semantics=ValueSemantics.SINGLE,
            state=PremiseState.ACTIVE,
            valid_at=now,
            created_at=now,
        )
        existing = self.store.get_premise(premise.id)
        if existing is not None and (
            existing.state != PremiseState.ACTIVE
            or session["turn_id"] != turn_id
            or existing.value_digest != premise.value_digest
        ):
            raise AuthorizationError("turn ID was reused with a different prompt")
        if existing is None:
            self.store.replace_active_premise(premise)
        with self.store.database.transaction() as connection:
            connection.execute(
                "UPDATE codex_sessions SET prompt_digest=?,turn_id=? WHERE session_id=?",
                (digest, turn_id, session_id),
            )

    def changed(self, session_id: str) -> tuple[str, ...]:
        session = self._session(session_id)
        prior = json.loads(session["baseline_json"])
        current = self.fingerprints()
        changed = tuple(
            sorted(
                name for name in set(prior) | set(current) if prior.get(name) != current.get(name)
            )
        )
        if changed:
            with self.store.database.transaction() as connection:
                connection.execute(
                    "UPDATE codex_sessions SET recovery_required=1 WHERE session_id=?",
                    (session_id,),
                )
        return changed

    def _premise(self, session_id: str, turn_id: str) -> Premise:
        session = self._session(session_id)
        if session["turn_id"] != turn_id or not turn_id:
            raise AuthorizationError("tool belongs to a stale or unregistered Codex turn")
        premises = self.store.find_active_premises(
            run_id=session["run_id"],
            scope="codex-session",
            subject="task",
            relation="revision",
        )
        if len(premises) != 1 or premises[0].value.get("turn_id") != turn_id:
            raise AuthorizationError("session has no unique active task revision")
        return premises[0]

    def pre(self, event: Mapping[str, Any]) -> dict[str, Any]:
        session_id, turn_id = str(event["session_id"]), str(event["turn_id"])
        session = self._session(session_id)
        changed = self.changed(session_id)
        session = self._session(session_id)
        if changed or session["recovery_required"]:
            current = self.fingerprints()
            recovery = json.loads(session["recovery_json"] or "null")
            if current != recovery:
                self._new_recovery_revision(session_id, turn_id, current)
                return deny(
                    "TARS revoked the old task revision: requirements changed ("
                    + ", ".join(changed or ("previously detected",))
                    + "). Read the latest requirements "
                    "with cat and repair local files using apply_patch. General commands and "
                    "publishing are blocked during recovery. When you stop, TARS will execute "
                    "the configured tests itself before accepting the new baseline. "
                    "Do not retry the stale operation or claim that previous effects were undone."
                )
            tool_input = event.get("tool_input")
            workdir = (
                tool_input.get("workdir", str(self.root)) if isinstance(tool_input, dict) else ""
            )
            if (
                not isinstance(workdir, str)
                or Path(workdir).resolve() != self.root
                or not repair_allowed(self, str(event.get("tool_name", "")), tool_input)
            ):
                return deny(
                    "TARS recovery permits only local apply_patch repairs, cat, pwd, "
                    "git diff, git status --short, and the configured test command. "
                    "Inspect requirements and repair, then stop for independent verification."
                )
        premise = self._premise(session_id, turn_id)
        call_id = event.get("tool_use_id")
        tool = event.get("tool_name")
        if not isinstance(call_id, str) or not call_id or len(call_id) > 256:
            raise ValidationError("a bounded tool_use_id is required")
        if not isinstance(tool, str) or not tool or len(tool) > 256:
            raise ValidationError("a bounded tool_name is required")
        payload_digest = canonical_digest({"tool": tool, "input": event.get("tool_input")})
        action_id = session["run_id"] + ":call:" + sha256_digest(call_id)[:32]
        now = self.store.clock.utc_now()
        warrant_id, effect_id = action_id + ":warrant", action_id + ":effect"
        # Claim the tool-use ID before creating kernel records. A crash after
        # this point permanently prevents replay of this exact invocation.
        try:
            with self.store.database.transaction() as connection:
                connection.execute(
                    "INSERT INTO codex_calls(session_id,tool_use_id,action_id,payload_digest) "
                    "VALUES(?,?,?,?)",
                    (session_id, call_id, action_id, payload_digest),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("duplicate tool invocation; TARS will not replay it") from exc
        current_fingerprints = self.fingerprints()
        artifacts = {name: canonical_digest(value) for name, value in current_fingerprints.items()}
        self.store.create_warrant(
            Warrant(
                id=warrant_id,
                run_id=session["run_id"],
                agent_id=session["run_id"] + ":agent",
                scope=premise.scope,
                authorized_targets=(tool,),
                state=WarrantState.AUTHORIZED,
                risk=RiskLevel.HIGH,
                artifact_hashes=artifacts,
                issued_at=now,
                expires_at=now + timedelta(minutes=5),
            )
        )
        self.store.link_warrant_premise(
            WarrantPremise(
                warrant_id=warrant_id,
                premise_id=premise.id,
                premise_digest=premise.value_digest,
                created_at=now,
            )
        )
        self.store.create_action(
            ActionIntent(
                id=action_id,
                run_id=session["run_id"],
                agent_id=session["run_id"] + ":agent",
                warrant_id=warrant_id,
                scope=premise.scope,
                action_type=ActionType.COMMAND,
                target=tool,
                payload_digest=payload_digest,
                premise_vector={premise.id: premise.value_digest},
                artifact_vector=artifacts,
                risk=RiskLevel.HIGH,
                reversibility=Reversibility.IRREVERSIBLE,
                state=ActionState.PREPARED,
                idempotency_key=action_id,
                created_at=now,
                updated_at=now,
                metadata={"tool_name": tool},
            )
        )
        self.store.create_effect(
            EffectRecord(
                id=effect_id,
                run_id=session["run_id"],
                action_id=action_id,
                scope=premise.scope,
                target=tool,
                effect_type=EffectType.COMMAND,
                reversibility=Reversibility.IRREVERSIBLE,
                state=EffectState.PREPARED,
                created_at=now,
                updated_at=now,
                idempotency_key=effect_id,
            )
        )
        gateway = EffectGateway(self.store)
        authorization = gateway.authorize(
            action_id,
            effect_id=effect_id,
            current_artifact_hashes=artifacts,
            passed_test_ids=(),
        )
        # Repeat file and task checks directly before the transactional fence.
        self.changed(session_id)
        if self.fingerprints() != current_fingerprints:
            raise AuthorizationError("requirements changed during preflight")
        current = {name: canonical_digest(value) for name, value in self.fingerprints().items()}
        gateway.dispatch(
            action_id,
            effect_id=effect_id,
            capability_token=authorization.capability_token,
            current_artifact_hashes=current,
            passed_test_ids=(),
        )
        # No permissionDecision=allow: normal Codex approvals still apply.
        return {}

    def post(self, event: Mapping[str, Any]) -> dict[str, Any]:
        session_id, call_id = str(event["session_id"]), str(event["tool_use_id"])
        self._session(session_id)
        with self.store.database.connection(readonly=True) as connection:
            call = connection.execute(
                "SELECT * FROM codex_calls WHERE session_id=? AND tool_use_id=?",
                (session_id, call_id),
            ).fetchone()
        if call is None:
            raise AuthorizationError("postflight has no corresponding TARS admission")
        payload = canonical_digest(
            {"tool": event.get("tool_name"), "input": event.get("tool_input")}
        )
        if payload != call["payload_digest"]:
            raise AuthorizationError("postflight tool input does not match admitted input")
        response = canonical_digest(event.get("tool_response"))
        if call["response_digest"] is not None:
            if call["response_digest"] != response:
                raise AuthorizationError("duplicate postflight has a different response")
            return {}
        action = self.store.get_action(call["action_id"])
        effect = self.store.get_effect(call["action_id"] + ":effect")
        if action is None or effect is None:
            raise IntegrityError("postflight kernel records are missing")
        if action.state == ActionState.DISPATCHING:
            EffectGateway(self.store).complete(
                EffectRecord.model_validate(
                    effect.model_copy(
                        update={
                            "state": EffectState.EXECUTED,
                            "metadata": {
                                "observation": "Codex PostToolUse",
                                "response_sha256": response,
                                "success_claim": False,
                            },
                        }
                    ).model_dump()
                )
            )
        elif action.state != ActionState.EXECUTED:
            raise AuthorizationError("postflight action is not awaiting observation")
        elif effect.metadata.get("response_sha256") != response:
            raise AuthorizationError("completed observation has a different response")
        with self.store.database.transaction() as connection:
            connection.execute(
                "UPDATE codex_calls SET response_digest=? WHERE session_id=? AND tool_use_id=?",
                (response, session_id, call_id),
            )
        changed = self.changed(session_id)
        session = self._session(session_id)
        if changed and json.loads(session["recovery_json"] or "null") != self.fingerprints():
            return {
                "decision": "block",
                "reason": "TARS: requirements changed during this call. "
                "Side effects may already exist. "
                "Inspect affected work before proceeding. Changed files: " + ", ".join(changed),
            }
        return {}

    def _new_recovery_revision(
        self, session_id: str, turn_id: str, baseline: dict[str, str]
    ) -> None:
        prior = self._premise(session_id, turn_id)
        now = self.store.clock.utc_now()
        value = {
            "turn_id": turn_id,
            "prompt_sha256": self._session(session_id)["prompt_digest"],
            "requirements": baseline,
        }
        revision = canonical_digest(value)
        self.store.replace_active_premise(
            Premise(
                id=new_id("codex-recovery"),
                run_id=prior.run_id,
                scope=prior.scope,
                subject="task",
                relation="revision",
                value=value,
                value_digest=revision,
                semantics=ValueSemantics.SINGLE,
                state=PremiseState.ACTIVE,
                valid_at=now,
                created_at=now,
                replaces_premise_id=prior.id,
            )
        )
        with self.store.database.transaction() as connection:
            connection.execute(
                "UPDATE codex_sessions SET recovery_json=?,recovery_attempts=0 WHERE session_id=?",
                (json.dumps(baseline), session_id),
            )

    def accept(
        self,
        session_id: str,
        *,
        verified_test_ids: tuple[str, ...] = (),
        acknowledge_partial_effects: bool = False,
    ) -> dict[str, Any]:
        session = self._session(session_id)
        baseline = self.fingerprints()
        with self.store.database.transaction() as connection:
            pending = self.store.list_actions(
                session["run_id"], state=ActionState.DISPATCHING, connection=connection
            )
            if pending:
                raise AuthorizationError("unobserved calls remain; reconcile them before accepting")
            contained = self.store.list_actions(
                session["run_id"], state=ActionState.CONTAINMENT_REQUIRED, connection=connection
            )
            if contained and not acknowledge_partial_effects:
                raise AuthorizationError("partial effects require explicit operator acknowledgment")
            for test_id in verified_test_ids:
                test = self.store.get_test_run(test_id, connection=connection)
                if (
                    test is None
                    or test.run_id != session["run_id"]
                    or test.state != TestState.PASSED
                    or test.metadata.get("producer") != "tars-codex-recovery"
                    or test.metadata.get("requirements") != baseline
                ):
                    raise AuthorizationError("recovery test is missing, stale, foreign, or failed")
            self.store.journal.append(
                run_id=session["run_id"],
                kind="codex.baseline_accepted",
                aggregate_type="run",
                aggregate_id=session["run_id"],
                payload={
                    "baseline": baseline,
                    "verified_test_ids": verified_test_ids,
                    "partial_effects_acknowledged": acknowledge_partial_effects,
                },
                connection=connection,
            )
            connection.execute(
                "UPDATE codex_sessions SET baseline_json=?,recovery_required=0,recovery_json=NULL "
                "WHERE session_id=?",
                (json.dumps(baseline, sort_keys=True), session_id),
            )
        return {
            "session_id": session_id,
            "baseline_accepted": True,
            "tests_verified": bool(verified_test_ids),
        }

    def contain(self, session_id: str) -> dict[str, Any]:
        """Record unknown external truth without executing or replaying a call."""
        session = self._session(session_id)
        actions = self.store.list_actions(session["run_id"], state=ActionState.DISPATCHING)
        for action in actions:
            self.store.record_dispatch_reconciliation(
                DispatchReconciliationRecord(
                    id=new_id("codex-observation"),
                    run_id=action.run_id,
                    action_id=action.id,
                    effect_id=action.id + ":effect",
                    adapter="codex-native-hooks",
                    outcome=DispatchReconciliationOutcome.UNKNOWN,
                    expected={"tool_use_id_digest": action.id.rsplit(":", 1)[-1]},
                    observed={"completion": "missing"},
                    reason="Operator contained an unobserved native tool call; "
                    "external effects unknown",
                    reconciled_at=self.store.clock.utc_now(),
                )
            )
        with self.store.database.transaction() as connection:
            connection.execute(
                "UPDATE codex_sessions SET recovery_required=1 WHERE session_id=?", (session_id,)
            )
        return {
            "contained_calls": [action.id for action in actions],
            "replayed": False,
            "partial_effects_possible": True,
        }

    def status(self) -> dict[str, Any]:
        with self.store.database.connection(readonly=True) as connection:
            sessions = connection.execute(
                "SELECT * FROM codex_sessions ORDER BY session_id"
            ).fetchall()
        result = []
        for session in sessions:
            changed = self.changed(session["session_id"])
            actions = self.store.list_actions(session["run_id"])
            result.append(
                {
                    "session_id": session["session_id"],
                    "run_id": session["run_id"],
                    "changed_files": changed,
                    "recovery_required": bool(
                        changed or self._session(session["session_id"])["recovery_required"]
                    ),
                    "unobserved_calls": [
                        action.id for action in actions if action.state == ActionState.DISPATCHING
                    ],
                    "containment_required": [
                        action.id
                        for action in actions
                        if action.state == ActionState.CONTAINMENT_REQUIRED
                    ],
                    "observed_calls": sum(
                        action.state == ActionState.EXECUTED for action in actions
                    ),
                    "event_head": self.store.journal.verify_chain(session["run_id"]),
                }
            )
        return {
            "mode": "cooperative-native-hooks",
            "watch": self.watch,
            "tests": self.tests,
            "sessions": result,
        }

    def handle(self, event: Mapping[str, Any]) -> dict[str, Any]:
        kind = event.get("hook_event_name")
        if kind not in EVENTS:
            raise ValidationError("unsupported TARS hook event")
        session_id = str(event.get("session_id", ""))
        if kind == "SessionStart":
            self.start(session_id)
            return context(kind, CONTEXT)
        if kind == "UserPromptSubmit":
            self.prompt(session_id, str(event.get("turn_id", "")), str(event.get("prompt", "")))
            changed = self.changed(session_id)
            return context(
                kind, CONTEXT + (" Changed requirements: " + ", ".join(changed) if changed else "")
            )
        if kind == "PreToolUse":
            return self.pre(event)
        if kind == "PostToolUse":
            return self.post(event)
        session = self._session(session_id)
        changed = self.changed(session_id)
        pending = self.store.list_actions(session["run_id"], state=ActionState.DISPATCHING)
        if (changed or session["recovery_required"]) and not pending:
            return verify_recovery(self, session_id)
        if changed or pending or session["recovery_required"]:
            return {
                "systemMessage": "TARS: unresolved requirements changes "
                "or unobserved calls remain. "
                "This session is not verified. Run `tars-revoke codex status`."
            }
        return {}
