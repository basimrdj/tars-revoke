"""Bounded local repair policy and independently executed recovery tests."""

from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tars_revoke.adapters.processes import AsyncProcessRunner
from tars_revoke.domain.canonical import canonical_digest
from tars_revoke.domain.enums import ActionState, TestKind, TestState
from tars_revoke.domain.models import TestRun
from tars_revoke.errors import AuthorizationError, ValidationError
from tars_revoke.ids import new_id

if TYPE_CHECKING:
    from tars_revoke.codex_hooks import HookRuntime


def discover_tests(root: Path) -> list[list[str]]:
    if (root / "pyproject.toml").exists() and (root / "tests").is_dir():
        python = root / ".venv/bin/python"
        return [[str(python) if python.is_file() else "python3", "-m", "pytest", "-q"]]
    package = root / "package.json"
    if package.is_file():
        metadata = json.loads(package.read_text())
        test = metadata.get("scripts", {}).get("test", "")
        if isinstance(test, str) and test and "no test specified" not in test:
            return [
                [
                    "npm",
                    "test",
                    *(["--", "--run"] if "vitest" in test and "run" not in test else []),
                ]
            ]
    return []


def repair_allowed(runtime: HookRuntime, tool: str, tool_input: Any) -> bool:
    from tars_revoke.codex_hooks import safe_file

    if not isinstance(tool_input, dict):
        return False
    if tool == "apply_patch":
        patch = tool_input.get("command", "")
        if not isinstance(patch, str):
            return False
        paths = []
        for line in patch.splitlines():
            for prefix in (
                "*** Add File: ",
                "*** Update File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ):
                if line.startswith(prefix):
                    target = Path(line[len(prefix) :])
                    if target.is_absolute():
                        try:
                            target = target.relative_to(runtime.root)
                        except ValueError:
                            return False
                    name = target.as_posix()
                    if name in runtime.watch or name.startswith((".tars/", ".codex/", ".git/")):
                        return False
                    try:
                        safe_file(runtime.root, name)
                    except (OSError, ValidationError):
                        return False
                    paths.append(name)
        return bool(paths)
    if tool != "Bash":
        return False
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        return False
    try:
        # Reconstructing rejects shell syntax, substitution, redirects and
        # alternative spellings. Recovery grants no general shell allowance.
        argv = shlex.split(command)
        if not argv or any(character in command for character in "\n\r;&|><`$"):
            return False
        if argv in runtime.tests:
            return True
        if argv == ["pwd"] or argv in (["git", "status", "--short"], ["git", "diff"]):
            return True
        if argv[0] == "cat" and len(argv) > 1:
            return all(
                not name.startswith("-") and safe_file(runtime.root, name).is_file()
                for name in argv[1:]
            )
    except (ValueError, OSError, ValidationError):
        return False
    return False


def verify_recovery(runtime: HookRuntime, session_id: str) -> dict[str, Any]:
    """Run declared argv tests, never a model-reported success or shell string."""
    session = runtime._session(session_id)
    if runtime.store.list_actions(session["run_id"], state=ActionState.CONTAINMENT_REQUIRED):
        return {
            "continue": False,
            "stopReason": "TARS cannot automatically resolve unknown "
            "external effects. Inspect containment records and explicitly acknowledge them.",
        }
    if not runtime.tests:
        return {
            "continue": False,
            "stopReason": "TARS cannot verify recovery: configure a test "
            "command with `tars-revoke codex setup --test 'COMMAND'` before using auto recovery.",
        }
    attempts = int(session["recovery_attempts"])
    if attempts >= 3:
        return {
            "continue": False,
            "stopReason": "TARS recovery stopped after three verification "
            "attempts. Inspect the failing tests and partial effects before continuing.",
        }
    if runtime.store.list_actions(session["run_id"], state=runtime.dispatching_state):
        return {
            "continue": False,
            "stopReason": "TARS has an unobserved call. It will not replay "
            "or infer its effects. Inspect `tars-revoke codex status`.",
        }
    baseline = runtime.fingerprints()
    if json.loads(session["recovery_json"] or "null") != baseline:
        return {
            "decision": "block",
            "reason": "TARS requirements changed again. Read the latest "
            "requirements and attempt a fresh local repair.",
        }
    with runtime.store.database.transaction() as connection:
        connection.execute(
            "UPDATE codex_sessions SET recovery_attempts=recovery_attempts+1 WHERE session_id=?",
            (session_id,),
        )
    passed: list[str] = []
    failures: list[dict[str, Any]] = []
    for argv in runtime.tests:
        call_id = new_id("recovery-test")
        call = {
            "session_id": session_id,
            "turn_id": session["turn_id"],
            "tool_use_id": call_id,
            "tool_name": "Bash",
            "tool_input": {"command": shlex.join(argv)},
        }
        admitted = runtime.pre(call)
        if admitted:
            raise AuthorizationError("test admission was denied")
        action_id = session["run_id"] + ":call:" + runtime.digest(call_id)[:32]
        started = runtime.store.clock.utc_now()
        result = asyncio.run(
            AsyncProcessRunner([runtime.root]).run(
                argv,
                cwd=runtime.root,
                timeout_seconds=120,
            )
        )
        runtime.post(
            {
                **call,
                "tool_response": {
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stdout_sha256": runtime.digest(result.stdout),
                    "stderr_sha256": runtime.digest(result.stderr),
                },
            }
        )
        test_id = new_id("verified-test")
        runtime.store.create_test_run(
            TestRun(
                id=test_id,
                run_id=session["run_id"],
                action_id=action_id,
                kind=TestKind.REGRESSION,
                argv=tuple(argv),
                state=TestState.PASSED if result.succeeded else TestState.FAILED,
                started_at=started,
                finished_at=runtime.store.clock.utc_now(),
                exit_code=result.exit_code,
                environment_digest=canonical_digest(result.environment),
                metadata={"producer": "tars-codex-recovery", "requirements": baseline},
            )
        )
        if result.succeeded:
            passed.append(test_id)
        else:
            failures.append(
                {
                    "argv": argv,
                    "exit_code": result.exit_code,
                    "output": (result.stderr + result.stdout)[-2400:],
                }
            )
    if failures:
        return {
            "decision": "block",
            "reason": "TARS independently ran recovery tests; they failed. "
            "Repair the local code, then stop again for verification. " + json.dumps(failures),
        }
    if runtime.fingerprints() != baseline:
        return {
            "decision": "block",
            "reason": "Requirements changed while tests ran. "
            "Their results cannot authorize this revision; inspect the latest requirements.",
        }
    runtime.accept(session_id, verified_test_ids=tuple(passed))
    return {
        "systemMessage": "TARS independently ran the configured tests successfully and "
        "accepted a fresh requirements baseline. This verifies those tests only; "
        "it does not prove external effects were reversed or a deployment is safe."
    }
