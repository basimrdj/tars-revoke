"""Real Codex wire fixtures through the existing durable gateway."""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tars_revoke.cli import app
from tars_revoke.codex_hook_cli import dispatch, setup_hooks
from tars_revoke.codex_hooks import HookRuntime
from tars_revoke.domain.enums import ActionState, EffectState, LeaseState
from tars_revoke.errors import AuthorizationError, ValidationError


def event(kind: str, **overrides: Any) -> dict[str, Any]:
    return {
        "session_id": "session-a",
        "turn_id": "turn-1",
        "cwd": ".",
        "hook_event_name": kind,
        **overrides,
    }


@pytest.fixture
def runtime(tmp_path: Path) -> HookRuntime:
    (tmp_path / "SPEC.md").write_text("Use Stripe")
    runtime = HookRuntime.enable(tmp_path)
    runtime.handle(event("SessionStart"))
    runtime.handle(event("UserPromptSubmit", prompt="Implement checkout"))
    return runtime


def pre(call: str = "call-1", **overrides: Any) -> dict[str, Any]:
    return event(
        "PreToolUse",
        **{
            "tool_name": "Bash",
            "tool_use_id": call,
            "tool_input": {"command": "python -m pytest"},
            **overrides,
        },
    )


def post(call: str = "call-1", **overrides: Any) -> dict[str, Any]:
    return {
        **pre(call),
        "hook_event_name": "PostToolUse",
        "tool_response": "exit code 0",
        **overrides,
    }


def test_admission_uses_kernel_and_observation_never_claims_test_success(
    runtime: HookRuntime,
) -> None:
    assert runtime.handle(pre()) == {}
    run = runtime.status()["sessions"][0]["run_id"]
    assert len(runtime.store.list_warrants(run)) == 1
    assert runtime.store.list_actions(run)[0].state == ActionState.DISPATCHING
    assert runtime.store.list_effects(run)[0].state == EffectState.DISPATCHING
    assert runtime.store.list_leases(run)[0].state == LeaseState.CONSUMED
    assert runtime.handle(post()) == {}
    assert runtime.store.list_actions(run)[0].state == ActionState.EXECUTED
    assert runtime.store.list_test_runs(run) == []
    assert runtime.store.list_effects(run)[0].metadata["success_claim"] is False
    assert runtime.status()["sessions"][0]["observed_calls"] == 1
    runtime.store.journal.verify_chain(run)


def test_changed_requirements_block_and_stay_blocked_after_bytes_restored(
    runtime: HookRuntime,
) -> None:
    spec = runtime.root / "SPEC.md"
    spec.write_text("Use Paddle")
    output = runtime.handle(pre())
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    spec.write_text("Use Stripe")
    assert runtime.handle(pre())["hookSpecificOutput"]["permissionDecision"] == "deny"
    runtime.accept("session-a")
    assert runtime.handle(pre()) == {}


def test_missing_or_new_requirements_are_changes(runtime: HookRuntime) -> None:
    (runtime.root / "TARS.md").write_text("new constraints")
    assert runtime.handle(pre())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_deleted_requirements_block(runtime: HookRuntime) -> None:
    (runtime.root / "SPEC.md").unlink()
    assert runtime.handle(pre())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_repeated_preflight_cannot_replay_and_postflight_is_idempotent(
    runtime: HookRuntime,
) -> None:
    runtime.handle(pre())
    with pytest.raises(AuthorizationError, match="duplicate"):
        runtime.handle(pre())
    runtime.handle(post())
    runtime.handle(post())
    with pytest.raises(AuthorizationError, match="different response"):
        runtime.handle(post(tool_response="different"))
    assert runtime.status()["sessions"][0]["observed_calls"] == 1


def test_unobserved_calls_survive_restart_and_prevent_acceptance(runtime: HookRuntime) -> None:
    runtime.handle(pre())
    reopened = HookRuntime(runtime.root)
    reopened.start("session-a")
    assert len(reopened.status()["sessions"][0]["unobserved_calls"]) == 1
    with pytest.raises(AuthorizationError, match="unobserved"):
        reopened.accept("session-a")
    with pytest.raises(AuthorizationError, match="duplicate"):
        reopened.handle(pre())


def test_stale_turn_is_blocked_and_unrelated_session_still_runs(runtime: HookRuntime) -> None:
    runtime.start("session-b")
    runtime.prompt("session-b", "turn-b", "Improve logging")
    runtime.prompt("session-a", "turn-2", "Actually use Paddle")
    with pytest.raises(AuthorizationError, match="stale"):
        runtime.handle(pre())
    assert runtime.handle(pre(session_id="session-b", turn_id="turn-b")) == {}
    assert runtime.handle(pre("new", turn_id="turn-2")) == {}


def test_postflight_must_match_admitted_payload(runtime: HookRuntime) -> None:
    with pytest.raises(AuthorizationError, match="no corresponding"):
        runtime.handle(post())
    runtime.handle(pre())
    with pytest.raises(AuthorizationError, match="does not match"):
        runtime.handle(post(tool_input={"command": "git push"}))


def test_change_during_execution_is_disclosed_not_rolled_back(runtime: HookRuntime) -> None:
    runtime.handle(pre())
    (runtime.root / "SPEC.md").write_text("Use Paddle")
    output = runtime.handle(post())
    assert output["decision"] == "block"
    assert "may already exist" in output["reason"]


def test_concurrent_preflights_have_one_admission(runtime: HookRuntime) -> None:
    def attempt(_: int) -> bool:
        try:
            HookRuntime(runtime.root).handle(pre())
        except AuthorizationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(attempt, range(2))) == 1


def test_no_raw_prompts_commands_or_responses_in_state(runtime: HookRuntime) -> None:
    runtime.handle(pre(tool_input={"command": "echo private-company-information"}))
    runtime.handle(
        post(
            tool_input={"command": "echo private-company-information"},
            tool_response="private-response",
        )
    )
    with runtime.store.database.connection() as connection:
        dump = "\n".join(connection.iterdump())
    assert "private-company-information" not in dump
    assert "private-response" not in dump
    assert "Implement checkout" not in dump


@pytest.mark.parametrize("name", ["../outside", "/etc/hosts", "."])
def test_setup_rejects_escaping_or_directory_inputs(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValidationError):
        HookRuntime.enable(tmp_path, (name,))


def test_symlinked_inputs_fail_closed(runtime: HookRuntime) -> None:
    path = runtime.root / "SPEC.md"
    path.unlink()
    path.symlink_to("/etc/hosts")
    with pytest.raises(ValidationError):
        runtime.handle(pre())


def test_setup_preserves_hooks_and_reinstall_is_idempotent(tmp_path: Path) -> None:
    hooks = tmp_path / ".codex" / "hooks.json"
    hooks.parent.mkdir()
    original = {
        "description": "team hooks",
        "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "team-check"}]}]},
    }
    hooks.write_text(json.dumps(original))
    setup_hooks(tmp_path)
    setup_hooks(tmp_path)
    installed = json.loads(hooks.read_text())
    assert installed["description"] == "team hooks"
    assert installed["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]
    assert len(installed["hooks"]["PreToolUse"]) == 2
    assert json.loads(hooks.with_name("hooks.json.before-tars").read_text()) == original


def test_unconfigured_repository_is_not_globally_blocked(tmp_path: Path) -> None:
    assert dispatch(event("PreToolUse", cwd=str(tmp_path))) == {}


def test_cli_json_wire_and_status(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["codex", "setup", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app, ["codex", "hook"], input=json.dumps(event("SessionStart", cwd=str(tmp_path)))
    )
    assert result.exit_code == 0
    assert "permissionDecision" not in result.output
    status = runner.invoke(app, ["codex", "status", "--root", str(tmp_path)])
    assert json.loads(status.output)["mode"] == "cooperative-native-hooks"


def test_standalone_wrapper_denies_malformed_input_and_missing_backend() -> None:
    wrapper = Path(__file__).parents[2] / "src/tars_revoke/codex_hook_entry.py"
    result = subprocess.run(
        [sys.executable, str(wrapper)], input="[]", text=True, capture_output=True
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_plugin_bundle_and_backend_wrapper_match() -> None:
    root = Path(__file__).parents[2]
    assert (root / "plugins/tars-revoke/scripts/hook.py").read_bytes() == (
        root / "src/tars_revoke/codex_hook_entry.py"
    ).read_bytes()
    manifest = json.loads((root / "plugins/tars-revoke/plugin.json").read_text())
    assert manifest["extensions"]["com.openai"]["hooks"] == "./hooks/hooks.json"


def test_automatic_recovery_executes_real_tests_and_accepts_fresh_revision(tmp_path: Path) -> None:
    spec = tmp_path / "SPEC.md"
    spec.write_text("v1")
    test_file = tmp_path / "verify.py"
    test_file.write_text("from pathlib import Path\nassert Path('fixed').read_text() == 'v2'\n")
    runtime = HookRuntime.enable(tmp_path, tests=[[sys.executable, str(test_file)]])
    runtime.start("session-a")
    runtime.prompt("session-a", "turn-1", "Implement the specification")
    prior = runtime._premise("session-a", "turn-1")
    spec.write_text("v2")
    assert runtime.handle(pre())["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert runtime._premise("session-a", "turn-1").id != prior.id
    patch = {"command": "*** Begin Patch\n*** Add File: fixed\n+v2\n*** End Patch"}
    assert runtime.handle(pre("repair", tool_name="apply_patch", tool_input=patch)) == {}
    (tmp_path / "fixed").write_text("v2")
    runtime.handle(post("repair", tool_name="apply_patch", tool_input=patch))
    report = runtime.handle(event("Stop"))
    assert "successfully" in report["systemMessage"]
    assert runtime.status()["sessions"][0]["recovery_required"] is False
    run = runtime._session("session-a")["run_id"]
    tests = runtime.store.list_test_runs(run)
    assert len(tests) == 1 and tests[0].state.value == "PASSED"
    assert runtime.handle(pre("new-command")) == {}


def test_automatic_recovery_does_not_accept_failed_tests(tmp_path: Path) -> None:
    (tmp_path / "SPEC.md").write_text("v1")
    runtime = HookRuntime.enable(tmp_path, tests=[[sys.executable, "-c", "raise SystemExit(7)"]])
    runtime.start("session-a")
    runtime.prompt("session-a", "turn-1", "Implement specification")
    (tmp_path / "SPEC.md").write_text("v2")
    runtime.handle(pre())
    for _ in range(3):
        report = runtime.handle(event("Stop"))
        assert report["decision"] == "block"
        assert runtime.status()["sessions"][0]["recovery_required"] is True
    report = runtime.handle(event("Stop"))
    assert report["continue"] is False
    assert "three" in report["stopReason"]


def test_recovery_never_invents_a_test_command(runtime: HookRuntime) -> None:
    (runtime.root / "SPEC.md").write_text("v2")
    runtime.handle(pre())
    assert runtime.handle(event("Stop"))["continue"] is False


@pytest.mark.parametrize(
    "command",
    [
        "git push",
        "cat SPEC.md > out",
        "cat $(pwd)",
        "python3 -c 'print(1)'",
        "cat SPEC.md; git push",
    ],
)
def test_recovery_blocks_general_shell_and_publishing(runtime: HookRuntime, command: str) -> None:
    (runtime.root / "SPEC.md").write_text("v2")
    runtime.handle(pre())
    result = runtime.handle(pre("unsafe", tool_input={"command": command}))
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_recovery_blocks_patches_to_its_own_policy(runtime: HookRuntime) -> None:
    (runtime.root / "SPEC.md").write_text("v2")
    runtime.handle(pre())
    for path in (".tars/codex.json", "./.tars/codex.json", "SPEC.md", "../../outside"):
        patch = {
            "command": "*** Begin Patch\n*** Update File: " + path + "\n@@\n-x\n+y\n*** End Patch"
        }
        result = runtime.handle(pre(path, tool_name="apply_patch", tool_input=patch))
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_old_prompt_event_cannot_restore_old_turn(runtime: HookRuntime) -> None:
    runtime.prompt("session-a", "turn-2", "new requirement")
    with pytest.raises(AuthorizationError):
        runtime.prompt("session-a", "turn-1", "Implement checkout")
    assert runtime._session("session-a")["turn_id"] == "turn-2"


def test_missing_backend_returns_explicit_denial_without_site_packages() -> None:
    wrapper = Path(__file__).parents[2] / "src/tars_revoke/codex_hook_entry.py"
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(wrapper)],
        input=json.dumps(pre()),
        text=True,
        capture_output=True,
        env={"PATH": ""},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_containment_records_unknown_truth_and_requires_operator_acknowledgment(
    runtime: HookRuntime,
) -> None:
    runtime.handle(pre())
    result = runtime.contain("session-a")
    assert result["replayed"] is False
    assert len(result["contained_calls"]) == 1
    state = runtime.status()["sessions"][0]
    assert len(state["containment_required"]) == 1
    assert state["unobserved_calls"] == []
    with pytest.raises(AuthorizationError, match="acknowledgment"):
        runtime.accept("session-a")
    report = runtime.accept("session-a", acknowledge_partial_effects=True)
    assert report["tests_verified"] is False
    assert runtime.contain("session-a")["contained_calls"] == []


def test_model_claimed_test_success_cannot_authorize_recovery(runtime: HookRuntime) -> None:
    with pytest.raises(AuthorizationError, match="missing"):
        runtime.accept("session-a", verified_test_ids=("invented-test",))


def test_crash_between_effect_and_call_observation_cannot_substitute_response(
    runtime: HookRuntime,
) -> None:
    runtime.handle(pre())
    runtime.handle(post())
    with runtime.store.database.transaction() as connection:
        connection.execute("UPDATE codex_calls SET response_digest=NULL")
    with pytest.raises(AuthorizationError, match="different response"):
        runtime.handle(post(tool_response="invented response"))
    runtime.handle(post())


def test_disable_preserves_other_hooks_and_history_then_setup_reenables(tmp_path: Path) -> None:
    runner = CliRunner()
    setup_hooks(tmp_path)
    hook_file = tmp_path / ".codex/hooks.json"
    document = json.loads(hook_file.read_text())
    document["hooks"]["PreToolUse"].append(
        {"hooks": [{"type": "command", "command": "team-check"}]}
    )
    hook_file.write_text(json.dumps(document))
    result = runner.invoke(app, ["codex", "disable", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".tars/codex.sqlite").exists()
    assert len(json.loads(hook_file.read_text())["hooks"]["PreToolUse"]) == 1
    assert dispatch(event("PreToolUse", cwd=str(tmp_path))) == {}
    setup_hooks(tmp_path)
    assert json.loads((tmp_path / ".tars/codex.json").read_text())["enabled"] is True


def test_experiment_binds_identical_runtime_bytes_without_losing_child_environment(
    tmp_path: Path,
) -> None:
    from tars_revoke.demo.scenario import _resolve_experiment_argv
    from tars_revoke.demo.scripted_codex import ScriptedCodex
    from tars_revoke.domain.canonical import sha256_digest

    invocation = tmp_path / "venv/bin/python"
    invocation.parent.mkdir(parents=True)
    invocation.symlink_to(sys.executable)
    provider = ScriptedCodex(python_executable=invocation)
    # Child tests keep their invocation context; read-only observers use the
    # same runtime bytes directly, with no virtualenv imports required.
    assert provider.python_executable == invocation
    argv = _resolve_experiment_argv(("python", "-c", "print(1)"), python_executable=invocation)
    assert sha256_digest(Path(argv[0]).read_bytes()) == sha256_digest(
        Path(sys.executable).read_bytes()
    )


def test_experiment_rejects_unregistered_same_bytes_interpreter(tmp_path: Path) -> None:
    import shutil

    from tars_revoke.demo.experiment_sandbox import bound_experiment_python
    from tars_revoke.errors import IntegrityError

    foreign = tmp_path / "python"
    shutil.copy2(sys.executable, foreign)
    with pytest.raises(IntegrityError):
        bound_experiment_python(foreign)
    with pytest.raises(IntegrityError):
        bound_experiment_python(Path("python"))


def test_plugin_setup_configures_policy_without_duplicate_direct_hooks(tmp_path: Path) -> None:
    setup_hooks(tmp_path, plugin=True)
    assert not (tmp_path / ".codex/hooks.json").exists()
    assert (tmp_path / ".tars/codex.json").exists()
    setup_hooks(tmp_path)
    setup_hooks(tmp_path, plugin=True)
    hooks = json.loads((tmp_path / ".codex/hooks.json").read_text())
    assert all(not groups for groups in hooks["hooks"].values())
