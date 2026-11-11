"""Run an isolated, metered real-Codex native recovery qualification.

This is separate from the historical R-01 through R-20 canonical release qualification.
The invocation-only hook-trust bypass is for these reviewed test definitions;
normal developer installation still requires Codex's hook review.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from tars_revoke import __version__
from tars_revoke.adapters._safety import CODEX_SUBPROCESS_ENV_KEYS, redact_text
from tars_revoke.codex_hook_cli import setup_hooks
from tars_revoke.codex_hooks import HookRuntime
from tars_revoke.domain.enums import PremiseState, TestState


def toml(value: Any) -> str:
    if isinstance(value, dict):
        return (
            "{" + ",".join(json.dumps(key) + "=" + toml(item) for key, item in value.items()) + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(map(toml, value)) + "]"
    return json.dumps(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--codex-bin", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace.expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit("qualification workspace must be nonexistent or empty")
    root.mkdir(parents=True, exist_ok=True)
    executable = args.codex_bin.expanduser().resolve(strict=True)
    (root / "SPEC.md").write_text("stripe\n")
    (root / "app.py").write_text('def provider():\n    return "stripe"\n')
    (root / "verify.py").write_text(
        "from pathlib import Path\nfrom app import provider\n"
        "assert provider() == Path('SPEC.md').read_text().strip()\n"
    )
    (root / "trigger.py").write_text(
        "from pathlib import Path\nPath('SPEC.md').write_text('paddle\\n')\n"
        "print('external provider requirement updated')\n"
    )
    setup_hooks(root, tests=[[sys.executable, "verify.py"]])
    hooks = json.loads((root / ".codex/hooks.json").read_text())["hooks"]
    prompt = (
        "This is an isolated local TARS integration test. First use exec_command to run "
        "exactly `python3 trigger.py` in the current directory. This intentionally simulates "
        "an external requirements change. Then make app.py implement the provider now "
        "required in SPEC.md using apply_patch. Do not change SPEC.md, trigger.py, verify.py, "
        ".codex, or .tars. During recovery use only simple cat commands and apply_patch, "
        "with no compound shell commands. Stop after repairing app.py so TARS can independently "
        "execute its configured test. No external services, commits, or pushes."
    )
    env = {key: value for key, value in os.environ.items() if key in CODEX_SUBPROCESS_ENV_KEYS}
    command = [
        str(executable),
        "exec",
        "--ignore-user-config",
        "--skip-git-repo-check",
        "--ephemeral",
        "--dangerously-bypass-hook-trust",
        "--sandbox",
        "workspace-write",
        "--cd",
        str(root),
        "--json",
        "--config",
        "features.hooks=true",
        "--config",
        "hooks=" + toml(hooks),
        prompt,
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=240,
        env=env,
        check=False,
    )
    (root / "codex.stdout.jsonl").write_text(redact_text(completed.stdout))
    (root / "codex.stderr.log").write_text(redact_text(completed.stderr))
    if completed.returncode:
        raise SystemExit("live Codex failed; inspect retained logs")
    runtime = HookRuntime(root)
    status = runtime.status()
    if len(status["sessions"]) != 1:
        raise SystemExit("expected exactly one native Codex session")
    session = status["sessions"][0]
    tests = runtime.store.list_test_runs(session["run_id"])
    premises = runtime.store.list_premises(session["run_id"])
    assert tests and all(test.state == TestState.PASSED for test in tests)
    assert any(premise.state == PremiseState.SUPERSEDED for premise in premises)
    assert not session["recovery_required"] and not session["unobserved_calls"]
    assert not session["containment_required"]
    assert '"paddle"' in (root / "app.py").read_text()
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=True, env=env
    ).stdout.strip()
    report = {
        "scope": "native-local-repair-only",
        "passed": True,
        "tars_version": __version__,
        "python_version": sys.version.split()[0],
        "codex_version": version,
        "session_id": session["session_id"],
        "observed_calls": session["observed_calls"],
        "independent_test_ids": [test.id for test in tests],
        "event_head": session["event_head"],
        "limitations": [
            "invocation-only reviewed-hook trust bypass in qualification",
            "simulated requirements update during real Codex execution",
            "does not qualify hosted enforcement or arbitrary rollback",
        ],
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
