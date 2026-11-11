"""Install a built wheel into a fresh environment and exercise native recovery.

Usage: python tools/smoke_codex_wheel.py /absolute/path/to/package.whl
Requires uv. Does not invoke Codex or any metered model.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def main() -> None:
    wheel = Path(sys.argv[1]).resolve(strict=True)
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required for the isolated wheel smoke test")
    with tempfile.TemporaryDirectory(prefix="tars-wheel-") as temporary:
        root = Path(temporary)
        environment = root / "env"
        project = root / "project"
        project.mkdir()
        subprocess.run([uv, "venv", "--python", sys.executable, str(environment)], check=True)
        python = environment / "bin/python"
        cli = environment / "bin/tars-revoke"
        subprocess.run([uv, "pip", "install", "--python", str(python), str(wheel)], check=True)
        (project / "SPEC.md").write_text("v1")
        (project / "verify.py").write_text(
            "from pathlib import Path\nassert Path('implementation').read_text() == "
            "Path('SPEC.md').read_text()\n"
        )
        child_env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH", "PYTHONHOME"}
        }
        subprocess.run(
            [str(cli), "codex", "setup", "--root", str(project), "--test", f"{python} verify.py"],
            check=True,
            cwd=project,
            env=child_env,
        )

        def hook(kind: str, **extra: Any) -> dict[str, Any]:
            payload = {
                "hook_event_name": kind,
                "session_id": "wheel-smoke",
                "turn_id": "turn-1",
                "cwd": str(project),
                **extra,
            }
            result = subprocess.run(
                [str(cli), "codex", "hook"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                check=True,
                cwd=project,
                env=child_env,
            )
            return json.loads(result.stdout)

        hook("SessionStart")
        hook("UserPromptSubmit", prompt="Implement the current specification")
        (project / "SPEC.md").write_text("v2")
        blocked = hook(
            "PreToolUse", tool_use_id="stale", tool_name="Bash", tool_input={"command": "git push"}
        )
        assert blocked["hookSpecificOutput"]["permissionDecision"] == "deny"
        patch = {"command": "*** Begin Patch\n*** Add File: implementation\n+v2\n*** End Patch"}
        assert (
            hook("PreToolUse", tool_use_id="repair", tool_name="apply_patch", tool_input=patch)
            == {}
        )
        (project / "implementation").write_text("v2")
        hook(
            "PostToolUse",
            tool_use_id="repair",
            tool_name="apply_patch",
            tool_input=patch,
            tool_response="patch applied",
        )
        verified = hook("Stop")
        assert "successfully" in verified["systemMessage"], verified
        status = subprocess.run(
            [str(cli), "codex", "status", "--root", str(project)],
            capture_output=True,
            text=True,
            check=True,
            cwd=project,
            env=child_env,
        )
        assert json.loads(status.stdout)["sessions"][0]["recovery_required"] is False
        subprocess.run(
            [
                str(python),
                "-c",
                "from importlib.resources import files; "
                "assert files('tars_revoke').joinpath('codex_plugin/plugin.json').is_file()",
            ],
            check=True,
            cwd=project,
            env=child_env,
        )
        print(
            json.dumps(
                {
                    "wheel": wheel.name,
                    "isolated_install": "passed",
                    "requirements_block": "passed",
                    "independent_recovery_test": "passed",
                    "plugin_assets": "passed",
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
