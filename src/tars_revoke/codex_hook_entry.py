"""Dependency-light hook entry point: always emit a supported denial on errors.

Also shipped verbatim inside the plugin so a missing backend remains visible.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any

MAX_INPUT = 2 * 1024 * 1024


def failure(event: str, message: str) -> dict[str, Any]:
    if event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    if event in {"SessionStart", "UserPromptSubmit"}:
        return {"continue": False, "stopReason": message, "systemMessage": message}
    return {"systemMessage": message}


def main() -> None:
    event = "PreToolUse"  # malformed input must never default to permission
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("hook input exceeds 2 MiB")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook input must be an object")
        event = payload.get("hook_event_name", "PreToolUse")
        try:
            from tars_revoke.codex_hook_cli import dispatch
        except ImportError:
            executable = shutil.which("tars-revoke")
            if executable is None:
                raise RuntimeError(
                    "install TARS REVOKE and reopen Codex; backend is unavailable"
                ) from None
            completed = subprocess.run(
                [executable, "codex", "hook"],
                input=raw,
                capture_output=True,
                timeout=8,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    "TARS backend failed; inspect `tars-revoke codex status`"
                ) from None
            result = json.loads(completed.stdout)
        else:
            result = dispatch(payload)
        if not isinstance(result, dict):
            raise ValueError("invalid backend response")
    except Exception:
        # Avoid echoing raw exceptions: they can include tool inputs or secrets.
        result = failure(
            event,
            "TARS protection could not complete its check. Tool admission is blocked; "
            "check the installation and run `tars-revoke codex status`.",
        )
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
