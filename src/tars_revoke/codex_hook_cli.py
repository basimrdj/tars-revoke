"""Codex setup and hook transport. No user configuration is silently replaced."""

from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

import typer

from tars_revoke.adapters._safety import validate_argv
from tars_revoke.codex_hooks import DEFAULT_WATCH, EVENTS, HookRuntime, repo_root
from tars_revoke.errors import RevokeError, ValidationError

app = typer.Typer(
    help="Set up automatic local Codex checks (developer preview).", no_args_is_help=True
)


def dispatch(payload: Mapping[str, Any]) -> dict[str, Any]:
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise ValidationError("hook cwd is required")
    root = repo_root(Path(cwd))
    if not (root / ".tars" / "codex.json").exists():
        # Global plugin: repositories opt in individually, with no global pause.
        return {}
    runtime = HookRuntime(root)
    if json.loads(runtime.config_path.read_text()).get("enabled", True) is False:
        return {}
    return runtime.handle(payload)


def _atomic_json(path: Path, value: Any) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".tars-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def setup_hooks(
    root: Path,
    watch: tuple[str, ...] = DEFAULT_WATCH,
    tests: list[list[str]] | None = None,
    plugin: bool = False,
) -> dict[str, Any]:
    if tests is not None:
        if len(tests) > 1:
            raise ValidationError("configure one test-suite command")
        tests = [list(validate_argv(command)) for command in tests]
    root = root.expanduser().resolve(strict=True)
    hooks_dir = root / ".codex"
    target = hooks_dir / "hooks.json"
    if hooks_dir.is_symlink() or target.is_symlink():
        raise ValidationError("Codex hook configuration must not be a symlink")
    hooks_dir.mkdir(exist_ok=True)
    existing = json.loads(target.read_text()) if target.exists() else {}
    if not isinstance(existing, dict) or not isinstance(existing.get("hooks", {}), dict):
        raise ValidationError("existing hooks.json has an unsupported shape")
    hooks = existing.setdefault("hooks", {})
    command = shlex.join([sys.executable, str(Path(__file__).with_name("codex_hook_entry.py"))])
    for event in sorted(EVENTS):
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValidationError("existing hook groups must be lists")
        if any(
            not isinstance(group, dict) or not isinstance(group.get("hooks", []), list)
            for group in groups
        ):
            raise ValidationError("existing hook groups have an unsupported shape")
        # Replace only our owned group. Preserve arbitrary other hooks and metadata.
        groups[:] = [group for group in groups if group.get("description") != "TARS REVOKE v1"]
        if not plugin:
            groups.append(
                {
                    "description": "TARS REVOKE v1",
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "timeout": 150 if event == "Stop" else 10,
                            "statusMessage": "Checking TARS requirements",
                            **(
                                {"additionalContextLimit": 800}
                                if event in {"SessionStart", "UserPromptSubmit"}
                                else {}
                            ),
                        }
                    ],
                }
            )
    runtime = HookRuntime.enable(root, watch)
    config = json.loads(runtime.config_path.read_text())
    config["enabled"] = True
    if tests is not None:
        config["tests"] = tests
    _atomic_json(runtime.config_path, config)
    if target.exists():
        backup = hooks_dir / "hooks.json.before-tars"
        if not backup.exists():
            with backup.open("xb") as stream:
                stream.write(target.read_bytes())
    if target.exists() or not plugin:
        _atomic_json(target, existing)
    return {
        "installed": True,
        "hook_source": "plugin" if plugin else "repository",
        "mode": "cooperative-native-hooks",
        "root": str(root),
        "watch": watch,
        "next": "Restart or resume Codex, then review and trust TARS in /hooks. "
        "In the desktop app use Settings > Hooks. Protection is inactive until trusted.",
    }


def _print(value: Any) -> None:
    typer.echo(json.dumps(value, sort_keys=True))


@app.command()
def setup(
    root: Annotated[Path, typer.Option("--root")] = Path("."),
    watch: Annotated[list[str] | None, typer.Option("--watch")] = None,
    plugin: Annotated[
        bool, typer.Option("--plugin", help="Use installed plugin hooks; configure policy only.")
    ] = False,
    test: Annotated[
        str | None, typer.Option("--test", help="One argv test-suite command; no shell.")
    ] = None,
) -> None:
    """Enable TARS in a repository and merge hooks without replacing other hooks."""
    try:
        _print(
            setup_hooks(
                root,
                tuple(watch) if watch else DEFAULT_WATCH,
                tests=[shlex.split(test)] if test is not None else None,
                plugin=plugin,
            )
        )
    except (RevokeError, OSError, ValueError):
        typer.echo(
            "TARS setup failed. Check the watch paths and existing hook configuration.", err=True
        )
        raise typer.Exit(1) from None


@app.command()
def status(root: Annotated[Path, typer.Option("--root")] = Path(".")) -> None:
    """Show durable observations, unresolved calls, and requirements drift."""
    try:
        _print(HookRuntime(repo_root(root)).status())
    except (RevokeError, OSError, ValueError):
        typer.echo(
            "TARS state is unavailable or invalid; run codex setup for this repository.", err=True
        )
        raise typer.Exit(1) from None


@app.command()
def accept(
    session: Annotated[str, typer.Option("--session")],
    acknowledge_partial_effects: Annotated[
        bool, typer.Option("--acknowledge-partial-effects")
    ] = False,
    root: Annotated[Path, typer.Option("--root")] = Path("."),
) -> None:
    """Explicit operator acceptance of changed requirements; never claims repair."""
    try:
        _print(
            HookRuntime(repo_root(root)).accept(
                session, acknowledge_partial_effects=acknowledge_partial_effects
            )
        )
    except (RevokeError, OSError, ValueError) as exc:
        typer.echo(
            str(exc) if isinstance(exc, RevokeError) else "TARS acceptance failed.", err=True
        )
        raise typer.Exit(1) from None


@app.command(hidden=True)
def hook() -> None:
    """Run one lifecycle hook over JSON stdin/stdout."""
    from tars_revoke.codex_hook_entry import main

    main()


@app.command()
def contain(
    session: Annotated[str, typer.Option("--session")],
    root: Annotated[Path, typer.Option("--root")] = Path("."),
) -> None:
    """Record missing call completion as unknown; never retry or claim rollback."""
    try:
        _print(HookRuntime(repo_root(root)).contain(session))
    except (RevokeError, OSError, ValueError):
        typer.echo("TARS could not record containment; inspect the local state.", err=True)
        raise typer.Exit(1) from None


@app.command()
def disable(root: Annotated[Path, typer.Option("--root")] = Path(".")) -> None:
    """Disable local checks and remove only TARS-owned direct hook groups."""
    try:
        runtime = HookRuntime(repo_root(root))
        target = runtime.root / ".codex" / "hooks.json"
        if target.is_symlink() or target.parent.is_symlink():
            raise ValidationError("hook configuration must not be a symlink")
        if target.exists():
            document = json.loads(target.read_text())
            if not isinstance(document, dict) or not isinstance(document.get("hooks", {}), dict):
                raise ValidationError("unsupported hook document")
            for groups in document.get("hooks", {}).values():
                if not isinstance(groups, list) or any(
                    not isinstance(group, dict) for group in groups
                ):
                    raise ValidationError("unsupported hook group shape")
                groups[:] = [
                    group for group in groups if group.get("description") != "TARS REVOKE v1"
                ]
            _atomic_json(target, document)
        config = json.loads(runtime.config_path.read_text())
        config["enabled"] = False
        _atomic_json(runtime.config_path, config)
        _print({"disabled": True, "history_preserved": True})
    except (RevokeError, OSError, ValueError):
        typer.echo("TARS could not disable its hooks; inspect the hook configuration.", err=True)
        raise typer.Exit(1) from None
