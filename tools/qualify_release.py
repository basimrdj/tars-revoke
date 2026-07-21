#!/usr/bin/env python3
"""Create a clean-clone, three-run live qualification journal.

This script intentionally uses only the Python standard library so it can run
before TARS REVOKE has been installed.  It clones one exact source commit into
an empty directory, executes the release gates, and then records exactly three
sequential live-Codex demo attempts.  Every command stream and discovered proof
bundle is content-addressed in a self-contained journal directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

SETUP_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("setup", ("make", "setup")),
    ("doctor", ("make", "doctor")),
    ("python-tests", ("make", "test-python-offline")),
    ("web-tests", ("make", "test-web")),
    ("build", ("make", "build")),
    ("release-check", ("make", "release-check")),
)

_INHERITED_ENVIRONMENT_KEYS = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
)
_LIVE_ONLY_ENVIRONMENT_KEYS = (
    "CODEX_API_KEY",
    "CODEX_HOME",
    "HOME",
    "OPENAI_API_KEY",
    "OPENAI_ORGANIZATION",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT",
    "OPENAI_PROJECT_ID",
)
_FIXED_ENVIRONMENT = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_CACHE_DIR": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUNBUFFERED": "1",
    "UV_NO_CACHE": "1",
}
_SECRET_OUTPUT_PATTERNS = (
    re.compile(rb"\b(?:sk|rk|ghp|github_pat|xox[baprs])-[A-Za-z0-9_-]{12,}\b"),
    re.compile(rb"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
        rb"-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)
_FORBIDDEN_ENVIRONMENT_KEYS = (
    "CONDA_PREFIX",
    "OPENAI_BASE_URL",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "TARS_CODEX_MODEL",
    "TARS_RUN_LIVE_CODEX",
    "VIRTUAL_ENV",
)
_CODEX_BUNDLE_IDENTIFIER = "com.openai.codex"
_CODEX_TEAM_IDENTIFIER = "2DC432GLL2"
_CODEX_BUNDLE_NAMES = {"ChatGPT.app", "Codex.app"}
_PINNED_CODEX_RELEASES = {
    "codex-cli 0.145.0-alpha.27": (
        "463957f969f1399d4993830722fdd3970a33500d0fbf2f57b917082363f022a9"
    ),
    "codex-cli 0.145.0-alpha.18": (
        "a2bc3f63b0d7ce5c065ae070e16d964fa71192bf6ceb8da82d2315227d55a6bf"
    ),
    "codex-cli 0.144.5": "bdcb530615d44fcc7b35d12fe00f30c3025c25fc22a21193591dcdb064304385",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(payload)


def _utc_after(previous: datetime | None = None) -> datetime:
    now = datetime.now(timezone.utc)
    if previous is not None and now <= previous:
        return previous + timedelta(microseconds=1)
    return now


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _run_git(repository: Path, *args: str) -> bytes:
    git_environment = {
        key: os.environ[key]
        for key in ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "TMPDIR", "TZ")
        if key in os.environ
    }
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        timeout=60,
        env=git_environment,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _source_manifest(repository: Path, source_commit: str) -> dict[str, Any]:
    raw_tree = _run_git(repository, "ls-tree", "-r", "-z", "--full-tree", source_commit)
    files: list[dict[str, Any]] = []
    for raw_entry in raw_tree.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            _mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("Git returned a malformed source-tree entry") from exc
        if object_type != "blob":
            raise RuntimeError(f"unsupported non-blob tracked entry: {path}")
        content = _run_git(repository, "cat-file", "blob", object_id)
        files.append({"path": path, "sha256": _sha256(content), "size": len(content)})
    files.sort(key=lambda item: str(item["path"]))
    if not files:
        raise RuntimeError("the qualified source commit has no tracked files")
    return {
        "protocol": "tars.source-tree/v1",
        "source_commit": source_commit,
        "files": files,
    }


def _write_bytes(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return _sha256(content)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _persist_journal(path: Path, journal: dict[str, Any]) -> None:
    unsigned = dict(journal)
    unsigned.pop("integrity", None)
    journal["integrity"] = {"canonical_digest": _canonical_digest(unsigned)}
    _write_json(path, journal)


def _execute(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    timeout_seconds: int,
    environment: dict[str, str],
) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=environment,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        suffix = f"\nqualification command timed out after {timeout_seconds}s\n".encode()
        return 124, stdout, stderr + suffix


def _stream_record(
    journal_root: Path,
    *,
    stem: str,
    stdout: bytes,
    stderr: bytes,
    forbidden_values: tuple[bytes, ...] = (),
) -> dict[str, str]:
    _assert_secret_free(stdout, label=f"{stem} stdout", forbidden_values=forbidden_values)
    _assert_secret_free(stderr, label=f"{stem} stderr", forbidden_values=forbidden_values)
    stdout_relative = Path("logs") / f"{stem}.stdout.log"
    stderr_relative = Path("logs") / f"{stem}.stderr.log"
    stdout_digest = _write_bytes(journal_root / stdout_relative, stdout)
    stderr_digest = _write_bytes(journal_root / stderr_relative, stderr)
    return {
        "stdout_path": stdout_relative.as_posix(),
        "stdout_sha256": stdout_digest,
        "stderr_path": stderr_relative.as_posix(),
        "stderr_sha256": stderr_digest,
    }


def _assert_secret_free(
    payload: bytes,
    *,
    label: str,
    forbidden_values: tuple[bytes, ...] = (),
) -> None:
    for secret in forbidden_values:
        if len(secret) >= 8 and secret in payload:
            raise RuntimeError(f"secret material appeared in {label}")
    if any(pattern.search(payload) is not None for pattern in _SECRET_OUTPUT_PATTERNS):
        raise RuntimeError(f"secret-looking material appeared in {label}")


def _git_snapshot_record(
    journal_root: Path,
    workspace: Path,
    *,
    stem: str,
    phase: str,
) -> tuple[dict[str, str], bytes, str]:
    status = _run_git(workspace, "status", "--porcelain")
    raw_head = _run_git(workspace, "rev-parse", "HEAD")
    try:
        head = raw_head.decode("ascii", errors="strict").strip()
    except UnicodeError as exc:
        raise RuntimeError("Git returned a non-ASCII HEAD object ID") from exc
    status_relative = Path("evidence") / "git-status" / f"{stem}.{phase}.txt"
    head_relative = Path("evidence") / "git-head" / f"{stem}.{phase}.txt"
    status_digest = _write_bytes(journal_root / status_relative, status)
    head_digest = _write_bytes(journal_root / head_relative, raw_head)
    return (
        {
            f"{phase}_git_status_path": status_relative.as_posix(),
            f"{phase}_git_status_sha256": status_digest,
            f"{phase}_git_head_path": head_relative.as_posix(),
            f"{phase}_git_head_sha256": head_digest,
        },
        status,
        head,
    )


def _executable_snapshot_record(
    journal_root: Path,
    executable: Path,
    *,
    stem: str,
    phase: str,
) -> tuple[dict[str, str], str]:
    if executable.is_symlink() or not executable.is_file():
        raise RuntimeError("qualified tars-revoke entry point is missing or unsafe")
    payload = executable.read_bytes()
    relative = Path("evidence") / "executables" / "invocations" / f"{stem}.{phase}.bin"
    digest = _write_bytes(journal_root / relative, payload)
    return (
        {
            f"{phase}_tars_revoke_path": relative.as_posix(),
            f"{phase}_tars_revoke_sha256": digest,
        },
        digest,
    )


def _qualification_environment(*, gate_home: Path | None = None) -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in _INHERITED_ENVIRONMENT_KEYS if key in os.environ
    }
    environment.update(_FIXED_ENVIRONMENT)
    environment["HOME"] = str((gate_home or Path("/var/empty")).resolve())
    return environment


def _live_environment(base_environment: dict[str, str]) -> dict[str, str]:
    environment = dict(base_environment)
    for key in _LIVE_ONLY_ENVIRONMENT_KEYS:
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def _environment_policy(
    environment: dict[str, str],
    live_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    live = live_environment or _live_environment(environment)
    inherited = sorted(key for key in _INHERITED_ENVIRONMENT_KEYS if key in environment)
    live_present = sorted(key for key in _LIVE_ONLY_ENVIRONMENT_KEYS if key in live)
    auth_keys = sorted(
        key
        for key in ("CODEX_API_KEY", "OPENAI_API_KEY")
        if live.get(key)
    )
    return {
        "protocol": "tars.qualification-environment/v3",
        "inherited_allowlist": list(_INHERITED_ENVIRONMENT_KEYS),
        "present_inherited_keys": inherited,
        "live_only_allowlist": list(_LIVE_ONLY_ENVIRONMENT_KEYS),
        "live_present_keys": live_present,
        "fixed_values": dict(_FIXED_ENVIRONMENT),
        "gate_injected_keys": ["HOME"],
        "runtime_injected_keys": ["TARS_CODEX_BIN"],
        "forbidden_keys": list(_FORBIDDEN_ENVIRONMENT_KEYS),
        "auth_key_names_present": auth_keys,
        "non_live_auth_keys_present": sorted(
            key for key in ("CODEX_API_KEY", "OPENAI_API_KEY") if environment.get(key)
        ),
        "live_auth_sources": sorted(
            [
                *auth_keys,
                *(key for key in ("CODEX_HOME",) if live.get(key)),
            ]
        ),
        "gate_home_sha256": _sha256(environment["HOME"].encode("utf-8")),
        "path_sha256": _sha256(environment.get("PATH", "").encode("utf-8")),
    }


_PYTHON_RUNTIME_PROBE = r"""
import hashlib
import importlib.metadata
import json
import pathlib
import site
import sys
import sysconfig

import tars_revoke
import tars_revoke.cli


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


workspace = pathlib.Path(sys.argv[1]).resolve(strict=True)
source_root = (workspace / "src").resolve(strict=True)
modules = []
for name, module in sorted(sys.modules.items()):
    raw = getattr(module, "__file__", None)
    if not isinstance(raw, str):
        continue
    candidate = pathlib.Path(raw)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        continue
    if resolved.suffix in {".pyc", ".pyo"}:
        source_candidate = resolved.with_suffix(".py")
        if source_candidate.is_file():
            resolved = source_candidate.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        continue
    source_relative = None
    try:
        source_relative = resolved.relative_to(workspace).as_posix()
    except ValueError:
        pass
    modules.append({
        "name": name,
        "path": str(resolved),
        "source_relative": source_relative,
        "sha256": digest(resolved),
        "size": resolved.stat().st_size,
    })

distributions = []
for distribution in sorted(
    importlib.metadata.distributions(),
    key=lambda item: (str(item.metadata.get("Name", "")).lower(), item.version),
):
    name = str(distribution.metadata.get("Name", ""))
    if not name:
        continue
    record_path = None
    direct_url = distribution.read_text("direct_url.json")
    for item in distribution.files or ():
        if pathlib.PurePosixPath(str(item)).name == "RECORD":
            candidate = pathlib.Path(distribution.locate_file(item)).resolve(strict=True)
            if candidate.is_file() and not candidate.is_symlink():
                record_path = candidate
                break
    distributions.append({
        "name": name,
        "version": distribution.version,
        "record_path": str(record_path) if record_path is not None else None,
        "record_sha256": digest(record_path) if record_path is not None else None,
        "direct_url": direct_url,
    })

package_file = pathlib.Path(tars_revoke.__file__).resolve(strict=True)
distribution = importlib.metadata.distribution("tars-revoke")
entry_points = sorted(
    [
        {"group": item.group, "name": item.name, "value": item.value}
        for item in distribution.entry_points
    ],
    key=lambda item: (item["group"], item["name"], item["value"]),
)
print(json.dumps({
    "protocol": "tars.python-runtime/v1",
    "sys_executable": sys.executable,
    "sys_prefix": sys.prefix,
    "sys_base_prefix": sys.base_prefix,
    "python_version": sys.version,
    "site_packages": site.getsitepackages(),
    "stdlib_path": sysconfig.get_path("stdlib"),
    "sys_path": sys.path,
    "package_file": str(package_file),
    "package_file_sha256": digest(package_file),
    "distribution_name": str(distribution.metadata["Name"]),
    "distribution_version": distribution.version,
    "distribution_direct_url": distribution.read_text("direct_url.json"),
    "distribution_entry_points": entry_points,
    "loaded_modules": modules,
    "distributions": distributions,
}, sort_keys=True, separators=(",", ":")))
"""


def _runtime_inventory(root_specs: list[dict[str, Any]]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    normalized_roots: list[dict[str, Any]] = []
    for spec in sorted(root_specs, key=lambda item: str(item["path"])):
        path = Path(str(spec["path"])).expanduser().resolve(strict=True)
        kind = str(spec["kind"])
        excludes = tuple(sorted(str(item) for item in spec.get("exclude_parts", [])))
        normalized_roots.append(
            {"path": str(path), "kind": kind, "exclude_parts": list(excludes)}
        )
        candidates: list[Path] = []
        if kind == "file":
            candidates = [path]
        elif kind == "tree":
            for directory, directory_names, file_names in os.walk(path, followlinks=False):
                current = Path(directory)
                candidates.extend(
                    current / name
                    for name in sorted(directory_names)
                    if name not in excludes and (current / name).is_symlink()
                )
                directory_names[:] = sorted(
                    name
                    for name in directory_names
                    if name not in excludes and not (current / name).is_symlink()
                )
                for name in sorted(file_names):
                    candidate = current / name
                    relative_parts = candidate.relative_to(path).parts
                    if not set(relative_parts) & set(excludes):
                        candidates.append(candidate)
        else:
            raise RuntimeError("Python runtime inventory root has an invalid kind")
        for candidate in candidates:
            metadata = candidate.lstat()
            entry: dict[str, Any] = {
                "root": str(path),
                "path": str(candidate),
                "mode": stat.S_IMODE(metadata.st_mode),
            }
            if stat.S_ISLNK(metadata.st_mode):
                entry.update({"kind": "symlink", "target": os.readlink(candidate)})
            elif stat.S_ISREG(metadata.st_mode):
                payload = candidate.read_bytes()
                entry.update(
                    {
                        "kind": "file",
                        "sha256": _sha256(payload),
                        "size": len(payload),
                    }
                )
            else:
                raise RuntimeError("Python runtime inventory contains an unsafe entry")
            entries.append(entry)
    entries.sort(key=lambda item: (str(item["root"]), str(item["path"])))
    payload: dict[str, Any] = {
        "protocol": "tars.python-runtime-inventory/v1",
        "roots": normalized_roots,
        "entries": entries,
    }
    payload["canonical_digest"] = _canonical_digest(payload)
    return payload


def _python_runtime_snapshot_record(
    journal_root: Path,
    *,
    runtime_inventory_path: Path,
    stem: str,
    phase: str,
) -> tuple[dict[str, str], str]:
    try:
        baseline = json.loads(runtime_inventory_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Python runtime inventory is unreadable") from exc
    if not isinstance(baseline, dict) or not isinstance(baseline.get("roots"), list):
        raise RuntimeError("Python runtime inventory is malformed")
    current = _runtime_inventory(list(baseline["roots"]))
    digest = str(current["canonical_digest"])
    baseline_digest = str(baseline.get("canonical_digest", ""))
    snapshot = {
        "protocol": "tars.python-runtime-snapshot/v1",
        "phase": phase,
        "baseline_digest": baseline_digest,
        "observed_digest": digest,
        "matches_baseline": current == baseline,
    }
    relative = Path("evidence") / "python" / "snapshots" / f"{stem}.{phase}.json"
    _write_json(journal_root / relative, snapshot)
    return (
        {
            f"{phase}_python_runtime_path": relative.as_posix(),
            f"{phase}_python_runtime_sha256": _sha256(
                (journal_root / relative).read_bytes()
            ),
            f"{phase}_python_runtime_digest": digest,
        },
        digest,
    )


def _python_runtime_record(
    journal_root: Path,
    *,
    workspace: Path,
    installed_entrypoint: Path,
    environment: dict[str, str],
) -> dict[str, str]:
    entrypoint_bytes = installed_entrypoint.read_bytes()
    if not entrypoint_bytes:
        raise RuntimeError("qualified tars-revoke entry point is empty")
    launcher = workspace / ".venv" / "bin" / "python"
    expected_bin = (workspace / ".venv" / "bin").resolve(strict=True)
    if not launcher.is_file() or launcher.parent.resolve(strict=True) != expected_bin:
        raise RuntimeError("qualified Python launcher escaped the fresh-clone virtualenv")
    resolved_python = launcher.resolve(strict=True)
    if not resolved_python.is_file() or resolved_python.is_symlink():
        raise RuntimeError("qualified Python runtime is missing or unsafe")
    exit_code, stdout, stderr = _execute(
        (str(launcher), "-I", "-B", "-c", _PYTHON_RUNTIME_PROBE, str(workspace)),
        cwd=workspace,
        timeout_seconds=120,
        environment=environment,
    )
    if exit_code != 0:
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Python runtime provenance probe failed: {detail}")
    try:
        payload = json.loads(stdout)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Python runtime provenance probe returned malformed JSON") from exc
    expected_package = (workspace / "src" / "tars_revoke" / "__init__.py").resolve(strict=True)
    direct_url = payload.get("distribution_direct_url")
    try:
        direct_url_payload = json.loads(direct_url) if isinstance(direct_url, str) else None
    except json.JSONDecodeError as exc:
        raise RuntimeError("installed tars-revoke direct_url.json is malformed") from exc
    entry_points = payload.get("distribution_entry_points")
    sys_prefix = (workspace / ".venv").resolve(strict=True)
    base_prefix = Path(str(payload.get("sys_base_prefix", ""))).resolve(strict=True)
    stdlib_path = Path(str(payload.get("stdlib_path", ""))).resolve(strict=True)
    site_packages = payload.get("site_packages")
    if (
        Path(str(payload.get("sys_executable", ""))).resolve(strict=True) != resolved_python
        or Path(str(payload.get("sys_prefix", ""))).resolve(strict=True)
        != sys_prefix
        or not stdlib_path.is_dir()
        or base_prefix not in stdlib_path.parents
        or Path(str(payload.get("package_file", ""))).resolve(strict=True) != expected_package
        or payload.get("distribution_name") != "tars-revoke"
        or entry_points
        != [
            {
                "group": "console_scripts",
                "name": "tars-revoke",
                "value": "tars_revoke.cli:app",
            }
        ]
        or not isinstance(site_packages, list)
        or not site_packages
        or any(
            not isinstance(path, str)
            or sys_prefix not in Path(path).resolve(strict=True).parents
            for path in site_packages
        )
        or not isinstance(direct_url_payload, dict)
        or direct_url_payload.get("url") != workspace.as_uri()
        or direct_url_payload.get("dir_info") != {"editable": True}
    ):
        raise RuntimeError("installed Python package provenance differs from the fresh clone")
    payload["entrypoint_path"] = str(installed_entrypoint)
    payload["entrypoint_sha256"] = _sha256(entrypoint_bytes)
    payload["entrypoint_format"] = (
        "direct-shebang" if entrypoint_bytes.startswith(b"#!") else "pip-trampoline"
    )
    payload["python_invocation_path"] = str(launcher)
    payload["resolved_executable"] = str(resolved_python)
    payload["resolved_executable_sha256"] = _sha256(resolved_python.read_bytes())
    runtime_roots = [
        {"path": str(sys_prefix), "kind": "tree", "exclude_parts": []},
        {
            "path": str(stdlib_path),
            "kind": "tree",
            "exclude_parts": ["__pycache__", "site-packages"],
        },
        {"path": str(resolved_python), "kind": "file", "exclude_parts": []},
    ]
    libpython_candidates = sorted((base_prefix / "lib").glob("libpython*.dylib"))
    if len(libpython_candidates) != 1:
        raise RuntimeError("qualified Python runtime has no unique libpython dylib")
    runtime_roots.append(
        {
            "path": str(libpython_candidates[0].resolve(strict=True)),
            "kind": "file",
            "exclude_parts": [],
        }
    )
    inventory = _runtime_inventory(runtime_roots)
    inventory_relative = Path("evidence") / "python" / "runtime-inventory.json"
    _write_json(journal_root / inventory_relative, inventory)
    payload["runtime_inventory_path"] = inventory_relative.as_posix()
    payload["runtime_inventory_digest"] = inventory["canonical_digest"]
    runtime_relative = Path("evidence") / "python" / "runtime.json"
    _write_json(journal_root / runtime_relative, payload)
    executable_relative = Path("evidence") / "executables" / "python-runtime"
    executable_evidence = journal_root / executable_relative
    executable_evidence.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resolved_python, executable_evidence)
    executable_evidence.chmod(0o555)
    return {
        "python_runtime_path": runtime_relative.as_posix(),
        "python_runtime_sha256": _sha256((journal_root / runtime_relative).read_bytes()),
        "python_executable_evidence_path": executable_relative.as_posix(),
        "python_executable_sha256": _sha256(executable_evidence.read_bytes()),
        "python_invocation_path": str(launcher),
        "python_resolved_path": str(resolved_python),
        "python_runtime_inventory_path": inventory_relative.as_posix(),
        "python_runtime_inventory_sha256": _sha256(
            (journal_root / inventory_relative).read_bytes()
        ),
        "python_runtime_inventory_digest": str(inventory["canonical_digest"]),
    }


def _discover_official_codex() -> Path:
    configured = os.environ.get("TARS_CODEX_BIN", "").strip()
    candidates: tuple[Path, ...] = (
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path("/Applications/Codex.app/Contents/Resources/codex"),
        Path.home() / "Applications/ChatGPT.app/Contents/Resources/codex",
        Path.home() / "Applications/Codex.app/Contents/Resources/codex",
    )
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            raise RuntimeError("TARS_CODEX_BIN must be an absolute path")
        candidates = (configured_path, *candidates)
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve(strict=True)
    raise RuntimeError("an official OpenAI desktop Codex executable is required for qualification")


def _codex_signing_record(
    journal_root: Path,
    executable: Path,
    *,
    cwd: Path,
    environment: dict[str, str],
    forbidden_values: tuple[bytes, ...] = (),
) -> dict[str, Any]:
    try:
        bundle = executable.resolve(strict=True).parents[2]
    except (IndexError, OSError) as exc:
        raise RuntimeError("official Codex executable is not inside an app bundle") from exc
    if bundle.name not in _CODEX_BUNDLE_NAMES or bundle.suffix != ".app":
        raise RuntimeError("official Codex executable is not inside an OpenAI desktop app")
    codesign = Path("/usr/bin/codesign")
    if not codesign.is_file():
        raise RuntimeError("macOS codesign is required for Codex identity verification")
    verify_argv = (
        str(codesign),
        "--verify",
        "--deep",
        "--strict",
        "--verbose=2",
        str(bundle),
    )
    display_argv = (str(codesign), "-d", "--verbose=4", str(bundle))
    verify_exit, verify_stdout, verify_stderr = _execute(
        verify_argv,
        cwd=cwd,
        timeout_seconds=120,
        environment=environment,
    )
    display_exit, display_stdout, display_stderr = _execute(
        display_argv,
        cwd=cwd,
        timeout_seconds=120,
        environment=environment,
    )
    verify_streams = _stream_record(
        journal_root,
        stem="codex-codesign-verify",
        stdout=verify_stdout,
        stderr=verify_stderr,
        forbidden_values=forbidden_values,
    )
    display_streams = _stream_record(
        journal_root,
        stem="codex-codesign-display",
        stdout=display_stdout,
        stderr=display_stderr,
        forbidden_values=forbidden_values,
    )
    display_text = (display_stdout + b"\n" + display_stderr).decode(
        "utf-8", errors="replace"
    )
    identifier = re.search(r"(?m)^Identifier=([^\r\n]+)$", display_text)
    team = re.search(r"(?m)^TeamIdentifier=([^\r\n]+)$", display_text)
    if display_exit != 0:
        raise RuntimeError("OpenAI desktop app did not expose signed identity metadata")
    if identifier is None or identifier.group(1) != _CODEX_BUNDLE_IDENTIFIER:
        raise RuntimeError("OpenAI desktop app has an unexpected signed bundle identifier")
    if team is None or team.group(1) != _CODEX_TEAM_IDENTIFIER:
        raise RuntimeError("OpenAI desktop app is not signed by the expected OpenAI team")
    return {
        "protocol": "tars.codex-codesign/v1",
        "bundle_path": str(bundle),
        "bundle_identifier": identifier.group(1),
        "team_identifier": team.group(1),
        "verify_argv": list(verify_argv),
        "verify_exit_code": verify_exit,
        "strict_verification_passed": verify_exit == 0,
        "verify_stdout_path": verify_streams["stdout_path"],
        "verify_stdout_sha256": verify_streams["stdout_sha256"],
        "verify_stderr_path": verify_streams["stderr_path"],
        "verify_stderr_sha256": verify_streams["stderr_sha256"],
        "display_argv": list(display_argv),
        "display_exit_code": display_exit,
        "display_stdout_path": display_streams["stdout_path"],
        "display_stdout_sha256": display_streams["stdout_sha256"],
        "display_stderr_path": display_streams["stderr_path"],
        "display_stderr_sha256": display_streams["stderr_sha256"],
    }


def _fail(
    journal_path: Path,
    journal: dict[str, Any],
    *,
    phase: str,
    message: str,
) -> NoReturn:
    journal["result"] = "failed"
    journal["failure"] = {"phase": phase, "message": message}
    _persist_journal(journal_path, journal)
    raise RuntimeError(message)


def _assert_empty_destination(destination: Path) -> None:
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise RuntimeError("qualification workspace must be a real directory")
        if any(destination.iterdir()):
            raise RuntimeError("qualification workspace must not exist or must be empty")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)


def _single_report(output_root: Path, *, suite: str) -> Path:
    reports = sorted(output_root.glob("*/report.json"))
    if len(reports) != 1 or reports[0].is_symlink() or not reports[0].is_file():
        raise RuntimeError(f"{suite} did not produce exactly one regular report.json")
    return reports[0]


def _output_record(path: Path, *, label: str) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} did not produce a regular output file")
    return {"path": str(path), "sha256": _sha256(path.read_bytes())}


def _workflow_step(
    workflow_root: Path,
    workspace: Path,
    *,
    name: str,
    argv: tuple[str, ...],
    timeout_seconds: int,
    source_commit: str,
    qualified_executable: Path,
    qualified_executable_sha256: str,
    python_runtime_inventory_path: Path,
    python_runtime_inventory_digest: str,
    environment: dict[str, str],
    forbidden_values: tuple[bytes, ...] = (),
) -> dict[str, Any]:
    pre_status, pre_bytes, pre_head = _git_snapshot_record(
        workflow_root,
        workspace,
        stem=name,
        phase="pre",
    )
    pre_executable, pre_executable_digest = _executable_snapshot_record(
        workflow_root,
        qualified_executable,
        stem=name,
        phase="pre",
    )
    pre_python, pre_python_digest = _python_runtime_snapshot_record(
        workflow_root,
        runtime_inventory_path=python_runtime_inventory_path,
        stem=name,
        phase="pre",
    )
    started = _utc_after()
    exit_code, stdout, stderr = _execute(
        argv,
        cwd=workspace,
        timeout_seconds=timeout_seconds,
        environment=environment,
    )
    finished = _utc_after(started)
    post_status, post_bytes, post_head = _git_snapshot_record(
        workflow_root,
        workspace,
        stem=name,
        phase="post",
    )
    post_executable, post_executable_digest = _executable_snapshot_record(
        workflow_root,
        qualified_executable,
        stem=name,
        phase="post",
    )
    post_python, post_python_digest = _python_runtime_snapshot_record(
        workflow_root,
        runtime_inventory_path=python_runtime_inventory_path,
        stem=name,
        phase="post",
    )
    record: dict[str, Any] = {
        "name": name,
        "started_at": _timestamp(started),
        "finished_at": _timestamp(finished),
        "argv": list(argv),
        "cwd": str(workspace),
        "exit_code": exit_code,
        **_stream_record(
            workflow_root,
            stem=name,
            stdout=stdout,
            stderr=stderr,
            forbidden_values=forbidden_values,
        ),
        **pre_status,
        **post_status,
        **pre_executable,
        **post_executable,
        **pre_python,
        **post_python,
    }
    record["passed"] = (
        exit_code == 0
        and not pre_bytes
        and not post_bytes
        and pre_head == source_commit
        and post_head == source_commit
        and pre_executable_digest == qualified_executable_sha256
        and post_executable_digest == qualified_executable_sha256
        and pre_python_digest == python_runtime_inventory_digest
        and post_python_digest == python_runtime_inventory_digest
    )
    return record


def qualify(
    *,
    source: Path,
    workspace: Path,
    timeout_seconds: int,
) -> Path:
    source = source.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    if any(shutil.which(command) is None for command in ("git", "make", "uv")):
        raise RuntimeError("qualification requires git, make, and uv on PATH")
    if not (source / ".git").exists():
        raise RuntimeError("--source must be a Git working tree")
    source_status = _run_git(source, "status", "--porcelain=v1", "--untracked-files=all")
    if source_status:
        raise RuntimeError("source working tree must be clean before qualification")
    source_commit = _run_git(source, "rev-parse", "HEAD").decode("ascii").strip()
    bootstrap_environment = _qualification_environment()

    _assert_empty_destination(workspace)
    print(f"Cloning {source_commit} into {workspace}", flush=True)
    clone_argv = ("git", "clone", "--no-local", str(source), str(workspace))
    clone_started = _utc_after()
    clone = subprocess.run(
        clone_argv,
        cwd=workspace.parent,
        check=False,
        capture_output=True,
        timeout=300,
        env=bootstrap_environment,
    )
    clone_finished = _utc_after(clone_started)
    if clone.returncode != 0:
        detail = (clone.stderr or clone.stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"fresh clone failed: {detail}")

    journal_root = workspace / ".tars" / "qualification"
    runs_root = journal_root / "runs"
    runs_root.mkdir(parents=True)
    gate_home = journal_root / "gate-home"
    gate_home.mkdir(mode=0o700)
    qualification_environment = _qualification_environment(gate_home=gate_home)
    codex_executable = _discover_official_codex()
    qualification_environment["TARS_CODEX_BIN"] = str(codex_executable)
    live_environment = _live_environment(qualification_environment)
    environment_policy = _environment_policy(
        qualification_environment,
        live_environment,
    )
    secret_values = tuple(
        value.encode("utf-8")
        for key, value in live_environment.items()
        if key in {"CODEX_API_KEY", "OPENAI_API_KEY"} and value
    )
    journal_path = journal_root / "journal.json"
    evidence_root = journal_root / "evidence"
    head_relative = Path("evidence") / "git-head.txt"
    status_relative = Path("evidence") / "git-status.txt"
    manifest_relative = Path("evidence") / "source-manifest.json"

    cloned_head = _run_git(workspace, "rev-parse", "HEAD")
    cloned_status = _run_git(
        workspace, "status", "--porcelain=v1", "--untracked-files=all"
    )
    if cloned_head.decode("ascii").strip() != source_commit or cloned_status:
        raise RuntimeError("fresh clone does not exactly match the clean source commit")
    head_digest = _write_bytes(journal_root / head_relative, cloned_head)
    status_digest = _write_bytes(journal_root / status_relative, cloned_status)
    source_manifest = _source_manifest(workspace, source_commit)
    _write_json(journal_root / manifest_relative, source_manifest)
    manifest_bytes = (journal_root / manifest_relative).read_bytes()
    clone_streams = _stream_record(
        journal_root,
        stem="clone",
        stdout=clone.stdout,
        stderr=clone.stderr,
        forbidden_values=secret_values,
    )

    journal: dict[str, Any] = {
        "protocol": "tars.qualification-journal/v2",
        "clone": {
            "started_at": _timestamp(clone_started),
            "finished_at": _timestamp(clone_finished),
            "argv": list(clone_argv),
            "cwd": str(workspace.parent),
            "exit_code": clone.returncode,
            **clone_streams,
        },
        "source": {
            "recorded_workspace_root": str(workspace),
            "recorded_qualification_output_root": str(runs_root),
            "qualification_output_root": "runs",
            "source_commit": source_commit,
            "source_tree_digest": _canonical_digest(source_manifest),
            "source_manifest_path": manifest_relative.as_posix(),
            "source_manifest_sha256": _sha256(manifest_bytes),
            "git_head_path": head_relative.as_posix(),
            "git_head_sha256": head_digest,
            "git_status_path": status_relative.as_posix(),
            "git_status_sha256": status_digest,
            "clone_directory_was_empty": True,
            "tars_revoke_executable": "",
            "tars_revoke_executable_sha256": "",
            "tars_revoke_executable_evidence_path": "",
            "tars_revoke_installed_entrypoint": "",
            "python_runtime_path": "",
            "python_runtime_sha256": "",
            "python_executable_evidence_path": "",
            "python_executable_sha256": "",
            "python_invocation_path": "",
            "python_resolved_path": "",
            "python_runtime_inventory_path": "",
            "python_runtime_inventory_sha256": "",
            "python_runtime_inventory_digest": "",
            "codex_executable": "",
            "codex_executable_sha256": "",
            "codex_executable_version": "",
            "codex_signing": {},
            "codex_version_stdout_path": "",
            "codex_version_stdout_sha256": "",
            "codex_version_stderr_path": "",
            "codex_version_stderr_sha256": "",
        },
        "setup_steps": [],
        "attempts": [],
        "environment_policy": environment_policy,
        "result": "running",
    }
    evidence_root.mkdir(parents=True, exist_ok=True)
    _persist_journal(journal_path, journal)

    for name, argv in SETUP_COMMANDS:
        print(f"[{name}] {' '.join(argv)}", flush=True)
        pre_status, pre_status_bytes, pre_head = _git_snapshot_record(
            journal_root,
            workspace,
            stem=f"setup-{name}",
            phase="pre",
        )
        exit_code, stdout, stderr = _execute(
            argv,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            environment=qualification_environment,
        )
        post_status, post_status_bytes, post_head = _git_snapshot_record(
            journal_root,
            workspace,
            stem=f"setup-{name}",
            phase="post",
        )
        record: dict[str, Any] = {
            "name": name,
            "argv": list(argv),
            "cwd": str(workspace),
            "exit_code": exit_code,
            **_stream_record(
                journal_root,
                stem=f"setup-{name}",
                stdout=stdout,
                stderr=stderr,
                forbidden_values=secret_values,
            ),
            **pre_status,
            **post_status,
        }
        journal["setup_steps"].append(record)
        _persist_journal(journal_path, journal)
        if exit_code != 0:
            _fail(
                journal_path,
                journal,
                phase=name,
                message=f"qualification gate {name} failed with exit code {exit_code}",
            )
        if (
            pre_status_bytes
            or post_status_bytes
            or pre_head != source_commit
            or post_head != source_commit
        ):
            _fail(
                journal_path,
                journal,
                phase=name,
                message=(
                    f"qualification gate {name} changed or dirtied the qualified source commit"
                ),
            )

    installed_tars_revoke = workspace / ".venv" / "bin" / "tars-revoke"
    if not installed_tars_revoke.is_file():
        _fail(
            journal_path,
            journal,
            phase="live-runs",
            message="setup did not create .venv/bin/tars-revoke",
        )
    tars_evidence_relative = Path("evidence") / "executables" / "tars-revoke"
    tars_evidence = journal_root / tars_evidence_relative
    tars_evidence.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(installed_tars_revoke, tars_evidence)
    tars_evidence.chmod(0o555)
    tars_revoke = tars_evidence
    try:
        python_runtime = _python_runtime_record(
            journal_root,
            workspace=workspace,
            installed_entrypoint=installed_tars_revoke,
            environment=qualification_environment,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        _fail(
            journal_path,
            journal,
            phase="runtime-provenance",
            message=f"Python runtime provenance failed: {exc}",
        )
    try:
        codex_signing = _codex_signing_record(
            journal_root,
            codex_executable,
            cwd=workspace,
            environment=qualification_environment,
            forbidden_values=secret_values,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        _fail(
            journal_path,
            journal,
            phase="codex-provenance",
            message=f"Codex provenance failed: {exc}",
        )
    codex_exit, codex_stdout, codex_stderr = _execute(
        (str(codex_executable), "--version"),
        cwd=workspace,
        timeout_seconds=60,
        environment=qualification_environment,
    )
    codex_streams = _stream_record(
        journal_root,
        stem="codex-version",
        stdout=codex_stdout,
        stderr=codex_stderr,
        forbidden_values=secret_values,
    )
    version_lines = (codex_stdout or codex_stderr).decode(
        "utf-8", errors="replace"
    ).strip().splitlines()
    if codex_exit != 0 or not version_lines or not version_lines[0].startswith("codex-cli "):
        _fail(
            journal_path,
            journal,
            phase="codex-provenance",
            message="official Codex executable did not return a valid version",
        )
    codex_digest = _sha256(codex_executable.read_bytes())
    if _PINNED_CODEX_RELEASES.get(version_lines[0]) != codex_digest:
        _fail(
            journal_path,
            journal,
            phase="codex-provenance",
            message="Codex executable does not match the pinned official release bytes",
        )
    journal["source"].update(
        {
            "tars_revoke_executable": str(tars_revoke),
            "tars_revoke_executable_sha256": _sha256(tars_evidence.read_bytes()),
            "tars_revoke_executable_evidence_path": tars_evidence_relative.as_posix(),
            "tars_revoke_installed_entrypoint": str(installed_tars_revoke),
            **python_runtime,
            "codex_executable": str(codex_executable),
            "codex_executable_sha256": codex_digest,
            "codex_executable_version": version_lines[0],
            "codex_signing": codex_signing,
            "codex_version_stdout_path": codex_streams["stdout_path"],
            "codex_version_stdout_sha256": codex_streams["stdout_sha256"],
            "codex_version_stderr_path": codex_streams["stderr_path"],
            "codex_version_stderr_sha256": codex_streams["stderr_sha256"],
        }
    )
    _persist_journal(journal_path, journal)

    qualified_executable_sha256 = str(journal["source"]["tars_revoke_executable_sha256"])
    python_invocation = Path(str(python_runtime["python_invocation_path"]))
    runtime_inventory_path = journal_root / str(
        python_runtime["python_runtime_inventory_path"]
    )
    runtime_inventory_digest = str(python_runtime["python_runtime_inventory_digest"])

    previous_finish: datetime | None = None
    for attempt_index in (1, 2, 3):
        argv = (
            str(python_invocation),
            "-I",
            "-B",
            "-m",
            "tars_revoke.cli",
            "demo",
            "--scenario",
            "external-schema-v2",
            "--live-codex",
            "--output-root",
            str(runs_root),
        )
        before = {path for path in runs_root.iterdir() if path.is_dir()}
        pre_status, pre_status_bytes, pre_head = _git_snapshot_record(
            journal_root,
            workspace,
            stem=f"attempt-{attempt_index}",
            phase="pre",
        )
        pre_executable, pre_executable_digest = _executable_snapshot_record(
            journal_root,
            tars_revoke,
            stem=f"attempt-{attempt_index}",
            phase="pre",
        )
        pre_python, pre_python_digest = _python_runtime_snapshot_record(
            journal_root,
            runtime_inventory_path=runtime_inventory_path,
            stem=f"attempt-{attempt_index}",
            phase="pre",
        )
        started = _utc_after(previous_finish)
        print(f"[live-{attempt_index}] starting real Codex qualification run", flush=True)
        exit_code, stdout, stderr = _execute(
            argv,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            environment=live_environment,
        )
        finished = _utc_after(started)
        previous_finish = finished
        post_status, post_status_bytes, post_head = _git_snapshot_record(
            journal_root,
            workspace,
            stem=f"attempt-{attempt_index}",
            phase="post",
        )
        post_executable, post_executable_digest = _executable_snapshot_record(
            journal_root,
            tars_revoke,
            stem=f"attempt-{attempt_index}",
            phase="post",
        )
        post_python, post_python_digest = _python_runtime_snapshot_record(
            journal_root,
            runtime_inventory_path=runtime_inventory_path,
            stem=f"attempt-{attempt_index}",
            phase="post",
        )
        after = {path for path in runs_root.iterdir() if path.is_dir()}
        discovered = sorted(after - before)
        stream = _stream_record(
            journal_root,
            stem=f"attempt-{attempt_index}",
            stdout=stdout,
            stderr=stderr,
            forbidden_values=secret_values,
        )
        attempt: dict[str, Any] = {
            "attempt_index": attempt_index,
            "started_at": _timestamp(started),
            "finished_at": _timestamp(finished),
            "argv": list(argv),
            "cwd": str(workspace),
            "exit_code": exit_code,
            **stream,
            **pre_status,
            **post_status,
            **pre_executable,
            **post_executable,
            **pre_python,
            **post_python,
            "artifact_root": "",
            "recorded_artifact_root": "",
            "recorded_output_root": str(runs_root),
            "discovered_run_id": "",
            "receipt_sha256": "",
        }
        if len(discovered) == 1:
            run_container = discovered[0]
            receipt_candidates = sorted(
                path
                for path in (run_container / "artifacts").glob("*/receipt.json")
                if path.is_file()
                and not path.is_symlink()
                and not path.parent.is_symlink()
                and not run_container.is_symlink()
            )
            if len(receipt_candidates) == 1:
                receipt_path = receipt_candidates[0]
                bundle_root = receipt_path.parent
                try:
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    receipt = None
                if isinstance(receipt, dict) and isinstance(receipt.get("run_id"), str):
                    attempt.update(
                        {
                            "artifact_root": bundle_root.relative_to(journal_root).as_posix(),
                            "recorded_artifact_root": str(bundle_root),
                            "discovered_run_id": receipt["run_id"],
                            "receipt_sha256": _sha256(receipt_path.read_bytes()),
                        }
                    )
        journal["attempts"].append(attempt)
        _persist_journal(journal_path, journal)
        if exit_code != 0:
            _fail(
                journal_path,
                journal,
                phase=f"live-{attempt_index}",
                message=(
                    f"live qualification attempt {attempt_index} failed "
                    f"with exit code {exit_code}"
                ),
            )
        if (
            pre_status_bytes
            or post_status_bytes
            or pre_head != source_commit
            or post_head != source_commit
            or pre_executable_digest != qualified_executable_sha256
            or post_executable_digest != qualified_executable_sha256
            or pre_python_digest != runtime_inventory_digest
            or post_python_digest != runtime_inventory_digest
        ):
            _fail(
                journal_path,
                journal,
                phase=f"live-{attempt_index}",
                message=(
                    f"live qualification attempt {attempt_index} changed the qualified "
                    "source commit or entry point"
                ),
            )
        if len(discovered) != 1 or not attempt["discovered_run_id"]:
            _fail(
                journal_path,
                journal,
                phase=f"live-{attempt_index}",
                message="live qualification did not produce exactly one valid proof bundle",
            )

    journal["result"] = "passed"
    _persist_journal(journal_path, journal)

    workflow_root = workspace / ".tars" / "release-workflow"
    workflow_path = workflow_root / "workflow.json"
    crash_output = workflow_root / "inputs" / "crash"
    benchmark_output = workflow_root / "inputs" / "revoke"
    release_root = workspace / ".tars" / "release-proof"
    workflow: dict[str, Any] = {
        "protocol": "tars.release-workflow/v1",
        "qualification_journal": str(journal_path),
        "qualification_journal_sha256": _sha256(journal_path.read_bytes()),
        "outputs": {},
        "steps": [],
        "result": "running",
    }
    _persist_journal(workflow_path, workflow)
    cli_prefix = (
        str(python_invocation),
        "-I",
        "-B",
        "-m",
        "tars_revoke.cli",
    )
    post_commands = (
        (
            "crashbench-11",
            (
                *cli_prefix,
                "bench",
                "--suite",
                "CrashBench-11",
                "--output-root",
                str(crash_output),
            ),
        ),
        (
            "revokebench-20",
            (
                *cli_prefix,
                "bench",
                "--suite",
                "RevokeBench-20",
                "--output-root",
                str(benchmark_output),
            ),
        ),
    )
    try:
        for name, argv in post_commands:
            print(f"[{name}] generating executable release evidence", flush=True)
            step = _workflow_step(
                workflow_root,
                workspace,
                name=name,
                argv=argv,
                timeout_seconds=timeout_seconds,
                source_commit=source_commit,
                qualified_executable=tars_revoke,
                qualified_executable_sha256=qualified_executable_sha256,
                python_runtime_inventory_path=runtime_inventory_path,
                python_runtime_inventory_digest=runtime_inventory_digest,
                environment=qualification_environment,
                forbidden_values=secret_values,
            )
            workflow["steps"].append(step)
            _persist_journal(workflow_path, workflow)
            if step["exit_code"] != 0:
                raise RuntimeError(
                    f"release workflow step {name} failed with exit code {step['exit_code']}"
                )
            if step["passed"] is not True:
                raise RuntimeError(f"release workflow step {name} dirtied the qualified source")
        crash_report = _single_report(crash_output, suite="CrashBench-11")
        benchmark_report = _single_report(benchmark_output, suite="RevokeBench-20")
        workflow["outputs"].update(
            {
                "crash_report": _output_record(
                    crash_report,
                    label="CrashBench-11",
                ),
                "benchmark_report": _output_record(
                    benchmark_report,
                    label="RevokeBench-20",
                ),
            }
        )
        _persist_journal(workflow_path, workflow)
        attest_argv = (
            *cli_prefix,
            "attest-release",
            "--qualification-journal",
            str(journal_path),
            "--crash-report",
            str(crash_report),
            "--benchmark-report",
            str(benchmark_report),
            "--output-root",
            str(release_root),
        )
        print("[attest-release] building portable strict proof", flush=True)
        attest_step = _workflow_step(
            workflow_root,
            workspace,
            name="attest-release",
            argv=attest_argv,
            timeout_seconds=timeout_seconds,
            source_commit=source_commit,
            qualified_executable=tars_revoke,
            qualified_executable_sha256=qualified_executable_sha256,
            python_runtime_inventory_path=runtime_inventory_path,
            python_runtime_inventory_digest=runtime_inventory_digest,
            environment=qualification_environment,
            forbidden_values=secret_values,
        )
        workflow["steps"].append(attest_step)
        _persist_journal(workflow_path, workflow)
        if attest_step["passed"] is not True:
            raise RuntimeError("release workflow step attest-release failed or dirtied source")
        attestation = release_root / "release-attestation.json"
        workflow["outputs"]["release_attestation"] = _output_record(
            attestation,
            label="release attestation",
        )
        _persist_journal(workflow_path, workflow)
        verify_argv = (*cli_prefix, "verify", str(attestation), "--strict")
        print("[verify-release] independently verifying R-01 through R-20", flush=True)
        verify_step = _workflow_step(
            workflow_root,
            workspace,
            name="verify-release",
            argv=verify_argv,
            timeout_seconds=timeout_seconds,
            source_commit=source_commit,
            qualified_executable=tars_revoke,
            qualified_executable_sha256=qualified_executable_sha256,
            python_runtime_inventory_path=runtime_inventory_path,
            python_runtime_inventory_digest=runtime_inventory_digest,
            environment=qualification_environment,
            forbidden_values=secret_values,
        )
        workflow["steps"].append(verify_step)
        _persist_journal(workflow_path, workflow)
        if verify_step["passed"] is not True:
            raise RuntimeError("release workflow step verify-release failed or dirtied source")
        verified_attestation = _output_record(
            attestation,
            label="verified release attestation",
        )
        if verified_attestation != workflow["outputs"]["release_attestation"]:
            raise RuntimeError("strict verification mutated the release attestation")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        workflow["result"] = "failed"
        workflow["failure"] = str(exc)
        _persist_journal(workflow_path, workflow)
        raise
    workflow["result"] = "passed"
    workflow["crash_report"] = str(crash_report)
    workflow["crash_report_sha256"] = workflow["outputs"]["crash_report"]["sha256"]
    workflow["benchmark_report"] = str(benchmark_report)
    workflow["benchmark_report_sha256"] = workflow["outputs"]["benchmark_report"][
        "sha256"
    ]
    workflow["release_root"] = str(release_root)
    workflow["release_attestation"] = str(attestation)
    workflow["release_attestation_sha256"] = workflow["outputs"][
        "release_attestation"
    ]["sha256"]
    _persist_journal(workflow_path, workflow)
    print(f"Qualification journal: {journal_path}", flush=True)
    print(f"Strict release proof: {release_root}", flush=True)
    return journal_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify one exact TARS REVOKE commit with three live Codex runs."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path.cwd(),
        help="clean source Git working tree (default: current directory)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="nonexistent or empty destination for the qualification clone",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=7200,
        help="maximum duration of each setup or live command",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.timeout_seconds < 60:
        print("--timeout-seconds must be at least 60", file=sys.stderr)
        return 2
    try:
        qualify(
            source=args.source,
            workspace=args.workspace,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"qualification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
