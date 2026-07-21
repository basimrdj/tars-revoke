from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tars_revoke.domain.canonical import canonical_digest, sha256_digest
from tars_revoke.errors import IntegrityError

SANDBOX_BACKEND = "macos-sandbox-exec"
SANDBOX_EXECUTABLE = Path("/usr/bin/sandbox-exec")
OTOOL_EXECUTABLE = Path("/usr/bin/otool")
EXPERIMENT_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}


def _scheme_string(value: str) -> str:
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise IntegrityError("sandbox paths must be non-empty single-line strings")
    return json.dumps(value, ensure_ascii=True)


def render_macos_profile(
    *,
    process_executables: tuple[str, ...],
    read_subpaths: tuple[str, ...],
    read_literals: tuple[str, ...],
) -> str:
    """Render the exact fail-closed Seatbelt policy used by the observer.

    The observer may execute only the selected Python interpreter and may read
    only the selected worktree, its Python runtime, and exact loader inputs.
    There is no rule granting writes, network access, child-process execution,
    Mach service access, or reads elsewhere on the host.
    """

    if not process_executables or not read_subpaths or not read_literals:
        raise IntegrityError("sandbox allow-only policy is incomplete")
    processes = " ".join(
        f"(literal {_scheme_string(path)})" for path in process_executables
    )
    subpaths = " ".join(
        f"(subpath {_scheme_string(path)})" for path in read_subpaths
    )
    literals = " ".join(
        f"(literal {_scheme_string(path)})" for path in read_literals
    )
    return (
        "(version 1)\n"
        "(deny default)\n"
        f"(allow process-exec {processes})\n"
        "(allow process-info*)\n"
        "(allow signal (target self))\n"
        f"(allow file-read* {subpaths} {literals})\n"
    )


def _ancestor_literals(paths: tuple[Path, ...]) -> tuple[str, ...]:
    ancestors = {"/"}
    for path in paths:
        current = path
        while current != current.parent:
            ancestors.add(str(current))
            current = current.parent
    return tuple(sorted(ancestors))


def _dynamic_libraries(
    executable: Path,
    *,
    allowed_roots: tuple[Path, ...],
) -> tuple[dict[str, str], ...]:
    if not OTOOL_EXECUTABLE.is_file() or OTOOL_EXECUTABLE.is_symlink():
        raise IntegrityError("macOS otool is required to bind Python loader inputs")
    result = subprocess.run(
        (str(OTOOL_EXECUTABLE), "-L", str(executable)),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={},
    )
    if result.returncode != 0:
        raise IntegrityError("cannot enumerate decisive experiment loader inputs")
    records: list[dict[str, str]] = []
    for line in result.stdout.splitlines()[1:]:
        raw = line.strip().split(" (", 1)[0]
        if not raw.startswith("/"):
            continue
        path = Path(raw)
        if not path.exists():
            # macOS dyld shared-cache entries often have no standalone file.
            continue
        resolved = path.resolve(strict=True)
        if any(resolved == root or root in resolved.parents for root in allowed_roots):
            continue
        if path.is_dir() or resolved.is_dir():
            raise IntegrityError("Python loader input is not a regular file")
        records.append(
            {
                "path": str(path),
                "resolved_path": str(resolved),
                "sha256": sha256_digest(resolved.read_bytes()),
            }
        )
    return tuple(sorted(records, key=lambda item: (item["path"], item["resolved_path"])))


@dataclass(frozen=True)
class ExperimentSandboxPlan:
    backend: str
    executable: str
    executable_sha256: str
    profile: str
    profile_sha256: str
    logical_argv: tuple[str, ...]
    supervisor_argv: tuple[str, ...]
    environment: dict[str, str]
    environment_digest: str
    process_executables: tuple[str, ...]
    read_subpaths: tuple[str, ...]
    read_literals: tuple[str, ...]
    dynamic_libraries: tuple[dict[str, str], ...]
    python_invocation_path: str
    python_resolved_path: str
    python_sha256: str

    def as_mapping(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "profile_sha256": self.profile_sha256,
            "logical_argv": list(self.logical_argv),
            "supervisor_argv": list(self.supervisor_argv),
            "environment": dict(self.environment),
            "environment_digest": self.environment_digest,
            "process_executables": list(self.process_executables),
            "read_subpaths": list(self.read_subpaths),
            "read_literals": list(self.read_literals),
            "dynamic_libraries": [dict(item) for item in self.dynamic_libraries],
            "python_invocation_path": self.python_invocation_path,
            "python_resolved_path": self.python_resolved_path,
            "python_sha256": self.python_sha256,
        }


def build_experiment_sandbox(
    *,
    logical_argv: tuple[str, ...],
    worktree: Path,
) -> ExperimentSandboxPlan:
    if sys.platform != "darwin":
        raise IntegrityError(
            "the release-grade decisive experiment requires macOS sandbox-exec"
        )
    sandbox = SANDBOX_EXECUTABLE.resolve(strict=True)
    if sandbox.is_symlink() or not sandbox.is_file():
        raise IntegrityError("macOS sandbox-exec is missing or unsafe")
    root = worktree.expanduser().resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise IntegrityError("experiment worktree is missing or unsafe")
    if not logical_argv:
        raise IntegrityError("experiment logical argv is empty")
    python_invocation = Path(logical_argv[0]).expanduser()
    if not python_invocation.is_absolute() or not python_invocation.is_file():
        raise IntegrityError("experiment Python invocation path is invalid")
    python_resolved = python_invocation.resolve(strict=True)
    current_python = Path(sys.executable).expanduser().resolve(strict=True)
    if python_resolved != current_python:
        raise IntegrityError("experiment Python differs from the running TARS runtime")

    allowed_paths = tuple(
        sorted(
            {
                root,
                Path(sys.prefix).expanduser().resolve(strict=True),
                Path(sys.base_prefix).expanduser().resolve(strict=True),
            },
            key=str,
        )
    )
    process_executables = tuple(sorted({str(python_invocation), str(python_resolved)}))
    dynamic_libraries = _dynamic_libraries(
        python_resolved,
        allowed_roots=allowed_paths,
    )
    literal_paths = [*allowed_paths]
    for dependency in dynamic_libraries:
        literal_paths.extend(
            (Path(dependency["path"]), Path(dependency["resolved_path"]))
        )
    read_subpaths = tuple(str(path) for path in allowed_paths)
    read_literals = tuple(
        sorted(
            {
                *_ancestor_literals(tuple(literal_paths)),
                *(str(path) for path in literal_paths),
            }
        )
    )
    profile = render_macos_profile(
        process_executables=process_executables,
        read_subpaths=read_subpaths,
        read_literals=read_literals,
    )
    supervisor_argv = (
        str(sandbox),
        "-p",
        profile,
        "--",
        *logical_argv,
    )
    environment = dict(EXPERIMENT_ENVIRONMENT)
    return ExperimentSandboxPlan(
        backend=SANDBOX_BACKEND,
        executable=str(sandbox),
        executable_sha256=sha256_digest(sandbox.read_bytes()),
        profile=profile,
        profile_sha256=sha256_digest(profile.encode("utf-8")),
        logical_argv=logical_argv,
        supervisor_argv=supervisor_argv,
        environment=environment,
        environment_digest=canonical_digest(environment),
        process_executables=process_executables,
        read_subpaths=read_subpaths,
        read_literals=read_literals,
        dynamic_libraries=dynamic_libraries,
        python_invocation_path=str(python_invocation),
        python_resolved_path=str(python_resolved),
        python_sha256=sha256_digest(python_resolved.read_bytes()),
    )


def workspace_manifest(root: Path) -> dict[str, Any]:
    """Hash every worktree entry so the read-only claim is observable."""

    resolved = root.expanduser().resolve(strict=True)
    if not resolved.is_dir() or resolved.is_symlink():
        raise IntegrityError("experiment worktree is missing or unsafe")
    entries: list[dict[str, Any]] = []
    for directory, directory_names, file_names in os.walk(resolved, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current = Path(directory)
        for name in directory_names:
            path = current / name
            if path.is_symlink():
                raise IntegrityError("experiment worktree contains a directory symlink")
        for name in file_names:
            path = current / name
            metadata = path.lstat()
            relative = path.relative_to(resolved).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                raise IntegrityError("experiment worktree contains a file symlink")
            if not stat.S_ISREG(metadata.st_mode):
                raise IntegrityError("experiment worktree contains a non-regular entry")
            payload = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "sha256": sha256_digest(payload),
                    "size": len(payload),
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
    manifest: dict[str, Any] = {
        "protocol": "tars.experiment-worktree/v1",
        "root": str(resolved),
        "entries": entries,
    }
    manifest["canonical_digest"] = canonical_digest(manifest)
    return manifest
