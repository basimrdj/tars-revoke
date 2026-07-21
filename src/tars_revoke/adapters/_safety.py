from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tars_revoke.errors import AdapterError, ValidationError

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|bearer|credential|password|passwd|secret|"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk|ghp|github_pat|xox[baprs])-[-A-Za-z0-9_]{12,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|credential)\s*[:=]\s*"
        r"([^\s,;]+)"
    ),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)
_ENVIRONMENT_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PYTHON_EXECUTABLE_NAME = re.compile(
    r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?\Z",
    re.IGNORECASE,
)

# These names carry runtime mechanics, never application credentials.  Process
# callers may extend the set for one adapter, but there is no broad os.environ
# inheritance path.
MINIMAL_SUBPROCESS_ENV_KEYS = frozenset(
    {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    }
)
PYTHON_SUBPROCESS_ENV_KEYS = MINIMAL_SUBPROCESS_ENV_KEYS | {
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
    "PYTHONUTF8",
}
GIT_SUBPROCESS_ENV_KEYS = MINIMAL_SUBPROCESS_ENV_KEYS
CODEX_RUNTIME_ENV_KEYS = MINIMAL_SUBPROCESS_ENV_KEYS | {
    "CODEX_HOME",
    "HOME",
    "USERPROFILE",
}
CODEX_AUTH_ENV_KEYS = frozenset(
    {
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORGANIZATION",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT",
        "OPENAI_PROJECT_ID",
    }
)
CODEX_SUBPROCESS_ENV_KEYS = CODEX_RUNTIME_ENV_KEYS | CODEX_AUTH_ENV_KEYS


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_roots(roots: Iterable[Path]) -> tuple[Path, ...]:
    normalized = tuple(Path(root).expanduser().resolve(strict=True) for root in roots)
    if not normalized:
        raise ValidationError("at least one allowed root is required")
    if any(not root.is_dir() for root in normalized):
        raise ValidationError("allowed roots must be existing directories")
    return normalized


def resolve_under_roots(
    path: Path,
    roots: Sequence[Path],
    *,
    must_exist: bool = True,
    require_directory: bool | None = None,
) -> Path:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise ValidationError(f"invalid path: {candidate}") from exc
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise ValidationError(f"path escapes registered roots: {candidate}")
    if must_exist and require_directory is True and not resolved.is_dir():
        raise ValidationError(f"directory required: {candidate}")
    if must_exist and require_directory is False and not resolved.is_file():
        raise ValidationError(f"file required: {candidate}")
    return resolved


def validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, str | bytes):
        raise ValidationError("commands must be argv sequences, never shell strings")
    normalized = tuple(argv)
    if not normalized:
        raise ValidationError("argv cannot be empty")
    for index, item in enumerate(normalized):
        if not isinstance(item, str):
            raise ValidationError(f"argv[{index}] must be a string")
        if not item or "\x00" in item:
            raise ValidationError(f"argv[{index}] is empty or contains NUL")
    return normalized


def is_python_executable(value: str | Path) -> bool:
    """Return whether a basename is an exact conventional Python executable name."""

    return _PYTHON_EXECUTABLE_NAME.fullmatch(Path(value).name) is not None


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def redact_mapping(value: Mapping[str, str]) -> dict[str, str]:
    return {
        key: "<redacted>" if _SECRET_KEY.search(key) else redact_text(item)
        for key, item in value.items()
    }


def sanitized_environment(
    overlay: Mapping[str, str] | None = None,
    *,
    inherited_keys: Iterable[str] = MINIMAL_SUBPROCESS_ENV_KEYS,
) -> dict[str, str]:
    requested_keys = frozenset(inherited_keys)
    for key in requested_keys:
        if not isinstance(key, str) or not _ENVIRONMENT_KEY.fullmatch(key):
            raise ValidationError("inherited environment keys must be portable names")
    env = {key: os.environ[key] for key in sorted(requested_keys) if key in os.environ}
    for key, value in (overlay or {}).items():
        if (
            not isinstance(key, str)
            or not _ENVIRONMENT_KEY.fullmatch(key)
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ValidationError(
                "environment keys must be portable names and values must be NUL-free strings"
            )
        env[key] = value
    return env


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def require_non_secret_payload(value: Any, *, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                raise AdapterError(f"secret-bearing field rejected at {path}.{key}")
            require_non_secret_payload(item, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            require_non_secret_payload(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and redact_text(value) != value:
        raise AdapterError(f"secret-looking value rejected at {path}")


def require_no_secret_values(value: Any, *, path: str = "payload") -> None:
    """Reject embedded secret values while allowing schemas to name secret fields.

    A JSON Schema may describe a field named ``api_key``; the schema itself
    still may not contain an actual key as a default, example, or description.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            require_no_secret_values(item, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            require_no_secret_values(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and redact_text(value) != value:
        raise AdapterError(f"secret-looking value rejected at {path}")
