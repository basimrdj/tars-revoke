"""
TARS Model Registry  (Phase 2.5A part 1)
=========================================

A small, swappable registry that maps cognitive ROLES to MODELS.

The Phase 2.5 plan demands this:

> Do not use one model for everything. Use a router.
>
>   inner_fast      — background thoughts, low-stakes reflection
>   inner_candidate — challenger model under benchmark
>   cloud_strong    — sleep/world/self high-quality cognition

Roles are stable strings the rest of the codebase can ask for; the actual
model behind each role is configurable via env vars or `tars_models.json`.

Usage::

    reg = ModelRegistry.load_default()
    spec = reg.get("inner_fast")            # ModelSpec or None
    if spec and spec.enabled:
        url = spec.endpoint               # OpenAI-compatible /v1/chat/completions

Persistence is JSON only. No network, no LLM calls — this module is the
*addressing layer*, not the cognition itself. A concrete chat-client that
talks to whatever role is wired separately (the existing
``LocalModelClient`` in ``tars_inner_voice.py`` already does HTTP for the
local mlx_lm.server endpoint).

The registry is FAIL-SOFT: every getter returns ``None`` for missing roles
so callers can degrade gracefully.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional


REGISTRY_FILENAME = "tars_models.json"


@dataclass
class ModelSpec:
    """One model entry. Compatible with both local (mlx_lm.server) and cloud."""
    role: str                                  # eg "inner_fast", "cloud_strong"
    provider: str                              # "mlx" | "openai" | "anthropic" | "stub"
    model: str                                 # provider-specific id
    endpoint: Optional[str] = None             # full /v1/chat/completions URL for HTTP providers
    api_key_env: Optional[str] = None          # name of the env var holding the key
    description: str = ""
    enabled: bool = True
    extra: Dict = field(default_factory=dict)  # arbitrary provider-specific knobs

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, role: str, d: Dict) -> "ModelSpec":
        return cls(
            role=role,
            provider=str(d.get("provider", "stub")),
            model=str(d.get("model", "")),
            endpoint=d.get("endpoint"),
            api_key_env=d.get("api_key_env"),
            description=str(d.get("description", "") or d.get("role", "")),
            enabled=bool(d.get("enabled", True)),
            extra={k: v for k, v in d.items()
                   if k not in {"provider", "model", "endpoint",
                                "api_key_env", "description", "enabled", "role"}},
        )


# Default registry for current runtime.
# These are *defaults*. tars_models.json (if present) overrides; env vars
# override that. Order: env > file > built-in default.
DEFAULT_REGISTRY: Dict[str, Dict] = {
    "inner_fast": {
        "provider":    "mlx",
        "model":       "mlx-community/gemma-4-e4b-it-4bit",
        "endpoint":    "http://127.0.0.1:8765/v1/chat/completions",
        "description": "background cognition (continuous thoughts)",
        "enabled":     True,
    },
    "inner_candidate": {
        "provider":    "mlx",
        "model":       "mlx-community/gemma-4-e4b-it-4bit",
        "endpoint":    "http://127.0.0.1:8766/v1/chat/completions",
        "description": "disabled second-port candidate; override for benchmarks",
        "enabled":     False,
    },
    "cloud_strong": {
        "provider":    "openai",
        "model":       "gpt-4o-mini",
        "endpoint":    None,           # cloud client builds its own URL
        "api_key_env": "OPENAI_API_KEY",
        "description": "sleep/world/self high-quality cognition",
        "enabled":     True,
    },
}


# Env-var override schema:
#   TARS_MODEL_<ROLE>_PROVIDER
#   TARS_MODEL_<ROLE>_MODEL
#   TARS_MODEL_<ROLE>_ENDPOINT
#   TARS_MODEL_<ROLE>_API_KEY_ENV
#   TARS_MODEL_<ROLE>_ENABLED
def _env_override_for(role: str) -> Dict:
    out: Dict = {}
    prefix = f"TARS_MODEL_{role.upper()}_"
    for short_key, env_suffix, cast in (
        ("provider",    "PROVIDER",    str),
        ("model",       "MODEL",       str),
        ("endpoint",    "ENDPOINT",    str),
        ("api_key_env", "API_KEY_ENV", str),
        ("enabled",     "ENABLED",     lambda s: s.lower() in {"1", "true", "yes", "on"}),
    ):
        v = os.getenv(prefix + env_suffix)
        if v is not None and v != "":
            out[short_key] = cast(v)
    return out


class ModelRegistry:
    """Thread-safe registry of role → ModelSpec."""

    def __init__(self, project_dir: str, log_fn=None):
        self.project_dir = project_dir
        self.path = os.path.join(project_dir, REGISTRY_FILENAME)
        self._log = log_fn or (lambda *a, **k: None)
        self._lock = threading.RLock()
        self._specs: Dict[str, ModelSpec] = {}
        self._load()

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @classmethod
    def load_default(cls, project_dir: Optional[str] = None,
                     log_fn=None) -> "ModelRegistry":
        if project_dir is None:
            project_dir = os.path.dirname(os.path.abspath(__file__))
        return cls(project_dir, log_fn=log_fn)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> None:
        with self._lock:
            # Start from built-in defaults
            merged: Dict[str, Dict] = {k: dict(v) for k, v in DEFAULT_REGISTRY.items()}

            # Layer file overrides
            if os.path.exists(self.path):
                try:
                    with open(self.path, "r", encoding="utf-8") as f:
                        on_disk = json.load(f)
                    if isinstance(on_disk, dict):
                        for role, d in on_disk.items():
                            if not isinstance(d, dict):
                                continue
                            merged.setdefault(role, {}).update(d)
                except Exception as e:
                    self._log(f"[model-registry] failed to read {REGISTRY_FILENAME}: {e}")

            # Layer env overrides last
            for role in list(merged.keys()):
                env_override = _env_override_for(role)
                if env_override:
                    merged[role].update(env_override)

            # Materialize
            self._specs = {role: ModelSpec.from_dict(role, d)
                           for role, d in merged.items()}

    def save(self) -> None:
        """Persist the current state to tars_models.json."""
        with self._lock:
            payload = {role: spec.to_dict() for role, spec in self._specs.items()}
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            os.replace(tmp, self.path)
        except Exception as e:
            self._log(f"[model-registry] save failed: {e}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, role: str) -> Optional[ModelSpec]:
        with self._lock:
            return self._specs.get(role)

    def get_required(self, role: str) -> ModelSpec:
        spec = self.get(role)
        if spec is None:
            raise KeyError(f"No model registered for role {role!r}")
        return spec

    def list_roles(self) -> List[str]:
        with self._lock:
            return sorted(self._specs.keys())

    def enabled_roles(self) -> List[str]:
        with self._lock:
            return sorted(r for r, s in self._specs.items() if s.enabled)

    def set(self, role: str, spec: ModelSpec) -> None:
        with self._lock:
            spec.role = role
            self._specs[role] = spec

    def set_enabled(self, role: str, enabled: bool) -> bool:
        with self._lock:
            spec = self._specs.get(role)
            if spec is None:
                return False
            spec.enabled = bool(enabled)
            return True

    def resolve_api_key(self, role: str) -> Optional[str]:
        """Return the API key for a role, looking up the env var named in
        the spec. Returns None if no key configured."""
        spec = self.get(role)
        if spec is None or not spec.api_key_env:
            return None
        return os.getenv(spec.api_key_env)

    def summary(self) -> List[Dict]:
        """Compact human-readable view for logs / dashboards."""
        with self._lock:
            return [
                {
                    "role":       s.role,
                    "provider":   s.provider,
                    "model":      s.model,
                    "endpoint":   s.endpoint,
                    "enabled":    s.enabled,
                    "has_key":    bool(self.resolve_api_key(s.role)) if s.api_key_env else None,
                }
                for s in sorted(self._specs.values(), key=lambda x: x.role)
            ]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile, sys, pprint
    with tempfile.TemporaryDirectory() as td:
        reg = ModelRegistry(td, log_fn=lambda m: print("[log]", m))
        print("Roles:", reg.list_roles())
        print("Enabled:", reg.enabled_roles())
        print("Summary:")
        pprint.pp(reg.summary())
        # Sanity: env override works
        os.environ["TARS_MODEL_INNER_FAST_MODEL"] = "TestModel-7B"
        reg2 = ModelRegistry(td)
        spec = reg2.get("inner_fast")
        assert spec is not None and spec.model == "TestModel-7B", spec
        print("env-override OK ->", spec.model)
        # Save + reload
        reg2.save()
        reg3 = ModelRegistry(td)
        assert reg3.get("inner_fast").model == "TestModel-7B"
        print("save/reload OK")
        print("MODEL REGISTRY SELF-TEST OK")
