from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from tars_revoke.domain.enums import RiskLevel
from tars_revoke.errors import ValidationError

from .experiment_contract import CANONICAL_EXPERIMENT_SPECS, HYPOTHESES
from .migration_contract import (
    MIGRATION_SOURCE_PATH,
    OPAQUE_CONTRACT_SQL,
    UUID_CONTRACT_SQL,
)

UUID_MODEL_SOURCE = """from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID


@dataclass(frozen=True)
class Customer:
    customer_id: UUID
    email: str


def parse_customer(payload: Mapping[str, Any]) -> Customer:
    raw_customer_id = str(payload.get("customer_id", "")).strip()
    email = str(payload.get("email", "")).strip()
    if not raw_customer_id:
        raise ValueError("customer_id is required")
    try:
        customer_id = UUID(raw_customer_id)
    except ValueError as error:
        raise ValueError("customer_id must be a UUID") from error
    if "@" not in email:
        raise ValueError("email must be valid")
    return Customer(customer_id=customer_id, email=email)
"""


OPAQUE_MODEL_SOURCE = """from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


CUSTOMER_ID_PATTERN = re.compile(r"cus_[A-Za-z0-9]+\\Z")


@dataclass(frozen=True)
class Customer:
    customer_id: str
    email: str


def parse_customer(payload: Mapping[str, Any]) -> Customer:
    customer_id = str(payload.get("customer_id", "")).strip()
    email = str(payload.get("email", "")).strip()
    if "@" not in email:
        raise ValueError("email must be valid")
    if not CUSTOMER_ID_PATTERN.fullmatch(customer_id):
        raise ValueError("customer_id must use the published cus_ format")
    return Customer(customer_id=customer_id, email=email)
"""


V2_CONTRACT_TEST_SOURCE = """from __future__ import annotations

import json
from pathlib import Path

from billing.models import parse_customer


ROOT = Path(__file__).resolve().parents[1]


def test_customer_matches_published_v2_example() -> None:
    payload = json.loads((ROOT / "examples/customer-v2.json").read_text(encoding="utf-8"))
    customer = parse_customer(payload)
    assert customer.customer_id == payload["customer_id"]
"""


@dataclass(frozen=True)
class ScriptedExperiment:
    id: str
    hypotheses: tuple[str, ...]
    predictions: dict[str, str]
    argv: tuple[str, ...]
    touched_files: tuple[str, ...]
    risk: RiskLevel
    estimated_runtime_ms: int
    command_count: int = 1


@dataclass(frozen=True)
class ScriptedRepair:
    provider: str
    session_id: str
    response_ids: tuple[str, ...]
    changed_paths: tuple[str, ...]
    summary: str


class ScriptedCodex:
    """Deterministic demo double; never represented as a live Codex session.

    The canonical local test uses this provider so it is repeatable and does not
    need network credentials. Production proof must opt into ``LiveCodexPath``;
    callers must never silently fall back to this implementation.
    """

    provider = "scripted-codex-demo-double"

    def __init__(self, *, python_executable: Path) -> None:
        self.python_executable = python_executable.expanduser().resolve(strict=True)

    def initial_uuid_change(self, worktree: Path) -> tuple[str, ...]:
        model = self._bounded_path(worktree, "billing/models.py")
        migration = self._bounded_path(worktree, MIGRATION_SOURCE_PATH)
        model.write_text(UUID_MODEL_SOURCE, encoding="utf-8")
        migration.write_text(UUID_CONTRACT_SQL, encoding="utf-8")
        return ("billing/models.py", MIGRATION_SOURCE_PATH)

    def propose_experiments(
        self,
        worktree: Path,
        *,
        case_id: str,
    ) -> tuple[ScriptedExperiment, ...]:
        _root = worktree.expanduser().resolve(strict=True)
        python = str(self.python_executable)
        return tuple(
            ScriptedExperiment(
                id=f"{case_id}-{spec.name}",
                hypotheses=HYPOTHESES,
                predictions=spec.prediction_map,
                argv=(python, *spec.portable_argv[1:]),
                touched_files=(),
                risk=RiskLevel.LOW,
                estimated_runtime_ms=spec.estimated_runtime_ms,
            )
            for spec in CANONICAL_EXPERIMENT_SPECS
        )

    def repair(self, worktree: Path, *, case_id: str) -> ScriptedRepair:
        model = self._bounded_path(worktree, "billing/models.py")
        migration = self._bounded_path(worktree, MIGRATION_SOURCE_PATH)
        contract_test = self._bounded_path(worktree, "tests/test_contract.py")
        model.write_text(OPAQUE_MODEL_SOURCE, encoding="utf-8")
        migration.write_text(OPAQUE_CONTRACT_SQL, encoding="utf-8")
        contract_test.write_text(V2_CONTRACT_TEST_SOURCE, encoding="utf-8")
        return ScriptedRepair(
            provider=self.provider,
            session_id=f"scripted-session-{case_id}",
            response_ids=(f"scripted-response-{case_id}",),
            changed_paths=(
                "billing/models.py",
                MIGRATION_SOURCE_PATH,
                "tests/test_contract.py",
            ),
            summary=(
                "Deterministic fixture repair: enforce the signed v2 cus_ contract "
                "and move the contract test to the v2 example."
            ),
        )

    @staticmethod
    def _bounded_path(worktree: Path, relative: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", relative) or relative.startswith("/"):
            raise ValidationError("scripted repair path is unsafe")
        root = worktree.expanduser().resolve(strict=True)
        target = (root / relative).resolve(strict=True)
        if root not in target.parents:
            raise ValidationError("scripted repair path escaped its worktree")
        if target.is_symlink() or not target.is_file():
            raise ValidationError("scripted repair target must be a regular file")
        return target
