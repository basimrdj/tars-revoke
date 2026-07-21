from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tars_revoke.domain.canonical import canonical_json

HYPOTHESES = (
    "implementation_rejects_signed_v2",
    "implementation_accepts_signed_v2",
)


def _single_fixture_observer(example_path: str) -> str:
    return (
        "import json; from pathlib import Path; "
        "from scripts.contract_probe import probe; "
        f"result = probe(Path('{example_path}')); "
        "print(json.dumps({'accepted': bool(result['accepted'])}, "
        "sort_keys=True, separators=(',', ':')))"
    )


_MATRIX_OBSERVER = (
    "import json; from pathlib import Path; "
    "from scripts.contract_probe import probe; "
    "v1 = probe(Path('examples/customer-v1.json')); "
    "v2 = probe(Path('examples/customer-v2.json')); "
    "print(json.dumps({'v1_accepted': bool(v1['accepted']), "
    "'v2_accepted': bool(v2['accepted'])}, sort_keys=True, separators=(',', ':')))"
)


@dataclass(frozen=True)
class CanonicalExperimentSpec:
    name: str
    portable_argv: tuple[str, ...]
    predictions: tuple[tuple[str, str], ...]
    estimated_runtime_ms: int

    @property
    def prediction_map(self) -> dict[str, str]:
        return dict(self.predictions)


CANONICAL_EXPERIMENT_SPECS = (
    CanonicalExperimentSpec(
        name="observe-v2-acceptance",
        portable_argv=(
            "python",
            "-B",
            "-c",
            _single_fixture_observer("examples/customer-v2.json"),
        ),
        predictions=(
            (HYPOTHESES[0], canonical_json({"accepted": False})),
            (HYPOTHESES[1], canonical_json({"accepted": True})),
        ),
        estimated_runtime_ms=50,
    ),
    CanonicalExperimentSpec(
        name="observe-v1-acceptance",
        portable_argv=(
            "python",
            "-B",
            "-c",
            _single_fixture_observer("examples/customer-v1.json"),
        ),
        predictions=(
            (HYPOTHESES[0], canonical_json({"accepted": True})),
            (HYPOTHESES[1], canonical_json({"accepted": False})),
        ),
        estimated_runtime_ms=70,
    ),
    CanonicalExperimentSpec(
        name="observe-contract-matrix",
        portable_argv=("python", "-B", "-c", _MATRIX_OBSERVER),
        predictions=(
            (
                HYPOTHESES[0],
                canonical_json({"v1_accepted": True, "v2_accepted": False}),
            ),
            (
                HYPOTHESES[1],
                canonical_json({"v1_accepted": False, "v2_accepted": True}),
            ),
        ),
        estimated_runtime_ms=100,
    ),
)


def canonical_experiment_spec(argv: tuple[str, ...]) -> CanonicalExperimentSpec | None:
    return next(
        (spec for spec in CANONICAL_EXPERIMENT_SPECS if spec.portable_argv == argv),
        None,
    )


def matching_hypotheses(
    predictions: dict[str, Any],
    observed_outcome: Any,
) -> tuple[str, ...]:
    canonical_outcome = canonical_json(observed_outcome)
    return tuple(
        hypothesis
        for hypothesis, prediction in predictions.items()
        if prediction == canonical_outcome
    )
