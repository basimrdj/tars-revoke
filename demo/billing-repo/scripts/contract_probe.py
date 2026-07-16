from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from billing.models import parse_customer  # noqa: E402


def probe(example_path: Path) -> dict[str, object]:
    payload = json.loads(example_path.read_text(encoding="utf-8"))
    try:
        customer = parse_customer(payload)
    except Exception as error:
        return {
            "accepted": False,
            "customer_id": payload.get("customer_id"),
            "error": f"{type(error).__name__}: {error}",
        }
    return {
        "accepted": True,
        "customer_id": str(customer.customer_id),
        "runtime_type": type(customer.customer_id).__name__,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--example", type=Path, required=True)
    parser.add_argument("--expect", choices=("accept", "reject"), required=True)
    args = parser.parse_args()

    result = probe(args.example)
    print(json.dumps(result, sort_keys=True))
    expected = result["accepted"] is (args.expect == "accept")
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
