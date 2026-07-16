from __future__ import annotations

import json
from pathlib import Path

from billing.models import parse_customer


ROOT = Path(__file__).resolve().parents[1]


def test_customer_matches_published_v1_example() -> None:
    payload = json.loads((ROOT / "examples/customer-v1.json").read_text(encoding="utf-8"))
    customer = parse_customer(payload)
    assert str(customer.customer_id) == payload["customer_id"]
