from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class Customer:
    customer_id: str
    email: str


def parse_customer(payload: Mapping[str, Any]) -> Customer:
    customer_id = str(payload.get("customer_id", "")).strip()
    email = str(payload.get("email", "")).strip()
    if not customer_id:
        raise ValueError("customer_id is required")
    if "@" not in email:
        raise ValueError("email must be valid")
    return Customer(customer_id=customer_id, email=email)
