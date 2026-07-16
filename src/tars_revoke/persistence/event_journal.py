from __future__ import annotations

import hmac
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from tars_revoke.clock import Clock, SystemClock
from tars_revoke.domain.canonical import canonical_digest, canonical_json
from tars_revoke.domain.enums import OutboxState
from tars_revoke.domain.models import EventRecord, OutboxRecord
from tars_revoke.errors import IntegrityError, ValidationError
from tars_revoke.ids import new_id

from .database import Database

GENESIS_HASH = "0" * 64


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _loads(value: str) -> Any:
    return json.loads(value)


class EventJournal:
    """Transactional per-run hash chain with an atomic delivery outbox."""

    def __init__(self, database: Database, *, clock: Clock | None = None):
        self.database = database
        self.clock = clock or SystemClock()

    def append(
        self,
        *,
        run_id: str,
        kind: str,
        aggregate_type: str,
        aggregate_id: str,
        payload: Mapping[str, Any],
        topic: str | None = "state.changed",
        connection: sqlite3.Connection | None = None,
    ) -> EventRecord:
        if connection is None:
            with self.database.transaction() as transaction:
                return self.append(
                    run_id=run_id,
                    kind=kind,
                    aggregate_type=aggregate_type,
                    aggregate_id=aggregate_id,
                    payload=payload,
                    topic=topic,
                    connection=transaction,
                )

        tail = connection.execute(
            """
            SELECT sequence, event_hash FROM events
             WHERE run_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        sequence = int(tail["sequence"]) + 1 if tail else 1
        previous_hash = str(tail["event_hash"]) if tail else GENESIS_HASH
        event_id = new_id("evt")
        created_at = self.clock.utc_now()
        envelope: dict[str, Any] = {
            "id": event_id,
            "run_id": run_id,
            "sequence": sequence,
            "kind": kind,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "payload": payload,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }
        event_hash = canonical_digest(envelope)
        connection.execute(
            """
            INSERT INTO events(
                id, run_id, sequence, kind, aggregate_type, aggregate_id,
                payload_json, created_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                run_id,
                sequence,
                kind,
                aggregate_type,
                aggregate_id,
                canonical_json(payload),
                _iso(created_at),
                previous_hash,
                event_hash,
            ),
        )
        event = EventRecord(**envelope, event_hash=event_hash)
        if topic is not None:
            outbox_id = new_id("out")
            connection.execute(
                """
                INSERT INTO outbox(
                    id, run_id, event_id, topic, payload_json, state, attempts,
                    available_at, created_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', 0, ?, ?)
                """,
                (
                    outbox_id,
                    run_id,
                    event_id,
                    topic,
                    canonical_json({"event_id": event_id, "sequence": sequence}),
                    _iso(created_at),
                    _iso(created_at),
                ),
            )
        return event

    def list_events(self, run_id: str, *, after_sequence: int = 0) -> list[EventRecord]:
        with self.database.connection(readonly=True) as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE run_id = ? AND sequence > ? ORDER BY sequence",
                (run_id, int(after_sequence)),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def head(self, run_id: str) -> EventRecord | None:
        with self.database.connection(readonly=True) as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE run_id = ? ORDER BY sequence DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        return self._event_from_row(row) if row else None

    def verify_chain(self, run_id: str) -> str:
        expected_previous = GENESIS_HASH
        expected_sequence = 1
        for event in self.list_events(run_id):
            if event.sequence != expected_sequence:
                raise IntegrityError(
                    f"event sequence gap: expected {expected_sequence}, got {event.sequence}"
                )
            if not hmac.compare_digest(event.previous_hash, expected_previous):
                raise IntegrityError(f"event {event.id} has an invalid previous hash")
            envelope = {
                "id": event.id,
                "run_id": event.run_id,
                "sequence": event.sequence,
                "kind": event.kind,
                "aggregate_type": event.aggregate_type,
                "aggregate_id": event.aggregate_id,
                "payload": event.payload,
                "created_at": event.created_at,
                "previous_hash": event.previous_hash,
            }
            expected_hash = canonical_digest(envelope)
            if not hmac.compare_digest(event.event_hash, expected_hash):
                raise IntegrityError(f"event {event.id} hash is invalid")
            expected_previous = event.event_hash
            expected_sequence += 1
        return expected_previous

    def claim_outbox(
        self,
        *,
        limit: int = 100,
        stale_after: timedelta = timedelta(minutes=5),
    ) -> list[OutboxRecord]:
        if limit < 1:
            raise ValidationError("outbox claim limit must be positive")
        now = self.clock.utc_now()
        stale = now - stale_after
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE outbox
                   SET state = 'FAILED', locked_at = NULL,
                       last_error = COALESCE(last_error, 'claim expired')
                 WHERE state = 'CLAIMED' AND locked_at < ?
                """,
                (_iso(stale),),
            )
            rows = connection.execute(
                """
                SELECT * FROM outbox
                 WHERE state IN ('PENDING','FAILED') AND available_at <= ?
                 ORDER BY available_at, id LIMIT ?
                """,
                (_iso(now), int(limit)),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                connection.execute(
                    f"""
                    UPDATE outbox
                       SET state = 'CLAIMED', attempts = attempts + 1, locked_at = ?
                     WHERE id IN ({placeholders})
                    """,
                    (_iso(now), *ids),
                )
                rows = connection.execute(
                    f"SELECT * FROM outbox WHERE id IN ({placeholders}) ORDER BY available_at, id",
                    ids,
                ).fetchall()
        return [self._outbox_from_row(row) for row in rows]

    def mark_outbox_published(self, outbox_id: str) -> None:
        now = self.clock.utc_now()
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE outbox
                   SET state = 'PUBLISHED', published_at = ?, locked_at = NULL
                 WHERE id = ? AND state = 'CLAIMED'
                """,
                (_iso(now), outbox_id),
            )
            if cursor.rowcount != 1:
                raise ValidationError(f"outbox record {outbox_id} is not claimed")

    def mark_outbox_failed(
        self,
        outbox_id: str,
        error: str,
        *,
        retry_at: datetime | None = None,
        dead_after_attempts: int = 10,
    ) -> None:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT attempts, state FROM outbox WHERE id = ?", (outbox_id,)
            ).fetchone()
            if row is None or row["state"] != OutboxState.CLAIMED.value:
                raise ValidationError(f"outbox record {outbox_id} is not claimed")
            state = "DEAD" if int(row["attempts"]) >= dead_after_attempts else "FAILED"
            available = retry_at or self.clock.utc_now()
            connection.execute(
                """
                UPDATE outbox
                   SET state = ?, available_at = ?, locked_at = NULL, last_error = ?
                 WHERE id = ?
                """,
                (state, _iso(available), error[:1000], outbox_id),
            )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            id=row["id"],
            run_id=row["run_id"],
            sequence=row["sequence"],
            kind=row["kind"],
            aggregate_type=row["aggregate_type"],
            aggregate_id=row["aggregate_id"],
            payload=_loads(row["payload_json"]),
            created_at=row["created_at"],
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )

    @staticmethod
    def _outbox_from_row(row: sqlite3.Row) -> OutboxRecord:
        return OutboxRecord(
            id=row["id"],
            run_id=row["run_id"],
            event_id=row["event_id"],
            topic=row["topic"],
            payload=_loads(row["payload_json"]),
            state=row["state"],
            attempts=row["attempts"],
            available_at=row["available_at"],
            locked_at=row["locked_at"],
            published_at=row["published_at"],
            last_error=row["last_error"],
            created_at=row["created_at"],
        )
