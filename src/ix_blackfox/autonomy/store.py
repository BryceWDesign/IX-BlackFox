from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import canonical_bytes, strict_json
from ix_blackfox.autonomy.contracts import OperationError


class OperationStore:
    """Transactional operation snapshots and a retained transition journal."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=15)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY, state TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operation_events (
                    seq INTEGER PRIMARY KEY, operation_id TEXT NOT NULL, event TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS operation_event_index
                    ON operation_events(operation_id, seq);
            """)

    def ready(self) -> bool:
        try:
            with self.transaction(write=False) as db:
                db.execute("SELECT operation_id FROM operations LIMIT 0")
                db.execute("SELECT event FROM operation_events LIMIT 0")
        except (OSError, sqlite3.Error):
            return False
        return True

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        with closing(
            sqlite3.connect(self.path, timeout=15, isolation_level=None)
        ) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def load(db: sqlite3.Connection, operation_id: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT state FROM operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise OperationError("Operation not found.", 404)
        return strict_json(row[0].encode())

    @staticmethod
    def save(
        db: sqlite3.Connection, state: dict[str, Any], event: str, **details: Any
    ) -> None:
        op = state["plan"]["operation_id"]
        db.execute(
            "INSERT INTO operations VALUES (?, ?) ON CONFLICT(operation_id) DO UPDATE SET state=excluded.state",
            (op, canonical_bytes(state).decode()),
        )
        db.execute(
            "INSERT INTO operation_events(operation_id,event) VALUES (?,?)",
            (
                op,
                canonical_bytes(
                    {"event": event, "at": datetime.now(UTC).isoformat(), **details}
                ).decode(),
            ),
        )

    @staticmethod
    def events(
        db: sqlite3.Connection, operation_id: str, after: int
    ) -> list[dict[str, Any]]:
        return [
            {"sequence": seq, **strict_json(event.encode())}
            for seq, event in db.execute(
                "SELECT seq,event FROM operation_events WHERE operation_id=? AND seq>? ORDER BY seq LIMIT 50",
                (operation_id, after),
            )
        ]
