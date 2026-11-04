from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import canonical_bytes, strict_json


class MeshLedger:
    """Durable request reservations; an ambiguous command is never auto-replayed."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS mesh_requests (
                request_id TEXT PRIMARY KEY, subject_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('reserved','complete')),
                response_json TEXT, authorization_id TEXT NOT NULL DEFAULT '')""")
            db.execute("""CREATE TABLE IF NOT EXISTS mesh_sinks (
                sink_id TEXT PRIMARY KEY, contract_digest TEXT NOT NULL,
                source_id TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0,
                receipt_digest TEXT NOT NULL DEFAULT '')""")
            db.execute("""CREATE TABLE IF NOT EXISTS mesh_outbox (
                sink_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                event_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0,
                lease_token TEXT NOT NULL DEFAULT '', last_status INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(sink_id, sequence))""")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(
        self, request_id: str, subject_digest: str
    ) -> tuple[str, dict[str, Any] | None]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM mesh_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if row:
                if row["subject_digest"] != subject_digest:
                    return "conflict", None
                if row["state"] == "complete":
                    return "complete", strict_json(row["response_json"].encode())
                return "reserved", None
            db.execute(
                "INSERT INTO mesh_requests(request_id,subject_digest,state) VALUES(?,?,?)",
                (request_id, subject_digest, "reserved"),
            )
        return "new", None

    def authorized(self, request_id: str, receipt_id: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE mesh_requests SET authorization_id=? WHERE request_id=? AND state=?",
                (receipt_id, request_id, "reserved"),
            )

    def complete(self, request_id: str, response: dict[str, Any]) -> None:
        raw = canonical_bytes(response).decode()
        with self.connect() as db:
            changed = db.execute(
                "UPDATE mesh_requests SET state=?, response_json=? WHERE request_id=? AND state=?",
                ("complete", raw, request_id, "reserved"),
            ).rowcount
            if changed != 1:
                raise ValueError("Request reservation cannot be completed twice.")

    def inspect_request(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT request_id,subject_digest,state,authorization_id FROM mesh_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            return dict(row) if row else None

    def status(self) -> dict[str, Any]:
        with self.connect() as db:
            requests = dict(
                db.execute(
                    "SELECT state,COUNT(*) FROM mesh_requests GROUP BY state"
                ).fetchall()
            )
            outbox = dict(
                db.execute(
                    "SELECT state,COUNT(*) FROM mesh_outbox GROUP BY state"
                ).fetchall()
            )
            sinks = [
                dict(row)
                for row in db.execute("SELECT * FROM mesh_sinks ORDER BY sink_id")
            ]
        return {"requests": requests, "outbox": outbox, "audit_cursors": sinks}
