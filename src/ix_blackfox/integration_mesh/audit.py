from __future__ import annotations

import secrets
import time
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    digest,
    strict_json,
)
from ix_blackfox.integration_mesh.config import AuditSink, MeshConfig
from ix_blackfox.integration_mesh.ledger import MeshLedger
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.upstream import UpstreamTransportError, request_upstream


def receipt_event(record: dict[str, Any], source_id: str) -> dict[str, Any]:
    return {
        "specversion": "1.0",
        "id": record["receipt_id"],
        "source": f"urn:ix-blackfox:authority:{source_id}",
        "type": "io.ix-blackfox.authority." + record["record_type"],
        "time": record["recorded_at"],
        "datacontenttype": "application/json",
        "subject": record["subject"].get("tool_name", ""),
        "data": record,
    }


class AuditRelay:
    """Ordered, durable, at-least-once delivery of signed receipt CloudEvents."""

    def __init__(self, config: MeshConfig, receipts: AuthorityReceiptStore) -> None:
        self.config = config
        self.receipts = receipts
        self.ledger = MeshLedger(config.database)

    def sync(self, sink: AuditSink, limit: int = 100) -> int:
        if self.receipts.signing is None:
            raise AuthorityProofError("Audit relay requires a signed receipt stream.")
        policy = self.receipts.signing.current_policy()
        source_id = digest(
            {"deployment": policy.deployment_id, "stream": policy.stream_id}
        )
        # Serialize concurrent sync workers; no network or signing runs in this transaction.
        with self.ledger.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO mesh_sinks(sink_id,contract_digest,source_id) VALUES(?,?,?)",
                (sink.sink_id, sink.contract_digest, source_id),
            )
            row = db.execute(
                "SELECT * FROM mesh_sinks WHERE sink_id=?", (sink.sink_id,)
            ).fetchone()
            assert row is not None
            if (row["contract_digest"], row["source_id"]) != (
                sink.contract_digest,
                source_id,
            ):
                raise AuthorityProofError(
                    "Sink contract or source changed; provision a new sink_id."
                )
            after = int(row["sequence"])
            records = self.receipts.verified_page(after, limit)
            if after:
                retained = self.receipts.verified_page(after - 1, 1)
                if (
                    not retained
                    or retained[0]["receipt_digest"] != row["receipt_digest"]
                ):
                    raise AuthorityProofError(
                        "Signed source does not extend the retained audit cursor."
                    )
            previous = row["receipt_digest"]
            for record in records:
                if record["previous_receipt_digest"] != previous:
                    raise AuthorityProofError(
                        "Source receipt linkage differs from audit cursor."
                    )
                event = receipt_event(record, source_id)
                db.execute(
                    "INSERT INTO mesh_outbox(sink_id,sequence,event_json) VALUES(?,?,?)",
                    (sink.sink_id, record["sequence"], canonical_bytes(event).decode()),
                )
                previous = record["receipt_digest"]
            if records:
                db.execute(
                    "UPDATE mesh_sinks SET sequence=?,receipt_digest=? WHERE sink_id=?",
                    (records[-1]["sequence"], previous, sink.sink_id),
                )
        return len(records)

    def deliver_one(
        self, sink: AuditSink, *, now: float | None = None
    ) -> dict[str, Any]:
        current = time.time() if now is None else now
        # Resolve secrets before taking a lease; secrets are never stored in the outbox.
        headers = sink.headers()
        token = secrets.token_hex(16)
        with self.ledger.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            contract = db.execute(
                "SELECT contract_digest FROM mesh_sinks WHERE sink_id=?",
                (sink.sink_id,),
            ).fetchone()
            if contract is None or contract[0] != sink.contract_digest:
                raise AuthorityProofError(
                    "Audit sink has not been synced with this contract."
                )
            row = db.execute(
                "SELECT * FROM mesh_outbox WHERE sink_id=? AND state != 'delivered' ORDER BY sequence LIMIT 1",
                (sink.sink_id,),
            ).fetchone()
            if row is None:
                return {"state": "idle"}
            if row["state"] == "dead":
                return {"state": "dead", "sequence": row["sequence"]}
            if row["due"] > current:
                return {"state": "waiting", "sequence": row["sequence"]}
            if row["attempts"] >= sink.max_attempts:
                db.execute(
                    "UPDATE mesh_outbox SET state='dead' WHERE sink_id=? AND sequence=?",
                    (sink.sink_id, row["sequence"]),
                )
                return {"state": "dead", "sequence": row["sequence"]}
            sequence, attempts = int(row["sequence"]), int(row["attempts"]) + 1
            # Lease exceeds the configured network timeout. A stalled/dead process can cause
            # a duplicate after expiry; receivers deduplicate the stable event id.
            db.execute(
                "UPDATE mesh_outbox SET state='leased',attempts=?,due=?,lease_token=? WHERE sink_id=? AND sequence=?",
                (
                    attempts,
                    current + self.config.timeout_seconds + 30,
                    token,
                    sink.sink_id,
                    sequence,
                ),
            )
            raw = row["event_json"].encode()
        event = strict_json(raw)
        if self.receipts.signing is None:
            raise AuthorityProofError("Signed audit policy unavailable.")
        # Detect stored-event mutation before sending to an external sink.
        from ix_blackfox.authority_crypto.verification import verify_receipt

        record = event.get("data")
        if not isinstance(record, dict):
            raise AuthorityProofError("Audit event has no signed receipt.")
        verify_receipt(record, self.receipts.signing.current_policy())
        policy = self.receipts.signing.current_policy()
        source_id = digest(
            {"deployment": policy.deployment_id, "stream": policy.stream_id}
        )
        if (
            canonical_bytes(event) != canonical_bytes(receipt_event(record, source_id))
            or record["sequence"] != sequence
        ):
            raise AuthorityProofError("Audit envelope differs from its signed receipt.")
        headers["Idempotency-Key"] = event["id"]
        status = 0
        retry_after = ""
        try:
            response = request_upstream(
                url=sink.url,
                method="POST",
                headers=headers,
                body=raw,
                timeout_seconds=self.config.timeout_seconds,
                max_response_bytes=64 * 1024,
            )
            status = response.status
            retry_after = response.header("Retry-After")
        except UpstreamTransportError:
            pass
        if 200 <= status < 300:
            state, due = "delivered", 0.0
        elif (
            status in {0, 408, 429} or 500 <= status < 600
        ) and attempts < sink.max_attempts:
            delay = min(300, 2 ** min(attempts, 8))
            if retry_after.isascii() and retry_after.isdecimal():
                delay = max(delay, min(3600, int(retry_after[:8])))
            state, due = "pending", current + delay
        else:
            state, due = "dead", 0.0
        with self.ledger.connect() as db:
            changed = db.execute(
                "UPDATE mesh_outbox SET state=?,due=?,last_status=?,lease_token=? WHERE sink_id=? AND sequence=? AND lease_token=?",
                (state, due, status, "", sink.sink_id, sequence, token),
            ).rowcount
        return {
            "state": state if changed else "lease_lost",
            "sequence": sequence,
            "attempts": attempts,
            "status": status,
        }

    def requeue(self, sink: AuditSink, sequence: int) -> None:
        """Operator-only retry of audit delivery; this cannot re-execute commands."""
        with self.ledger.connect() as db:
            contract = db.execute(
                "SELECT contract_digest FROM mesh_sinks WHERE sink_id=?",
                (sink.sink_id,),
            ).fetchone()
            if contract is None or contract[0] != sink.contract_digest:
                raise AuthorityProofError("Audit sink contract changed.")
            changed = db.execute(
                "UPDATE mesh_outbox SET state='pending',attempts=0,due=0 WHERE sink_id=? AND sequence=? AND state='dead'",
                (sink.sink_id, sequence),
            ).rowcount
            if changed != 1:
                raise ValueError("Only a dead audit event can be requeued.")
