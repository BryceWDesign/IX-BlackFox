from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.live_gateway.models import WAVE14_RECEIPT_SCHEMA_VERSION
from ix_blackfox.operating.models import digest_payload


@dataclass(frozen=True, slots=True)
class ReceiptChainVerification:
    """Verification report for the durable Wave 14 receipt chain."""

    passed: bool
    receipt_count: int
    head_digest: str
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "receipt_count": self.receipt_count,
            "head_digest": self.head_digest,
            "issue_count": len(self.issues),
            "issues": list(self.issues),
        }


@dataclass(slots=True)
class AuthorityReceiptStore:
    """SQLite-backed, transactionally hash-chained Wave 14 authority receipts."""

    path: Path

    def __post_init__(self) -> None:
        self.path = self.path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT sequence, receipt_digest FROM receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if row is None else int(row[0]) + 1
            previous_digest = "" if row is None else str(row[1])
            receipt: dict[str, Any] = {
                "schema_version": WAVE14_RECEIPT_SCHEMA_VERSION,
                "sequence": sequence,
                "previous_receipt_digest": previous_digest,
                **payload,
            }
            digest = digest_payload(receipt)
            receipt_id = f"wave14-receipt-{digest[:24]}"
            receipt["receipt_id"] = receipt_id
            receipt["receipt_digest"] = digest_payload(
                {key: value for key, value in receipt.items() if key != "receipt_digest"}
            )
            body = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            connection.execute(
                "INSERT INTO receipts(sequence, receipt_id, receipt_digest, previous_digest, payload_json) VALUES (?, ?, ?, ?, ?)",
                (
                    sequence,
                    receipt_id,
                    receipt["receipt_digest"],
                    previous_digest,
                    body,
                ),
            )
            connection.commit()
            return receipt

    def claim_single_use_evidence(
        self,
        evidence_ids: tuple[str, ...],
        *,
        subject_digest: str,
        claimed_at: str,
    ) -> tuple[str, ...]:
        """Atomically reserve single-use evidence before any upstream side effect.

        A non-empty return value lists evidence ids that were already claimed. No
        new claim is inserted when any requested id conflicts.
        """

        unique_ids = tuple(dict.fromkeys(evidence_ids))
        if not unique_ids:
            return ()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in unique_ids)
            rows = connection.execute(
                f"SELECT evidence_id FROM evidence_claims WHERE evidence_id IN ({placeholders})",
                unique_ids,
            ).fetchall()
            conflicts = tuple(sorted(str(row[0]) for row in rows))
            if conflicts:
                connection.rollback()
                return conflicts
            for evidence_id in unique_ids:
                claim_digest = digest_payload(
                    {
                        "evidence_id": evidence_id,
                        "subject_digest": subject_digest,
                        "claimed_at": claimed_at,
                    }
                )
                connection.execute(
                    "INSERT INTO evidence_claims(evidence_id, subject_digest, claimed_at, claim_digest) VALUES (?, ?, ?, ?)",
                    (evidence_id, subject_digest, claimed_at, claim_digest),
                )
            connection.commit()
        return ()

    def get(self, receipt_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row[0]))
        return dict(payload) if isinstance(payload, dict) else None

    def recent(self, limit: int = 50) -> tuple[dict[str, Any], ...]:
        if limit <= 0 or limit > 1000:
            raise ValueError("Receipt limit must be between 1 and 1000.")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM receipts ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(str(row[0]))
            if isinstance(payload, dict):
                result.append(dict(payload))
        return tuple(result)

    def verify_chain(self) -> ReceiptChainVerification:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, receipt_id, receipt_digest, previous_digest, payload_json FROM receipts ORDER BY sequence"
            ).fetchall()
            claim_rows = connection.execute(
                "SELECT evidence_id, subject_digest, claimed_at, claim_digest FROM evidence_claims ORDER BY evidence_id"
            ).fetchall()

        issues: list[str] = []
        previous = ""
        expected_sequence = 1
        receipt_claims: dict[str, str] = {}
        for row in rows:
            sequence = int(row[0])
            receipt_id = str(row[1])
            stored_digest = str(row[2])
            stored_previous = str(row[3])
            try:
                payload = json.loads(str(row[4]))
            except json.JSONDecodeError:
                issues.append(f"receipt {receipt_id}: payload is invalid JSON")
                continue
            if not isinstance(payload, dict):
                issues.append(f"receipt {receipt_id}: payload is not an object")
                continue
            if sequence != expected_sequence:
                issues.append(f"receipt {receipt_id}: sequence gap or reordering")
            if stored_previous != previous or payload.get("previous_receipt_digest") != previous:
                issues.append(f"receipt {receipt_id}: previous digest mismatch")
            if payload.get("receipt_id") != receipt_id:
                issues.append(f"receipt {receipt_id}: id mismatch")
            claimed = str(payload.get("receipt_digest", ""))
            recomputed = digest_payload(
                {key: value for key, value in payload.items() if key != "receipt_digest"}
            )
            if stored_digest != claimed or claimed != recomputed:
                issues.append(f"receipt {receipt_id}: digest mismatch")
            raw_claims = payload.get("single_use_evidence_claims", [])
            if not isinstance(raw_claims, list) or any(not isinstance(item, str) for item in raw_claims):
                issues.append(f"receipt {receipt_id}: single-use evidence claims are malformed")
            else:
                subject = payload.get("subject", {})
                subject_digest = subject.get("digest", "") if isinstance(subject, dict) else ""
                for evidence_id in raw_claims:
                    prior = receipt_claims.setdefault(evidence_id, str(subject_digest))
                    if prior != str(subject_digest):
                        issues.append(f"receipt {receipt_id}: evidence claim appears under multiple subjects")
            previous = stored_digest
            expected_sequence += 1

        database_claims: dict[str, str] = {}
        for evidence_id_raw, subject_digest_raw, claimed_at_raw, claim_digest_raw in claim_rows:
            evidence_id = str(evidence_id_raw)
            subject_digest = str(subject_digest_raw)
            claimed_at = str(claimed_at_raw)
            claim_digest = str(claim_digest_raw)
            expected_claim_digest = digest_payload(
                {
                    "evidence_id": evidence_id,
                    "subject_digest": subject_digest,
                    "claimed_at": claimed_at,
                }
            )
            if claim_digest != expected_claim_digest:
                issues.append(f"evidence claim {evidence_id}: digest mismatch")
            database_claims[evidence_id] = subject_digest

        for evidence_id, subject_digest in receipt_claims.items():
            if database_claims.get(evidence_id) != subject_digest:
                issues.append(f"evidence claim {evidence_id}: receipt/database claim mismatch")
        return ReceiptChainVerification(
            passed=not issues,
            receipt_count=len(rows),
            head_digest=previous,
            issues=tuple(issues),
        )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    sequence INTEGER PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE,
                    receipt_digest TEXT NOT NULL,
                    previous_digest TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_claims (
                    evidence_id TEXT PRIMARY KEY,
                    subject_digest TEXT NOT NULL,
                    claimed_at TEXT NOT NULL,
                    claim_digest TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection
