from __future__ import annotations

import json
import sqlite3
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    RECEIPT_TYPE,
    AuthorityProofError,
    canonical_bytes,
    digest,
    strict_json,
)
from ix_blackfox.authority_crypto.signing import SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy, fingerprint
from ix_blackfox.authority_crypto.verification import (
    BUNDLE_SCHEMA,
    RECEIPT_SCHEMA,
    VerifiedStreamState,
    checkpoint_body,
    replay_records,
    verify_records,
)
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


@dataclass(slots=True, weakref_slot=True)
class AuthorityReceiptStore:
    """SQLite-backed, transactionally hash-chained Wave 14 authority receipts."""

    path: Path
    signing: SigningController | None = None
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False
    )
    _connection: sqlite3.Connection | None = field(default=None, init=False, repr=False)
    _finalizer: weakref.finalize[[], AuthorityReceiptStore] | None = field(
        default=None, init=False, repr=False
    )
    _state: VerifiedStreamState | None = field(default=None, init=False, repr=False)
    _generation: int = field(default=-1, init=False, repr=False)
    _policy_digest: str = field(default="", init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = self.path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.signing is not None:
            # data_version is comparable only on the SAME connection. All local
            # writes use this connection so every other writer invalidates cache.
            self._connection = sqlite3.connect(
                self.path, timeout=10.0, check_same_thread=False
            )
            self._finalizer = weakref.finalize(self, self._connection.close)
        try:
            self._initialize()
            if self.signing is not None:
                with self._connect() as connection:
                    connection.execute("BEGIN")
                    self._refresh_state(connection, self.signing.current_policy())
        except Exception:
            self.close()
            raise

    @staticmethod
    def _policy_token(policy: TrustPolicy) -> str:
        return digest(
            {
                "deployment": policy.deployment_id,
                "stream": policy.stream_id,
                "expires": policy.expires_at.isoformat(),
                "skew": policy.clock_skew_seconds,
                "keys": [
                    [
                        key.key_id,
                        key.algorithm,
                        fingerprint(key.key),
                        key.not_before.isoformat(),
                        key.not_after.isoformat(),
                        key.revoked,
                    ]
                    for key in policy.keys
                ],
            }
        )

    def _refresh_state(
        self, connection: sqlite3.Connection, policy: TrustPolicy
    ) -> VerifiedStreamState:
        generation = int(connection.execute("PRAGMA data_version").fetchone()[0])
        token = self._policy_token(policy)
        if (
            self._state is None
            or generation != self._generation
            or token != self._policy_digest
        ):
            records = self._signed_records(connection)
            state = replay_records(records, policy)
            if self._state is not None and (
                state.sequence < self._state.sequence
                or (
                    self._state.sequence
                    and records[self._state.sequence - 1]["receipt_digest"]
                    != self._state.head
                )
            ):
                raise AuthorityProofError(
                    "Database no longer extends the verified head."
                )
            self._state = state
            self._generation = generation
            self._policy_digest = token
        return self._state

    def _make_receipt(
        self, payload: dict[str, Any], sequence: int, previous: str
    ) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "schema_version": WAVE14_RECEIPT_SCHEMA_VERSION,
            "sequence": sequence,
            "previous_receipt_digest": previous,
            **payload,
        }
        if self.signing is not None:
            reserved = {
                "schema_version",
                "sequence",
                "previous_receipt_digest",
                "receipt_id",
                "receipt_digest",
                "attestation",
                "deployment_id",
                "stream_id",
            }
            if reserved.intersection(payload):
                raise AuthorityProofError("Payload overrides reserved receipt fields.")
            policy = self.signing.current_policy()
            receipt.update(
                schema_version=RECEIPT_SCHEMA,
                deployment_id=policy.deployment_id,
                stream_id=policy.stream_id,
            )
            receipt_id = "wave16-receipt-" + digest(receipt)
        else:
            receipt_id = "wave14-receipt-" + digest_payload(receipt)[:24]
        receipt["receipt_id"] = receipt_id
        receipt["receipt_digest"] = (
            digest if self.signing is not None else digest_payload
        )(receipt)
        if self.signing is not None:
            receipt["attestation"] = self.signing.envelope(RECEIPT_TYPE, dict(receipt))
        return receipt

    @staticmethod
    def _insert(connection: sqlite3.Connection, receipt: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO receipts(sequence, receipt_id, receipt_digest, previous_digest, payload_json) VALUES (?, ?, ?, ?, ?)",
            (
                receipt["sequence"],
                receipt["receipt_id"],
                receipt["receipt_digest"],
                receipt["previous_receipt_digest"],
                json.dumps(
                    receipt,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ),
            ),
        )

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            if self.signing is None:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT sequence, receipt_digest FROM receipts ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                receipt = self._make_receipt(
                    payload,
                    1 if row is None else int(row[0]) + 1,
                    "" if row is None else str(row[1]),
                )
                self._insert(connection, receipt)
                connection.commit()
                return receipt
            # Serialize local callers, but do not hold a SQLite writer/read lock
            # while a remote signer is performing network I/O.
            for _ in range(16):
                connection.execute("BEGIN")
                policy = self.signing.current_policy()
                state = self._refresh_state(connection, policy)
                generation, token = self._generation, self._policy_digest
                connection.rollback()
                receipt = self._make_receipt(payload, state.sequence + 1, state.head)
                body = state.validate(receipt, self.signing.current_policy())
                connection.execute("BEGIN IMMEDIATE")
                if (
                    int(connection.execute("PRAGMA data_version").fetchone()[0])
                    != generation
                    or self._policy_token(self.signing.current_policy()) != token
                ):
                    connection.rollback()
                    continue
                self._insert(connection, receipt)
                connection.commit()
                # Return data must not alias the private state retained for parent
                # linkage. verify_receipt returns a detached signed body.
                state.advance(body)
                return receipt
            raise AuthorityProofError(
                "Receipt stream changed repeatedly during signing; append refused."
            )

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
            connection.execute("BEGIN")
            rows = connection.execute(
                "SELECT sequence, receipt_id, receipt_digest, previous_digest, payload_json FROM receipts ORDER BY sequence"
            ).fetchall()
            claim_rows = connection.execute(
                "SELECT evidence_id, subject_digest, claimed_at, claim_digest FROM evidence_claims ORDER BY evidence_id"
            ).fetchall()

        issues: list[str] = []
        if self.signing is not None:
            try:
                verify_records(
                    [strict_json(str(row[4]).encode("utf-8")) for row in rows],
                    self.signing.current_policy(),
                )
            except (AuthorityProofError, KeyError, TypeError, OSError) as exc:
                return ReceiptChainVerification(False, len(rows), "", (str(exc),))
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
            if (
                stored_previous != previous
                or payload.get("previous_receipt_digest") != previous
            ):
                issues.append(f"receipt {receipt_id}: previous digest mismatch")
            if payload.get("receipt_id") != receipt_id:
                issues.append(f"receipt {receipt_id}: id mismatch")
            if payload.get("sequence") != sequence:
                issues.append(f"receipt {receipt_id}: payload sequence mismatch")
            claimed = str(payload.get("receipt_digest", ""))
            recomputed = (digest if self.signing is not None else digest_payload)(
                {
                    key: value
                    for key, value in payload.items()
                    if key
                    not in (
                        {"receipt_digest", "attestation"}
                        if self.signing is not None
                        else {"receipt_digest"}
                    )
                }
            )
            if stored_digest != claimed or claimed != recomputed:
                issues.append(f"receipt {receipt_id}: digest mismatch")
            raw_claims = payload.get("single_use_evidence_claims", [])
            if not isinstance(raw_claims, list) or any(
                not isinstance(item, str) for item in raw_claims
            ):
                issues.append(
                    f"receipt {receipt_id}: single-use evidence claims are malformed"
                )
            else:
                subject = payload.get("subject", {})
                subject_digest = (
                    subject.get("digest", "") if isinstance(subject, dict) else ""
                )
                for evidence_id in raw_claims:
                    prior = receipt_claims.setdefault(evidence_id, str(subject_digest))
                    if prior != str(subject_digest):
                        issues.append(
                            f"receipt {receipt_id}: evidence claim appears under multiple subjects"
                        )
            previous = stored_digest
            expected_sequence += 1

        database_claims: dict[str, str] = {}
        for (
            evidence_id_raw,
            subject_digest_raw,
            claimed_at_raw,
            claim_digest_raw,
        ) in claim_rows:
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
                issues.append(
                    f"evidence claim {evidence_id}: receipt/database claim mismatch"
                )
        return ReceiptChainVerification(
            passed=not issues,
            receipt_count=len(rows),
            head_digest=previous,
            issues=tuple(issues),
        )

    def _signed_records(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT sequence, receipt_id, receipt_digest, previous_digest, payload_json FROM receipts ORDER BY sequence"
        ).fetchall()
        records = []
        for sequence, receipt_id, receipt_digest, previous, raw in rows:
            record = strict_json(str(raw).encode("utf-8"))
            if canonical_bytes(
                [sequence, receipt_id, receipt_digest, previous]
            ) != canonical_bytes(
                [
                    record.get("sequence"),
                    record.get("receipt_id"),
                    record.get("receipt_digest"),
                    record.get("previous_receipt_digest"),
                ]
            ):
                raise AuthorityProofError(
                    "Receipt database index differs from signed payload."
                )
            records.append(record)
        return records

    def verified_page(
        self, after: int = 0, limit: int = 100
    ) -> tuple[dict[str, Any], ...]:
        """Read a bounded signed-stream page from a verified SQLite snapshot."""
        if self.signing is None or after < 0 or not 1 <= limit <= 1000:
            raise AuthorityProofError(
                "Signed page requires signing, a nonnegative cursor and bounded limit."
            )
        with self._connect() as connection:
            connection.execute("BEGIN")
            state = self._refresh_state(connection, self.signing.current_policy())
            if after > state.sequence:
                raise AuthorityProofError(
                    "Audit cursor is ahead of the signed source stream."
                )
            rows = connection.execute(
                "SELECT payload_json FROM receipts WHERE sequence > ? ORDER BY sequence LIMIT ?",
                (after, limit),
            ).fetchall()
            return tuple(strict_json(str(row[0]).encode("utf-8")) for row in rows)

    def export_bundle(self) -> dict[str, Any]:
        if self.signing is None:
            raise AuthorityProofError(
                "Unsigned historical receipts cannot be exported as Wave 16."
            )
        with self._connect() as connection:
            connection.execute("BEGIN")
            records = self._signed_records(connection)
            policy = self.signing.current_policy()
            verify_records(records, policy)
            checkpoint = self.signing.envelope(
                CHECKPOINT_TYPE, checkpoint_body(records, policy)
            )
            return {
                "schema_version": BUNDLE_SCHEMA,
                "deployment_id": policy.deployment_id,
                "stream_id": policy.stream_id,
                "receipts": records,
                "checkpoint": checkpoint,
            }

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

    def close(self) -> None:
        """Release the signed-store observer, including its Windows file handle."""
        with self._lock:
            if self._finalizer is not None:
                self._finalizer()
            self._connection = None
            self._state = None
            self._closed = True

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise AuthorityProofError("Receipt store is closed.")
            connection = self._connection or sqlite3.connect(self.path, timeout=10.0)
            try:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA synchronous=FULL")
                yield connection
            finally:
                if connection.in_transaction:
                    connection.rollback()
                if self._connection is None:
                    connection.close()
