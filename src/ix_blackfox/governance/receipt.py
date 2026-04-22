from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from threading import RLock
from typing import Any
from uuid import uuid4


class ReceiptEventType(StrEnum):
    """
    High-level governed execution events captured by receipts.
    """

    POLICY_ALLOWED = auto()
    POLICY_REVIEW_REQUIRED = auto()
    POLICY_BLOCKED = auto()
    APPROVAL_RECORDED = auto()
    APPROVAL_REJECTED = auto()
    EXECUTION_STARTED = auto()
    EXECUTION_COMPLETED = auto()
    EXECUTION_FAILED = auto()
    VERIFICATION_PASSED = auto()
    VERIFICATION_FAILED = auto()


@dataclass(frozen=True, slots=True)
class GovernanceReceiptRecord:
    """
    One chained governance receipt bound to an action intent.

    Attributes
    ----------
    receipt_id:
        Stable unique receipt identifier.
    intent_id:
        Action-intent identifier this receipt belongs to.
    event_type:
        Canonical governed execution event.
    summary:
        Short human-readable summary of the event.
    previous_receipt_id:
        Prior receipt identifier in the same intent chain, if any.
    previous_chain_digest:
        Prior chain digest in the same intent chain, if any.
    chain_digest:
        Tamper-evident chain digest for this receipt.
    created_at:
        UTC timestamp when the receipt was created.
    actor:
        Optional actor or subsystem label that emitted the receipt.
    metadata:
        Optional structured metadata payload.
    """

    receipt_id: str
    intent_id: str
    event_type: ReceiptEventType
    summary: str
    previous_receipt_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    actor: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_identifier(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "intent_id",
            _normalize_identifier(self.intent_id, label="intent_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "actor", _normalize_optional_text(self.actor))


@dataclass(frozen=True, slots=True)
class GovernanceReceiptLedgerSnapshot:
    """
    Immutable view of governance receipt records.
    """

    records: tuple[GovernanceReceiptRecord, ...]

    def filter_by_intent(self, intent_id: str) -> tuple[GovernanceReceiptRecord, ...]:
        """
        Return all receipts for one action intent in creation order.
        """
        normalized_intent_id = _normalize_identifier(intent_id, label="intent_id")
        return tuple(
            record for record in self.records if record.intent_id == normalized_intent_id
        )

    def latest_for_intent(self, intent_id: str) -> GovernanceReceiptRecord | None:
        """
        Return the latest receipt for one action intent.
        """
        records = self.filter_by_intent(intent_id)
        if not records:
            return None
        return records[-1]


class GovernanceReceiptLedger:
    """
    Thread-safe chained ledger for governed execution receipts.

    Receipt chains make policy, approval, execution, and verification
    events auditable per action intent, with tamper-evident digests
    linking each successive record.
    """

    def __init__(self) -> None:
        self._records: list[GovernanceReceiptRecord] = []
        self._lock = RLock()

    def append(
        self,
        *,
        intent_id: str,
        event_type: ReceiptEventType,
        summary: str,
        actor: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GovernanceReceiptRecord:
        """
        Append a new receipt to an intent-specific chain.
        """
        normalized_intent_id = _normalize_identifier(intent_id, label="intent_id")
        normalized_summary = _normalize_text(summary, label="summary")
        normalized_actor = _normalize_optional_text(actor)
        normalized_metadata = dict(metadata or {})

        with self._lock:
            previous = self._latest_for_intent_unlocked(normalized_intent_id)
            previous_receipt_id = None if previous is None else previous.receipt_id
            previous_chain_digest = None if previous is None else previous.chain_digest

            receipt_id = f"receipt-{uuid4().hex}"
            created_at = _utc_now()
            chain_digest = _compute_chain_digest(
                receipt_id=receipt_id,
                intent_id=normalized_intent_id,
                event_type=event_type.value,
                summary=normalized_summary,
                previous_chain_digest=previous_chain_digest,
                actor=normalized_actor,
                metadata=normalized_metadata,
            )

            record = GovernanceReceiptRecord(
                receipt_id=receipt_id,
                intent_id=normalized_intent_id,
                event_type=event_type,
                summary=normalized_summary,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=chain_digest,
                created_at=created_at,
                actor=normalized_actor,
                metadata=normalized_metadata,
            )
            self._records.append(record)
            return record

    def snapshot(self) -> GovernanceReceiptLedgerSnapshot:
        """
        Return an immutable snapshot of ledger records in creation order.
        """
        with self._lock:
            records = tuple(self._records)
        return GovernanceReceiptLedgerSnapshot(records=records)

    def verify_intent_chain(self, intent_id: str) -> bool:
        """
        Verify the integrity of one action-intent receipt chain.
        """
        normalized_intent_id = _normalize_identifier(intent_id, label="intent_id")

        with self._lock:
            records = [
                record for record in self._records if record.intent_id == normalized_intent_id
            ]

        previous_record: GovernanceReceiptRecord | None = None
        for record in records:
            expected_previous_receipt_id = (
                None if previous_record is None else previous_record.receipt_id
            )
            expected_previous_chain_digest = (
                None if previous_record is None else previous_record.chain_digest
            )

            if record.previous_receipt_id != expected_previous_receipt_id:
                return False
            if record.previous_chain_digest != expected_previous_chain_digest:
                return False

            expected_chain_digest = _compute_chain_digest(
                receipt_id=record.receipt_id,
                intent_id=record.intent_id,
                event_type=record.event_type.value,
                summary=record.summary,
                previous_chain_digest=record.previous_chain_digest,
                actor=record.actor,
                metadata=record.metadata,
            )
            if record.chain_digest != expected_chain_digest:
                return False

            previous_record = record

        return True

    def count(self) -> int:
        """
        Return the total number of stored receipts.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all stored receipts.
        """
        with self._lock:
            self._records.clear()

    def _latest_for_intent_unlocked(self, intent_id: str) -> GovernanceReceiptRecord | None:
        for record in reversed(self._records):
            if record.intent_id == intent_id:
                return record
        return None


def _compute_chain_digest(
    *,
    receipt_id: str,
    intent_id: str,
    event_type: str,
    summary: str,
    previous_chain_digest: str | None,
    actor: str | None,
    metadata: dict[str, Any],
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "intent_id": intent_id,
        "event_type": event_type,
        "summary": summary,
        "previous_chain_digest": previous_chain_digest,
        "actor": actor,
        "metadata": metadata,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
