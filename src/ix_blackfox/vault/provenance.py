from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """
    One provenance-ledger record.

    Attributes
    ----------
    record_id:
        Stable unique record identifier.
    subject:
        Logical subject of the record, such as an artifact or task.
    action:
        Action performed on the subject, such as created, updated, or verified.
    fingerprint:
        Stable content fingerprint associated with the subject state.
    previous_record_id:
        Prior record identifier in the same subject chain, if any.
    previous_chain_digest:
        Prior chain digest in the same subject chain, if any.
    chain_digest:
        Tamper-evident digest for this record, bound to the previous link.
    created_at:
        UTC timestamp when the record was created.
    actor:
        Optional actor or subsystem label that performed the action.
    metadata:
        Optional structured metadata payload.
    """

    record_id: str
    subject: str
    action: str
    fingerprint: str
    previous_record_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    actor: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProvenanceLedgerSnapshot:
    """
    Immutable view of provenance-ledger records.
    """

    records: tuple[ProvenanceRecord, ...]

    def filter_by_subject(self, subject: str) -> tuple[ProvenanceRecord, ...]:
        """
        Return all records for a given subject in creation order.
        """
        normalized_subject = _normalize_identifier(subject, label="subject")
        return tuple(
            record for record in self.records if record.subject == normalized_subject
        )

    def latest_for_subject(self, subject: str) -> ProvenanceRecord | None:
        """
        Return the most recent record for a subject.
        """
        subject_records = self.filter_by_subject(subject)
        if not subject_records:
            return None
        return subject_records[-1]


class ProvenanceLedger:
    """
    Thread-safe provenance ledger for BlackFox artifacts and actions.

    The ledger creates a per-subject hash chain so changes remain auditable
    and accidental tampering becomes detectable.
    """

    def __init__(self) -> None:
        self._records: list[ProvenanceRecord] = []
        self._lock = RLock()

    def append(
        self,
        *,
        subject: str,
        action: str,
        fingerprint: str,
        actor: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """
        Append a new provenance record for a subject.
        """
        normalized_subject = _normalize_identifier(subject, label="subject")
        normalized_action = _normalize_identifier(action, label="action")
        normalized_fingerprint = _normalize_fingerprint(fingerprint)
        normalized_actor = _normalize_optional_text(actor)
        normalized_metadata = dict(metadata or {})

        with self._lock:
            previous = self._latest_for_subject_unlocked(normalized_subject)
            previous_record_id = None if previous is None else previous.record_id
            previous_chain_digest = None if previous is None else previous.chain_digest

            record_id = f"prov-{uuid4().hex}"
            created_at = _utc_now()
            chain_digest = _compute_chain_digest(
                record_id=record_id,
                subject=normalized_subject,
                action=normalized_action,
                fingerprint=normalized_fingerprint,
                previous_chain_digest=previous_chain_digest,
                actor=normalized_actor,
                metadata=normalized_metadata,
            )

            record = ProvenanceRecord(
                record_id=record_id,
                subject=normalized_subject,
                action=normalized_action,
                fingerprint=normalized_fingerprint,
                previous_record_id=previous_record_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=chain_digest,
                created_at=created_at,
                actor=normalized_actor,
                metadata=normalized_metadata,
            )
            self._records.append(record)
            return record

    def snapshot(self) -> ProvenanceLedgerSnapshot:
        """
        Return an immutable snapshot of the ledger in creation order.
        """
        with self._lock:
            return ProvenanceLedgerSnapshot(records=tuple(self._records))

    def verify_subject_chain(self, subject: str) -> bool:
        """
        Verify the integrity of the chain for one subject.
        """
        normalized_subject = _normalize_identifier(subject, label="subject")

        with self._lock:
            records = [
                record for record in self._records if record.subject == normalized_subject
            ]

        previous_record: ProvenanceRecord | None = None
        for record in records:
            expected_previous_id = None if previous_record is None else previous_record.record_id
            expected_previous_digest = (
                None if previous_record is None else previous_record.chain_digest
            )

            if record.previous_record_id != expected_previous_id:
                return False
            if record.previous_chain_digest != expected_previous_digest:
                return False

            expected_digest = _compute_chain_digest(
                record_id=record.record_id,
                subject=record.subject,
                action=record.action,
                fingerprint=record.fingerprint,
                previous_chain_digest=record.previous_chain_digest,
                actor=record.actor,
                metadata=record.metadata,
            )
            if record.chain_digest != expected_digest:
                return False

            previous_record = record

        return True

    def count(self) -> int:
        """
        Return the total number of provenance records.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all provenance records.
        """
        with self._lock:
            self._records.clear()

    def _latest_for_subject_unlocked(self, subject: str) -> ProvenanceRecord | None:
        for record in reversed(self._records):
            if record.subject == subject:
                return record
        return None


def _compute_chain_digest(
    *,
    record_id: str,
    subject: str,
    action: str,
    fingerprint: str,
    previous_chain_digest: str | None,
    actor: str | None,
    metadata: dict[str, Any],
) -> str:
    payload = {
        "record_id": record_id,
        "subject": subject,
        "action": action,
        "fingerprint": fingerprint,
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
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Vault provenance {label} must not be empty.")
    return cleaned


def _normalize_fingerprint(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Vault provenance fingerprint must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
