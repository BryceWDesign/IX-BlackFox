from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """
    One evidence record captured for evaluation and audit.

    Attributes
    ----------
    evidence_id:
        Stable unique evidence identifier.
    subject_id:
        Logical subject under evaluation, such as a task, artifact, or plan.
    evidence_type:
        Classification such as artifact, trace, regression, or assertion.
    summary:
        Short human-readable description of the evidence.
    created_at:
        UTC timestamp when the evidence was recorded.
    source:
        Optional source label that produced the evidence.
    artifact_refs:
        Optional logical artifact references related to the evidence.
    trace_ids:
        Optional related trace identifiers.
    metadata:
        Optional structured payload for downstream evaluation or reporting.
    """

    evidence_id: str
    subject_id: str
    evidence_type: str
    summary: str
    created_at: datetime
    source: str | None = None
    artifact_refs: tuple[str, ...] = field(default_factory=tuple)
    trace_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_subject = _normalize_identifier(self.subject_id, label="subject id")
        normalized_type = _normalize_identifier(self.evidence_type, label="evidence type")
        normalized_summary = _normalize_text(self.summary, label="summary")
        normalized_source = _normalize_optional_text(self.source)
        normalized_artifacts = _normalize_strings(
            self.artifact_refs,
            label="artifact reference",
        )
        normalized_trace_ids = _normalize_strings(
            self.trace_ids,
            label="trace id",
        )

        object.__setattr__(self, "subject_id", normalized_subject)
        object.__setattr__(self, "evidence_type", normalized_type)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "artifact_refs", normalized_artifacts)
        object.__setattr__(self, "trace_ids", normalized_trace_ids)


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """
    Immutable view of recorded evaluation evidence.
    """

    records: tuple[EvidenceRecord, ...]

    def filter_by_subject(self, subject_id: str) -> tuple[EvidenceRecord, ...]:
        """
        Return all evidence records for a subject.
        """
        normalized_subject = _normalize_identifier(subject_id, label="subject id")
        return tuple(
            record for record in self.records if record.subject_id == normalized_subject
        )

    def filter_by_type(self, evidence_type: str) -> tuple[EvidenceRecord, ...]:
        """
        Return all evidence records of a given type.
        """
        normalized_type = _normalize_identifier(
            evidence_type,
            label="evidence type",
        )
        return tuple(
            record for record in self.records if record.evidence_type == normalized_type
        )

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """
        Retrieve one evidence record by identifier.
        """
        normalized_id = _normalize_text(evidence_id, label="evidence id")
        for record in self.records:
            if record.evidence_id == normalized_id:
                return record
        return None


class EvidenceRecorder:
    """
    Thread-safe recorder for evaluation evidence.

    Evidence is stored as immutable records so later verification layers can
    audit what supported a result without re-parsing logs or artifacts.
    """

    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []
        self._lock = RLock()

    def record(
        self,
        *,
        subject_id: str,
        evidence_type: str,
        summary: str,
        source: str | None = None,
        artifact_refs: tuple[str, ...] = (),
        trace_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Create and store one evidence record.
        """
        record = EvidenceRecord(
            evidence_id=f"ev-{uuid4().hex}",
            subject_id=subject_id,
            evidence_type=evidence_type,
            summary=summary,
            created_at=_utc_now(),
            source=source,
            artifact_refs=artifact_refs,
            trace_ids=trace_ids,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._records.append(record)

        return record

    def snapshot(self) -> EvidenceSnapshot:
        """
        Return an immutable snapshot of all evidence records.
        """
        with self._lock:
            return EvidenceSnapshot(records=tuple(self._records))

    def count(self) -> int:
        """
        Return the total number of evidence records.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all evidence records.
        """
        with self._lock:
            self._records.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Evaluation evidence {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Evaluation evidence {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_strings(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_text(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
