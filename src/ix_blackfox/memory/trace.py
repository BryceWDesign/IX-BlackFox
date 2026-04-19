from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """
    One execution-trace record.

    Attributes
    ----------
    trace_id:
        Stable unique trace identifier.
    correlation_id:
        Stable correlation identifier used to group related trace records.
    stage:
        Logical execution stage, such as intake, routing, forge, or eval.
    message:
        Human-readable trace message.
    level:
        Trace severity or importance level.
    created_at:
        UTC timestamp when the record was created.
    source:
        Optional source label that emitted the trace.
    tags:
        Optional normalized tags for filtering and grouping.
    data:
        Optional structured trace payload.
    """

    trace_id: str
    correlation_id: str
    stage: str
    message: str
    level: str
    created_at: datetime
    source: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    data: dict[str, Any] = field(default_factory=dict)

    def with_message(self, message: str) -> TraceRecord:
        """
        Return a copy with an updated message.
        """
        normalized_message = _normalize_text(message, label="message")
        return replace(self, message=normalized_message)


@dataclass(frozen=True, slots=True)
class TraceMemorySnapshot:
    """
    Immutable view of trace-memory records.
    """

    records: tuple[TraceRecord, ...]

    def filter_by_correlation(self, correlation_id: str) -> tuple[TraceRecord, ...]:
        """
        Return all trace records for a correlation identifier.
        """
        normalized_correlation = _normalize_text(
            correlation_id,
            label="correlation id",
        )
        return tuple(
            record
            for record in self.records
            if record.correlation_id == normalized_correlation
        )

    def filter_by_stage(self, stage: str) -> tuple[TraceRecord, ...]:
        """
        Return all trace records for a stage.
        """
        normalized_stage = _normalize_identifier(stage, label="stage")
        return tuple(record for record in self.records if record.stage == normalized_stage)

    def filter_by_tag(self, tag: str) -> tuple[TraceRecord, ...]:
        """
        Return all trace records containing a given tag.
        """
        normalized_tag = _normalize_identifier(tag, label="tag")
        return tuple(record for record in self.records if normalized_tag in record.tags)

    def filter_by_level(self, level: str) -> tuple[TraceRecord, ...]:
        """
        Return all trace records for a given level.
        """
        normalized_level = _normalize_identifier(level, label="level")
        return tuple(record for record in self.records if record.level == normalized_level)


class TraceMemoryStore:
    """
    Thread-safe execution trace store.

    Trace memory captures the why and how of runtime behavior so task
    execution remains auditable instead of opaque.
    """

    def __init__(self) -> None:
        self._records: dict[str, TraceRecord] = {}
        self._lock = RLock()

    def append(
        self,
        *,
        correlation_id: str,
        stage: str,
        message: str,
        level: str = "info",
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
        data: dict[str, Any] | None = None,
    ) -> TraceRecord:
        """
        Create and store a new trace record.
        """
        normalized_correlation = _normalize_text(
            correlation_id,
            label="correlation id",
        )
        normalized_stage = _normalize_identifier(stage, label="stage")
        normalized_message = _normalize_text(message, label="message")
        normalized_level = _normalize_identifier(level, label="level")
        normalized_source = _normalize_optional_text(source)
        normalized_tags = _normalize_identifiers(tags or (), label="tag")

        record = TraceRecord(
            trace_id=f"tr-{uuid4().hex}",
            correlation_id=normalized_correlation,
            stage=normalized_stage,
            message=normalized_message,
            level=normalized_level,
            created_at=_utc_now(),
            source=normalized_source,
            tags=normalized_tags,
            data=dict(data or {}),
        )

        with self._lock:
            self._records[record.trace_id] = record

        return record

    def get(self, trace_id: str) -> TraceRecord | None:
        """
        Retrieve a trace record by its unique trace identifier.
        """
        normalized_trace_id = _normalize_text(trace_id, label="trace id")
        with self._lock:
            return self._records.get(normalized_trace_id)

    def snapshot(self) -> TraceMemorySnapshot:
        """
        Return an immutable snapshot of trace-memory records in creation order.
        """
        with self._lock:
            records = tuple(
                sorted(
                    self._records.values(),
                    key=lambda item: (item.created_at, item.trace_id),
                )
            )
        return TraceMemorySnapshot(records=records)

    def count(self) -> int:
        """
        Return the total number of trace records stored.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all trace records.
        """
        with self._lock:
            self._records.clear()


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Trace memory {label} must not be empty.")
    return cleaned


def _normalize_identifier(value: str, *, label: str) -> str:
    return _normalize_text(value, label=label).lower()


def _normalize_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_identifier(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
