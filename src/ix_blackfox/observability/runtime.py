from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ix_blackfox.config import RuntimeConfig


class LogLevel(StrEnum):
    """
    Structured log levels used by BlackFox runtime logging.
    """

    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class LogRecord:
    """
    One structured runtime log record.

    Attributes
    ----------
    record_id:
        Stable unique log record identifier.
    level:
        Structured log level.
    event:
        Machine-readable event name.
    message:
        Human-readable event message.
    created_at:
        UTC timestamp when the log record was created.
    source:
        Optional subsystem or component source label.
    correlation_id:
        Optional task, trace, or session correlation identifier.
    data:
        Optional structured payload associated with the event.
    """

    record_id: str
    level: LogLevel
    event: str
    message: str
    created_at: datetime
    source: str | None = None
    correlation_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_event = _normalize_identifier(self.event, label="event")
        normalized_message = _normalize_text(self.message, label="message")
        normalized_source = _normalize_optional_text(self.source)
        normalized_correlation = _normalize_optional_text(self.correlation_id)

        object.__setattr__(self, "event", normalized_event)
        object.__setattr__(self, "message", normalized_message)
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "correlation_id", normalized_correlation)

    def to_json_dict(self) -> dict[str, Any]:
        """
        Convert the record to a JSON-serializable dictionary.
        """
        return {
            "record_id": self.record_id,
            "level": self.level.value,
            "event": self.event,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "source": self.source,
            "correlation_id": self.correlation_id,
            "data": self.data,
        }

    @classmethod
    def from_json_dict(cls, raw: dict[str, Any]) -> LogRecord:
        """
        Construct a log record from a JSON dictionary.
        """
        return cls(
            record_id=_normalize_text(str(raw["record_id"]), label="record id"),
            level=LogLevel(str(raw["level"])),
            event=str(raw["event"]),
            message=str(raw["message"]),
            created_at=_parse_datetime(str(raw["created_at"])),
            source=None if raw.get("source") is None else str(raw["source"]),
            correlation_id=(
                None
                if raw.get("correlation_id") is None
                else str(raw["correlation_id"])
            ),
            data=dict(raw.get("data", {})),
        )


@dataclass(frozen=True, slots=True)
class LogSnapshot:
    """
    Immutable view of structured runtime logs.
    """

    records: tuple[LogRecord, ...]

    def filter_by_level(self, level: LogLevel) -> tuple[LogRecord, ...]:
        """
        Return log records matching one level.
        """
        return tuple(record for record in self.records if record.level == level)

    def filter_by_source(self, source: str) -> tuple[LogRecord, ...]:
        """
        Return log records emitted by one source.
        """
        normalized_source = _normalize_text(source, label="source")
        return tuple(
            record for record in self.records if record.source == normalized_source
        )

    def filter_by_event(self, event: str) -> tuple[LogRecord, ...]:
        """
        Return log records matching one event name.
        """
        normalized_event = _normalize_identifier(event, label="event")
        return tuple(record for record in self.records if record.event == normalized_event)


class JsonlStructuredLogger:
    """
    Append-only JSONL logger for BlackFox observability.

    Records are written as one JSON object per line under the configured
    runtime logs directory so they remain easy to stream, inspect, and
    correlate without requiring a database.
    """

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        filename: str = "blackfox-runtime.jsonl",
    ) -> None:
        normalized_filename = _normalize_filename(filename)
        self._config = config
        self._path = (config.paths.logs_dir / normalized_filename).resolve()
        self._lock = RLock()
        self._config.paths.logs_dir.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        """
        Filesystem path for the JSONL log file.
        """
        return self._path

    def log(
        self,
        *,
        level: LogLevel,
        event: str,
        message: str,
        source: str | None = None,
        correlation_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> LogRecord:
        """
        Append one structured log record to disk.
        """
        record = LogRecord(
            record_id=f"log-{uuid4().hex}",
            level=level,
            event=event,
            message=message,
            created_at=_utc_now(),
            source=source,
            correlation_id=correlation_id,
            data=dict(data or {}),
        )

        try:
            line = json.dumps(
                record.to_json_dict(),
                sort_keys=True,
                ensure_ascii=False,
            )
        except TypeError as exc:
            raise ValueError(f"Structured log data is not JSON-serializable: {exc}") from exc

        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")

        return record

    def read(self, *, limit: int | None = None) -> LogSnapshot:
        """
        Read structured log records from disk.

        Parameters
        ----------
        limit:
            Optional number of most recent records to return.
        """
        if limit is not None and limit < 0:
            raise ValueError("Log read limit must be greater than or equal to zero.")

        with self._lock:
            if not self._path.exists():
                return LogSnapshot(records=())

            lines = self._path.read_text(encoding="utf-8").splitlines()

        if limit == 0:
            return LogSnapshot(records=())

        selected_lines = lines if limit is None else lines[-limit:]

        records: list[LogRecord] = []
        for line in selected_lines:
            if not line.strip():
                continue
            raw = json.loads(line)
            records.append(LogRecord.from_json_dict(raw))

        return LogSnapshot(records=tuple(records))

    def clear(self) -> None:
        """
        Remove all structured log content.
        """
        with self._lock:
            if self._path.exists():
                self._path.unlink()

    def count(self) -> int:
        """
        Return the total number of stored log records.
        """
        return len(self.read().records)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Structured log {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Structured log {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_filename(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Structured log filename must not be empty.")
    if Path(cleaned).name != cleaned:
        raise ValueError("Structured log filename must not include path separators.")
    return cleaned


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
