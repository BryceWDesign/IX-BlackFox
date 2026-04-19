from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any
from uuid import uuid4


class EventTopic(StrEnum):
    """
    Typed event topics carried across the BlackFox internal bus.
    """

    KERNEL = auto()
    TASK = auto()
    MEMORY = auto()
    PACK = auto()
    FORGE = auto()
    SENTINEL = auto()
    VAULT = auto()
    EVAL = auto()
    INTERFACE = auto()
    SYSTEM = auto()


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """
    Immutable event envelope for BlackFox bus traffic.

    Attributes
    ----------
    event_id:
        Stable unique event identifier.
    topic:
        Event topic classification.
    source:
        Logical source that emitted the event.
    created_at:
        UTC timestamp when the event was created.
    payload:
        Event payload body.
    correlation_id:
        Optional task, trace, or session correlation identifier.
    tags:
        Optional normalized tags for filtering or diagnostics.
    """

    event_id: str
    topic: EventTopic
    source: str
    created_at: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def create(
        cls,
        *,
        topic: EventTopic,
        source: str,
        payload: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        tags: tuple[str, ...] | None = None,
    ) -> EventEnvelope:
        """
        Construct a new normalized event envelope.
        """
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("Event source must not be empty.")

        normalized_correlation = _normalize_optional_text(correlation_id)

        return cls(
            event_id=f"evt-{uuid4().hex}",
            topic=topic,
            source=normalized_source,
            created_at=_utc_now(),
            payload=dict(payload or {}),
            correlation_id=normalized_correlation,
            tags=_normalize_tags(tags or ()),
        )


def _normalize_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_tag in tags:
        cleaned = raw_tag.strip().lower()
        if not cleaned:
            continue
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
