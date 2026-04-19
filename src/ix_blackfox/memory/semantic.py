from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class SemanticMemoryRecord:
    """
    One distilled semantic-memory record.

    Attributes
    ----------
    concept_id:
        Stable unique identifier for the semantic concept.
    key:
        Canonical key for the concept.
    value:
        Distilled value associated with the concept.
    fact_type:
        Classification such as fact, rule, preference, or constraint.
    confidence:
        Confidence score from 0.0 to 1.0 for the stored value.
    created_at:
        UTC timestamp when the concept was first stored.
    updated_at:
        UTC timestamp of the most recent update.
    source:
        Optional source label that produced the concept.
    tags:
        Optional normalized tags for grouping and retrieval.
    aliases:
        Optional alternate names that can resolve to the same concept.
    """

    concept_id: str
    key: str
    value: Any
    fact_type: str
    confidence: float
    created_at: datetime
    updated_at: datetime
    source: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def touch(
        self,
        *,
        value: Any,
        fact_type: str,
        confidence: float,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
        aliases: tuple[str, ...] | None = None,
    ) -> SemanticMemoryRecord:
        """
        Return an updated copy of the semantic record.
        """
        normalized_fact_type = _normalize_identifier(fact_type, label="fact type")
        normalized_confidence = _normalize_confidence(confidence)

        return replace(
            self,
            value=value,
            fact_type=normalized_fact_type,
            confidence=normalized_confidence,
            updated_at=_utc_now(),
            source=_normalize_optional_text(source),
            tags=self.tags if tags is None else _normalize_identifiers(tags, label="tag"),
            aliases=(
                self.aliases
                if aliases is None
                else _normalize_identifiers(aliases, label="alias")
            ),
        )


@dataclass(frozen=True, slots=True)
class SemanticMemorySnapshot:
    """
    Immutable view of semantic-memory contents.
    """

    records: tuple[SemanticMemoryRecord, ...]

    def get(self, key: str) -> SemanticMemoryRecord | None:
        """
        Retrieve a record by canonical key or alias.
        """
        normalized_key = _normalize_identifier(key, label="key")
        for record in self.records:
            if record.key == normalized_key or normalized_key in record.aliases:
                return record
        return None

    def filter_by_fact_type(self, fact_type: str) -> tuple[SemanticMemoryRecord, ...]:
        """
        Return all records matching the given fact type.
        """
        normalized_fact_type = _normalize_identifier(fact_type, label="fact type")
        return tuple(
            record for record in self.records if record.fact_type == normalized_fact_type
        )

    def filter_by_tag(self, tag: str) -> tuple[SemanticMemoryRecord, ...]:
        """
        Return all records containing the given tag.
        """
        normalized_tag = _normalize_identifier(tag, label="tag")
        return tuple(record for record in self.records if normalized_tag in record.tags)


class SemanticMemoryStore:
    """
    Thread-safe semantic-memory store.

    Semantic memory holds distilled facts, constraints, and reusable
    knowledge that should persist beyond one active execution window.
    """

    def __init__(self) -> None:
        self._records: dict[str, SemanticMemoryRecord] = {}
        self._alias_to_key: dict[str, str] = {}
        self._lock = RLock()

    def upsert(
        self,
        *,
        key: str,
        value: Any,
        fact_type: str = "fact",
        confidence: float = 1.0,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
        aliases: tuple[str, ...] | None = None,
    ) -> SemanticMemoryRecord:
        """
        Insert or update a semantic-memory record.
        """
        normalized_key = _normalize_identifier(key, label="key")
        normalized_fact_type = _normalize_identifier(fact_type, label="fact type")
        normalized_confidence = _normalize_confidence(confidence)
        normalized_source = _normalize_optional_text(source)
        normalized_tags = _normalize_identifiers(tags or (), label="tag")
        normalized_aliases = tuple(
            alias
            for alias in _normalize_identifiers(aliases or (), label="alias")
            if alias != normalized_key
        )

        with self._lock:
            existing = self._records.get(normalized_key)
            if existing is None:
                now = _utc_now()
                record = SemanticMemoryRecord(
                    concept_id=f"sm-{uuid4().hex}",
                    key=normalized_key,
                    value=value,
                    fact_type=normalized_fact_type,
                    confidence=normalized_confidence,
                    created_at=now,
                    updated_at=now,
                    source=normalized_source,
                    tags=normalized_tags,
                    aliases=normalized_aliases,
                )
            else:
                record = existing.touch(
                    value=value,
                    fact_type=normalized_fact_type,
                    confidence=normalized_confidence,
                    source=normalized_source,
                    tags=normalized_tags,
                    aliases=normalized_aliases,
                )

            self._records[normalized_key] = record
            self._rebuild_alias_index_for_key(normalized_key)
            return record

    def get(self, key: str) -> SemanticMemoryRecord | None:
        """
        Retrieve a semantic-memory record by key or alias.
        """
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            canonical_key = self._alias_to_key.get(normalized_key, normalized_key)
            return self._records.get(canonical_key)

    def delete(self, key: str) -> bool:
        """
        Delete a semantic-memory record by canonical key.

        Aliases are removed with the canonical record.
        """
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            if normalized_key not in self._records:
                return False

            del self._records[normalized_key]
            aliases_to_remove = [
                alias
                for alias, canonical_key in self._alias_to_key.items()
                if canonical_key == normalized_key
            ]
            for alias in aliases_to_remove:
                del self._alias_to_key[alias]
            return True

    def snapshot(self) -> SemanticMemorySnapshot:
        """
        Return an immutable snapshot of semantic-memory records.
        """
        with self._lock:
            records = tuple(
                sorted(
                    self._records.values(),
                    key=lambda item: (item.key, item.updated_at, item.concept_id),
                )
            )
        return SemanticMemorySnapshot(records=records)

    def count(self) -> int:
        """
        Return the total number of semantic-memory records.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all semantic-memory records and alias mappings.
        """
        with self._lock:
            self._records.clear()
            self._alias_to_key.clear()

    def _rebuild_alias_index_for_key(self, key: str) -> None:
        aliases_to_remove = [
            alias for alias, canonical_key in self._alias_to_key.items() if canonical_key == key
        ]
        for alias in aliases_to_remove:
            del self._alias_to_key[alias]

        record = self._records[key]
        for alias in record.aliases:
            self._alias_to_key[alias] = key


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Semantic memory {label} must not be empty.")
    return cleaned


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


def _normalize_confidence(value: float) -> float:
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError("Semantic memory confidence must be between 0.0 and 1.0.")
    return normalized


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
