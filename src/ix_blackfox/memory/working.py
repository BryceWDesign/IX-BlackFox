from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class WorkingMemoryItem:
    """
    One item stored in working memory.

    Attributes
    ----------
    item_id:
        Stable unique item identifier.
    namespace:
        Logical grouping for the item.
    key:
        Stable item key within the namespace.
    value:
        Stored payload.
    created_at:
        UTC timestamp when the item was first created.
    updated_at:
        UTC timestamp of the most recent update.
    source:
        Optional source label describing who wrote the item.
    tags:
        Optional normalized tags for filtering and traceability.
    """

    item_id: str
    namespace: str
    key: str
    value: Any
    created_at: datetime
    updated_at: datetime
    source: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def touch(
        self,
        *,
        value: Any,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
    ) -> WorkingMemoryItem:
        """
        Return an updated copy of the item with a refreshed timestamp.
        """
        return replace(
            self,
            value=value,
            updated_at=_utc_now(),
            source=_normalize_optional_text(source),
            tags=self.tags if tags is None else _normalize_tags(tags),
        )


@dataclass(frozen=True, slots=True)
class WorkingMemorySnapshot:
    """
    Immutable view of current working-memory contents.
    """

    items: tuple[WorkingMemoryItem, ...]

    def get(self, namespace: str, key: str) -> WorkingMemoryItem | None:
        """
        Retrieve one working-memory item by namespace and key.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        for item in self.items:
            if item.namespace == normalized_namespace and item.key == normalized_key:
                return item
        return None

    def filter_by_tag(self, tag: str) -> tuple[WorkingMemoryItem, ...]:
        """
        Return all items containing the given tag.
        """
        normalized_tag = _normalize_identifier(tag, label="tag")
        return tuple(item for item in self.items if normalized_tag in item.tags)

    def namespaces(self) -> tuple[str, ...]:
        """
        Return all namespaces present in the snapshot.
        """
        return tuple(sorted({item.namespace for item in self.items}))


class WorkingMemoryStore:
    """
    Thread-safe working-memory store for live execution context.

    Working memory is intentionally short-horizon and mutable. It is used
    for active plan fragments, intermediate results, current assumptions,
    and runtime coordination that should not be promoted into longer-term
    memory automatically.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], WorkingMemoryItem] = {}
        self._lock = RLock()

    def put(
        self,
        namespace: str,
        key: str,
        value: Any,
        *,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
    ) -> WorkingMemoryItem:
        """
        Insert or update a working-memory item.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")
        normalized_source = _normalize_optional_text(source)
        normalized_tags = _normalize_tags(tags or ())

        with self._lock:
            item_key = (normalized_namespace, normalized_key)
            existing = self._items.get(item_key)
            if existing is None:
                now = _utc_now()
                item = WorkingMemoryItem(
                    item_id=f"wm-{uuid4().hex}",
                    namespace=normalized_namespace,
                    key=normalized_key,
                    value=value,
                    created_at=now,
                    updated_at=now,
                    source=normalized_source,
                    tags=normalized_tags,
                )
            else:
                item = existing.touch(
                    value=value,
                    source=normalized_source,
                    tags=normalized_tags,
                )

            self._items[item_key] = item
            return item

    def get(self, namespace: str, key: str) -> WorkingMemoryItem | None:
        """
        Retrieve a working-memory item by namespace and key.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            return self._items.get((normalized_namespace, normalized_key))

    def delete(self, namespace: str, key: str) -> bool:
        """
        Delete one working-memory item if it exists.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            item_key = (normalized_namespace, normalized_key)
            if item_key not in self._items:
                return False
            del self._items[item_key]
            return True

    def clear_namespace(self, namespace: str) -> int:
        """
        Remove all items from one namespace and return the number removed.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")

        with self._lock:
            keys_to_remove = [
                item_key
                for item_key in self._items
                if item_key[0] == normalized_namespace
            ]
            for item_key in keys_to_remove:
                del self._items[item_key]
            return len(keys_to_remove)

    def snapshot(self, *, namespace: str | None = None) -> WorkingMemorySnapshot:
        """
        Return an immutable snapshot of current working-memory items.
        """
        normalized_namespace = (
            _normalize_identifier(namespace, label="namespace")
            if namespace is not None
            else None
        )

        with self._lock:
            items = tuple(
                item
                for item in sorted(
                    self._items.values(),
                    key=lambda current: (current.namespace, current.key),
                )
                if normalized_namespace is None or item.namespace == normalized_namespace
            )

        return WorkingMemorySnapshot(items=items)

    def count(self) -> int:
        """
        Return the total number of items in working memory.
        """
        with self._lock:
            return len(self._items)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Working memory {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for tag in tags:
        cleaned = tag.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
