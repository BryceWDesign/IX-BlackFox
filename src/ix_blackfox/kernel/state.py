from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any


@dataclass(frozen=True, slots=True)
class StateEntry:
    """
    Immutable record for one shared-state value.

    Attributes
    ----------
    namespace:
        Logical grouping for the value.
    key:
        Stable key within the namespace.
    value:
        Stored payload.
    version:
        Monotonic version for this key.
    updated_at:
        UTC timestamp of the last write.
    source:
        Optional source label that performed the write.
    """

    namespace: str
    key: str
    value: Any
    version: int
    updated_at: datetime
    source: str | None = None


@dataclass(frozen=True, slots=True)
class SharedStateSnapshot:
    """
    Immutable snapshot of the BlackFox shared-state store.
    """

    entries: tuple[StateEntry, ...]

    def get(self, namespace: str, key: str) -> StateEntry | None:
        """
        Retrieve an entry from the snapshot by namespace and key.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        for entry in self.entries:
            if entry.namespace == normalized_namespace and entry.key == normalized_key:
                return entry
        return None

    def as_nested_dict(self) -> dict[str, dict[str, Any]]:
        """
        Represent the snapshot as a nested namespace/key dictionary.
        """
        result: dict[str, dict[str, Any]] = {}
        for entry in self.entries:
            result.setdefault(entry.namespace, {})[entry.key] = entry.value
        return result


class SharedStateStore:
    """
    Thread-safe shared-state manager for the BlackFox kernel.

    This store is intentionally small and deterministic. It provides a
    consistent place for runtime coordination data before more advanced
    state backends are introduced.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], StateEntry] = {}
        self._lock = RLock()

    def put(
        self,
        namespace: str,
        key: str,
        value: Any,
        *,
        source: str | None = None,
    ) -> StateEntry:
        """
        Insert or update a state value, incrementing its version.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")
        normalized_source = _normalize_optional_text(source)

        with self._lock:
            entry_key = (normalized_namespace, normalized_key)
            previous = self._entries.get(entry_key)
            next_version = 1 if previous is None else previous.version + 1

            entry = StateEntry(
                namespace=normalized_namespace,
                key=normalized_key,
                value=value,
                version=next_version,
                updated_at=_utc_now(),
                source=normalized_source,
            )
            self._entries[entry_key] = entry
            return entry

    def get(self, namespace: str, key: str) -> StateEntry | None:
        """
        Retrieve a state entry by namespace and key.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            return self._entries.get((normalized_namespace, normalized_key))

    def delete(self, namespace: str, key: str) -> bool:
        """
        Delete a state entry if it exists.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")

        with self._lock:
            entry_key = (normalized_namespace, normalized_key)
            if entry_key not in self._entries:
                return False
            del self._entries[entry_key]
            return True

    def compare_and_set(
        self,
        namespace: str,
        key: str,
        *,
        expected_version: int,
        value: Any,
        source: str | None = None,
    ) -> StateEntry | None:
        """
        Update a value only if the current version matches the expected one.

        Returns the new entry on success, or None if the current version does
        not match.
        """
        if expected_version < 1:
            raise ValueError("Expected version must be greater than or equal to 1.")

        normalized_namespace = _normalize_identifier(namespace, label="namespace")
        normalized_key = _normalize_identifier(key, label="key")
        normalized_source = _normalize_optional_text(source)

        with self._lock:
            entry_key = (normalized_namespace, normalized_key)
            current = self._entries.get(entry_key)
            if current is None or current.version != expected_version:
                return None

            updated = StateEntry(
                namespace=normalized_namespace,
                key=normalized_key,
                value=value,
                version=current.version + 1,
                updated_at=_utc_now(),
                source=normalized_source,
            )
            self._entries[entry_key] = updated
            return updated

    def namespaces(self) -> tuple[str, ...]:
        """
        Return all namespaces present in sorted order.
        """
        with self._lock:
            return tuple(sorted({namespace for namespace, _ in self._entries}))

    def keys(self, namespace: str) -> tuple[str, ...]:
        """
        Return all keys for a namespace in sorted order.
        """
        normalized_namespace = _normalize_identifier(namespace, label="namespace")

        with self._lock:
            return tuple(
                sorted(
                    key
                    for entry_namespace, key in self._entries
                    if entry_namespace == normalized_namespace
                )
            )

    def snapshot(self, *, namespace: str | None = None) -> SharedStateSnapshot:
        """
        Capture an immutable snapshot of the store.

        If a namespace is provided, only entries from that namespace are
        included.
        """
        normalized_namespace = (
            _normalize_identifier(namespace, label="namespace")
            if namespace is not None
            else None
        )

        with self._lock:
            entries = tuple(
                entry
                for entry in sorted(
                    self._entries.values(),
                    key=lambda item: (item.namespace, item.key),
                )
                if normalized_namespace is None or entry.namespace == normalized_namespace
            )

        return SharedStateSnapshot(entries=entries)

    def clear(self) -> None:
        """
        Remove all shared-state entries.
        """
        with self._lock:
            self._entries.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"State {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
