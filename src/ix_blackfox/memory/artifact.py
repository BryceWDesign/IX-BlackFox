from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """
    One artifact-memory record.

    Attributes
    ----------
    artifact_id:
        Stable unique artifact identifier.
    logical_name:
        Canonical logical name for the artifact.
    path:
        Filesystem path associated with the artifact.
    artifact_type:
        Classification such as file, report, patch, or manifest.
    digest:
        Optional content digest string.
    created_at:
        UTC timestamp when the record was created.
    updated_at:
        UTC timestamp of the most recent update.
    source:
        Optional source label that produced the artifact.
    tags:
        Optional normalized tags for lookup and grouping.
    metadata:
        Optional structured artifact metadata.
    """

    artifact_id: str
    logical_name: str
    path: Path
    artifact_type: str
    digest: str | None
    created_at: datetime
    updated_at: datetime
    source: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(
        self,
        *,
        path: Path,
        artifact_type: str,
        digest: str | None = None,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRecord:
        """
        Return an updated copy of the artifact record.
        """
        return replace(
            self,
            path=path.resolve(),
            artifact_type=_normalize_identifier(artifact_type, label="artifact type"),
            digest=_normalize_optional_text(digest),
            updated_at=_utc_now(),
            source=_normalize_optional_text(source),
            tags=self.tags if tags is None else _normalize_identifiers(tags, label="tag"),
            metadata=self.metadata if metadata is None else dict(metadata),
        )


@dataclass(frozen=True, slots=True)
class ArtifactMemorySnapshot:
    """
    Immutable view of artifact-memory contents.
    """

    records: tuple[ArtifactRecord, ...]

    def get(self, logical_name: str) -> ArtifactRecord | None:
        """
        Retrieve an artifact by logical name.
        """
        normalized_name = _normalize_identifier(logical_name, label="logical name")
        for record in self.records:
            if record.logical_name == normalized_name:
                return record
        return None

    def filter_by_type(self, artifact_type: str) -> tuple[ArtifactRecord, ...]:
        """
        Return all artifacts of the given type.
        """
        normalized_type = _normalize_identifier(artifact_type, label="artifact type")
        return tuple(record for record in self.records if record.artifact_type == normalized_type)

    def filter_by_tag(self, tag: str) -> tuple[ArtifactRecord, ...]:
        """
        Return all artifacts containing the given tag.
        """
        normalized_tag = _normalize_identifier(tag, label="tag")
        return tuple(record for record in self.records if normalized_tag in record.tags)


class ArtifactMemoryStore:
    """
    Thread-safe store for artifact-memory records.

    Artifact memory tracks files and generated outputs that matter across
    tasks and sessions, including reports, patches, manifests, and other
    durable runtime products.
    """

    def __init__(self) -> None:
        self._records: dict[str, ArtifactRecord] = {}
        self._lock = RLock()

    def upsert(
        self,
        *,
        logical_name: str,
        path: Path,
        artifact_type: str,
        digest: str | None = None,
        source: str | None = None,
        tags: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRecord:
        """
        Insert or update an artifact-memory record by logical name.
        """
        normalized_name = _normalize_identifier(logical_name, label="logical name")
        normalized_path = path.resolve()
        normalized_type = _normalize_identifier(artifact_type, label="artifact type")
        normalized_digest = _normalize_optional_text(digest)
        normalized_source = _normalize_optional_text(source)
        normalized_tags = _normalize_identifiers(tags or (), label="tag")
        normalized_metadata = dict(metadata or {})

        with self._lock:
            existing = self._records.get(normalized_name)
            if existing is None:
                now = _utc_now()
                record = ArtifactRecord(
                    artifact_id=f"art-{uuid4().hex}",
                    logical_name=normalized_name,
                    path=normalized_path,
                    artifact_type=normalized_type,
                    digest=normalized_digest,
                    created_at=now,
                    updated_at=now,
                    source=normalized_source,
                    tags=normalized_tags,
                    metadata=normalized_metadata,
                )
            else:
                record = existing.touch(
                    path=normalized_path,
                    artifact_type=normalized_type,
                    digest=normalized_digest,
                    source=normalized_source,
                    tags=normalized_tags,
                    metadata=normalized_metadata,
                )

            self._records[normalized_name] = record
            return record

    def get(self, logical_name: str) -> ArtifactRecord | None:
        """
        Retrieve an artifact-memory record by logical name.
        """
        normalized_name = _normalize_identifier(logical_name, label="logical name")
        with self._lock:
            return self._records.get(normalized_name)

    def delete(self, logical_name: str) -> bool:
        """
        Delete an artifact-memory record by logical name.
        """
        normalized_name = _normalize_identifier(logical_name, label="logical name")
        with self._lock:
            if normalized_name not in self._records:
                return False
            del self._records[normalized_name]
            return True

    def snapshot(self) -> ArtifactMemorySnapshot:
        """
        Return an immutable snapshot of artifact-memory records.
        """
        with self._lock:
            records = tuple(
                sorted(
                    self._records.values(),
                    key=lambda item: (item.logical_name, item.updated_at, item.artifact_id),
                )
            )
        return ArtifactMemorySnapshot(records=records)

    def count(self) -> int:
        """
        Return the total number of artifact-memory records.
        """
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Remove all artifact-memory records.
        """
        with self._lock:
            self._records.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Artifact memory {label} must not be empty.")
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


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
