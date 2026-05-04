from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self
from uuid import uuid4


class PatchOperationType(StrEnum):
    """
    Supported patch operation types.

    The patch runtime intentionally starts with a small operation set so the
    governed control plane can reason about file changes without executing
    model-provided code.
    """

    REPLACE = auto()
    CREATE = auto()
    DELETE = auto()


class PatchApplyStatus(StrEnum):
    """
    Result status for applying a PatchDiff to a workspace.
    """

    APPLIED = auto()
    REJECTED = auto()
    FAILED = auto()


@dataclass(frozen=True, slots=True)
class PatchOperation:
    """
    One deterministic file operation inside a patch diff.
    """

    path: str
    operation: PatchOperationType
    before: str | None = None
    after: str | None = None
    rationale: str = "patch operation"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        if self.operation is PatchOperationType.REPLACE and self.before is None:
            raise ValueError("REPLACE operations require before text.")
        if self.operation in {PatchOperationType.REPLACE, PatchOperationType.CREATE} and self.after is None:
            raise ValueError(f"{self.operation.value.upper()} operations require after text.")
        if self.operation is PatchOperationType.DELETE and self.before is None:
            raise ValueError("DELETE operations require before text.")
        object.__setattr__(
            self,
            "rationale",
            _normalize_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def before_sha256(self) -> str | None:
        if self.before is None:
            return None
        return hashlib.sha256(self.before.encode("utf-8")).hexdigest()

    @property
    def after_sha256(self) -> str | None:
        if self.after is None:
            return None
        return hashlib.sha256(self.after.encode("utf-8")).hexdigest()

    @property
    def size_delta(self) -> int:
        before_size = len((self.before or "").encode("utf-8"))
        after_size = len((self.after or "").encode("utf-8"))
        return after_size - before_size

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "path": self.path,
            "operation": self.operation.value,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "size_delta": self.size_delta,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def replace(
        cls,
        *,
        path: str,
        before: str,
        after: str,
        rationale: str = "replace file content",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            operation=PatchOperationType.REPLACE,
            before=before,
            after=after,
            rationale=rationale,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def create(
        cls,
        *,
        path: str,
        after: str,
        rationale: str = "create file",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            operation=PatchOperationType.CREATE,
            after=after,
            rationale=rationale,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def delete(
        cls,
        *,
        path: str,
        before: str,
        rationale: str = "delete file",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            operation=PatchOperationType.DELETE,
            before=before,
            rationale=rationale,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class PatchDiff:
    """
    Deterministic patch diff made of file operations.
    """

    patch_id: str
    operations: tuple[PatchOperation, ...]
    intent_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "patch_id", _normalize_identifier(self.patch_id, label="patch_id")
        )
        operations = tuple(self.operations)
        if not operations:
            raise ValueError("PatchDiff requires at least one operation.")
        duplicate_paths = _duplicate_paths(operation.path for operation in operations)
        if duplicate_paths:
            raise ValueError(
                f"PatchDiff cannot contain duplicate paths: {', '.join(duplicate_paths)}."
            )
        object.__setattr__(self, "operations", operations)
        object.__setattr__(
            self, "intent_id", _normalize_optional_identifier(self.intent_id)
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        operations: Iterable[PatchOperation],
        intent_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            patch_id=f"patch-{uuid4().hex}",
            operations=tuple(operations),
            intent_id=intent_id,
            metadata=dict(metadata or {}),
        )

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(operation.path for operation in self.operations)

    @property
    def total_size_delta(self) -> int:
        return sum(operation.size_delta for operation in self.operations)

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "patch_id": self.patch_id,
            "intent_id": self.intent_id,
            "operation_count": len(self.operations),
            "changed_paths": list(self.changed_paths),
            "total_size_delta": self.total_size_delta,
            "operations": [
                operation.to_dict(include_digest=include_digest)
                for operation in self.operations
            ],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload
