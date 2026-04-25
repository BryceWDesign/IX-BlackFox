from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.tools.contracts import ToolOutputArtifact


class ToolArtifactPersistenceError(RuntimeError):
    """
    Raised when a governed tool artifact cannot be safely persisted.
    """


@dataclass(frozen=True, slots=True)
class ToolArtifactStore:
    """
    Filesystem-backed artifact store for governed tool outputs.

    The store only writes below its configured artifact root. It rejects absolute
    paths and traversal so a tool cannot smuggle output into arbitrary host
    locations. Returned artifact contracts include URI, media type, size, and
    SHA-256 digest for later receipt capture and run-bundle export.
    """

    artifact_root: Path

    def __post_init__(self) -> None:
        root = self.artifact_root.expanduser().resolve()
        object.__setattr__(self, "artifact_root", root)

    def write_text(
        self,
        *,
        relative_path: str,
        text: str,
        media_type: str = "text/plain",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolOutputArtifact:
        payload = text.encode("utf-8")
        return self.write_bytes(
            relative_path=relative_path,
            payload=payload,
            media_type=media_type,
            metadata={
                "encoding": "utf-8",
                **dict(metadata or {}),
            },
        )

    def write_json(
        self,
        *,
        relative_path: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolOutputArtifact:
        text = json.dumps(
            dict(payload),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        return self.write_text(
            relative_path=relative_path,
            text=f"{text}\n",
            media_type="application/json",
            metadata=metadata,
        )

    def write_bytes(
        self,
        *,
        relative_path: str,
        payload: bytes,
        media_type: str = "application/octet-stream",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolOutputArtifact:
        destination = self.resolve_relative_path(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

        digest = hashlib.sha256(payload).hexdigest()
        uri = destination.relative_to(self.artifact_root).as_posix()

        return ToolOutputArtifact.create(
            name=destination.name,
            uri=uri,
            media_type=media_type,
            sha256=digest,
            metadata={
                "artifact_root": str(self.artifact_root),
                "relative_path": uri,
                "size_bytes": len(payload),
                **dict(metadata or {}),
            },
        )

    def resolve_relative_path(self, relative_path: str) -> Path:
        cleaned = relative_path.strip().replace("\\", "/")
        if not cleaned:
            raise ToolArtifactPersistenceError("Artifact relative_path must not be empty.")

        candidate = Path(cleaned)
        if candidate.is_absolute() or cleaned.startswith("~"):
            raise ToolArtifactPersistenceError(
                f"Artifact path must be relative: {relative_path!r}."
            )

        destination = (self.artifact_root / candidate).resolve()
        if not _is_relative_to(destination, self.artifact_root):
            raise ToolArtifactPersistenceError(
                f"Artifact path escapes artifact root: {relative_path!r}."
            )

        return destination


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
