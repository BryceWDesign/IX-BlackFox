from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self
from uuid import uuid4


class RunBundleArtifactKind(StrEnum):
    """
    Canonical artifact categories inside a BlackFox run bundle.

    The layout is intentionally boring and review-friendly. A skeptical operator
    should know where to look for receipts, patches, tests, verification, traces,
    and the human-readable summary without knowing the internal Python modules.
    """

    RUN_REPORT = auto()
    GOVERNANCE_RECEIPTS = auto()
    TOOL_RECEIPTS = auto()
    REPAIR_RECEIPTS = auto()
    PATCH_MODEL = auto()
    PATCH_DIFF = auto()
    TEST_RESULT = auto()
    TEST_STDOUT = auto()
    TEST_STDERR = auto()
    VERIFICATION_SUMMARY = auto()
    OPERATOR_SUMMARY = auto()
    TRACE = auto()
    MANIFEST = auto()
    GENERIC = auto()


@dataclass(frozen=True, slots=True)
class RunBundleArtifact:
    """
    Manifest entry for one persisted run-bundle artifact.
    """

    artifact_id: str
    kind: RunBundleArtifactKind
    relative_path: str
    media_type: str
    sha256: str
    size_bytes: int
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            _normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(
            self,
            "relative_path",
            _normalize_relative_path(self.relative_path),
        )
        object.__setattr__(
            self,
            "media_type",
            _normalize_text(self.media_type, label="media_type"),
        )
        object.__setattr__(
            self,
            "sha256",
            _normalize_digest(self.sha256),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.size_bytes < 0:
            raise ValueError("RunBundleArtifact size_bytes must not be negative.")
        if self.created_at.tzinfo is None:
            raise ValueError("RunBundleArtifact created_at must be timezone-aware.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "relative_path": self.relative_path,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            artifact_id=_require_text(payload, "artifact_id"),
            kind=RunBundleArtifactKind(_require_text(payload, "kind")),
            relative_path=_require_text(payload, "relative_path"),
            media_type=_require_text(payload, "media_type"),
            sha256=_require_text(payload, "sha256"),
            size_bytes=int(payload.get("size_bytes", 0)),
            created_at=_parse_datetime(_require_text(payload, "created_at")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RunBundleManifest:
    """
    Manifest for the complete contents of one operator run bundle.
    """

    bundle_id: str
    run_id: str
    task_id: str | None
    root_path: str
    created_at: datetime
    artifacts: tuple[RunBundleArtifact, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "bundle_id",
            _normalize_identifier(self.bundle_id, label="bundle_id"),
        )
        object.__setattr__(
            self,
            "run_id",
            _normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(self, "task_id", _normalize_optional_identifier(self.task_id))
        object.__setattr__(self, "root_path", _normalize_text(self.root_path, label="root_path"))
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.created_at.tzinfo is None:
            raise ValueError("RunBundleManifest created_at must be timezone-aware.")

        paths = [artifact.relative_path for artifact in self.artifacts]
        duplicate_paths = tuple(sorted(path for path in set(paths) if paths.count(path) > 1))
        if duplicate_paths:
            raise ValueError(
                "RunBundleManifest cannot contain duplicate artifact paths: "
                f"{', '.join(duplicate_paths)}."
            )

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def artifact_paths(self) -> tuple[str, ...]:
        return tuple(artifact.relative_path for artifact in self.artifacts)

    @property
    def digest(self) -> str:
        payload = {
            "bundle_id": self.bundle_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "root_path": self.root_path,
            "created_at": self.created_at.isoformat(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "metadata": dict(self.metadata),
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def add_artifact(self, artifact: RunBundleArtifact) -> RunBundleManifest:
        if artifact.relative_path in self.artifact_paths:
            raise ValueError(
                f"Run bundle artifact already exists: {artifact.relative_path!r}."
            )
        return replace(self, artifacts=(*self.artifacts, artifact))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "root_path": self.root_path,
            "created_at": self.created_at.isoformat(),
            "artifact_count": self.artifact_count,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "digest": self.digest,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_artifacts = payload.get("artifacts", ())
        if not isinstance(raw_artifacts, list | tuple):
            raise TypeError("artifacts must be a list or tuple of mappings.")

        artifacts: list[RunBundleArtifact] = []
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise TypeError("artifacts must contain only mappings.")
            artifacts.append(RunBundleArtifact.from_dict(raw_artifact))

        return cls(
            bundle_id=_require_text(payload, "bundle_id"),
            run_id=_require_text(payload, "run_id"),
            task_id=_optional_text_from_payload(payload, "task_id"),
            root_path=_require_text(payload, "root_path"),
            created_at=_parse_datetime(_require_text(payload, "created_at")),
            artifacts=tuple(artifacts),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RunBundleLayout:
    """
    Directory layout for one IX-BlackFox run bundle.

    Example:

    artifacts/runs/<run_id>/
      manifest.json
      reports/run-report.json
      reports/operator-summary.md
      receipts/governance-receipts.json
      receipts/tool-receipts.json
      receipts/repair-receipts.json
      patches/
      tests/
      verification/
      traces/
    """

    root_dir: Path
    run_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "run_id",
            _normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(self, "root_dir", self.root_dir.expanduser().resolve())

    @property
    def bundle_root(self) -> Path:
        return self.root_dir / "artifacts" / "runs" / self.run_id

    @property
    def reports_dir(self) -> Path:
        return self.bundle_root / "reports"

    @property
    def receipts_dir(self) -> Path:
        return self.bundle_root / "receipts"

    @property
    def patches_dir(self) -> Path:
        return self.bundle_root / "patches"

    @property
    def tests_dir(self) -> Path:
        return self.bundle_root / "tests"

    @property
    def verification_dir(self) -> Path:
        return self.bundle_root / "verification"

    @property
    def traces_dir(self) -> Path:
        return self.bundle_root / "traces"

    @property
    def manifest_path(self) -> Path:
        return self.bundle_root / "manifest.json"

    def ensure_directories(self) -> None:
        for directory in (
            self.bundle_root,
            self.reports_dir,
            self.receipts_dir,
            self.patches_dir,
            self.tests_dir,
            self.verification_dir,
            self.traces_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def relative_to_bundle(self, path: Path) -> str:
        resolved = path.expanduser().resolve()
        bundle_root = self.bundle_root.resolve()
        if not _is_relative_to(resolved, bundle_root):
            raise ValueError(f"Path is outside run bundle root: {path}")
        return resolved.relative_to(bundle_root).as_posix()

    def path_for_kind(self, kind: RunBundleArtifactKind, filename: str) -> Path:
        safe_filename = _normalize_filename(filename)

        if kind is RunBundleArtifactKind.RUN_REPORT:
            return self.reports_dir / safe_filename
        if kind is RunBundleArtifactKind.OPERATOR_SUMMARY:
            return self.reports_dir / safe_filename
        if kind is RunBundleArtifactKind.VERIFICATION_SUMMARY:
            return self.verification_dir / safe_filename
        if kind in {
            RunBundleArtifactKind.GOVERNANCE_RECEIPTS,
            RunBundleArtifactKind.TOOL_RECEIPTS,
            RunBundleArtifactKind.REPAIR_RECEIPTS,
        }:
            return self.receipts_dir / safe_filename
        if kind in {RunBundleArtifactKind.PATCH_MODEL, RunBundleArtifactKind.PATCH_DIFF}:
            return self.patches_dir / safe_filename
        if kind in {
            RunBundleArtifactKind.TEST_RESULT,
            RunBundleArtifactKind.TEST_STDOUT,
            RunBundleArtifactKind.TEST_STDERR,
        }:
            return self.tests_dir / safe_filename
        if kind is RunBundleArtifactKind.TRACE:
            return self.traces_dir / safe_filename
        if kind is RunBundleArtifactKind.MANIFEST:
            return self.manifest_path

        return self.bundle_root / safe_filename


@dataclass(slots=True)
class RunBundleWriter:
    """
    Filesystem writer for operator run bundles.

    The writer owns a manifest and persists every artifact beneath the layout's
    bundle root. It refuses absolute/traversal artifact paths by routing writes
    through ``RunBundleLayout.path_for_kind`` and checking the resolved path.
    """

    layout: RunBundleLayout
    task_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    _manifest: RunBundleManifest = field(init=False)

    def __post_init__(self) -> None:
        self.layout.ensure_directories()
        self._manifest = RunBundleManifest(
            bundle_id=f"run-bundle-{uuid4().hex}",
            run_id=self.layout.run_id,
            task_id=self.task_id,
            root_path=str(self.layout.bundle_root),
            created_at=datetime.now(tz=UTC),
            artifacts=(),
            metadata=dict(self.metadata),
        )

    @property
    def manifest(self) -> RunBundleManifest:
        return self._manifest

    def write_json(
        self,
        *,
        kind: RunBundleArtifactKind,
        filename: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> RunBundleArtifact:
        text = json.dumps(
            dict(payload),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        return self.write_text(
            kind=kind,
            filename=filename,
            text=f"{text}\n",
            media_type="application/json",
            metadata=metadata,
        )

    def write_text(
        self,
        *,
        kind: RunBundleArtifactKind,
        filename: str,
        text: str,
        media_type: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> RunBundleArtifact:
        return self.write_bytes(
            kind=kind,
            filename=filename,
            payload=text.encode("utf-8"),
            media_type=media_type,
            metadata=metadata,
        )

    def write_bytes(
        self,
        *,
        kind: RunBundleArtifactKind,
        filename: str,
        payload: bytes,
        media_type: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> RunBundleArtifact:
        destination = self.layout.path_for_kind(kind, filename).resolve()
        bundle_root = self.layout.bundle_root.resolve()

        if not _is_relative_to(destination, bundle_root):
            raise ValueError(f"Run bundle artifact path escapes bundle root: {filename!r}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

        artifact = RunBundleArtifact(
            artifact_id=f"run-artifact-{uuid4().hex}",
            kind=kind,
            relative_path=self.layout.relative_to_bundle(destination),
            media_type=media_type,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            created_at=datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )
        self._manifest = self._manifest.add_artifact(artifact)
        return artifact

    def persist_manifest(self) -> RunBundleArtifact:
        """
        Persist manifest.json and return its artifact entry.

        The manifest artifact is not added to the manifest before writing because
        that would create a self-referential digest. Instead, the manifest file
        contains the exact manifest state for all previously written artifacts.
        """
        payload = self._manifest.to_dict()
        text = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")

        destination = self.layout.manifest_path.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(text + b"\n")

        return RunBundleArtifact(
            artifact_id=f"run-artifact-{uuid4().hex}",
            kind=RunBundleArtifactKind.MANIFEST,
            relative_path=self.layout.relative_to_bundle(destination),
            media_type="application/json",
            sha256=hashlib.sha256(text + b"\n").hexdigest(),
            size_bytes=len(text) + 1,
            created_at=datetime.now(tz=UTC),
            metadata={
                "manifest_digest": self._manifest.digest,
                "artifact_count": self._manifest.artifact_count,
            },
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label="optional_identifier")


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_digest(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("Digest must be a 64-character SHA-256 hex string.")
    int(cleaned, 16)
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative_path must not be empty.")
    if cleaned.startswith(("/", "~")):
        raise ValueError(f"relative_path must be relative: {value!r}.")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"relative_path must not contain traversal: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("relative_path must not resolve to the bundle root.")

    return "/".join(parts)


def _normalize_filename(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("filename must not be empty.")
    if "/" in cleaned or cleaned.startswith(("~", ".")):
        raise ValueError(
            "filename must be a simple file name, not a path or hidden file."
        )
    return cleaned


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Serialized datetimes must be timezone-aware.")
    return parsed


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
