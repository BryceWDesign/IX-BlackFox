from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from uuid import uuid4

if TYPE_CHECKING:
    from ix_blackfox.runtime.control_plane import AuthoredEngineeringControlPlaneReport
    from ix_blackfox.runtime.wave3_acceptance import Wave3AcceptanceReport


class Wave3EvidenceArtifactKind(StrEnum):
    """
    File kinds written by the Wave 3 evidence package writer.
    """

    AUTHORED_ENGINEERING_REPORT = auto()
    AUTHORING_RECEIPTS = auto()
    WAVE3_ACCEPTANCE_REPORT = auto()
    WAVE2_ENGINEERING_REPORT = auto()
    WAVE3_EVIDENCE_INDEX = auto()
    WAVE3_PACKAGE_MANIFEST = auto()


@dataclass(frozen=True, slots=True)
class Wave3EvidenceArtifact:
    """
    One persisted Wave 3 evidence artifact.
    """

    kind: Wave3EvidenceArtifactKind
    path: str
    sha256: str
    size_bytes: int
    media_type: str = "application/json"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_text(self.path, label="path"))
        object.__setattr__(self, "sha256", _normalize_sha256(self.sha256))
        object.__setattr__(
            self, "media_type", _normalize_text(self.media_type, label="media_type")
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.size_bytes < 0:
            raise ValueError("size_bytes must be zero or greater.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            kind=Wave3EvidenceArtifactKind(_require_text(payload, "kind")),
            path=_require_text(payload, "path"),
            sha256=_require_text(payload, "sha256"),
            size_bytes=_require_int(payload, "size_bytes"),
            media_type=_require_text(payload, "media_type"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class Wave3EvidencePackageManifest:
    """
    Manifest for a persisted Wave 3 evidence package.

    The package is separate from the Wave 2 run bundle. It preserves the
    authored repair layer, authoring receipts, acceptance report, and linked
    Wave 2 report together for review.
    """

    package_id: str
    run_id: str
    task_id: str
    root_path: str
    acceptance_status: str
    selected_patch_id: str | None
    selected_candidate_id: str | None
    authoring_chain_digest: str | None
    artifact_count: int
    artifacts: tuple[Wave3EvidenceArtifact, ...]
    created_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "package_id",
            _normalize_identifier(self.package_id, label="package_id"),
        )
        object.__setattr__(
            self, "run_id", _normalize_identifier(self.run_id, label="run_id")
        )
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        object.__setattr__(
            self, "root_path", _normalize_text(self.root_path, label="root_path")
        )
        object.__setattr__(
            self,
            "acceptance_status",
            _normalize_text(self.acceptance_status, label="acceptance_status"),
        )
        object.__setattr__(
            self,
            "selected_patch_id",
            _normalize_optional_identifier(
                self.selected_patch_id, label="selected_patch_id"
            ),
        )
        object.__setattr__(
            self,
            "selected_candidate_id",
            _normalize_optional_identifier(
                self.selected_candidate_id, label="selected_candidate_id"
            ),
        )
        object.__setattr__(
            self,
            "authoring_chain_digest",
            _normalize_optional_sha256(self.authoring_chain_digest),
        )
        artifacts = tuple(self.artifacts)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "created_at", _normalize_datetime(self.created_at))
        object.__setattr__(self, "metadata", dict(self.metadata))

        manifest_included = any(
            artifact.kind is Wave3EvidenceArtifactKind.WAVE3_PACKAGE_MANIFEST
            for artifact in artifacts
        )
        valid_counts = {len(artifacts)}
        if manifest_included:
            valid_counts.add(len(artifacts) - 1)
        if self.artifact_count not in valid_counts:
            raise ValueError(
                "artifact_count must match persisted core artifacts, "
                "excluding the package manifest when that self-artifact is included."
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(self.to_dict(include_digest=False)).encode("utf-8")
        ).hexdigest()

    @property
    def artifact_paths(self) -> tuple[str, ...]:
        return tuple(artifact.path for artifact in self.artifacts)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "package_id": self.package_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "root_path": self.root_path,
            "acceptance_status": self.acceptance_status,
            "selected_patch_id": self.selected_patch_id,
            "selected_candidate_id": self.selected_candidate_id,
            "authoring_chain_digest": self.authoring_chain_digest,
            "artifact_count": self.artifact_count,
            "artifact_paths": list(self.artifact_paths),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            package_id=_require_text(payload, "package_id"),
            run_id=_require_text(payload, "run_id"),
            task_id=_require_text(payload, "task_id"),
            root_path=_require_text(payload, "root_path"),
            acceptance_status=_require_text(payload, "acceptance_status"),
            selected_patch_id=_optional_text_from_payload(payload, "selected_patch_id"),
            selected_candidate_id=_optional_text_from_payload(
                payload, "selected_candidate_id"
            ),
            authoring_chain_digest=_optional_text_from_payload(
                payload, "authoring_chain_digest"
            ),
            artifact_count=_require_int(payload, "artifact_count"),
            artifacts=_load_artifacts(payload.get("artifacts", ())),
            created_at=_datetime_from_payload(payload, "created_at"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class Wave3EvidencePackageWriterConfig:
    """
    Configuration for Wave 3 evidence package output.
    """

    package_dir_name: str = "wave3-evidence"
    overwrite_existing: bool = True
    indent: int = 2

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "package_dir_name",
            _normalize_safe_dir_name(self.package_dir_name),
        )
        if self.indent < 0:
            raise ValueError("indent must be zero or greater.")


@dataclass(frozen=True, slots=True)
class Wave3EvidencePackageWriter:
    """
    Persist Wave 3 authored-repair evidence to disk.

    This writer does not evaluate success. It packages the evidence already
    produced by the authored repair runtime, Wave 2 control plane, and Wave 3
    acceptance validator.
    """

    root_dir: Path
    config: Wave3EvidencePackageWriterConfig = field(
        default_factory=Wave3EvidencePackageWriterConfig
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "root_dir", self.root_dir.expanduser().resolve())

    def write(
        self,
        *,
        authored_report: AuthoredEngineeringControlPlaneReport,
        acceptance_report: Wave3AcceptanceReport,
        metadata: Mapping[str, Any] | None = None,
    ) -> Wave3EvidencePackageManifest:
        package_root = (
            self.root_dir / authored_report.run_id / self.config.package_dir_name
        )
        if package_root.exists() and not self.config.overwrite_existing:
            raise FileExistsError(
                f"Wave 3 evidence package already exists: {package_root}"
            )

        package_root.mkdir(parents=True, exist_ok=True)

        artifacts: list[Wave3EvidenceArtifact] = []

        artifacts.append(
            self._write_json_artifact(
                package_root=package_root,
                kind=Wave3EvidenceArtifactKind.AUTHORED_ENGINEERING_REPORT,
                filename="authored-engineering-report.json",
                payload=authored_report.to_dict(),
                metadata={
                    "run_id": authored_report.run_id,
                    "task_id": authored_report.task_id,
                    "authored_status": authored_report.authored_status,
                    "wave2_executed": authored_report.wave2_executed,
                },
            )
        )

        artifacts.append(
            self._write_json_artifact(
                package_root=package_root,
                kind=Wave3EvidenceArtifactKind.AUTHORING_RECEIPTS,
                filename="authoring-receipts.json",
                payload=authored_report.authored_repair_report.receipt_snapshot.to_dict(),
                metadata={
                    "receipt_count": authored_report.authored_repair_report.receipt_snapshot.count,
                    "latest_chain_digest": authored_report.authored_repair_report.receipt_snapshot.latest_chain_digest,
                },
            )
        )

        artifacts.append(
            self._write_json_artifact(
                package_root=package_root,
                kind=Wave3EvidenceArtifactKind.WAVE3_ACCEPTANCE_REPORT,
                filename="wave3-acceptance-report.json",
                payload=acceptance_report.to_dict(),
                metadata={
                    "acceptance_status": acceptance_report.status.value,
                    "acceptance_digest": acceptance_report.digest,
                    "selected_patch_id": acceptance_report.selected_patch_id,
                },
            )
        )

        if authored_report.wave2_report is not None:
            artifacts.append(
                self._write_json_artifact(
                    package_root=package_root,
                    kind=Wave3EvidenceArtifactKind.WAVE2_ENGINEERING_REPORT,
                    filename="wave2-engineering-report.json",
                    payload=authored_report.wave2_report.to_dict(),
                    metadata={
                        "wave2_succeeded": authored_report.wave2_report.succeeded,
                        "verification_status": authored_report.wave2_report.verification_status,
                        "bundle_root": authored_report.wave2_report.bundle_root,
                    },
                )
            )

        evidence_index = self._build_evidence_index_payload(
            authored_report=authored_report,
            acceptance_report=acceptance_report,
            artifacts=tuple(artifacts),
            package_root=package_root,
            metadata=dict(metadata or {}),
        )
        artifacts.append(
            self._write_json_artifact(
                package_root=package_root,
                kind=Wave3EvidenceArtifactKind.WAVE3_EVIDENCE_INDEX,
                filename="wave3-evidence-index.json",
                payload=evidence_index,
                metadata={
                    "index_for": authored_report.run_id,
                    "artifact_count_before_index": len(artifacts),
                },
            )
        )

        manifest_without_self = Wave3EvidencePackageManifest(
            package_id=f"wave3-evidence-package-{uuid4().hex}",
            run_id=authored_report.run_id,
            task_id=authored_report.task_id,
            root_path=str(package_root),
            acceptance_status=acceptance_report.status.value,
            selected_patch_id=authored_report.selected_patch_id,
            selected_candidate_id=None
            if authored_report.authored_repair_report.selected_candidate is None
            else authored_report.authored_repair_report.selected_candidate.candidate_id,
            authoring_chain_digest=authored_report.authored_repair_report.receipt_snapshot.latest_chain_digest,
            artifact_count=len(artifacts),
            artifacts=tuple(artifacts),
            created_at=datetime.now(tz=UTC),
            metadata={
                "writer": "Wave3EvidencePackageWriter",
                "wave": 3,
                "wave2_executed": authored_report.wave2_executed,
                "acceptance_passed": acceptance_report.passed,
                **dict(metadata or {}),
            },
        )

        manifest_artifact = self._write_json_artifact(
            package_root=package_root,
            kind=Wave3EvidenceArtifactKind.WAVE3_PACKAGE_MANIFEST,
            filename="wave3-evidence-manifest.json",
            payload=manifest_without_self.to_dict(),
            metadata={
                "manifest_digest": manifest_without_self.digest,
                "manifest_for": authored_report.run_id,
            },
        )

        final_artifacts = (*artifacts, manifest_artifact)
        return Wave3EvidencePackageManifest(
            package_id=manifest_without_self.package_id,
            run_id=manifest_without_self.run_id,
            task_id=manifest_without_self.task_id,
            root_path=manifest_without_self.root_path,
            acceptance_status=manifest_without_self.acceptance_status,
            selected_patch_id=manifest_without_self.selected_patch_id,
            selected_candidate_id=manifest_without_self.selected_candidate_id,
            authoring_chain_digest=manifest_without_self.authoring_chain_digest,
            artifact_count=manifest_without_self.artifact_count,
            artifacts=final_artifacts,
            created_at=manifest_without_self.created_at,
            metadata=manifest_without_self.metadata,
        )

    def _write_json_artifact(
        self,
        *,
        package_root: Path,
        kind: Wave3EvidenceArtifactKind,
        filename: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> Wave3EvidenceArtifact:
        target = package_root / filename
        text = (
            json.dumps(
                _to_jsonable(dict(payload)),
                indent=self.config.indent,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        )
        target.write_text(text, encoding="utf-8")

        relative_path = target.relative_to(self.root_dir).as_posix()
        encoded = text.encode("utf-8")

        return Wave3EvidenceArtifact(
            kind=kind,
            path=relative_path,
            sha256=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
            media_type="application/json",
            metadata=dict(metadata or {}),
        )

    def _build_evidence_index_payload(
        self,
        *,
        authored_report: AuthoredEngineeringControlPlaneReport,
        acceptance_report: Wave3AcceptanceReport,
        artifacts: tuple[Wave3EvidenceArtifact, ...],
        package_root: Path,
        metadata: Mapping[str, Any],
    ) -> dict[str, Any]:
        authored_runtime_report = authored_report.authored_repair_report
        selected_candidate = authored_runtime_report.selected_candidate
        selected_patch = authored_runtime_report.selected_patch

        return {
            "schema_version": "wave3.evidence_index.v1",
            "run_id": authored_report.run_id,
            "task_id": authored_report.task_id,
            "package_root": str(package_root),
            "authored_status": authored_report.authored_status,
            "acceptance_status": acceptance_report.status.value,
            "acceptance_passed": acceptance_report.passed,
            "wave2_executed": authored_report.wave2_executed,
            "wave2_succeeded": False
            if authored_report.wave2_report is None
            else authored_report.wave2_report.succeeded,
            "selected_candidate_id": None
            if selected_candidate is None
            else selected_candidate.candidate_id,
            "selected_patch_id": None
            if selected_patch is None
            else selected_patch.patch_id,
            "selected_patch_digest": None
            if selected_patch is None
            else selected_patch.digest,
            "authoring_request_id": authored_runtime_report.request.request_id,
            "authoring_receipt_count": authored_runtime_report.receipt_snapshot.count,
            "authoring_chain_digest": authored_runtime_report.receipt_snapshot.latest_chain_digest,
            "proposal_count": len(authored_runtime_report.proposals),
            "compiled_candidate_count": len(
                authored_runtime_report.compiled_candidates
            ),
            "policy_report_count": len(authored_runtime_report.policy_reports),
            "artifact_count": len(artifacts),
            "artifacts": [artifact.to_dict() for artifact in artifacts],
            "metadata": dict(metadata),
        }


def _load_artifacts(value: Any) -> tuple[Wave3EvidenceArtifact, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("artifacts must be an iterable of mappings.")

    artifacts: list[Wave3EvidenceArtifact] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("artifacts must contain only mappings.")
        artifacts.append(Wave3EvidenceArtifact.from_dict(item))
    return tuple(artifacts)


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        _to_jsonable(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _to_jsonable(nested) for key, nested in value.items()}
    if isinstance(value, tuple | list):
        return [_to_jsonable(item) for item in value]
    return value


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_safe_dir_name(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("package_dir_name must not be empty.")
    if "/" in cleaned or cleaned in {".", ".."}:
        raise ValueError("package_dir_name must be a single safe directory name.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _datetime_from_payload(payload: Mapping[str, Any], key: str) -> datetime:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be an ISO datetime string.")
    return _normalize_datetime(datetime.fromisoformat(value))


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


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value
