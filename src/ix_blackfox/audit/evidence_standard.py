from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, cast

from ix_blackfox.audit.models import (
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditSubject,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_relative_path,
    normalize_sha256,
    normalize_text,
)

_CHUNK_SIZE = 1024 * 1024
_INTERNAL_SOURCE_WAVES = frozenset(
    {
        AuditEvidenceSourceWave.WAVE5,
        AuditEvidenceSourceWave.WAVE6,
        AuditEvidenceSourceWave.WAVE7,
        AuditEvidenceSourceWave.WAVE8,
        AuditEvidenceSourceWave.WAVE9,
    }
)


class EvidenceManifestIssueSeverity(StrEnum):
    """Severity for evidence-standard validation issues."""

    INFO = auto()
    WARNING = auto()
    BLOCKING = auto()


@dataclass(frozen=True, slots=True)
class EvidenceManifestIssue:
    """Single issue found while validating a Wave 9 evidence manifest."""

    issue_id: str
    severity: EvidenceManifestIssueSeverity
    summary: str
    artifact_id: str = ""
    remediation: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "issue_id", normalize_identifier(self.issue_id, label="issue_id"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "artifact_id",
            normalize_optional_text(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(
            self,
            "remediation",
            normalize_optional_text(self.remediation, label="remediation"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocks_audit_ready(self) -> bool:
        return self.severity is EvidenceManifestIssueSeverity.BLOCKING

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "severity": self.severity.value,
            "summary": self.summary,
            "artifact_id": self.artifact_id,
            "remediation": self.remediation,
            "blocks_audit_ready": self.blocks_audit_ready,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceManifestValidationResult:
    """Deterministic validation result for a Wave 9 evidence manifest."""

    manifest_digest: str
    issues: tuple[EvidenceManifestIssue, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest_digest",
            normalize_sha256(self.manifest_digest),
        )
        object.__setattr__(self, "issues", tuple(sorted(self.issues, key=_issue_sort_key)))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def blocking_issue_count(self) -> int:
        return sum(1 for issue in self.issues if issue.blocks_audit_ready)

    @property
    def warning_issue_count(self) -> int:
        return sum(
            1
            for issue in self.issues
            if issue.severity is EvidenceManifestIssueSeverity.WARNING
        )

    @property
    def has_blocking_issues(self) -> bool:
        return self.blocking_issue_count > 0

    @property
    def is_valid(self) -> bool:
        return not self.has_blocking_issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_digest": self.manifest_digest,
            "is_valid": self.is_valid,
            "issue_count": self.issue_count,
            "blocking_issue_count": self.blocking_issue_count,
            "warning_issue_count": self.warning_issue_count,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


def inspect_evidence_file(
    repo_root: str | Path,
    relative_path: str,
    *,
    kind: AuditEvidenceKind,
    source_wave: AuditEvidenceSourceWave,
    artifact_id: str = "",
    producer: str = "ix_blackfox.audit.evidence_standard",
    head_sha: str = "",
    schema_version: str = "",
    verified: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> AuditEvidenceArtifact:
    """
    Inspect one repository-relative evidence file and return normalized metadata.

    The function refuses absolute paths, parent traversal, directories, missing
    files, and symlink escapes outside the declared repository root. It computes
    SHA-256 and byte size from the actual file so later Wave 9 controls can bind
    reports and signoffs to inspectable evidence instead of hand-entered claims.
    """

    normalized_path = normalize_relative_path(relative_path)
    evidence_path = resolve_evidence_path(repo_root, normalized_path)
    if evidence_path.is_dir():
        raise IsADirectoryError(f"Evidence path is a directory, not a file: {normalized_path}")
    size_bytes = evidence_path.stat().st_size
    if size_bytes <= 0:
        raise ValueError(f"Evidence file must not be empty: {normalized_path}")
    return AuditEvidenceArtifact(
        artifact_id=artifact_id or default_artifact_id(kind, source_wave, normalized_path),
        kind=kind,
        source_wave=source_wave,
        path=normalized_path,
        sha256=sha256_file(evidence_path),
        size_bytes=size_bytes,
        producer=producer,
        head_sha=head_sha,
        schema_version=schema_version,
        verified=verified,
        metadata=dict(metadata or {}),
    )


def validate_evidence_manifest(
    manifest: AuditEvidenceManifest,
    *,
    repo_root: str | Path | None = None,
    require_artifacts: bool = True,
    require_internal_head_sha_binding: bool = True,
) -> EvidenceManifestValidationResult:
    """
    Validate a Wave 9 evidence manifest with fail-closed evidence semantics.

    A valid result means the manifest structure and referenced artifacts are
    inspectable under the requested validation mode. It does not mean the repo is
    certified, production-ready, or audit-approved; later controls and human
    signoff still decide the final governance report disposition.
    """

    issues: list[EvidenceManifestIssue] = []
    if require_artifacts and not manifest.artifacts:
        issues.append(
            _issue(
                "W9-EVIDENCE-NO-ARTIFACTS",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence manifest contains no artifacts.",
                remediation="Add at least one inspectable evidence artifact before audit evaluation.",
            )
        )

    artifact_ids = [artifact.artifact_id for artifact in manifest.artifacts]
    duplicate_ids = sorted({artifact_id for artifact_id in artifact_ids if artifact_ids.count(artifact_id) > 1})
    for artifact_id in duplicate_ids:
        issues.append(
            _issue(
                "W9-EVIDENCE-DUPLICATE-ARTIFACT-ID",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence manifest contains a duplicate artifact ID.",
                artifact_id=artifact_id,
                remediation="Give every evidence artifact a unique stable artifact_id.",
            )
        )

    resolved_root: Path | None = None
    if repo_root is not None:
        resolved_root = resolve_repo_root(repo_root)

    for artifact in manifest.artifacts:
        issues.extend(
            _validate_artifact_metadata(
                artifact,
                manifest.subject,
                require_internal_head_sha_binding=require_internal_head_sha_binding,
            )
        )
        if resolved_root is not None:
            issues.extend(_validate_artifact_file(resolved_root, artifact))

    return EvidenceManifestValidationResult(
        manifest_digest=manifest.digest,
        issues=tuple(issues),
        metadata={
            "manifest_id": manifest.manifest_id,
            "artifact_count": manifest.artifact_count,
            "repo_root_checked": str(resolved_root) if resolved_root else "",
            "require_artifacts": require_artifacts,
            "require_internal_head_sha_binding": require_internal_head_sha_binding,
        },
    )


def build_evidence_manifest(
    manifest_id: str,
    subject: AuditSubject,
    artifacts: Sequence[AuditEvidenceArtifact],
    *,
    generated_at: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> AuditEvidenceManifest:
    """Build a deterministic evidence manifest from normalized artifacts."""

    if generated_at is None:
        return AuditEvidenceManifest(
            manifest_id=manifest_id,
            subject=subject,
            artifacts=tuple(artifacts),
            metadata=dict(metadata or {}),
        )
    return AuditEvidenceManifest(
        manifest_id=manifest_id,
        subject=subject,
        artifacts=tuple(artifacts),
        generated_at=generated_at,
        metadata=dict(metadata or {}),
    )


def read_json_evidence_file(repo_root: str | Path, relative_path: str) -> Mapping[str, Any]:
    """Read an evidence JSON object from a repository-relative file."""

    evidence_path = resolve_evidence_path(repo_root, relative_path)
    with evidence_path.open("r", encoding="utf-8") as handle:
        payload: Any = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Evidence JSON file must contain an object: {relative_path}")
    return cast(Mapping[str, Any], payload)


def sha256_file(path: str | Path) -> str:
    """Compute SHA-256 for a file using bounded memory."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_repo_root(repo_root: str | Path) -> Path:
    """Resolve and validate a repository root path."""

    root = Path(repo_root).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {repo_root}")
    return root


def resolve_evidence_path(repo_root: str | Path, relative_path: str) -> Path:
    """Resolve a repository-relative evidence path while preventing escapes."""

    root = resolve_repo_root(repo_root)
    normalized_path = normalize_relative_path(relative_path)
    evidence_path = (root / normalized_path).resolve(strict=True)
    try:
        evidence_path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Evidence path escapes repository root: {relative_path}") from exc
    return evidence_path


def default_artifact_id(
    kind: AuditEvidenceKind,
    source_wave: AuditEvidenceSourceWave,
    relative_path: str,
) -> str:
    """Create a stable safe artifact ID from kind, source wave, and path."""

    normalized_path = normalize_relative_path(relative_path)
    suffix = digest_payload(
        {"kind": kind.value, "source_wave": source_wave.value, "path": normalized_path}
    )[:16]
    return f"artifact:{source_wave.value}:{kind.value}:{suffix}"


def _validate_artifact_metadata(
    artifact: AuditEvidenceArtifact,
    subject: AuditSubject,
    *,
    require_internal_head_sha_binding: bool,
) -> tuple[EvidenceManifestIssue, ...]:
    issues: list[EvidenceManifestIssue] = []
    if artifact.source_wave is AuditEvidenceSourceWave.UNKNOWN:
        issues.append(
            _issue(
                "W9-EVIDENCE-UNKNOWN-SOURCE-WAVE",
                EvidenceManifestIssueSeverity.WARNING,
                "Evidence artifact uses unknown source wave.",
                artifact_id=artifact.artifact_id,
                remediation="Classify the evidence source wave or mark it external if it is outside IX-BlackFox.",
            )
        )
    if artifact.source_wave in _INTERNAL_SOURCE_WAVES and require_internal_head_sha_binding:
        if not artifact.head_sha:
            issues.append(
                _issue(
                    "W9-EVIDENCE-MISSING-HEAD-SHA",
                    EvidenceManifestIssueSeverity.BLOCKING,
                    "Internal IX-BlackFox evidence is not bound to the audited head SHA.",
                    artifact_id=artifact.artifact_id,
                    remediation="Set artifact.head_sha to the same reviewed head SHA as the audit subject.",
                )
            )
        elif artifact.head_sha != subject.head_sha:
            issues.append(
                _issue(
                    "W9-EVIDENCE-HEAD-SHA-MISMATCH",
                    EvidenceManifestIssueSeverity.BLOCKING,
                    "Evidence artifact head SHA does not match the audit subject head SHA.",
                    artifact_id=artifact.artifact_id,
                    remediation="Regenerate or relabel the evidence so it is bound to the reviewed commit.",
                    metadata={
                        "artifact_head_sha": artifact.head_sha,
                        "subject_head_sha": subject.head_sha,
                    },
                )
            )
    if artifact.kind is AuditEvidenceKind.ATTESTATION and not artifact.verified:
        issues.append(
            _issue(
                "W9-EVIDENCE-UNVERIFIED-ATTESTATION",
                EvidenceManifestIssueSeverity.WARNING,
                "Attestation artifact is recorded but not marked verified.",
                artifact_id=artifact.artifact_id,
                remediation=(
                    "Keep the attestation as recorded metadata only, or add an actual verification result before "
                    "treating it as verified provenance."
                ),
            )
        )
    return tuple(issues)


def _validate_artifact_file(
    repo_root: Path,
    artifact: AuditEvidenceArtifact,
) -> tuple[EvidenceManifestIssue, ...]:
    issues: list[EvidenceManifestIssue] = []
    try:
        artifact_path = resolve_evidence_path(repo_root, artifact.path)
    except FileNotFoundError:
        return (
            _issue(
                "W9-EVIDENCE-FILE-MISSING",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact path does not exist.",
                artifact_id=artifact.artifact_id,
                remediation="Regenerate the artifact or remove stale evidence from the manifest.",
                metadata={"path": artifact.path},
            ),
        )
    except (NotADirectoryError, ValueError) as exc:
        return (
            _issue(
                "W9-EVIDENCE-FILE-PATH-INVALID",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact path cannot be resolved safely inside the repository root.",
                artifact_id=artifact.artifact_id,
                remediation="Use a repository-relative evidence path that does not escape the repo root.",
                metadata={"path": artifact.path, "error": str(exc)},
            ),
        )

    if artifact_path.is_dir():
        issues.append(
            _issue(
                "W9-EVIDENCE-FILE-IS-DIRECTORY",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact path resolves to a directory.",
                artifact_id=artifact.artifact_id,
                remediation="Point the evidence artifact at a concrete file.",
                metadata={"path": artifact.path},
            )
        )
        return tuple(issues)

    actual_size = artifact_path.stat().st_size
    if actual_size <= 0:
        issues.append(
            _issue(
                "W9-EVIDENCE-FILE-EMPTY",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact file is empty.",
                artifact_id=artifact.artifact_id,
                remediation="Regenerate the evidence artifact with inspectable content.",
                metadata={"path": artifact.path},
            )
        )
    if actual_size != artifact.size_bytes:
        issues.append(
            _issue(
                "W9-EVIDENCE-SIZE-MISMATCH",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact byte size does not match the manifest.",
                artifact_id=artifact.artifact_id,
                remediation="Regenerate the evidence manifest after producing the final artifact file.",
                metadata={
                    "path": artifact.path,
                    "manifest_size_bytes": artifact.size_bytes,
                    "actual_size_bytes": actual_size,
                },
            )
        )

    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != artifact.sha256:
        issues.append(
            _issue(
                "W9-EVIDENCE-DIGEST-MISMATCH",
                EvidenceManifestIssueSeverity.BLOCKING,
                "Evidence artifact SHA-256 does not match the manifest.",
                artifact_id=artifact.artifact_id,
                remediation="Regenerate the evidence manifest after producing the final artifact file.",
                metadata={
                    "path": artifact.path,
                    "manifest_sha256": artifact.sha256,
                    "actual_sha256": actual_sha256,
                },
            )
        )
    return tuple(issues)


def _issue(
    issue_id: str,
    severity: EvidenceManifestIssueSeverity,
    summary: str,
    *,
    artifact_id: str = "",
    remediation: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceManifestIssue:
    return EvidenceManifestIssue(
        issue_id=issue_id,
        severity=severity,
        summary=summary,
        artifact_id=artifact_id,
        remediation=remediation,
        metadata=dict(metadata or {}),
    )


def _issue_sort_key(issue: EvidenceManifestIssue) -> tuple[str, str]:
    return (issue.issue_id, issue.artifact_id)
