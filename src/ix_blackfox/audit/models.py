from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any

WAVE9_GOVERNANCE_REPORT_SCHEMA_VERSION = "wave9.compliance_audit_attestation.v1"
WAVE9_EVIDENCE_MANIFEST_SCHEMA_VERSION = "wave9.evidence_manifest.v1"
WAVE9_POLICY_PACK_SCHEMA_VERSION = "wave9.policy_pack.v1"
WAVE9_ATTESTATION_SUBJECT_SCHEMA_VERSION = "wave9.attestation_subject.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")


class AuditDisposition(StrEnum):
    """Final Wave 9 audit gate disposition."""

    AUDIT_READY = auto()
    WARNING = auto()
    BLOCKED = auto()


class AuditControlStatus(StrEnum):
    """Per-control evaluation status."""

    PASSED = auto()
    WARNING = auto()
    BLOCKED = auto()
    NOT_APPLICABLE = auto()


class AuditControlSeverity(StrEnum):
    """Control severity used by fail-closed audit evaluation."""

    INFO = auto()
    WARNING = auto()
    BLOCKING = auto()


class AuditEvidenceKind(StrEnum):
    """Kinds of evidence Wave 9 can normalize into an audit manifest."""

    PR_EVIDENCE_PACK = auto()
    CI_EVIDENCE = auto()
    APPROVAL_RECORD = auto()
    HUMAN_REVIEW = auto()
    GOVERNANCE_RECEIPT = auto()
    SANDBOX_RECEIPT_BUNDLE = auto()
    SANDBOX_ADVERSARIAL_REPORT = auto()
    MODEL_REPAIR_REPORT = auto()
    MODEL_REPAIR_RECEIPT = auto()
    REPOSITORY_INTELLIGENCE_REPORT = auto()
    REPOSITORY_EVIDENCE_SNAPSHOT = auto()
    POLICY_DECISION = auto()
    ATTESTATION = auto()
    GOVERNANCE_REPORT = auto()
    OTHER = auto()


class AuditEvidenceSourceWave(StrEnum):
    """Origin layer for evidence consumed by Wave 9."""

    WAVE5 = auto()
    WAVE6 = auto()
    WAVE7 = auto()
    WAVE8 = auto()
    WAVE9 = auto()
    EXTERNAL = auto()
    UNKNOWN = auto()


class AuditReviewerKind(StrEnum):
    """Reviewer authority category for audit signoff."""

    HUMAN = auto()
    SYSTEM = auto()
    MODEL = auto()


class AuditReviewDecision(StrEnum):
    """Reviewer decision captured by Wave 9 signoff."""

    APPROVED = auto()
    CHANGES_REQUESTED = auto()
    REJECTED = auto()
    COMMENTED = auto()


class AuditStandardsMappingKind(StrEnum):
    """Bounded external/internal mapping labels, not compliance claims."""

    INTERNAL_IX_BLACKFOX = auto()
    NIST_SSDF = auto()
    OSCAL_ASSESSMENT_RESULTS = auto()
    SLSA_PROVENANCE = auto()
    IN_TOTO_STATEMENT = auto()
    GITHUB_ARTIFACT_ATTESTATION = auto()
    DOD_ENTERPRISE_DEVSECOPS = auto()
    OTHER = auto()


@dataclass(frozen=True, slots=True)
class AuditStandardsMapping:
    """
    Bounded standards alignment note.

    This records why a Wave 9 control is shaped like a known public standard
    pattern. It is not a certification, assessment result, ATO/cATO, or proof of
    formal compliance.
    """

    kind: AuditStandardsMappingKind
    reference_id: str
    summary: str
    claim: str = "alignment_reference_only"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference_id",
            normalize_identifier(self.reference_id, label="reference_id"),
        )
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "claim", normalize_text(self.claim, label="claim"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "reference_id": self.reference_id,
            "summary": self.summary,
            "claim": self.claim,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AuditSubject:
    """Repository/change subject bound to Wave 9 audit evidence."""

    repository: str
    head_sha: str
    scope: str
    changed_paths: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository",
            normalize_identifier(self.repository, label="repository"),
        )
        object.__setattr__(self, "head_sha", normalize_head_sha(self.head_sha))
        object.__setattr__(self, "scope", normalize_text(self.scope, label="scope"))
        object.__setattr__(
            self,
            "changed_paths",
            normalize_path_tuple(self.changed_paths, label="changed_paths"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE9_ATTESTATION_SUBJECT_SCHEMA_VERSION,
            "repository": self.repository,
            "head_sha": self.head_sha,
            "scope": self.scope,
            "changed_paths": list(self.changed_paths),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AuditEvidenceArtifact:
    """Single evidence artifact normalized for Wave 9 audit evaluation."""

    artifact_id: str
    kind: AuditEvidenceKind
    source_wave: AuditEvidenceSourceWave
    path: str
    sha256: str
    size_bytes: int
    producer: str
    head_sha: str = ""
    schema_version: str = ""
    verified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256))
        if self.size_bytes <= 0:
            raise ValueError("size_bytes must be greater than zero for audit evidence.")
        object.__setattr__(self, "producer", normalize_text(self.producer, label="producer"))
        object.__setattr__(self, "head_sha", normalize_optional_head_sha(self.head_sha))
        object.__setattr__(
            self,
            "schema_version",
            normalize_optional_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "source_wave": self.source_wave.value,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "producer": self.producer,
            "head_sha": self.head_sha,
            "schema_version": self.schema_version,
            "verified": self.verified,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AuditEvidenceManifest:
    """Deterministic Wave 9 evidence manifest."""

    manifest_id: str
    subject: AuditSubject
    artifacts: tuple[AuditEvidenceArtifact, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest_id",
            normalize_identifier(self.manifest_id, label="manifest_id"),
        )
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")
        artifacts = tuple(sorted(self.artifacts, key=lambda item: item.artifact_id))
        artifact_ids = [artifact.artifact_id for artifact in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("AuditEvidenceManifest artifact_id values must be unique.")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def artifact_by_id(self, artifact_id: str) -> AuditEvidenceArtifact:
        normalized = normalize_identifier(artifact_id, label="artifact_id")
        for artifact in self.artifacts:
            if artifact.artifact_id == normalized:
                return artifact
        raise KeyError(f"Unknown audit evidence artifact: {normalized}")

    def artifacts_by_kind(self, kind: AuditEvidenceKind) -> tuple[AuditEvidenceArtifact, ...]:
        return tuple(artifact for artifact in self.artifacts if artifact.kind is kind)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE9_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            "manifest_id": self.manifest_id,
            "subject": self.subject.to_dict(),
            "generated_at": self.generated_at.isoformat(),
            "artifact_count": self.artifact_count,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AuditControlRequirement:
    """Policy-pack control requirement evaluated by Wave 9."""

    control_id: str
    title: str
    objective: str
    severity: AuditControlSeverity
    required_evidence_kinds: tuple[AuditEvidenceKind, ...] = ()
    standards_mappings: tuple[AuditStandardsMapping, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "objective", normalize_text(self.objective, label="objective"))
        object.__setattr__(
            self,
            "required_evidence_kinds",
            tuple(self.required_evidence_kinds),
        )
        object.__setattr__(
            self,
            "standards_mappings",
            tuple(sorted(self.standards_mappings, key=lambda item: item.reference_id)),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "objective": self.objective,
            "severity": self.severity.value,
            "required_evidence_kinds": [kind.value for kind in self.required_evidence_kinds],
            "standards_mappings": [mapping.to_dict() for mapping in self.standards_mappings],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AuditControlFinding:
    """Result of evaluating one Wave 9 control."""

    control_id: str
    status: AuditControlStatus
    severity: AuditControlSeverity
    summary: str
    evidence_artifact_ids: tuple[str, ...] = ()
    remediation: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id"),
        )
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "remediation",
            normalize_optional_text(self.remediation, label="remediation"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocks_audit_ready(self) -> bool:
        return self.status is AuditControlStatus.BLOCKED or (
            self.status is AuditControlStatus.WARNING
            and self.severity is AuditControlSeverity.BLOCKING
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "remediation": self.remediation,
            "blocks_audit_ready": self.blocks_audit_ready,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AuditReviewerSignoff:
    """Reviewer signoff bound to an immutable Wave 9 attestation subject digest."""

    signoff_id: str
    reviewer_id: str
    reviewer_kind: AuditReviewerKind
    decision: AuditReviewDecision
    subject_digest: str
    policy_pack_digest: str
    signed_at: datetime
    role: str
    notes: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "signoff_id",
            normalize_identifier(self.signoff_id, label="signoff_id"),
        )
        object.__setattr__(
            self,
            "reviewer_id",
            normalize_identifier(self.reviewer_id, label="reviewer_id"),
        )
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(
            self,
            "policy_pack_digest",
            normalize_sha256(self.policy_pack_digest),
        )
        if self.signed_at.tzinfo is None:
            raise ValueError("signed_at must be timezone-aware.")
        object.__setattr__(self, "role", normalize_text(self.role, label="role"))
        object.__setattr__(self, "notes", normalize_optional_text(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def is_authoritative_human_approval(self) -> bool:
        return (
            self.reviewer_kind is AuditReviewerKind.HUMAN
            and self.decision is AuditReviewDecision.APPROVED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signoff_id": self.signoff_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_kind": self.reviewer_kind.value,
            "decision": self.decision.value,
            "subject_digest": self.subject_digest,
            "policy_pack_digest": self.policy_pack_digest,
            "signed_at": self.signed_at.isoformat(),
            "role": self.role,
            "notes": self.notes,
            "is_authoritative_human_approval": self.is_authoritative_human_approval,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AuditNonClaimSet:
    """Explicit claims Wave 9 refuses to make."""

    items: tuple[str, ...] = (
        "Wave 9 audit attestation does not certify production readiness.",
        "Wave 9 audit attestation does not grant ATO, cATO, procurement approval, or deployment authority.",
        "Wave 9 audit attestation does not prove DoD endorsement, affiliation, acceptance, or certification.",
        "Wave 9 audit attestation does not authorize autonomous code changes or autonomous release decisions.",
        "Wave 9 audit attestation does not treat model confidence as evidence or human approval.",
    )

    def __post_init__(self) -> None:
        normalized = normalize_text_tuple(self.items, label="items")
        if len(normalized) != len(set(normalized)):
            raise ValueError("AuditNonClaimSet items must be unique.")
        object.__setattr__(self, "items", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {"items": list(self.items)}


def derive_audit_disposition(findings: Sequence[AuditControlFinding]) -> AuditDisposition:
    """Derive fail-closed Wave 9 disposition from control findings."""

    normalized_findings = tuple(findings)
    if any(finding.blocks_audit_ready for finding in normalized_findings):
        return AuditDisposition.BLOCKED
    if any(finding.status is AuditControlStatus.WARNING for finding in normalized_findings):
        return AuditDisposition.WARNING
    return AuditDisposition.AUDIT_READY


def digest_payload(value: Any) -> str:
    """Return deterministic SHA-256 for a JSON-serializable payload."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_identifier(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty.")
    if not _SAFE_IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{label} contains unsafe characters: {value!r}")
    return normalized


def normalize_identifier_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized = tuple(normalize_identifier(value, label=label) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} values must be unique.")
    return tuple(sorted(normalized))


def normalize_text(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty.")
    return normalized


def normalize_optional_text(value: str, *, label: str) -> str:
    if not value:
        return ""
    return normalize_text(value, label=label)


def normalize_text_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized = tuple(normalize_text(value, label=label) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} values must be unique.")
    return normalized


def normalize_sha256(value: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return normalized


def normalize_head_sha(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("head_sha must not be empty.")
    if any(character.isspace() for character in normalized):
        raise ValueError("head_sha must not contain whitespace.")
    return normalized


def normalize_optional_head_sha(value: str) -> str:
    if not value:
        return ""
    return normalize_head_sha(value)


def normalize_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    if not normalized:
        raise ValueError("path must not be empty.")
    path = PurePosixPath(normalized)
    posix_path = path.as_posix()
    if posix_path in {".", ".."}:
        raise ValueError(f"path must be a concrete repository-relative file path: {value!r}")
    if path.is_absolute():
        raise ValueError(f"path must be repository-relative: {value!r}")
    if path.parts and ":" in path.parts[0]:
        raise ValueError(f"path must not include a drive, URI scheme, or colon prefix: {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"path must not contain empty/current/parent segments: {value!r}")
    return posix_path


def normalize_path_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized = tuple(normalize_relative_path(value) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} values must be unique.")
    return tuple(sorted(normalized))
