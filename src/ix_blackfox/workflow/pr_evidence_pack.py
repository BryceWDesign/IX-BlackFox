from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")


class EvidenceArtifactKind(StrEnum):
    RUN_BUNDLE = auto()
    TEST_REPORT = auto()
    GOVERNANCE_RECEIPT = auto()
    RELIABILITY_REPORT = auto()
    POLICY_DECISION = auto()
    APPROVAL_RECORD = auto()
    CI_SUMMARY = auto()
    HUMAN_REVIEW = auto()
    SANDBOX_RECEIPT_BUNDLE = auto()
    OTHER = auto()


class ArtifactAttestationKind(StrEnum):
    LOCAL_MANIFEST = auto()
    GITHUB_ARTIFACT_ATTESTATION = auto()
    SIGSTORE_BUNDLE = auto()
    IN_TOTO_STATEMENT = auto()
    SLSA_PROVENANCE = auto()
    OTHER = auto()


class ReviewerKind(StrEnum):
    HUMAN = auto()
    SYSTEM = auto()
    MODEL = auto()


class ReviewDecision(StrEnum):
    APPROVED = auto()
    CHANGES_REQUESTED = auto()
    REJECTED = auto()
    COMMENTED = auto()


class Wave5ValidationSeverity(StrEnum):
    ERROR = auto()
    WARNING = auto()


@dataclass(frozen=True, slots=True)
class Wave5ValidationIssue:
    code: str
    severity: Wave5ValidationSeverity
    summary: str
    location: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "location", _normalize_text(self.location, label="location"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class Wave5ValidationReport:
    pack_id: str
    validated_at: datetime
    issues: tuple[Wave5ValidationIssue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pack_id", _normalize_token(self.pack_id, label="pack_id"))
        _require_aware_datetime(self.validated_at, label="validated_at")
        object.__setattr__(self, "issues", tuple(self.issues))

    @property
    def passed(self) -> bool:
        return not any(issue.severity is Wave5ValidationSeverity.ERROR for issue in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.WARNING)

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "validated_at": self.validated_at.isoformat(),
            "passed": self.passed,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issue_codes": list(self.issue_codes),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class PullRequestIdentity:
    provider: str
    repository: str
    pull_request_id: str
    base_ref: str
    head_ref: str
    head_sha: str
    author: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _normalize_token(self.provider, label="provider"))
        object.__setattr__(self, "repository", _normalize_repository(self.repository))
        object.__setattr__(
            self,
            "pull_request_id",
            _normalize_token(self.pull_request_id, label="pull_request_id"),
        )
        object.__setattr__(self, "base_ref", _normalize_ref(self.base_ref, label="base_ref"))
        object.__setattr__(self, "head_ref", _normalize_ref(self.head_ref, label="head_ref"))
        object.__setattr__(self, "head_sha", _normalize_sha(self.head_sha))
        object.__setattr__(self, "author", _normalize_text(self.author, label="author"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "repository": self.repository,
            "pull_request_id": self.pull_request_id,
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "head_sha": self.head_sha,
            "author": self.author,
        }


@dataclass(frozen=True, slots=True)
class ArtifactAttestation:
    attestation_id: str
    kind: ArtifactAttestationKind
    uri: str
    produced_by: str
    predicate_type: str
    sha256: str
    size_bytes: int
    head_sha: str
    subject_sha256: str
    verified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attestation_id",
            _normalize_token(self.attestation_id, label="attestation_id"),
        )
        object.__setattr__(self, "uri", _normalize_uri(self.uri))
        object.__setattr__(self, "produced_by", _normalize_text(self.produced_by, label="produced_by"))
        object.__setattr__(
            self,
            "predicate_type",
            _normalize_text(self.predicate_type, label="predicate_type"),
        )
        object.__setattr__(self, "sha256", _normalize_required_sha256(self.sha256, label="sha256"))
        object.__setattr__(self, "size_bytes", _normalize_required_size(self.size_bytes))
        object.__setattr__(self, "head_sha", _normalize_sha(self.head_sha))
        object.__setattr__(
            self,
            "subject_sha256",
            _normalize_required_sha256(self.subject_sha256, label="subject_sha256"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "kind": self.kind.value,
            "uri": self.uri,
            "produced_by": self.produced_by,
            "predicate_type": self.predicate_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "head_sha": self.head_sha,
            "subject_sha256": self.subject_sha256,
            "verified": self.verified,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    artifact_id: str
    kind: EvidenceArtifactKind
    uri: str
    produced_by: str
    sha256: str | None = None
    size_bytes: int | None = None
    head_sha: str | None = None
    attestations: tuple[ArtifactAttestation, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _normalize_token(self.artifact_id, label="artifact_id"))
        object.__setattr__(self, "uri", _normalize_uri(self.uri))
        object.__setattr__(self, "produced_by", _normalize_text(self.produced_by, label="produced_by"))
        object.__setattr__(self, "sha256", _normalize_optional_sha256(self.sha256))
        object.__setattr__(self, "size_bytes", _normalize_optional_size(self.size_bytes))
        object.__setattr__(self, "head_sha", _normalize_optional_sha(self.head_sha, label="head_sha"))
        object.__setattr__(self, "attestations", tuple(self.attestations))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "uri": self.uri,
            "produced_by": self.produced_by,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "head_sha": self.head_sha,
            "attestations": [attestation.to_dict() for attestation in self.attestations],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PullRequestApproval:
    approval_id: str
    reviewer_id: str
    reviewer_kind: ReviewerKind
    decision: ReviewDecision
    decided_at: datetime
    note: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    roles: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "approval_id", _normalize_token(self.approval_id, label="approval_id"))
        object.__setattr__(self, "reviewer_id", _normalize_text(self.reviewer_id, label="reviewer_id"))
        _require_aware_datetime(self.decided_at, label="decided_at")
        object.__setattr__(self, "note", _normalize_text(self.note, label="note"))
        object.__setattr__(self, "evidence_refs", _normalize_refs(self.evidence_refs))
        object.__setattr__(self, "roles", _normalize_labels(self.roles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_kind": self.reviewer_kind.value,
            "decision": self.decision.value,
            "decided_at": self.decided_at.isoformat(),
            "note": self.note,
            "evidence_refs": list(self.evidence_refs),
            "roles": list(self.roles),
        }


@dataclass(frozen=True, slots=True)
class PullRequestEvidencePack:
    pack_id: str
    pull_request: PullRequestIdentity
    created_at: datetime
    summary: str
    changed_files: tuple[str, ...]
    requested_checks: tuple[str, ...]
    artifacts: tuple[EvidenceArtifact, ...]
    approvals: tuple[PullRequestApproval, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pack_id", _normalize_token(self.pack_id, label="pack_id"))
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "changed_files", _normalize_changed_files(self.changed_files))
        object.__setattr__(self, "requested_checks", _normalize_labels(self.requested_checks))
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "approvals", tuple(self.approvals))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.artifacts)

    def artifact_kinds(self) -> tuple[EvidenceArtifactKind, ...]:
        return tuple(artifact.kind for artifact in self.artifacts)

    def human_approvals(self) -> tuple[PullRequestApproval, ...]:
        return tuple(
            approval
            for approval in self.approvals
            if approval.reviewer_kind is ReviewerKind.HUMAN
            and approval.decision is ReviewDecision.APPROVED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "pull_request": self.pull_request.to_dict(),
            "created_at": self.created_at.isoformat(),
            "summary": self.summary,
            "changed_files": list(self.changed_files),
            "requested_checks": list(self.requested_checks),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "approvals": [approval.to_dict() for approval in self.approvals],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PullRequestEvidencePackValidator:
    required_artifact_kinds: tuple[EvidenceArtifactKind, ...] = (
        EvidenceArtifactKind.RUN_BUNDLE,
        EvidenceArtifactKind.TEST_REPORT,
        EvidenceArtifactKind.GOVERNANCE_RECEIPT,
        EvidenceArtifactKind.RELIABILITY_REPORT,
    )
    require_human_approval: bool = True
    allow_model_approval_only: bool = False
    require_attestations_for_required_artifacts: bool = False
    require_sandbox_receipt_bundle: bool = False

    def validate(self, pack: PullRequestEvidencePack) -> Wave5ValidationReport:
        issues: list[Wave5ValidationIssue] = []
        issues.extend(_validate_changed_files(pack.changed_files))
        issues.extend(_validate_requested_checks(pack.requested_checks))
        issues.extend(_validate_artifacts(pack, self))
        issues.extend(_validate_approvals(pack, self))
        return Wave5ValidationReport(
            pack_id=pack.pack_id,
            validated_at=datetime.now(tz=UTC),
            issues=tuple(issues),
        )


def _validate_changed_files(changed_files: tuple[str, ...]) -> tuple[Wave5ValidationIssue, ...]:
    if changed_files:
        return ()
    return (_error("wave5.changed_files_missing", "PR evidence pack must list at least one changed file.", "changed_files"),)


def _validate_requested_checks(requested_checks: tuple[str, ...]) -> tuple[Wave5ValidationIssue, ...]:
    if requested_checks:
        return ()
    return (_warning("wave5.requested_checks_missing", "PR evidence pack does not list requested CI or local checks.", "requested_checks"),)


def _validate_artifacts(
    pack: PullRequestEvidencePack,
    validator: PullRequestEvidencePackValidator,
) -> tuple[Wave5ValidationIssue, ...]:
    issues: list[Wave5ValidationIssue] = []
    for artifact_id in _duplicates(pack.artifact_ids()):
        issues.append(_error("wave5.duplicate_artifact_id", f"Artifact id '{artifact_id}' appears more than once.", "artifacts"))

    required_artifact_kinds = _required_artifact_kinds(validator)
    required_kind_set = set(required_artifact_kinds)
    artifact_kinds = set(pack.artifact_kinds())
    for required_kind in required_artifact_kinds:
        if required_kind not in artifact_kinds:
            issues.append(_error("wave5.required_artifact_missing", f"Required artifact kind '{required_kind.value}' is missing.", "artifacts"))

    for artifact in pack.artifacts:
        artifact_is_required = artifact.kind in required_kind_set
        if artifact.sha256 is None:
            issue = _error if artifact_is_required else _warning
            issues.append(
                issue(
                    "wave5.artifact_digest_missing",
                    f"Artifact '{artifact.artifact_id}' does not include a SHA-256 digest.",
                    f"artifacts.{artifact.artifact_id}.sha256",
                )
            )
        if artifact.size_bytes is None:
            issue = _error if artifact_is_required else _warning
            issues.append(
                issue(
                    "wave5.artifact_size_missing",
                    f"Artifact '{artifact.artifact_id}' does not include a byte size.",
                    f"artifacts.{artifact.artifact_id}.size_bytes",
                )
            )
        elif artifact.size_bytes == 0 and artifact_is_required:
            issues.append(
                _error(
                    "wave5.required_artifact_empty",
                    f"Required artifact '{artifact.artifact_id}' has a zero byte size.",
                    f"artifacts.{artifact.artifact_id}.size_bytes",
                )
            )
        if artifact.head_sha is None:
            issue = _error if artifact_is_required else _warning
            issues.append(
                issue(
                    "wave5.artifact_head_sha_missing",
                    f"Artifact '{artifact.artifact_id}' does not declare the PR head SHA it was produced for.",
                    f"artifacts.{artifact.artifact_id}.head_sha",
                )
            )
        elif artifact.head_sha != pack.pull_request.head_sha:
            issues.append(
                _error(
                    "wave5.artifact_head_sha_mismatch",
                    f"Artifact '{artifact.artifact_id}' was produced for head SHA '{artifact.head_sha}', not PR head SHA '{pack.pull_request.head_sha}'.",
                    f"artifacts.{artifact.artifact_id}.head_sha",
                )
            )
        issues.extend(
            _validate_artifact_attestations(
                pack=pack,
                artifact=artifact,
                artifact_is_required=artifact_is_required,
                require_attestation=validator.require_attestations_for_required_artifacts,
            )
        )
    return tuple(issues)


def _required_artifact_kinds(
    validator: PullRequestEvidencePackValidator,
) -> tuple[EvidenceArtifactKind, ...]:
    required = list(validator.required_artifact_kinds)
    if (
        validator.require_sandbox_receipt_bundle
        and EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE not in required
    ):
        required.append(EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE)
    return tuple(required)


def _validate_artifact_attestations(
    *,
    pack: PullRequestEvidencePack,
    artifact: EvidenceArtifact,
    artifact_is_required: bool,
    require_attestation: bool,
) -> tuple[Wave5ValidationIssue, ...]:
    issues: list[Wave5ValidationIssue] = []
    if require_attestation and artifact_is_required and not artifact.attestations:
        issues.append(
            _error(
                "wave5.artifact_attestation_missing",
                f"Required artifact '{artifact.artifact_id}' does not include an attestation record.",
                f"artifacts.{artifact.artifact_id}.attestations",
            )
        )
    for attestation_id in _duplicates(
        attestation.attestation_id for attestation in artifact.attestations
    ):
        issues.append(
            _error(
                "wave5.duplicate_attestation_id",
                f"Attestation id '{attestation_id}' appears more than once on artifact '{artifact.artifact_id}'.",
                f"artifacts.{artifact.artifact_id}.attestations",
            )
        )
    for attestation in artifact.attestations:
        if artifact.sha256 is None:
            issues.append(
                _error(
                    "wave5.attestation_subject_digest_unverifiable",
                    f"Attestation '{attestation.attestation_id}' cannot be matched because artifact '{artifact.artifact_id}' has no SHA-256 digest.",
                    f"artifacts.{artifact.artifact_id}.attestations.{attestation.attestation_id}.subject_sha256",
                )
            )
        elif attestation.subject_sha256 != artifact.sha256:
            issues.append(
                _error(
                    "wave5.attestation_subject_digest_mismatch",
                    f"Attestation '{attestation.attestation_id}' subject digest does not match artifact '{artifact.artifact_id}'.",
                    f"artifacts.{artifact.artifact_id}.attestations.{attestation.attestation_id}.subject_sha256",
                )
            )
        if artifact.head_sha is not None and attestation.head_sha != artifact.head_sha:
            issues.append(
                _error(
                    "wave5.attestation_artifact_head_sha_mismatch",
                    f"Attestation '{attestation.attestation_id}' head SHA does not match artifact '{artifact.artifact_id}'.",
                    f"artifacts.{artifact.artifact_id}.attestations.{attestation.attestation_id}.head_sha",
                )
            )
        if attestation.head_sha != pack.pull_request.head_sha:
            issues.append(
                _error(
                    "wave5.attestation_pr_head_sha_mismatch",
                    f"Attestation '{attestation.attestation_id}' head SHA does not match the PR head SHA.",
                    f"artifacts.{artifact.artifact_id}.attestations.{attestation.attestation_id}.head_sha",
                )
            )
    return tuple(issues)


def _validate_approvals(
    pack: PullRequestEvidencePack,
    validator: PullRequestEvidencePackValidator,
) -> tuple[Wave5ValidationIssue, ...]:
    issues: list[Wave5ValidationIssue] = []
    for approval_id in _duplicates(approval.approval_id for approval in pack.approvals):
        issues.append(_error("wave5.duplicate_approval_id", f"Approval id '{approval_id}' appears more than once.", "approvals"))

    artifact_ids = set(pack.artifact_ids())
    for approval in pack.approvals:
        for evidence_ref in approval.evidence_refs:
            if evidence_ref not in artifact_ids:
                issues.append(_error("wave5.approval_evidence_ref_missing", f"Approval '{approval.approval_id}' references missing artifact '{evidence_ref}'.", f"approvals.{approval.approval_id}.evidence_refs"))
        if approval.reviewer_kind is ReviewerKind.MODEL and approval.decision is ReviewDecision.APPROVED:
            issues.append(_warning("wave5.model_approval_not_authoritative", "Model approval is recorded as advisory evidence, not human authority.", f"approvals.{approval.approval_id}.reviewer_kind"))

    if any(
        approval.decision in (ReviewDecision.REJECTED, ReviewDecision.CHANGES_REQUESTED)
        for approval in pack.approvals
    ):
        issues.append(_error("wave5.review_blocks_merge", "At least one review rejected the change or requested changes.", "approvals"))

    if validator.require_human_approval and not pack.human_approvals():
        severity = Wave5ValidationSeverity.WARNING if validator.allow_model_approval_only else Wave5ValidationSeverity.ERROR
        issues.append(Wave5ValidationIssue("wave5.human_approval_missing", severity, "PR evidence pack requires at least one approving human review.", "approvals"))
    return tuple(issues)


def _duplicates(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    return tuple(duplicates)


def _error(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.ERROR, summary, location)


def _warning(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.WARNING, summary, location)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_TOKEN_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_repository(value: str) -> str:
    cleaned = _normalize_token(value, label="repository")
    if cleaned.startswith("/") or cleaned.endswith("/"):
        raise ValueError("repository must be a stable owner/name token, not an absolute path.")
    return cleaned


def _normalize_ref(value: str, *, label: str) -> str:
    cleaned = _normalize_token(value, label=label)
    if cleaned.startswith("/") or cleaned.endswith("/"):
        raise ValueError(f"{label} must not be an absolute path.")
    return cleaned


def _normalize_sha(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="head_sha")
    if not re.fullmatch(r"[0-9a-f]{7,64}", cleaned):
        raise ValueError("head_sha must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_required_sha256(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.lower(), label=label)
    if not _SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_required_sha256(value, label="sha256")


def _normalize_optional_sha(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    cleaned = _normalize_text(value.lower(), label=label)
    if not re.fullmatch(r"[0-9a-f]{7,64}", cleaned):
        raise ValueError(f"{label} must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_optional_size(value: int | None) -> int | None:
    if value is not None and value < 0:
        raise ValueError("size_bytes must be non-negative.")
    return value


def _normalize_required_size(value: int) -> int:
    if value <= 0:
        raise ValueError("size_bytes must be greater than zero.")
    return value


def _normalize_uri(value: str) -> str:
    cleaned = _normalize_text(value, label="uri")
    if cleaned.startswith(("http://", "https://")):
        return cleaned
    return _normalize_relative_path(cleaned, label="uri")


def _normalize_changed_files(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_relative_path(value, label="changed_file") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("changed_files must not contain duplicates.")
    return normalized


def _normalize_relative_path(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.replace("\\", "/"), label=label)
    if cleaned.startswith("/"):
        raise ValueError(f"{label} must be relative, not absolute.")
    path = PurePosixPath(cleaned)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"{label} must not contain empty, '.', or '..' path segments.")
    return path.as_posix()


def _normalize_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_token(value, label="evidence_ref") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("evidence_refs must not contain duplicates.")
    return normalized


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_token(value, label="label") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("labels must not contain duplicates.")
    return normalized


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
