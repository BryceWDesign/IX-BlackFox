from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)


class ReviewBundleSectionKind(StrEnum):
    """Canonical section families expected in a Wave 10 human review bundle."""

    REGISTRY = auto()
    TEAM_AUTHORITY = auto()
    CAMPAIGN = auto()
    EVIDENCE_INVENTORY = auto()
    REPLAY_MANIFEST = auto()
    REPLAY_VALIDATION = auto()
    WORK_PACKAGE = auto()
    OPERATING_REPORT = auto()


@dataclass(frozen=True, slots=True)
class ReviewBundleArtifact:
    """Artifact entry that must be available to human reviewers."""

    artifact: OperatingArtifactRef
    required: bool = True
    review_note: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "review_note",
            normalize_optional_text(self.review_note, label="review_note"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_id(self) -> str:
        return self.artifact.artifact_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "required": self.required,
            "review_note": self.review_note,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReviewBundleSection:
    """Digest-bound operating envelope summary exported for human review."""

    section_id: str
    section_kind: ReviewBundleSectionKind
    title: str
    envelope: OperatingEnvelope
    required: bool = True
    reviewer_instructions: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "section_id",
            normalize_identifier(self.section_id, label="section_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(
            self,
            "reviewer_instructions",
            normalize_text_tuple(
                self.reviewer_instructions,
                label="reviewer_instructions",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def envelope_digest(self) -> str:
        return self.envelope.digest

    @property
    def disposition(self) -> OperatingDisposition:
        return self.envelope.disposition

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.envelope.evidence)

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.envelope.findings)

    @property
    def blocking(self) -> bool:
        return self.required and self.disposition is OperatingDisposition.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "section_kind": self.section_kind.value,
            "title": self.title,
            "required": self.required,
            "artifact_kind": self.envelope.artifact_kind.value,
            "subject": self.envelope.subject,
            "domains": [domain.value for domain in self.envelope.domains],
            "artifact_ids": list(self.artifact_ids),
            "finding_codes": list(self.finding_codes),
            "blocking_finding_count": len(self.envelope.blocking_findings),
            "disposition": self.disposition.value,
            "envelope_digest": self.envelope_digest,
            "reviewer_instructions": list(self.reviewer_instructions),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingReviewBundle:
    """Deterministic human-review bundle for Wave 10 operating evidence.

    The bundle is an evidence export, not an execution token. It is fail-closed
    when required sections are missing, required artifacts are absent, or any
    required section already has a blocked disposition.
    """

    bundle_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    created_by: str
    sections: tuple[ReviewBundleSection, ...]
    artifacts: tuple[ReviewBundleArtifact, ...]
    required_section_kinds: tuple[ReviewBundleSectionKind, ...] = (
        ReviewBundleSectionKind.REGISTRY,
        ReviewBundleSectionKind.TEAM_AUTHORITY,
        ReviewBundleSectionKind.CAMPAIGN,
        ReviewBundleSectionKind.EVIDENCE_INVENTORY,
        ReviewBundleSectionKind.REPLAY_MANIFEST,
    )
    reviewer_questions: tuple[str, ...] = ()
    requires_human_authority: bool = True
    allowed_for_automatic_execution: bool = False
    generated_by: str = "IX-BlackFox Wave 10 review bundle"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.requires_human_authority:
            raise ValueError("OperatingReviewBundle must require human authority.")
        if self.allowed_for_automatic_execution:
            raise ValueError(
                "OperatingReviewBundle must never allow automatic execution."
            )
        object.__setattr__(
            self,
            "bundle_id",
            normalize_identifier(self.bundle_id, label="bundle_id"),
        )
        object.__setattr__(
            self,
            "campaign_id",
            normalize_identifier(self.campaign_id, label="campaign_id"),
        )
        if not self.repository_ids:
            raise ValueError("OperatingReviewBundle repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(
            self,
            "created_by",
            normalize_text(self.created_by, label="created_by"),
        )
        if not self.sections:
            raise ValueError("OperatingReviewBundle sections must not be empty.")
        sections = tuple(sorted(self.sections, key=lambda section: section.section_id))
        section_ids = [section.section_id for section in sections]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("OperatingReviewBundle section_id values must be unique.")
        object.__setattr__(self, "sections", sections)
        if not self.artifacts:
            raise ValueError("OperatingReviewBundle artifacts must not be empty.")
        artifacts = tuple(
            sorted(self.artifacts, key=lambda artifact: artifact.artifact_id)
        )
        artifact_ids = [artifact.artifact_id for artifact in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("OperatingReviewBundle artifact_id values must be unique.")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(
            self,
            "required_section_kinds",
            unique_sorted_enum_tuple(self.required_section_kinds),
        )
        object.__setattr__(
            self,
            "reviewer_questions",
            normalize_text_tuple(self.reviewer_questions, label="reviewer_questions"),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.artifacts)

    @property
    def required_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            artifact.artifact_id for artifact in self.artifacts if artifact.required
        )

    @property
    def section_kinds_present(self) -> tuple[ReviewBundleSectionKind, ...]:
        return unique_sorted_enum_tuple(
            tuple(section.section_kind for section in self.sections)
        )

    @property
    def missing_required_section_kinds(self) -> tuple[ReviewBundleSectionKind, ...]:
        present = set(self.section_kinds_present)
        return tuple(
            kind for kind in self.required_section_kinds if kind not in present
        )

    @property
    def section_artifact_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(
                artifact_id
                for section in self.sections
                for artifact_id in section.artifact_ids
            ),
            label="section_artifact_ids",
        )

    @property
    def missing_section_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.section_artifact_ids) - set(self.artifact_ids)))

    @property
    def blocking_section_ids(self) -> tuple[str, ...]:
        return tuple(
            section.section_id for section in self.sections if section.blocking
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for section_kind in self.missing_required_section_kinds:
            findings.append(
                self._finding(
                    code="operating.review_bundle.missing-required-section",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        "Review bundle is missing required section "
                        f"{section_kind.value}."
                    ),
                    metadata={"section_kind": section_kind.value},
                )
            )
        for artifact_id in self.missing_section_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.review_bundle.section-artifact-not-exported",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Section references artifact {artifact_id} that is not "
                        "exported in the bundle."
                    ),
                    metadata={"artifact_id": artifact_id},
                )
            )
        for section_id in self.blocking_section_ids:
            findings.append(
                self._finding(
                    code="operating.review_bundle.blocked-section",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Required review bundle section {section_id} has "
                        "blocked disposition."
                    ),
                    metadata={"section_id": section_id},
                )
            )
        return tuple(
            sorted(findings, key=lambda finding: (finding.code, finding.summary))
        )

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if any(
            section.disposition is OperatingDisposition.WARNING
            for section in self.sections
        ):
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def export_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.bundle_id}-review-bundle-envelope",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            subject=f"Wave 10 review bundle {self.bundle_id}",
            domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
            evidence=tuple(artifact.artifact for artifact in self.artifacts),
            findings=self.findings,
            metadata={
                "bundle_id": self.bundle_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "section_ids": [section.section_id for section in self.sections],
                "artifact_ids": list(self.artifact_ids),
                "requires_human_authority": self.requires_human_authority,
                "allowed_for_automatic_execution": self.allowed_for_automatic_execution,
            },
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bundle_id": self.bundle_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "created_by": self.created_by,
            "sections": [section.to_dict() for section in self.sections],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "required_section_kinds": [
                kind.value for kind in self.required_section_kinds
            ],
            "section_kinds_present": [
                kind.value for kind in self.section_kinds_present
            ],
            "missing_required_section_kinds": [
                kind.value for kind in self.missing_required_section_kinds
            ],
            "artifact_ids": list(self.artifact_ids),
            "required_artifact_ids": list(self.required_artifact_ids),
            "section_artifact_ids": list(self.section_artifact_ids),
            "missing_section_artifact_ids": list(self.missing_section_artifact_ids),
            "blocking_section_ids": list(self.blocking_section_ids),
            "reviewer_questions": list(self.reviewer_questions),
            "requires_human_authority": self.requires_human_authority,
            "allowed_for_automatic_execution": self.allowed_for_automatic_execution,
            "generated_by": self.generated_by,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
            blocking=True,
            metadata={"bundle_id": self.bundle_id, **dict(metadata or {})},
        )


@dataclass(frozen=True, slots=True)
class ReviewBundleValidation:
    """Validation result for exported review bundle artifacts and digest binding."""

    validation_id: str
    bundle: OperatingReviewBundle
    observed_artifacts: tuple[OperatingArtifactRef, ...]
    checked_by: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "validation_id",
            normalize_identifier(self.validation_id, label="validation_id"),
        )
        observed = tuple(
            sorted(self.observed_artifacts, key=lambda artifact: artifact.artifact_id)
        )
        artifact_ids = [artifact.artifact_id for artifact in observed]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError(
                "ReviewBundleValidation observed artifact_id values must be unique."
            )
        object.__setattr__(self, "observed_artifacts", observed)
        object.__setattr__(
            self,
            "checked_by",
            normalize_text(self.checked_by, label="checked_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def observed_artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.observed_artifacts)

    @property
    def missing_required_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                set(self.bundle.required_artifact_ids)
                - set(self.observed_artifact_ids)
            )
        )

    @property
    def unexpected_artifact_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self.observed_artifact_ids) - set(self.bundle.artifact_ids))
        )

    @property
    def mismatched_artifact_ids(self) -> tuple[str, ...]:
        expected = {
            artifact.artifact_id: artifact.artifact.sha256
            for artifact in self.bundle.artifacts
        }
        observed = {
            artifact.artifact_id: artifact.sha256
            for artifact in self.observed_artifacts
        }
        return tuple(
            sorted(
                artifact_id
                for artifact_id, expected_sha256 in expected.items()
                if artifact_id in observed and observed[artifact_id] != expected_sha256
            )
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = [*self.bundle.findings]
        for artifact_id in self.missing_required_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.review_bundle.missing-required-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Required review bundle artifact {artifact_id} was "
                        "not observed."
                    ),
                    metadata={"artifact_id": artifact_id},
                )
            )
        for artifact_id in self.mismatched_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.review_bundle.artifact-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Review bundle artifact {artifact_id} digest does not "
                        "match export metadata."
                    ),
                    metadata={"artifact_id": artifact_id},
                )
            )
        for artifact_id in self.unexpected_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.review_bundle.unexpected-artifact",
                    severity=OperatingSeverity.MEDIUM,
                    summary=(
                        "Review bundle validation observed unexpected "
                        f"artifact {artifact_id}."
                    ),
                    blocking=False,
                    metadata={"artifact_id": artifact_id},
                )
            )
        return tuple(
            sorted(findings, key=lambda finding: (finding.code, finding.summary))
        )

    @property
    def passed(self) -> bool:
        return not any(finding.blocking for finding in self.findings)

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.validation_id}-review-bundle-validation-envelope",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            subject=f"Wave 10 review bundle validation {self.validation_id}",
            domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
            evidence=self.observed_artifacts,
            findings=self.findings,
            metadata={
                "validation_id": self.validation_id,
                "bundle_id": self.bundle.bundle_id,
                "checked_by": self.checked_by,
                "observed_artifact_ids": list(self.observed_artifact_ids),
                "missing_required_artifact_ids": list(
                    self.missing_required_artifact_ids
                ),
                "mismatched_artifact_ids": list(self.mismatched_artifact_ids),
                "unexpected_artifact_ids": list(self.unexpected_artifact_ids),
                "passed": self.passed,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "validation_id": self.validation_id,
            "bundle": self.bundle.to_dict(),
            "observed_artifacts": [
                artifact.to_dict() for artifact in self.observed_artifacts
            ],
            "observed_artifact_ids": list(self.observed_artifact_ids),
            "checked_by": self.checked_by,
            "missing_required_artifact_ids": list(
                self.missing_required_artifact_ids
            ),
            "mismatched_artifact_ids": list(self.mismatched_artifact_ids),
            "unexpected_artifact_ids": list(self.unexpected_artifact_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
            blocking=blocking,
            metadata={
                "validation_id": self.validation_id,
                "bundle_id": self.bundle.bundle_id,
                **dict(metadata or {}),
            },
        )
