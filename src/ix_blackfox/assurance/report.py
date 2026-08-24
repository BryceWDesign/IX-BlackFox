from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.crosswalk import (
    AssuranceCrosswalkReport,
    ControlEvaluationStatus,
)
from ix_blackfox.assurance.models import (
    AssuranceEvidenceKind,
    AssuranceManifest,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
    digest_payload,
)
from ix_blackfox.operating.models import normalize_identifier, normalize_text

WAVE12_READINESS_SCHEMA_VERSION = "wave12.assurance_readiness.v1"


class AssuranceReadinessStatus(StrEnum):
    """Disposition of a Wave 12 package before external assessment."""

    BLOCKED = auto()
    REVIEW_REQUIRED = auto()
    READY_FOR_EXTERNAL_ASSESSMENT = auto()


class AssuranceFindingSeverity(StrEnum):
    """Severity scale for deterministic Wave 12 readiness findings."""

    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class AssuranceFindingCode(StrEnum):
    """Stable finding codes emitted by the Wave 12 readiness gate."""

    MANDATORY_CONTROL_UNSATISFIED = auto()
    OPTIONAL_CONTROL_PARTIAL = auto()
    REQUIRED_EVIDENCE_NOT_INTEGRITY_VERIFIED = auto()
    PROHIBITED_ASSERTED_CLAIM = auto()
    REVIEW_REQUIRED = auto()
    REVIEW_SUBJECT_MISMATCH = auto()
    REVIEW_PROFILE_MISMATCH = auto()
    REVIEWER_SELF_APPROVAL = auto()
    NON_HUMAN_APPROVAL_ATTEMPT = auto()
    REVIEW_AUTHENTICATION_UNVERIFIED = auto()
    REVIEW_VERIFICATION_ARTIFACT_MISSING = auto()
    REVIEW_VERIFICATION_ARTIFACT_WRONG_KIND = auto()
    REVIEW_VERIFICATION_ARTIFACT_NOT_EXTERNALLY_VERIFIED = auto()
    REVIEW_REJECTED_OR_CHANGES_REQUIRED = auto()
    ADVISORY_REVIEW_RECORDED = auto()
    AUTHORITATIVE_HUMAN_APPROVAL_RECORDED = auto()


@dataclass(frozen=True, slots=True)
class AssuranceFinding:
    """One Wave 12 readiness finding."""

    code: AssuranceFindingCode
    severity: AssuranceFindingSeverity
    summary: str
    blocking: bool
    control_id: str = ""
    artifact_id: str = ""
    review_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "summary",
            normalize_text(self.summary, label="summary"),
        )
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id")
            if self.control_id
            else "",
        )
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id")
            if self.artifact_id
            else "",
        )
        object.__setattr__(
            self,
            "review_id",
            normalize_identifier(self.review_id, label="review_id")
            if self.review_id
            else "",
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "blocking": self.blocking,
            "control_id": self.control_id,
            "artifact_id": self.artifact_id,
            "review_id": self.review_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssuranceReadinessReport:
    """Fail-closed readiness result for a Wave 12 evidence package."""

    report_id: str
    manifest_digest: str
    subject_digest: str
    profile_digest: str
    crosswalk_digest: str
    findings: tuple[AssuranceFinding, ...]
    reviews: tuple[AuthorityReview, ...]
    generated_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(
                    self.findings,
                    key=lambda item: (
                        item.blocking is False,
                        item.code.value,
                        item.summary,
                    ),
                )
            ),
        )
        reviews = tuple(sorted(self.reviews, key=lambda item: item.review_id))
        review_ids = [review.review_id for review in reviews]
        if len(review_ids) != len(set(review_ids)):
            raise ValueError("AssuranceReadinessReport review_id values must be unique.")
        object.__setattr__(self, "reviews", reviews)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking_findings(self) -> tuple[AssuranceFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def warning_findings(self) -> tuple[AssuranceFinding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if not finding.blocking
            and finding.severity
            in {
                AssuranceFindingSeverity.MEDIUM,
                AssuranceFindingSeverity.HIGH,
                AssuranceFindingSeverity.CRITICAL,
            }
        )

    @property
    def authoritative_human_approval_count(self) -> int:
        blocked_review_ids = {
            finding.review_id
            for finding in self.blocking_findings
            if finding.review_id
        }
        return sum(
            review.authoritative_human_approval
            and review.review_id not in blocked_review_ids
            for review in self.reviews
        )

    @property
    def status(self) -> AssuranceReadinessStatus:
        if self.blocking_findings:
            return AssuranceReadinessStatus.BLOCKED
        if self.authoritative_human_approval_count == 0:
            return AssuranceReadinessStatus.REVIEW_REQUIRED
        return AssuranceReadinessStatus.READY_FOR_EXTERNAL_ASSESSMENT

    @property
    def ready_for_external_assessment(self) -> bool:
        return self.status is AssuranceReadinessStatus.READY_FOR_EXTERNAL_ASSESSMENT

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE12_READINESS_SCHEMA_VERSION,
            "report_id": self.report_id,
            "status": self.status.value,
            "ready_for_external_assessment": self.ready_for_external_assessment,
            "manifest_digest": self.manifest_digest,
            "subject_digest": self.subject_digest,
            "profile_digest": self.profile_digest,
            "crosswalk_digest": self.crosswalk_digest,
            "generated_at": self.generated_at,
            "finding_count": len(self.findings),
            "blocking_finding_count": len(self.blocking_findings),
            "warning_finding_count": len(self.warning_findings),
            "review_count": len(self.reviews),
            "authoritative_human_approval_count": (
                self.authoritative_human_approval_count
            ),
            "findings": [finding.to_dict() for finding in self.findings],
            "reviews": [review.to_dict() for review in self.reviews],
            "metadata": dict(self.metadata),
            "scope_note": (
                "Ready for external assessment means the bounded evidence package "
                "passed BlackFox integrity, completeness, claim, and separate-human-"
                "authority gates. It does not mean certified, compliant, authorized, "
                "approved for deployment, or approved for production."
            ),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_assurance_readiness_report(
    *,
    manifest: AssuranceManifest,
    crosswalk: AssuranceCrosswalkReport,
    reviews: Sequence[AuthorityReview] = (),
    report_id: str = "wave12-assurance-readiness",
    metadata: Mapping[str, Any] | None = None,
) -> AssuranceReadinessReport:
    """Evaluate completeness, claims, and separate human authority."""

    normalized_reviews = tuple(sorted(reviews, key=lambda item: item.review_id))
    findings: list[AssuranceFinding] = []
    findings.extend(_crosswalk_findings(crosswalk))
    findings.extend(_evidence_findings(manifest))
    findings.extend(_claim_findings(manifest))
    findings.extend(_review_findings(manifest, normalized_reviews))
    if not any(review.authoritative_human_approval for review in normalized_reviews):
        findings.append(
            AssuranceFinding(
                code=AssuranceFindingCode.REVIEW_REQUIRED,
                severity=AssuranceFindingSeverity.HIGH,
                summary=(
                    "A separately authenticated human authority must approve the "
                    "manifest for external assessment."
                ),
                blocking=False,
            )
        )

    return AssuranceReadinessReport(
        report_id=report_id,
        manifest_digest=manifest.digest,
        subject_digest=manifest.subject.digest,
        profile_digest=manifest.profile.digest,
        crosswalk_digest=crosswalk.digest,
        findings=tuple(findings),
        reviews=normalized_reviews,
        generated_at=manifest.subject.generated_at,
        metadata={} if metadata is None else dict(metadata),
    )


def _crosswalk_findings(
    crosswalk: AssuranceCrosswalkReport,
) -> tuple[AssuranceFinding, ...]:
    findings: list[AssuranceFinding] = []
    for evaluation in crosswalk.evaluations:
        if evaluation.blocking:
            findings.append(
                AssuranceFinding(
                    code=AssuranceFindingCode.MANDATORY_CONTROL_UNSATISFIED,
                    severity=AssuranceFindingSeverity.CRITICAL,
                    summary=(
                        f"Mandatory assurance control {evaluation.control.control_id} "
                        f"is {evaluation.status.value}."
                    ),
                    blocking=True,
                    control_id=evaluation.control.control_id,
                    metadata={
                        "missing_kinds": [
                            kind.value for kind in evaluation.missing_kinds
                        ],
                        "insufficient_verification_artifact_ids": list(
                            evaluation.insufficient_verification_artifact_ids
                        ),
                    },
                )
            )
        elif evaluation.status in {
            ControlEvaluationStatus.PARTIAL,
            ControlEvaluationStatus.MISSING,
        }:
            findings.append(
                AssuranceFinding(
                    code=AssuranceFindingCode.OPTIONAL_CONTROL_PARTIAL,
                    severity=AssuranceFindingSeverity.MEDIUM,
                    summary=(
                        f"Optional assurance mapping {evaluation.control.control_id} "
                        f"is {evaluation.status.value}."
                    ),
                    blocking=False,
                    control_id=evaluation.control.control_id,
                )
            )
    return tuple(findings)


def _evidence_findings(
    manifest: AssuranceManifest,
) -> tuple[AssuranceFinding, ...]:
    return tuple(
        AssuranceFinding(
            code=AssuranceFindingCode.REQUIRED_EVIDENCE_NOT_INTEGRITY_VERIFIED,
            severity=AssuranceFindingSeverity.CRITICAL,
            summary=(
                f"Required evidence artifact {artifact.artifact_id} is not "
                "integrity-verified."
            ),
            blocking=True,
            artifact_id=artifact.artifact_id,
        )
        for artifact in manifest.evidence
        if artifact.required and not artifact.integrity_verified
    )


def _claim_findings(manifest: AssuranceManifest) -> tuple[AssuranceFinding, ...]:
    return tuple(
        AssuranceFinding(
            code=AssuranceFindingCode.PROHIBITED_ASSERTED_CLAIM,
            severity=AssuranceFindingSeverity.CRITICAL,
            summary=f"Asserted assurance claim contains prohibited term: {term}.",
            blocking=True,
            metadata={"term": term},
        )
        for term in manifest.claims.prohibited_hits
    )


def _review_findings(
    manifest: AssuranceManifest,
    reviews: tuple[AuthorityReview, ...],
) -> tuple[AssuranceFinding, ...]:
    findings: list[AssuranceFinding] = []
    evidence_by_id = manifest.evidence_by_id

    for review in reviews:
        if review.subject_digest != manifest.digest:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.REVIEW_SUBJECT_MISMATCH,
                    "Reviewer decision is not bound to this manifest digest.",
                    blocking=True,
                )
            )
        if review.profile_digest != manifest.profile.digest:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.REVIEW_PROFILE_MISMATCH,
                    "Reviewer decision is not bound to this profile digest.",
                    blocking=True,
                )
            )
        if review.reviewer_agent_id == manifest.subject.producer_agent_id:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.REVIEWER_SELF_APPROVAL,
                    "Package producer attempted to review its own manifest.",
                    blocking=True,
                )
            )
        if (
            review.decision
            is AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
            and review.reviewer_kind is not AgentKind.HUMAN_OPERATOR
        ):
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.NON_HUMAN_APPROVAL_ATTEMPT,
                    "A non-human actor attempted authoritative external-assessment approval.",
                    blocking=True,
                )
            )
        if review.decision in {
            AuthorityReviewDecision.REJECT,
            AuthorityReviewDecision.REQUEST_CHANGES,
        }:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.REVIEW_REJECTED_OR_CHANGES_REQUIRED,
                    "Human review rejected the package or requested changes.",
                    blocking=True,
                )
            )
        if (
            review.reviewer_kind is AgentKind.HUMAN_OPERATOR
            and review.decision
            is AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
            and not review.authoritative_human_approval
        ):
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.REVIEW_AUTHENTICATION_UNVERIFIED,
                    "Human approval is recorded but reviewer authentication is unverified.",
                    blocking=False,
                    severity=AssuranceFindingSeverity.HIGH,
                )
            )
        for artifact_id in review.verification_artifact_ids:
            artifact = evidence_by_id.get(artifact_id)
            if artifact is None:
                findings.append(
                    _review_finding(
                        review,
                        AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_MISSING,
                        f"Review verification artifact is missing: {artifact_id}.",
                        blocking=True,
                        metadata={"artifact_id": artifact_id},
                    )
                )
            elif artifact.evidence_kind is not AssuranceEvidenceKind.HUMAN_REVIEW:
                findings.append(
                    _review_finding(
                        review,
                        AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_WRONG_KIND,
                        (
                            "Review verification artifact is not classified as "
                            f"human-review evidence: {artifact_id}."
                        ),
                        blocking=True,
                        metadata={"artifact_id": artifact_id},
                    )
                )
            elif (
                review.decision
                is AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
                and review.authentication_state is ReviewAuthenticationState.VERIFIED
                and not artifact.verification_state.satisfies(
                    EvidenceVerificationState.EXTERNALLY_VERIFIED
                )
            ):
                findings.append(
                    _review_finding(
                        review,
                        AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_NOT_EXTERNALLY_VERIFIED,
                        (
                            "Review authentication evidence was not externally "
                            f"verified: {artifact_id}."
                        ),
                        blocking=True,
                        metadata={"artifact_id": artifact_id},
                    )
                )

        if review.authoritative_human_approval:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.AUTHORITATIVE_HUMAN_APPROVAL_RECORDED,
                    "A separately authenticated human authority approved external assessment.",
                    blocking=False,
                    severity=AssuranceFindingSeverity.INFO,
                )
            )
        elif review.decision is AuthorityReviewDecision.ADVISORY_ONLY:
            findings.append(
                _review_finding(
                    review,
                    AssuranceFindingCode.ADVISORY_REVIEW_RECORDED,
                    "An advisory review was recorded without authority elevation.",
                    blocking=False,
                    severity=AssuranceFindingSeverity.INFO,
                )
            )

    return tuple(findings)


def _review_finding(
    review: AuthorityReview,
    code: AssuranceFindingCode,
    summary: str,
    *,
    blocking: bool,
    severity: AssuranceFindingSeverity = AssuranceFindingSeverity.CRITICAL,
    metadata: Mapping[str, Any] | None = None,
) -> AssuranceFinding:
    return AssuranceFinding(
        code=code,
        severity=severity,
        summary=summary,
        blocking=blocking,
        review_id=review.review_id,
        metadata={} if metadata is None else dict(metadata),
    )
