from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.audit.models import (
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    AuditSubject,
    digest_payload,
    normalize_identifier,
    normalize_identifier_tuple,
    normalize_optional_text,
    normalize_sha256,
    normalize_text,
)
from ix_blackfox.audit.policy_packs import AuditPolicyPack


class SignoffValidationIssueSeverity(StrEnum):
    """Severity for Wave 9 signoff validation issues."""

    INFO = auto()
    WARNING = auto()
    BLOCKING = auto()


@dataclass(frozen=True, slots=True)
class SignoffValidationIssue:
    """One signoff-validation issue found during Wave 9 authority checks."""

    issue_id: str
    severity: SignoffValidationIssueSeverity
    summary: str
    signoff_id: str = ""
    remediation: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "issue_id", normalize_identifier(self.issue_id, label="issue_id"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "signoff_id",
            normalize_optional_text(self.signoff_id, label="signoff_id"),
        )
        object.__setattr__(
            self,
            "remediation",
            normalize_optional_text(self.remediation, label="remediation"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocks_audit_ready(self) -> bool:
        return self.severity is SignoffValidationIssueSeverity.BLOCKING

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "severity": self.severity.value,
            "summary": self.summary,
            "signoff_id": self.signoff_id,
            "remediation": self.remediation,
            "blocks_audit_ready": self.blocks_audit_ready,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SignoffValidationResult:
    """Deterministic result of validating Wave 9 reviewer signoffs."""

    subject_digest: str
    policy_pack_digest: str
    issues: tuple[SignoffValidationIssue, ...] = ()
    authoritative_human_approval_ids: tuple[str, ...] = ()
    advisory_signoff_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "policy_pack_digest", normalize_sha256(self.policy_pack_digest))
        object.__setattr__(self, "issues", tuple(sorted(self.issues, key=_issue_sort_key)))
        object.__setattr__(
            self,
            "authoritative_human_approval_ids",
            normalize_identifier_tuple(
                self.authoritative_human_approval_ids,
                label="authoritative_human_approval_ids",
            ),
        )
        object.__setattr__(
            self,
            "advisory_signoff_ids",
            normalize_identifier_tuple(self.advisory_signoff_ids, label="advisory_signoff_ids"),
        )
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
            1 for issue in self.issues if issue.severity is SignoffValidationIssueSeverity.WARNING
        )

    @property
    def has_authoritative_human_approval(self) -> bool:
        return bool(self.authoritative_human_approval_ids)

    @property
    def has_blocking_issues(self) -> bool:
        return self.blocking_issue_count > 0

    @property
    def is_valid(self) -> bool:
        return not self.has_blocking_issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_digest": self.subject_digest,
            "policy_pack_digest": self.policy_pack_digest,
            "is_valid": self.is_valid,
            "has_authoritative_human_approval": self.has_authoritative_human_approval,
            "issue_count": self.issue_count,
            "blocking_issue_count": self.blocking_issue_count,
            "warning_issue_count": self.warning_issue_count,
            "authoritative_human_approval_ids": list(self.authoritative_human_approval_ids),
            "advisory_signoff_ids": list(self.advisory_signoff_ids),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SignoffAuthoritySummary:
    """Compact authority summary for governance reports and CLI output."""

    subject_digest: str
    policy_pack_digest: str
    signoff_count: int
    authoritative_human_approval_ids: tuple[str, ...]
    advisory_signoff_ids: tuple[str, ...]
    non_authoritative_approval_ids: tuple[str, ...]
    validation_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "policy_pack_digest", normalize_sha256(self.policy_pack_digest))
        if self.signoff_count < 0:
            raise ValueError("signoff_count must be zero or greater.")
        object.__setattr__(
            self,
            "authoritative_human_approval_ids",
            normalize_identifier_tuple(
                self.authoritative_human_approval_ids,
                label="authoritative_human_approval_ids",
            ),
        )
        object.__setattr__(
            self,
            "advisory_signoff_ids",
            normalize_identifier_tuple(self.advisory_signoff_ids, label="advisory_signoff_ids"),
        )
        object.__setattr__(
            self,
            "non_authoritative_approval_ids",
            normalize_identifier_tuple(
                self.non_authoritative_approval_ids,
                label="non_authoritative_approval_ids",
            ),
        )
        object.__setattr__(self, "validation_digest", normalize_sha256(self.validation_digest))

    @property
    def has_authoritative_human_approval(self) -> bool:
        return bool(self.authoritative_human_approval_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_digest": self.subject_digest,
            "policy_pack_digest": self.policy_pack_digest,
            "signoff_count": self.signoff_count,
            "has_authoritative_human_approval": self.has_authoritative_human_approval,
            "authoritative_human_approval_ids": list(self.authoritative_human_approval_ids),
            "advisory_signoff_ids": list(self.advisory_signoff_ids),
            "non_authoritative_approval_ids": list(self.non_authoritative_approval_ids),
            "validation_digest": self.validation_digest,
        }


def create_reviewer_signoff(
    *,
    signoff_id: str,
    reviewer_id: str,
    reviewer_kind: AuditReviewerKind,
    decision: AuditReviewDecision,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    role: str,
    signed_at: datetime | None = None,
    notes: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> AuditReviewerSignoff:
    """Create a reviewer signoff bound to the current subject and policy pack."""

    return AuditReviewerSignoff(
        signoff_id=signoff_id,
        reviewer_id=reviewer_id,
        reviewer_kind=reviewer_kind,
        decision=decision,
        subject_digest=subject.digest,
        policy_pack_digest=policy_pack.digest,
        signed_at=signed_at or datetime.now(tz=UTC),
        role=role,
        notes=notes,
        metadata={
            "binding": signoff_binding_payload(subject, policy_pack),
            **dict(metadata or {}),
        },
    )


def create_human_approval_signoff(
    *,
    signoff_id: str,
    reviewer_id: str,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    role: str = "human-reviewer",
    signed_at: datetime | None = None,
    notes: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> AuditReviewerSignoff:
    """Create an authoritative human approval signoff for Wave 9 audit readiness."""

    return create_reviewer_signoff(
        signoff_id=signoff_id,
        reviewer_id=reviewer_id,
        reviewer_kind=AuditReviewerKind.HUMAN,
        decision=AuditReviewDecision.APPROVED,
        subject=subject,
        policy_pack=policy_pack,
        role=role,
        signed_at=signed_at,
        notes=notes,
        metadata=metadata,
    )


def create_advisory_model_signoff(
    *,
    signoff_id: str,
    reviewer_id: str,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    decision: AuditReviewDecision = AuditReviewDecision.COMMENTED,
    role: str = "model-advisory-reviewer",
    signed_at: datetime | None = None,
    notes: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> AuditReviewerSignoff:
    """Create a non-authoritative model signoff for advisory review state."""

    return create_reviewer_signoff(
        signoff_id=signoff_id,
        reviewer_id=reviewer_id,
        reviewer_kind=AuditReviewerKind.MODEL,
        decision=decision,
        subject=subject,
        policy_pack=policy_pack,
        role=role,
        signed_at=signed_at,
        notes=notes,
        metadata=metadata,
    )


def create_advisory_system_signoff(
    *,
    signoff_id: str,
    reviewer_id: str,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    decision: AuditReviewDecision = AuditReviewDecision.COMMENTED,
    role: str = "system-advisory-reviewer",
    signed_at: datetime | None = None,
    notes: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> AuditReviewerSignoff:
    """Create a non-authoritative system signoff for advisory review state."""

    return create_reviewer_signoff(
        signoff_id=signoff_id,
        reviewer_id=reviewer_id,
        reviewer_kind=AuditReviewerKind.SYSTEM,
        decision=decision,
        subject=subject,
        policy_pack=policy_pack,
        role=role,
        signed_at=signed_at,
        notes=notes,
        metadata=metadata,
    )


def validate_reviewer_signoffs(
    signoffs: Sequence[AuditReviewerSignoff],
    *,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    require_human_approval: bool = True,
) -> SignoffValidationResult:
    """
    Validate reviewer signoffs against Wave 9 authority rules.

    Only a human approval bound to the current subject digest and policy-pack
    digest is authoritative. Model and system signoffs are allowed as advisory
    evidence, but they cannot satisfy audit-ready authority.
    """

    expected_subject_digest = subject.digest
    expected_policy_pack_digest = policy_pack.digest
    sorted_signoffs = tuple(sorted(signoffs, key=lambda signoff: signoff.signoff_id))
    issues: list[SignoffValidationIssue] = []
    authoritative_human_approval_ids: list[str] = []
    advisory_signoff_ids: list[str] = []

    signoff_ids = [signoff.signoff_id for signoff in sorted_signoffs]
    duplicate_ids = sorted({signoff_id for signoff_id in signoff_ids if signoff_ids.count(signoff_id) > 1})
    for signoff_id in duplicate_ids:
        issues.append(
            _issue(
                "W9-SIGNOFF-DUPLICATE-ID",
                SignoffValidationIssueSeverity.BLOCKING,
                "Reviewer signoff IDs must be unique.",
                signoff_id=signoff_id,
                remediation="Give every reviewer signoff a unique stable signoff_id.",
            )
        )

    for signoff in sorted_signoffs:
        binding_issues = _binding_issues(
            signoff,
            expected_subject_digest=expected_subject_digest,
            expected_policy_pack_digest=expected_policy_pack_digest,
        )
        issues.extend(binding_issues)
        bound_to_current_audit = not binding_issues
        if bound_to_current_audit and signoff.is_authoritative_human_approval:
            authoritative_human_approval_ids.append(signoff.signoff_id)
        else:
            advisory_signoff_ids.append(signoff.signoff_id)
        if signoff.reviewer_kind is not AuditReviewerKind.HUMAN and signoff.decision is AuditReviewDecision.APPROVED:
            issues.append(
                _issue(
                    "W9-SIGNOFF-NON-HUMAN-APPROVAL-IS-ADVISORY",
                    SignoffValidationIssueSeverity.WARNING,
                    "Model or system approval is advisory and cannot satisfy human authority.",
                    signoff_id=signoff.signoff_id,
                    remediation="Require a human approval bound to the same subject and policy-pack digests.",
                    metadata={
                        "reviewer_kind": signoff.reviewer_kind.value,
                        "decision": signoff.decision.value,
                    },
                )
            )

    if require_human_approval and not authoritative_human_approval_ids:
        issues.append(
            _issue(
                "W9-SIGNOFF-MISSING-HUMAN-APPROVAL",
                SignoffValidationIssueSeverity.BLOCKING,
                "No authoritative human approval is bound to the current subject and policy pack.",
                remediation="Add a human approval signoff for the current subject digest and policy-pack digest.",
                metadata={
                    "subject_digest": expected_subject_digest,
                    "policy_pack_digest": expected_policy_pack_digest,
                    "signoff_count": len(sorted_signoffs),
                },
            )
        )

    return SignoffValidationResult(
        subject_digest=expected_subject_digest,
        policy_pack_digest=expected_policy_pack_digest,
        issues=tuple(issues),
        authoritative_human_approval_ids=tuple(authoritative_human_approval_ids),
        advisory_signoff_ids=tuple(advisory_signoff_ids),
        metadata={
            "signoff_count": len(sorted_signoffs),
            "require_human_approval": require_human_approval,
            "policy_pack_id": policy_pack.pack_id,
            "policy_pack_version": policy_pack.version,
        },
    )


def authoritative_human_approvals(
    signoffs: Sequence[AuditReviewerSignoff],
    *,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
) -> tuple[AuditReviewerSignoff, ...]:
    """Return signoffs that satisfy Wave 9 authoritative human approval rules."""

    expected_subject_digest = subject.digest
    expected_policy_pack_digest = policy_pack.digest
    return tuple(
        sorted(
            (
                signoff
                for signoff in signoffs
                if signoff.is_authoritative_human_approval
                and signoff.subject_digest == expected_subject_digest
                and signoff.policy_pack_digest == expected_policy_pack_digest
            ),
            key=lambda signoff: signoff.signoff_id,
        )
    )


def non_authoritative_approval_ids(signoffs: Sequence[AuditReviewerSignoff]) -> tuple[str, ...]:
    """Return model/system approval IDs that must remain advisory only."""

    return tuple(
        sorted(
            signoff.signoff_id
            for signoff in signoffs
            if signoff.reviewer_kind is not AuditReviewerKind.HUMAN
            and signoff.decision is AuditReviewDecision.APPROVED
        )
    )


def signoff_binding_payload(subject: AuditSubject, policy_pack: AuditPolicyPack) -> dict[str, Any]:
    """Return the deterministic subject/policy binding payload for signoffs."""

    return {
        "subject_digest": subject.digest,
        "subject": subject.to_dict(),
        "policy_pack_digest": policy_pack.digest,
        "policy_pack": {
            "pack_id": policy_pack.pack_id,
            "version": policy_pack.version,
            "control_ids": list(policy_pack.control_ids),
        },
    }


def signoff_binding_digest(subject: AuditSubject, policy_pack: AuditPolicyPack) -> str:
    """Return deterministic digest for the signoff binding payload."""

    return digest_payload(signoff_binding_payload(subject, policy_pack))


def summarize_signoff_authority(
    signoffs: Sequence[AuditReviewerSignoff],
    *,
    subject: AuditSubject,
    policy_pack: AuditPolicyPack,
    require_human_approval: bool = True,
) -> SignoffAuthoritySummary:
    """Build a compact authority summary for governance reports."""

    validation = validate_reviewer_signoffs(
        signoffs,
        subject=subject,
        policy_pack=policy_pack,
        require_human_approval=require_human_approval,
    )
    sorted_signoffs = tuple(sorted(signoffs, key=lambda signoff: signoff.signoff_id))
    return SignoffAuthoritySummary(
        subject_digest=subject.digest,
        policy_pack_digest=policy_pack.digest,
        signoff_count=len(sorted_signoffs),
        authoritative_human_approval_ids=validation.authoritative_human_approval_ids,
        advisory_signoff_ids=validation.advisory_signoff_ids,
        non_authoritative_approval_ids=non_authoritative_approval_ids(sorted_signoffs),
        validation_digest=digest_payload(validation.to_dict()),
    )


def _binding_issues(
    signoff: AuditReviewerSignoff,
    *,
    expected_subject_digest: str,
    expected_policy_pack_digest: str,
) -> tuple[SignoffValidationIssue, ...]:
    issues: list[SignoffValidationIssue] = []
    if signoff.subject_digest != expected_subject_digest:
        issues.append(
            _issue(
                "W9-SIGNOFF-SUBJECT-DIGEST-MISMATCH",
                SignoffValidationIssueSeverity.BLOCKING,
                "Reviewer signoff is not bound to the current audit subject digest.",
                signoff_id=signoff.signoff_id,
                remediation="Regenerate or reissue the signoff for the current audited subject.",
                metadata={
                    "signoff_subject_digest": signoff.subject_digest,
                    "expected_subject_digest": expected_subject_digest,
                },
            )
        )
    if signoff.policy_pack_digest != expected_policy_pack_digest:
        issues.append(
            _issue(
                "W9-SIGNOFF-POLICY-PACK-DIGEST-MISMATCH",
                SignoffValidationIssueSeverity.BLOCKING,
                "Reviewer signoff is not bound to the current policy-pack digest.",
                signoff_id=signoff.signoff_id,
                remediation="Regenerate or reissue the signoff for the evaluated policy pack.",
                metadata={
                    "signoff_policy_pack_digest": signoff.policy_pack_digest,
                    "expected_policy_pack_digest": expected_policy_pack_digest,
                },
            )
        )
    return tuple(issues)


def _issue(
    issue_id: str,
    severity: SignoffValidationIssueSeverity,
    summary: str,
    *,
    signoff_id: str = "",
    remediation: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> SignoffValidationIssue:
    return SignoffValidationIssue(
        issue_id=issue_id,
        severity=severity,
        summary=summary,
        signoff_id=signoff_id,
        remediation=remediation,
        metadata=dict(metadata or {}),
    )


def _issue_sort_key(issue: SignoffValidationIssue) -> tuple[str, str]:
    return (issue.issue_id, issue.signoff_id)
