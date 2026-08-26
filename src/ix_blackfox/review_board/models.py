from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.assurance.models import normalize_timestamp
from ix_blackfox.operating.models import (
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_sha256,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple

WAVE13_REVIEW_BOARD_SCHEMA_VERSION = "wave13.human_machine_review_board.v1"
WAVE13_POLICY_SCHEMA_VERSION = "wave13.review_board_policy.v1"
WAVE13_SUBJECT_SCHEMA_VERSION = "wave13.review_board_subject.v1"
WAVE13_MACHINE_ADVISORY_SCHEMA_VERSION = "wave13.machine_advisory.v1"
WAVE13_HUMAN_REVIEW_SCHEMA_VERSION = "wave13.human_review.v1"
WAVE13_EXTERNAL_VERIFICATION_SCHEMA_VERSION = (
    "wave13.external_human_review_verification.v1"
)
WAVE13_CHALLENGE_SCHEMA_VERSION = "wave13.evidence_challenge.v1"
WAVE13_EVALUATION_SCHEMA_VERSION = "wave13.review_board_evaluation.v1"


class ReviewRole(StrEnum):
    """Human review roles in the locked Wave 13 roadmap."""

    SECURITY = auto()
    QA = auto()
    SYSTEMS = auto()
    SAFETY = auto()
    OPERATIONS = auto()
    MANUFACTURING = auto()
    MAINTAINER = auto()


class HumanReviewDecision(StrEnum):
    """Decision a human reviewer can record for one role."""

    APPROVE = auto()
    REQUEST_CHANGES = auto()
    REJECT = auto()
    ABSTAIN = auto()


class ReviewAuthenticationState(StrEnum):
    """Whether identity verification was merely recorded or supplied externally."""

    RECORDED = auto()
    EXTERNALLY_VERIFIED = auto()


class MachineRecommendation(StrEnum):
    """Non-authoritative machine advisory outcomes."""

    PROCEED_TO_HUMAN_REVIEW = auto()
    REQUEST_CHANGES = auto()
    BLOCK = auto()
    INSUFFICIENT_EVIDENCE = auto()


class EvidenceChallengeStatus(StrEnum):
    """Lifecycle state for evidence challenges raised during board review."""

    OPEN = auto()
    RESOLVED = auto()
    WITHDRAWN = auto()


class ReviewBoardStatus(StrEnum):
    """Wave 13 board disposition without implying deployment authority."""

    BLOCKED = auto()
    HUMAN_REVIEW_REQUIRED = auto()
    APPROVED_FOR_NEXT_GATE = auto()


class ReviewBoardFindingCode(StrEnum):
    """Stable finding codes emitted by the Wave 13 policy engine."""

    MACHINE_ADVISORY_RECORDED = auto()
    MACHINE_BLOCK_RECOMMENDATION = auto()
    MACHINE_CHANGE_RECOMMENDATION = auto()
    MACHINE_ADVISORY_BINDING_MISMATCH = auto()
    HUMAN_REVIEW_NOT_EXTERNALLY_VERIFIED = auto()
    HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISSING = auto()
    HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISMATCH = auto()
    EXTERNAL_VERIFICATION_ORPHANED = auto()
    HUMAN_REVIEW_RECUSAL_RECORDED = auto()
    HUMAN_REVIEW_SELF_APPROVAL_BLOCKED = auto()
    HUMAN_REVIEW_SUBJECT_BINDING_MISMATCH = auto()
    HUMAN_REVIEW_POLICY_BINDING_MISMATCH = auto()
    HUMAN_REVIEW_CONFLICT_REQUIRES_RECUSAL = auto()
    HUMAN_REVIEW_REJECTED = auto()
    HUMAN_REVIEW_REQUESTED_CHANGES = auto()
    REQUIRED_ROLE_APPROVAL_MISSING = auto()
    MINIMUM_HUMAN_APPROVALS_NOT_MET = auto()
    DISTINCT_REVIEWER_QUORUM_NOT_MET = auto()
    OPEN_EVIDENCE_CHALLENGE = auto()
    CHALLENGE_SUBJECT_BINDING_MISMATCH = auto()
    BOARD_APPROVAL_REQUIREMENTS_SATISFIED = auto()


@dataclass(frozen=True, slots=True)
class ReviewBoardSubject:
    """Exact Wave 12 package subject admitted into a Wave 13 review case."""

    repository: str
    revision: str
    scope: str
    producer_agent_id: str
    wave12_archive_sha256: str
    wave12_manifest_digest: str
    wave12_profile_digest: str
    admitted_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "repository", normalize_text(self.repository, label="repository"))
        object.__setattr__(self, "revision", normalize_text(self.revision, label="revision"))
        object.__setattr__(self, "scope", normalize_text(self.scope, label="scope"))
        object.__setattr__(
            self,
            "producer_agent_id",
            normalize_identifier(self.producer_agent_id, label="producer_agent_id"),
        )
        object.__setattr__(
            self,
            "wave12_archive_sha256",
            normalize_sha256(self.wave12_archive_sha256),
        )
        object.__setattr__(
            self,
            "wave12_manifest_digest",
            normalize_sha256(self.wave12_manifest_digest),
        )
        object.__setattr__(
            self,
            "wave12_profile_digest",
            normalize_sha256(self.wave12_profile_digest),
        )
        object.__setattr__(self, "admitted_at", normalize_timestamp(self.admitted_at, label="admitted_at"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_SUBJECT_SCHEMA_VERSION,
            "repository": self.repository,
            "revision": self.revision,
            "scope": self.scope,
            "producer_agent_id": self.producer_agent_id,
            "wave12_archive_sha256": self.wave12_archive_sha256,
            "wave12_manifest_digest": self.wave12_manifest_digest,
            "wave12_profile_digest": self.wave12_profile_digest,
            "admitted_at": self.admitted_at,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class ReviewBoardPolicy:
    """Role, quorum, and fail-closed authority rules for one board case."""

    policy_id: str
    version: str
    supported_roles: tuple[ReviewRole, ...]
    required_roles: tuple[ReviewRole, ...]
    minimum_human_approvals: int
    require_distinct_reviewers: bool = True
    require_each_required_role: bool = True
    require_external_identity_verification: bool = True
    block_on_authenticated_reject: bool = True
    block_on_authenticated_request_changes: bool = True
    block_on_open_challenge: bool = True
    prevent_subject_producer_self_approval: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", normalize_identifier(self.policy_id, label="policy_id"))
        object.__setattr__(self, "version", normalize_text(self.version, label="version"))
        supported = _unique_sorted_roles(self.supported_roles)
        required = _unique_sorted_roles(self.required_roles)
        if not supported:
            raise ValueError("ReviewBoardPolicy supported_roles must not be empty.")
        if not required:
            raise ValueError("ReviewBoardPolicy required_roles must not be empty.")
        if not set(required).issubset(set(supported)):
            raise ValueError("ReviewBoardPolicy required_roles must be supported roles.")
        if self.minimum_human_approvals <= 0:
            raise ValueError("minimum_human_approvals must be positive.")
        if self.minimum_human_approvals > len(supported):
            raise ValueError(
                "minimum_human_approvals cannot exceed supported role count."
            )
        if self.minimum_human_approvals > len(required) and self.require_each_required_role:
            raise ValueError(
                "minimum_human_approvals cannot exceed required role count when every role is required."
            )
        object.__setattr__(self, "supported_roles", supported)
        object.__setattr__(self, "required_roles", required)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_POLICY_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "version": self.version,
            "supported_roles": [role.value for role in self.supported_roles],
            "required_roles": [role.value for role in self.required_roles],
            "minimum_human_approvals": self.minimum_human_approvals,
            "require_distinct_reviewers": self.require_distinct_reviewers,
            "require_each_required_role": self.require_each_required_role,
            "require_external_identity_verification": self.require_external_identity_verification,
            "block_on_authenticated_reject": self.block_on_authenticated_reject,
            "block_on_authenticated_request_changes": self.block_on_authenticated_request_changes,
            "block_on_open_challenge": self.block_on_open_challenge,
            "prevent_subject_producer_self_approval": self.prevent_subject_producer_self_approval,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class MachineAdvisory:
    """Machine analysis bound to a board subject and policy with no vote authority."""

    advisory_id: str
    producer_agent_id: str
    recommendation: MachineRecommendation
    subject_digest: str
    policy_digest: str
    produced_at: str
    summary: str
    findings: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "advisory_id", normalize_identifier(self.advisory_id, label="advisory_id"))
        object.__setattr__(
            self,
            "producer_agent_id",
            normalize_identifier(self.producer_agent_id, label="producer_agent_id"),
        )
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "policy_digest", normalize_sha256(self.policy_digest))
        object.__setattr__(self, "produced_at", normalize_timestamp(self.produced_at, label="produced_at"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "findings",
            _normalize_text_tuple(self.findings, label="findings"),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            normalize_identifier_tuple(self.evidence_refs, label="evidence_refs"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_MACHINE_ADVISORY_SCHEMA_VERSION,
            "advisory_id": self.advisory_id,
            "producer_agent_id": self.producer_agent_id,
            "recommendation": self.recommendation.value,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "produced_at": self.produced_at,
            "summary": self.summary,
            "findings": list(self.findings),
            "evidence_refs": list(self.evidence_refs),
            "authoritative": False,
            "vote_weight": 0,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class HumanReview:
    """One role-specific human decision bound to the exact case subject and policy."""

    review_id: str
    reviewer_id: str
    role: ReviewRole
    decision: HumanReviewDecision
    subject_digest: str
    policy_digest: str
    reviewed_at: str
    authentication_state: ReviewAuthenticationState
    rationale: str
    identity_verification_ref: str = ""
    identity_verification_sha256: str = ""
    authority_verification_ref: str = ""
    authority_verification_sha256: str = ""
    conflict_declared: bool = False
    recused: bool = False
    evidence_refs: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "review_id", normalize_identifier(self.review_id, label="review_id"))
        object.__setattr__(self, "reviewer_id", normalize_identifier(self.reviewer_id, label="reviewer_id"))
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "policy_digest", normalize_sha256(self.policy_digest))
        object.__setattr__(self, "reviewed_at", normalize_timestamp(self.reviewed_at, label="reviewed_at"))
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(
            self,
            "identity_verification_ref",
            normalize_optional_text(
                self.identity_verification_ref,
                label="identity_verification_ref",
            ),
        )
        if self.identity_verification_sha256:
            object.__setattr__(
                self,
                "identity_verification_sha256",
                normalize_sha256(self.identity_verification_sha256),
            )
        object.__setattr__(
            self,
            "authority_verification_ref",
            normalize_optional_text(
                self.authority_verification_ref,
                label="authority_verification_ref",
            ),
        )
        if self.authority_verification_sha256:
            object.__setattr__(
                self,
                "authority_verification_sha256",
                normalize_sha256(self.authority_verification_sha256),
            )
        object.__setattr__(
            self,
            "evidence_refs",
            normalize_identifier_tuple(self.evidence_refs, label="evidence_refs"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.authentication_state is ReviewAuthenticationState.EXTERNALLY_VERIFIED:
            if (
                not self.identity_verification_ref
                or not self.identity_verification_sha256
                or not self.authority_verification_ref
                or not self.authority_verification_sha256
            ):
                raise ValueError(
                    "Externally verified human reviews require identity and role-authority "
                    "verification references and SHA-256 digests."
                )
        if self.recused and self.decision is HumanReviewDecision.APPROVE:
            raise ValueError("A recused reviewer cannot record an approval decision.")

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_HUMAN_REVIEW_SCHEMA_VERSION,
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "role": self.role.value,
            "decision": self.decision.value,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "reviewed_at": self.reviewed_at,
            "authentication_state": self.authentication_state.value,
            "rationale": self.rationale,
            "identity_verification_ref": self.identity_verification_ref,
            "identity_verification_sha256": self.identity_verification_sha256,
            "authority_verification_ref": self.authority_verification_ref,
            "authority_verification_sha256": self.authority_verification_sha256,
            "conflict_declared": self.conflict_declared,
            "recused": self.recused,
            "evidence_refs": list(self.evidence_refs),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class ExternalHumanReviewVerification:
    """Trusted out-of-band confirmation for one serialized human review.

    This object is deliberately not embedded in the review-board package as an
    authority source. A caller must supply it from a separately trusted identity
    and role-authorization integration when building or verifying an authoritative
    human disposition. Serialized package data cannot manufacture this context.
    """

    review_id: str
    reviewer_id: str
    role: ReviewRole
    identity_verification_sha256: str
    authority_verification_sha256: str
    review_digest: str
    verifier_id: str
    verified_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "review_id",
            normalize_identifier(self.review_id, label="review_id"),
        )
        object.__setattr__(
            self,
            "reviewer_id",
            normalize_identifier(self.reviewer_id, label="reviewer_id"),
        )
        object.__setattr__(
            self,
            "identity_verification_sha256",
            normalize_sha256(self.identity_verification_sha256),
        )
        object.__setattr__(
            self,
            "authority_verification_sha256",
            normalize_sha256(self.authority_verification_sha256),
        )
        object.__setattr__(self, "review_digest", normalize_sha256(self.review_digest))
        object.__setattr__(
            self,
            "verifier_id",
            normalize_identifier(self.verifier_id, label="verifier_id"),
        )
        object.__setattr__(
            self,
            "verified_at",
            normalize_timestamp(self.verified_at, label="verified_at"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def matches(self, review: HumanReview) -> bool:
        return (
            self.review_id == review.review_id
            and self.reviewer_id == review.reviewer_id
            and self.role is review.role
            and self.identity_verification_sha256
            == review.identity_verification_sha256
            and self.authority_verification_sha256
            == review.authority_verification_sha256
            and self.review_digest == review.digest
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_EXTERNAL_VERIFICATION_SCHEMA_VERSION,
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "role": self.role.value,
            "identity_verification_sha256": self.identity_verification_sha256,
            "authority_verification_sha256": self.authority_verification_sha256,
            "review_digest": self.review_digest,
            "verifier_id": self.verifier_id,
            "verified_at": self.verified_at,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class EvidenceChallenge:
    """Human-raised challenge to evidence used by the review board."""

    challenge_id: str
    raised_by: str
    role: ReviewRole
    subject_digest: str
    raised_at: str
    status: EvidenceChallengeStatus
    summary: str
    evidence_refs: tuple[str, ...] = ()
    resolution_note: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "challenge_id",
            normalize_identifier(self.challenge_id, label="challenge_id"),
        )
        object.__setattr__(self, "raised_by", normalize_identifier(self.raised_by, label="raised_by"))
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "raised_at", normalize_timestamp(self.raised_at, label="raised_at"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "evidence_refs",
            normalize_identifier_tuple(self.evidence_refs, label="evidence_refs"),
        )
        object.__setattr__(
            self,
            "resolution_note",
            normalize_optional_text(self.resolution_note, label="resolution_note"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.status is EvidenceChallengeStatus.RESOLVED and not self.resolution_note:
            raise ValueError("Resolved evidence challenges require a resolution_note.")

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_CHALLENGE_SCHEMA_VERSION,
            "challenge_id": self.challenge_id,
            "raised_by": self.raised_by,
            "role": self.role.value,
            "subject_digest": self.subject_digest,
            "raised_at": self.raised_at,
            "status": self.status.value,
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "resolution_note": self.resolution_note,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class ReviewBoardFinding:
    """One deterministic Wave 13 review-board finding."""

    code: ReviewBoardFindingCode
    summary: str
    blocking: bool = False
    role: ReviewRole | None = None
    object_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "object_id",
            normalize_optional_text(self.object_id, label="object_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "summary": self.summary,
            "blocking": self.blocking,
            "role": self.role.value if self.role is not None else "",
            "object_id": self.object_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReviewBoardEvaluation:
    """Recomputable disposition for one Wave 13 board case."""

    subject_digest: str
    policy_digest: str
    status: ReviewBoardStatus
    findings: tuple[ReviewBoardFinding, ...]
    qualifying_review_ids: tuple[str, ...]
    qualifying_reviewer_ids: tuple[str, ...]
    approved_roles: tuple[ReviewRole, ...]
    missing_required_roles: tuple[ReviewRole, ...]
    machine_advisory_count: int
    human_review_count: int
    external_verification_count: int
    external_verification_context_digest: str
    open_challenge_count: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "policy_digest", normalize_sha256(self.policy_digest))
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(
                    self.findings,
                    key=lambda finding: (
                        finding.code.value,
                        finding.role.value if finding.role is not None else "",
                        finding.object_id,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "qualifying_review_ids",
            normalize_identifier_tuple(
                self.qualifying_review_ids,
                label="qualifying_review_ids",
            ),
        )
        object.__setattr__(
            self,
            "qualifying_reviewer_ids",
            normalize_identifier_tuple(
                self.qualifying_reviewer_ids,
                label="qualifying_reviewer_ids",
            ),
        )
        object.__setattr__(self, "approved_roles", _unique_sorted_roles(self.approved_roles))
        object.__setattr__(
            self,
            "missing_required_roles",
            _unique_sorted_roles(self.missing_required_roles),
        )
        if self.machine_advisory_count < 0 or self.human_review_count < 0:
            raise ValueError("Review counts must not be negative.")
        if self.external_verification_count < 0:
            raise ValueError("external_verification_count must not be negative.")
        object.__setattr__(
            self,
            "external_verification_context_digest",
            normalize_sha256(self.external_verification_context_digest),
        )
        if self.open_challenge_count < 0:
            raise ValueError("open_challenge_count must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking_findings(self) -> tuple[ReviewBoardFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE13_EVALUATION_SCHEMA_VERSION,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "status": self.status.value,
            "approved_for_next_gate": self.status is ReviewBoardStatus.APPROVED_FOR_NEXT_GATE,
            "blocking_finding_count": len(self.blocking_findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "qualifying_review_ids": list(self.qualifying_review_ids),
            "qualifying_reviewer_ids": list(self.qualifying_reviewer_ids),
            "approved_roles": [role.value for role in self.approved_roles],
            "missing_required_roles": [role.value for role in self.missing_required_roles],
            "machine_advisory_count": self.machine_advisory_count,
            "human_review_count": self.human_review_count,
            "external_verification_count": self.external_verification_count,
            "external_verification_context_digest": (
                self.external_verification_context_digest
            ),
            "open_challenge_count": self.open_challenge_count,
            "metadata": dict(self.metadata),
            "scope_note": (
                "Board approval means the configured human review requirements are "
                "satisfied for the bound evidence package. It does not grant deployment, "
                "production, certification, procurement, or operational authority."
            ),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def _unique_sorted_roles(values: Sequence[ReviewRole]) -> tuple[ReviewRole, ...]:
    by_value = {value.value: value for value in values}
    return tuple(by_value[key] for key in sorted(by_value))


def _normalize_text_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    return tuple(sorted({normalize_text(value, label=label) for value in values}))
