from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ix_blackfox.operating.models import digest_payload
from ix_blackfox.review_board.models import (
    EvidenceChallenge,
    EvidenceChallengeStatus,
    ExternalHumanReviewVerification,
    HumanReview,
    HumanReviewDecision,
    MachineAdvisory,
    MachineRecommendation,
    ReviewAuthenticationState,
    ReviewBoardEvaluation,
    ReviewBoardFinding,
    ReviewBoardFindingCode,
    ReviewBoardPolicy,
    ReviewBoardStatus,
    ReviewBoardSubject,
    ReviewRole,
)

DEFAULT_WAVE13_POLICY_ID = "ix-blackfox-wave13-full-board"
DEFAULT_WAVE13_POLICY_VERSION = "1.0.0"


def default_wave13_review_policy() -> ReviewBoardPolicy:
    """Return the locked-roadmap full-board policy with all seven human roles."""

    roles = tuple(ReviewRole)
    return ReviewBoardPolicy(
        policy_id=DEFAULT_WAVE13_POLICY_ID,
        version=DEFAULT_WAVE13_POLICY_VERSION,
        supported_roles=roles,
        required_roles=roles,
        minimum_human_approvals=len(roles),
        require_distinct_reviewers=True,
        require_each_required_role=True,
        require_external_identity_verification=True,
        block_on_authenticated_reject=True,
        block_on_authenticated_request_changes=True,
        block_on_open_challenge=True,
        prevent_subject_producer_self_approval=True,
        metadata={
            "roadmap_roles": [role.value for role in roles],
            "machine_vote_weight": 0,
        },
    )


def build_machine_advisory(
    *,
    advisory_id: str,
    producer_agent_id: str,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    produced_at: str,
    upstream_verification_passed: bool,
    upstream_readiness_status: str,
    evidence_refs: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> MachineAdvisory:
    """Build a deterministic non-authoritative advisory from verified upstream state."""

    if upstream_verification_passed:
        recommendation = MachineRecommendation.PROCEED_TO_HUMAN_REVIEW
        summary = (
            "The admitted Wave 12 package passed independent package verification; "
            "human board review remains required."
        )
    else:
        recommendation = MachineRecommendation.BLOCK
        summary = (
            "The admitted Wave 12 package did not pass independent package verification."
        )
    return MachineAdvisory(
        advisory_id=advisory_id,
        producer_agent_id=producer_agent_id,
        recommendation=recommendation,
        subject_digest=subject.digest,
        policy_digest=policy.digest,
        produced_at=produced_at,
        summary=summary,
        findings=(
            f"wave12_verification_passed={str(upstream_verification_passed).lower()}",
            f"wave12_readiness_status={upstream_readiness_status}",
        ),
        evidence_refs=tuple(evidence_refs),
        metadata={} if metadata is None else dict(metadata),
    )


def evaluate_review_board(
    *,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    machine_advisories: Sequence[MachineAdvisory] = (),
    human_reviews: Sequence[HumanReview] = (),
    external_verifications: Sequence[ExternalHumanReviewVerification] = (),
    challenges: Sequence[EvidenceChallenge] = (),
    metadata: Mapping[str, Any] | None = None,
) -> ReviewBoardEvaluation:
    """Evaluate human authority, role coverage, challenges, and fail-closed blockers."""

    advisories = tuple(sorted(machine_advisories, key=lambda item: item.advisory_id))
    reviews = tuple(sorted(human_reviews, key=lambda item: item.review_id))
    verifications = tuple(
        sorted(external_verifications, key=lambda item: item.review_id)
    )
    normalized_challenges = tuple(
        sorted(challenges, key=lambda item: item.challenge_id)
    )
    _require_unique_ids(advisories, reviews, normalized_challenges)
    _require_unique_external_verifications(verifications)
    findings: list[ReviewBoardFinding] = []
    qualifying: list[HumanReview] = []
    verification_by_review_id = {
        verification.review_id: verification for verification in verifications
    }
    review_ids = {review.review_id for review in reviews}
    for verification in verifications:
        if verification.review_id not in review_ids:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.EXTERNAL_VERIFICATION_ORPHANED,
                    summary=(
                        "Trusted external verification references a human review "
                        "that is not present in the board case."
                    ),
                    blocking=True,
                    object_id=verification.review_id,
                )
            )

    for advisory in advisories:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.MACHINE_ADVISORY_RECORDED,
                summary=(
                    "Machine advisory was recorded as non-authoritative and contributes "
                    "zero human approvals."
                ),
                object_id=advisory.advisory_id,
                metadata={"recommendation": advisory.recommendation.value},
            )
        )
        if advisory.subject_digest != subject.digest or advisory.policy_digest != policy.digest:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.MACHINE_ADVISORY_BINDING_MISMATCH,
                    summary="Machine advisory does not bind to the active subject and policy.",
                    blocking=True,
                    object_id=advisory.advisory_id,
                )
            )
        if advisory.recommendation is MachineRecommendation.BLOCK:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.MACHINE_BLOCK_RECOMMENDATION,
                    summary=(
                        "Machine advisory recommends blocking; the recommendation is visible "
                        "but does not itself exercise human authority."
                    ),
                    object_id=advisory.advisory_id,
                )
            )
        elif advisory.recommendation is MachineRecommendation.REQUEST_CHANGES:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.MACHINE_CHANGE_RECOMMENDATION,
                    summary=(
                        "Machine advisory recommends changes; the recommendation is visible "
                        "but does not itself exercise human authority."
                    ),
                    object_id=advisory.advisory_id,
                )
            )

    for review in reviews:
        review_qualifies, review_findings = _evaluate_human_review(
            subject=subject,
            policy=policy,
            review=review,
            external_verification=verification_by_review_id.get(review.review_id),
        )
        findings.extend(review_findings)
        if review_qualifies:
            qualifying.append(review)

    open_challenge_count = 0
    for challenge in normalized_challenges:
        if challenge.subject_digest != subject.digest:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.CHALLENGE_SUBJECT_BINDING_MISMATCH,
                    summary="Evidence challenge does not bind to the active board subject.",
                    blocking=True,
                    role=challenge.role,
                    object_id=challenge.challenge_id,
                )
            )
        if challenge.status is EvidenceChallengeStatus.OPEN:
            open_challenge_count += 1
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.OPEN_EVIDENCE_CHALLENGE,
                    summary="An unresolved human evidence challenge remains open.",
                    blocking=policy.block_on_open_challenge,
                    role=challenge.role,
                    object_id=challenge.challenge_id,
                )
            )

    approved_roles = tuple(sorted({review.role for review in qualifying}, key=lambda role: role.value))
    missing_roles = tuple(
        role for role in policy.required_roles if role not in set(approved_roles)
    )
    if policy.require_each_required_role:
        for role in missing_roles:
            findings.append(
                ReviewBoardFinding(
                    code=ReviewBoardFindingCode.REQUIRED_ROLE_APPROVAL_MISSING,
                    summary=f"Required human approval for role '{role.value}' is missing.",
                    role=role,
                )
            )

    if len(qualifying) < policy.minimum_human_approvals:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.MINIMUM_HUMAN_APPROVALS_NOT_MET,
                summary=(
                    "Qualifying externally verified human approvals do not meet the "
                    "configured minimum."
                ),
                metadata={
                    "required": policy.minimum_human_approvals,
                    "observed": len(qualifying),
                },
            )
        )

    qualifying_reviewer_ids = tuple(sorted({review.reviewer_id for review in qualifying}))
    if policy.require_distinct_reviewers and len(qualifying_reviewer_ids) < len(qualifying):
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.DISTINCT_REVIEWER_QUORUM_NOT_MET,
                summary=(
                    "One human identity is attempting to satisfy multiple qualifying board roles."
                ),
            )
        )

    blocking = any(finding.blocking for finding in findings)
    role_requirement_satisfied = not policy.require_each_required_role or not missing_roles
    approval_requirement_satisfied = len(qualifying) >= policy.minimum_human_approvals
    distinct_requirement_satisfied = (
        not policy.require_distinct_reviewers
        or len(qualifying_reviewer_ids) == len(qualifying)
    )

    if blocking:
        status = ReviewBoardStatus.BLOCKED
    elif (
        role_requirement_satisfied
        and approval_requirement_satisfied
        and distinct_requirement_satisfied
    ):
        status = ReviewBoardStatus.APPROVED_FOR_NEXT_GATE
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.BOARD_APPROVAL_REQUIREMENTS_SATISFIED,
                summary=(
                    "Configured role coverage, external identity state, and human quorum "
                    "requirements are satisfied for the bound evidence package."
                ),
            )
        )
    else:
        status = ReviewBoardStatus.HUMAN_REVIEW_REQUIRED

    return ReviewBoardEvaluation(
        subject_digest=subject.digest,
        policy_digest=policy.digest,
        status=status,
        findings=tuple(findings),
        qualifying_review_ids=tuple(review.review_id for review in qualifying),
        qualifying_reviewer_ids=qualifying_reviewer_ids,
        approved_roles=approved_roles,
        missing_required_roles=missing_roles,
        machine_advisory_count=len(advisories),
        human_review_count=len(reviews),
        external_verification_count=len(verifications),
        external_verification_context_digest=_external_verification_context_digest(
            verifications
        ),
        open_challenge_count=open_challenge_count,
        metadata={} if metadata is None else dict(metadata),
    )


def _evaluate_human_review(
    *,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    review: HumanReview,
    external_verification: ExternalHumanReviewVerification | None,
) -> tuple[bool, tuple[ReviewBoardFinding, ...]]:
    findings: list[ReviewBoardFinding] = []
    valid_binding = True

    if review.role not in policy.supported_roles:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_POLICY_BINDING_MISMATCH,
                summary=(
                    "Human review role is not supported by the active review-board policy."
                ),
                blocking=True,
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    if review.subject_digest != subject.digest:
        valid_binding = False
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_SUBJECT_BINDING_MISMATCH,
                summary="Human review is bound to a different review-board subject.",
                blocking=True,
                role=review.role,
                object_id=review.review_id,
            )
        )
    if review.policy_digest != policy.digest:
        valid_binding = False
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_POLICY_BINDING_MISMATCH,
                summary="Human review is bound to a different review-board policy.",
                blocking=True,
                role=review.role,
                object_id=review.review_id,
            )
        )
    if (
        policy.prevent_subject_producer_self_approval
        and review.reviewer_id == subject.producer_agent_id
    ):
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_SELF_APPROVAL_BLOCKED,
                summary="The subject producer cannot satisfy its own human approval gate.",
                blocking=True,
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    if review.conflict_declared and not review.recused:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_CONFLICT_REQUIRES_RECUSAL,
                summary="A declared reviewer conflict requires recusal before the review can count.",
                blocking=True,
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    if review.recused:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_RECUSAL_RECORDED,
                summary="Reviewer recusal is preserved and contributes no approval authority.",
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    recorded_as_externally_verified = (
        review.authentication_state is ReviewAuthenticationState.EXTERNALLY_VERIFIED
    )
    if policy.require_external_identity_verification and not recorded_as_externally_verified:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_NOT_EXTERNALLY_VERIFIED,
                summary=(
                    "Recorded human review lacks externally supplied identity verification "
                    "and does not count toward quorum."
                ),
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    externally_confirmed = False
    if policy.require_external_identity_verification:
        if external_verification is None:
            findings.append(
                ReviewBoardFinding(
                    code=(
                        ReviewBoardFindingCode.HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISSING
                    ),
                    summary=(
                        "Serialized external-verification state was not confirmed by "
                        "trusted out-of-band identity and role-authority context."
                    ),
                    role=review.role,
                    object_id=review.review_id,
                )
            )
            return False, tuple(findings)
        if not external_verification.matches(review):
            findings.append(
                ReviewBoardFinding(
                    code=(
                        ReviewBoardFindingCode.HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISMATCH
                    ),
                    summary=(
                        "Trusted external verification does not match the serialized "
                        "reviewer identity, role, or bound verification digests."
                    ),
                    blocking=True,
                    role=review.role,
                    object_id=review.review_id,
                )
            )
            return False, tuple(findings)
        externally_confirmed = True

    authenticated = (
        externally_confirmed if policy.require_external_identity_verification else True
    )

    if authenticated and review.decision is HumanReviewDecision.REJECT:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_REJECTED,
                summary="An externally verified human reviewer rejected the case.",
                blocking=policy.block_on_authenticated_reject,
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    if authenticated and review.decision is HumanReviewDecision.REQUEST_CHANGES:
        findings.append(
            ReviewBoardFinding(
                code=ReviewBoardFindingCode.HUMAN_REVIEW_REQUESTED_CHANGES,
                summary="An externally verified human reviewer requested changes.",
                blocking=policy.block_on_authenticated_request_changes,
                role=review.role,
                object_id=review.review_id,
            )
        )
        return False, tuple(findings)

    return (
        valid_binding and authenticated and review.decision is HumanReviewDecision.APPROVE,
        tuple(findings),
    )


def _require_unique_ids(
    advisories: Sequence[MachineAdvisory],
    reviews: Sequence[HumanReview],
    challenges: Sequence[EvidenceChallenge],
) -> None:
    groups = (
        ("machine advisory", [item.advisory_id for item in advisories]),
        ("human review", [item.review_id for item in reviews]),
        ("evidence challenge", [item.challenge_id for item in challenges]),
    )
    for label, values in groups:
        if len(values) != len(set(values)):
            raise ValueError(f"Duplicate {label} ids are not allowed.")


def _require_unique_external_verifications(
    verifications: Sequence[ExternalHumanReviewVerification],
) -> None:
    review_ids = [item.review_id for item in verifications]
    if len(review_ids) != len(set(review_ids)):
        raise ValueError("Duplicate external human-review verification ids are not allowed.")


def _external_verification_context_digest(
    verifications: Sequence[ExternalHumanReviewVerification],
) -> str:
    return digest_payload(
        {
            "schema_version": "wave13.external_verification_context.v1",
            "verifications": [item.to_dict() for item in verifications],
        }
    )
