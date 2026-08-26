from __future__ import annotations

from dataclasses import replace

import pytest

from ix_blackfox.review_board import (
    EvidenceChallenge,
    EvidenceChallengeStatus,
    HumanReview,
    HumanReviewDecision,
    MachineAdvisory,
    MachineRecommendation,
    ReviewAuthenticationState,
    ReviewBoardFindingCode,
    ReviewBoardStatus,
    ReviewRole,
)
from ix_blackfox.review_board.policy import (
    build_machine_advisory,
    default_wave13_review_policy,
    evaluate_review_board,
)
from tests.review_board.helpers import (
    AUTHORITY_DIGEST,
    IDENTITY_DIGEST,
    WAVE13_TIME,
    admit_fixture,
    external_verifications_for_reviews,
    full_human_approvals,
)


def test_default_policy_covers_every_locked_wave13_role() -> None:
    policy = default_wave13_review_policy()

    assert policy.supported_roles == tuple(sorted(ReviewRole, key=lambda role: role.value))
    assert policy.required_roles == tuple(sorted(ReviewRole, key=lambda role: role.value))
    assert policy.minimum_human_approvals == 7
    assert policy.require_distinct_reviewers is True
    assert policy.require_external_identity_verification is True
    assert policy.metadata["machine_vote_weight"] == 0


def test_machine_only_case_cannot_approve(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    advisory = build_machine_advisory(
        advisory_id="ci-advisory",
        producer_agent_id="wave13-rule-engine",
        subject=admission.subject,
        policy=policy,
        produced_at=WAVE13_TIME,
        upstream_verification_passed=True,
        upstream_readiness_status=admission.verification.readiness_status,
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        machine_advisories=(advisory,),
    )

    assert result.status is ReviewBoardStatus.HUMAN_REVIEW_REQUIRED
    assert result.qualifying_review_ids == ()
    assert result.approved_roles == ()
    assert len(result.missing_required_roles) == 7
    assert any(
        finding.code is ReviewBoardFindingCode.MACHINE_ADVISORY_RECORDED
        for finding in result.findings
    )


def test_full_distinct_externally_verified_human_board_can_approve_next_gate(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()

    reviews = full_human_approvals(admission)
    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=reviews,
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.APPROVED_FOR_NEXT_GATE
    assert len(result.qualifying_review_ids) == 7
    assert len(result.qualifying_reviewer_ids) == 7
    assert result.missing_required_roles == ()
    assert any(
        finding.code is ReviewBoardFindingCode.BOARD_APPROVAL_REQUIREMENTS_SATISFIED
        for finding in result.findings
    )


def test_serialized_external_verification_claims_cannot_self_authorize(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = full_human_approvals(admission)

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=reviews,
    )

    assert result.status is ReviewBoardStatus.HUMAN_REVIEW_REQUIRED
    assert result.qualifying_review_ids == ()
    missing = [
        finding
        for finding in result.findings
        if finding.code
        is ReviewBoardFindingCode.HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISSING
    ]
    assert len(missing) == 7


def test_external_verification_binds_exact_review_digest(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = list(full_human_approvals(admission))
    verifications = external_verifications_for_reviews(reviews)
    reviews[0] = replace(
        reviews[0],
        rationale="Decision record changed after external verification.",
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=tuple(reviews),
        external_verifications=verifications,
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code
        is ReviewBoardFindingCode.HUMAN_REVIEW_EXTERNAL_VERIFICATION_MISMATCH
        and finding.blocking
        for finding in result.findings
    )


def test_orphaned_external_verification_fails_closed(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    reviews = full_human_approvals(admission)
    verification = external_verifications_for_reviews(reviews[:1])[0]

    result = evaluate_review_board(
        subject=admission.subject,
        policy=default_wave13_review_policy(),
        external_verifications=(verification,),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.EXTERNAL_VERIFICATION_ORPHANED
        and finding.blocking
        for finding in result.findings
    )


def test_recorded_identity_never_counts_toward_quorum(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    review = HumanReview(
        review_id="security-recorded-only",
        reviewer_id="security-human",
        role=ReviewRole.SECURITY,
        decision=HumanReviewDecision.APPROVE,
        subject_digest=admission.subject.digest,
        policy_digest=policy.digest,
        reviewed_at=WAVE13_TIME,
        authentication_state=ReviewAuthenticationState.RECORDED,
        rationale="Identity is recorded but not externally verified.",
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=(review,),
    )

    assert result.status is ReviewBoardStatus.HUMAN_REVIEW_REQUIRED
    assert result.qualifying_review_ids == ()
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_NOT_EXTERNALLY_VERIFIED
        for finding in result.findings
    )


def test_authenticated_rejection_fails_closed(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = list(full_human_approvals(admission))
    reviews[0] = replace(
        reviews[0],
        decision=HumanReviewDecision.REJECT,
        rationale="Security rejects the case.",
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=tuple(reviews),
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_REJECTED
        and finding.blocking
        for finding in result.findings
    )


def test_authenticated_request_changes_fails_closed(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = list(full_human_approvals(admission))
    reviews[1] = replace(
        reviews[1],
        decision=HumanReviewDecision.REQUEST_CHANGES,
        rationale="QA requests remediation.",
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=tuple(reviews),
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_REQUESTED_CHANGES
        and finding.blocking
        for finding in result.findings
    )


def test_open_evidence_challenge_blocks_even_with_full_approvals(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    challenge = EvidenceChallenge(
        challenge_id="challenge-1",
        raised_by="human-safety",
        role=ReviewRole.SAFETY,
        subject_digest=admission.subject.digest,
        raised_at=WAVE13_TIME,
        status=EvidenceChallengeStatus.OPEN,
        summary="Safety evidence requires clarification.",
    )

    reviews = full_human_approvals(admission)
    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=reviews,
        external_verifications=external_verifications_for_reviews(reviews),
        challenges=(challenge,),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert result.open_challenge_count == 1


def test_resolved_evidence_challenge_does_not_block(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    challenge = EvidenceChallenge(
        challenge_id="challenge-1",
        raised_by="human-safety",
        role=ReviewRole.SAFETY,
        subject_digest=admission.subject.digest,
        raised_at=WAVE13_TIME,
        status=EvidenceChallengeStatus.RESOLVED,
        summary="Safety evidence required clarification.",
        resolution_note="Reviewer accepted the corrected evidence binding.",
    )

    reviews = full_human_approvals(admission)
    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=reviews,
        external_verifications=external_verifications_for_reviews(reviews),
        challenges=(challenge,),
    )

    assert result.status is ReviewBoardStatus.APPROVED_FOR_NEXT_GATE
    assert result.open_challenge_count == 0


def test_declared_conflict_requires_recusal(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = list(full_human_approvals(admission))
    reviews[0] = replace(reviews[0], conflict_declared=True)

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=tuple(reviews),
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_CONFLICT_REQUIRES_RECUSAL
        for finding in result.findings
    )


def test_recusal_is_preserved_and_cannot_count_as_approval(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    reviews = list(full_human_approvals(admission))
    reviews[0] = replace(
        reviews[0],
        decision=HumanReviewDecision.ABSTAIN,
        conflict_declared=True,
        recused=True,
        rationale="Reviewer recused due to disclosed conflict.",
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=tuple(reviews),
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.HUMAN_REVIEW_REQUIRED
    assert ReviewRole.SECURITY in result.missing_required_roles
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_RECUSAL_RECORDED
        for finding in result.findings
    )


def test_subject_producer_cannot_self_approve(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    review = HumanReview(
        review_id="self-approval",
        reviewer_id=admission.subject.producer_agent_id,
        role=ReviewRole.SECURITY,
        decision=HumanReviewDecision.APPROVE,
        subject_digest=admission.subject.digest,
        policy_digest=policy.digest,
        reviewed_at=WAVE13_TIME,
        authentication_state=ReviewAuthenticationState.EXTERNALLY_VERIFIED,
        rationale="Attempted self approval.",
        identity_verification_ref="fixture-idp://producer",
        identity_verification_sha256=IDENTITY_DIGEST,
        authority_verification_ref="fixture-authority://reviewer/role",
        authority_verification_sha256=AUTHORITY_DIGEST,
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=(review,),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_SELF_APPROVAL_BLOCKED
        for finding in result.findings
    )


def test_same_human_cannot_satisfy_multiple_roles_under_default_policy(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    reviews = tuple(
        replace(review, reviewer_id="one-human")
        for review in full_human_approvals(admission)
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=default_wave13_review_policy(),
        human_reviews=reviews,
        external_verifications=external_verifications_for_reviews(reviews),
    )

    assert result.status is ReviewBoardStatus.HUMAN_REVIEW_REQUIRED
    assert any(
        finding.code is ReviewBoardFindingCode.DISTINCT_REVIEWER_QUORUM_NOT_MET
        for finding in result.findings
    )


def test_stale_subject_binding_blocks(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    review = HumanReview(
        review_id="stale-review",
        reviewer_id="human-security",
        role=ReviewRole.SECURITY,
        decision=HumanReviewDecision.APPROVE,
        subject_digest="b" * 64,
        policy_digest=policy.digest,
        reviewed_at=WAVE13_TIME,
        authentication_state=ReviewAuthenticationState.EXTERNALLY_VERIFIED,
        rationale="Bound to a different subject.",
        identity_verification_ref="fixture-idp://human-security",
        identity_verification_sha256=IDENTITY_DIGEST,
        authority_verification_ref="fixture-authority://reviewer/role",
        authority_verification_sha256=AUTHORITY_DIGEST,
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=(review,),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_SUBJECT_BINDING_MISMATCH
        for finding in result.findings
    )


def test_machine_advisory_zero_vote_fields_are_derived(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    advisory = MachineAdvisory(
        advisory_id="machine-1",
        producer_agent_id="model-brain",
        recommendation=MachineRecommendation.PROCEED_TO_HUMAN_REVIEW,
        subject_digest=admission.subject.digest,
        policy_digest=policy.digest,
        produced_at=WAVE13_TIME,
        summary="Advisory only.",
    )

    payload = advisory.to_dict()
    assert payload["authoritative"] is False
    assert payload["vote_weight"] == 0


def test_externally_verified_review_requires_verification_reference_and_digest(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()

    with pytest.raises(ValueError, match="identity and role-authority verification references"):
        HumanReview(
            review_id="bad-review",
            reviewer_id="human-security",
            role=ReviewRole.SECURITY,
            decision=HumanReviewDecision.APPROVE,
            subject_digest=admission.subject.digest,
            policy_digest=policy.digest,
            reviewed_at=WAVE13_TIME,
            authentication_state=ReviewAuthenticationState.EXTERNALLY_VERIFIED,
            rationale="Missing identity evidence.",
        )


def test_recused_review_cannot_claim_approval(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()

    with pytest.raises(ValueError, match="recused reviewer"):
        HumanReview(
            review_id="bad-recusal",
            reviewer_id="human-security",
            role=ReviewRole.SECURITY,
            decision=HumanReviewDecision.APPROVE,
            subject_digest=admission.subject.digest,
            policy_digest=policy.digest,
            reviewed_at=WAVE13_TIME,
            authentication_state=ReviewAuthenticationState.RECORDED,
            rationale="Invalid recusal state.",
            recused=True,
        )


def test_policy_rejects_impossible_minimum_above_supported_role_count() -> None:
    policy = default_wave13_review_policy()

    with pytest.raises(ValueError, match="cannot exceed supported role count"):
        replace(
            policy,
            supported_roles=(ReviewRole.SECURITY,),
            required_roles=(ReviewRole.SECURITY,),
            minimum_human_approvals=2,
            require_each_required_role=False,
        )


def test_review_for_role_outside_active_policy_fails_closed(tmp_path) -> None:
    _, admission = admit_fixture(tmp_path)
    policy = replace(
        default_wave13_review_policy(),
        supported_roles=(ReviewRole.SECURITY,),
        required_roles=(ReviewRole.SECURITY,),
        minimum_human_approvals=1,
    )
    review = HumanReview(
        review_id="unsupported-role-review",
        reviewer_id="human-qa",
        role=ReviewRole.QA,
        decision=HumanReviewDecision.APPROVE,
        subject_digest=admission.subject.digest,
        policy_digest=policy.digest,
        reviewed_at=WAVE13_TIME,
        authentication_state=ReviewAuthenticationState.EXTERNALLY_VERIFIED,
        rationale="This role is outside the active policy.",
        identity_verification_ref="fixture-idp://human-qa",
        identity_verification_sha256=IDENTITY_DIGEST,
        authority_verification_ref="fixture-authority://reviewer/role",
        authority_verification_sha256=AUTHORITY_DIGEST,
    )

    result = evaluate_review_board(
        subject=admission.subject,
        policy=policy,
        human_reviews=(review,),
    )

    assert result.status is ReviewBoardStatus.BLOCKED
    assert any(
        finding.code is ReviewBoardFindingCode.HUMAN_REVIEW_POLICY_BINDING_MISMATCH
        for finding in result.findings
    )
