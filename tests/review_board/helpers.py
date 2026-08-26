from __future__ import annotations

from pathlib import Path

from ix_blackfox.assurance.package import build_assurance_package
from ix_blackfox.review_board import (
    ExternalHumanReviewVerification,
    HumanReview,
    HumanReviewDecision,
    ReviewAuthenticationState,
    ReviewRole,
)
from ix_blackfox.review_board.admission import Wave12Admission, admit_wave12_package
from ix_blackfox.review_board.policy import default_wave13_review_policy
from tests.assurance.helpers import FIXED_TIME, REVISION, build_stack

WAVE13_TIME = "2026-08-25T16:00:00+00:00"
IDENTITY_DIGEST = "a" * 64
AUTHORITY_DIGEST = "b" * 64


def build_wave12_package(tmp_path: Path) -> Path:
    stack = build_stack(tmp_path)
    package = stack.root / "wave12.zip"
    build_assurance_package(
        output_path=package,
        manifest=stack.manifest,
        crosswalk=stack.crosswalk,
        readiness=stack.readiness,
        evidence=stack.evidence,
        reviews=stack.reviews,
        metadata={"fixture": True},
    )
    return package


def admit_fixture(tmp_path: Path) -> tuple[Path, Wave12Admission]:
    package = build_wave12_package(tmp_path)
    return package, admit_wave12_package(package, admitted_at=WAVE13_TIME)


def full_human_approvals(admission: Wave12Admission) -> tuple[HumanReview, ...]:
    policy = default_wave13_review_policy()
    return tuple(
        HumanReview(
            review_id=f"review-{role.value}",
            reviewer_id=f"human-{index}-{role.value}",
            role=role,
            decision=HumanReviewDecision.APPROVE,
            subject_digest=admission.subject.digest,
            policy_digest=policy.digest,
            reviewed_at=WAVE13_TIME,
            authentication_state=ReviewAuthenticationState.EXTERNALLY_VERIFIED,
            rationale=f"Fixture approval for {role.value} role.",
            identity_verification_ref=f"fixture-idp://human-{index}-{role.value}",
            identity_verification_sha256=IDENTITY_DIGEST,
            authority_verification_ref=(
                f"fixture-authority://human-{index}-{role.value}/{role.value}"
            ),
            authority_verification_sha256=AUTHORITY_DIGEST,
        )
        for index, role in enumerate(ReviewRole, start=1)
    )


def external_verifications_for_reviews(
    reviews: tuple[HumanReview, ...] | list[HumanReview],
) -> tuple[ExternalHumanReviewVerification, ...]:
    return tuple(
        ExternalHumanReviewVerification(
            review_id=review.review_id,
            reviewer_id=review.reviewer_id,
            role=review.role,
            identity_verification_sha256=review.identity_verification_sha256,
            authority_verification_sha256=review.authority_verification_sha256,
            review_digest=review.digest,
            verifier_id="fixture-trusted-human-authority-verifier",
            verified_at=WAVE13_TIME,
            metadata={"fixture": True},
        )
        for review in reviews
        if review.authentication_state is ReviewAuthenticationState.EXTERNALLY_VERIFIED
    )


__all__ = [
    "AUTHORITY_DIGEST",
    "FIXED_TIME",
    "IDENTITY_DIGEST",
    "REVISION",
    "WAVE13_TIME",
    "admit_fixture",
    "build_wave12_package",
    "external_verifications_for_reviews",
    "full_human_approvals",
]
