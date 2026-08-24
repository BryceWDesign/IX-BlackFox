from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.crosswalk import (
    AssuranceCrosswalkReport,
    ControlEvaluationStatus,
    build_assurance_crosswalk,
    evaluate_control,
)
from ix_blackfox.assurance.models import (
    AssuranceClaimSet,
    AssuranceEvidenceKind,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
)
from ix_blackfox.assurance.report import (
    AssuranceFindingCode,
    AssuranceReadinessReport,
    AssuranceReadinessStatus,
    build_assurance_readiness_report,
)
from tests.assurance.helpers import FIXED_TIME, build_stack


def test_default_fixture_satisfies_all_mandatory_evidence_controls(
    tmp_path: Path,
) -> None:
    stack = build_stack(tmp_path)
    assert stack.crosswalk.mandatory_evidence_complete
    assert stack.crosswalk.blocking_evaluations == ()
    assert stack.crosswalk.satisfied_control_count == 7
    by_id = {
        evaluation.control.control_id: evaluation
        for evaluation in stack.crosswalk.evaluations
    }
    assert by_id["oscal-assessment-results-alignment"].status is (
        ControlEvaluationStatus.NOT_APPLICABLE
    )
    assert by_id["slsa-1-2-provenance-alignment"].status is (
        ControlEvaluationStatus.PARTIAL
    )


def test_missing_mandatory_kind_blocks_crosswalk(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    artifacts = tuple(
        artifact
        for artifact in stack.manifest.evidence
        if artifact.evidence_kind is not AssuranceEvidenceKind.TEST_RESULT
    )
    crosswalk = build_assurance_crosswalk(
        subject=stack.manifest.subject,
        profile=stack.manifest.profile,
        artifacts=artifacts,
    )
    assert not crosswalk.mandatory_evidence_complete
    evaluation = next(
        item
        for item in crosswalk.evaluations
        if item.control.control_id == "bf-w12-001-quality-gates"
    )
    assert evaluation.status is ControlEvaluationStatus.PARTIAL
    assert evaluation.blocking
    assert evaluation.missing_kinds == (AssuranceEvidenceKind.TEST_RESULT,)


def test_recorded_evidence_does_not_satisfy_integrity_requirement(
    tmp_path: Path,
) -> None:
    stack = build_stack(tmp_path)
    control = next(
        control
        for control in stack.manifest.profile.controls
        if control.control_id == "bf-w12-001-quality-gates"
    )
    artifacts = tuple(
        replace(
            artifact,
            verification_state=EvidenceVerificationState.RECORDED,
        )
        if artifact.evidence_kind is AssuranceEvidenceKind.TEST_RESULT
        else artifact
        for artifact in stack.manifest.evidence
    )
    evaluation = evaluate_control(control, artifacts)
    assert evaluation.status is ControlEvaluationStatus.PARTIAL
    assert "artifact-test-result" in evaluation.insufficient_verification_artifact_ids


def test_crosswalk_digest_is_deterministic(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    reversed_report = AssuranceCrosswalkReport(
        report_id=stack.crosswalk.report_id,
        subject_digest=stack.crosswalk.subject_digest,
        profile_digest=stack.crosswalk.profile_digest,
        evaluations=tuple(reversed(stack.crosswalk.evaluations)),
        generated_at=stack.crosswalk.generated_at,
    )
    assert reversed_report.digest == stack.crosswalk.digest


def test_complete_package_without_human_review_stays_review_required(
    tmp_path: Path,
) -> None:
    stack = build_stack(tmp_path)
    assert stack.readiness.status is AssuranceReadinessStatus.REVIEW_REQUIRED
    assert not stack.readiness.ready_for_external_assessment
    codes = {finding.code for finding in stack.readiness.findings}
    assert AssuranceFindingCode.REVIEW_REQUIRED in codes
    assert not stack.readiness.blocking_findings


def test_separate_authenticated_human_review_advances_only_to_external_assessment(
    tmp_path: Path,
) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
        human_review_externally_verified=True,
    )
    assert stack.readiness.status is (
        AssuranceReadinessStatus.READY_FOR_EXTERNAL_ASSESSMENT
    )
    assert stack.readiness.authoritative_human_approval_count == 1
    assert "does not mean certified" in stack.readiness.to_dict()["scope_note"]


def test_locally_recorded_review_evidence_cannot_elevate_readiness(
    tmp_path: Path,
) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
    )
    assert stack.readiness.status is AssuranceReadinessStatus.BLOCKED
    assert stack.readiness.authoritative_human_approval_count == 0
    assert (
        AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_NOT_EXTERNALLY_VERIFIED
        in {finding.code for finding in stack.readiness.blocking_findings}
    )


def test_self_approval_blocks_readiness(tmp_path: Path) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
        reviewer_agent_id="wave12-package-builder",
    )
    assert stack.readiness.status is AssuranceReadinessStatus.BLOCKED
    assert AssuranceFindingCode.REVIEWER_SELF_APPROVAL in {
        finding.code for finding in stack.readiness.blocking_findings
    }


@pytest.mark.parametrize(
    "kind",
    [AgentKind.MODEL_BRAIN, AgentKind.TOOL, AgentKind.CI_RUNNER, AgentKind.SYSTEM_SERVICE],
)
def test_non_human_approval_attempt_blocks_readiness(
    tmp_path: Path,
    kind: AgentKind,
) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
        reviewer_kind=kind,
    )
    assert stack.readiness.status is AssuranceReadinessStatus.BLOCKED
    assert AssuranceFindingCode.NON_HUMAN_APPROVAL_ATTEMPT in {
        finding.code for finding in stack.readiness.blocking_findings
    }


def test_recorded_but_unauthenticated_human_review_remains_review_required(
    tmp_path: Path,
) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
        authentication_state=ReviewAuthenticationState.RECORDED,
    )
    assert stack.readiness.status is AssuranceReadinessStatus.REVIEW_REQUIRED
    assert AssuranceFindingCode.REVIEW_AUTHENTICATION_UNVERIFIED in {
        finding.code for finding in stack.readiness.findings
    }


@pytest.mark.parametrize(
    "decision",
    [AuthorityReviewDecision.REJECT, AuthorityReviewDecision.REQUEST_CHANGES],
)
def test_reject_or_change_request_blocks_readiness(
    tmp_path: Path,
    decision: AuthorityReviewDecision,
) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
        decision=decision,
    )
    assert stack.readiness.status is AssuranceReadinessStatus.BLOCKED
    assert AssuranceFindingCode.REVIEW_REJECTED_OR_CHANGES_REQUIRED in {
        finding.code for finding in stack.readiness.blocking_findings
    }


def test_missing_review_verification_artifact_blocks(tmp_path: Path) -> None:
    stack = build_stack(tmp_path, add_authoritative_review=True)
    assert AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_MISSING in {
        finding.code for finding in stack.readiness.blocking_findings
    }


def test_wrong_kind_review_verification_artifact_blocks(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    review = AuthorityReview(
        review_id="wrong-kind",
        reviewer_agent_id="release-owner",
        reviewer_kind=AgentKind.HUMAN_OPERATOR,
        decision=AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT,
        subject_digest=stack.manifest.digest,
        profile_digest=stack.manifest.profile.digest,
        reviewed_at=FIXED_TIME,
        authentication_state=ReviewAuthenticationState.VERIFIED,
        verification_artifact_ids=("artifact-test-result",),
    )
    report = build_assurance_readiness_report(
        manifest=stack.manifest,
        crosswalk=stack.crosswalk,
        reviews=(review,),
    )
    assert AssuranceFindingCode.REVIEW_VERIFICATION_ARTIFACT_WRONG_KIND in {
        finding.code for finding in report.blocking_findings
    }


def test_review_subject_and_profile_mismatch_block(tmp_path: Path) -> None:
    stack = build_stack(tmp_path, include_human_review_evidence=True)
    review = AuthorityReview(
        review_id="mismatch",
        reviewer_agent_id="release-owner",
        reviewer_kind=AgentKind.HUMAN_OPERATOR,
        decision=AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT,
        subject_digest="a" * 64,
        profile_digest="b" * 64,
        reviewed_at=FIXED_TIME,
        authentication_state=ReviewAuthenticationState.VERIFIED,
        verification_artifact_ids=("artifact-human-review",),
    )
    report = build_assurance_readiness_report(
        manifest=stack.manifest,
        crosswalk=stack.crosswalk,
        reviews=(review,),
    )
    codes = {finding.code for finding in report.blocking_findings}
    assert AssuranceFindingCode.REVIEW_SUBJECT_MISMATCH in codes
    assert AssuranceFindingCode.REVIEW_PROFILE_MISMATCH in codes


def test_prohibited_asserted_claim_blocks_readiness(tmp_path: Path) -> None:
    claims = AssuranceClaimSet(
        asserted_claims=("IX-BlackFox is certified for production.",),
        non_claims=("No government approval is claimed.",),
    )
    stack = build_stack(tmp_path, claims=claims)
    assert stack.readiness.status is AssuranceReadinessStatus.BLOCKED
    assert AssuranceFindingCode.PROHIBITED_ASSERTED_CLAIM in {
        finding.code for finding in stack.readiness.blocking_findings
    }


def test_duplicate_review_ids_are_rejected(tmp_path: Path) -> None:
    stack = build_stack(
        tmp_path,
        include_human_review_evidence=True,
        add_authoritative_review=True,
    )
    review = stack.reviews[0]
    with pytest.raises(ValueError, match="review_id"):
        AssuranceReadinessReport(
            report_id="duplicate-review",
            manifest_digest=stack.manifest.digest,
            subject_digest=stack.manifest.subject.digest,
            profile_digest=stack.manifest.profile.digest,
            crosswalk_digest=stack.crosswalk.digest,
            findings=(),
            reviews=(review, review),
            generated_at=FIXED_TIME,
        )
