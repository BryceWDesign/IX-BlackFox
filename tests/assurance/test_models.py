from __future__ import annotations

import pytest

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.models import (
    AssuranceClaimSet,
    AssuranceControl,
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    AssuranceManifest,
    AssuranceProfile,
    AssuranceSubject,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
    default_wave12_claims,
    digest_payload,
    normalize_timestamp,
)
from ix_blackfox.assurance.profiles import default_wave12_assurance_profile
from tests.assurance.helpers import FIXED_TIME, REVISION, build_stack


def test_subject_normalizes_and_has_stable_digest() -> None:
    subject = AssuranceSubject(
        repository="  IX-BlackFox  ",
        revision=f"  {REVISION}  ",
        scope="  bounded   scope ",
        producer_agent_id=" Package Builder ",
        generated_at="2026-08-23T12:00:00Z",
    )
    assert subject.repository == "IX-BlackFox"
    assert subject.scope == "bounded scope"
    assert subject.producer_agent_id == "package-builder"
    assert subject.generated_at == FIXED_TIME
    assert subject.digest == digest_payload(subject.to_dict(include_digest=False))


@pytest.mark.parametrize(
    "value",
    ["", "2026-08-23", "not-a-timestamp"],
)
def test_timestamp_rejects_empty_naive_and_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_timestamp(value, label="generated_at")


def test_evidence_descriptor_requires_evidence_namespace() -> None:
    with pytest.raises(ValueError, match="beneath evidence"):
        _artifact(path="reports/result.json")


def test_evidence_descriptor_rejects_negative_size() -> None:
    with pytest.raises(ValueError, match="negative"):
        _artifact(size_bytes=-1)


def test_verification_state_order_is_explicit() -> None:
    assert EvidenceVerificationState.RECORDED.rank == 0
    assert EvidenceVerificationState.INTEGRITY_VERIFIED.satisfies(
        EvidenceVerificationState.RECORDED
    )
    assert not EvidenceVerificationState.RECORDED.satisfies(
        EvidenceVerificationState.INTEGRITY_VERIFIED
    )
    assert EvidenceVerificationState.EXTERNALLY_VERIFIED.satisfies(
        EvidenceVerificationState.INTEGRITY_VERIFIED
    )


def test_control_requires_evidence_kinds() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        _control(evidence_kinds=())


def test_control_requires_https_reference() -> None:
    with pytest.raises(ValueError, match="https"):
        _control(reference_uri="http://example.test/control")


def test_profile_rejects_duplicate_control_ids() -> None:
    control = _control()
    with pytest.raises(ValueError, match="unique"):
        AssuranceProfile(
            profile_id="profile",
            version="1",
            title="Profile",
            controls=(control, control),
            description="Profile description",
            claim_boundary="Evidence mapping only",
        )


def test_default_claims_are_bounded_without_false_hits() -> None:
    claims = default_wave12_claims()
    assert claims.prohibited_hits == ()
    assert any("does not grant certification" in item for item in claims.non_claims)


def test_claim_scan_checks_assertions_not_explicit_non_claims() -> None:
    claims = AssuranceClaimSet(
        asserted_claims=("This package is certified for production.",),
        non_claims=("This does not claim certification.",),
    )
    assert claims.prohibited_hits == ("certified",)


def test_claim_policy_cannot_remove_default_prohibited_terms() -> None:
    claims = AssuranceClaimSet(
        asserted_claims=("Certification granted for IX-BlackFox.",),
        non_claims=("No deployment approval is implied.",),
        prohibited_asserted_terms=("custom forbidden phrase",),
    )
    assert "certification" in claims.prohibited_asserted_terms
    assert "custom forbidden phrase" in claims.prohibited_asserted_terms
    assert claims.prohibited_hits == ("certification",)


def test_verified_review_requires_verification_artifact() -> None:
    with pytest.raises(ValueError, match="verification_artifact_ids"):
        _review(verification_artifact_ids=())


def test_recorded_review_can_remain_advisory_without_artifact() -> None:
    review = _review(
        authentication_state=ReviewAuthenticationState.RECORDED,
        decision=AuthorityReviewDecision.ADVISORY_ONLY,
        verification_artifact_ids=(),
    )
    assert not review.authoritative_human_approval


@pytest.mark.parametrize(
    "kind",
    [
        AgentKind.MODEL_BRAIN,
        AgentKind.TOOL,
        AgentKind.CI_RUNNER,
        AgentKind.SYSTEM_SERVICE,
    ],
)
def test_non_human_review_is_never_authoritative(kind: AgentKind) -> None:
    review = _review(reviewer_kind=kind)
    assert not review.authoritative_human_approval


def test_verified_human_review_is_authoritative_for_external_assessment_only() -> None:
    review = _review()
    assert review.authoritative_human_approval
    assert review.to_dict()["decision"] == "approve_for_external_assessment"


def test_manifest_sorts_evidence_and_exposes_digest(tmp_path) -> None:
    stack = build_stack(tmp_path)
    ids = [item.artifact_id for item in stack.manifest.evidence]
    assert ids == sorted(ids)
    assert stack.manifest.to_dict()["manifest_digest"] == stack.manifest.digest


def test_manifest_rejects_duplicate_artifact_ids(tmp_path) -> None:
    stack = build_stack(tmp_path)
    artifact = stack.manifest.evidence[0]
    with pytest.raises(ValueError, match="artifact_id"):
        AssuranceManifest(
            manifest_id="duplicate-id",
            subject=stack.manifest.subject,
            profile=stack.manifest.profile,
            evidence=(artifact, artifact),
            claims=stack.manifest.claims,
        )


def test_manifest_rejects_duplicate_paths(tmp_path) -> None:
    stack = build_stack(tmp_path)
    first = stack.manifest.evidence[0]
    second = AssuranceEvidenceArtifact(
        artifact_id="different-id",
        source_wave=first.source_wave,
        evidence_kind=first.evidence_kind,
        path=first.path,
        sha256=first.sha256,
        size_bytes=first.size_bytes,
        media_type=first.media_type,
        producer=first.producer,
        verification_state=first.verification_state,
    )
    with pytest.raises(ValueError, match="paths"):
        AssuranceManifest(
            manifest_id="duplicate-path",
            subject=stack.manifest.subject,
            profile=stack.manifest.profile,
            evidence=(first, second),
            claims=stack.manifest.claims,
        )


def test_default_profile_is_versioned_and_mapping_bounded() -> None:
    profile = default_wave12_assurance_profile()
    assert profile.profile_id == "ix-blackfox-wave12-core"
    assert profile.version == "1.0.0"
    assert len(profile.controls) == 9
    assert profile.metadata["external_framework_entries_are_mappings_only"] is True
    assert len(profile.digest) == 64


def _artifact(
    *,
    path: str = "evidence/result.json",
    size_bytes: int = 2,
) -> AssuranceEvidenceArtifact:
    return AssuranceEvidenceArtifact(
        artifact_id="artifact",
        source_wave=AssuranceEvidenceSource.WAVE12,
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        path=path,
        sha256="a" * 64,
        size_bytes=size_bytes,
        media_type="application/json",
        producer="test",
        verification_state=EvidenceVerificationState.INTEGRITY_VERIFIED,
    )


def _control(
    *,
    evidence_kinds: tuple[AssuranceEvidenceKind, ...] = (
        AssuranceEvidenceKind.TEST_RESULT,
    ),
    reference_uri: str = "https://example.test/control",
) -> AssuranceControl:
    return AssuranceControl(
        control_id="control",
        framework="Test framework",
        reference_id="T-1",
        title="Test control",
        evidence_kinds=evidence_kinds,
        statement="Require test evidence.",
        reference_uri=reference_uri,
    )


def _review(
    *,
    reviewer_kind: AgentKind = AgentKind.HUMAN_OPERATOR,
    decision: AuthorityReviewDecision = (
        AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
    ),
    authentication_state: ReviewAuthenticationState = (
        ReviewAuthenticationState.VERIFIED
    ),
    verification_artifact_ids: tuple[str, ...] = ("human-review",),
) -> AuthorityReview:
    return AuthorityReview(
        review_id="review",
        reviewer_agent_id="reviewer",
        reviewer_kind=reviewer_kind,
        decision=decision,
        subject_digest="a" * 64,
        profile_digest="b" * 64,
        reviewed_at=FIXED_TIME,
        authentication_state=authentication_state,
        verification_artifact_ids=verification_artifact_ids,
    )
