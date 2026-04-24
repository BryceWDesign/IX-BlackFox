from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    SafeguardAssessment,
    SafeguardDisposition,
    SafeguardEvidenceKind,
    SafeguardEvidenceRef,
    SafeguardFinding,
    SafeguardFindingSeverity,
)


def test_safeguard_evidence_ref_normalizes_fields() -> None:
    evidence = SafeguardEvidenceRef(
        kind=SafeguardEvidenceKind.TEXT_SPAN,
        value="  delete workspace  ",
        locator=" src\\ix_blackfox\\runtime\\orchestrator.py ",
        excerpt="  rm -rf /workspace  ",
        metadata={"line": 42},
    )

    assert evidence.kind is SafeguardEvidenceKind.TEXT_SPAN
    assert evidence.value == "delete workspace"
    assert evidence.locator == "src/ix_blackfox/runtime/orchestrator.py"
    assert evidence.excerpt == "rm -rf /workspace"
    assert evidence.metadata == {"line": 42}


def test_safeguard_finding_create_normalizes_policy_tags_and_scores() -> None:
    finding = SafeguardFinding.create(
        code=" Destructive Workspace Mutation ",
        severity=SafeguardFindingSeverity.HIGH,
        summary="  Request appears to destroy repository state.  ",
        policy_tags=(" destructive ", "destructive", "repo-state "),
        evidence=(
            SafeguardEvidenceRef(
                kind=SafeguardEvidenceKind.TEXT_SPAN,
                value="rm -rf",
            ),
            SafeguardEvidenceRef(
                kind=SafeguardEvidenceKind.POLICY_TAG,
                value="destructive",
            ),
        ),
        confidence=0.92,
        uncertainty=0.11,
        metadata={"source": "safeguard-model"},
    )

    assert finding.finding_id.startswith("safeguard-finding-")
    assert finding.code == "destructive-workspace-mutation"
    assert finding.summary == "Request appears to destroy repository state."
    assert finding.policy_tags == ("destructive", "repo-state")
    assert len(finding.evidence) == 2
    assert finding.confidence == 0.92
    assert finding.uncertainty == 0.11
    assert finding.requires_review is True
    assert finding.recommends_block is True
    assert finding.metadata == {"source": "safeguard-model"}


def test_safeguard_assessment_infers_disposition_from_findings() -> None:
    review_finding = SafeguardFinding.create(
        code="network-egress-uncertainty",
        severity=SafeguardFindingSeverity.MODERATE,
        summary="Possible network egress intent detected.",
        policy_tags=("network", "review"),
    )
    block_finding = SafeguardFinding.create(
        code="destructive-action",
        severity=SafeguardFindingSeverity.CRITICAL,
        summary="Explicit destructive action requested.",
        policy_tags=("destructive", "block"),
    )

    review_assessment = SafeguardAssessment.from_findings(
        brain_name=" gpt oss safeguard 20b ",
        invocation_id=" brain call 123 ",
        findings=(review_finding,),
        metadata={"lane": "semantic-safety"},
    )
    block_assessment = SafeguardAssessment.from_findings(
        brain_name="gpt-oss-safeguard-20b",
        invocation_id="brain-call-456",
        findings=(review_finding, block_finding),
    )

    assert review_assessment.brain_name == "gpt-oss-safeguard-20b"
    assert review_assessment.invocation_id == "brain-call-123"
    assert review_assessment.advisory_disposition is SafeguardDisposition.REVIEW
    assert review_assessment.highest_severity is SafeguardFindingSeverity.MODERATE
    assert review_assessment.finding_codes() == ("network-egress-uncertainty",)
    assert review_assessment.policy_tags() == ("network", "review")
    assert review_assessment.metadata == {"lane": "semantic-safety"}

    assert block_assessment.advisory_disposition is SafeguardDisposition.BLOCK
    assert block_assessment.highest_severity is SafeguardFindingSeverity.CRITICAL
    assert block_assessment.finding_codes() == (
        "network-egress-uncertainty",
        "destructive-action",
    )
    assert block_assessment.policy_tags() == (
        "network",
        "review",
        "destructive",
        "block",
    )


def test_safeguard_assessment_without_findings_defaults_to_allow() -> None:
    assessment = SafeguardAssessment.from_findings(
        brain_name="gpt-oss-safeguard-20b",
        invocation_id="brain-call-789",
        findings=(),
    )

    assert assessment.advisory_disposition is SafeguardDisposition.ALLOW
    assert assessment.highest_severity is None
    assert assessment.finding_codes() == ()
    assert assessment.policy_tags() == ()


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: SafeguardFinding.create(
                code="bad-confidence",
                severity=SafeguardFindingSeverity.LOW,
                summary="Invalid confidence.",
                confidence=1.5,
            ),
            "confidence must be between 0.0 and 1.0",
        ),
        (
            lambda: SafeguardFinding.create(
                code="bad-uncertainty",
                severity=SafeguardFindingSeverity.LOW,
                summary="Invalid uncertainty.",
                uncertainty=-0.1,
            ),
            "uncertainty must be between 0.0 and 1.0",
        ),
        (
            lambda: SafeguardAssessment(
                brain_name="gpt-oss-safeguard-20b",
                invocation_id="brain-call-123",
                advisory_disposition=SafeguardDisposition.BLOCK,
                findings=(),
            ),
            "without findings must use advisory_disposition=ALLOW",
        ),
    ],
)
def test_invalid_safeguard_values_raise(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
