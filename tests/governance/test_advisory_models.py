from __future__ import annotations

import pytest

from ix_blackfox.governance import (
    PolicyAdvisoryAssessment,
    PolicyAdvisoryDisposition,
    PolicyAdvisoryNote,
)


def test_policy_advisory_note_create_normalizes_values() -> None:
    note = PolicyAdvisoryNote.create(
        code=" Sensitive Boundary Review ",
        summary="  Boundary sensitivity requires a human look.  ",
        policy_tags=(" review ", "review", "sensitive-boundary "),
        confidence=0.82,
        metadata={"source": "policy-brain"},
    )

    assert note.note_id.startswith("policy-note-")
    assert note.code == "sensitive-boundary-review"
    assert note.summary == "Boundary sensitivity requires a human look."
    assert note.policy_tags == ("review", "sensitive-boundary")
    assert note.confidence == 0.82
    assert note.metadata == {"source": "policy-brain"}


def test_policy_advisory_assessment_exposes_note_codes_and_tags() -> None:
    note = PolicyAdvisoryNote.create(
        code="sensitive-boundary-review",
        summary="Boundary sensitivity requires a human look.",
        policy_tags=("review", "sensitive-boundary"),
        confidence=0.82,
    )
    assessment = PolicyAdvisoryAssessment.create(
        brain_name=" GPT OSS Policy 20B ",
        invocation_id=" policy call 123 ",
        advisory_disposition=PolicyAdvisoryDisposition.REVIEW,
        rationale="This request crosses a sensitive boundary and needs review.",
        notes=(note,),
        metadata={"lane": "policy-advisory"},
    )

    assert assessment.brain_name == "gpt-oss-policy-20b"
    assert assessment.invocation_id == "policy-call-123"
    assert assessment.advisory_disposition is PolicyAdvisoryDisposition.REVIEW
    assert assessment.rationale == "This request crosses a sensitive boundary and needs review."
    assert assessment.note_codes() == ("sensitive-boundary-review",)
    assert assessment.policy_tags() == ("review", "sensitive-boundary")
    assert assessment.metadata == {"lane": "policy-advisory"}


def test_policy_advisory_allow_can_exist_without_notes() -> None:
    assessment = PolicyAdvisoryAssessment.create(
        brain_name="gpt-oss-policy-20b",
        invocation_id="policy-call-allow",
        advisory_disposition=PolicyAdvisoryDisposition.ALLOW,
        rationale="No additional policy concerns were detected.",
        notes=(),
    )

    assert assessment.advisory_disposition is PolicyAdvisoryDisposition.ALLOW
    assert assessment.note_codes() == ()
    assert assessment.policy_tags() == ()


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: PolicyAdvisoryNote.create(
                code="bad-confidence",
                summary="Invalid confidence.",
                confidence=1.5,
            ),
            "confidence must be between 0.0 and 1.0",
        ),
        (
            lambda: PolicyAdvisoryAssessment.create(
                brain_name="gpt-oss-policy-20b",
                invocation_id="policy-call-456",
                advisory_disposition=PolicyAdvisoryDisposition.BLOCK,
                rationale="Blocking rationale.",
                notes=(),
            ),
            "without notes must use advisory_disposition=ALLOW",
        ),
    ],
)
def test_invalid_policy_advisory_values_raise(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
