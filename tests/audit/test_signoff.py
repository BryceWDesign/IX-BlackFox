from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.audit import (
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    AuditSubject,
    SignoffValidationIssueSeverity,
    authoritative_human_approvals,
    create_advisory_model_signoff,
    create_advisory_system_signoff,
    create_human_approval_signoff,
    default_wave9_policy_pack,
    non_authoritative_approval_ids,
    signoff_binding_digest,
    signoff_binding_payload,
    summarize_signoff_authority,
    validate_reviewer_signoffs,
)

_HEAD_SHA = "abc123def456"
_GENERATED_AT = datetime(2026, 1, 1, tzinfo=UTC)
_WRONG_DIGEST = "9" * 64


def _subject() -> AuditSubject:
    return AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope="Wave 9 signoff validation test",
    )


def test_create_human_approval_signoff_binds_subject_and_policy_pack_digest() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()

    signoff = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        role="release-reviewer",
        signed_at=_GENERATED_AT,
        notes="Approved for test.",
    )

    assert signoff.subject_digest == subject.digest
    assert signoff.policy_pack_digest == policy_pack.digest
    assert signoff.is_authoritative_human_approval is True
    assert signoff.metadata["binding"]["subject_digest"] == subject.digest


def test_validate_reviewer_signoffs_passes_with_bound_human_approval() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    signoff = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )

    result = validate_reviewer_signoffs(
        (signoff,),
        subject=subject,
        policy_pack=policy_pack,
    )

    assert result.is_valid is True
    assert result.has_authoritative_human_approval is True
    assert result.authoritative_human_approval_ids == ("signoff:human",)
    assert result.issue_count == 0


def test_validate_reviewer_signoffs_blocks_missing_human_approval() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()

    result = validate_reviewer_signoffs(
        (),
        subject=subject,
        policy_pack=policy_pack,
    )

    assert result.is_valid is False
    assert result.blocking_issue_count == 1
    assert result.issues[0].issue_id == "W9-SIGNOFF-MISSING-HUMAN-APPROVAL"
    assert result.issues[0].severity is SignoffValidationIssueSeverity.BLOCKING


def test_validate_reviewer_signoffs_blocks_digest_mismatches() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    wrong = AuditReviewerSignoff(
        signoff_id="signoff:wrong-digest",
        reviewer_id="reviewer:human",
        reviewer_kind=AuditReviewerKind.HUMAN,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=_WRONG_DIGEST,
        policy_pack_digest=_WRONG_DIGEST,
        signed_at=_GENERATED_AT,
        role="release-reviewer",
    )

    result = validate_reviewer_signoffs(
        (wrong,),
        subject=subject,
        policy_pack=policy_pack,
    )
    issue_ids = {issue.issue_id for issue in result.issues}

    assert result.is_valid is False
    assert "W9-SIGNOFF-SUBJECT-DIGEST-MISMATCH" in issue_ids
    assert "W9-SIGNOFF-POLICY-PACK-DIGEST-MISMATCH" in issue_ids
    assert "W9-SIGNOFF-MISSING-HUMAN-APPROVAL" in issue_ids


def test_model_and_system_signoffs_remain_advisory_only() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    model = create_advisory_model_signoff(
        signoff_id="signoff:model",
        reviewer_id="reviewer:model",
        subject=subject,
        policy_pack=policy_pack,
        decision=AuditReviewDecision.APPROVED,
        signed_at=_GENERATED_AT,
    )
    system = create_advisory_system_signoff(
        signoff_id="signoff:system",
        reviewer_id="reviewer:system",
        subject=subject,
        policy_pack=policy_pack,
        decision=AuditReviewDecision.COMMENTED,
        signed_at=_GENERATED_AT,
    )

    result = validate_reviewer_signoffs(
        (model, system),
        subject=subject,
        policy_pack=policy_pack,
    )

    assert result.is_valid is False
    assert result.advisory_signoff_ids == ("signoff:model", "signoff:system")
    assert non_authoritative_approval_ids((model, system)) == ("signoff:model",)
    assert any(
        issue.issue_id == "W9-SIGNOFF-NON-HUMAN-APPROVAL-IS-ADVISORY"
        for issue in result.issues
    )


def test_signoff_authority_summary_is_deterministic() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    human = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )
    model = create_advisory_model_signoff(
        signoff_id="signoff:model",
        reviewer_id="reviewer:model",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )

    first = summarize_signoff_authority((model, human), subject=subject, policy_pack=policy_pack)
    second = summarize_signoff_authority((human, model), subject=subject, policy_pack=policy_pack)

    assert first.to_dict() == second.to_dict()
    assert first.signoff_count == 2
    assert first.has_authoritative_human_approval is True
    assert first.authoritative_human_approval_ids == ("signoff:human",)
    assert first.advisory_signoff_ids == ("signoff:model",)


def test_authoritative_human_approvals_filters_unbound_or_nonhuman_records() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    human = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )
    wrong_subject = AuditReviewerSignoff(
        signoff_id="signoff:wrong-subject",
        reviewer_id="reviewer:human2",
        reviewer_kind=AuditReviewerKind.HUMAN,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=_WRONG_DIGEST,
        policy_pack_digest=policy_pack.digest,
        signed_at=_GENERATED_AT,
        role="release-reviewer",
    )
    model = create_advisory_model_signoff(
        signoff_id="signoff:model",
        reviewer_id="reviewer:model",
        subject=subject,
        policy_pack=policy_pack,
        decision=AuditReviewDecision.APPROVED,
        signed_at=_GENERATED_AT,
    )

    assert authoritative_human_approvals(
        (wrong_subject, model, human),
        subject=subject,
        policy_pack=policy_pack,
    ) == (human,)


def test_signoff_binding_payload_and_digest_are_stable() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()

    payload = signoff_binding_payload(subject, policy_pack)

    assert payload["subject_digest"] == subject.digest
    assert payload["policy_pack_digest"] == policy_pack.digest
    assert signoff_binding_digest(subject, policy_pack) == signoff_binding_digest(
        subject,
        policy_pack,
    )
