from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.audit import (
    AuditControlStatus,
    AuditDisposition,
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    AuditSubject,
    default_wave9_policy_pack,
    evaluate_policy_pack,
    validate_evidence_manifest,
)

_HEAD_SHA = "abc123def456"
_GENERATED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _subject(scope: str | None = None) -> AuditSubject:
    return AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope=scope
        or (
            "change review pull_request merge audit for ci sandbox model repair "
            "dependency impact code_graph architecture_memory verified provenance"
        ),
        changed_paths=("src/ix_blackfox/audit/controls.py",),
    )


def _artifact(
    artifact_id: str,
    kind: AuditEvidenceKind,
    source_wave: AuditEvidenceSourceWave,
    path: str,
    digest_character: str,
    *,
    verified: bool = False,
    head_sha: str = _HEAD_SHA,
) -> AuditEvidenceArtifact:
    return AuditEvidenceArtifact(
        artifact_id=artifact_id,
        kind=kind,
        source_wave=source_wave,
        path=path,
        sha256=digest_character * 64,
        size_bytes=128,
        producer="unit-test",
        head_sha=head_sha,
        schema_version="unit.test.v1",
        verified=verified,
    )


def _complete_manifest(subject: AuditSubject | None = None) -> AuditEvidenceManifest:
    audit_subject = subject or _subject()
    return AuditEvidenceManifest(
        manifest_id="wave9:complete-manifest",
        subject=audit_subject,
        artifacts=(
            _artifact(
                "wave5:pr-pack",
                AuditEvidenceKind.PR_EVIDENCE_PACK,
                AuditEvidenceSourceWave.WAVE5,
                "evidence/wave5-pr-pack.json",
                "a",
            ),
            _artifact(
                "wave5:ci",
                AuditEvidenceKind.CI_EVIDENCE,
                AuditEvidenceSourceWave.WAVE5,
                "evidence/wave5-ci.json",
                "b",
            ),
            _artifact(
                "wave6:sandbox",
                AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
                AuditEvidenceSourceWave.WAVE6,
                ".blackfox-artifacts/wave6/report.json",
                "c",
            ),
            _artifact(
                "wave7:model-repair",
                AuditEvidenceKind.MODEL_REPAIR_REPORT,
                AuditEvidenceSourceWave.WAVE7,
                ".blackfox-artifacts/wave7/report.json",
                "d",
            ),
            _artifact(
                "wave8:repo-intelligence",
                AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
                AuditEvidenceSourceWave.WAVE8,
                ".blackfox-artifacts/wave8/report.json",
                "e",
            ),
            _artifact(
                "external:verified-attestation",
                AuditEvidenceKind.ATTESTATION,
                AuditEvidenceSourceWave.EXTERNAL,
                "attestations/verified-provenance.json",
                "f",
                verified=True,
                head_sha="",
            ),
        ),
        generated_at=_GENERATED_AT,
    )


def _human_signoff(subject: AuditSubject, policy_digest: str) -> AuditReviewerSignoff:
    return AuditReviewerSignoff(
        signoff_id="signoff:human-release-reviewer",
        reviewer_id="reviewer:human",
        reviewer_kind=AuditReviewerKind.HUMAN,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=subject.digest,
        policy_pack_digest=policy_digest,
        signed_at=_GENERATED_AT,
        role="release-reviewer",
        notes="Approved Wave 9 audit evidence for test subject.",
    )


def test_policy_pack_evaluation_can_reach_audit_ready_with_complete_evidence_and_human_signoff() -> None:
    policy_pack = default_wave9_policy_pack()
    subject = _subject()
    manifest = _complete_manifest(subject)
    evidence_validation = validate_evidence_manifest(manifest)
    signoff = _human_signoff(subject, policy_pack.digest)

    evaluation = evaluate_policy_pack(
        policy_pack,
        manifest,
        evidence_validation=evidence_validation,
        reviewer_signoffs=(signoff,),
        claims=(
            "ci green",
            "sandbox isolated workspace egress control",
            "model repair routing candidate evidence",
            "dependency impact code_graph architecture_memory",
            "verified provenance sigstore",
        ),
    )

    assert evidence_validation.is_valid is True
    assert evaluation.disposition is AuditDisposition.AUDIT_READY
    assert evaluation.blocked_count == 0
    assert evaluation.finding_by_control_id("BF-W9-011").status is AuditControlStatus.PASSED
    assert evaluation.finding_by_control_id("BF-W9-015").status is AuditControlStatus.PASSED


def test_policy_pack_evaluation_blocks_required_evidence_gap_for_applicable_scope() -> None:
    policy_pack = default_wave9_policy_pack()
    subject = _subject("change review pull_request merge audit with ci green claim")
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:missing-pr-evidence",
        subject=subject,
        artifacts=(
            _artifact(
                "wave5:ci",
                AuditEvidenceKind.CI_EVIDENCE,
                AuditEvidenceSourceWave.WAVE5,
                "evidence/wave5-ci.json",
                "a",
            ),
        ),
        generated_at=_GENERATED_AT,
    )
    signoff = _human_signoff(subject, policy_pack.digest)

    evaluation = evaluate_policy_pack(
        policy_pack,
        manifest,
        evidence_validation=validate_evidence_manifest(manifest),
        reviewer_signoffs=(signoff,),
        claims=("ci green",),
    )

    assert evaluation.disposition is AuditDisposition.BLOCKED
    assert evaluation.finding_by_control_id("BF-W9-004").status is AuditControlStatus.BLOCKED
    assert evaluation.finding_by_control_id("BF-W9-014").status is AuditControlStatus.BLOCKED


def test_policy_pack_evaluation_marks_untriggered_conditional_controls_not_applicable() -> None:
    policy_pack = default_wave9_policy_pack()
    subject = _subject("policy pack and non-claims diagnostic audit")
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:diagnostic-manifest",
        subject=subject,
        artifacts=(
            _artifact(
                "wave5:policy-decision",
                AuditEvidenceKind.POLICY_DECISION,
                AuditEvidenceSourceWave.WAVE5,
                "evidence/policy-decision.json",
                "a",
            ),
        ),
        generated_at=_GENERATED_AT,
    )
    signoff = _human_signoff(subject, policy_pack.digest)

    evaluation = evaluate_policy_pack(
        policy_pack,
        manifest,
        evidence_validation=validate_evidence_manifest(manifest),
        reviewer_signoffs=(signoff,),
        claims=("policy digest review",),
    )

    assert evaluation.finding_by_control_id("BF-W9-004").status is AuditControlStatus.NOT_APPLICABLE
    assert evaluation.finding_by_control_id("BF-W9-006").status is AuditControlStatus.NOT_APPLICABLE
    assert evaluation.finding_by_control_id("BF-W9-008").status is AuditControlStatus.NOT_APPLICABLE


def test_policy_pack_evaluation_blocks_verified_provenance_claim_without_verified_attestation() -> None:
    policy_pack = default_wave9_policy_pack()
    subject = _subject("verified provenance review")
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:unverified-attestation",
        subject=subject,
        artifacts=(
            _artifact(
                "external:unverified-attestation",
                AuditEvidenceKind.ATTESTATION,
                AuditEvidenceSourceWave.EXTERNAL,
                "attestations/unverified.json",
                "a",
                verified=False,
                head_sha="",
            ),
        ),
        generated_at=_GENERATED_AT,
    )
    signoff = _human_signoff(subject, policy_pack.digest)

    evaluation = evaluate_policy_pack(
        policy_pack,
        manifest,
        evidence_validation=validate_evidence_manifest(manifest),
        reviewer_signoffs=(signoff,),
        claims=("verified provenance sigstore",),
    )

    assert evaluation.disposition is AuditDisposition.BLOCKED
    assert evaluation.finding_by_control_id("BF-W9-010").status is AuditControlStatus.BLOCKED


def test_policy_pack_evaluation_warns_but_does_not_count_model_approval_as_human_authority() -> None:
    policy_pack = default_wave9_policy_pack()
    subject = _subject("policy pack review")
    manifest = AuditEvidenceManifest(
        manifest_id="wave9:model-approval-only",
        subject=subject,
        artifacts=(
            _artifact(
                "wave5:policy-decision",
                AuditEvidenceKind.POLICY_DECISION,
                AuditEvidenceSourceWave.WAVE5,
                "evidence/policy-decision.json",
                "a",
            ),
        ),
        generated_at=_GENERATED_AT,
    )
    model_signoff = AuditReviewerSignoff(
        signoff_id="signoff:model-approval",
        reviewer_id="reviewer:model",
        reviewer_kind=AuditReviewerKind.MODEL,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=subject.digest,
        policy_pack_digest=policy_pack.digest,
        signed_at=_GENERATED_AT,
        role="model-advisory-reviewer",
    )

    evaluation = evaluate_policy_pack(
        policy_pack,
        manifest,
        evidence_validation=validate_evidence_manifest(manifest),
        reviewer_signoffs=(model_signoff,),
        claims=("policy digest review",),
    )

    assert evaluation.disposition is AuditDisposition.BLOCKED
    assert evaluation.finding_by_control_id("BF-W9-011").status is AuditControlStatus.BLOCKED
    assert evaluation.finding_by_control_id("BF-W9-012").status is AuditControlStatus.WARNING
