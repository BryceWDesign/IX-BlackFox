from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.audit import (
    AuditDisposition,
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditSubject,
    create_human_approval_signoff,
    default_wave9_policy_pack,
    validate_evidence_manifest,
)
from ix_blackfox.audit.report import (
    Wave9GovernanceReport,
    build_governance_report,
    default_governance_report_run_id,
    load_governance_report_payload,
    validate_governance_report_payload_shape,
    write_governance_report,
)

_HEAD_SHA = "abc123def456"
_GENERATED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _subject(scope: str | None = None) -> AuditSubject:
    return AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope=scope or "policy digest diagnostic audit",
        changed_paths=("src/ix_blackfox/audit/report.py",),
    )


def _artifact(artifact_id: str, kind: AuditEvidenceKind, digest_character: str) -> AuditEvidenceArtifact:
    return AuditEvidenceArtifact(
        artifact_id=artifact_id,
        kind=kind,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        path=f"evidence/{artifact_id.replace(':', '-')}.json",
        sha256=digest_character * 64,
        size_bytes=128,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )


def _manifest(subject: AuditSubject) -> AuditEvidenceManifest:
    return AuditEvidenceManifest(
        manifest_id="wave9:governance-report-manifest",
        subject=subject,
        artifacts=(
            _artifact("wave5:policy-decision", AuditEvidenceKind.POLICY_DECISION, "a"),
        ),
        generated_at=_GENERATED_AT,
    )


def test_build_governance_report_is_blocked_without_required_human_approval() -> None:
    subject = _subject()
    manifest = _manifest(subject)

    report = build_governance_report(
        subject,
        manifest,
        generated_at=_GENERATED_AT,
        claims=("policy digest review",),
    )

    assert report.disposition is AuditDisposition.BLOCKED
    assert report.signoff_validation.has_authoritative_human_approval is False
    assert report.signoff_validation.blocking_issue_count == 1
    assert report.to_dict()["report_digest"] == report.report_digest


def test_build_governance_report_can_reach_audit_ready_for_diagnostic_scope_with_human_approval() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    manifest = _manifest(subject)
    signoff = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )

    report = build_governance_report(
        subject,
        manifest,
        generated_at=_GENERATED_AT,
        policy_pack=policy_pack,
        reviewer_signoffs=(signoff,),
        claims=("policy digest review",),
    )

    assert report.disposition is AuditDisposition.AUDIT_READY
    assert report.control_evaluation.disposition is AuditDisposition.AUDIT_READY
    assert report.signoff_authority.has_authoritative_human_approval is True
    assert report.attestation_subject_digest == report.attestation_subject_digest
    assert report.report_digest == report.report_digest


def test_governance_report_run_id_is_deterministic_and_claim_sensitive() -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    manifest = _manifest(subject)

    first = default_governance_report_run_id(
        subject,
        policy_pack,
        manifest,
        claims=("policy digest review",),
    )
    second = default_governance_report_run_id(
        subject,
        policy_pack,
        manifest,
        claims=("policy digest review",),
    )
    different = default_governance_report_run_id(
        subject,
        policy_pack,
        manifest,
        claims=("different claim",),
    )

    assert first == second
    assert first != different
    assert first.startswith("wave9:")


def test_write_load_and_shape_validate_governance_report(tmp_path) -> None:
    subject = _subject()
    policy_pack = default_wave9_policy_pack()
    manifest = _manifest(subject)
    signoff = create_human_approval_signoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        signed_at=_GENERATED_AT,
    )
    report = build_governance_report(
        subject,
        manifest,
        generated_at=_GENERATED_AT,
        policy_pack=policy_pack,
        reviewer_signoffs=(signoff,),
        claims=("policy digest review",),
    )
    report_path = tmp_path / "wave9-report.json"

    written = write_governance_report(report, report_path)
    loaded = load_governance_report_payload(written)

    assert written == report_path
    assert loaded["report_digest"] == report.report_digest
    assert validate_governance_report_payload_shape(loaded) == ()


def test_shape_validation_rejects_wrong_schema_wave_and_missing_digest() -> None:
    subject = _subject()
    manifest = _manifest(subject)
    report = build_governance_report(
        subject,
        manifest,
        generated_at=_GENERATED_AT,
        claims=("policy digest review",),
        require_human_approval=False,
    )
    payload = report.to_dict()
    payload["schema_version"] = "wrong.schema"
    payload["wave"] = 8
    payload.pop("report_digest")

    issues = validate_governance_report_payload_shape(payload)

    assert any("missing required keys" in issue for issue in issues)
    assert any("schema_version" in issue for issue in issues)
    assert any("wave must be 9" in issue for issue in issues)


def test_governance_report_rejects_mismatched_subject_and_manifest_link() -> None:
    subject = _subject()
    other_subject = AuditSubject(
        repository="IX-BlackFox",
        head_sha="other-head-sha",
        scope="different subject",
    )
    manifest = _manifest(other_subject)
    policy_pack = default_wave9_policy_pack()
    evidence_validation = validate_evidence_manifest(manifest)
    report = build_governance_report(
        other_subject,
        manifest,
        generated_at=_GENERATED_AT,
        policy_pack=policy_pack,
        claims=("policy digest review",),
        require_human_approval=False,
        evidence_validation=evidence_validation,
    )

    with pytest.raises(ValueError, match="evidence_manifest subject digest"):
        Wave9GovernanceReport(
            run_id="wave9:bad-link",
            subject=subject,
            policy_pack=policy_pack,
            evidence_manifest=manifest,
            evidence_validation=evidence_validation,
            control_evaluation=report.control_evaluation,
            signoff_validation=report.signoff_validation,
            signoff_authority=report.signoff_authority,
            generated_at=_GENERATED_AT,
            disposition=report.disposition,
        )
