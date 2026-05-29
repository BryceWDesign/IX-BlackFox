from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.audit import (
    WAVE9_ATTESTATION_SUBJECT_SCHEMA_VERSION,
    AuditControlFinding,
    AuditControlSeverity,
    AuditControlStatus,
    AuditDisposition,
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditNonClaimSet,
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    AuditStandardsMapping,
    AuditStandardsMappingKind,
    AuditSubject,
    derive_audit_disposition,
    digest_payload,
    normalize_relative_path,
)

_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_HEAD_SHA = "abc123def456"


def test_digest_payload_is_deterministic_for_mapping_order() -> None:
    left = {"b": [2, 1], "a": {"z": True, "x": "value"}}
    right = {"a": {"x": "value", "z": True}, "b": [2, 1]}

    assert digest_payload(left) == digest_payload(right)
    assert len(digest_payload(left)) == 64


def test_audit_subject_digest_is_stable_and_includes_schema_version() -> None:
    subject = AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope="Wave 9 audit scope",
        changed_paths=("src/ix_blackfox/audit/models.py", "tests/audit/test_models.py"),
        metadata={"purpose": "unit-test"},
    )

    payload = subject.to_dict()

    assert payload["schema_version"] == WAVE9_ATTESTATION_SUBJECT_SCHEMA_VERSION
    assert payload["digest"] == subject.digest
    assert subject.digest == AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope="Wave 9 audit scope",
        changed_paths=("tests/audit/test_models.py", "src/ix_blackfox/audit/models.py"),
        metadata={"purpose": "unit-test"},
    ).digest


def test_normalize_relative_path_rejects_unsafe_paths() -> None:
    assert normalize_relative_path(r"docs\\wave9.md") == "docs/wave9.md"

    for path in (
        "/tmp/evidence.json",
        "../evidence.json",
        "docs/../evidence.json",
        "C:/tmp/evidence.json",
    ):
        with pytest.raises(ValueError):
            normalize_relative_path(path)


def test_evidence_artifact_requires_inspectable_metadata() -> None:
    artifact = AuditEvidenceArtifact(
        artifact_id="wave8:repo-intelligence",
        kind=AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE8,
        path=".blackfox-artifacts/wave8/report.json",
        sha256=_SHA256_A,
        size_bytes=42,
        producer="unit-test",
        head_sha=_HEAD_SHA,
        schema_version="wave8.repository_intelligence_ci_report.v1",
        verified=True,
    )

    assert artifact.to_dict()["sha256"] == _SHA256_A
    assert artifact.to_dict()["verified"] is True

    with pytest.raises(ValueError):
        AuditEvidenceArtifact(
            artifact_id="bad:empty",
            kind=AuditEvidenceKind.CI_EVIDENCE,
            source_wave=AuditEvidenceSourceWave.WAVE5,
            path="evidence.json",
            sha256=_SHA256_A,
            size_bytes=0,
            producer="unit-test",
        )

    with pytest.raises(ValueError):
        AuditEvidenceArtifact(
            artifact_id="bad:digest",
            kind=AuditEvidenceKind.CI_EVIDENCE,
            source_wave=AuditEvidenceSourceWave.WAVE5,
            path="evidence.json",
            sha256="not-a-digest",
            size_bytes=1,
            producer="unit-test",
        )


def test_evidence_manifest_sorts_artifacts_and_has_stable_digest() -> None:
    subject = AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope="Wave 9 audit scope",
    )
    artifact_b = AuditEvidenceArtifact(
        artifact_id="wave8:b",
        kind=AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT,
        source_wave=AuditEvidenceSourceWave.WAVE8,
        path=".blackfox-artifacts/wave8/b.json",
        sha256=_SHA256_B,
        size_bytes=2,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )
    artifact_a = AuditEvidenceArtifact(
        artifact_id="wave8:a",
        kind=AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE8,
        path=".blackfox-artifacts/wave8/a.json",
        sha256=_SHA256_A,
        size_bytes=1,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )
    generated_at = datetime(2026, 1, 1, tzinfo=UTC)

    manifest = AuditEvidenceManifest(
        manifest_id="wave9:test-manifest",
        subject=subject,
        artifacts=(artifact_b, artifact_a),
        generated_at=generated_at,
    )
    manifest_same = AuditEvidenceManifest(
        manifest_id="wave9:test-manifest",
        subject=subject,
        artifacts=(artifact_a, artifact_b),
        generated_at=generated_at,
    )

    assert [artifact.artifact_id for artifact in manifest.artifacts] == ["wave8:a", "wave8:b"]
    assert manifest.artifact_count == 2
    assert manifest.digest == manifest_same.digest
    assert manifest.artifact_by_id("wave8:a") == artifact_a
    assert manifest.artifacts_by_kind(AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT) == (
        artifact_b,
    )


def test_evidence_manifest_rejects_duplicate_artifact_ids() -> None:
    subject = AuditSubject(repository="IX-BlackFox", head_sha=_HEAD_SHA, scope="Wave 9 audit scope")
    artifact = AuditEvidenceArtifact(
        artifact_id="duplicate",
        kind=AuditEvidenceKind.CI_EVIDENCE,
        source_wave=AuditEvidenceSourceWave.WAVE5,
        path="evidence/ci.json",
        sha256=_SHA256_A,
        size_bytes=1,
        producer="unit-test",
        head_sha=_HEAD_SHA,
    )

    with pytest.raises(ValueError):
        AuditEvidenceManifest(
            manifest_id="wave9:test-manifest",
            subject=subject,
            artifacts=(artifact, artifact),
        )


def test_control_findings_drive_fail_closed_disposition() -> None:
    passed = AuditControlFinding(
        control_id="BF-W9-001",
        status=AuditControlStatus.PASSED,
        severity=AuditControlSeverity.BLOCKING,
        summary="passed",
    )
    warning = AuditControlFinding(
        control_id="BF-W9-002",
        status=AuditControlStatus.WARNING,
        severity=AuditControlSeverity.WARNING,
        summary="warning",
    )
    blocking_warning = AuditControlFinding(
        control_id="BF-W9-003",
        status=AuditControlStatus.WARNING,
        severity=AuditControlSeverity.BLOCKING,
        summary="blocking warning",
    )
    blocked = AuditControlFinding(
        control_id="BF-W9-004",
        status=AuditControlStatus.BLOCKED,
        severity=AuditControlSeverity.WARNING,
        summary="blocked",
    )

    assert derive_audit_disposition((passed,)) is AuditDisposition.AUDIT_READY
    assert derive_audit_disposition((passed, warning)) is AuditDisposition.WARNING
    assert derive_audit_disposition((passed, blocking_warning)) is AuditDisposition.BLOCKED
    assert derive_audit_disposition((passed, blocked)) is AuditDisposition.BLOCKED


def test_reviewer_signoff_authority_is_human_approval_only() -> None:
    human = AuditReviewerSignoff(
        signoff_id="signoff:human",
        reviewer_id="reviewer:human",
        reviewer_kind=AuditReviewerKind.HUMAN,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=_SHA256_A,
        policy_pack_digest=_SHA256_B,
        signed_at=datetime(2026, 1, 1, tzinfo=UTC),
        role="release-reviewer",
    )
    model = AuditReviewerSignoff(
        signoff_id="signoff:model",
        reviewer_id="reviewer:model",
        reviewer_kind=AuditReviewerKind.MODEL,
        decision=AuditReviewDecision.APPROVED,
        subject_digest=_SHA256_A,
        policy_pack_digest=_SHA256_B,
        signed_at=datetime(2026, 1, 1, tzinfo=UTC),
        role="model-reviewer",
    )

    assert human.is_authoritative_human_approval is True
    assert model.is_authoritative_human_approval is False


def test_non_claim_set_rejects_duplicate_claims() -> None:
    with pytest.raises(ValueError):
        AuditNonClaimSet(items=("no production readiness", "no production readiness"))


def test_standards_mapping_preserves_alignment_only_claim() -> None:
    mapping = AuditStandardsMapping(
        kind=AuditStandardsMappingKind.NIST_SSDF,
        reference_id="NIST-SSDF-MAPPING-ONLY",
        summary="Mapping note only.",
    )

    assert mapping.to_dict()["claim"] == "alignment_reference_only"
