from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ix_blackfox.audit import (
    WAVE6_CI_REPORT_PATH,
    WAVE7_CI_REPORT_PATH,
    WAVE8_CI_REPORT_PATH,
    WAVE8_EVIDENCE_SNAPSHOT_PATH,
    AuditEvidenceKind,
    AuditEvidenceSourceWave,
    AuditReviewDecision,
    AuditReviewerKind,
    artifact_is_verified_by_attestation,
    bridge_pr_evidence_pack_artifacts,
    bridge_pr_evidence_pack_file,
    bridge_wave5_approval_to_signoff,
    bridge_wave5_approvals_to_signoffs,
    bridge_wave5_evidence_artifact,
    collect_known_wave_evidence,
    default_known_wave_evidence_paths,
    map_wave5_artifact_kind,
    map_wave5_review_decision,
    map_wave5_reviewer_kind,
    relative_path_from_wave5_uri,
    sha256_file,
)
from ix_blackfox.workflow.pr_evidence_pack import (
    ArtifactAttestation,
    ArtifactAttestationKind,
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
)

_HEAD_SHA = "abc123def456"
_SUBJECT_DIGEST = "a" * 64
_POLICY_DIGEST = "b" * 64
_ARTIFACT_SHA = "c" * 64
_ATTESTATION_SHA = "d" * 64
_SUBJECT_SHA = "e" * 64


def _write_json(path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _pr_identity() -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="123",
        base_ref="main",
        head_ref="wave9/audit",
        head_sha=_HEAD_SHA,
        author="Bryce Lovell",
    )


def _approval(
    *,
    approval_id: str = "approval:human",
    reviewer_kind: ReviewerKind = ReviewerKind.HUMAN,
    decision: ReviewDecision = ReviewDecision.APPROVED,
) -> PullRequestApproval:
    return PullRequestApproval(
        approval_id=approval_id,
        reviewer_id="reviewer:human" if reviewer_kind is ReviewerKind.HUMAN else "reviewer:system",
        reviewer_kind=reviewer_kind,
        decision=decision,
        decided_at=datetime(2026, 1, 1, tzinfo=UTC),
        note="Reviewed Wave 9 evidence.",
        evidence_refs=("artifact:ci",),
        roles=("release-reviewer",),
    )


def _verified_attestation() -> ArtifactAttestation:
    return ArtifactAttestation(
        attestation_id="attestation:ci",
        kind=ArtifactAttestationKind.LOCAL_MANIFEST,
        uri="attestations/ci.json",
        produced_by="unit-test",
        predicate_type="local-test-attestation",
        sha256=_ATTESTATION_SHA,
        size_bytes=64,
        head_sha=_HEAD_SHA,
        subject_sha256=_SUBJECT_SHA,
        verified=True,
    )


def _wave5_artifact(
    *,
    artifact_id: str = "artifact:ci",
    kind: EvidenceArtifactKind = EvidenceArtifactKind.CI_SUMMARY,
    uri: str = "evidence/ci.json",
    sha256: str | None = _ARTIFACT_SHA,
    size_bytes: int | None = 128,
    head_sha: str | None = _HEAD_SHA,
    attestations: tuple[ArtifactAttestation, ...] = (),
) -> EvidenceArtifact:
    return EvidenceArtifact(
        artifact_id=artifact_id,
        kind=kind,
        uri=uri,
        produced_by="unit-test",
        sha256=sha256,
        size_bytes=size_bytes,
        head_sha=head_sha,
        attestations=attestations,
        metadata={"source": "unit-test"},
    )


def _pr_pack() -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="pack:wave5",
        pull_request=_pr_identity(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        summary="Wave 5 PR evidence pack for Wave 9 bridge tests.",
        changed_files=("src/ix_blackfox/audit/evidence_bridges.py",),
        requested_checks=("pytest",),
        artifacts=(_wave5_artifact(attestations=(_verified_attestation(),)),),
        approvals=(_approval(),),
        metadata={"purpose": "unit-test"},
    )


def test_default_known_wave_evidence_paths_are_stable_and_unique() -> None:
    known_paths = default_known_wave_evidence_paths()

    assert [path.relative_path for path in known_paths] == [
        WAVE6_CI_REPORT_PATH,
        WAVE7_CI_REPORT_PATH,
        WAVE8_CI_REPORT_PATH,
        WAVE8_EVIDENCE_SNAPSHOT_PATH,
    ]
    assert len({path.artifact_id for path in known_paths}) == len(known_paths)
    assert {path.source_wave for path in known_paths} == {
        AuditEvidenceSourceWave.WAVE6,
        AuditEvidenceSourceWave.WAVE7,
        AuditEvidenceSourceWave.WAVE8,
    }


def test_collect_known_wave_evidence_skips_missing_paths_by_default(tmp_path) -> None:
    assert collect_known_wave_evidence(tmp_path, head_sha=_HEAD_SHA) == ()


def test_collect_known_wave_evidence_can_require_existing_paths(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_known_wave_evidence(tmp_path, head_sha=_HEAD_SHA, require_existing=True)


def test_collect_known_wave_evidence_inspects_existing_generated_reports(tmp_path) -> None:
    wave7_path = tmp_path / WAVE7_CI_REPORT_PATH
    _write_json(
        wave7_path,
        {
            "schema_version": "wave7.model_repair_ci_report.v1",
            "head_sha": _HEAD_SHA,
            "passed": True,
            "run_id": "wave7:test",
        },
    )

    artifacts = collect_known_wave_evidence(tmp_path, head_sha="fallback-head-sha")

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.artifact_id == "wave7:model-repair-ci-report"
    assert artifact.kind is AuditEvidenceKind.MODEL_REPAIR_REPORT
    assert artifact.source_wave is AuditEvidenceSourceWave.WAVE7
    assert artifact.head_sha == _HEAD_SHA
    assert artifact.schema_version == "wave7.model_repair_ci_report.v1"
    assert artifact.sha256 == sha256_file(wave7_path)
    assert artifact.metadata["head_sha"] == _HEAD_SHA


def test_bridge_pr_evidence_pack_file_creates_wave9_pr_artifact(tmp_path) -> None:
    pack = _pr_pack()
    pack_path = tmp_path / "artifacts" / "pr-pack.json"
    pack_path.parent.mkdir()
    pack_path.write_text(json.dumps(pack.to_dict(), sort_keys=True) + "\n", encoding="utf-8")

    artifact = bridge_pr_evidence_pack_file(tmp_path, "artifacts/pr-pack.json")

    assert artifact.artifact_id == "wave5:pr-evidence-pack"
    assert artifact.kind is AuditEvidenceKind.PR_EVIDENCE_PACK
    assert artifact.source_wave is AuditEvidenceSourceWave.WAVE5
    assert artifact.head_sha == _HEAD_SHA
    assert artifact.sha256 == sha256_file(pack_path)
    assert artifact.metadata["pack_id"] == "pack:wave5"
    assert artifact.metadata["human_approval_count"] == 1


def test_bridge_wave5_evidence_artifact_maps_kind_digest_and_verified_attestation() -> None:
    artifact = _wave5_artifact(
        kind=EvidenceArtifactKind.SANDBOX_ADVERSARIAL_REPORT,
        attestations=(_verified_attestation(),),
    )

    bridged = bridge_wave5_evidence_artifact(artifact)

    assert bridged.artifact_id == "wave5:artifact:ci"
    assert bridged.kind is AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT
    assert bridged.source_wave is AuditEvidenceSourceWave.WAVE5
    assert bridged.path == "evidence/ci.json"
    assert bridged.sha256 == _ARTIFACT_SHA
    assert bridged.size_bytes == 128
    assert bridged.head_sha == _HEAD_SHA
    assert bridged.verified is True
    assert bridged.metadata["verified_attestation_count"] == 1


def test_bridge_wave5_evidence_artifact_requires_digest_size_and_safe_path() -> None:
    with pytest.raises(ValueError, match="missing SHA-256"):
        bridge_wave5_evidence_artifact(_wave5_artifact(sha256=None))

    with pytest.raises(ValueError, match="positive size_bytes"):
        bridge_wave5_evidence_artifact(_wave5_artifact(size_bytes=None))

    with pytest.raises(ValueError, match="not a repository-relative path"):
        bridge_wave5_evidence_artifact(
            _wave5_artifact(uri="https://example.invalid/artifact.json")
        )


def test_bridge_wave5_evidence_artifact_accepts_fallback_path_for_external_uri() -> None:
    artifact = _wave5_artifact(uri="https://example.invalid/artifact.json")

    bridged = bridge_wave5_evidence_artifact(
        artifact,
        fallback_path="evidence/fallback-artifact.json",
    )

    assert bridged.path == "evidence/fallback-artifact.json"


def test_bridge_pr_evidence_pack_artifacts_is_deterministic() -> None:
    first = _wave5_artifact(artifact_id="artifact:b", kind=EvidenceArtifactKind.CI_SUMMARY)
    second = _wave5_artifact(artifact_id="artifact:a", kind=EvidenceArtifactKind.TEST_REPORT)
    pack = PullRequestEvidencePack(
        pack_id="pack:wave5",
        pull_request=_pr_identity(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        summary="Wave 5 PR evidence pack for deterministic artifact bridge tests.",
        changed_files=("src/ix_blackfox/audit/evidence_bridges.py",),
        requested_checks=("pytest",),
        artifacts=(first, second),
    )

    bridged = bridge_pr_evidence_pack_artifacts(pack)

    assert [artifact.artifact_id for artifact in bridged] == [
        "wave5:artifact:a",
        "wave5:artifact:b",
    ]


def test_bridge_wave5_approval_to_signoff_preserves_human_authority_binding() -> None:
    signoff = bridge_wave5_approval_to_signoff(
        _approval(),
        subject_digest=_SUBJECT_DIGEST,
        policy_pack_digest=_POLICY_DIGEST,
    )

    assert signoff.signoff_id == "wave5:approval:human"
    assert signoff.reviewer_kind is AuditReviewerKind.HUMAN
    assert signoff.decision is AuditReviewDecision.APPROVED
    assert signoff.subject_digest == _SUBJECT_DIGEST
    assert signoff.policy_pack_digest == _POLICY_DIGEST
    assert signoff.is_authoritative_human_approval is True
    assert signoff.metadata["bridge"] == "wave5_approval_to_signoff"


def test_bridge_wave5_approvals_to_signoffs_sorts_by_signoff_id() -> None:
    approvals = (
        _approval(approval_id="approval:b", reviewer_kind=ReviewerKind.SYSTEM),
        _approval(approval_id="approval:a", reviewer_kind=ReviewerKind.HUMAN),
    )

    signoffs = bridge_wave5_approvals_to_signoffs(
        approvals,
        subject_digest=_SUBJECT_DIGEST,
        policy_pack_digest=_POLICY_DIGEST,
    )

    assert [signoff.signoff_id for signoff in signoffs] == [
        "wave5:approval:a",
        "wave5:approval:b",
    ]
    assert signoffs[0].reviewer_kind is AuditReviewerKind.HUMAN
    assert signoffs[1].reviewer_kind is AuditReviewerKind.SYSTEM


def test_wave5_mapping_functions_cover_expected_enums() -> None:
    assert map_wave5_artifact_kind(EvidenceArtifactKind.CI_SUMMARY) is AuditEvidenceKind.CI_EVIDENCE
    assert (
        map_wave5_artifact_kind(EvidenceArtifactKind.SANDBOX_RECEIPT_BUNDLE)
        is AuditEvidenceKind.SANDBOX_RECEIPT_BUNDLE
    )
    assert map_wave5_reviewer_kind(ReviewerKind.MODEL) is AuditReviewerKind.MODEL
    assert map_wave5_review_decision(ReviewDecision.CHANGES_REQUESTED) is AuditReviewDecision.CHANGES_REQUESTED


def test_artifact_is_verified_by_attestation_requires_verified_attestation() -> None:
    unverified_attestation = ArtifactAttestation(
        attestation_id="attestation:unverified",
        kind=ArtifactAttestationKind.LOCAL_MANIFEST,
        uri="attestations/unverified.json",
        produced_by="unit-test",
        predicate_type="local-test-attestation",
        sha256=_ATTESTATION_SHA,
        size_bytes=64,
        head_sha=_HEAD_SHA,
        subject_sha256=_SUBJECT_SHA,
        verified=False,
    )

    assert artifact_is_verified_by_attestation(_wave5_artifact(attestations=())) is False
    assert artifact_is_verified_by_attestation(
        _wave5_artifact(attestations=(unverified_attestation,))
    ) is False
    assert artifact_is_verified_by_attestation(
        _wave5_artifact(attestations=(_verified_attestation(),))
    ) is True


def test_relative_path_from_wave5_uri_accepts_safe_file_uri_and_rejects_absolute() -> None:
    assert relative_path_from_wave5_uri("file://evidence/report.json") == "evidence/report.json"
    assert relative_path_from_wave5_uri("./evidence/report.json") == "evidence/report.json"

    with pytest.raises(ValueError):
        relative_path_from_wave5_uri("file:///tmp/report.json")
