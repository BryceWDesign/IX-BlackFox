from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.workflow import (
    ArtifactAttestation,
    ArtifactAttestationKind,
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestEvidencePackValidator,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
)

_HEAD_SHA = "abc1234"
_DIGEST = "a" * 64
_ATTESTATION_DIGEST = "f" * 64


def test_wave5_pr_evidence_pack_passes_with_required_evidence_and_human_approval() -> None:
    pack = _complete_pack()

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is True
    assert report.error_count == 0
    assert report.issue_codes == ()
    assert report.to_dict()["passed"] is True


def test_wave5_pr_evidence_pack_fails_closed_without_required_artifacts() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-missing-artifacts",
        pull_request=_identity(),
        created_at=_now(),
        summary="Incomplete pack should not be accepted as Wave 5 proof.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            EvidenceArtifact(
                artifact_id="run-bundle",
                kind=EvidenceArtifactKind.RUN_BUNDLE,
                uri="artifacts/run-bundle.json",
                produced_by="blackfox-runtime",
                sha256=_DIGEST,
                size_bytes=512,
                head_sha=_HEAD_SHA,
            ),
        ),
        approvals=(
            PullRequestApproval(
                approval_id="approval-existing-evidence-only",
                reviewer_id="reviewer-a",
                reviewer_kind=ReviewerKind.HUMAN,
                decision=ReviewDecision.APPROVED,
                decided_at=_now(),
                note="Human approval references only the evidence actually present.",
                evidence_refs=("run-bundle",),
                roles=("maintainer",),
            ),
        ),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 3
    assert report.issue_codes.count("wave5.required_artifact_missing") == 3


def test_wave5_pr_evidence_pack_requires_human_authority_not_model_self_approval() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-model-only",
        pull_request=_identity(),
        created_at=_now(),
        summary="Model-only approval remains advisory evidence.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=_required_artifacts(),
        approvals=(
            PullRequestApproval(
                approval_id="approval-model-advisory",
                reviewer_id="model:blackfox-brain",
                reviewer_kind=ReviewerKind.MODEL,
                decision=ReviewDecision.APPROVED,
                decided_at=_now(),
                note="Advisory model review only.",
                evidence_refs=("run-bundle",),
                roles=("advisory",),
            ),
        ),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert "wave5.model_approval_not_authoritative" in report.issue_codes
    assert "wave5.human_approval_missing" in report.issue_codes


def test_wave5_pr_evidence_pack_blocks_rejected_or_changes_requested_reviews() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-change-requested",
        pull_request=_identity(),
        created_at=_now(),
        summary="A changes-requested review blocks merge readiness.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=_required_artifacts(),
        approvals=(
            _human_approval(),
            PullRequestApproval(
                approval_id="approval-change-requested",
                reviewer_id="reviewer-b",
                reviewer_kind=ReviewerKind.HUMAN,
                decision=ReviewDecision.CHANGES_REQUESTED,
                decided_at=_now(),
                note="Evidence gap requires correction before merge.",
                evidence_refs=("test-report",),
                roles=("reviewer",),
            ),
        ),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert "wave5.review_blocks_merge" in report.issue_codes


def test_wave5_pr_evidence_pack_blocks_missing_approval_evidence_refs() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-bad-approval-ref",
        pull_request=_identity(),
        created_at=_now(),
        summary="Approval cannot cite missing evidence.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=_required_artifacts(),
        approvals=(
            PullRequestApproval(
                approval_id="approval-missing-ref",
                reviewer_id="reviewer-a",
                reviewer_kind=ReviewerKind.HUMAN,
                decision=ReviewDecision.APPROVED,
                decided_at=_now(),
                note="Bad approval reference.",
                evidence_refs=("missing-artifact",),
                roles=("maintainer",),
            ),
        ),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert "wave5.approval_evidence_ref_missing" in report.issue_codes


def test_wave5_pr_evidence_pack_rejects_unsafe_changed_paths() -> None:
    with pytest.raises(ValueError, match="changed_file must not contain"):
        PullRequestEvidencePack(
            pack_id="wave5-pack-unsafe-path",
            pull_request=_identity(),
            created_at=_now(),
            summary="Unsafe changed path should fail before validation.",
            changed_files=("../outside.py",),
            requested_checks=("pytest",),
            artifacts=_required_artifacts(),
            approvals=(_human_approval(),),
        )


def test_wave5_pr_evidence_pack_fails_required_artifacts_without_measurements() -> None:
    artifacts = tuple(
        EvidenceArtifact(
            artifact_id=artifact.artifact_id,
            kind=artifact.kind,
            uri=artifact.uri,
            produced_by=artifact.produced_by,
            head_sha=artifact.head_sha,
        )
        for artifact in _required_artifacts()
    )
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-unmeasured-required-artifacts",
        pull_request=_identity(),
        created_at=_now(),
        summary="Required artifacts must have identity before Wave 6 can consume them.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=artifacts,
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 8
    assert report.warning_count == 0
    assert report.issue_codes.count("wave5.artifact_digest_missing") == 4
    assert report.issue_codes.count("wave5.artifact_size_missing") == 4


def test_wave5_pr_evidence_pack_fails_required_artifacts_without_head_sha() -> None:
    artifacts = tuple(
        EvidenceArtifact(
            artifact_id=artifact.artifact_id,
            kind=artifact.kind,
            uri=artifact.uri,
            produced_by=artifact.produced_by,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
        )
        for artifact in _required_artifacts()
    )
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-unbound-required-artifacts",
        pull_request=_identity(),
        created_at=_now(),
        summary="Required artifacts must declare the PR head SHA they were produced for.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=artifacts,
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 4
    assert report.warning_count == 0
    assert report.issue_codes.count("wave5.artifact_head_sha_missing") == 4


def test_wave5_pr_evidence_pack_rejects_stale_artifact_head_sha() -> None:
    run_bundle, *remaining = _required_artifacts()
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-stale-artifact",
        pull_request=_identity(),
        created_at=_now(),
        summary="A stale artifact from another commit must not satisfy the PR gate.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            EvidenceArtifact(
                artifact_id=run_bundle.artifact_id,
                kind=run_bundle.kind,
                uri=run_bundle.uri,
                produced_by=run_bundle.produced_by,
                sha256=run_bundle.sha256,
                size_bytes=run_bundle.size_bytes,
                head_sha="def5678",
            ),
            *remaining,
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 1
    assert "wave5.artifact_head_sha_mismatch" in report.issue_codes


def test_wave5_pr_evidence_pack_accepts_attestations_when_future_gate_requires_them() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-attested-required-artifacts",
        pull_request=_identity(),
        created_at=_now(),
        summary="Attestation-ready artifacts prepare Wave 6 signed evidence bundles.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=tuple(_attested_artifact(artifact) for artifact in _required_artifacts()),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator(
        require_attestations_for_required_artifacts=True
    ).validate(pack)

    assert report.passed is True
    assert report.error_count == 0
    assert report.warning_count == 0
    assert pack.to_dict()["artifacts"][0]["attestations"][0]["verified"] is False


def test_wave5_pr_evidence_pack_can_require_attestations_for_required_artifacts() -> None:
    pack = _complete_pack()

    report = PullRequestEvidencePackValidator(
        require_attestations_for_required_artifacts=True
    ).validate(pack)

    assert report.passed is False
    assert report.error_count == 4
    assert report.issue_codes.count("wave5.artifact_attestation_missing") == 4


def test_wave5_pr_evidence_pack_rejects_attestation_subject_digest_mismatch() -> None:
    run_bundle, *remaining = _required_artifacts()
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-bad-attestation-subject",
        pull_request=_identity(),
        created_at=_now(),
        summary="Attestation subject digests must bind to the artifact digest.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            _attested_artifact(run_bundle, subject_sha256="e" * 64),
            *remaining,
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 1
    assert "wave5.attestation_subject_digest_mismatch" in report.issue_codes


def test_wave5_pr_evidence_pack_rejects_attestation_head_sha_mismatch() -> None:
    run_bundle, *remaining = _required_artifacts()
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-stale-attestation",
        pull_request=_identity(),
        created_at=_now(),
        summary="Attestations must bind to the artifact and PR head SHA.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            _attested_artifact(run_bundle, head_sha="def5678"),
            *remaining,
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 2
    assert "wave5.attestation_artifact_head_sha_mismatch" in report.issue_codes
    assert "wave5.attestation_pr_head_sha_mismatch" in report.issue_codes


def test_wave5_pr_evidence_pack_rejects_duplicate_attestation_ids() -> None:
    run_bundle, *remaining = _required_artifacts()
    attestation = _attestation(run_bundle)
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-duplicate-attestations",
        pull_request=_identity(),
        created_at=_now(),
        summary="Attestation identifiers must be stable and unique per artifact.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            EvidenceArtifact(
                artifact_id=run_bundle.artifact_id,
                kind=run_bundle.kind,
                uri=run_bundle.uri,
                produced_by=run_bundle.produced_by,
                sha256=run_bundle.sha256,
                size_bytes=run_bundle.size_bytes,
                head_sha=run_bundle.head_sha,
                attestations=(attestation, attestation),
            ),
            *remaining,
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 1
    assert "wave5.duplicate_attestation_id" in report.issue_codes


def test_wave5_pr_evidence_pack_warns_on_optional_artifacts_without_measurements() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-unmeasured-optional-artifact",
        pull_request=_identity(),
        created_at=_now(),
        summary="Optional artifacts may be advisory, but missing identity is still reported.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            *_required_artifacts(),
            EvidenceArtifact(
                artifact_id="optional-policy-note",
                kind=EvidenceArtifactKind.OTHER,
                uri="artifacts/optional-policy-note.json",
                produced_by="blackfox-workflow",
                head_sha=_HEAD_SHA,
            ),
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is True
    assert report.error_count == 0
    assert report.warning_count == 2
    assert "wave5.artifact_digest_missing" in report.issue_codes
    assert "wave5.artifact_size_missing" in report.issue_codes


def test_wave5_pr_evidence_pack_warns_on_optional_artifact_without_head_sha() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-unbound-optional-artifact",
        pull_request=_identity(),
        created_at=_now(),
        summary="Optional evidence without head binding remains advisory but visible.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            *_required_artifacts(),
            EvidenceArtifact(
                artifact_id="optional-policy-note",
                kind=EvidenceArtifactKind.OTHER,
                uri="artifacts/optional-policy-note.json",
                produced_by="blackfox-workflow",
                sha256="e" * 64,
                size_bytes=128,
            ),
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is True
    assert report.error_count == 0
    assert report.warning_count == 1
    assert "wave5.artifact_head_sha_missing" in report.issue_codes


def test_wave5_pr_evidence_pack_fails_zero_byte_required_artifact() -> None:
    run_bundle, *remaining = _required_artifacts()
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-empty-required-artifact",
        pull_request=_identity(),
        created_at=_now(),
        summary="A zero-byte required artifact is not acceptable merge evidence.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=(
            EvidenceArtifact(
                artifact_id=run_bundle.artifact_id,
                kind=run_bundle.kind,
                uri=run_bundle.uri,
                produced_by=run_bundle.produced_by,
                sha256=run_bundle.sha256,
                size_bytes=0,
                head_sha=run_bundle.head_sha,
            ),
            *remaining,
        ),
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is False
    assert report.error_count == 1
    assert "wave5.required_artifact_empty" in report.issue_codes


def _complete_pack() -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="wave5-pack-complete",
        pull_request=_identity(),
        created_at=_now(),
        summary="Complete Wave 5 PR evidence pack for an organization review gate.",
        changed_files=("src/ix_blackfox/workflow/pr_evidence_pack.py",),
        requested_checks=("pytest", "ruff", "mypy"),
        artifacts=_required_artifacts(),
        approvals=(_human_approval(),),
        metadata={"wave": "5", "scope": "pr-evidence-pack-contract"},
    )


def _identity() -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="pr-1",
        base_ref="main",
        head_ref="wave5-pr-evidence-pack",
        head_sha=_HEAD_SHA,
        author="Bryce Lovell",
    )


def _required_artifacts() -> tuple[EvidenceArtifact, ...]:
    return (
        EvidenceArtifact(
            artifact_id="run-bundle",
            kind=EvidenceArtifactKind.RUN_BUNDLE,
            uri="artifacts/run-bundle.json",
            produced_by="blackfox-runtime",
            sha256=_DIGEST,
            size_bytes=512,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="test-report",
            kind=EvidenceArtifactKind.TEST_REPORT,
            uri="artifacts/pytest-report.json",
            produced_by="pytest",
            sha256="b" * 64,
            size_bytes=768,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="governance-receipt",
            kind=EvidenceArtifactKind.GOVERNANCE_RECEIPT,
            uri="artifacts/governance-receipts.json",
            produced_by="blackfox-governance",
            sha256="c" * 64,
            size_bytes=384,
            head_sha=_HEAD_SHA,
        ),
        EvidenceArtifact(
            artifact_id="reliability-report",
            kind=EvidenceArtifactKind.RELIABILITY_REPORT,
            uri="artifacts/wave4-reliability-report.json",
            produced_by="blackfox-reliability-lab",
            sha256="d" * 64,
            size_bytes=1024,
            head_sha=_HEAD_SHA,
        ),
    )


def _attested_artifact(
    artifact: EvidenceArtifact,
    *,
    head_sha: str = _HEAD_SHA,
    subject_sha256: str | None = None,
) -> EvidenceArtifact:
    return EvidenceArtifact(
        artifact_id=artifact.artifact_id,
        kind=artifact.kind,
        uri=artifact.uri,
        produced_by=artifact.produced_by,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        head_sha=artifact.head_sha,
        attestations=(
            _attestation(
                artifact,
                head_sha=head_sha,
                subject_sha256=subject_sha256,
            ),
        ),
    )


def _attestation(
    artifact: EvidenceArtifact,
    *,
    head_sha: str = _HEAD_SHA,
    subject_sha256: str | None = None,
) -> ArtifactAttestation:
    if artifact.sha256 is None:
        raise ValueError("test artifact must include sha256")
    return ArtifactAttestation(
        attestation_id=f"attestation-{artifact.artifact_id}",
        kind=ArtifactAttestationKind.LOCAL_MANIFEST,
        uri=f"artifacts/attestations/{artifact.artifact_id}.json",
        produced_by="blackfox-workflow",
        predicate_type="https://ix.blackfox.local/predicate/pr-evidence/v1",
        sha256=_ATTESTATION_DIGEST,
        size_bytes=256,
        head_sha=head_sha,
        subject_sha256=subject_sha256 if subject_sha256 is not None else artifact.sha256,
        verified=False,
        metadata={"wave": "5.5", "future_consumer": "wave6-sandbox-evidence"},
    )


def _human_approval() -> PullRequestApproval:
    return PullRequestApproval(
        approval_id="approval-human-maintainer",
        reviewer_id="maintainer-a",
        reviewer_kind=ReviewerKind.HUMAN,
        decision=ReviewDecision.APPROVED,
        decided_at=_now(),
        note="Human maintainer approved after reviewing supplied evidence artifacts.",
        evidence_refs=("run-bundle", "test-report", "governance-receipt", "reliability-report"),
        roles=("maintainer",),
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
