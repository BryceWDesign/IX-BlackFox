from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.workflow import (
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestEvidencePackValidator,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
)

_DIGEST = "a" * 64


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


def test_wave5_pr_evidence_pack_warns_on_missing_artifact_measurements() -> None:
    artifacts = tuple(
        EvidenceArtifact(
            artifact_id=artifact.artifact_id,
            kind=artifact.kind,
            uri=artifact.uri,
            produced_by=artifact.produced_by,
        )
        for artifact in _required_artifacts()
    )
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-unmeasured-artifacts",
        pull_request=_identity(),
        created_at=_now(),
        summary="Artifacts can be referenced before digest enforcement is complete.",
        changed_files=("src/ix_blackfox/runtime/example.py",),
        requested_checks=("pytest",),
        artifacts=artifacts,
        approvals=(_human_approval(),),
    )

    report = PullRequestEvidencePackValidator().validate(pack)

    assert report.passed is True
    assert report.error_count == 0
    assert report.warning_count == 8
    assert "wave5.artifact_digest_missing" in report.issue_codes
    assert "wave5.artifact_size_missing" in report.issue_codes


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
        head_sha="abc1234",
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
        ),
        EvidenceArtifact(
            artifact_id="test-report",
            kind=EvidenceArtifactKind.TEST_REPORT,
            uri="artifacts/pytest-report.json",
            produced_by="pytest",
            sha256="b" * 64,
            size_bytes=768,
        ),
        EvidenceArtifact(
            artifact_id="governance-receipt",
            kind=EvidenceArtifactKind.GOVERNANCE_RECEIPT,
            uri="artifacts/governance-receipts.json",
            produced_by="blackfox-governance",
            sha256="c" * 64,
            size_bytes=384,
        ),
        EvidenceArtifact(
            artifact_id="reliability-report",
            kind=EvidenceArtifactKind.RELIABILITY_REPORT,
            uri="artifacts/wave4-reliability-report.json",
            produced_by="blackfox-reliability-lab",
            sha256="d" * 64,
            size_bytes=1024,
        ),
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
