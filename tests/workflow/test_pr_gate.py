from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.workflow import (
    CiCheckConclusion,
    CiCheckStatus,
    CiEvidenceBundle,
    CiEvidenceRecord,
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestGate,
    PullRequestGateStatus,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
    evaluate_default_pull_request_gate,
)

_DIGEST = "a" * 64


def test_wave5_pr_gate_passes_with_evidence_approval_and_matching_ci() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
    )
    ci_bundle = _ci_bundle(head_sha="abc1234", records=(_ci_record("pytest", CiCheckConclusion.SUCCESS),))

    decision = evaluate_default_pull_request_gate(pack, ci_bundle=ci_bundle)

    assert decision.passed is True
    assert decision.status is PullRequestGateStatus.MERGE_READY
    assert decision.error_count == 0
    assert decision.to_dict()["status"] == "merge_ready"


def test_wave5_pr_gate_fails_closed_when_ci_evidence_is_missing() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
    )

    decision = evaluate_default_pull_request_gate(pack)

    assert decision.passed is False
    assert decision.status is PullRequestGateStatus.BLOCKED
    assert "wave5.pr_gate_ci_evidence_missing" in decision.issue_codes


def test_wave5_pr_gate_fails_closed_when_ci_head_sha_does_not_match_pack() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
    )
    ci_bundle = _ci_bundle(head_sha="def5678", records=(_ci_record("pytest", CiCheckConclusion.SUCCESS),))

    decision = evaluate_default_pull_request_gate(pack, ci_bundle=ci_bundle)

    assert decision.passed is False
    assert "wave5.pr_gate_head_sha_mismatch" in decision.issue_codes


def test_wave5_pr_gate_fails_closed_when_ci_required_check_fails() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
    )
    ci_bundle = _ci_bundle(head_sha="abc1234", records=(_ci_record("pytest", CiCheckConclusion.FAILURE),))

    decision = evaluate_default_pull_request_gate(pack, ci_bundle=ci_bundle)

    assert decision.passed is False
    assert "wave5.ci_required_check_failed" in decision.issue_codes


def test_wave5_pr_gate_combines_evidence_pack_and_approval_policy_errors() -> None:
    pack = PullRequestEvidencePack(
        pack_id="wave5-pack-incomplete",
        pull_request=_identity(),
        created_at=_now(),
        summary="Incomplete evidence pack must not pass the PR gate.",
        changed_files=("src/ix_blackfox/workflow/pr_gate.py",),
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
            _approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),
        ),
    )
    ci_bundle = _ci_bundle(head_sha="abc1234", records=(_ci_record("pytest", CiCheckConclusion.SUCCESS),))

    decision = evaluate_default_pull_request_gate(pack, ci_bundle=ci_bundle)

    assert decision.passed is False
    assert "wave5.required_artifact_missing" in decision.issue_codes
    assert "wave5.approval_policy_human_threshold_missing" in decision.issue_codes
    assert "wave5.approval_policy_role_missing" in decision.issue_codes


def test_wave5_pr_gate_blocks_changes_requested_review_even_when_ci_passes() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(
            _approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),
            PullRequestApproval(
                approval_id="approval-changes-requested",
                reviewer_id="reviewer-b",
                reviewer_kind=ReviewerKind.HUMAN,
                decision=ReviewDecision.CHANGES_REQUESTED,
                decided_at=_now(),
                note="Changes requested blocks merge readiness.",
                evidence_refs=("test-report",),
                roles=("reviewer",),
            ),
        ),
    )
    ci_bundle = _ci_bundle(head_sha="abc1234", records=(_ci_record("pytest", CiCheckConclusion.SUCCESS),))

    decision = evaluate_default_pull_request_gate(pack, ci_bundle=ci_bundle)

    assert decision.passed is False
    assert "wave5.review_blocks_merge" in decision.issue_codes
    assert "wave5.approval_policy_blocking_review" in decision.issue_codes


def test_wave5_pr_gate_can_require_multiple_ci_checks() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
        requested_checks=("pytest", "ruff"),
    )
    ci_bundle = _ci_bundle(head_sha="abc1234", records=(_ci_record("pytest", CiCheckConclusion.SUCCESS),))

    decision = PullRequestGate(required_ci_checks=("pytest", "ruff")).evaluate(pack, ci_bundle=ci_bundle)

    assert decision.passed is False
    assert "wave5.ci_required_check_missing" in decision.issue_codes


def test_wave5_pr_gate_rejects_duplicate_required_ci_checks() -> None:
    with pytest.raises(ValueError, match="required_ci_checks must not contain duplicates"):
        PullRequestGate(required_ci_checks=("pytest", "pytest"))


def _pack(
    *,
    changed_files: tuple[str, ...],
    approvals: tuple[PullRequestApproval, ...],
    requested_checks: tuple[str, ...] = ("pytest",),
) -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="wave5-pack-gate",
        pull_request=_identity(),
        created_at=_now(),
        summary="Wave 5 PR gate evaluation pack.",
        changed_files=changed_files,
        requested_checks=requested_checks,
        artifacts=_artifacts(),
        approvals=approvals,
    )


def _identity() -> PullRequestIdentity:
    return PullRequestIdentity(
        provider="github",
        repository="BryceWDesign/IX-BlackFox",
        pull_request_id="pr-4",
        base_ref="main",
        head_ref="wave5-pr-gate",
        head_sha="abc1234",
        author="Bryce Lovell",
    )


def _artifacts() -> tuple[EvidenceArtifact, ...]:
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


def _approval(approval_id: str, reviewer_id: str, *, roles: tuple[str, ...]) -> PullRequestApproval:
    return PullRequestApproval(
        approval_id=approval_id,
        reviewer_id=reviewer_id,
        reviewer_kind=ReviewerKind.HUMAN,
        decision=ReviewDecision.APPROVED,
        decided_at=_now(),
        note="Human review approval for Wave 5 PR gate evaluation.",
        evidence_refs=("run-bundle", "test-report", "governance-receipt", "reliability-report"),
        roles=roles,
    )


def _ci_bundle(*, head_sha: str, records: tuple[CiEvidenceRecord, ...]) -> CiEvidenceBundle:
    return CiEvidenceBundle(
        bundle_id="ci-bundle-gate",
        provider="github-actions",
        repository="BryceWDesign/IX-BlackFox",
        head_sha=head_sha,
        collected_at=_now(),
        records=records,
    )


def _ci_record(check_name: str, conclusion: CiCheckConclusion) -> CiEvidenceRecord:
    return CiEvidenceRecord(
        check_name=check_name,
        provider="github-actions",
        status=CiCheckStatus.COMPLETED,
        conclusion=conclusion,
        started_at=datetime(2026, 5, 16, 11, 58, tzinfo=UTC),
        completed_at=_now(),
        url=f"https://example.test/actions/{check_name}",
        required=True,
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
