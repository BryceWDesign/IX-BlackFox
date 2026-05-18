from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.workflow import (
    ApprovalPolicyEvaluator,
    ApprovalPolicyMatrix,
    ApprovalRequirement,
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
    evaluate_default_wave5_approval_policy,
)

_DIGEST = "a" * 64


def test_wave5_default_approval_policy_passes_with_required_human_roles_and_evidence() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/workflow/pr_evidence_pack.py",),
        approvals=(
            _approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),
            _approval("approval-reviewer", "reviewer-a", roles=("reviewer",)),
        ),
    )

    decision = evaluate_default_wave5_approval_policy(pack)

    assert decision.passed is True
    assert decision.error_count == 0
    assert decision.matched_requirement_ids == (
        "wave5.default-human-review",
        "wave5.workflow-governance-review",
    )
    assert decision.to_dict()["passed"] is True


def test_wave5_approval_policy_fails_when_required_role_is_missing() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/workflow/approval_policy.py",),
        approvals=(
            _approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),
            _approval("approval-second-maintainer", "maintainer-b", roles=("maintainer",)),
        ),
    )

    decision = evaluate_default_wave5_approval_policy(pack)

    assert decision.passed is False
    assert "wave5.approval_policy_role_missing" in decision.issue_codes


def test_wave5_approval_policy_excludes_author_self_approval_from_human_authority() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(
            _approval("approval-author", "Bryce Lovell", roles=("maintainer",)),
        ),
    )

    decision = evaluate_default_wave5_approval_policy(pack)

    assert decision.passed is False
    assert "wave5.approval_policy_author_approval_excluded" in decision.issue_codes
    assert "wave5.approval_policy_human_threshold_missing" in decision.issue_codes
    assert "wave5.approval_policy_role_missing" in decision.issue_codes


def test_wave5_approval_policy_treats_model_approval_as_advisory_only() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(
            PullRequestApproval(
                approval_id="approval-model",
                reviewer_id="model:blackfox-brain",
                reviewer_kind=ReviewerKind.MODEL,
                decision=ReviewDecision.APPROVED,
                decided_at=_now(),
                note="Advisory model review only.",
                evidence_refs=("run-bundle",),
                roles=("maintainer",),
            ),
        ),
    )

    decision = evaluate_default_wave5_approval_policy(pack)

    assert decision.passed is False
    assert "wave5.approval_policy_model_approval_advisory" in decision.issue_codes
    assert "wave5.approval_policy_human_threshold_missing" in decision.issue_codes


def test_wave5_approval_policy_blocks_rejected_or_changes_requested_reviews() -> None:
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        approvals=(
            _approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),
            PullRequestApproval(
                approval_id="approval-blocking",
                reviewer_id="reviewer-b",
                reviewer_kind=ReviewerKind.HUMAN,
                decision=ReviewDecision.CHANGES_REQUESTED,
                decided_at=_now(),
                note="Requested changes must block merge readiness.",
                evidence_refs=("test-report",),
                roles=("reviewer",),
            ),
        ),
    )

    decision = evaluate_default_wave5_approval_policy(pack)

    assert decision.passed is False
    assert "wave5.approval_policy_blocking_review" in decision.issue_codes


def test_wave5_approval_policy_requires_artifacts_declared_by_requirement() -> None:
    matrix = ApprovalPolicyMatrix(
        requirements=(
            ApprovalRequirement(
                requirement_id="wave5.custom-reliability-required",
                description="Custom requirement that needs reliability evidence.",
                required_roles=("maintainer",),
                required_artifact_kinds=(EvidenceArtifactKind.RELIABILITY_REPORT,),
                minimum_human_approvals=1,
            ),
        )
    )
    pack = _pack(
        changed_files=("src/ix_blackfox/runtime/control_plane.py",),
        artifacts=_artifacts(include_reliability=False),
        approvals=(_approval("approval-maintainer", "maintainer-a", roles=("maintainer",)),),
    )

    decision = ApprovalPolicyEvaluator(matrix).evaluate(pack)

    assert decision.passed is False
    assert "wave5.approval_policy_artifact_missing" in decision.issue_codes


def test_wave5_approval_policy_rejects_unsafe_path_prefixes() -> None:
    with pytest.raises(ValueError, match="path_prefix must not contain"):
        ApprovalRequirement(
            requirement_id="wave5.bad-prefix",
            description="Bad path prefix should be rejected.",
            path_prefixes=("../outside",),
        )


def _pack(
    *,
    changed_files: tuple[str, ...],
    approvals: tuple[PullRequestApproval, ...],
    artifacts: tuple[EvidenceArtifact, ...] | None = None,
) -> PullRequestEvidencePack:
    return PullRequestEvidencePack(
        pack_id="wave5-pack-approval-policy",
        pull_request=PullRequestIdentity(
            provider="github",
            repository="BryceWDesign/IX-BlackFox",
            pull_request_id="pr-2",
            base_ref="main",
            head_ref="wave5-approval-policy",
            head_sha="def5678",
            author="Bryce Lovell",
        ),
        created_at=_now(),
        summary="Wave 5 approval policy evaluation pack.",
        changed_files=changed_files,
        requested_checks=("pytest",),
        artifacts=artifacts if artifacts is not None else _artifacts(include_reliability=True),
        approvals=approvals,
    )


def _artifacts(*, include_reliability: bool) -> tuple[EvidenceArtifact, ...]:
    artifacts = [
        EvidenceArtifact(
            artifact_id="run-bundle",
            kind=EvidenceArtifactKind.RUN_BUNDLE,
            uri="artifacts/run-bundle.json",
            produced_by="blackfox-runtime",
            sha256=_DIGEST,
            size_bytes=512,
            head_sha="def5678",
        ),
        EvidenceArtifact(
            artifact_id="test-report",
            kind=EvidenceArtifactKind.TEST_REPORT,
            uri="artifacts/pytest-report.json",
            produced_by="pytest",
            sha256="b" * 64,
            size_bytes=768,
            head_sha="def5678",
        ),
        EvidenceArtifact(
            artifact_id="governance-receipt",
            kind=EvidenceArtifactKind.GOVERNANCE_RECEIPT,
            uri="artifacts/governance-receipts.json",
            produced_by="blackfox-governance",
            sha256="c" * 64,
            size_bytes=384,
            head_sha="def5678",
        ),
    ]
    if include_reliability:
        artifacts.append(
            EvidenceArtifact(
                artifact_id="reliability-report",
                kind=EvidenceArtifactKind.RELIABILITY_REPORT,
                uri="artifacts/wave4-reliability-report.json",
                produced_by="blackfox-reliability-lab",
                sha256="d" * 64,
                size_bytes=1024,
                head_sha="def5678",
            )
        )
    return tuple(artifacts)


def _approval(approval_id: str, reviewer_id: str, *, roles: tuple[str, ...]) -> PullRequestApproval:
    return PullRequestApproval(
        approval_id=approval_id,
        reviewer_id=reviewer_id,
        reviewer_kind=ReviewerKind.HUMAN,
        decision=ReviewDecision.APPROVED,
        decided_at=_now(),
        note="Human review approval for Wave 5 policy evaluation.",
        evidence_refs=("run-bundle", "test-report", "governance-receipt"),
        roles=roles,
    )


def _now() -> datetime:
    return datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
