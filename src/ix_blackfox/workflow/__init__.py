"""
Wave 5 organization workflow primitives.

This package is the first Wave 5 layer for IX-BlackFox. It does not
claim that organization-grade workflow is complete. It defines the
reviewable pull-request evidence-pack contract that later CI and approval
workflow integrations can enforce.
"""

from __future__ import annotations

from ix_blackfox.workflow.approval_policy import (
    ApprovalPolicyDecision,
    ApprovalPolicyEvaluator,
    ApprovalPolicyMatrix,
    ApprovalRequirement,
    default_wave5_approval_policy_matrix,
    evaluate_default_wave5_approval_policy,
)
from ix_blackfox.workflow.pr_evidence_pack import (
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestEvidencePackValidator,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
    Wave5ValidationIssue,
    Wave5ValidationReport,
    Wave5ValidationSeverity,
)

__all__ = [
    "ApprovalPolicyDecision",
    "ApprovalPolicyEvaluator",
    "ApprovalPolicyMatrix",
    "ApprovalRequirement",
    "EvidenceArtifact",
    "EvidenceArtifactKind",
    "PullRequestApproval",
    "PullRequestEvidencePack",
    "PullRequestEvidencePackValidator",
    "PullRequestIdentity",
    "ReviewDecision",
    "ReviewerKind",
    "Wave5ValidationIssue",
    "Wave5ValidationReport",
    "Wave5ValidationSeverity",
    "default_wave5_approval_policy_matrix",
    "evaluate_default_wave5_approval_policy",
]
