from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ix_blackfox.workflow.pr_evidence_pack import (
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    ReviewDecision,
    ReviewerKind,
    Wave5ValidationIssue,
    Wave5ValidationSeverity,
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    requirement_id: str
    description: str
    path_prefixes: tuple[str, ...] = field(default_factory=tuple)
    required_roles: tuple[str, ...] = field(default_factory=tuple)
    required_artifact_kinds: tuple[EvidenceArtifactKind, ...] = field(default_factory=tuple)
    minimum_human_approvals: int = 1
    block_author_approval: bool = True
    model_approval_is_advisory_only: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requirement_id",
            _normalize_token(self.requirement_id, label="requirement_id"),
        )
        object.__setattr__(self, "description", _normalize_text(self.description, label="description"))
        object.__setattr__(self, "path_prefixes", _normalize_path_prefixes(self.path_prefixes))
        object.__setattr__(self, "required_roles", _normalize_labels(self.required_roles))
        object.__setattr__(self, "required_artifact_kinds", tuple(self.required_artifact_kinds))
        if self.minimum_human_approvals < 1:
            raise ValueError("minimum_human_approvals must be at least 1.")

    def matches(self, changed_files: tuple[str, ...]) -> bool:
        if not self.path_prefixes:
            return True
        return any(_file_matches_prefix(changed_file, prefix) for changed_file in changed_files for prefix in self.path_prefixes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "description": self.description,
            "path_prefixes": list(self.path_prefixes),
            "required_roles": list(self.required_roles),
            "required_artifact_kinds": [kind.value for kind in self.required_artifact_kinds],
            "minimum_human_approvals": self.minimum_human_approvals,
            "block_author_approval": self.block_author_approval,
            "model_approval_is_advisory_only": self.model_approval_is_advisory_only,
        }


@dataclass(frozen=True, slots=True)
class ApprovalPolicyMatrix:
    requirements: tuple[ApprovalRequirement, ...]

    def __post_init__(self) -> None:
        if not self.requirements:
            raise ValueError("ApprovalPolicyMatrix requires at least one requirement.")
        requirement_ids = tuple(requirement.requirement_id for requirement in self.requirements)
        if len(set(requirement_ids)) != len(requirement_ids):
            raise ValueError("ApprovalPolicyMatrix requirement ids must be unique.")
        object.__setattr__(self, "requirements", tuple(self.requirements))

    def matching_requirements(self, changed_files: tuple[str, ...]) -> tuple[ApprovalRequirement, ...]:
        return tuple(requirement for requirement in self.requirements if requirement.matches(changed_files))

    def to_dict(self) -> dict[str, Any]:
        return {"requirements": [requirement.to_dict() for requirement in self.requirements]}


@dataclass(frozen=True, slots=True)
class ApprovalPolicyDecision:
    pack_id: str
    matched_requirement_ids: tuple[str, ...]
    issues: tuple[Wave5ValidationIssue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pack_id", _normalize_token(self.pack_id, label="pack_id"))
        object.__setattr__(self, "matched_requirement_ids", _normalize_labels(self.matched_requirement_ids))
        object.__setattr__(self, "issues", tuple(self.issues))

    @property
    def passed(self) -> bool:
        return not any(issue.severity is Wave5ValidationSeverity.ERROR for issue in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.WARNING)

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "passed": self.passed,
            "matched_requirement_ids": list(self.matched_requirement_ids),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issue_codes": list(self.issue_codes),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class ApprovalPolicyEvaluator:
    matrix: ApprovalPolicyMatrix

    def evaluate(self, pack: PullRequestEvidencePack) -> ApprovalPolicyDecision:
        matched_requirements = self.matrix.matching_requirements(pack.changed_files)
        issues: list[Wave5ValidationIssue] = []
        if not matched_requirements:
            issues.append(
                _error(
                    "wave5.approval_policy_no_matching_requirement",
                    "No approval policy requirement matched the changed files.",
                    "changed_files",
                )
            )
        issues.extend(_blocking_review_issues(pack.approvals))
        for requirement in matched_requirements:
            issues.extend(_evaluate_requirement(pack, requirement))
        return ApprovalPolicyDecision(
            pack_id=pack.pack_id,
            matched_requirement_ids=tuple(requirement.requirement_id for requirement in matched_requirements),
            issues=tuple(issues),
        )


def default_wave5_approval_policy_matrix() -> ApprovalPolicyMatrix:
    return ApprovalPolicyMatrix(
        requirements=(
            ApprovalRequirement(
                requirement_id="wave5.default-human-review",
                description="Every PR evidence pack requires at least one non-author human maintainer approval.",
                required_roles=("maintainer",),
                required_artifact_kinds=(
                    EvidenceArtifactKind.RUN_BUNDLE,
                    EvidenceArtifactKind.TEST_REPORT,
                    EvidenceArtifactKind.GOVERNANCE_RECEIPT,
                ),
                minimum_human_approvals=1,
            ),
            ApprovalRequirement(
                requirement_id="wave5.workflow-governance-review",
                description="Workflow, governance, and reliability changes require stronger human review and reliability evidence.",
                path_prefixes=(
                    ".github/workflows",
                    "src/ix_blackfox/workflow",
                    "src/ix_blackfox/governance",
                    "src/ix_blackfox/reliability",
                    "tests/workflow",
                    "tests/governance",
                    "tests/reliability",
                ),
                required_roles=("maintainer", "reviewer"),
                required_artifact_kinds=(
                    EvidenceArtifactKind.RUN_BUNDLE,
                    EvidenceArtifactKind.TEST_REPORT,
                    EvidenceArtifactKind.GOVERNANCE_RECEIPT,
                    EvidenceArtifactKind.RELIABILITY_REPORT,
                ),
                minimum_human_approvals=2,
            ),
        )
    )


def evaluate_default_wave5_approval_policy(pack: PullRequestEvidencePack) -> ApprovalPolicyDecision:
    return ApprovalPolicyEvaluator(default_wave5_approval_policy_matrix()).evaluate(pack)


def _evaluate_requirement(
    pack: PullRequestEvidencePack,
    requirement: ApprovalRequirement,
) -> tuple[Wave5ValidationIssue, ...]:
    issues: list[Wave5ValidationIssue] = []
    qualifying_approvals = _qualifying_human_approvals(pack, requirement)
    if len(qualifying_approvals) < requirement.minimum_human_approvals:
        issues.append(
            _error(
                "wave5.approval_policy_human_threshold_missing",
                f"Requirement '{requirement.requirement_id}' needs at least {requirement.minimum_human_approvals} non-author human approval(s).",
                f"approval_policy.{requirement.requirement_id}.minimum_human_approvals",
            )
        )

    present_roles = _approval_roles(qualifying_approvals)
    for role in requirement.required_roles:
        if role not in present_roles:
            issues.append(
                _error(
                    "wave5.approval_policy_role_missing",
                    f"Requirement '{requirement.requirement_id}' needs approving human role '{role}'.",
                    f"approval_policy.{requirement.requirement_id}.required_roles",
                )
            )

    present_artifact_kinds = set(pack.artifact_kinds())
    for required_kind in requirement.required_artifact_kinds:
        if required_kind not in present_artifact_kinds:
            issues.append(
                _error(
                    "wave5.approval_policy_artifact_missing",
                    f"Requirement '{requirement.requirement_id}' needs artifact kind '{required_kind.value}'.",
                    f"approval_policy.{requirement.requirement_id}.required_artifact_kinds",
                )
            )

    if requirement.block_author_approval:
        for approval in pack.approvals:
            if approval.reviewer_kind is ReviewerKind.HUMAN and _same_actor(approval.reviewer_id, pack.pull_request.author):
                issues.append(
                    _warning(
                        "wave5.approval_policy_author_approval_excluded",
                        f"Approval '{approval.approval_id}' is from the PR author and cannot satisfy human authority.",
                        f"approvals.{approval.approval_id}.reviewer_id",
                    )
                )

    if requirement.model_approval_is_advisory_only:
        for approval in pack.approvals:
            if approval.reviewer_kind is ReviewerKind.MODEL and approval.decision is ReviewDecision.APPROVED:
                issues.append(
                    _warning(
                        "wave5.approval_policy_model_approval_advisory",
                        f"Model approval '{approval.approval_id}' is advisory only and cannot satisfy human authority.",
                        f"approvals.{approval.approval_id}.reviewer_kind",
                    )
                )
    return tuple(issues)


def _qualifying_human_approvals(
    pack: PullRequestEvidencePack,
    requirement: ApprovalRequirement,
) -> tuple[PullRequestApproval, ...]:
    approvals: list[PullRequestApproval] = []
    for approval in pack.approvals:
        if approval.reviewer_kind is not ReviewerKind.HUMAN:
            continue
        if approval.decision is not ReviewDecision.APPROVED:
            continue
        if requirement.block_author_approval and _same_actor(approval.reviewer_id, pack.pull_request.author):
            continue
        approvals.append(approval)
    return tuple(approvals)


def _blocking_review_issues(approvals: tuple[PullRequestApproval, ...]) -> tuple[Wave5ValidationIssue, ...]:
    issues: list[Wave5ValidationIssue] = []
    for approval in approvals:
        if approval.decision in (ReviewDecision.REJECTED, ReviewDecision.CHANGES_REQUESTED):
            issues.append(
                _error(
                    "wave5.approval_policy_blocking_review",
                    f"Review '{approval.approval_id}' blocks merge readiness with decision '{approval.decision.value}'.",
                    f"approvals.{approval.approval_id}.decision",
                )
            )
    return tuple(issues)


def _approval_roles(approvals: tuple[PullRequestApproval, ...]) -> set[str]:
    roles: set[str] = set()
    for approval in approvals:
        roles.update(approval.roles)
    return roles


def _same_actor(left: str, right: str) -> bool:
    return left.strip().casefold() == right.strip().casefold()


def _file_matches_prefix(changed_file: str, prefix: str) -> bool:
    return changed_file == prefix or changed_file.startswith(f"{prefix}/")


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_TOKEN_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_token(value, label="label") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("labels must not contain duplicates.")
    return normalized


def _normalize_path_prefixes(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_path_prefix(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("path_prefixes must not contain duplicates.")
    return normalized


def _normalize_path_prefix(value: str) -> str:
    cleaned = _normalize_text(value.replace("\\", "/"), label="path_prefix").rstrip("/")
    if cleaned.startswith("/"):
        raise ValueError("path_prefix must be relative, not absolute.")
    path = PurePosixPath(cleaned)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("path_prefix must not contain empty, '.', or '..' path segments.")
    return path.as_posix()


def _error(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.ERROR, summary, location)


def _warning(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.WARNING, summary, location)
