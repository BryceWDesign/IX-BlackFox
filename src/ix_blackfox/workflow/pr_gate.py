from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.workflow.approval_policy import (
    ApprovalPolicyDecision,
    ApprovalPolicyEvaluator,
    ApprovalPolicyMatrix,
    default_wave5_approval_policy_matrix,
)
from ix_blackfox.workflow.ci_evidence import (
    CiEvidenceBundle,
    CiEvidenceValidationReport,
    CiEvidenceValidator,
)
from ix_blackfox.workflow.pr_evidence_pack import (
    PullRequestEvidencePack,
    PullRequestEvidencePackValidator,
    Wave5ValidationIssue,
    Wave5ValidationReport,
    Wave5ValidationSeverity,
)


class PullRequestGateStatus(StrEnum):
    MERGE_READY = auto()
    BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class PullRequestGateDecision:
    pack_id: str
    evaluated_at: datetime
    evidence_report: Wave5ValidationReport
    approval_policy_decision: ApprovalPolicyDecision
    ci_report: CiEvidenceValidationReport | None = None
    gate_issues: tuple[Wave5ValidationIssue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware.")
        object.__setattr__(self, "gate_issues", tuple(self.gate_issues))

    @property
    def issues(self) -> tuple[Wave5ValidationIssue, ...]:
        ci_issues = self.ci_report.issues if self.ci_report is not None else ()
        return (
            *self.evidence_report.issues,
            *self.approval_policy_decision.issues,
            *ci_issues,
            *self.gate_issues,
        )

    @property
    def passed(self) -> bool:
        return not any(issue.severity is Wave5ValidationSeverity.ERROR for issue in self.issues)

    @property
    def status(self) -> PullRequestGateStatus:
        return PullRequestGateStatus.MERGE_READY if self.passed else PullRequestGateStatus.BLOCKED

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
            "evaluated_at": self.evaluated_at.isoformat(),
            "status": self.status.value,
            "passed": self.passed,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issue_codes": list(self.issue_codes),
            "evidence_report": self.evidence_report.to_dict(),
            "approval_policy_decision": self.approval_policy_decision.to_dict(),
            "ci_report": self.ci_report.to_dict() if self.ci_report is not None else None,
            "gate_issues": [issue.to_dict() for issue in self.gate_issues],
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class PullRequestGate:
    evidence_validator: PullRequestEvidencePackValidator = field(
        default_factory=PullRequestEvidencePackValidator
    )
    approval_policy_matrix: ApprovalPolicyMatrix = field(
        default_factory=default_wave5_approval_policy_matrix
    )
    required_ci_checks: tuple[str, ...] = ("pytest",)
    require_ci_evidence: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_ci_checks", _normalize_check_names(self.required_ci_checks))
        if self.require_ci_evidence and not self.required_ci_checks:
            raise ValueError("required_ci_checks must not be empty when CI evidence is required.")

    def evaluate(
        self,
        pack: PullRequestEvidencePack,
        *,
        ci_bundle: CiEvidenceBundle | None = None,
    ) -> PullRequestGateDecision:
        evidence_report = self.evidence_validator.validate(pack)
        approval_policy_decision = ApprovalPolicyEvaluator(self.approval_policy_matrix).evaluate(pack)
        ci_report = self._evaluate_ci_bundle(ci_bundle)
        gate_issues = self._gate_binding_issues(pack, ci_bundle)
        return PullRequestGateDecision(
            pack_id=pack.pack_id,
            evaluated_at=datetime.now(tz=UTC),
            evidence_report=evidence_report,
            approval_policy_decision=approval_policy_decision,
            ci_report=ci_report,
            gate_issues=gate_issues,
        )

    def _evaluate_ci_bundle(
        self,
        ci_bundle: CiEvidenceBundle | None,
    ) -> CiEvidenceValidationReport | None:
        if ci_bundle is None:
            return None
        checks = self.required_ci_checks
        if not checks:
            return None
        return CiEvidenceValidator(required_checks=checks).validate(ci_bundle)

    def _gate_binding_issues(
        self,
        pack: PullRequestEvidencePack,
        ci_bundle: CiEvidenceBundle | None,
    ) -> tuple[Wave5ValidationIssue, ...]:
        issues: list[Wave5ValidationIssue] = []
        if self.require_ci_evidence and ci_bundle is None:
            issues.append(
                _error(
                    "wave5.pr_gate_ci_evidence_missing",
                    "PR gate requires a CI evidence bundle before merge readiness can be granted.",
                    "ci_bundle",
                )
            )
            return tuple(issues)
        if ci_bundle is None:
            return tuple(issues)
        if ci_bundle.repository != pack.pull_request.repository:
            issues.append(
                _error(
                    "wave5.pr_gate_repository_mismatch",
                    "CI evidence repository does not match the PR evidence pack repository.",
                    "ci_bundle.repository",
                )
            )
        if ci_bundle.head_sha != pack.pull_request.head_sha:
            issues.append(
                _error(
                    "wave5.pr_gate_head_sha_mismatch",
                    "CI evidence head SHA does not match the PR evidence pack head SHA.",
                    "ci_bundle.head_sha",
                )
            )
        return tuple(issues)


def evaluate_default_pull_request_gate(
    pack: PullRequestEvidencePack,
    *,
    ci_bundle: CiEvidenceBundle | None = None,
) -> PullRequestGateDecision:
    return PullRequestGate().evaluate(pack, ci_bundle=ci_bundle)


def _normalize_check_names(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_check_name(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("required_ci_checks must not contain duplicates.")
    return normalized


def _normalize_check_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("required_ci_checks must not contain empty check names.")
    return cleaned


def _error(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.ERROR, summary, location)
