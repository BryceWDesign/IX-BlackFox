from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto

from ix_blackfox.eval.core import EvaluationResult, EvaluationSeverity, EvaluationStatus
from ix_blackfox.forge import RegressionReport, RegressionStatus


class VerificationStatus(StrEnum):
    """
    Overall output-verification outcome classification.
    """

    PASSED = auto()
    FAILED = auto()
    NEEDS_REVIEW = auto()


@dataclass(frozen=True, slots=True)
class VerificationIssue:
    """
    One output-verification issue.

    Attributes
    ----------
    code:
        Stable machine-readable issue code.
    severity:
        Severity level borrowed from the evaluation subsystem.
    summary:
        Short human-readable issue summary.
    details:
        Optional longer-form detail.
    """

    code: str
    severity: EvaluationSeverity
    summary: str
    details: str | None = None

    def __post_init__(self) -> None:
        normalized_code = _normalize_identifier(self.code, label="issue code")
        normalized_summary = _normalize_text(self.summary, label="issue summary")
        normalized_details = _normalize_optional_text(self.details)

        object.__setattr__(self, "code", normalized_code)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "details", normalized_details)


@dataclass(frozen=True, slots=True)
class VerificationContext:
    """
    Context supplied to the output-verification layer.

    Attributes
    ----------
    subject_id:
        Logical subject under verification.
    expected_artifacts:
        Logical artifact names expected from the run.
    produced_artifacts:
        Logical artifact names actually produced by the run.
    evaluation_results:
        Prior evaluation results relevant to the subject.
    regression_report:
        Optional regression report from forge testing.
    """

    subject_id: str
    expected_artifacts: tuple[str, ...] = field(default_factory=tuple)
    produced_artifacts: tuple[str, ...] = field(default_factory=tuple)
    evaluation_results: tuple[EvaluationResult, ...] = field(default_factory=tuple)
    regression_report: RegressionReport | None = None

    def __post_init__(self) -> None:
        normalized_subject_id = _normalize_identifier(
            self.subject_id,
            label="subject id",
        )
        normalized_expected_artifacts = _normalize_strings(
            self.expected_artifacts,
            label="expected artifact",
        )
        normalized_produced_artifacts = _normalize_strings(
            self.produced_artifacts,
            label="produced artifact",
        )

        object.__setattr__(self, "subject_id", normalized_subject_id)
        object.__setattr__(self, "expected_artifacts", normalized_expected_artifacts)
        object.__setattr__(self, "produced_artifacts", normalized_produced_artifacts)


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """
    Immutable report from the output-verification layer.
    """

    subject_id: str
    verified_at: datetime
    status: VerificationStatus
    issues: tuple[VerificationIssue, ...] = field(default_factory=tuple)

    def passed(self) -> bool:
        """
        Return True when the verification status is PASSED.
        """
        return self.status == VerificationStatus.PASSED

    def filter_by_severity(
        self,
        severity: EvaluationSeverity,
    ) -> tuple[VerificationIssue, ...]:
        """
        Return issues matching one severity level.
        """
        return tuple(issue for issue in self.issues if issue.severity == severity)


class OutputVerifier:
    """
    Deterministic output-verification layer for BlackFox.

    This verifier combines expected artifacts, evaluation outcomes, and
    optional regression results into one normalized verification report.
    """

    def verify(self, context: VerificationContext) -> VerificationReport:
        """
        Verify one subject and return a normalized report.
        """
        issues: list[VerificationIssue] = []

        issues.extend(_verify_artifacts(context))
        issues.extend(_verify_evaluations(context))
        issues.extend(_verify_regression(context))

        status = _status_from_issues(tuple(issues))

        return VerificationReport(
            subject_id=context.subject_id,
            verified_at=_utc_now(),
            status=status,
            issues=tuple(issues),
        )


def _verify_artifacts(context: VerificationContext) -> tuple[VerificationIssue, ...]:
    if not context.expected_artifacts:
        return ()

    produced = set(context.produced_artifacts)
    missing = tuple(
        artifact
        for artifact in context.expected_artifacts
        if artifact not in produced
    )
    if not missing:
        return ()

    return (
        VerificationIssue(
            code="verification.missing_artifact",
            severity=EvaluationSeverity.ERROR,
            summary="Expected artifacts were not produced.",
            details="Missing artifacts: " + ", ".join(missing),
        ),
    )


def _verify_evaluations(context: VerificationContext) -> tuple[VerificationIssue, ...]:
    if not context.evaluation_results:
        return (
            VerificationIssue(
                code="verification.no_evaluations",
                severity=EvaluationSeverity.WARNING,
                summary="No evaluation results were supplied for verification.",
            ),
        )

    issues: list[VerificationIssue] = []

    for result in context.evaluation_results:
        if result.status == EvaluationStatus.FAILED:
            issues.append(
                VerificationIssue(
                    code="verification.evaluation_failed",
                    severity=EvaluationSeverity.ERROR,
                    summary=(
                        f"Evaluation '{result.evaluator_name}' failed verification."
                    ),
                    details=f"score={result.score}",
                )
            )
        elif result.status == EvaluationStatus.NEEDS_REVIEW:
            issues.append(
                VerificationIssue(
                    code="verification.evaluation_needs_review",
                    severity=EvaluationSeverity.WARNING,
                    summary=(
                        f"Evaluation '{result.evaluator_name}' requires review."
                    ),
                    details=f"score={result.score}",
                )
            )

    return tuple(issues)


def _verify_regression(context: VerificationContext) -> tuple[VerificationIssue, ...]:
    report = context.regression_report
    if report is None:
        return ()

    if report.status == RegressionStatus.PASSED:
        return ()

    if report.status == RegressionStatus.FAILED:
        return (
            VerificationIssue(
                code="verification.regression_failed",
                severity=EvaluationSeverity.ERROR,
                summary="Regression run reported test failures.",
                details=(
                    f"tests={report.tests}, failures={report.failures}, "
                    f"errors={report.errors}"
                ),
            ),
        )

    return (
        VerificationIssue(
            code="verification.regression_error",
            severity=EvaluationSeverity.ERROR,
            summary="Regression run reported execution or report errors.",
            details=", ".join(report.notes) if report.notes else None,
        ),
    )


def _status_from_issues(
    issues: tuple[VerificationIssue, ...],
) -> VerificationStatus:
    severities = {issue.severity for issue in issues}
    if EvaluationSeverity.ERROR in severities:
        return VerificationStatus.FAILED
    if EvaluationSeverity.WARNING in severities:
        return VerificationStatus.NEEDS_REVIEW
    return VerificationStatus.PASSED


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Output verification {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Output verification {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_strings(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_text(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
