from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.kernel import TaskRecord


class EvaluationStatus(StrEnum):
    """
    Overall evaluation outcome classification.
    """

    PASSED = auto()
    FAILED = auto()
    NEEDS_REVIEW = auto()


class EvaluationSeverity(StrEnum):
    """
    Severity levels for individual evaluation findings.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class EvaluationFinding:
    """
    One evaluation finding emitted by an evaluator.

    Attributes
    ----------
    code:
        Stable machine-readable finding code.
    severity:
        Severity level for the finding.
    summary:
        Short human-readable finding summary.
    details:
        Optional longer diagnostic detail.
    data:
        Optional structured metadata payload.
    """

    code: str
    severity: EvaluationSeverity
    summary: str
    details: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_code = _normalize_identifier(self.code, label="finding code")
        normalized_summary = _normalize_text(self.summary, label="finding summary")
        normalized_details = _normalize_optional_text(self.details)

        object.__setattr__(self, "code", normalized_code)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "details", normalized_details)


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """
    Context supplied to an evaluator.

    Attributes
    ----------
    task:
        Optional task record under evaluation.
    artifacts:
        Optional logical artifact references relevant to the evaluation.
    metadata:
        Optional structured context payload.
    """

    task: TaskRecord | None = None
    artifacts: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """
    Immutable result of one evaluation pass.
    """

    evaluator_name: str
    evaluated_at: datetime
    status: EvaluationStatus
    score: float
    findings: tuple[EvaluationFinding, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_name = _normalize_identifier(
            self.evaluator_name,
            label="evaluator name",
        )
        normalized_score = float(self.score)
        if not 0.0 <= normalized_score <= 1.0:
            raise ValueError("Evaluation score must be between 0.0 and 1.0.")

        object.__setattr__(self, "evaluator_name", normalized_name)
        object.__setattr__(self, "score", normalized_score)

    def passed(self) -> bool:
        """
        Return True when the evaluation status is PASSED.
        """
        return self.status == EvaluationStatus.PASSED

    def filter_by_severity(
        self,
        severity: EvaluationSeverity,
    ) -> tuple[EvaluationFinding, ...]:
        """
        Return findings matching one severity level.
        """
        return tuple(
            finding for finding in self.findings if finding.severity == severity
        )


class BaseEvaluator(ABC):
    """
    Base protocol for BlackFox evaluators.
    """

    @property
    @abstractmethod
    def evaluator_name(self) -> str:
        """
        Stable internal evaluator name.
        """

    @abstractmethod
    def evaluate(self, context: EvaluationContext) -> EvaluationResult:
        """
        Evaluate one context and return a normalized result.
        """


class RuleBasedEvaluator(BaseEvaluator):
    """
    Small deterministic evaluator for rule-based checks.

    Rules are functions that accept an EvaluationContext and either return
    an EvaluationFinding or None. Any ERROR finding fails the evaluation.
    Any WARNING finding produces NEEDS_REVIEW unless an ERROR is present.
    """

    def __init__(
        self,
        *,
        evaluator_name: str,
        rules: tuple[EvaluationRule, ...],
        passing_score: float = 1.0,
        review_score: float = 0.5,
        failing_score: float = 0.0,
    ) -> None:
        normalized_name = _normalize_identifier(
            evaluator_name,
            label="evaluator name",
        )
        if not rules:
            raise ValueError("Rule-based evaluator must define at least one rule.")
        self._evaluator_name = normalized_name
        self._rules = rules
        self._passing_score = _normalize_score(passing_score)
        self._review_score = _normalize_score(review_score)
        self._failing_score = _normalize_score(failing_score)

    @property
    def evaluator_name(self) -> str:
        return self._evaluator_name

    def evaluate(self, context: EvaluationContext) -> EvaluationResult:
        findings: list[EvaluationFinding] = []

        for rule in self._rules:
            finding = rule(context)
            if finding is not None:
                findings.append(finding)

        status = _status_from_findings(tuple(findings))
        score = _score_for_status(
            status=status,
            passing_score=self._passing_score,
            review_score=self._review_score,
            failing_score=self._failing_score,
        )

        return EvaluationResult(
            evaluator_name=self._evaluator_name,
            evaluated_at=_utc_now(),
            status=status,
            score=score,
            findings=tuple(findings),
        )


type EvaluationRule = callable


def _status_from_findings(
    findings: tuple[EvaluationFinding, ...],
) -> EvaluationStatus:
    severities = {finding.severity for finding in findings}
    if EvaluationSeverity.ERROR in severities:
        return EvaluationStatus.FAILED
    if EvaluationSeverity.WARNING in severities:
        return EvaluationStatus.NEEDS_REVIEW
    return EvaluationStatus.PASSED


def _score_for_status(
    *,
    status: EvaluationStatus,
    passing_score: float,
    review_score: float,
    failing_score: float,
) -> float:
    if status == EvaluationStatus.PASSED:
        return passing_score
    if status == EvaluationStatus.NEEDS_REVIEW:
        return review_score
    return failing_score


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Evaluation {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Evaluation {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_score(value: float) -> float:
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError("Evaluation score must be between 0.0 and 1.0.")
    return normalized


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
