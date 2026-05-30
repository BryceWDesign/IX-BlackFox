from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Protocol, cast

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


class MetricStatus(StrEnum):
    """Normalized scorecard result for one Wave 10 operating metric."""

    PASSING = auto()
    WARNING = auto()
    FAILING = auto()
    NOT_MEASURED = auto()


class ScorecardMetricKind(StrEnum):
    """Metric families required for Wave 10 measurable operating governance."""

    COVERAGE = auto()
    RISK = auto()
    REVIEW = auto()
    REPLAY = auto()
    POLICY = auto()
    EVIDENCE = auto()


class ScorecardMetric(Protocol):
    """Protocol shared by all scorecard metric records."""

    metric_id: str
    title: str
    mandatory: bool

    @property
    def status(self) -> MetricStatus:
        """Return the metric status."""

    @property
    def blocking(self) -> bool:
        """Return whether this metric blocks final readiness."""

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        """Return the metric finding when the metric is not cleanly passing."""

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-ready metric data."""


@dataclass(frozen=True, slots=True)
class CoverageMetric:
    """Coverage metric for policy, evidence, replay, review, or repo scope coverage."""

    metric_id: str
    title: str
    covered_count: int
    required_count: int
    required_ratio: float = 1.0
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.COVERAGE

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        if self.covered_count < 0:
            raise ValueError("covered_count must not be negative.")
        if self.required_count < 0:
            raise ValueError("required_count must not be negative.")
        if not 0 <= self.required_ratio <= 1:
            raise ValueError("required_ratio must be between 0 and 1.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def ratio(self) -> float:
        if self.required_count == 0:
            return 0.0
        return round(self.covered_count / self.required_count, 4)

    @property
    def status(self) -> MetricStatus:
        if self.required_count == 0:
            return MetricStatus.NOT_MEASURED
        if self.ratio >= self.required_ratio:
            return MetricStatus.PASSING
        return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status in {MetricStatus.FAILING, MetricStatus.NOT_MEASURED}

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.coverage-gap",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Coverage metric {self.metric_id} measured {self.covered_count}/"
                f"{self.required_count} with ratio {self.ratio}; required ratio is "
                f"{self.required_ratio}."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "covered_count": self.covered_count,
            "required_count": self.required_count,
            "required_ratio": self.required_ratio,
            "ratio": self.ratio,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RiskMetric:
    """Risk metric where lower measured risk is better."""

    metric_id: str
    title: str
    risk_score: int
    maximum_allowed_score: int
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.RISK

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        if self.risk_score < 0:
            raise ValueError("risk_score must not be negative.")
        if self.maximum_allowed_score < 0:
            raise ValueError("maximum_allowed_score must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def status(self) -> MetricStatus:
        if self.risk_score <= self.maximum_allowed_score:
            return MetricStatus.PASSING
        return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status is MetricStatus.FAILING

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.risk-threshold-exceeded",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Risk metric {self.metric_id} measured score {self.risk_score}; "
                f"maximum allowed score is {self.maximum_allowed_score}."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "risk_score": self.risk_score,
            "maximum_allowed_score": self.maximum_allowed_score,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReviewMetric:
    """Human-review and separation-of-duties metric."""

    metric_id: str
    title: str
    authoritative_approval_count: int
    required_authoritative_approvals: int
    self_approval_attempt_count: int = 0
    model_approval_attempt_count: int = 0
    system_approval_attempt_count: int = 0
    missing_review_count: int = 0
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.REVIEW

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        for label, value in (
            ("authoritative_approval_count", self.authoritative_approval_count),
            ("required_authoritative_approvals", self.required_authoritative_approvals),
            ("self_approval_attempt_count", self.self_approval_attempt_count),
            ("model_approval_attempt_count", self.model_approval_attempt_count),
            ("system_approval_attempt_count", self.system_approval_attempt_count),
            ("missing_review_count", self.missing_review_count),
        ):
            if value < 0:
                raise ValueError(f"{label} must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def unauthorized_approval_attempt_count(self) -> int:
        return (
            self.self_approval_attempt_count
            + self.model_approval_attempt_count
            + self.system_approval_attempt_count
        )

    @property
    def status(self) -> MetricStatus:
        if self.required_authoritative_approvals == 0:
            return MetricStatus.NOT_MEASURED
        if (
            self.authoritative_approval_count >= self.required_authoritative_approvals
            and self.unauthorized_approval_attempt_count == 0
            and self.missing_review_count == 0
        ):
            return MetricStatus.PASSING
        return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status in {MetricStatus.FAILING, MetricStatus.NOT_MEASURED}

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.review-authority-gap",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Review metric {self.metric_id} has "
                f"{self.authoritative_approval_count}/"
                f"{self.required_authoritative_approvals} authoritative approvals, "
                f"{self.unauthorized_approval_attempt_count} unauthorized approval attempts, "
                f"and {self.missing_review_count} missing reviews."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "authoritative_approval_count": self.authoritative_approval_count,
            "required_authoritative_approvals": self.required_authoritative_approvals,
            "self_approval_attempt_count": self.self_approval_attempt_count,
            "model_approval_attempt_count": self.model_approval_attempt_count,
            "system_approval_attempt_count": self.system_approval_attempt_count,
            "unauthorized_approval_attempt_count": self.unauthorized_approval_attempt_count,
            "missing_review_count": self.missing_review_count,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReplayMetric:
    """Replayability metric for deterministic Wave 10 evidence reproduction."""

    metric_id: str
    title: str
    replay_passed: bool
    required_step_count: int
    executed_step_count: int
    artifact_mismatch_count: int = 0
    missing_artifact_count: int = 0
    network_required_step_count: int = 0
    nondeterministic_step_count: int = 0
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.REPLAY

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        for label, value in (
            ("required_step_count", self.required_step_count),
            ("executed_step_count", self.executed_step_count),
            ("artifact_mismatch_count", self.artifact_mismatch_count),
            ("missing_artifact_count", self.missing_artifact_count),
            ("network_required_step_count", self.network_required_step_count),
            ("nondeterministic_step_count", self.nondeterministic_step_count),
        ):
            if value < 0:
                raise ValueError(f"{label} must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def executed_ratio(self) -> float:
        if self.required_step_count == 0:
            return 0.0
        return round(self.executed_step_count / self.required_step_count, 4)

    @property
    def status(self) -> MetricStatus:
        if self.required_step_count == 0:
            return MetricStatus.NOT_MEASURED
        if (
            self.replay_passed
            and self.executed_step_count >= self.required_step_count
            and self.artifact_mismatch_count == 0
            and self.missing_artifact_count == 0
            and self.network_required_step_count == 0
            and self.nondeterministic_step_count == 0
        ):
            return MetricStatus.PASSING
        return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status in {MetricStatus.FAILING, MetricStatus.NOT_MEASURED}

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.replay-gap",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Replay metric {self.metric_id} did not satisfy deterministic replay: "
                f"passed={self.replay_passed}, executed_ratio={self.executed_ratio}, "
                f"artifact_mismatch_count={self.artifact_mismatch_count}, "
                f"missing_artifact_count={self.missing_artifact_count}."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "replay_passed": self.replay_passed,
            "required_step_count": self.required_step_count,
            "executed_step_count": self.executed_step_count,
            "executed_ratio": self.executed_ratio,
            "artifact_mismatch_count": self.artifact_mismatch_count,
            "missing_artifact_count": self.missing_artifact_count,
            "network_required_step_count": self.network_required_step_count,
            "nondeterministic_step_count": self.nondeterministic_step_count,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PolicyMetric:
    """Policy-pack and gate-result metric."""

    metric_id: str
    title: str
    evaluated_control_count: int
    failed_control_count: int = 0
    warning_control_count: int = 0
    missing_policy_pack_count: int = 0
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.POLICY

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        for label, value in (
            ("evaluated_control_count", self.evaluated_control_count),
            ("failed_control_count", self.failed_control_count),
            ("warning_control_count", self.warning_control_count),
            ("missing_policy_pack_count", self.missing_policy_pack_count),
        ):
            if value < 0:
                raise ValueError(f"{label} must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def status(self) -> MetricStatus:
        if self.evaluated_control_count == 0:
            return MetricStatus.NOT_MEASURED
        if self.failed_control_count > 0 or self.missing_policy_pack_count > 0:
            return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING
        if self.warning_control_count > 0:
            return MetricStatus.WARNING
        return MetricStatus.PASSING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status in {MetricStatus.FAILING, MetricStatus.NOT_MEASURED}

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.policy-gap",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Policy metric {self.metric_id} has {self.failed_control_count} "
                f"failed controls, {self.warning_control_count} warning controls, "
                f"and {self.missing_policy_pack_count} missing policy packs."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "evaluated_control_count": self.evaluated_control_count,
            "failed_control_count": self.failed_control_count,
            "warning_control_count": self.warning_control_count,
            "missing_policy_pack_count": self.missing_policy_pack_count,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceMetric:
    """Evidence inventory and trust metric."""

    metric_id: str
    title: str
    required_artifact_count: int
    trusted_artifact_count: int
    missing_artifact_count: int = 0
    stale_artifact_count: int = 0
    untrusted_artifact_count: int = 0
    schema_invalid_count: int = 0
    severity_on_gap: OperatingSeverity = OperatingSeverity.CRITICAL
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    kind: ScorecardMetricKind = ScorecardMetricKind.EVIDENCE

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", normalize_identifier(self.metric_id, label="metric_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        for label, value in (
            ("required_artifact_count", self.required_artifact_count),
            ("trusted_artifact_count", self.trusted_artifact_count),
            ("missing_artifact_count", self.missing_artifact_count),
            ("stale_artifact_count", self.stale_artifact_count),
            ("untrusted_artifact_count", self.untrusted_artifact_count),
            ("schema_invalid_count", self.schema_invalid_count),
        ):
            if value < 0:
                raise ValueError(f"{label} must not be negative.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def trusted_ratio(self) -> float:
        if self.required_artifact_count == 0:
            return 0.0
        return round(self.trusted_artifact_count / self.required_artifact_count, 4)

    @property
    def status(self) -> MetricStatus:
        if self.required_artifact_count == 0:
            return MetricStatus.NOT_MEASURED
        if (
            self.missing_artifact_count > 0
            or self.untrusted_artifact_count > 0
            or self.schema_invalid_count > 0
        ):
            return MetricStatus.FAILING if self.mandatory else MetricStatus.WARNING
        if self.stale_artifact_count > 0 or self.trusted_artifact_count < self.required_artifact_count:
            return MetricStatus.WARNING
        return MetricStatus.PASSING

    @property
    def blocking(self) -> bool:
        return self.mandatory and self.status in {MetricStatus.FAILING, MetricStatus.NOT_MEASURED}

    def to_finding(self, *, scorecard_id: str) -> OperatingFinding | None:
        if self.status is MetricStatus.PASSING:
            return None
        return scorecard_finding(
            scorecard_id=scorecard_id,
            metric_id=self.metric_id,
            code="operating.scorecard.evidence-gap",
            severity=self.severity_on_gap if self.blocking else OperatingSeverity.MEDIUM,
            summary=(
                f"Evidence metric {self.metric_id} has trusted_ratio={self.trusted_ratio}, "
                f"missing_artifact_count={self.missing_artifact_count}, "
                f"stale_artifact_count={self.stale_artifact_count}, "
                f"untrusted_artifact_count={self.untrusted_artifact_count}, "
                f"schema_invalid_count={self.schema_invalid_count}."
            ),
            blocking=self.blocking,
            metadata=self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_id": self.metric_id,
            "kind": self.kind.value,
            "title": self.title,
            "required_artifact_count": self.required_artifact_count,
            "trusted_artifact_count": self.trusted_artifact_count,
            "trusted_ratio": self.trusted_ratio,
            "missing_artifact_count": self.missing_artifact_count,
            "stale_artifact_count": self.stale_artifact_count,
            "untrusted_artifact_count": self.untrusted_artifact_count,
            "schema_invalid_count": self.schema_invalid_count,
            "status": self.status.value,
            "severity_on_gap": self.severity_on_gap.value,
            "mandatory": self.mandatory,
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingScorecard:
    """Buyer-readable Wave 10 measurable operating scorecard."""

    scorecard_id: str
    registry_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    coverage_metrics: tuple[CoverageMetric, ...] = ()
    risk_metrics: tuple[RiskMetric, ...] = ()
    review_metrics: tuple[ReviewMetric, ...] = ()
    replay_metrics: tuple[ReplayMetric, ...] = ()
    policy_metrics: tuple[PolicyMetric, ...] = ()
    evidence_metrics: tuple[EvidenceMetric, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 operating scorecard"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scorecard_id",
            normalize_identifier(self.scorecard_id, label="scorecard_id"),
        )
        object.__setattr__(
            self,
            "registry_id",
            normalize_identifier(self.registry_id, label="registry_id"),
        )
        object.__setattr__(
            self,
            "campaign_id",
            normalize_identifier(self.campaign_id, label="campaign_id"),
        )
        if not self.repository_ids:
            raise ValueError("OperatingScorecard repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        if not self.all_metrics:
            raise ValueError("OperatingScorecard must include at least one metric.")
        metric_ids = [metric.metric_id for metric in self.all_metrics]
        if len(metric_ids) != len(set(metric_ids)):
            raise ValueError("OperatingScorecard metric_id values must be unique.")
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def all_metrics(self) -> tuple[ScorecardMetric, ...]:
        return cast(
            tuple[ScorecardMetric, ...],
            (
                *self.coverage_metrics,
                *self.evidence_metrics,
                *self.policy_metrics,
                *self.risk_metrics,
                *self.replay_metrics,
                *self.review_metrics,
            ),
        )

    @property
    def metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics)

    @property
    def total_metric_count(self) -> int:
        return len(self.all_metrics)

    @property
    def passing_metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics if metric.status is MetricStatus.PASSING)

    @property
    def warning_metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics if metric.status is MetricStatus.WARNING)

    @property
    def failing_metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics if metric.status is MetricStatus.FAILING)

    @property
    def not_measured_metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics if metric.status is MetricStatus.NOT_MEASURED)

    @property
    def blocking_metric_ids(self) -> tuple[str, ...]:
        return tuple(metric.metric_id for metric in self.all_metrics if metric.blocking)

    @property
    def status_counts(self) -> dict[str, int]:
        return {
            MetricStatus.PASSING.value: len(self.passing_metric_ids),
            MetricStatus.WARNING.value: len(self.warning_metric_ids),
            MetricStatus.FAILING.value: len(self.failing_metric_ids),
            MetricStatus.NOT_MEASURED.value: len(self.not_measured_metric_ids),
        }

    @property
    def operating_score(self) -> float:
        values = {
            MetricStatus.PASSING: 100.0,
            MetricStatus.WARNING: 75.0,
            MetricStatus.NOT_MEASURED: 25.0,
            MetricStatus.FAILING: 0.0,
        }
        return round(
            sum(values[metric.status] for metric in self.all_metrics) / len(self.all_metrics),
            2,
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings = tuple(
            finding
            for metric in self.all_metrics
            if (finding := metric.to_finding(scorecard_id=self.scorecard_id)) is not None
        )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.scorecard_id}-operating-scorecard-envelope",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            subject=f"Wave 10 operating scorecard {self.scorecard_id}",
            domains=(
                OperatingDomain.MEASURABLE,
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.REVIEWABLE,
            ),
            findings=self.findings,
            metadata={
                "scorecard_id": self.scorecard_id,
                "registry_id": self.registry_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "metric_ids": list(self.metric_ids),
                "total_metric_count": self.total_metric_count,
                "status_counts": self.status_counts,
                "passing_metric_ids": list(self.passing_metric_ids),
                "warning_metric_ids": list(self.warning_metric_ids),
                "failing_metric_ids": list(self.failing_metric_ids),
                "not_measured_metric_ids": list(self.not_measured_metric_ids),
                "blocking_metric_ids": list(self.blocking_metric_ids),
                "operating_score": self.operating_score,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "scorecard_id": self.scorecard_id,
            "registry_id": self.registry_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "coverage_metrics": [metric.to_dict() for metric in self.coverage_metrics],
            "risk_metrics": [metric.to_dict() for metric in self.risk_metrics],
            "review_metrics": [metric.to_dict() for metric in self.review_metrics],
            "replay_metrics": [metric.to_dict() for metric in self.replay_metrics],
            "policy_metrics": [metric.to_dict() for metric in self.policy_metrics],
            "evidence_metrics": [metric.to_dict() for metric in self.evidence_metrics],
            "metric_ids": list(self.metric_ids),
            "total_metric_count": self.total_metric_count,
            "status_counts": self.status_counts,
            "passing_metric_ids": list(self.passing_metric_ids),
            "warning_metric_ids": list(self.warning_metric_ids),
            "failing_metric_ids": list(self.failing_metric_ids),
            "not_measured_metric_ids": list(self.not_measured_metric_ids),
            "blocking_metric_ids": list(self.blocking_metric_ids),
            "operating_score": self.operating_score,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "generated_by": self.generated_by,
            "metadata": dict(self.metadata),
        }


def scorecard_finding(
    *,
    scorecard_id: str,
    metric_id: str,
    code: str,
    severity: OperatingSeverity,
    summary: str,
    blocking: bool,
    metadata: Mapping[str, Any],
) -> OperatingFinding:
    return OperatingFinding(
        code=code,
        severity=severity,
        summary=summary,
        domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
        blocking=blocking,
        metadata={
            "scorecard_id": scorecard_id,
            "metric_id": metric_id,
            **dict(metadata),
        },
    )
