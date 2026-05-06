from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.reliability.models import (
    ReliabilityFinding,
    ReliabilityFindingSeverity,
    ReliabilityMetric,
    ReliabilityMetricUnit,
    ReliabilityScenarioResult,
    ReliabilityScenarioStatus,
)


class RepairMetricOutcome(StrEnum):
    """
    Normalized outcome for one repair attempt or reliability event.
    """

    ATTEMPTED = auto()
    ACCEPTED = auto()
    REJECTED = auto()
    BLOCKED_UNSAFE = auto()
    REGRESSION = auto()
    ERRORED = auto()
    INCONCLUSIVE = auto()


@dataclass(frozen=True, slots=True)
class RepairMetricObservation:
    """
    One repair-oriented observation consumed by the Wave 4 metrics collector.
    """

    outcome: RepairMetricOutcome
    observation_id: str = field(default_factory=lambda: f"repair-observation-{uuid4().hex}")
    scenario_id: str | None = None
    patch_id: str | None = None
    attempt_index: int = 0
    retry_count: int = 0
    evidence_required: tuple[str, ...] = field(default_factory=tuple)
    evidence_present: tuple[str, ...] = field(default_factory=tuple)
    receipt_required: bool = True
    receipt_present: bool = False
    duration_ms: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        if self.attempt_index < 0:
            raise ValueError("attempt_index must be non-negative.")
        if self.retry_count < 0:
            raise ValueError("retry_count must be non-negative.")
        if self.duration_ms is not None and self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative when provided.")

        object.__setattr__(
            self,
            "observation_id",
            _normalize_token(self.observation_id, label="observation_id"),
        )
        object.__setattr__(
            self,
            "scenario_id",
            _normalize_optional_token(self.scenario_id, label="scenario_id"),
        )
        object.__setattr__(
            self,
            "patch_id",
            _normalize_optional_token(self.patch_id, label="patch_id"),
        )
        object.__setattr__(
            self,
            "evidence_required",
            _normalize_text_tuple(self.evidence_required, label="evidence_required"),
        )
        object.__setattr__(
            self,
            "evidence_present",
            _normalize_text_tuple(self.evidence_present, label="evidence_present"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.created_at, label="created_at")

    @property
    def accepted(self) -> bool:
        return self.outcome is RepairMetricOutcome.ACCEPTED

    @property
    def rejected(self) -> bool:
        return self.outcome in {
            RepairMetricOutcome.REJECTED,
            RepairMetricOutcome.BLOCKED_UNSAFE,
            RepairMetricOutcome.REGRESSION,
            RepairMetricOutcome.ERRORED,
            RepairMetricOutcome.INCONCLUSIVE,
        }

    @property
    def blocked_unsafe(self) -> bool:
        return self.outcome is RepairMetricOutcome.BLOCKED_UNSAFE

    @property
    def evidence_completeness_ratio(self) -> float:
        if not self.evidence_required:
            return 1.0

        present = set(self.evidence_present)
        required = set(self.evidence_required)
        return len(required.intersection(present)) / len(required)

    @property
    def receipt_completeness_ratio(self) -> float:
        if not self.receipt_required:
            return 1.0
        return 1.0 if self.receipt_present else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "outcome": self.outcome.value,
            "scenario_id": self.scenario_id,
            "patch_id": self.patch_id,
            "attempt_index": self.attempt_index,
            "retry_count": self.retry_count,
            "evidence_required": list(self.evidence_required),
            "evidence_present": list(self.evidence_present),
            "evidence_completeness_ratio": self.evidence_completeness_ratio,
            "receipt_required": self.receipt_required,
            "receipt_present": self.receipt_present,
            "receipt_completeness_ratio": self.receipt_completeness_ratio,
            "duration_ms": self.duration_ms,
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        duration_ms = payload.get("duration_ms")
        if duration_ms is not None and not isinstance(duration_ms, int):
            raise TypeError("duration_ms must be an integer or null.")

        return cls(
            observation_id=str(
                payload.get("observation_id", f"repair-observation-{uuid4().hex}")
            ),
            outcome=RepairMetricOutcome(_require_text(payload, "outcome")),
            scenario_id=_optional_text(payload, "scenario_id"),
            patch_id=_optional_text(payload, "patch_id"),
            attempt_index=int(payload.get("attempt_index", 0)),
            retry_count=int(payload.get("retry_count", 0)),
            evidence_required=_string_tuple(
                payload.get("evidence_required", ()),
                "evidence_required",
            ),
            evidence_present=_string_tuple(
                payload.get("evidence_present", ()),
                "evidence_present",
            ),
            receipt_required=bool(payload.get("receipt_required", True)),
            receipt_present=bool(payload.get("receipt_present", False)),
            duration_ms=duration_ms,
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
            created_at=_datetime_from_payload(payload, "created_at"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityMetricsSummary:
    """
    Aggregated Wave 4 repair and scenario metrics.
    """

    observations: tuple[RepairMetricObservation, ...]
    scenario_results: tuple[ReliabilityScenarioResult, ...]
    metrics: tuple[ReliabilityMetric, ...]
    findings: tuple[ReliabilityFinding, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "scenario_results", tuple(self.scenario_results))
        object.__setattr__(self, "metrics", tuple(self.metrics))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.created_at, label="created_at")

    def metric_by_name(self, name: str) -> ReliabilityMetric:
        normalized = _normalize_token(name, label="name")
        for metric in self.metrics:
            if metric.name == normalized:
                return metric
        raise KeyError(f"Unknown reliability metric: {name!r}.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [observation.to_dict() for observation in self.observations],
            "scenario_results": [result.to_dict() for result in self.scenario_results],
            "metrics": [metric.to_dict() for metric in self.metrics],
            "findings": [finding.to_dict() for finding in self.findings],
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
        }


class ReliabilityMetricsCollector:
    """
    Deterministic Wave 4 collector for repair and scenario quality metrics.
    """

    def collect(
        self,
        *,
        observations: Iterable[RepairMetricObservation] = (),
        scenario_results: Iterable[ReliabilityScenarioResult] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityMetricsSummary:
        observation_tuple = tuple(observations)
        scenario_result_tuple = tuple(scenario_results)
        metrics = (
            *_repair_metrics(observation_tuple),
            *_scenario_metrics(scenario_result_tuple),
        )
        findings = (
            *_repair_findings(observation_tuple),
            *_scenario_findings(scenario_result_tuple),
        )
        return ReliabilityMetricsSummary(
            observations=observation_tuple,
            scenario_results=scenario_result_tuple,
            metrics=metrics,
            findings=findings,
            metadata={"collector": "wave4-reliability-metrics", **dict(metadata or {})},
        )

    def collect_from_dicts(
        self,
        *,
        observations: Iterable[Mapping[str, Any]] = (),
        scenario_results: Iterable[Mapping[str, Any]] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityMetricsSummary:
        return self.collect(
            observations=(
                RepairMetricObservation.from_dict(payload)
                for payload in observations
            ),
            scenario_results=(
                ReliabilityScenarioResult.from_dict(payload)
                for payload in scenario_results
            ),
            metadata=metadata,
        )

    def observations_from_repair_report(
        self,
        report_payload: Mapping[str, Any],
    ) -> tuple[RepairMetricObservation, ...]:
        """
        Build metric observations from a serialized ProgrammingRepairRunReport.
        """

        raw_patch_results = report_payload.get("patch_results", ())
        raw_test_results = report_payload.get("test_results", ())
        patch_results = _mapping_sequence(raw_patch_results, "patch_results")
        test_results = _mapping_sequence(raw_test_results, "test_results")
        receipts = _mapping_sequence(
            report_payload.get("repair_receipts", ()),
            "repair_receipts",
        )
        receipt_present = bool(receipts)
        observations: list[RepairMetricObservation] = []

        for index, patch_result in enumerate(patch_results):
            status = str(patch_result.get("status", "")).strip().lower()
            output = patch_result.get("output", {})
            patch_id = _patch_id_from_output(output)
            outcome = _outcome_from_patch_status(status)
            observations.append(
                RepairMetricObservation(
                    outcome=outcome,
                    patch_id=patch_id,
                    attempt_index=index,
                    retry_count=max(0, index),
                    evidence_required=("patch-apply-report", "receipt-ledger"),
                    evidence_present=_present_evidence_from_result(
                        patch_result,
                        receipt_present=receipt_present,
                    ),
                    receipt_required=True,
                    receipt_present=receipt_present,
                    metadata={"source": "programming_repair.patch_result", "status": status},
                )
            )

        for index, test_result in enumerate(test_results):
            status = str(test_result.get("status", "")).strip().lower()
            observations.append(
                RepairMetricObservation(
                    outcome=_outcome_from_test_status(status),
                    attempt_index=index,
                    retry_count=max(0, index),
                    evidence_required=("test-run-result", "receipt-ledger"),
                    evidence_present=_present_evidence_from_result(
                        test_result,
                        receipt_present=receipt_present,
                    ),
                    receipt_required=True,
                    receipt_present=receipt_present,
                    metadata={"source": "programming_repair.test_result", "status": status},
                )
            )

        return tuple(observations)


def _repair_metrics(
    observations: tuple[RepairMetricObservation, ...],
) -> tuple[ReliabilityMetric, ...]:
    attempted_count = len(observations)
    accepted_count = sum(1 for observation in observations if observation.accepted)
    rejected_count = sum(1 for observation in observations if observation.rejected)
    blocked_count = sum(1 for observation in observations if observation.blocked_unsafe)
    regression_count = sum(
        1 for observation in observations if observation.outcome is RepairMetricOutcome.REGRESSION
    )
    retry_count = sum(observation.retry_count for observation in observations)
    evidence_ratio = _average(
        observation.evidence_completeness_ratio for observation in observations
    )
    receipt_ratio = _average(
        observation.receipt_completeness_ratio for observation in observations
    )
    time_to_green = _time_to_green_ms(observations)

    return (
        ReliabilityMetric(
            name="repair-attempt-count",
            value=float(attempted_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=1.0,
            passed=attempted_count > 0,
        ),
        ReliabilityMetric(
            name="repair-accepted-count",
            value=float(accepted_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=1.0,
            passed=accepted_count > 0 if attempted_count else False,
        ),
        ReliabilityMetric(
            name="repair-rejected-count",
            value=float(rejected_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=rejected_count == 0,
        ),
        ReliabilityMetric(
            name="unsafe-block-count",
            value=float(blocked_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=blocked_count == 0,
        ),
        ReliabilityMetric(
            name="regression-count",
            value=float(regression_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=regression_count == 0,
        ),
        ReliabilityMetric(
            name="retry-count",
            value=float(retry_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=retry_count == 0,
        ),
        ReliabilityMetric(
            name="evidence-completeness-ratio",
            value=evidence_ratio,
            unit=ReliabilityMetricUnit.RATIO,
            target=1.0,
            passed=evidence_ratio == 1.0,
        ),
        ReliabilityMetric(
            name="receipt-completeness-ratio",
            value=receipt_ratio,
            unit=ReliabilityMetricUnit.RATIO,
            target=1.0,
            passed=receipt_ratio == 1.0,
        ),
        ReliabilityMetric(
            name="time-to-green-ms",
            value=float(time_to_green or 0),
            unit=ReliabilityMetricUnit.MILLISECONDS,
            target=0.0,
            passed=time_to_green is not None,
            metadata={"not_observed_value": time_to_green is None},
        ),
    )


def _scenario_metrics(
    scenario_results: tuple[ReliabilityScenarioResult, ...],
) -> tuple[ReliabilityMetric, ...]:
    scenario_count = len(scenario_results)
    passed_count = sum(
        1 for result in scenario_results if result.status is ReliabilityScenarioStatus.PASSED
    )
    failed_count = sum(
        1 for result in scenario_results if result.status is ReliabilityScenarioStatus.FAILED
    )
    blocked_count = sum(
        1 for result in scenario_results if result.status is ReliabilityScenarioStatus.BLOCKED
    )
    errored_count = sum(
        1 for result in scenario_results if result.status is ReliabilityScenarioStatus.ERRORED
    )
    pass_ratio = _ratio(passed_count, scenario_count)

    return (
        ReliabilityMetric(
            name="scenario-count",
            value=float(scenario_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=1.0,
            passed=scenario_count > 0,
        ),
        ReliabilityMetric(
            name="scenario-pass-ratio",
            value=pass_ratio,
            unit=ReliabilityMetricUnit.RATIO,
            target=1.0,
            passed=pass_ratio == 1.0 if scenario_count else False,
        ),
        ReliabilityMetric(
            name="scenario-fail-count",
            value=float(failed_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=failed_count == 0,
        ),
        ReliabilityMetric(
            name="scenario-block-count",
            value=float(blocked_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=blocked_count == 0,
        ),
        ReliabilityMetric(
            name="scenario-error-count",
            value=float(errored_count),
            unit=ReliabilityMetricUnit.COUNT,
            target=0.0,
            passed=errored_count == 0,
        ),
    )


def _repair_findings(
    observations: tuple[RepairMetricObservation, ...],
) -> tuple[ReliabilityFinding, ...]:
    findings: list[ReliabilityFinding] = []
    for observation in observations:
        if observation.evidence_completeness_ratio < 1.0:
            findings.append(
                ReliabilityFinding(
                    code="repair-evidence-incomplete",
                    severity=ReliabilityFindingSeverity.ERROR,
                    summary="Repair observation is missing required evidence.",
                    scenario_id=observation.scenario_id,
                    metadata=observation.to_dict(),
                )
            )
        if observation.receipt_completeness_ratio < 1.0:
            findings.append(
                ReliabilityFinding(
                    code="repair-receipt-incomplete",
                    severity=ReliabilityFindingSeverity.ERROR,
                    summary="Repair observation is missing required receipt evidence.",
                    scenario_id=observation.scenario_id,
                    metadata=observation.to_dict(),
                )
            )
        if observation.blocked_unsafe:
            findings.append(
                ReliabilityFinding(
                    code="unsafe-repair-blocked",
                    severity=ReliabilityFindingSeverity.INFO,
                    summary="Unsafe repair attempt was blocked by reliability gates.",
                    scenario_id=observation.scenario_id,
                    metadata=observation.to_dict(),
                )
            )
    return tuple(findings)


def _scenario_findings(
    scenario_results: tuple[ReliabilityScenarioResult, ...],
) -> tuple[ReliabilityFinding, ...]:
    findings: list[ReliabilityFinding] = []
    for result in scenario_results:
        if result.status is ReliabilityScenarioStatus.PASSED:
            continue
        severity = (
            ReliabilityFindingSeverity.CRITICAL
            if result.status is ReliabilityScenarioStatus.ERRORED
            else ReliabilityFindingSeverity.ERROR
        )
        findings.append(
            ReliabilityFinding(
                code="scenario-not-passed",
                severity=severity,
                summary=f"Reliability scenario {result.scenario_id} ended as {result.status.value}.",
                scenario_id=result.scenario_id,
                metadata={"scenario_result": result.to_dict()},
            )
        )
    return tuple(findings)


def _time_to_green_ms(observations: tuple[RepairMetricObservation, ...]) -> int | None:
    elapsed = 0
    saw_duration = False
    for observation in observations:
        if observation.duration_ms is not None:
            elapsed += observation.duration_ms
            saw_duration = True
        if observation.accepted:
            return elapsed if saw_duration else observation.duration_ms
    return None


def _average(values: Iterable[float]) -> float:
    value_tuple = tuple(values)
    if not value_tuple:
        return 1.0
    return sum(value_tuple) / len(value_tuple)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _outcome_from_patch_status(status: str) -> RepairMetricOutcome:
    if status == "succeeded":
        return RepairMetricOutcome.ACCEPTED
    if status == "blocked":
        return RepairMetricOutcome.BLOCKED_UNSAFE
    if status in {"timed_out", "failed"}:
        return RepairMetricOutcome.ERRORED
    return RepairMetricOutcome.INCONCLUSIVE


def _outcome_from_test_status(status: str) -> RepairMetricOutcome:
    if status == "succeeded":
        return RepairMetricOutcome.ACCEPTED
    if status == "blocked":
        return RepairMetricOutcome.BLOCKED_UNSAFE
    if status in {"failed", "timed_out"}:
        return RepairMetricOutcome.REGRESSION
    return RepairMetricOutcome.INCONCLUSIVE


def _present_evidence_from_result(
    result: Mapping[str, Any],
    *,
    receipt_present: bool,
) -> tuple[str, ...]:
    evidence: list[str] = []
    if result.get("output"):
        evidence.append("patch-apply-report")
        evidence.append("test-run-result")
    if result.get("artifacts"):
        evidence.append("artifact")
    if receipt_present:
        evidence.append("receipt-ledger")
    return tuple(dict.fromkeys(evidence))


def _patch_id_from_output(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    patch_id = value.get("patch_id")
    if not isinstance(patch_id, str):
        return None
    return patch_id


def _mapping_sequence(value: Any, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of mappings.")
    mappings: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError(f"{field_name} must contain only mappings.")
        mappings.append(item)
    return tuple(mappings)


def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    strings: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        strings.append(item)

    return tuple(strings)


def _normalize_text_tuple(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    return tuple(_normalize_text(value, label=label) for value in values)


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_token(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_token(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _optional_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string when provided.")
    return value


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _datetime_from_payload(payload: Mapping[str, Any], key: str) -> datetime:
    value = payload.get(key)
    if not isinstance(value, str):
        return datetime.now(tz=UTC)
    parsed = datetime.fromisoformat(value)
    _require_aware_datetime(parsed, label=key)
    return parsed


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
