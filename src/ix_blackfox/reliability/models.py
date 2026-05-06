from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self, cast
from uuid import uuid4


class ReliabilityScenarioKind(StrEnum):
    """
    Canonical scenario family for the Wave 4 reliability lab.
    """

    BASELINE = auto()
    REGRESSION = auto()
    ADVERSARIAL = auto()
    POLICY_GATE = auto()
    REPAIR_LOOP = auto()
    EVIDENCE = auto()


class ReliabilityScenarioStatus(StrEnum):
    """
    Execution status for one reliability scenario.
    """

    PLANNED = auto()
    PASSED = auto()
    FAILED = auto()
    BLOCKED = auto()
    ERRORED = auto()
    SKIPPED = auto()


class ReliabilityFindingSeverity(StrEnum):
    """
    Severity for findings emitted by reliability scenarios and reports.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


class ReliabilityMetricUnit(StrEnum):
    """
    Stable unit vocabulary for reliability metrics.
    """

    COUNT = auto()
    RATIO = auto()
    PERCENT = auto()
    MILLISECONDS = auto()
    BOOLEAN = auto()


class ReliabilityGateDecision(StrEnum):
    """
    Final gate decision for a scenario suite or reliability report.
    """

    PASS = auto()
    FAIL = auto()
    BLOCK = auto()
    INCONCLUSIVE = auto()


@dataclass(frozen=True, slots=True)
class ReliabilityFinding:
    """
    One structured finding from a reliability scenario, suite, or lab run.
    """

    code: str
    severity: ReliabilityFindingSeverity
    summary: str
    scenario_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "scenario_id",
            _normalize_optional_token(self.scenario_id, label="scenario_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.created_at, label="created_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "scenario_id": self.scenario_id,
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=ReliabilityFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            scenario_id=_optional_text(payload, "scenario_id"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
            created_at=_datetime_from_payload(payload, "created_at"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityMetric:
    """
    One named numeric or boolean measurement captured by the reliability lab.
    """

    name: str
    value: float | bool
    unit: ReliabilityMetricUnit
    target: float | bool | None = None
    passed: bool | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_token(self.name, label="name"))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if isinstance(self.value, bool) and self.unit is not ReliabilityMetricUnit.BOOLEAN:
            raise ValueError("Boolean reliability metrics must use BOOLEAN unit.")
        if not isinstance(self.value, bool) and self.unit is ReliabilityMetricUnit.BOOLEAN:
            raise ValueError("BOOLEAN reliability metrics must use a bool value.")
        if self.target is not None and isinstance(self.target, bool) != isinstance(
            self.value,
            bool,
        ):
            raise ValueError("Reliability metric target must match value type.")

    def with_passed(self, passed: bool) -> Self:
        return replace(self, passed=passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit.value,
            "target": self.target,
            "passed": self.passed,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_value = payload.get("value")
        if not isinstance(raw_value, bool | int | float):
            raise TypeError("Reliability metric value must be numeric or boolean.")

        raw_target = payload.get("target")
        if raw_target is not None and not isinstance(raw_target, bool | int | float):
            raise TypeError("Reliability metric target must be numeric, boolean, or null.")

        raw_passed = payload.get("passed")
        if raw_passed is not None and not isinstance(raw_passed, bool):
            raise TypeError("Reliability metric passed must be boolean or null.")

        unit = ReliabilityMetricUnit(_require_text(payload, "unit"))

        value: float | bool
        target: float | bool | None
        if unit is ReliabilityMetricUnit.BOOLEAN:
            if not isinstance(raw_value, bool):
                raise TypeError("BOOLEAN reliability metric value must be boolean.")
            value = raw_value
            target = raw_target if isinstance(raw_target, bool) else None
        else:
            if isinstance(raw_value, bool):
                raise TypeError("Numeric reliability metric value must not be boolean.")
            value = float(raw_value)
            if isinstance(raw_target, bool):
                raise TypeError("Numeric reliability metric target must not be boolean.")
            target = float(raw_target) if raw_target is not None else None

        return cls(
            name=_require_text(payload, "name"),
            value=value,
            unit=unit,
            target=target,
            passed=raw_passed,
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityScenario:
    """
    Declarative scenario contract for Wave 4 reliability-lab execution.
    """

    scenario_id: str
    name: str
    kind: ReliabilityScenarioKind
    objective: str
    acceptance_criteria: tuple[str, ...]
    expected_status: ReliabilityScenarioStatus = ReliabilityScenarioStatus.PASSED
    required_evidence: tuple[str, ...] = field(default_factory=tuple)
    adversarial: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scenario_id",
            _normalize_token(self.scenario_id, label="scenario_id"),
        )
        object.__setattr__(self, "name", _normalize_text(self.name, label="name"))
        object.__setattr__(
            self,
            "objective",
            _normalize_text(self.objective, label="objective"),
        )
        object.__setattr__(
            self,
            "acceptance_criteria",
            _normalize_text_tuple(
                self.acceptance_criteria,
                label="acceptance_criteria",
            ),
        )

        if not self.acceptance_criteria:
            raise ValueError(
                "ReliabilityScenario requires at least one acceptance criterion."
            )

        object.__setattr__(
            self,
            "required_evidence",
            _normalize_text_tuple(self.required_evidence, label="required_evidence"),
        )
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "kind": self.kind.value,
            "objective": self.objective,
            "acceptance_criteria": list(self.acceptance_criteria),
            "expected_status": self.expected_status.value,
            "required_evidence": list(self.required_evidence),
            "adversarial": self.adversarial,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            scenario_id=_require_text(payload, "scenario_id"),
            name=_require_text(payload, "name"),
            kind=ReliabilityScenarioKind(_require_text(payload, "kind")),
            objective=_require_text(payload, "objective"),
            acceptance_criteria=_string_tuple(
                payload.get("acceptance_criteria", ()),
                "acceptance_criteria",
            ),
            expected_status=ReliabilityScenarioStatus(
                str(payload.get("expected_status", ReliabilityScenarioStatus.PASSED.value))
            ),
            required_evidence=_string_tuple(
                payload.get("required_evidence", ()),
                "required_evidence",
            ),
            adversarial=bool(payload.get("adversarial", False)),
            tags=_string_tuple(payload.get("tags", ()), "tags"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityScenarioSuite:
    """
    Named set of scenarios executed together as a reliability lab suite.
    """

    suite_id: str
    name: str
    scenarios: tuple[ReliabilityScenario, ...]
    description: str = "Wave 4 reliability scenario suite."
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "suite_id",
            _normalize_token(self.suite_id, label="suite_id"),
        )
        object.__setattr__(self, "name", _normalize_text(self.name, label="name"))
        object.__setattr__(
            self,
            "description",
            _normalize_text(self.description, label="description"),
        )
        object.__setattr__(self, "scenarios", tuple(self.scenarios))

        if not self.scenarios:
            raise ValueError("ReliabilityScenarioSuite requires at least one scenario.")

        scenario_ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("ReliabilityScenarioSuite scenario ids must be unique.")

        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def scenario_count(self) -> int:
        return len(self.scenarios)

    @property
    def adversarial_count(self) -> int:
        return sum(1 for scenario in self.scenarios if scenario.adversarial)

    def scenario_by_id(self, scenario_id: str) -> ReliabilityScenario:
        normalized = _normalize_token(scenario_id, label="scenario_id")
        for scenario in self.scenarios:
            if scenario.scenario_id == normalized:
                return scenario

        raise KeyError(f"Unknown reliability scenario id: {scenario_id!r}.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "name": self.name,
            "description": self.description,
            "scenario_count": self.scenario_count,
            "adversarial_count": self.adversarial_count,
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        scenarios = tuple(
            ReliabilityScenario.from_dict(raw_scenario)
            for raw_scenario in _mapping_tuple(
                payload.get("scenarios", ()),
                "scenarios",
            )
        )

        return cls(
            suite_id=_require_text(payload, "suite_id"),
            name=_require_text(payload, "name"),
            description=str(
                payload.get("description", "Wave 4 reliability scenario suite.")
            ),
            scenarios=scenarios,
            tags=_string_tuple(payload.get("tags", ()), "tags"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityScenarioResult:
    """
    Result for one reliability scenario execution.
    """

    scenario_id: str
    status: ReliabilityScenarioStatus
    findings: tuple[ReliabilityFinding, ...] = field(default_factory=tuple)
    metrics: tuple[ReliabilityMetric, ...] = field(default_factory=tuple)
    evidence_uris: tuple[str, ...] = field(default_factory=tuple)
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    completed_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scenario_id",
            _normalize_token(self.scenario_id, label="scenario_id"),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metrics", tuple(self.metrics))
        object.__setattr__(
            self,
            "evidence_uris",
            _normalize_text_tuple(self.evidence_uris, label="evidence_uris"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.started_at, label="started_at")

        if self.completed_at is not None:
            _require_aware_datetime(self.completed_at, label="completed_at")
            if self.completed_at < self.started_at:
                raise ValueError("completed_at cannot predate started_at.")

    @classmethod
    def planned(cls, scenario_id: str) -> Self:
        return cls(
            scenario_id=scenario_id,
            status=ReliabilityScenarioStatus.PLANNED,
        )

    def complete(
        self,
        *,
        status: ReliabilityScenarioStatus,
        findings: Iterable[ReliabilityFinding] = (),
        metrics: Iterable[ReliabilityMetric] = (),
        evidence_uris: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return replace(
            self,
            status=status,
            findings=tuple(findings),
            metrics=tuple(metrics),
            evidence_uris=tuple(evidence_uris),
            completed_at=datetime.now(tz=UTC),
            metadata={**dict(self.metadata), **dict(metadata or {})},
        )

    @property
    def passed(self) -> bool:
        return self.status is ReliabilityScenarioStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status in {
            ReliabilityScenarioStatus.FAILED,
            ReliabilityScenarioStatus.ERRORED,
        }

    @property
    def blocked(self) -> bool:
        return self.status is ReliabilityScenarioStatus.BLOCKED

    @property
    def duration_ms(self) -> int | None:
        if self.completed_at is None:
            return None

        return int((self.completed_at - self.started_at).total_seconds() * 1000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "status": self.status.value,
            "passed": self.passed,
            "failed": self.failed,
            "blocked": self.blocked,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": [metric.to_dict() for metric in self.metrics],
            "evidence_uris": list(self.evidence_uris),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        completed_at = payload.get("completed_at")

        return cls(
            scenario_id=_require_text(payload, "scenario_id"),
            status=ReliabilityScenarioStatus(_require_text(payload, "status")),
            findings=tuple(
                ReliabilityFinding.from_dict(raw_finding)
                for raw_finding in _mapping_tuple(
                    payload.get("findings", ()),
                    "findings",
                )
            ),
            metrics=tuple(
                ReliabilityMetric.from_dict(raw_metric)
                for raw_metric in _mapping_tuple(payload.get("metrics", ()), "metrics")
            ),
            evidence_uris=_string_tuple(
                payload.get("evidence_uris", ()),
                "evidence_uris",
            ),
            started_at=_datetime_from_payload(payload, "started_at"),
            completed_at=_parse_optional_datetime(
                completed_at,
                field_name="completed_at",
            ),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityMetricSnapshot:
    """
    Aggregated metrics for one suite/report evaluation.
    """

    scenario_count: int
    passed_count: int
    failed_count: int
    blocked_count: int
    errored_count: int
    skipped_count: int
    metrics: tuple[ReliabilityMetric, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        for field_name in (
            "scenario_count",
            "passed_count",
            "failed_count",
            "blocked_count",
            "errored_count",
            "skipped_count",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} must be non-negative.")

        counted = (
            self.passed_count
            + self.failed_count
            + self.blocked_count
            + self.errored_count
            + self.skipped_count
        )
        if counted > self.scenario_count:
            raise ValueError("Reliability metric counts cannot exceed scenario_count.")

        object.__setattr__(self, "metrics", tuple(self.metrics))
        _require_aware_datetime(self.created_at, label="created_at")

    @classmethod
    def from_results(cls, results: Iterable[ReliabilityScenarioResult]) -> Self:
        result_tuple = tuple(results)
        scenario_count = len(result_tuple)
        passed_count = sum(
            1
            for result in result_tuple
            if result.status is ReliabilityScenarioStatus.PASSED
        )
        failed_count = sum(
            1
            for result in result_tuple
            if result.status is ReliabilityScenarioStatus.FAILED
        )
        blocked_count = sum(
            1
            for result in result_tuple
            if result.status is ReliabilityScenarioStatus.BLOCKED
        )
        errored_count = sum(
            1
            for result in result_tuple
            if result.status is ReliabilityScenarioStatus.ERRORED
        )
        skipped_count = sum(
            1
            for result in result_tuple
            if result.status is ReliabilityScenarioStatus.SKIPPED
        )
        completed_count = (
            passed_count
            + failed_count
            + blocked_count
            + errored_count
            + skipped_count
        )
        pass_ratio = float(passed_count / scenario_count) if scenario_count else 0.0
        completion_ratio = (
            float(completed_count / scenario_count) if scenario_count else 0.0
        )

        return cls(
            scenario_count=scenario_count,
            passed_count=passed_count,
            failed_count=failed_count,
            blocked_count=blocked_count,
            errored_count=errored_count,
            skipped_count=skipped_count,
            metrics=(
                ReliabilityMetric(
                    name="scenario-pass-ratio",
                    value=pass_ratio,
                    unit=ReliabilityMetricUnit.RATIO,
                    target=1.0,
                    passed=pass_ratio == 1.0,
                ),
                ReliabilityMetric(
                    name="scenario-completion-ratio",
                    value=completion_ratio,
                    unit=ReliabilityMetricUnit.RATIO,
                    target=1.0,
                    passed=completion_ratio == 1.0,
                ),
                ReliabilityMetric(
                    name="blocked-scenario-count",
                    value=float(blocked_count),
                    unit=ReliabilityMetricUnit.COUNT,
                    target=0.0,
                    passed=blocked_count == 0,
                ),
            ),
        )

    @property
    def pass_ratio(self) -> float:
        if self.scenario_count == 0:
            return 0.0

        return self.passed_count / self.scenario_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_count": self.scenario_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "blocked_count": self.blocked_count,
            "errored_count": self.errored_count,
            "skipped_count": self.skipped_count,
            "pass_ratio": self.pass_ratio,
            "metrics": [metric.to_dict() for metric in self.metrics],
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            scenario_count=int(payload.get("scenario_count", 0)),
            passed_count=int(payload.get("passed_count", 0)),
            failed_count=int(payload.get("failed_count", 0)),
            blocked_count=int(payload.get("blocked_count", 0)),
            errored_count=int(payload.get("errored_count", 0)),
            skipped_count=int(payload.get("skipped_count", 0)),
            metrics=tuple(
                ReliabilityMetric.from_dict(raw_metric)
                for raw_metric in _mapping_tuple(payload.get("metrics", ()), "metrics")
            ),
            created_at=_datetime_from_payload(payload, "created_at"),
        )


@dataclass(frozen=True, slots=True)
class ReliabilityReport:
    """
    Final serializable Wave 4 reliability lab report.
    """

    report_id: str
    suite: ReliabilityScenarioSuite
    results: tuple[ReliabilityScenarioResult, ...]
    decision: ReliabilityGateDecision
    metric_snapshot: ReliabilityMetricSnapshot
    findings: tuple[ReliabilityFinding, ...] = field(default_factory=tuple)
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    completed_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_token(self.report_id, label="report_id"),
        )
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.started_at, label="started_at")
        _require_aware_datetime(self.completed_at, label="completed_at")

        if self.completed_at < self.started_at:
            raise ValueError("ReliabilityReport completed_at cannot predate started_at.")

        suite_ids = {scenario.scenario_id for scenario in self.suite.scenarios}
        result_ids = {result.scenario_id for result in self.results}
        unknown_result_ids = result_ids.difference(suite_ids)
        if unknown_result_ids:
            unknown = ", ".join(sorted(unknown_result_ids))
            raise ValueError(
                f"ReliabilityReport contains results outside the suite: {unknown}."
            )

    @classmethod
    def create(
        cls,
        *,
        suite: ReliabilityScenarioSuite,
        results: Iterable[ReliabilityScenarioResult],
        findings: Iterable[ReliabilityFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        result_tuple = tuple(results)
        snapshot = ReliabilityMetricSnapshot.from_results(result_tuple)

        return cls(
            report_id=f"reliability-report-{uuid4().hex}",
            suite=suite,
            results=result_tuple,
            decision=_decision_from_results(result_tuple),
            metric_snapshot=snapshot,
            findings=tuple(findings),
            started_at=_earliest_started_at(result_tuple),
            completed_at=datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )

    @property
    def passed(self) -> bool:
        return self.decision is ReliabilityGateDecision.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "suite": self.suite.to_dict(),
            "results": [result.to_dict() for result in self.results],
            "decision": self.decision.value,
            "passed": self.passed,
            "metric_snapshot": self.metric_snapshot.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_suite = payload.get("suite")
        if not isinstance(raw_suite, Mapping):
            raise TypeError("ReliabilityReport suite must be a mapping.")

        raw_snapshot = payload.get("metric_snapshot")
        if not isinstance(raw_snapshot, Mapping):
            raise TypeError("ReliabilityReport metric_snapshot must be a mapping.")

        return cls(
            report_id=_require_text(payload, "report_id"),
            suite=ReliabilityScenarioSuite.from_dict(
                cast(Mapping[str, Any], raw_suite)
            ),
            results=tuple(
                ReliabilityScenarioResult.from_dict(raw_result)
                for raw_result in _mapping_tuple(payload.get("results", ()), "results")
            ),
            decision=ReliabilityGateDecision(_require_text(payload, "decision")),
            metric_snapshot=ReliabilityMetricSnapshot.from_dict(
                cast(Mapping[str, Any], raw_snapshot)
            ),
            findings=tuple(
                ReliabilityFinding.from_dict(raw_finding)
                for raw_finding in _mapping_tuple(
                    payload.get("findings", ()),
                    "findings",
                )
            ),
            started_at=_datetime_from_payload(payload, "started_at"),
            completed_at=_datetime_from_payload(payload, "completed_at"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


def _decision_from_results(
    results: tuple[ReliabilityScenarioResult, ...],
) -> ReliabilityGateDecision:
    if not results:
        return ReliabilityGateDecision.INCONCLUSIVE

    if any(result.status is ReliabilityScenarioStatus.BLOCKED for result in results):
        return ReliabilityGateDecision.BLOCK

    if any(
        result.status
        in {ReliabilityScenarioStatus.FAILED, ReliabilityScenarioStatus.ERRORED}
        for result in results
    ):
        return ReliabilityGateDecision.FAIL

    if all(result.status is ReliabilityScenarioStatus.PASSED for result in results):
        return ReliabilityGateDecision.PASS

    return ReliabilityGateDecision.INCONCLUSIVE


def _earliest_started_at(results: tuple[ReliabilityScenarioResult, ...]) -> datetime:
    if not results:
        return datetime.now(tz=UTC)

    return min(result.started_at for result in results)


def _mapping_tuple(value: Any, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of mappings.")

    mappings: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError(f"{field_name} must contain only mappings.")
        mappings.append(cast(Mapping[str, Any], item))

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
    normalized: list[str] = []
    for value in values:
        normalized.append(_normalize_text(value, label=label))

    return tuple(normalized)


def _normalize_tags(values: Iterable[str]) -> tuple[str, ...]:
    tags: list[str] = []
    seen: set[str] = set()

    for value in values:
        tag = _normalize_token(value, label="tag")
        if tag in seen:
            continue
        tags.append(tag)
        seen.add(tag)

    return tuple(tags)


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

    return _parse_datetime(value, field_name=key)


def _parse_optional_datetime(value: Any, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be an ISO datetime string or null.")

    return _parse_datetime(value, field_name=field_name)


def _parse_datetime(value: str, *, field_name: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    _require_aware_datetime(parsed, label=field_name)
    return parsed


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
