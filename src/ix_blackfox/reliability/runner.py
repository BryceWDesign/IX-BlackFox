from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.reliability.adversarial import AdversarialReliabilityHarness
from ix_blackfox.reliability.metrics import (
    ReliabilityMetricsCollector,
    ReliabilityMetricsSummary,
    RepairMetricObservation,
    RepairMetricOutcome,
)
from ix_blackfox.reliability.models import (
    ReliabilityFinding,
    ReliabilityFindingSeverity,
    ReliabilityMetric,
    ReliabilityMetricUnit,
    ReliabilityReport,
    ReliabilityScenario,
    ReliabilityScenarioResult,
    ReliabilityScenarioStatus,
    ReliabilityScenarioSuite,
)
from ix_blackfox.reliability.scenarios import (
    WAVE4_FULL_SUITE_ID,
    ReliabilityScenarioRegistry,
)


@dataclass(frozen=True, slots=True)
class ReliabilityLabRunConfig:
    """
    Configuration for one Wave 4 reliability lab run.

    The runner is evidence-first. It can evaluate built-in adversarial probes
    directly because they are deterministic and non-executing. Core repair
    scenarios require supplied observations or explicit scenario results; the
    runner marks missing core evidence as skipped instead of fabricating success.
    """

    suite_id: str = WAVE4_FULL_SUITE_ID
    include_adversarial_harness: bool = True
    require_external_evidence_for_core: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "suite_id", _normalize_token(self.suite_id, label="suite_id"))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class ReliabilityLabRunResult:
    """
    Complete result object for one Wave 4 reliability lab run.
    """

    report: ReliabilityReport
    metrics_summary: ReliabilityMetricsSummary
    observations: tuple[RepairMetricObservation, ...]
    external_results: tuple[ReliabilityScenarioResult, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "external_results", tuple(self.external_results))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.report.passed

    @property
    def decision(self) -> str:
        return self.report.decision.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "decision": self.decision,
            "report": self.report.to_dict(),
            "metrics_summary": self.metrics_summary.to_dict(),
            "observations": [observation.to_dict() for observation in self.observations],
            "external_results": [result.to_dict() for result in self.external_results],
            "metadata": dict(self.metadata),
        }


class ReliabilityLabRunner:
    """
    Wave 4 reliability lab runner.

    The runner composes:
    - built-in scenario suites,
    - adversarial fail-closed probes,
    - supplied repair observations,
    - supplied external scenario results,
    - aggregated repair and scenario metrics,
    - final ReliabilityReport generation.

    It does not apply patches, run shell commands, mutate workspaces, or claim
    evidence it was not given. That keeps Wave 4 governance auditable.
    """

    def __init__(
        self,
        *,
        registry: ReliabilityScenarioRegistry | None = None,
        adversarial_harness: AdversarialReliabilityHarness | None = None,
        metrics_collector: ReliabilityMetricsCollector | None = None,
    ) -> None:
        self._registry = registry or ReliabilityScenarioRegistry.built_in()
        self._adversarial_harness = adversarial_harness or AdversarialReliabilityHarness()
        self._metrics_collector = metrics_collector or ReliabilityMetricsCollector()

    @property
    def registry(self) -> ReliabilityScenarioRegistry:
        return self._registry

    def run(
        self,
        *,
        config: ReliabilityLabRunConfig | None = None,
        observations: Iterable[RepairMetricObservation] = (),
        external_results: Iterable[ReliabilityScenarioResult] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityLabRunResult:
        """
        Run the configured built-in reliability suite.
        """

        effective_config = config or ReliabilityLabRunConfig()
        suite = self._registry.require_suite(effective_config.suite_id)
        return self.run_suite(
            suite=suite,
            config=effective_config,
            observations=observations,
            external_results=external_results,
            metadata=metadata,
        )

    def run_suite(
        self,
        *,
        suite: ReliabilityScenarioSuite,
        config: ReliabilityLabRunConfig | None = None,
        observations: Iterable[RepairMetricObservation] = (),
        external_results: Iterable[ReliabilityScenarioResult] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityLabRunResult:
        """
        Run a concrete reliability scenario suite.
        """

        effective_config = config or ReliabilityLabRunConfig(suite_id=suite.suite_id)
        observation_tuple = tuple(observations)
        external_result_tuple = tuple(external_results)
        external_result_map = _external_result_map(external_result_tuple)

        scenario_results = tuple(
            self._evaluate_scenario(
                scenario=scenario,
                observations=observation_tuple,
                external_result_map=external_result_map,
                config=effective_config,
            )
            for scenario in suite.scenarios
        )
        metrics_summary = self._metrics_collector.collect(
            observations=observation_tuple,
            scenario_results=scenario_results,
            metadata={
                "suite_id": suite.suite_id,
                "runner": "wave4-reliability-lab",
            },
        )
        report = ReliabilityReport.create(
            suite=suite,
            results=scenario_results,
            findings=metrics_summary.findings,
            metadata={
                "runner": "wave4-reliability-lab",
                "suite_id": suite.suite_id,
                "config": _config_payload(effective_config),
                "metrics_summary": metrics_summary.to_dict(),
                **dict(metadata or {}),
            },
        )
        return ReliabilityLabRunResult(
            report=report,
            metrics_summary=metrics_summary,
            observations=observation_tuple,
            external_results=external_result_tuple,
            metadata={
                "runner": "wave4-reliability-lab",
                "suite_id": suite.suite_id,
                **dict(metadata or {}),
            },
        )

    def _evaluate_scenario(
        self,
        *,
        scenario: ReliabilityScenario,
        observations: tuple[RepairMetricObservation, ...],
        external_result_map: Mapping[str, ReliabilityScenarioResult],
        config: ReliabilityLabRunConfig,
    ) -> ReliabilityScenarioResult:
        external_result = external_result_map.get(scenario.scenario_id)
        if external_result is not None:
            return external_result

        if config.include_adversarial_harness:
            adversarial_evaluation = self._adversarial_harness.evaluate_scenario(scenario)
            if adversarial_evaluation is not None:
                return adversarial_evaluation.to_scenario_result()

        return _evaluate_core_scenario_from_observations(
            scenario=scenario,
            observations=observations,
            require_external_evidence=config.require_external_evidence_for_core,
        )


def _evaluate_core_scenario_from_observations(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
    require_external_evidence: bool,
) -> ReliabilityScenarioResult:
    if scenario.scenario_id == "safe-patch-success":
        return _evaluate_safe_patch_success(scenario=scenario, observations=observations)

    if scenario.scenario_id == "missing-evidence-rejection":
        return _evaluate_missing_evidence_rejection(
            scenario=scenario,
            observations=observations,
        )

    if scenario.scenario_id == "regression-detection":
        return _evaluate_regression_detection(scenario=scenario, observations=observations)

    if scenario.scenario_id == "incomplete-repair-rejection":
        return _evaluate_incomplete_repair_rejection(
            scenario=scenario,
            observations=observations,
        )

    if require_external_evidence:
        return _skipped_result(
            scenario=scenario,
            code="scenario-requires-external-evidence",
            summary=(
                "Scenario requires explicit external evidence and no matching "
                "scenario result was supplied."
            ),
        )

    return _skipped_result(
        scenario=scenario,
        code="scenario-not-executable-by-runner",
        summary="Scenario has no built-in runner evaluator.",
    )


def _evaluate_safe_patch_success(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
) -> ReliabilityScenarioResult:
    accepted_observations = tuple(
        observation
        for observation in observations
        if observation.accepted
        and observation.evidence_completeness_ratio == 1.0
        and observation.receipt_completeness_ratio == 1.0
    )

    if not accepted_observations:
        return _skipped_result(
            scenario=scenario,
            code="safe-patch-success-evidence-missing",
            summary=(
                "No accepted repair observation with complete evidence and "
                "receipts was supplied."
            ),
        )

    return _passed_from_observations(
        scenario=scenario,
        observations=accepted_observations,
        code="safe-patch-success-observed",
        summary="Accepted repair observation with complete evidence and receipts was supplied.",
    )


def _evaluate_missing_evidence_rejection(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
) -> ReliabilityScenarioResult:
    incomplete_observations = tuple(
        observation
        for observation in observations
        if observation.evidence_completeness_ratio < 1.0
        or observation.receipt_completeness_ratio < 1.0
    )

    if not incomplete_observations:
        return _skipped_result(
            scenario=scenario,
            code="missing-evidence-case-not-observed",
            summary="No incomplete-evidence observation was supplied for rejection testing.",
        )

    return _passed_from_observations(
        scenario=scenario,
        observations=incomplete_observations,
        code="missing-evidence-rejection-observed",
        summary="Incomplete evidence was detected and preserved as reliability evidence.",
    )


def _evaluate_regression_detection(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
) -> ReliabilityScenarioResult:
    regression_observations = tuple(
        observation
        for observation in observations
        if observation.outcome is RepairMetricOutcome.REGRESSION
    )

    if not regression_observations:
        return _skipped_result(
            scenario=scenario,
            code="regression-case-not-observed",
            summary="No regression observation was supplied for regression detection.",
        )

    return _passed_from_observations(
        scenario=scenario,
        observations=regression_observations,
        code="regression-detection-observed",
        summary="Regression observation was detected and preserved as reliability evidence.",
    )


def _evaluate_incomplete_repair_rejection(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
) -> ReliabilityScenarioResult:
    incomplete_outcomes = {
        RepairMetricOutcome.REJECTED,
        RepairMetricOutcome.ERRORED,
        RepairMetricOutcome.INCONCLUSIVE,
    }
    incomplete_observations = tuple(
        observation
        for observation in observations
        if observation.outcome in incomplete_outcomes
    )

    if not incomplete_observations:
        return _skipped_result(
            scenario=scenario,
            code="incomplete-repair-case-not-observed",
            summary="No rejected, errored, or inconclusive repair observation was supplied.",
        )

    return _passed_from_observations(
        scenario=scenario,
        observations=incomplete_observations,
        code="incomplete-repair-rejection-observed",
        summary="Incomplete repair observation was rejected or held inconclusive.",
    )


def _passed_from_observations(
    *,
    scenario: ReliabilityScenario,
    observations: tuple[RepairMetricObservation, ...],
    code: str,
    summary: str,
) -> ReliabilityScenarioResult:
    finding = ReliabilityFinding(
        code=code,
        severity=ReliabilityFindingSeverity.INFO,
        summary=summary,
        scenario_id=scenario.scenario_id,
        metadata={
            "observation_ids": [observation.observation_id for observation in observations],
        },
    )
    evidence_uris = tuple(
        f"observation://{observation.observation_id}"
        for observation in observations
    )
    return ReliabilityScenarioResult.planned(scenario.scenario_id).complete(
        status=ReliabilityScenarioStatus.PASSED,
        findings=(finding,),
        metrics=(
            ReliabilityMetric(
                name="supporting-observation-count",
                value=float(len(observations)),
                unit=ReliabilityMetricUnit.COUNT,
                target=1.0,
                passed=True,
            ),
            ReliabilityMetric(
                name="scenario-evidence-present",
                value=True,
                unit=ReliabilityMetricUnit.BOOLEAN,
                target=True,
                passed=True,
            ),
        ),
        evidence_uris=evidence_uris,
        metadata={
            "runner": "wave4-reliability-lab",
            "source": "repair-metric-observations",
            "expected_status": scenario.expected_status.value,
        },
    )


def _skipped_result(
    *,
    scenario: ReliabilityScenario,
    code: str,
    summary: str,
) -> ReliabilityScenarioResult:
    finding = ReliabilityFinding(
        code=code,
        severity=ReliabilityFindingSeverity.WARNING,
        summary=summary,
        scenario_id=scenario.scenario_id,
        metadata={
            "scenario_id": scenario.scenario_id,
            "required_evidence": list(scenario.required_evidence),
        },
    )
    return ReliabilityScenarioResult.planned(scenario.scenario_id).complete(
        status=ReliabilityScenarioStatus.SKIPPED,
        findings=(finding,),
        metrics=(
            ReliabilityMetric(
                name="scenario-evidence-present",
                value=False,
                unit=ReliabilityMetricUnit.BOOLEAN,
                target=True,
                passed=False,
            ),
        ),
        metadata={
            "runner": "wave4-reliability-lab",
            "reason": code,
            "expected_status": scenario.expected_status.value,
        },
    )


def _external_result_map(
    results: tuple[ReliabilityScenarioResult, ...],
) -> dict[str, ReliabilityScenarioResult]:
    result_map: dict[str, ReliabilityScenarioResult] = {}
    for result in results:
        if result.scenario_id in result_map:
            raise ValueError(
                "External reliability scenario results must be unique by scenario_id: "
                f"{result.scenario_id!r}."
            )
        result_map[result.scenario_id] = result
    return result_map


def _config_payload(config: ReliabilityLabRunConfig) -> dict[str, Any]:
    return {
        "suite_id": config.suite_id,
        "include_adversarial_harness": config.include_adversarial_harness,
        "require_external_evidence_for_core": config.require_external_evidence_for_core,
        "metadata": dict(config.metadata),
    }


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned
