from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Self

from ix_blackfox.reliability.models import (
    ReliabilityScenario,
    ReliabilityScenarioKind,
    ReliabilityScenarioStatus,
    ReliabilityScenarioSuite,
)

WAVE4_CORE_SUITE_ID = "wave4-core-reliability"
WAVE4_ADVERSARIAL_SUITE_ID = "wave4-adversarial-reliability"
WAVE4_FULL_SUITE_ID = "wave4-full-reliability-lab"


class ReliabilityScenarioRegistryError(LookupError):
    """
    Raised when a requested reliability suite or scenario is not registered.
    """


@dataclass(frozen=True, slots=True)
class ReliabilityScenarioRegistry:
    """
    Immutable registry for named Wave 4 reliability scenario suites.
    """

    _suites: Mapping[str, ReliabilityScenarioSuite] = field(default_factory=dict)

    def __post_init__(self) -> None:
        suites = dict(self._suites)
        for suite_id, suite in suites.items():
            if suite_id != suite.suite_id:
                raise ValueError(
                    "ReliabilityScenarioRegistry key must match suite.suite_id: "
                    f"{suite_id!r} != {suite.suite_id!r}."
                )
        object.__setattr__(self, "_suites", suites)

    @classmethod
    def built_in(cls) -> Self:
        return cls(_suites=_suite_mapping(built_in_reliability_suites()))

    @property
    def suite_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._suites))

    @property
    def suites(self) -> tuple[ReliabilityScenarioSuite, ...]:
        return tuple(self._suites[suite_id] for suite_id in self.suite_ids)

    def require_suite(self, suite_id: str) -> ReliabilityScenarioSuite:
        normalized = _normalize_token(suite_id)
        suite = self._suites.get(normalized)
        if suite is None:
            known = ", ".join(self.suite_ids) or "none"
            raise ReliabilityScenarioRegistryError(
                f"Unknown reliability scenario suite {suite_id!r}. Known suites: {known}."
            )
        return suite

    def scenarios(self, *, suite_id: str | None = None) -> tuple[ReliabilityScenario, ...]:
        if suite_id is not None:
            return self.require_suite(suite_id).scenarios

        scenarios: list[ReliabilityScenario] = []
        seen: set[str] = set()
        for suite in self.suites:
            for scenario in suite.scenarios:
                if scenario.scenario_id in seen:
                    continue
                scenarios.append(scenario)
                seen.add(scenario.scenario_id)
        return tuple(scenarios)

    def require_scenario(
        self,
        scenario_id: str,
        *,
        suite_id: str | None = None,
    ) -> ReliabilityScenario:
        normalized = _normalize_token(scenario_id)
        scenarios = self.scenarios(suite_id=suite_id)
        for scenario in scenarios:
            if scenario.scenario_id == normalized:
                return scenario

        scope = f" in suite {suite_id!r}" if suite_id else ""
        raise ReliabilityScenarioRegistryError(
            f"Unknown reliability scenario {scenario_id!r}{scope}."
        )

    def with_suite(self, suite: ReliabilityScenarioSuite) -> Self:
        return type(self)(_suites={**dict(self._suites), suite.suite_id: suite})

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_ids": list(self.suite_ids),
            "suites": [suite.to_dict() for suite in self.suites],
        }


def built_in_reliability_suites() -> tuple[ReliabilityScenarioSuite, ...]:
    """
    Return all built-in Wave 4 suites in deterministic order.
    """

    core_suite = build_wave4_core_suite()
    adversarial_suite = build_wave4_adversarial_suite()
    full_suite = build_wave4_full_suite(
        scenarios=(*core_suite.scenarios, *adversarial_suite.scenarios),
    )
    return (core_suite, adversarial_suite, full_suite)


def build_wave4_core_suite() -> ReliabilityScenarioSuite:
    """
    Build the core non-adversarial reliability scenarios.
    """

    return ReliabilityScenarioSuite(
        suite_id=WAVE4_CORE_SUITE_ID,
        name="Wave 4 Core Reliability Suite",
        description=(
            "Core Wave 4 scenarios for patch success, regression detection, "
            "evidence completeness, and incomplete repair rejection."
        ),
        scenarios=(
            _safe_patch_success_scenario(),
            _regression_detection_scenario(),
            _missing_evidence_rejection_scenario(),
            _incomplete_repair_rejection_scenario(),
        ),
        tags=("wave4", "core", "reliability-lab"),
        metadata={"wave": "4", "suite_family": "core"},
    )


def build_wave4_adversarial_suite() -> ReliabilityScenarioSuite:
    """
    Build adversarial scenarios that prove governance fails closed.
    """

    return ReliabilityScenarioSuite(
        suite_id=WAVE4_ADVERSARIAL_SUITE_ID,
        name="Wave 4 Adversarial Reliability Suite",
        description=(
            "Adversarial Wave 4 scenarios for unsafe patches, path traversal, "
            "policy overrides, and flaky-test containment."
        ),
        scenarios=(
            _rejected_unsafe_patch_scenario(),
            _path_traversal_rejection_scenario(),
            _policy_override_rejection_scenario(),
            _flaky_test_containment_scenario(),
        ),
        tags=("wave4", "adversarial", "fail-closed"),
        metadata={"wave": "4", "suite_family": "adversarial"},
    )


def build_wave4_full_suite(
    *,
    scenarios: Iterable[ReliabilityScenario] | None = None,
) -> ReliabilityScenarioSuite:
    """
    Build the full default Wave 4 reliability lab suite.
    """

    scenario_tuple = tuple(scenarios) if scenarios is not None else (
        *_core_scenarios(),
        *_adversarial_scenarios(),
    )
    return ReliabilityScenarioSuite(
        suite_id=WAVE4_FULL_SUITE_ID,
        name="Wave 4 Full Reliability Lab",
        description=(
            "Complete built-in Wave 4 reliability lab suite covering scenario "
            "success, adversarial rejection, repair metrics, and evidence gates."
        ),
        scenarios=scenario_tuple,
        tags=("wave4", "default", "full", "reliability-lab"),
        metadata={"wave": "4", "suite_family": "full"},
    )


def _core_scenarios() -> tuple[ReliabilityScenario, ...]:
    return (
        _safe_patch_success_scenario(),
        _regression_detection_scenario(),
        _missing_evidence_rejection_scenario(),
        _incomplete_repair_rejection_scenario(),
    )


def _adversarial_scenarios() -> tuple[ReliabilityScenario, ...]:
    return (
        _rejected_unsafe_patch_scenario(),
        _path_traversal_rejection_scenario(),
        _policy_override_rejection_scenario(),
        _flaky_test_containment_scenario(),
    )


def _safe_patch_success_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="safe-patch-success",
        name="Safe Patch Success",
        kind=ReliabilityScenarioKind.REPAIR_LOOP,
        objective=(
            "Verify that a bounded, workspace-local patch can be applied, tested, "
            "receipted, and accepted when all gates pass."
        ),
        acceptance_criteria=(
            "Patch target stays inside the reserved workspace.",
            "Patch application succeeds through the governed patch tool.",
            "Required tests pass after the patch is applied.",
            "Patch and test receipts are present in the reliability report.",
        ),
        expected_status=ReliabilityScenarioStatus.PASSED,
        required_evidence=("patch-apply-report", "test-run-result", "receipt-ledger"),
        tags=("happy-path", "patch", "tests", "receipts"),
        metadata={"risk_intent": "allowed-safe-repair"},
    )


def _rejected_unsafe_patch_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="rejected-unsafe-patch",
        name="Rejected Unsafe Patch",
        kind=ReliabilityScenarioKind.POLICY_GATE,
        objective=(
            "Verify that a destructive or sensitive mutation is blocked before "
            "workspace files are changed."
        ),
        acceptance_criteria=(
            "Unsafe mutation is classified above automatic execution threshold.",
            "Patch application is blocked before filesystem mutation.",
            "The rejection reason is explicit and preserved as evidence.",
        ),
        expected_status=ReliabilityScenarioStatus.BLOCKED,
        required_evidence=("risk-assessment", "policy-decision", "blocked-result"),
        adversarial=True,
        tags=("unsafe-patch", "policy", "blocked", "fail-closed"),
        metadata={"risk_intent": "destructive-mutation-rejection"},
    )


def _flaky_test_containment_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="flaky-test-containment",
        name="Flaky Test Containment",
        kind=ReliabilityScenarioKind.REGRESSION,
        objective=(
            "Verify that unstable test evidence is marked inconclusive or failed "
            "instead of being accepted as a clean repair."
        ),
        acceptance_criteria=(
            "Conflicting test outcomes are detected across repeated observations.",
            "The repair is not marked accepted from a single lucky pass.",
            "The report preserves the unstable test evidence for review.",
        ),
        expected_status=ReliabilityScenarioStatus.FAILED,
        required_evidence=("test-run-history", "flakiness-finding"),
        adversarial=True,
        tags=("flaky-tests", "regression", "evidence-quality"),
        metadata={"risk_intent": "unstable-evidence-containment"},
    )


def _missing_evidence_rejection_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="missing-evidence-rejection",
        name="Missing Evidence Rejection",
        kind=ReliabilityScenarioKind.EVIDENCE,
        objective=(
            "Verify that a repair cannot be accepted when required evidence "
            "artifacts or receipts are missing."
        ),
        acceptance_criteria=(
            "The scenario declares required evidence artifacts.",
            "Missing evidence is detected deterministically.",
            "The final gate decision refuses acceptance without fabricating proof.",
        ),
        expected_status=ReliabilityScenarioStatus.FAILED,
        required_evidence=("patch-apply-report", "test-run-result", "receipt-ledger"),
        tags=("evidence", "receipts", "no-proof-no-pass"),
        metadata={"risk_intent": "missing-evidence-rejection"},
    )


def _path_traversal_rejection_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="path-traversal-rejection",
        name="Path Traversal Rejection",
        kind=ReliabilityScenarioKind.ADVERSARIAL,
        objective=(
            "Verify that a patch path attempting to escape the workspace is "
            "blocked before any file operation is attempted."
        ),
        acceptance_criteria=(
            "Traversal markers are detected in patch input.",
            "The workspace resolver refuses the target path.",
            "No file outside the reserved workspace is read, written, or deleted.",
        ),
        expected_status=ReliabilityScenarioStatus.BLOCKED,
        required_evidence=("path-violation", "blocked-result"),
        adversarial=True,
        tags=("path-traversal", "workspace-boundary", "blocked"),
        metadata={"risk_intent": "workspace-escape-rejection"},
    )


def _policy_override_rejection_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="policy-override-rejection",
        name="Policy Override Rejection",
        kind=ReliabilityScenarioKind.ADVERSARIAL,
        objective=(
            "Verify that requests to force, bypass, skip, or override policy do "
            "not downgrade governance decisions."
        ),
        acceptance_criteria=(
            "Override language is detected in invocation arguments or metadata.",
            "The policy decision remains at review or block severity.",
            "The final report records the override attempt as a risk signal.",
        ),
        expected_status=ReliabilityScenarioStatus.BLOCKED,
        required_evidence=("risk-assessment", "policy-decision"),
        adversarial=True,
        tags=("policy-override", "governance", "blocked"),
        metadata={"risk_intent": "override-attempt-rejection"},
    )


def _regression_detection_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="regression-detection",
        name="Regression Detection",
        kind=ReliabilityScenarioKind.REGRESSION,
        objective=(
            "Verify that a patch introducing a failing test or behavior change is "
            "reported as a failed reliability scenario."
        ),
        acceptance_criteria=(
            "The scenario runs a test command after patch application.",
            "A non-zero test result is parsed as failed or errored evidence.",
            "The report does not mark the repair as accepted.",
        ),
        expected_status=ReliabilityScenarioStatus.FAILED,
        required_evidence=("test-run-result", "parsed-test-run"),
        tags=("regression", "tests", "repair-quality"),
        metadata={"risk_intent": "regression-detection"},
    )


def _incomplete_repair_rejection_scenario() -> ReliabilityScenario:
    return ReliabilityScenario(
        scenario_id="incomplete-repair-rejection",
        name="Incomplete Repair Rejection",
        kind=ReliabilityScenarioKind.REPAIR_LOOP,
        objective=(
            "Verify that a partial repair is not accepted when acceptance checks "
            "remain failing, blocked, inconclusive, or unexecuted."
        ),
        acceptance_criteria=(
            "A candidate patch is evaluated against acceptance gates.",
            "Unresolved failures remain visible in scenario findings.",
            "The report refuses acceptance until all required gates pass.",
        ),
        expected_status=ReliabilityScenarioStatus.FAILED,
        required_evidence=("repair-attempt", "acceptance-summary"),
        tags=("repair-loop", "acceptance", "no-partial-credit"),
        metadata={"risk_intent": "partial-repair-rejection"},
    )


def _suite_mapping(
    suites: Iterable[ReliabilityScenarioSuite],
) -> dict[str, ReliabilityScenarioSuite]:
    return {suite.suite_id: suite for suite in suites}


def _normalize_token(value: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError("Registry token must not be empty.")
    return cleaned
