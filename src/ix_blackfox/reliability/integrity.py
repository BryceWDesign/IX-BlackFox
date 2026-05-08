from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.reliability.adversarial import (
    AdversarialProbe,
    AdversarialReliabilityHarness,
    default_adversarial_probes,
)
from ix_blackfox.reliability.models import ReliabilityScenarioSuite
from ix_blackfox.reliability.scenarios import (
    WAVE4_ADVERSARIAL_SUITE_ID,
    WAVE4_CORE_SUITE_ID,
    WAVE4_FULL_SUITE_ID,
    ReliabilityScenarioRegistry,
    ReliabilityScenarioRegistryError,
)


@dataclass(frozen=True, slots=True)
class Wave4ReliabilityLabIntegrityIssue:
    """
    One structural issue found in the built-in Wave 4 reliability lab wiring.
    """

    code: str
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class Wave4ReliabilityLabIntegrityReport:
    """
    Deterministic integrity report for the built-in Wave 4 reliability lab.
    """

    passed: bool
    issues: tuple[Wave4ReliabilityLabIntegrityIssue, ...]
    scenario_count: int
    probe_count: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.scenario_count < 0:
            raise ValueError("scenario_count must be non-negative.")
        if self.probe_count < 0:
            raise ValueError("probe_count must be non-negative.")
        if self.passed != (len(self.issues) == 0):
            raise ValueError("passed must match whether the issue list is empty.")

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "issue_count": self.issue_count,
            "issue_codes": list(self.issue_codes),
            "scenario_count": self.scenario_count,
            "probe_count": self.probe_count,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


def validate_wave4_reliability_lab(
    *,
    registry: ReliabilityScenarioRegistry | None = None,
    probes: Iterable[AdversarialProbe] | None = None,
) -> Wave4ReliabilityLabIntegrityReport:
    """
    Validate built-in Wave 4 suite/probe wiring before reliability execution.

    The integrity check is deterministic and non-executing: it does not mutate a
    workspace, apply patches, run shell commands, or read external resources. It
    verifies that the core/adversarial/full suites remain separated correctly and
    that default adversarial probes only target adversarial scenarios they can
    fail closed against.
    """

    scenario_registry = registry or ReliabilityScenarioRegistry.built_in()
    probe_tuple = tuple(probes) if probes is not None else default_adversarial_probes()
    issues: list[Wave4ReliabilityLabIntegrityIssue] = []

    suites = _load_required_suites(scenario_registry, issues)
    core_suite = suites.get(WAVE4_CORE_SUITE_ID)
    adversarial_suite = suites.get(WAVE4_ADVERSARIAL_SUITE_ID)
    full_suite = suites.get(WAVE4_FULL_SUITE_ID)

    core_ids = _scenario_ids(core_suite)
    adversarial_ids = _scenario_ids(adversarial_suite)
    full_ids = _scenario_ids(full_suite)
    known_ids = core_ids | adversarial_ids

    if core_suite is not None:
        _check_core_suite(core_suite, issues)
    if adversarial_suite is not None:
        _check_adversarial_suite(adversarial_suite, issues)
    if full_suite is not None:
        _check_full_suite(full_suite, expected_ids=known_ids, issues=issues)

    _check_probe_ids_are_unique(probe_tuple, issues)
    _check_probe_targets_are_known(probe_tuple, known_ids=known_ids, issues=issues)
    _check_probes_do_not_target_core_scenarios(
        probe_tuple,
        core_ids=core_ids,
        issues=issues,
    )
    _check_adversarial_scenario_probe_coverage(
        probe_tuple,
        adversarial_ids=adversarial_ids,
        issues=issues,
    )
    _check_probe_payloads_fail_closed(probe_tuple, issues)

    return Wave4ReliabilityLabIntegrityReport(
        passed=not issues,
        issues=tuple(issues),
        scenario_count=len(full_ids) if full_suite is not None else len(known_ids),
        probe_count=len(probe_tuple),
        metadata={
            "core_suite_id": WAVE4_CORE_SUITE_ID,
            "adversarial_suite_id": WAVE4_ADVERSARIAL_SUITE_ID,
            "full_suite_id": WAVE4_FULL_SUITE_ID,
        },
    )


def _load_required_suites(
    registry: ReliabilityScenarioRegistry,
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> dict[str, ReliabilityScenarioSuite]:
    suites: dict[str, ReliabilityScenarioSuite] = {}
    for suite_id in (
        WAVE4_CORE_SUITE_ID,
        WAVE4_ADVERSARIAL_SUITE_ID,
        WAVE4_FULL_SUITE_ID,
    ):
        try:
            suites[suite_id] = registry.require_suite(suite_id)
        except ReliabilityScenarioRegistryError as exc:
            issues.append(
                Wave4ReliabilityLabIntegrityIssue(
                    code="missing-required-suite",
                    summary=f"Required Wave 4 reliability suite is missing: {suite_id}.",
                    metadata={"suite_id": suite_id, "error": str(exc)},
                )
            )
    return suites


def _check_core_suite(
    suite: ReliabilityScenarioSuite,
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    adversarial_ids = tuple(
        scenario.scenario_id for scenario in suite.scenarios if scenario.adversarial
    )
    if adversarial_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="core-suite-contains-adversarial-scenarios",
                summary="Core Wave 4 reliability suite contains adversarial scenarios.",
                metadata={"suite_id": suite.suite_id, "scenario_ids": adversarial_ids},
            )
        )


def _check_adversarial_suite(
    suite: ReliabilityScenarioSuite,
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    non_adversarial_ids = tuple(
        scenario.scenario_id for scenario in suite.scenarios if not scenario.adversarial
    )
    if non_adversarial_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="adversarial-suite-contains-core-scenarios",
                summary="Adversarial Wave 4 suite contains non-adversarial scenarios.",
                metadata={
                    "suite_id": suite.suite_id,
                    "scenario_ids": non_adversarial_ids,
                },
            )
        )


def _check_full_suite(
    suite: ReliabilityScenarioSuite,
    *,
    expected_ids: set[str],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    full_ids = _scenario_ids(suite)
    if full_ids != expected_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="full-suite-scenario-set-mismatch",
                summary=(
                    "Full Wave 4 reliability lab suite must equal the union of "
                    "the core and adversarial suites."
                ),
                metadata={
                    "suite_id": suite.suite_id,
                    "missing_from_full": tuple(sorted(expected_ids - full_ids)),
                    "unexpected_in_full": tuple(sorted(full_ids - expected_ids)),
                },
            )
        )


def _check_probe_ids_are_unique(
    probes: tuple[AdversarialProbe, ...],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    seen: set[str] = set()
    duplicate_ids: list[str] = []
    for probe in probes:
        if probe.probe_id in seen:
            duplicate_ids.append(probe.probe_id)
            continue
        seen.add(probe.probe_id)

    if duplicate_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="duplicate-adversarial-probe-ids",
                summary="Adversarial probe identifiers must be unique.",
                metadata={"probe_ids": tuple(sorted(set(duplicate_ids)))},
            )
        )


def _check_probe_targets_are_known(
    probes: tuple[AdversarialProbe, ...],
    *,
    known_ids: set[str],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    unknown_targets = tuple(
        sorted(
            {
                probe.scenario_id
                for probe in probes
                if probe.scenario_id not in known_ids
            }
        )
    )
    if unknown_targets:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="adversarial-probe-targets-unknown-scenarios",
                summary="Adversarial probes target unknown Wave 4 scenarios.",
                metadata={"scenario_ids": unknown_targets},
            )
        )


def _check_probes_do_not_target_core_scenarios(
    probes: tuple[AdversarialProbe, ...],
    *,
    core_ids: set[str],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    misrouted = tuple(
        sorted(
            probe.probe_id for probe in probes if probe.scenario_id in core_ids
        )
    )
    if misrouted:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="adversarial-probes-target-core-scenarios",
                summary="Adversarial probes must not target core reliability scenarios.",
                metadata={"probe_ids": misrouted},
            )
        )


def _check_adversarial_scenario_probe_coverage(
    probes: tuple[AdversarialProbe, ...],
    *,
    adversarial_ids: set[str],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    covered_ids = {probe.scenario_id for probe in probes}
    missing_ids = tuple(sorted(adversarial_ids - covered_ids))
    if missing_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="adversarial-scenarios-without-probes",
                summary="Every built-in adversarial Wave 4 scenario requires probe coverage.",
                metadata={"scenario_ids": missing_ids},
            )
        )


def _check_probe_payloads_fail_closed(
    probes: tuple[AdversarialProbe, ...],
    issues: list[Wave4ReliabilityLabIntegrityIssue],
) -> None:
    harness = AdversarialReliabilityHarness(probes=probes)
    failed_open_probe_ids: list[str] = []
    for probe in probes:
        result = harness.evaluate_probe(probe)
        if result.failed_open:
            failed_open_probe_ids.append(probe.probe_id)

    if failed_open_probe_ids:
        issues.append(
            Wave4ReliabilityLabIntegrityIssue(
                code="adversarial-probes-fail-open",
                summary="Adversarial probe payloads must detect expected fail-closed signals.",
                metadata={"probe_ids": tuple(sorted(failed_open_probe_ids))},
            )
        )


def _scenario_ids(suite: ReliabilityScenarioSuite | None) -> set[str]:
    if suite is None:
        return set()
    return {scenario.scenario_id for scenario in suite.scenarios}


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned
