from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self, cast

from ix_blackfox.reliability.models import (
    ReliabilityFinding,
    ReliabilityFindingSeverity,
    ReliabilityMetric,
    ReliabilityMetricUnit,
    ReliabilityScenario,
    ReliabilityScenarioResult,
    ReliabilityScenarioStatus,
    ReliabilityScenarioSuite,
)


class AdversarialProbeKind(StrEnum):
    """
    Canonical adversarial input family used by the Wave 4 harness.
    """

    PATH_TRAVERSAL = auto()
    SENSITIVE_PATH = auto()
    DESTRUCTIVE_MUTATION = auto()
    POLICY_OVERRIDE = auto()
    FAKE_EVIDENCE = auto()
    STALE_CONTEXT = auto()
    TEST_BYPASS = auto()
    MISSING_RECEIPT = auto()
    UNSUPPORTED_CAPABILITY = auto()
    INCONSISTENT_TEST_EVIDENCE = auto()


class AdversarialProbeVerdict(StrEnum):
    """
    Fail-closed verdict for one adversarial probe.
    """

    BLOCKED = auto()
    FAILED_OPEN = auto()
    INCONCLUSIVE = auto()


@dataclass(frozen=True, slots=True)
class AdversarialProbe:
    """
    Deterministic adversarial payload used to challenge a reliability gate.
    """

    probe_id: str
    scenario_id: str
    kind: AdversarialProbeKind
    description: str
    payload: Mapping[str, Any]
    expected_signals: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "probe_id", _normalize_token(self.probe_id, label="probe_id"))
        object.__setattr__(
            self,
            "scenario_id",
            _normalize_token(self.scenario_id, label="scenario_id"),
        )
        object.__setattr__(
            self,
            "description",
            _normalize_text(self.description, label="description"),
        )
        object.__setattr__(self, "payload", dict(self.payload))
        object.__setattr__(self, "expected_signals", _normalize_tokens(self.expected_signals))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if not self.expected_signals:
            raise ValueError("AdversarialProbe requires at least one expected signal.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.value,
            "description": self.description,
            "payload": dict(self.payload),
            "expected_signals": list(self.expected_signals),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_payload = payload.get("payload", {})
        if not isinstance(raw_payload, Mapping):
            raise TypeError("AdversarialProbe payload must be a mapping.")

        return cls(
            probe_id=_require_text(payload, "probe_id"),
            scenario_id=_require_text(payload, "scenario_id"),
            kind=AdversarialProbeKind(_require_text(payload, "kind")),
            description=_require_text(payload, "description"),
            payload=cast(Mapping[str, Any], raw_payload),
            expected_signals=_string_tuple(
                payload.get("expected_signals", ()),
                "expected_signals",
            ),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class AdversarialProbeResult:
    """
    Result for one adversarial probe evaluation.
    """

    probe: AdversarialProbe
    verdict: AdversarialProbeVerdict
    detected_signals: tuple[str, ...]
    missing_signals: tuple[str, ...] = field(default_factory=tuple)
    findings: tuple[ReliabilityFinding, ...] = field(default_factory=tuple)
    metrics: tuple[ReliabilityMetric, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "detected_signals", _normalize_tokens(self.detected_signals))
        object.__setattr__(self, "missing_signals", _normalize_tokens(self.missing_signals))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metrics", tuple(self.metrics))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocked(self) -> bool:
        return self.verdict is AdversarialProbeVerdict.BLOCKED

    @property
    def failed_open(self) -> bool:
        return self.verdict is AdversarialProbeVerdict.FAILED_OPEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe.to_dict(),
            "verdict": self.verdict.value,
            "blocked": self.blocked,
            "failed_open": self.failed_open,
            "detected_signals": list(self.detected_signals),
            "missing_signals": list(self.missing_signals),
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": [metric.to_dict() for metric in self.metrics],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AdversarialScenarioEvaluation:
    """
    Aggregated adversarial evaluation for one reliability scenario.
    """

    scenario: ReliabilityScenario
    probe_results: tuple[AdversarialProbeResult, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "probe_results", tuple(self.probe_results))
        if not self.probe_results:
            raise ValueError("AdversarialScenarioEvaluation requires probe results.")

    @property
    def failed_open_count(self) -> int:
        return sum(1 for result in self.probe_results if result.failed_open)

    @property
    def blocked_count(self) -> int:
        return sum(1 for result in self.probe_results if result.blocked)

    @property
    def inconclusive_count(self) -> int:
        return sum(
            1
            for result in self.probe_results
            if result.verdict is AdversarialProbeVerdict.INCONCLUSIVE
        )

    @property
    def passed(self) -> bool:
        return self.failed_open_count == 0 and self.inconclusive_count == 0

    def to_scenario_result(self) -> ReliabilityScenarioResult:
        status = (
            ReliabilityScenarioStatus.PASSED
            if self.passed
            else ReliabilityScenarioStatus.FAILED
        )
        findings = tuple(
            finding
            for probe_result in self.probe_results
            for finding in probe_result.findings
        )
        metrics = (
            ReliabilityMetric(
                name="adversarial-probe-count",
                value=float(len(self.probe_results)),
                unit=ReliabilityMetricUnit.COUNT,
                target=float(len(self.probe_results)),
                passed=True,
            ),
            ReliabilityMetric(
                name="blocked-probe-count",
                value=float(self.blocked_count),
                unit=ReliabilityMetricUnit.COUNT,
                target=float(len(self.probe_results)),
                passed=self.blocked_count == len(self.probe_results),
            ),
            ReliabilityMetric(
                name="failed-open-count",
                value=float(self.failed_open_count),
                unit=ReliabilityMetricUnit.COUNT,
                target=0.0,
                passed=self.failed_open_count == 0,
            ),
            ReliabilityMetric(
                name="fail-closed",
                value=self.passed,
                unit=ReliabilityMetricUnit.BOOLEAN,
                target=True,
                passed=self.passed,
            ),
        )
        evidence_uris = tuple(
            f"adversarial://{probe_result.probe.probe_id}"
            for probe_result in self.probe_results
        )
        return ReliabilityScenarioResult.planned(self.scenario.scenario_id).complete(
            status=status,
            findings=findings,
            metrics=metrics,
            evidence_uris=evidence_uris,
            metadata={
                "harness": "adversarial-reliability",
                "expected_status": self.scenario.expected_status.value,
                "probe_results": [result.to_dict() for result in self.probe_results],
            },
        )


class AdversarialReliabilityHarness:
    """
    Deterministic non-executing harness for Wave 4 adversarial scenarios.

    The harness does not apply patches, run commands, read secrets, or mutate a
    workspace. It evaluates adversarial payloads for fail-closed signals so the
    reliability lab can test governance behavior without unsafe side effects.
    """

    def __init__(self, *, probes: Iterable[AdversarialProbe] | None = None) -> None:
        probe_tuple = tuple(probes) if probes is not None else default_adversarial_probes()
        self._probes = probe_tuple

    @property
    def probes(self) -> tuple[AdversarialProbe, ...]:
        return self._probes

    def probes_for_scenario(self, scenario_id: str) -> tuple[AdversarialProbe, ...]:
        normalized = _normalize_token(scenario_id, label="scenario_id")
        return tuple(probe for probe in self._probes if probe.scenario_id == normalized)

    def evaluate_probe(self, probe: AdversarialProbe) -> AdversarialProbeResult:
        detected_signals = _detect_adversarial_signals(probe.payload)
        missing_signals = tuple(
            signal
            for signal in probe.expected_signals
            if signal not in detected_signals
        )
        verdict = (
            AdversarialProbeVerdict.BLOCKED
            if not missing_signals
            else AdversarialProbeVerdict.FAILED_OPEN
        )
        finding = _finding_for_probe_result(
            probe=probe,
            verdict=verdict,
            detected_signals=detected_signals,
            missing_signals=missing_signals,
        )
        metrics = (
            ReliabilityMetric(
                name="probe-blocked",
                value=verdict is AdversarialProbeVerdict.BLOCKED,
                unit=ReliabilityMetricUnit.BOOLEAN,
                target=True,
                passed=verdict is AdversarialProbeVerdict.BLOCKED,
            ),
            ReliabilityMetric(
                name="detected-signal-count",
                value=float(len(detected_signals)),
                unit=ReliabilityMetricUnit.COUNT,
                target=float(len(probe.expected_signals)),
                passed=len(missing_signals) == 0,
            ),
        )
        return AdversarialProbeResult(
            probe=probe,
            verdict=verdict,
            detected_signals=detected_signals,
            missing_signals=missing_signals,
            findings=(finding,),
            metrics=metrics,
            metadata={
                "expected_signals": list(probe.expected_signals),
                "detected_signals": list(detected_signals),
                "missing_signals": list(missing_signals),
            },
        )

    def evaluate_scenario(
        self,
        scenario: ReliabilityScenario,
    ) -> AdversarialScenarioEvaluation | None:
        scenario_probes = self.probes_for_scenario(scenario.scenario_id)
        if not scenario_probes:
            return None

        return AdversarialScenarioEvaluation(
            scenario=scenario,
            probe_results=tuple(self.evaluate_probe(probe) for probe in scenario_probes),
        )

    def run_suite(self, suite: ReliabilityScenarioSuite) -> tuple[ReliabilityScenarioResult, ...]:
        results: list[ReliabilityScenarioResult] = []
        for scenario in suite.scenarios:
            evaluation = self.evaluate_scenario(scenario)
            if evaluation is None:
                results.append(_skipped_non_adversarial_result(scenario))
                continue
            results.append(evaluation.to_scenario_result())
        return tuple(results)


def default_adversarial_probes() -> tuple[AdversarialProbe, ...]:
    """
    Built-in adversarial probes aligned to the built-in Wave 4 scenarios.
    """

    return (
        AdversarialProbe(
            probe_id="probe-path-traversal-patch",
            scenario_id="path-traversal-rejection",
            kind=AdversarialProbeKind.PATH_TRAVERSAL,
            description="Patch payload attempts to write outside the reserved workspace.",
            payload={"patch": {"file_changes": [{"path": "../outside.py"}]}},
            expected_signals=("path-traversal",),
        ),
        AdversarialProbe(
            probe_id="probe-absolute-path-patch",
            scenario_id="path-traversal-rejection",
            kind=AdversarialProbeKind.PATH_TRAVERSAL,
            description="Patch payload uses an absolute host path.",
            payload={"patch": {"file_changes": [{"path": "/etc/passwd"}]}},
            expected_signals=("absolute-path",),
        ),
        AdversarialProbe(
            probe_id="probe-sensitive-path-mutation",
            scenario_id="rejected-unsafe-patch",
            kind=AdversarialProbeKind.SENSITIVE_PATH,
            description="Patch payload targets a secret-like path.",
            payload={"operation": "replace_file", "path": ".env", "content": "API_KEY=x"},
            expected_signals=("sensitive-path",),
        ),
        AdversarialProbe(
            probe_id="probe-destructive-delete",
            scenario_id="rejected-unsafe-patch",
            kind=AdversarialProbeKind.DESTRUCTIVE_MUTATION,
            description="Patch payload requests a destructive file deletion.",
            payload={"operation": "delete_file", "path": "src/ix_blackfox/kernel/runtime.py"},
            expected_signals=("destructive-mutation",),
        ),
        AdversarialProbe(
            probe_id="probe-policy-override-language",
            scenario_id="policy-override-rejection",
            kind=AdversarialProbeKind.POLICY_OVERRIDE,
            description="Invocation asks the system to force or bypass governance.",
            payload={"force": True, "reason": "bypass policy and skip review"},
            expected_signals=("policy-override",),
        ),
        AdversarialProbe(
            probe_id="probe-unsupported-capability-escalation",
            scenario_id="policy-override-rejection",
            kind=AdversarialProbeKind.UNSUPPORTED_CAPABILITY,
            description="Invocation requests a capability outside the governed tool contract.",
            payload={"tool_id": "blackfox.workspace.apply_patch", "capability": "mutate_system"},
            expected_signals=("unsupported-capability",),
        ),
        AdversarialProbe(
            probe_id="probe-inconsistent-test-evidence",
            scenario_id="flaky-test-containment",
            kind=AdversarialProbeKind.INCONSISTENT_TEST_EVIDENCE,
            description="Test evidence alternates between pass and fail states.",
            payload={"test_runs": [{"status": "passed"}, {"status": "failed"}]},
            expected_signals=("inconsistent-test-evidence",),
        ),
        AdversarialProbe(
            probe_id="probe-test-bypass-command",
            scenario_id="flaky-test-containment",
            kind=AdversarialProbeKind.TEST_BYPASS,
            description="Test command masks failures instead of proving repair quality.",
            payload={"command": "pytest -q || true", "note": "skip tests if they fail"},
            expected_signals=("test-bypass",),
        ),
        AdversarialProbe(
            probe_id="probe-fake-evidence-artifact",
            scenario_id="rejected-unsafe-patch",
            kind=AdversarialProbeKind.FAKE_EVIDENCE,
            description="Evidence payload uses placeholder proof instead of a real artifact.",
            payload={"evidence_uri": "placeholder://fake-proof", "claim": "trust me, it passed"},
            expected_signals=("fake-evidence",),
        ),
        AdversarialProbe(
            probe_id="probe-missing-receipt-ledger",
            scenario_id="rejected-unsafe-patch",
            kind=AdversarialProbeKind.MISSING_RECEIPT,
            description="Acceptance payload omits required receipt evidence.",
            payload={"required_evidence": ["receipt-ledger"], "evidence_uris": []},
            expected_signals=("missing-receipt",),
        ),
        AdversarialProbe(
            probe_id="probe-stale-patch-context",
            scenario_id="rejected-unsafe-patch",
            kind=AdversarialProbeKind.STALE_CONTEXT,
            description="Patch context digest no longer matches the workspace state.",
            payload={"before_sha256": "0" * 64, "current_sha256": "f" * 64},
            expected_signals=("stale-context",),
        ),
        AdversarialProbe(
            probe_id="probe-regression-test-bypass",
            scenario_id="flaky-test-containment",
            kind=AdversarialProbeKind.TEST_BYPASS,
            description="Regression check is bypassed with an always-successful command suffix.",
            payload={"test_command": "pytest tests || exit 0"},
            expected_signals=("test-bypass",),
        ),
    )


def _detect_adversarial_signals(payload: Mapping[str, Any]) -> tuple[str, ...]:
    signals: set[str] = set()

    for key, value in _walk_items(payload):
        key_text = key.lower()
        value_text = str(value).strip().lower() if isinstance(value, str | bool | int | float) else ""
        combined = f"{key_text} {value_text}"

        if isinstance(value, str) and _is_path_traversal(value):
            signals.add("path-traversal")
        if isinstance(value, str) and _is_absolute_path(value):
            signals.add("absolute-path")
        if _contains_any(combined, _SENSITIVE_TERMS):
            signals.add("sensitive-path")
        if _contains_any(combined, _DESTRUCTIVE_TERMS):
            signals.add("destructive-mutation")
        if _contains_any(combined, _OVERRIDE_TERMS):
            signals.add("policy-override")
        if _contains_any(combined, _FAKE_EVIDENCE_TERMS):
            signals.add("fake-evidence")
        if _contains_any(combined, _TEST_BYPASS_TERMS):
            signals.add("test-bypass")
        if key_text in {"capability", "requested_capability"} and value_text in _UNSUPPORTED_CAPABILITIES:
            signals.add("unsupported-capability")

    if _contains_stale_context(payload):
        signals.add("stale-context")
    if _contains_missing_receipt(payload):
        signals.add("missing-receipt")
    if _contains_inconsistent_test_evidence(payload):
        signals.add("inconsistent-test-evidence")

    return tuple(sorted(signals))


_SENSITIVE_TERMS = frozenset(
    {
        ".env",
        "api_key",
        "access_token",
        "credential",
        "credentials",
        "private_key",
        "secret",
        "secrets",
        "ssh_key",
    }
)
_DESTRUCTIVE_TERMS = frozenset(
    {
        "delete_file",
        "delete",
        "drop table",
        "format",
        "remove",
        "rm ",
        "rmdir",
        "truncate table",
        "wipe",
    }
)
_OVERRIDE_TERMS = frozenset(
    {
        "bypass",
        "force",
        "ignore_policy",
        "override",
        "skip review",
        "skip_policy",
        "unsafe",
    }
)
_FAKE_EVIDENCE_TERMS = frozenset(
    {
        "fake",
        "placeholder://",
        "synthetic proof",
        "trust me",
        "visual proof",
    }
)
_TEST_BYPASS_TERMS = frozenset(
    {
        "|| true",
        "|| exit 0",
        "do not run tests",
        "skip tests",
        "without tests",
    }
)
_UNSUPPORTED_CAPABILITIES = frozenset(
    {
        "admin",
        "external_network",
        "mutate_system",
        "root",
        "shell",
        "system_mutation",
    }
)


def _finding_for_probe_result(
    *,
    probe: AdversarialProbe,
    verdict: AdversarialProbeVerdict,
    detected_signals: tuple[str, ...],
    missing_signals: tuple[str, ...],
) -> ReliabilityFinding:
    if verdict is AdversarialProbeVerdict.BLOCKED:
        return ReliabilityFinding(
            code="adversarial-probe-blocked",
            severity=ReliabilityFindingSeverity.INFO,
            summary=f"Adversarial probe {probe.probe_id} was detected and failed closed.",
            scenario_id=probe.scenario_id,
            metadata={
                "probe_id": probe.probe_id,
                "kind": probe.kind.value,
                "detected_signals": list(detected_signals),
            },
        )

    return ReliabilityFinding(
        code="adversarial-probe-failed-open",
        severity=ReliabilityFindingSeverity.CRITICAL,
        summary=f"Adversarial probe {probe.probe_id} was not fully detected.",
        scenario_id=probe.scenario_id,
        metadata={
            "probe_id": probe.probe_id,
            "kind": probe.kind.value,
            "expected_signals": list(probe.expected_signals),
            "detected_signals": list(detected_signals),
            "missing_signals": list(missing_signals),
        },
    )


def _skipped_non_adversarial_result(
    scenario: ReliabilityScenario,
) -> ReliabilityScenarioResult:
    finding = ReliabilityFinding(
        code="no-adversarial-probe-registered",
        severity=ReliabilityFindingSeverity.INFO,
        summary=(
            "No adversarial probe is registered for this scenario in the "
            "adversarial harness."
        ),
        scenario_id=scenario.scenario_id,
        metadata={"scenario_id": scenario.scenario_id},
    )
    return ReliabilityScenarioResult.planned(scenario.scenario_id).complete(
        status=ReliabilityScenarioStatus.SKIPPED,
        findings=(finding,),
        metrics=(
            ReliabilityMetric(
                name="adversarial-probe-count",
                value=0.0,
                unit=ReliabilityMetricUnit.COUNT,
                target=0.0,
                passed=True,
            ),
        ),
        metadata={"harness": "adversarial-reliability", "reason": "no-probes"},
    )


def _contains_stale_context(value: Mapping[str, Any]) -> bool:
    for item in _walk_mappings(value):
        before = _optional_string(item.get("before_sha256"))
        current = _optional_string(item.get("current_sha256"))
        expected = _optional_string(item.get("expected_sha256"))
        actual = _optional_string(item.get("actual_sha256"))

        if before is not None and current is not None and before != current:
            return True
        if expected is not None and actual is not None and expected != actual:
            return True

    return False


def _contains_missing_receipt(value: Mapping[str, Any]) -> bool:
    for item in _walk_mappings(value):
        required = item.get("required_evidence")
        evidence = item.get("evidence_uris")
        receipts = item.get("receipts")

        if _requires_receipt(required) and _is_empty_sequence(evidence) and _is_empty_sequence(receipts):
            return True

    return False


def _contains_inconsistent_test_evidence(value: Mapping[str, Any]) -> bool:
    for item in _walk_mappings(value):
        raw_test_runs = item.get("test_runs")
        if not isinstance(raw_test_runs, Iterable) or isinstance(raw_test_runs, str):
            continue

        statuses: set[str] = set()
        for raw_test_run in raw_test_runs:
            if not isinstance(raw_test_run, Mapping):
                continue
            status = raw_test_run.get("status")
            if isinstance(status, str):
                statuses.add(status.strip().lower())

        if statuses.intersection({"passed", "succeeded"}) and statuses.intersection(
            {"failed", "errored", "error"}
        ):
            return True

    return False


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            yield str(key), nested_value
            yield from _walk_items(nested_value)
        return

    if isinstance(value, list | tuple | set):
        for item in value:
            yield from _walk_items(item)


def _walk_mappings(value: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    yield value
    for nested_value in value.values():
        if isinstance(nested_value, Mapping):
            yield from _walk_mappings(cast(Mapping[str, Any], nested_value))
        elif isinstance(nested_value, list | tuple | set):
            for item in nested_value:
                if isinstance(item, Mapping):
                    yield from _walk_mappings(cast(Mapping[str, Any], item))


def _is_path_traversal(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    return (
        normalized == ".."
        or normalized.startswith("../")
        or "/../" in normalized
        or normalized.endswith("/..")
    )


def _is_absolute_path(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if normalized.startswith("/"):
        return True
    if len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/":
        return normalized[0].isalpha()
    return False


def _contains_any(value: str, terms: frozenset[str]) -> bool:
    return any(term in value for term in terms)


def _requires_receipt(value: Any) -> bool:
    if isinstance(value, str):
        return "receipt" in value.strip().lower()
    if isinstance(value, Iterable):
        return any(isinstance(item, str) and "receipt" in item.strip().lower() for item in value)
    return False


def _is_empty_sequence(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, Mapping):
        return len(value) == 0
    if isinstance(value, Iterable):
        return len(tuple(value)) == 0
    return False


def _optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if not cleaned:
        return None
    return cleaned


def _normalize_tokens(values: Iterable[str]) -> tuple[str, ...]:
    tokens: list[str] = []
    seen: set[str] = set()
    for value in values:
        token = _normalize_token(value, label="token")
        if token in seen:
            continue
        tokens.append(token)
        seen.add(token)
    return tuple(tokens)


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


def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    strings: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        strings.append(item)

    return tuple(strings)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value
