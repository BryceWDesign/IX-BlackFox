from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

from ix_blackfox.interface.cli import main as blackfox_main
from ix_blackfox.reliability import (
    WAVE4_ADVERSARIAL_SUITE_ID,
    WAVE4_CORE_SUITE_ID,
    WAVE4_FULL_SUITE_ID,
    AdversarialReliabilityHarness,
    ReliabilityArtifactStore,
    ReliabilityGateDecision,
    ReliabilityLabRunConfig,
    ReliabilityLabRunner,
    ReliabilityMetricsCollector,
    ReliabilityMetricUnit,
    ReliabilityReport,
    ReliabilityScenarioRegistry,
    ReliabilityScenarioStatus,
    RepairMetricObservation,
    RepairMetricOutcome,
    build_wave4_adversarial_suite,
    build_wave4_core_suite,
    build_wave4_full_suite,
    validate_wave4_reliability_lab,
)


def test_built_in_reliability_suites_are_registered() -> None:
    registry = ReliabilityScenarioRegistry.built_in()

    assert registry.suite_ids == (
        WAVE4_ADVERSARIAL_SUITE_ID,
        WAVE4_CORE_SUITE_ID,
        WAVE4_FULL_SUITE_ID,
    )

    core_suite = registry.require_suite(WAVE4_CORE_SUITE_ID)
    adversarial_suite = registry.require_suite(WAVE4_ADVERSARIAL_SUITE_ID)
    full_suite = registry.require_suite(WAVE4_FULL_SUITE_ID)

    assert core_suite.scenario_count == 4
    assert adversarial_suite.scenario_count == 4
    assert full_suite.scenario_count == 8
    assert adversarial_suite.adversarial_count == 4
    assert full_suite.scenario_by_id("path-traversal-rejection").adversarial is True


def test_wave4_reliability_lab_integrity_check_passes_builtin_wiring() -> None:
    report = validate_wave4_reliability_lab()

    assert report.passed is True
    assert report.issue_count == 0
    assert report.scenario_count == 8
    assert report.probe_count == 12
    assert report.to_dict()["issue_codes"] == []


def test_wave4_reliability_lab_integrity_check_blocks_core_probe_targets() -> None:
    probe = next(
        probe
        for probe in AdversarialReliabilityHarness().probes
        if probe.probe_id == "probe-regression-test-bypass"
    )
    misrouted_probe = replace(probe, scenario_id="regression-detection")
    report = validate_wave4_reliability_lab(probes=(misrouted_probe,))

    assert report.passed is False
    assert "adversarial-probes-target-core-scenarios" in report.issue_codes


def test_scenario_suite_serialization_round_trips() -> None:
    suite = build_wave4_full_suite()
    restored = type(suite).from_dict(suite.to_dict())

    assert restored.suite_id == suite.suite_id
    assert restored.scenario_count == suite.scenario_count
    assert restored.adversarial_count == suite.adversarial_count
    assert restored.scenario_by_id("safe-patch-success").name == "Safe Patch Success"


def test_adversarial_harness_fails_closed_for_built_in_adversarial_suite() -> None:
    suite = build_wave4_adversarial_suite()
    harness = AdversarialReliabilityHarness()

    results = harness.run_suite(suite)

    assert len(results) == suite.scenario_count
    assert all(result.status is ReliabilityScenarioStatus.PASSED for result in results)
    assert all(result.evidence_uris for result in results)

    for result in results:
        fail_closed_metric = _metric(result, "fail-closed")
        assert fail_closed_metric.unit is ReliabilityMetricUnit.BOOLEAN
        assert fail_closed_metric.value is True
        assert fail_closed_metric.passed is True


def test_adversarial_harness_marks_non_adversarial_scenarios_skipped() -> None:
    suite = build_wave4_core_suite()
    harness = AdversarialReliabilityHarness()

    results = harness.run_suite(suite)

    assert len(results) == suite.scenario_count
    assert all(result.status is ReliabilityScenarioStatus.SKIPPED for result in results)
    assert all(
        result.findings[0].code == "no-adversarial-probe-registered"
        for result in results
    )


def test_metrics_collector_reports_repair_quality_counts() -> None:
    observations = _complete_wave4_observations()
    summary = ReliabilityMetricsCollector().collect(observations=observations)

    assert summary.metric_by_name("repair-attempt-count").value == 4.0
    assert summary.metric_by_name("repair-accepted-count").value == 1.0
    assert summary.metric_by_name("repair-rejected-count").value == 3.0
    assert summary.metric_by_name("regression-count").value == 1.0
    assert summary.metric_by_name("evidence-completeness-ratio").value < 1.0
    assert summary.metric_by_name("receipt-completeness-ratio").value < 1.0
    assert any(finding.code == "repair-evidence-incomplete" for finding in summary.findings)
    assert any(finding.code == "repair-receipt-incomplete" for finding in summary.findings)


def test_reliability_lab_runner_passes_full_suite_with_complete_wave4_observations() -> None:
    result = ReliabilityLabRunner().run(
        config=ReliabilityLabRunConfig(suite_id=WAVE4_FULL_SUITE_ID),
        observations=_complete_wave4_observations(),
    )

    assert result.passed is True
    assert result.decision == ReliabilityGateDecision.PASS.value
    assert result.report.suite.suite_id == WAVE4_FULL_SUITE_ID
    assert result.report.metric_snapshot.scenario_count == 8
    assert result.report.metric_snapshot.passed_count == 8
    assert result.report.metric_snapshot.pass_ratio == 1.0

    scenario_statuses = {
        scenario_result.scenario_id: scenario_result.status
        for scenario_result in result.report.results
    }
    assert scenario_statuses == {
        "safe-patch-success": ReliabilityScenarioStatus.PASSED,
        "regression-detection": ReliabilityScenarioStatus.PASSED,
        "missing-evidence-rejection": ReliabilityScenarioStatus.PASSED,
        "incomplete-repair-rejection": ReliabilityScenarioStatus.PASSED,
        "rejected-unsafe-patch": ReliabilityScenarioStatus.PASSED,
        "path-traversal-rejection": ReliabilityScenarioStatus.PASSED,
        "policy-override-rejection": ReliabilityScenarioStatus.PASSED,
        "flaky-test-containment": ReliabilityScenarioStatus.PASSED,
    }


def test_reliability_lab_runner_refuses_to_fabricate_missing_core_evidence() -> None:
    result = ReliabilityLabRunner().run(
        config=ReliabilityLabRunConfig(suite_id=WAVE4_CORE_SUITE_ID),
        observations=(),
    )

    assert result.passed is False
    assert result.decision == ReliabilityGateDecision.INCONCLUSIVE.value
    assert result.report.metric_snapshot.scenario_count == 4
    assert result.report.metric_snapshot.skipped_count == 4
    assert all(
        scenario_result.status is ReliabilityScenarioStatus.SKIPPED
        for scenario_result in result.report.results
    )


def test_reliability_report_serialization_round_trips() -> None:
    lab_result = ReliabilityLabRunner().run(
        config=ReliabilityLabRunConfig(suite_id=WAVE4_FULL_SUITE_ID),
        observations=_complete_wave4_observations(),
    )

    restored = ReliabilityReport.from_dict(lab_result.report.to_dict())

    assert restored.report_id == lab_result.report.report_id
    assert restored.suite.suite_id == lab_result.report.suite.suite_id
    assert restored.decision is lab_result.report.decision
    assert restored.metric_snapshot.scenario_count == 8
    assert restored.metric_snapshot.passed_count == 8


def test_reliability_artifact_store_writes_report_bundle(tmp_path: Path) -> None:
    lab_result = ReliabilityLabRunner().run(
        config=ReliabilityLabRunConfig(suite_id=WAVE4_FULL_SUITE_ID),
        observations=_complete_wave4_observations(),
    )
    store = ReliabilityArtifactStore(artifact_root=tmp_path / "artifacts")

    bundle = store.write_run_result(
        lab_result,
        bundle_id="test-wave4-bundle",
        metadata={"test": "artifact-store"},
    )

    assert bundle.bundle_id == "test-wave4-bundle"
    assert bundle.report_id == lab_result.report.report_id
    assert bundle.artifact_count == 6
    assert bundle.receipt_count >= 7
    assert bundle.metadata["manifest_uri"] == "reliability/test-wave4-bundle/manifest.json"

    for artifact in bundle.artifacts:
        artifact_path = tmp_path / "artifacts" / artifact.uri
        assert artifact_path.is_file()
        assert artifact.sha256
        assert artifact.size_bytes > 0

    manifest_payload = json.loads(
        (tmp_path / "artifacts" / "reliability/test-wave4-bundle/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest_payload["bundle_id"] == "test-wave4-bundle"
    assert manifest_payload["report_id"] == lab_result.report.report_id


def test_reliability_cli_runs_from_top_level_blackfox_dispatch(tmp_path: Path) -> None:
    observations_file = tmp_path / "observations.json"
    output_json = tmp_path / "wave4-result.json"
    artifact_root = tmp_path / "artifacts"
    observations_file.write_text(
        json.dumps(
            {
                "observations": [
                    observation.to_dict()
                    for observation in _complete_wave4_observations()
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = blackfox_main(
            [
                "reliability",
                "run",
                "--suite-id",
                WAVE4_FULL_SUITE_ID,
                "--observations-file",
                str(observations_file),
                "--artifact-root",
                str(artifact_root),
                "--bundle-id",
                "cli-wave4-bundle",
                "--output-json",
                str(output_json),
                "--json",
            ]
        )

    stdout_payload = json.loads(buffer.getvalue())
    file_payload = json.loads(output_json.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert stdout_payload["passed"] is True
    assert stdout_payload["decision"] == "pass"
    assert file_payload["passed"] is True
    assert file_payload["artifact_bundle"]["bundle_id"] == "cli-wave4-bundle"
    assert (artifact_root / "reliability/cli-wave4-bundle/manifest.json").is_file()


def test_reliability_cli_list_suites_from_top_level_dispatch() -> None:
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = blackfox_main(["reliability", "list-suites", "--json"])

    payload = json.loads(buffer.getvalue())

    assert exit_code == 0
    assert payload["suite_ids"] == [
        WAVE4_ADVERSARIAL_SUITE_ID,
        WAVE4_CORE_SUITE_ID,
        WAVE4_FULL_SUITE_ID,
    ]


def _complete_wave4_observations() -> tuple[RepairMetricObservation, ...]:
    return (
        RepairMetricObservation(
            outcome=RepairMetricOutcome.ACCEPTED,
            scenario_id="safe-patch-success",
            patch_id="patch-safe-success",
            evidence_required=("patch-apply-report", "test-run-result", "receipt-ledger"),
            evidence_present=("patch-apply-report", "test-run-result", "receipt-ledger"),
            receipt_required=True,
            receipt_present=True,
            duration_ms=120,
        ),
        RepairMetricObservation(
            outcome=RepairMetricOutcome.REJECTED,
            scenario_id="missing-evidence-rejection",
            patch_id="patch-missing-evidence",
            evidence_required=("patch-apply-report", "test-run-result", "receipt-ledger"),
            evidence_present=("patch-apply-report",),
            receipt_required=True,
            receipt_present=False,
            duration_ms=80,
        ),
        RepairMetricObservation(
            outcome=RepairMetricOutcome.REGRESSION,
            scenario_id="regression-detection",
            patch_id="patch-regression",
            evidence_required=("test-run-result", "receipt-ledger"),
            evidence_present=("test-run-result", "receipt-ledger"),
            receipt_required=True,
            receipt_present=True,
            duration_ms=90,
        ),
        RepairMetricObservation(
            outcome=RepairMetricOutcome.INCONCLUSIVE,
            scenario_id="incomplete-repair-rejection",
            patch_id="patch-incomplete",
            evidence_required=("repair-attempt", "acceptance-summary", "receipt-ledger"),
            evidence_present=("repair-attempt", "acceptance-summary", "receipt-ledger"),
            receipt_required=True,
            receipt_present=True,
            duration_ms=60,
        ),
    )


def _metric(scenario_result, name: str):
    for metric in scenario_result.metrics:
        if metric.name == name:
            return metric
    raise AssertionError(f"Missing metric {name!r}.")
