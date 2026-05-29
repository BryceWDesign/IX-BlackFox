from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.audit import AuditDisposition

_HEAD_SHA = "abc1234"
_GENERATED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_wave9_compliance_audit_ci_runner_builds_valid_blocked_report(tmp_path: Path) -> None:
    runner = _load_runner()
    output = tmp_path / ".blackfox-artifacts" / "wave9" / "wave9-compliance-audit-report.json"
    engine_evidence = tmp_path / ".blackfox-artifacts" / "wave9" / "wave9-ci-engine-evidence.json"

    report = runner.build_wave9_compliance_audit_ci_report(
        root=tmp_path,
        head_sha=_HEAD_SHA,
        output_path=output,
        engine_evidence_output_path=engine_evidence,
        generated_at=_GENERATED_AT,
        run_id="wave9-ci-test",
    )

    payload = report.to_dict()
    assert payload["wave"] == 9
    assert payload["run_id"] == "wave9-ci-test"
    assert payload["disposition"] == AuditDisposition.BLOCKED.value
    assert payload["evidence_manifest"]["artifact_count"] == 1
    assert payload["evidence_manifest"]["artifacts"][0]["artifact_id"] == "wave9:ci-engine-evidence"
    assert payload["evidence_manifest"]["artifacts"][0]["kind"] == "policy_decision"
    assert payload["signoff_authority"]["has_authoritative_human_approval"] is False
    assert payload["control_evaluation"]["blocked_count"] == 1
    assert payload["report_digest"]


def test_wave9_compliance_audit_ci_runner_writes_report_engine_evidence_and_summary(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave9-compliance-audit-report.json"
    engine_evidence = tmp_path / "wave9-ci-engine-evidence.json"
    summary_output = tmp_path / "wave9-compliance-audit-ci-summary.json"

    summary = runner.write_ci_payload(
        root=tmp_path,
        head_sha=_HEAD_SHA,
        output_path=output,
        engine_evidence_output_path=engine_evidence,
        summary_output_path=summary_output,
        generated_at=_GENERATED_AT,
        run_id="wave9-ci-test",
    )

    assert output.exists()
    assert engine_evidence.exists()
    assert summary_output.exists()
    assert summary["passed"] is True
    assert summary["wave"] == "9"
    assert summary["head_sha"] == _HEAD_SHA
    assert summary["expected_disposition"] == AuditDisposition.BLOCKED.value
    assert summary["disposition"] == AuditDisposition.BLOCKED.value
    assert summary["report_validation"]["passed"] is True
    assert summary["summary"]["evidence_artifact_count"] == 1
    assert summary["summary"]["has_authoritative_human_approval"] is False
    assert "does not fabricate human signoff" in engine_evidence.read_text(encoding="utf-8")

    report_payload = json.loads(output.read_text(encoding="utf-8"))
    summary_payload = json.loads(summary_output.read_text(encoding="utf-8"))
    assert report_payload["report_digest"] == summary_payload["report_digest"]
    assert report_payload["disposition"] == AuditDisposition.BLOCKED.value


def test_wave9_compliance_audit_ci_runner_main_returns_zero_for_expected_blocked_report(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave9-compliance-audit-report.json"
    engine_evidence = tmp_path / "wave9-ci-engine-evidence.json"
    summary_output = tmp_path / "wave9-compliance-audit-ci-summary.json"

    exit_code = runner.main(
        [
            "--root",
            str(tmp_path),
            "--head-sha",
            _HEAD_SHA,
            "--generated-at",
            "2026-01-01T00:00:00+00:00",
            "--run-id",
            "wave9-ci-main-test",
            "--output",
            str(output),
            "--engine-evidence-output",
            str(engine_evidence),
            "--summary-output",
            str(summary_output),
        ]
    )

    assert exit_code == 0
    assert output.exists()
    assert engine_evidence.exists()
    assert summary_output.exists()

    summary = json.loads(summary_output.read_text(encoding="utf-8"))
    assert summary["passed"] is True
    assert summary["disposition"] == AuditDisposition.BLOCKED.value
    assert summary["expected_disposition"] == AuditDisposition.BLOCKED.value


def test_wave9_compliance_audit_ci_runner_supports_audit_ready_diagnostic_mode(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave9-compliance-audit-report.json"
    engine_evidence = tmp_path / "wave9-ci-engine-evidence.json"
    summary_output = tmp_path / "wave9-compliance-audit-ci-summary.json"

    exit_code = runner.main(
        [
            "--root",
            str(tmp_path),
            "--head-sha",
            _HEAD_SHA,
            "--generated-at",
            "2026-01-01T00:00:00+00:00",
            "--output",
            str(output),
            "--engine-evidence-output",
            str(engine_evidence),
            "--summary-output",
            str(summary_output),
            "--no-require-human-approval",
            "--expected-disposition",
            "audit_ready",
        ]
    )

    assert exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    summary = json.loads(summary_output.read_text(encoding="utf-8"))
    assert payload["disposition"] == AuditDisposition.AUDIT_READY.value
    assert summary["passed"] is True
    assert summary["scope_note"].startswith("This CI payload verifies the Wave 9")


def test_wave9_compliance_audit_ci_runner_returns_failure_on_unexpected_disposition(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave9-compliance-audit-report.json"
    engine_evidence = tmp_path / "wave9-ci-engine-evidence.json"
    summary_output = tmp_path / "wave9-compliance-audit-ci-summary.json"

    exit_code = runner.main(
        [
            "--root",
            str(tmp_path),
            "--head-sha",
            _HEAD_SHA,
            "--generated-at",
            "2026-01-01T00:00:00+00:00",
            "--output",
            str(output),
            "--engine-evidence-output",
            str(engine_evidence),
            "--summary-output",
            str(summary_output),
            "--expected-disposition",
            "audit_ready",
        ]
    )

    assert exit_code == 1
    summary = json.loads(summary_output.read_text(encoding="utf-8"))
    assert summary["passed"] is False
    assert summary["disposition"] == AuditDisposition.BLOCKED.value
    assert summary["expected_disposition"] == AuditDisposition.AUDIT_READY.value


def _load_runner() -> Any:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "run_wave9_compliance_audit_ci.py"
    spec = importlib.util.spec_from_file_location(
        "wave9_compliance_audit_ci_runner",
        script,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to load scripts/run_wave9_compliance_audit_ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
