from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.agents import AgentReadinessStatus

_HEAD_SHA = "abc1234"
_GENERATED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_wave11_agent_identity_ci_runner_builds_warning_report() -> None:
    runner = _load_runner()

    report = runner.build_wave11_agent_identity_ci_report(
        head_sha=_HEAD_SHA,
        generated_at=_GENERATED_AT,
        run_id="wave11-ci-test",
    )

    payload = report.to_dict()
    assert payload["status"] == AgentReadinessStatus.WARNING.value
    assert payload["ready"] is False
    assert payload["metadata"]["wave"] == "11"
    assert payload["metadata"]["run_id"] == "wave11-ci-test"
    assert payload["active_agent_count"] == 3
    assert payload["authorization_decision_count"] == 2
    assert payload["authority_evaluation_count"] == 1
    assert payload["provenance_record_count"] == 2
    assert payload["blocking_finding_count"] == 0
    assert payload["warning_finding_count"] >= 1
    assert payload["digest"]


def test_wave11_agent_identity_ci_runner_writes_report_evidence_and_summary(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave11-agent-readiness-report.json"
    engine_evidence = tmp_path / "wave11-agent-identity-engine-evidence.json"
    summary_output = tmp_path / "wave11-agent-identity-ci-summary.json"

    summary = runner.write_ci_payload(
        root=tmp_path,
        head_sha=_HEAD_SHA,
        output_path=output,
        engine_evidence_output_path=engine_evidence,
        summary_output_path=summary_output,
        generated_at=_GENERATED_AT,
        run_id="wave11-ci-test",
    )

    assert output.exists()
    assert engine_evidence.exists()
    assert summary_output.exists()
    assert summary["passed"] is True
    assert summary["wave"] == "11"
    assert summary["head_sha"] == _HEAD_SHA
    assert summary["expected_status"] == AgentReadinessStatus.WARNING.value
    assert summary["status"] == AgentReadinessStatus.WARNING.value
    assert summary["report_validation"]["passed"] is True
    assert summary["summary"]["active_agent_count"] == 3
    assert summary["summary"]["provenance_record_count"] == 2

    report_payload = json.loads(output.read_text(encoding="utf-8"))
    evidence_payload = json.loads(engine_evidence.read_text(encoding="utf-8"))
    summary_payload = json.loads(summary_output.read_text(encoding="utf-8"))
    assert report_payload["digest"] == summary_payload["report_digest"]
    assert evidence_payload["report_digest"] == report_payload["digest"]
    assert evidence_payload["human_authority_preserved"] is True
    assert "not production authorization" in evidence_payload["scope_note"]


def test_wave11_agent_identity_ci_runner_main_returns_zero_for_expected_warning(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave11-agent-readiness-report.json"
    engine_evidence = tmp_path / "wave11-agent-identity-engine-evidence.json"
    summary_output = tmp_path / "wave11-agent-identity-ci-summary.json"

    exit_code = runner.main(
        [
            "--root",
            str(tmp_path),
            "--head-sha",
            _HEAD_SHA,
            "--generated-at",
            "2026-01-01T00:00:00+00:00",
            "--run-id",
            "wave11-ci-main-test",
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
    assert summary["status"] == AgentReadinessStatus.WARNING.value
    assert summary["expected_status"] == AgentReadinessStatus.WARNING.value


def test_wave11_agent_identity_ci_runner_returns_failure_for_unexpected_status(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave11-agent-readiness-report.json"
    engine_evidence = tmp_path / "wave11-agent-identity-engine-evidence.json"
    summary_output = tmp_path / "wave11-agent-identity-ci-summary.json"

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
            "--expected-status",
            "ready",
        ]
    )

    assert exit_code == 1
    summary = json.loads(summary_output.read_text(encoding="utf-8"))
    assert summary["passed"] is False
    assert summary["status"] == AgentReadinessStatus.WARNING.value
    assert summary["expected_status"] == AgentReadinessStatus.READY.value


def test_wave11_agent_identity_ci_runner_rejects_output_outside_root(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    outside = tmp_path.parent / "outside-wave11-report.json"

    try:
        runner.write_ci_payload(
            root=tmp_path,
            head_sha=_HEAD_SHA,
            output_path=outside,
            generated_at=_GENERATED_AT,
            run_id="wave11-ci-test",
        )
    except ValueError as exc:
        assert "under root" in str(exc)
    else:
        raise AssertionError("outside output path should fail")


def _load_runner() -> Any:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "run_wave11_agent_identity_ci.py"
    spec = importlib.util.spec_from_file_location(
        "wave11_agent_identity_ci_runner",
        script,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to load scripts/run_wave11_agent_identity_ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
