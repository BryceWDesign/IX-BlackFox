from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


def test_wave7_model_repair_workflow_runs_required_evidence_steps() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workflow = repo_root / ".github" / "workflows" / "wave7-model-repair-evidence.yml"

    text = workflow.read_text(encoding="utf-8")

    assert "Wave 7 Model Repair Evidence" in text
    assert "tests/brains" in text
    assert "tests/runtime/test_brain_proposal.py" in text
    assert "tests/runtime/test_brain_repair.py" in text
    assert "tests/runtime/test_brain_repair_evidence.py" in text
    assert "tests/ci/test_wave7_model_repair_ci_integration.py" in text
    assert "scripts/run_wave7_model_repair_ci.py" in text
    assert "wave7-model-repair-ci-evidence" in text
    assert ".blackfox-artifacts/wave7/" in text
    assert "timeout-minutes: 15" in text


def test_wave7_model_repair_ci_runner_builds_passing_payload() -> None:
    runner = _load_runner()

    selection_report = runner.build_wave7_selection_report()
    payload = runner.build_ci_payload(
        head_sha="abc1234",
        selection_report=selection_report,
    )

    assert payload["passed"] is True
    assert payload["wave"] == "7"
    assert payload["head_sha"] == "abc1234"
    assert payload["selected_source_id"] == "reasoned-local"
    assert payload["selected_brain_name"] == "reasoned-local-brain"
    assert payload["review_routed"] is True
    assert payload["blocked"] is False
    assert payload["selection_report"]["tribunal_decision"]["selected_brain_name"] == (
        "wave7-ci-critic-brain"
    )
    assert payload["selection_report"]["comparison_decision"]["selected_brain_name"] == (
        "reasoned-local-proposal-1"
    )


def test_wave7_model_repair_ci_runner_writes_payload_and_selection_evidence(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave7-model-repair-ci-report.json"

    payload = runner.write_ci_payload(head_sha="abc1234", output_path=output)

    selection_evidence = tmp_path / "wave7-model-repair-selection-evidence.json"
    assert output.exists()
    assert selection_evidence.exists()
    assert payload["passed"] is True
    assert payload["evidence_export"]["chain_valid"] is True
    assert payload["ledger_snapshot"]["receipt_count"] == 2
    assert '"passed": true' in output.read_text(encoding="utf-8")

    report_payload = json.loads(output.read_text(encoding="utf-8"))
    selection_payload = json.loads(selection_evidence.read_text(encoding="utf-8"))

    assert report_payload["passed"] is True
    assert report_payload["selected_source_id"] == "reasoned-local"
    assert report_payload["evidence_export"]["receipt"]["event_type"] == "report_exported"
    assert selection_payload["schema_version"] == "wave7.brain_repair_evidence.v1"
    assert selection_payload["selection_report"]["selected_source_id"] == "reasoned-local"
    assert selection_payload["receipt"]["event_type"] == "selection_recorded"


def test_wave7_model_repair_ci_runner_main_returns_zero_for_passing_payload(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    output = tmp_path / "wave7-model-repair-ci-report.json"

    exit_code = runner.main(
        [
            "--head-sha",
            "abc1234",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.exists()


def _load_runner() -> Any:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "run_wave7_model_repair_ci.py"
    spec = importlib.util.spec_from_file_location("wave7_model_repair_ci_runner", script)
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to load scripts/run_wave7_model_repair_ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
