from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


def test_wave6_sandbox_ci_workflow_runs_required_evidence_steps() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workflow = repo_root / ".github" / "workflows" / "wave6-sandbox-evidence.yml"

    text = workflow.read_text(encoding="utf-8")

    assert "Wave 6 Sandbox Evidence" in text
    assert "tests/sandbox" in text
    assert "tests/workflow/test_sandbox_receipt_evidence.py" in text
    assert "tests/workflow/test_sandbox_adversarial_evidence.py" in text
    assert "tests/ci/test_wave6_sandbox_ci_integration.py" in text
    assert "scripts/run_wave6_sandbox_ci.py" in text
    assert "wave6-sandbox-ci-evidence" in text
    assert "timeout-minutes: 15" in text


def test_wave6_sandbox_ci_runner_builds_passing_payload() -> None:
    runner = _load_runner()

    payload = runner.build_ci_payload(head_sha="abc1234")

    assert payload["passed"] is True
    assert payload["wave"] == "6"
    assert payload["head_sha"] == "abc1234"
    assert payload["adversarial_report"]["passed"] is True
    assert payload["adversarial_verification"]["passed"] is True
    assert payload["adversarial_artifact"]["kind"] == "sandbox_adversarial_report"
    assert payload["adversarial_artifact"]["sha256"] == payload["adversarial_report"]["digest"]
    assert payload["adversarial_artifact"]["head_sha"] == "abc1234"
    assert payload["adversarial_artifact"]["metadata"]["sandbox_adversarial_passed"] is True


def test_wave6_sandbox_ci_runner_writes_payload(tmp_path: Path) -> None:
    runner = _load_runner()
    output = tmp_path / "wave6-sandbox-ci-report.json"

    payload = runner.write_ci_payload(head_sha="abc1234", output_path=output)

    assert output.exists()
    assert payload["passed"] is True
    assert '"passed": true' in output.read_text(encoding="utf-8")


def _load_runner() -> Any:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "run_wave6_sandbox_ci.py"
    spec = importlib.util.spec_from_file_location("wave6_sandbox_ci_runner", script)
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to load scripts/run_wave6_sandbox_ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
