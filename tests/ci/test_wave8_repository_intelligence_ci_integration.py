from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


def test_wave8_repository_intelligence_ci_runner_builds_passing_report() -> None:
    runner = _load_runner()
    repo_root = Path(__file__).resolve().parents[2]

    report = runner.build_wave8_repository_intelligence_ci_report(
        root=repo_root,
        head_sha="abc1234",
        changed_paths=("src/ix_blackfox/repository/report.py",),
        run_id="wave8-ci-test",
    )
    payload = runner.build_ci_payload(
        head_sha="abc1234",
        report=report,
        include_full=False,
    )

    assert payload["passed"] is True
    assert payload["wave"] == "8"
    assert payload["head_sha"] == "abc1234"
    assert payload["run_id"] == "wave8-ci-test"
    assert payload["summary"]["file_count"] > 0
    assert payload["summary"]["source_file_count"] > 0
    assert payload["summary"]["test_file_count"] > 0
    assert payload["summary"]["syntax_error_count"] == 0
    assert payload["summary"]["receipt_count"] == 7
    assert payload["summary"]["evidence_chain_valid"] is True
    assert payload["report"]["wave"] == 8
    assert payload["report"]["passed"] is True
    assert "production certification" in payload["scope_note"]


def test_wave8_repository_intelligence_ci_runner_writes_report_and_evidence(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    repo_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "wave8-repository-intelligence-ci-report.json"
    evidence_output = tmp_path / "wave8-repository-intelligence-evidence.json"

    payload = runner.write_ci_payload(
        root=repo_root,
        head_sha="abc1234",
        output_path=output,
        evidence_output_path=evidence_output,
        changed_paths=("src/ix_blackfox/repository/report.py",),
        include_full=False,
    )

    assert output.exists()
    assert evidence_output.exists()
    assert payload["passed"] is True

    report_payload = json.loads(output.read_text(encoding="utf-8"))
    evidence_payload = json.loads(evidence_output.read_text(encoding="utf-8"))

    assert report_payload["passed"] is True
    assert report_payload["wave"] == "8"
    assert report_payload["report"]["schema_version"] == "wave8.repository_intelligence.v1"
    assert report_payload["summary"]["receipt_count"] == 7
    assert report_payload["evidence_validation"]["valid"] is True

    assert evidence_payload["chain_valid"] is True
    assert evidence_payload["receipt_count"] == 7
    assert evidence_payload["event_types"][0] == "inventory_snapshot"
    assert evidence_payload["event_types"][-1] == "report_exported"


def test_wave8_repository_intelligence_ci_runner_main_returns_zero_for_passing_payload(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    repo_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "wave8-repository-intelligence-ci-report.json"

    exit_code = runner.main(
        [
            "--root",
            str(repo_root),
            "--head-sha",
            "abc1234",
            "--changed",
            "src/ix_blackfox/repository/report.py",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.exists()

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["summary"]["evidence_chain_valid"] is True


def test_wave8_repository_intelligence_ci_runner_supports_default_changed_paths(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    repo_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "wave8-repository-intelligence-ci-report.json"

    payload = runner.write_ci_payload(
        root=repo_root,
        head_sha="abc1234",
        output_path=output,
    )

    assert payload["passed"] is True
    assert payload["changed_paths"] == [
        "scripts/run_wave8_repository_intelligence_ci.py",
        "src/ix_blackfox/repository/report.py",
    ]


def _load_runner() -> Any:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "run_wave8_repository_intelligence_ci.py"
    spec = importlib.util.spec_from_file_location(
        "wave8_repository_intelligence_ci_runner",
        script,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(
            "Unable to load scripts/run_wave8_repository_intelligence_ci.py"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
