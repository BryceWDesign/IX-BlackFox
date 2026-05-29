from __future__ import annotations

from pathlib import Path


def test_wave9_compliance_audit_workflow_exists() -> None:
    workflow = _workflow_path()

    assert workflow.exists()
    assert workflow.name == "wave9-compliance-audit.yml"


def test_wave9_compliance_audit_workflow_runs_targeted_wave9_checks() -> None:
    text = _workflow_text()

    assert "name: Wave 9 Compliance Audit Attestation" in text
    assert "python -m pytest tests/audit -q" in text
    assert "python -m pytest tests/ci/test_wave9_compliance_audit_ci_integration.py -q" in text
    assert "python -m pytest tests/ci/test_wave9_compliance_audit_workflow_contract.py -q" in text
    assert "python -m pytest tests/interface/test_audit_cli_routing.py -q" in text
    assert (
        "python -m compileall -q src/ix_blackfox/audit scripts tests/audit tests/ci tests/interface"
        in text
    )


def test_wave9_compliance_audit_workflow_generates_ci_evidence() -> None:
    text = _workflow_text()

    assert "python scripts/run_wave9_compliance_audit_ci.py" in text
    assert '--head-sha "${{ github.sha }}"' in text
    assert (
        '--output ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json"'
        in text
    )
    assert (
        '--engine-evidence-output ".blackfox-artifacts/wave9/wave9-ci-engine-evidence.json"'
        in text
    )
    assert (
        '--summary-output ".blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json"'
        in text
    )
    assert '--expected-disposition "blocked"' in text


def test_wave9_compliance_audit_workflow_validates_report_without_requiring_fake_approval() -> None:
    text = _workflow_text()

    assert "Validate Wave 9 governance report shape and digest" in text
    assert "python -m ix_blackfox.interface.cli audit validate" in text
    assert '--report ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json"' in text
    assert "audit gate" not in text
    assert "--no-require-human-approval" not in text
    assert "signoff" not in text.lower()


def test_wave9_compliance_audit_workflow_uploads_artifacts() -> None:
    text = _workflow_text()

    assert "uses: actions/upload-artifact@v4" in text
    assert "name: wave9-compliance-audit-evidence" in text
    assert ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json" in text
    assert ".blackfox-artifacts/wave9/wave9-ci-engine-evidence.json" in text
    assert ".blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json" in text
    assert "if-no-files-found: error" in text


def test_wave9_compliance_audit_workflow_is_offline_and_devsecops_oriented() -> None:
    text = _workflow_text()

    assert "timeout-minutes: 15" in text
    assert "contents: read" in text
    assert "uses: actions/checkout@v4" in text
    assert "uses: actions/setup-python@v5" in text
    assert "python -m pip install -e \".[dev]\"" in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AZURE_OPENAI" not in text
    assert "secrets." not in text


def _workflow_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "wave9-compliance-audit.yml"
    )


def _workflow_text() -> str:
    return _workflow_path().read_text(encoding="utf-8")
