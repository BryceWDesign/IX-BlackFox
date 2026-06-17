from __future__ import annotations

from pathlib import Path


def test_wave11_agent_identity_workflow_exists() -> None:
    workflow = _workflow_path()

    assert workflow.exists()
    assert workflow.name == "wave11-agent-identity.yml"


def test_wave11_agent_identity_workflow_runs_targeted_wave11_checks() -> None:
    text = _workflow_text()

    assert "name: Wave 11 Agent Identity" in text
    assert "python -m pytest tests/agents -q" in text
    assert (
        "python -m pytest tests/ci/test_wave11_agent_identity_ci_integration.py -q"
        in text
    )
    assert (
        "python -m pytest tests/ci/test_wave11_agent_identity_workflow_contract.py -q"
        in text
    )
    assert (
        "python -m compileall -q src/ix_blackfox/agents scripts tests/agents tests/ci"
        in text
    )


def test_wave11_agent_identity_workflow_generates_ci_evidence() -> None:
    text = _workflow_text()

    assert "python scripts/run_wave11_agent_identity_ci.py" in text
    assert '--head-sha "${{ github.sha }}"' in text
    assert (
        '--output ".blackfox-artifacts/wave11/wave11-agent-readiness-report.json"'
        in text
    )
    assert (
        '--engine-evidence-output ".blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json"'
        in text
    )
    assert (
        '--summary-output ".blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json"'
        in text
    )
    assert '--expected-status "warning"' in text


def test_wave11_agent_identity_workflow_uploads_artifacts() -> None:
    text = _workflow_text()

    assert "uses: actions/upload-artifact@v4" in text
    assert "name: wave11-agent-identity-evidence" in text
    assert ".blackfox-artifacts/wave11/wave11-agent-readiness-report.json" in text
    assert (
        ".blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json"
        in text
    )
    assert ".blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json" in text
    assert "if-no-files-found: error" in text


def test_wave11_agent_identity_workflow_is_offline_authority_oriented() -> None:
    text = _workflow_text()

    assert "timeout-minutes: 15" in text
    assert "contents: read" in text
    assert "uses: actions/checkout@v4" in text
    assert "uses: actions/setup-python@v5" in text
    assert 'python -m pip install -e ".[dev]"' in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AZURE_OPENAI" not in text
    assert "secrets." not in text


def test_wave11_agent_identity_workflow_does_not_claim_production_authority() -> None:
    text = _workflow_text().lower()

    assert "production authorization" not in text
    assert "model safety certification" not in text
    assert "ato" not in text
    assert "cato" not in text
    assert "approval granted" not in text
    assert "autonomous approval" not in text


def _workflow_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "wave11-agent-identity.yml"
    )


def _workflow_text() -> str:
    return _workflow_path().read_text(encoding="utf-8")
