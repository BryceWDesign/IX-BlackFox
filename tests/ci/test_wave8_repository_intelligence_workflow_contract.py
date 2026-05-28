from __future__ import annotations

from pathlib import Path


def test_wave8_repository_intelligence_workflow_exists() -> None:
    workflow = _workflow_path()

    assert workflow.exists()
    assert workflow.name == "wave8-repository-intelligence.yml"


def test_wave8_repository_intelligence_workflow_runs_targeted_wave8_checks() -> None:
    text = _workflow_text()

    assert "name: Wave 8 Repository Intelligence" in text
    assert "python -m pytest tests/repository -q" in text
    assert (
        "python -m pytest tests/ci/test_wave8_repository_intelligence_ci_integration.py -q"
        in text
    )
    assert (
        "python -m pytest tests/ci/test_wave8_repository_intelligence_workflow_contract.py -q"
        in text
    )
    assert (
        "python -m compileall -q src/ix_blackfox/repository scripts tests/repository tests/ci"
        in text
    )


def test_wave8_repository_intelligence_workflow_generates_ci_evidence() -> None:
    text = _workflow_text()

    assert "python scripts/run_wave8_repository_intelligence_ci.py" in text
    assert '--head-sha "${{ github.sha }}"' in text
    assert (
        '--output ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json"'
        in text
    )
    assert (
        '--evidence-output ".blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json"'
        in text
    )


def test_wave8_repository_intelligence_workflow_uploads_artifacts() -> None:
    text = _workflow_text()

    assert "uses: actions/upload-artifact@v4" in text
    assert "name: wave8-repository-intelligence-evidence" in text
    assert (
        ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json"
        in text
    )
    assert (
        ".blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json"
        in text
    )
    assert "if-no-files-found: error" in text


def test_wave8_repository_intelligence_workflow_is_offline_evidence_oriented() -> None:
    text = _workflow_text()

    assert "timeout-minutes: 15" in text
    assert "contents: read" in text
    assert "uses: actions/checkout@v4" in text
    assert "uses: actions/setup-python@v5" in text
    assert "python -m pip install -e \".[dev]\"" in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AZURE_OPENAI" not in text


def _workflow_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "wave8-repository-intelligence.yml"
    )


def _workflow_text() -> str:
    return _workflow_path().read_text(encoding="utf-8")
