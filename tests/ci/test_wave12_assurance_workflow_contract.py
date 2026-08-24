from __future__ import annotations

from pathlib import Path


def test_wave12_workflow_exists() -> None:
    workflow = _workflow_path()
    assert workflow.exists()
    assert workflow.name == "wave12-assurance-evidence.yml"


def test_wave12_workflow_runs_real_tests_and_compilation() -> None:
    text = _workflow_text()
    assert "name: Wave 12 Assurance Evidence" in text
    assert "python -m pytest \\" in text
    assert "tests/assurance \\" in text
    assert "tests/ci/test_wave12_assurance_runner_contract.py \\" in text
    assert "tests/ci/test_wave12_assurance_workflow_contract.py \\" in text
    assert "tests/docs/test_wave12_assurance_docs.py \\" in text
    assert "python -m compileall -q \\" in text
    assert "src/ix_blackfox/assurance \\" in text
    assert "scripts/run_wave12_assurance_ci.py \\" in text


def test_wave12_workflow_regenerates_and_verifies_package() -> None:
    text = _workflow_text()
    assert "python scripts/run_wave12_assurance_ci.py" in text
    assert '--head-sha "${{ github.sha }}"' in text
    assert '--expected-status "review_required"' in text
    assert "--skip-prerequisites" not in text
    assert "--skip-quality-gates" not in text


def test_wave12_workflow_uploads_complete_inspection_surface() -> None:
    text = _workflow_text()
    expected_paths = (
        "wave12-certification-ready-evidence.zip",
        "wave12-package-verification.json",
        "wave12-assurance-readiness-report.json",
        "wave12-assurance-crosswalk.json",
        "wave12-assurance-manifest.json",
        "wave12-evidence-spec.json",
        "wave12-assurance-ci-summary.json",
    )
    assert "uses: actions/upload-artifact@v4" in text
    assert "name: wave12-assurance-evidence" in text
    assert "if-no-files-found: error" in text
    for path in expected_paths:
        assert path in text


def test_wave12_workflow_has_no_credentials_or_external_model_authority() -> None:
    text = _workflow_text()
    assert "permissions:\n  contents: read" in text
    assert "timeout-minutes: 30" in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AZURE_OPENAI" not in text
    assert "AWS_ACCESS_KEY" not in text
    assert "secrets." not in text


def test_wave12_workflow_does_not_claim_certification_or_approval() -> None:
    text = _workflow_text().lower()
    assert "certification granted" not in text
    assert "compliance achieved" not in text
    assert "ato granted" not in text
    assert "cato granted" not in text
    assert "production approved" not in text
    assert "autonomous approval" not in text


def _workflow_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "wave12-assurance-evidence.yml"
    )


def _workflow_text() -> str:
    return _workflow_path().read_text(encoding="utf-8")
