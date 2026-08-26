from __future__ import annotations

from pathlib import Path


def test_wave13_workflow_exists() -> None:
    path = _workflow_path()
    assert path.exists()
    assert path.name == "wave13-human-machine-review-board.yml"


def test_wave13_workflow_runs_focused_tests_and_compilation() -> None:
    text = _workflow_text()
    assert "name: Wave 13 Human-Machine Review Board" in text
    assert "python -m pytest \\" in text
    assert "tests/review_board \\" in text
    assert "tests/ci/test_wave13_review_board_runner.py \\" in text
    assert "tests/ci/test_wave13_review_board_workflow_contract.py \\" in text
    assert "tests/docs/test_wave13_review_board_docs.py \\" in text
    assert "python -m compileall -q \\" in text
    assert "src/ix_blackfox/review_board \\" in text
    assert "scripts/run_wave13_review_board_ci.py \\" in text


def test_wave13_workflow_regenerates_wave12_before_wave13() -> None:
    text = _workflow_text()
    wave12_position = text.index("python scripts/run_wave12_assurance_ci.py")
    wave13_position = text.index("python scripts/run_wave13_review_board_ci.py")
    assert wave12_position < wave13_position
    assert '--head-sha "${{ github.sha }}"' in text
    assert '--expected-status "review_required"' in text
    assert '--expected-status "human_review_required"' in text


def test_wave13_workflow_uploads_complete_review_inspection_surface() -> None:
    text = _workflow_text()
    for name in (
        "wave13-human-machine-review-board.zip",
        "wave13-package-verification.json",
        "wave13-review-case.json",
        "wave13-machine-advisories.json",
        "wave13-board-evaluation.json",
        "wave13-review-board-ci-summary.json",
    ):
        assert name in text
    assert "uses: actions/upload-artifact@v4" in text
    assert "if-no-files-found: error" in text


def test_wave13_workflow_has_no_credentials_or_model_approval_authority() -> None:
    text = _workflow_text()
    assert "permissions:\n  contents: read" in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AZURE_OPENAI" not in text
    assert "AWS_ACCESS_KEY" not in text
    assert "secrets." not in text
    assert "human_review_required" in text


def _workflow_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "wave13-human-machine-review-board.yml"
    )


def _workflow_text() -> str:
    return _workflow_path().read_text(encoding="utf-8")
