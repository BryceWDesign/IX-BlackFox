from pathlib import Path


def test_wave15_workflow_runs_quality_full_tests_and_live_proof() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / ".github" / "workflows" / "wave15-enterprise-identity.yml").read_text(encoding="utf-8")
    assert 'python-version: ["3.11", "3.12", "3.13"]' in text
    assert "python -m ruff check src tests scripts" in text
    assert "python -m mypy src" in text
    assert "python -m pytest -q" in text
    assert "run_wave15_enterprise_identity_ci.py --root ." in text
    assert "wave15-enterprise-identity-summary.json" in text
