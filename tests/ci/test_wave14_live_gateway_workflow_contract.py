from __future__ import annotations

from pathlib import Path


def test_wave14_workflow_runs_quality_tests_and_live_network_proof() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / ".github" / "workflows" / "wave14-live-authority-gateway.yml").read_text(
        encoding="utf-8"
    )
    assert "python -m ruff check src tests scripts" in text
    assert "python -m mypy src" in text
    assert "tests/live_gateway" in text
    assert "run_wave14_live_gateway_ci.py --root ." in text
    assert "wave14-live-authority-gateway-summary.json" in text
    assert 'python-version: ["3.11", "3.12", "3.13"]' in text
