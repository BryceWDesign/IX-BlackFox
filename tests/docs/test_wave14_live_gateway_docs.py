from __future__ import annotations

from pathlib import Path


def test_wave14_docs_state_real_enforcement_and_explicit_limits() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "docs" / "wave14-live-authority-gateway.md").read_text(encoding="utf-8")

    required = (
        "evidence-conditioned authority",
        "/mcp",
        "/v1/invoke",
        "2026-07-28",
        "real upstream file write",
        "SQLite",
        "OIDC/OAuth",
        "production readiness",
        "target_digest",
    )
    for phrase in required:
        assert phrase.lower() in text.lower()


def test_readme_surfaces_wave14_before_wave13_foundation() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "README.md").read_text(encoding="utf-8")
    assert "## Wave 14: Live Authority Gateway" in text
    assert "## Wave 13 foundation: Human-Machine Review Board" in text
    assert text.index("## Wave 14") < text.index("## Wave 13 foundation")
