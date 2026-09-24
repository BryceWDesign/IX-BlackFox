from pathlib import Path


def test_wave15_docs_state_real_controls_and_claim_boundaries() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "docs" / "wave15-enterprise-identity-delegated-authority.md").read_text(encoding="utf-8")
    for phrase in (
        "RS256",
        "issuer",
        "audience",
        "jti",
        "delegation",
        "revocation",
        "federated_required",
        "does not claim DoD authorization",
        "does not fetch JWKS over the network",
    ):
        assert phrase in text


def test_readme_surfaces_wave15_before_wave14() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "README.md").read_text(encoding="utf-8")
    assert "## Wave 15: Enterprise Identity & Delegated Authority" in text
    assert "## Wave 14" in text
    assert text.index("## Wave 15") < text.index("## Wave 14")
