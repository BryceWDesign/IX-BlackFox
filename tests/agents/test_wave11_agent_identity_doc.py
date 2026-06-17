from __future__ import annotations

from pathlib import Path


def test_wave11_agent_identity_document_exists() -> None:
    document = _document_path()

    assert document.exists()
    assert document.name == "wave11-agent-identity.md"


def test_wave11_agent_identity_document_states_core_boundaries() -> None:
    text = _document_text()

    assert "AI proposes. Humans decide." in text
    assert "Wave 11 does not make BlackFox autonomous" in text
    assert "does not grant production authorization" in text
    assert "does not certify a model, tool, workflow, or deployment" in text
    assert "registered agent is still not trusted by default" in text


def test_wave11_agent_identity_document_covers_required_components() -> None:
    text = _document_text()

    required_sections = (
        "## Agent identity boundary",
        "## Capability boundary",
        "## Authorization boundary",
        "## Human authority boundary",
        "## Provenance boundary",
        "## Adapter boundary",
        "## Tool gateway boundary",
        "## Readiness boundary",
        "## CI boundary",
        "## Non-goals",
        "## Acceptance rule",
    )
    for section in required_sections:
        assert section in text


def test_wave11_agent_identity_document_preserves_non_goal_claims() -> None:
    text = _document_text()

    forbidden_claims = (
        "production authorization",
        "model safety certification",
        "ATO or cATO",
        "DoD endorsement",
        "procurement approval",
        "deployment approval",
        "autonomous agent approval",
    )
    for claim in forbidden_claims:
        assert f"- {claim}" in text


def test_wave11_agent_identity_document_names_acceptance_evidence() -> None:
    text = _document_text()

    assert "every actor is represented as an explicit agent identity" in text
    assert "capability grants are scoped and digest-bound" in text
    assert "non-human actors cannot hold human-only authority" in text
    assert "self-approval is blocked" in text
    assert "authorization decisions are provenance-recorded" in text
    assert "CI evidence is generated without external model or secret access" in text


def _document_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "wave11-agent-identity.md"


def _document_text() -> str:
    return _document_path().read_text(encoding="utf-8")
