from __future__ import annotations

from pathlib import Path


def test_wave12_assurance_document_exists() -> None:
    path = _doc_path()
    assert path.exists()
    assert path.name == "wave12-certification-ready-evidence.md"


def test_wave12_document_covers_the_implemented_modules() -> None:
    text = _doc_text()
    for module in (
        "`models`",
        "`profiles`",
        "`evidence`",
        "`crosswalk`",
        "`report`",
        "`quality`",
        "`package`",
        "`verify`",
        "`cli`",
    ):
        assert module in text


def test_wave12_document_defines_real_collection_and_revision_boundaries() -> None:
    text = _doc_text()
    for boundary in (
        "absolute paths",
        "parent traversal",
        "symlink path components",
        "duplicate artifact ids",
        "common credential and private-key filenames",
        "PEM private-key markers",
        "RFC 6901-style JSON pointer",
        "Stale evidence is not silently relabeled.",
    ):
        assert boundary in text


def test_wave12_document_bounds_external_framework_mappings() -> None:
    text = _doc_text()
    for framework in (
        "NIST SP 800-218 SSDF 1.1",
        "NIST AI RMF 1.0",
        "NIST OSCAL Assessment Results",
        "SLSA 1.2",
        "in-toto Statement v1",
    ):
        assert framework in text
    assert "These are mappings only." in text
    assert "does not emit a conformant OSCAL Assessment Results document" in text
    assert "does not claim a SLSA level" in text
    assert "It is not a signed attestation." in text


def test_wave12_document_exposes_commands_workflow_and_artifacts() -> None:
    text = _doc_text()
    assert "scripts/run_wave12_assurance_ci.py" in text
    assert ".github/workflows/wave12-assurance-evidence.yml" in text
    assert "blackfox assurance build" in text
    assert "blackfox assurance verify" in text
    assert "blackfox assurance gate" in text
    assert "wave12-certification-ready-evidence.zip" in text
    assert "wave12-package-verification.json" in text


def test_wave12_document_keeps_external_identity_verification_real() -> None:
    text = _doc_text()
    assert "`externally_verified`" in text
    assert "cannot move the CLI to `ready_for_external_assessment`" in text
    assert "An external identity or signature verifier must validate" in text
    assert "Wave 12 does not fake that verifier." in text


def test_wave12_document_says_verifier_recomputes_decisions() -> None:
    text = _doc_text()
    assert "does not trust self-consistent hashes alone" in text
    assert "recomputes the control crosswalk and readiness findings" in text
    assert "Rewriting a status and refreshing its digests" in text


def test_wave12_document_preserves_three_states_and_non_claims() -> None:
    text = _doc_text()
    assert "### `blocked`" in text
    assert "### `review_required`" in text
    assert "### `ready_for_external_assessment`" in text
    for non_goal in (
        "FedRAMP authorization",
        "ATO or cATO",
        "DoD approval or endorsement",
        "AWS approval or endorsement",
        "a built-in external reviewer-identity verifier",
        "autonomous approval authority",
    ):
        assert non_goal in text
    assert "## Strongest valid claim" in text


def test_system_architecture_includes_wave12_assurance_layer() -> None:
    text = _normalized_text(_architecture_path())
    assert "## 15. Assurance Evidence Packaging" in text
    assert "- `assurance/`" in text
    assert "recomputes the control crosswalk" in text
    assert "only an externally verified human-review artifact" in text


def _doc_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "wave12-certification-ready-evidence.md"
    )


def _architecture_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "system-architecture.md"


def _doc_text() -> str:
    return _normalized_text(_doc_path())


def _normalized_text(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())
