from __future__ import annotations

from pathlib import Path


def test_wave8_repository_intelligence_docs_exist() -> None:
    path = _doc_path()

    assert path.exists()
    assert path.name == "wave8-repository-intelligence.md"


def test_wave8_repository_intelligence_docs_cover_implemented_pipeline() -> None:
    text = _doc_text()

    required_terms = [
        "inventory",
        "Python code graph",
        "dependency map",
        "source-test coverage map",
        "architectural memory",
        "conservative impact analysis",
        "digest-chained evidence",
        "exportable Wave 8 report",
    ]

    for term in required_terms:
        assert term in text


def test_wave8_repository_intelligence_docs_include_operator_commands() -> None:
    text = _doc_text()

    assert "blackfox repository scan --root . --json" in text
    assert "blackfox repository impact" in text
    assert "blackfox repository report" in text
    assert "blackfox repo-intel scan --root . --json" in text
    assert "python scripts/run_wave8_repository_intelligence_ci.py" in text


def test_wave8_repository_intelligence_docs_include_artifact_paths_and_workflow() -> None:
    text = _doc_text()

    assert ".github/workflows/wave8-repository-intelligence.yml" in text
    assert ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json" in text
    assert ".blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json" in text
    assert "wave8.repository_intelligence.v1" in text


def test_wave8_repository_intelligence_docs_preserve_non_claims() -> None:
    text = _doc_text()

    non_claims = [
        "does not certify correctness",
        "does not replace human review",
        "does not mean the repository is production-ready",
        "does not mean the code is formally verified",
        "does not mean the code is certified",
        "does not mean the code is approved by any government or defense organization",
        "does not mean a model-generated patch is safe",
        "does not mean a human reviewer can be skipped",
        "does not mean autonomous execution authority has been granted",
    ]

    for non_claim in non_claims:
        assert non_claim in text


def test_wave8_repository_intelligence_docs_preserve_positioning_language() -> None:
    text = _doc_text()

    assert "AI proposes. Humans decide." in text
    assert "model output as untrusted input" in text
    assert "review evidence" in text
    assert "DoD-approved" in text
    assert "source-available research implementation" in text
    assert "Wave 8 makes repository-change boundaries more inspectable" in text


def test_wave8_repository_intelligence_docs_explicitly_label_overclaim_examples_as_avoid_language() -> None:
    text = _doc_text()

    assert "Avoid wording like:" in text
    assert "The repo understands itself." in text
    assert "Wave 8 proves patches are safe." in text
    assert "Wave 8 makes AI coding autonomous." in text
    assert "The correct positioning is:" in text
    assert (
        "Wave 8 makes repository-change boundaries more inspectable before "
        "AI-assisted code changes are trusted."
    ) in text


def _doc_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "wave8-repository-intelligence.md"
    )


def _doc_text() -> str:
    return _doc_path().read_text(encoding="utf-8")
