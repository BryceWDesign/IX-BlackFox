from __future__ import annotations

from pathlib import Path


def test_wave13_review_board_document_exists() -> None:
    path = _doc_path()
    assert path.exists()
    assert path.name == "wave13-human-machine-review-board.md"


def test_wave13_document_covers_locked_role_set_and_machine_authority_boundary() -> None:
    text = _doc_text()
    for role in (
        "security",
        "QA",
        "systems",
        "safety",
        "operations",
        "manufacturing",
        "maintainer",
    ):
        assert role in text
    assert "`authoritative: false`" in text
    assert "`vote_weight: 0`" in text
    assert "seven distinct human reviewer" in text


def test_wave13_document_defines_real_nested_wave12_verification() -> None:
    text = _doc_text()
    assert "exact Wave 12 ZIP is embedded" in text
    assert "independently verified again" in text
    assert "admit_wave12_package()" in text
    assert "corrupted nested Wave 12 package" in text
    assert "refreshing only the outer Wave 13 hashes" in text


def test_wave13_document_preserves_dissent_conflict_and_recusal() -> None:
    text = _doc_text()
    assert "trusted-context-confirmed `reject` fails closed" in text
    assert "trusted-context-confirmed `request_changes` also fails closed" in text
    assert "open `EvidenceChallenge` blocks" in text
    assert "conflicted reviewer must recuse" in text
    assert "recused review contributes no approval authority" in text


def test_wave13_document_exposes_commands_workflow_artifacts_and_schemas() -> None:
    text = _doc_text()
    assert "blackfox review-board build" in text
    assert "blackfox review-board verify" in text
    assert "blackfox review-board gate" in text
    assert "scripts/run_wave13_review_board_ci.py" in text
    assert ".github/workflows/wave13-human-machine-review-board.yml" in text
    assert "wave13-human-machine-review-board.zip" in text
    for schema in (
        "wave13-review-case.schema.json",
        "wave13-machine-advisories.schema.json",
        "wave13-human-reviews.schema.json",
        "wave13-evidence-challenges.schema.json",
        "wave13-board-evaluation.schema.json",
        "wave13-package-verification.schema.json",
        "wave13-review-board-ci-summary.schema.json",
    ):
        assert schema in text


def test_wave13_document_keeps_external_identity_verification_honest() -> None:
    text = _doc_text()
    assert "**not an identity provider**" in text
    assert "**cannot self-authorize a review**" in text
    assert "exact human-review digest" in text
    assert "Seven serialized" in text
    assert "zero human reviews and zero external-verification records" in text
    assert "does not manufacture a human decision" in text


def test_wave13_document_defines_three_bounded_states_and_non_claims() -> None:
    text = _doc_text()
    assert "`blocked`" in text
    assert "`human_review_required`" in text
    assert "`approved_for_next_gate`" in text
    assert "does not mean production approved" in text
    for non_claim in (
        "identity proofing",
        "qualified digital signatures",
        "certification or accreditation",
        "ATO or cATO authority",
        "deployment or production authorization",
        "autonomous human-equivalent approval",
    ):
        assert non_claim in text


def test_system_architecture_includes_wave13_review_board_layer() -> None:
    text = (
        Path(__file__).resolve().parents[2] / "docs" / "system-architecture.md"
    ).read_text(encoding="utf-8")
    assert "## 16. Human-Machine Review Board" in text
    assert "`review_board/`" in text
    assert "Machine advisories remain" in text
    assert "zero vote weight" in text
    assert "seven distinct" in text
    assert "exact review digest" in text
    assert "serialized `externally_verified`" in text
    assert "`approved_for_next_gate`" in text


def _doc_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "wave13-human-machine-review-board.md"
    )


def _doc_text() -> str:
    return _doc_path().read_text(encoding="utf-8")
