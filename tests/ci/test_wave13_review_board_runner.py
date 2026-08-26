from __future__ import annotations

from pathlib import Path

import pytest
from scripts.run_wave13_review_board_ci import run_wave13_review_board_ci
from tests.review_board.helpers import REVISION, WAVE13_TIME, build_wave12_package

from ix_blackfox.review_board import ReviewBoardStatus, ReviewRole
from ix_blackfox.review_board.verify import verify_review_board_package


def test_wave13_runner_consumes_real_verified_wave12_package_without_fake_humans(
    tmp_path: Path,
) -> None:
    wave12 = build_wave12_package(tmp_path)
    root = wave12.parent

    summary = run_wave13_review_board_ci(
        root=root,
        head_sha=REVISION,
        generated_at=WAVE13_TIME,
        wave12_package=Path("wave12.zip"),
    )

    assert summary["passed"] is True
    assert summary["board_status"] == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value
    assert summary["human_review_supplied"] is False
    assert summary["external_verification_supplied"] is False
    assert summary["external_verification_count"] == 0
    assert len(summary["external_verification_context_digest"]) == 64
    assert summary["qualifying_human_approval_count"] == 0
    assert summary["machine_vote_weight"] == 0
    assert summary["required_roles"] == sorted(role.value for role in ReviewRole)
    assert summary["missing_required_roles"] == sorted(role.value for role in ReviewRole)
    assert summary["upstream_wave12_verification_passed"] is True

    package = root / ".blackfox-artifacts/wave13/wave13-human-machine-review-board.zip"
    verification = verify_review_board_package(package)
    assert verification.passed is True
    assert verification.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value


def test_wave13_runner_rejects_wave12_revision_not_matching_ci_head(tmp_path: Path) -> None:
    wave12 = build_wave12_package(tmp_path)

    with pytest.raises(ValueError, match="does not match"):
        run_wave13_review_board_ci(
            root=wave12.parent,
            head_sha="f" * 40,
            generated_at=WAVE13_TIME,
            wave12_package=Path("wave12.zip"),
        )


def test_wave13_runner_source_preserves_human_authority_boundary() -> None:
    text = _runner_text()
    assert "human_reviews=()," in text
    assert '"human_review_supplied": False' in text
    assert '"external_verification_supplied": False' in text
    assert '"machine_vote_weight": 0' in text
    assert "admit_wave12_package(" in text
    assert "verify_review_board_package(" in text
    assert "verification.passed" in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AWS_ACCESS_KEY" not in text
    assert "secrets." not in text


def _runner_text() -> str:
    path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "run_wave13_review_board_ci.py"
    )
    return path.read_text(encoding="utf-8")
