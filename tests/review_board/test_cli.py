from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.interface.cli import main as blackfox_main
from ix_blackfox.review_board.cli import main
from tests.review_board.helpers import WAVE13_TIME, build_wave12_package


def test_review_board_cli_build_verify_and_pending_gate(tmp_path: Path, capsys) -> None:
    wave12 = build_wave12_package(tmp_path)
    output = tmp_path / "wave13.zip"

    assert (
        main(
            [
                "build",
                "--wave12-package",
                str(wave12),
                "--output",
                str(output),
                "--admitted-at",
                WAVE13_TIME,
            ]
        )
        == 0
    )
    build_payload = json.loads(capsys.readouterr().out)
    assert build_payload["status"] == "human_review_required"
    assert build_payload["verification_passed"] is True

    assert main(["verify", "--package", str(output)]) == 0
    verification_payload = json.loads(capsys.readouterr().out)
    assert verification_payload["passed"] is True
    assert verification_payload["status"] == "human_review_required"

    assert main(["gate", "--package", str(output)]) == 1
    strict_gate = json.loads(capsys.readouterr().out)
    assert strict_gate["gate_passed"] is False

    assert (
        main(
            [
                "gate",
                "--package",
                str(output),
                "--allow-human-review-required",
            ]
        )
        == 0
    )
    pending_gate = json.loads(capsys.readouterr().out)
    assert pending_gate["gate_passed"] is True


def test_top_level_blackfox_cli_routes_review_board_alias(tmp_path: Path, capsys) -> None:
    wave12 = build_wave12_package(tmp_path)
    output = tmp_path / "wave13.zip"
    assert (
        blackfox_main(
            [
                "review-board",
                "build",
                "--wave12-package",
                str(wave12),
                "--output",
                str(output),
                "--admitted-at",
                WAVE13_TIME,
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert blackfox_main(["review", "verify", "--package", str(output)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True


def test_review_board_cli_rejects_invalid_wave12_package(tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not-a-zip")

    assert (
        main(
            [
                "build",
                "--wave12-package",
                str(bad),
                "--output",
                str(tmp_path / "wave13.zip"),
                "--admitted-at",
                WAVE13_TIME,
            ]
        )
        == 2
    )
    assert "Wave 13 review-board input error" in capsys.readouterr().err
