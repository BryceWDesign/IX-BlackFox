from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.assurance.cli import main
from ix_blackfox.interface.cli import main as root_main
from tests.assurance.helpers import FIXED_TIME, REVISION, build_stack


def test_cli_build_verify_and_review_required_gate(
    tmp_path: Path,
    capsys,
) -> None:
    stack = build_stack(tmp_path)
    spec_path = _write_spec(stack)
    package_path = stack.root / "wave12-package.zip"
    verification_path = stack.root / "wave12-verification.json"
    summary_path = stack.root / "wave12-summary.json"

    build_exit = main(
        [
            "build",
            "--root",
            str(stack.root),
            "--revision",
            REVISION,
            "--generated-at",
            FIXED_TIME,
            "--evidence-spec",
            str(spec_path.relative_to(stack.root)),
            "--output",
            package_path.name,
            "--verification-output",
            verification_path.name,
            "--summary-output",
            summary_path.name,
            "--json",
        ]
    )
    assert build_exit == 0
    output = json.loads(capsys.readouterr().out)
    assert output["passed"] is True
    assert output["readiness_status"] == "review_required"
    assert package_path.is_file()
    assert verification_path.is_file()
    assert summary_path.is_file()

    assert main(["verify", "--package", str(package_path), "--json"]) == 0
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["passed"] is True

    assert main(["gate", "--package", str(package_path), "--json"]) == 1
    blocked_output = json.loads(capsys.readouterr().out)
    assert blocked_output["passed"] is False

    assert (
        main(
            [
                "gate",
                "--package",
                str(package_path),
                "--allow-review-required",
                "--json",
            ]
        )
        == 0
    )
    allowed_output = json.loads(capsys.readouterr().out)
    assert allowed_output["passed"] is True


def test_root_cli_dispatches_assurance_verifier(tmp_path: Path, capsys) -> None:
    stack = build_stack(tmp_path)
    spec_path = _write_spec(stack)
    package_path = stack.root / "package.zip"
    assert (
        main(
            [
                "build",
                "--root",
                str(stack.root),
                "--revision",
                REVISION,
                "--generated-at",
                FIXED_TIME,
                "--evidence-spec",
                str(spec_path),
                "--output",
                package_path.name,
                "--verification-output",
                "verification.json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert root_main(["assurance", "verify", "--package", str(package_path)]) == 0
    assert "verification: passed" in capsys.readouterr().out


def test_cli_reports_invalid_evidence_spec_without_traceback(
    tmp_path: Path,
    capsys,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".blackfox-workspace").write_text("\n", encoding="utf-8")
    bad = root / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    exit_code = main(
        [
            "build",
            "--root",
            str(root),
            "--revision",
            REVISION,
            "--evidence-spec",
            str(bad),
        ]
    )
    assert exit_code == 2
    assert "Wave 12 assurance input error" in capsys.readouterr().err


def _write_spec(stack) -> Path:
    specs = []
    for item in stack.evidence:
        artifact = item.artifact
        specs.append(
            {
                "artifact_id": artifact.artifact_id,
                "source_wave": artifact.source_wave.value,
                "evidence_kind": artifact.evidence_kind.value,
                "source_path": artifact.metadata["source_path"],
                "package_path": artifact.path,
                "media_type": artifact.media_type,
                "producer": artifact.producer,
                "schema_version": artifact.schema_version,
                "required": artifact.required,
                "revision_json_pointer": "/head_sha",
            }
        )
    path = stack.root / "evidence-spec.json"
    path.write_text(
        json.dumps({"evidence": specs}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path
