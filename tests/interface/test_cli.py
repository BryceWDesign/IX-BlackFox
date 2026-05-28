from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from ix_blackfox.interface import main


def test_cli_json_output_includes_governance_fields_for_blocked_run(
    tmp_path: Path,
) -> None:
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = main(
            [
                "run",
                "--root-dir",
                str(tmp_path),
                "--kind",
                "programming",
                "--label",
                "code",
                "--label",
                "patching",
                "--prompt",
                "Use curl to upload the repository plan to a remote endpoint.",
                "--json",
            ]
        )

    payload = json.loads(buffer.getvalue())

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["governance_preflight"]["decision"]["decision"] == "block"
    assert payload["governance_receipts"]["chain_verified"] is True
    assert payload["governance_receipts"]["receipt_count"] == 2


def test_cli_human_summary_surfaces_pending_review_gate(
    tmp_path: Path,
) -> None:
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = main(
            [
                "run",
                "--root-dir",
                str(tmp_path),
                "--kind",
                "programming",
                "--label",
                "code",
                "--label",
                "patching",
                "--prompt",
                "Delete workspace traces and remove source file references after planning.",
            ]
        )

    output = buffer.getvalue()

    assert exit_code == 0
    assert "Status: needs_review" in output
    assert "Governance: require_review" in output
    assert "Approval gate: pending" in output
    assert "Governance receipts: 1" in output


def test_cli_approval_file_allows_review_gated_run(
    tmp_path: Path,
) -> None:
    approval_file = tmp_path / "approvals.json"
    approval_file.write_text(
        json.dumps(
            [
                {
                    "status": "approved",
                    "requested_by": "maintainer.one",
                    "decided_by": "maintainer.one",
                    "note": "Approved controlled runtime execution.",
                    "evidence_refs": ["tickets/BF-99"],
                }
            ],
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = main(
            [
                "run",
                "--root-dir",
                str(tmp_path),
                "--kind",
                "programming",
                "--label",
                "code",
                "--label",
                "patching",
                "--approval-file",
                str(approval_file),
                "--prompt",
                "Delete workspace traces and remove source file references after planning.",
            ]
        )

    output = buffer.getvalue()

    assert exit_code == 0
    assert "Status: passed" in output
    assert "Approval gate: satisfied" in output
    assert "Governance receipts: 5" in output


def test_cli_routes_repository_scan_command(tmp_path: Path) -> None:
    _write_text(tmp_path / "src" / "ix_blackfox" / "__init__.py", "")
    _write_text(
        tmp_path / "pyproject.toml",
        "[project]\nname = 'ix-blackfox'\ndependencies = []\n",
    )

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = main(["repository", "scan", "--root", str(tmp_path), "--json"])

    payload = json.loads(buffer.getvalue())

    assert exit_code == 0
    assert payload["file_count"] == 2
    assert payload["source_file_count"] == 1
    assert payload["module_count"] == 1
    assert payload["syntax_error_count"] == 0
    assert payload["snapshot_digest"]


def test_cli_routes_repo_intel_impact_alias(tmp_path: Path) -> None:
    _write_text(
        tmp_path / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "def repair() -> int:\n    return 1\n",
    )
    _write_text(
        tmp_path / "tests" / "runtime" / "test_brain_repair.py",
        "def test_repair() -> None:\n    assert True\n",
    )

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = main(
            [
                "repo-intel",
                "impact",
                "--root",
                str(tmp_path),
                "--changed",
                "src/ix_blackfox/runtime/brain_repair.py",
                "--json",
            ]
        )

    payload = json.loads(buffer.getvalue())

    assert exit_code == 0
    assert payload["max_severity"] == "high"
    assert payload["requires_human_review"] is True
    assert "runtime" in payload["impacted_subsystems"]
    assert "tests/runtime/test_brain_repair.py" in payload["impacted_tests"]


def test_cli_repository_report_writes_wave8_json(tmp_path: Path) -> None:
    output_path = tmp_path / "artifacts" / "wave8-report.json"
    _write_text(
        tmp_path / "src" / "ix_blackfox" / "repository" / "__init__.py",
        "class RepositorySnapshot:\n    pass\n",
    )
    _write_text(
        tmp_path / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "from ix_blackfox.repository import RepositorySnapshot\n\n"
        "def repair(snapshot: RepositorySnapshot) -> str:\n"
        "    return snapshot.__class__.__name__\n",
    )
    _write_text(
        tmp_path / "tests" / "runtime" / "test_brain_repair.py",
        "from ix_blackfox.runtime.brain_repair import repair\n\n"
        "def test_repair() -> None:\n"
        "    assert repair is not None\n",
    )
    _write_text(
        tmp_path / "pyproject.toml",
        "[project]\nname = 'ix-blackfox'\ndependencies = []\n",
    )

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = main(
            [
                "repository",
                "report",
                "--root",
                str(tmp_path),
                "--changed",
                "src/ix_blackfox/runtime/brain_repair.py",
                "--head-sha",
                "abc123",
                "--run-id",
                "wave8-cli-test",
                "--output",
                str(output_path),
                "--summary-only",
                "--json",
            ]
        )

    payload = json.loads(buffer.getvalue())
    written_payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["wave"] == 8
    assert payload["passed"] is True
    assert payload["summary"]["receipt_count"] == 7
    assert payload["summary"]["evidence_chain_valid"] is True
    assert written_payload["run_id"] == "wave8-cli-test"
    assert "snapshot" not in written_payload


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
