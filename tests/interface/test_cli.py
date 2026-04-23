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
