from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ix_blackfox.interface.cli import main as blackfox_main
from ix_blackfox.workflow.cli import main as workflow_main


def test_wave5_workflow_cli_pr_gate_passes_with_bound_ci_evidence(tmp_path: Path) -> None:
    evidence_file = tmp_path / "pr-evidence.json"
    ci_file = tmp_path / "ci-evidence.json"
    evidence_file.write_text(json.dumps(_evidence_pack()), encoding="utf-8")
    ci_file.write_text(json.dumps(_ci_evidence()), encoding="utf-8")
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = workflow_main(
            [
                "pr-gate",
                "--evidence-pack",
                str(evidence_file),
                "--ci-evidence",
                str(ci_file),
            ]
        )

    output = buffer.getvalue()

    assert exit_code == 0
    assert "Wave 5 PR gate: merge_ready" in output
    assert "Passed: True" in output
    assert "Errors: 0" in output


def test_wave5_workflow_cli_pr_gate_outputs_json_decision(tmp_path: Path) -> None:
    evidence_file = tmp_path / "pr-evidence.json"
    ci_file = tmp_path / "ci-evidence.json"
    evidence_file.write_text(json.dumps(_evidence_pack()), encoding="utf-8")
    ci_file.write_text(json.dumps(_ci_evidence()), encoding="utf-8")
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = workflow_main(
            [
                "pr-gate",
                "--evidence-pack",
                str(evidence_file),
                "--ci-evidence",
                str(ci_file),
                "--json",
            ]
        )

    payload = json.loads(buffer.getvalue())

    assert exit_code == 0
    assert payload["status"] == "merge_ready"
    assert payload["passed"] is True
    assert payload["ci_report"]["passed"] is True


def test_wave5_workflow_cli_pr_gate_fails_closed_on_head_sha_mismatch(tmp_path: Path) -> None:
    evidence_file = tmp_path / "pr-evidence.json"
    ci_file = tmp_path / "ci-evidence.json"
    evidence_file.write_text(json.dumps(_evidence_pack()), encoding="utf-8")
    ci_payload = _ci_evidence()
    ci_payload["head_sha"] = "def5678"
    ci_file.write_text(json.dumps(ci_payload), encoding="utf-8")
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = workflow_main(
            [
                "pr-gate",
                "--evidence-pack",
                str(evidence_file),
                "--ci-evidence",
                str(ci_file),
            ]
        )

    output = buffer.getvalue()

    assert exit_code == 1
    assert "Wave 5 PR gate: blocked" in output
    assert "wave5.pr_gate_head_sha_mismatch" in output


def test_wave5_workflow_cli_returns_input_error_for_invalid_pack(tmp_path: Path) -> None:
    evidence_file = tmp_path / "pr-evidence.json"
    ci_file = tmp_path / "ci-evidence.json"
    evidence_file.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    ci_file.write_text(json.dumps(_ci_evidence()), encoding="utf-8")
    stderr = io.StringIO()

    with redirect_stderr(stderr):
        exit_code = workflow_main(
            [
                "pr-gate",
                "--evidence-pack",
                str(evidence_file),
                "--ci-evidence",
                str(ci_file),
            ]
        )

    assert exit_code == 2
    assert "Wave 5 PR gate input error" in stderr.getvalue()


def test_top_level_blackfox_cli_dispatches_workflow_pr_gate(tmp_path: Path) -> None:
    evidence_file = tmp_path / "pr-evidence.json"
    ci_file = tmp_path / "ci-evidence.json"
    evidence_file.write_text(json.dumps(_evidence_pack()), encoding="utf-8")
    ci_file.write_text(json.dumps(_ci_evidence()), encoding="utf-8")
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = blackfox_main(
            [
                "workflow",
                "pr-gate",
                "--evidence-pack",
                str(evidence_file),
                "--ci-evidence",
                str(ci_file),
            ]
        )

    assert exit_code == 0
    assert "Wave 5 PR gate: merge_ready" in buffer.getvalue()


def _evidence_pack() -> dict[str, object]:
    return {
        "pack_id": "wave5-cli-pack",
        "pull_request": {
            "provider": "github",
            "repository": "BryceWDesign/IX-BlackFox",
            "pull_request_id": "pr-5",
            "base_ref": "main",
            "head_ref": "wave5-cli-gate",
            "head_sha": "abc1234",
            "author": "Bryce Lovell",
        },
        "created_at": "2026-05-16T12:00:00Z",
        "summary": "Wave 5 CLI gate pack.",
        "changed_files": ["src/ix_blackfox/runtime/control_plane.py"],
        "requested_checks": ["pytest"],
        "artifacts": [
            _artifact("run-bundle", "run_bundle", "artifacts/run-bundle.json"),
            _artifact("test-report", "test_report", "artifacts/pytest-report.json"),
            _artifact(
                "governance-receipt",
                "governance_receipt",
                "artifacts/governance-receipt.json",
            ),
            _artifact(
                "reliability-report",
                "reliability_report",
                "artifacts/wave4-reliability-report.json",
            ),
        ],
        "approvals": [
            {
                "approval_id": "approval-maintainer",
                "reviewer_id": "maintainer-a",
                "reviewer_kind": "human",
                "decision": "approved",
                "decided_at": "2026-05-16T12:01:00Z",
                "note": "Human maintainer reviewed the supplied evidence.",
                "evidence_refs": [
                    "run-bundle",
                    "test-report",
                    "governance-receipt",
                    "reliability-report",
                ],
                "roles": ["maintainer"],
            }
        ],
    }


def _artifact(artifact_id: str, kind: str, uri: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "kind": kind,
        "uri": uri,
        "produced_by": "blackfox-test-fixture",
        "sha256": "a" * 64,
        "size_bytes": 512,
    }


def _ci_evidence() -> dict[str, object]:
    return {
        "bundle_id": "ci-bundle-cli",
        "provider": "github-actions",
        "repository": "BryceWDesign/IX-BlackFox",
        "head_sha": "abc1234",
        "collected_at": "2026-05-16T12:02:00Z",
        "records": [
            {
                "check_name": "pytest",
                "provider": "github-actions",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-05-16T12:00:00Z",
                "completed_at": "2026-05-16T12:02:00Z",
                "required": True,
            }
        ],
    }
