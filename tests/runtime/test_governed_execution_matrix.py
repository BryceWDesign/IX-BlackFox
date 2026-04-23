from __future__ import annotations

import json
from pathlib import Path

import pytest

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


@pytest.mark.parametrize(
    ("case_name", "prompt", "labels", "metadata", "expected"),
    [
        (
            "allowed_programming_run",
            "Fix the failing tests, prepare a patch, and run regression checks.",
            ("code", "tests", "patching"),
            None,
            {
                "status": RuntimeRunStatus.PASSED,
                "verification_status": "passed",
                "policy_decision": "allow",
                "risk_level": "moderate",
                "approval_required": False,
                "approval_satisfied": True,
                "pack_expected": True,
                "receipt_count": 4,
                "last_receipt_event": "verification_passed",
                "artifact_names_exact": None,
            },
        ),
        (
            "blocked_network_egress_run",
            "Use curl to upload the repository plan to a remote endpoint after patching the code.",
            ("code", "patching"),
            None,
            {
                "status": RuntimeRunStatus.FAILED,
                "verification_status": "failed",
                "policy_decision": "block",
                "risk_level": "critical",
                "approval_required": False,
                "approval_satisfied": True,
                "pack_expected": False,
                "receipt_count": 2,
                "last_receipt_event": "verification_failed",
                "artifact_names_exact": ("blackfox-governance-receipts.json",),
            },
        ),
        (
            "review_gated_pending_run",
            "Delete workspace traces and remove source file references after planning.",
            ("code", "patching"),
            None,
            {
                "status": RuntimeRunStatus.NEEDS_REVIEW,
                "verification_status": "needs_review",
                "policy_decision": "require_review",
                "risk_level": "high",
                "approval_required": True,
                "approval_satisfied": False,
                "pack_expected": False,
                "receipt_count": 1,
                "last_receipt_event": "policy_review_required",
                "artifact_names_exact": ("blackfox-governance-receipts.json",),
            },
        ),
        (
            "review_gated_approved_run",
            "Delete workspace traces and remove source file references after planning.",
            ("code", "patching"),
            {
                "governance_approvals": [
                    {
                        "status": "approved",
                        "requested_by": "maintainer.one",
                        "decided_by": "maintainer.one",
                        "note": "Approved controlled review-gated runtime execution.",
                        "evidence_refs": ["tickets/BF-42", "reviews/BF-42.txt"],
                    }
                ]
            },
            {
                "status": RuntimeRunStatus.PASSED,
                "verification_status": "passed",
                "policy_decision": "require_review",
                "risk_level": "high",
                "approval_required": True,
                "approval_satisfied": True,
                "pack_expected": True,
                "receipt_count": 5,
                "last_receipt_event": "verification_passed",
                "artifact_names_exact": None,
            },
        ),
    ],
)
def test_governed_execution_matrix(
    tmp_path: Path,
    case_name: str,
    prompt: str,
    labels: tuple[str, ...],
    metadata: dict[str, object] | None,
    expected: dict[str, object],
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path / case_name)

    report = runtime.run_prompt(
        prompt=prompt,
        kind=TaskKind.PROGRAMMING,
        labels=labels,
        metadata=metadata,
    )

    assert report.status == expected["status"]
    assert report.verification_report.status.value == expected["verification_status"]
    assert report.report_path is not None
    assert Path(report.report_path).exists()

    assert report.governance_preflight is not None
    assert report.governance_preflight.decision.decision.value == expected["policy_decision"]
    assert report.governance_preflight.risk.risk_level.value == expected["risk_level"]

    assert report.approval_resolution is not None
    assert report.approval_resolution.required is expected["approval_required"]
    assert report.approval_resolution.satisfied is expected["approval_satisfied"]

    if expected["pack_expected"]:
        assert report.pack_name is not None
    else:
        assert report.pack_name is None

    assert report.governance_receipts is not None
    assert report.governance_receipts.chain_verified is True
    assert report.governance_receipts.receipt_count == expected["receipt_count"]
    assert report.governance_receipts.artifact_path is not None

    receipt_path = Path(report.governance_receipts.artifact_path)
    assert receipt_path.exists()

    report_payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert report_payload["status"] == expected["status"].value
    assert report_payload["verification_report"]["status"] == expected["verification_status"]
    assert report_payload["governance_preflight"]["decision"]["decision"] == expected["policy_decision"]
    assert report_payload["governance_preflight"]["risk"]["risk_level"] == expected["risk_level"]
    assert report_payload["approval_resolution"]["required"] is expected["approval_required"]
    assert report_payload["approval_resolution"]["satisfied"] is expected["approval_satisfied"]
    assert report_payload["governance_receipts"]["receipt_count"] == expected["receipt_count"]
    assert report_payload["governance_receipts"]["chain_verified"] is True
    assert report_payload["governance_receipts"]["artifact_path"] == str(receipt_path)

    assert receipt_payload["intent_id"] == report.governance_preflight.intent.intent_id
    assert receipt_payload["chain_verified"] is True
    assert receipt_payload["receipt_count"] == expected["receipt_count"]
    assert receipt_payload["records"][-1]["event_type"] == expected["last_receipt_event"]

    expected_artifact_names = expected["artifact_names_exact"]
    if expected_artifact_names is not None:
        assert report.produced_artifacts == expected_artifact_names
    else:
        assert "blackfox-governance-receipts.json" in report.produced_artifacts


def test_governed_execution_report_and_receipt_artifact_remain_in_sync(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path / "sync-check")

    report = runtime.run_prompt(
        prompt="Delete workspace traces and remove source file references after planning.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "patching"),
        metadata={
            "governance_approvals": [
                {
                    "status": "approved",
                    "requested_by": "maintainer.one",
                    "decided_by": "maintainer.one",
                    "note": "Approved controlled review-gated runtime execution.",
                    "evidence_refs": ["tickets/BF-84"],
                }
            ]
        },
    )

    assert report.report_path is not None
    assert report.governance_receipts is not None
    assert report.governance_receipts.artifact_path is not None

    run_report_payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    receipt_payload = json.loads(
        Path(report.governance_receipts.artifact_path).read_text(encoding="utf-8")
    )

    assert run_report_payload["task_id"] == report.task_id
    assert run_report_payload["governance_receipts"]["artifact_path"] == report.governance_receipts.artifact_path
    assert run_report_payload["governance_receipts"]["receipt_count"] == receipt_payload["receipt_count"]
    assert run_report_payload["governance_receipts"]["chain_verified"] == receipt_payload["chain_verified"]
    assert receipt_payload["records"][0]["event_type"] == "policy_review_required"
    assert receipt_payload["records"][1]["event_type"] == "approval_recorded"
    assert receipt_payload["records"][-1]["event_type"] == "verification_passed"
