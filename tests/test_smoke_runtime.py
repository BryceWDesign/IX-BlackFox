from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


def test_smoke_programming_runtime_flow(tmp_path: Path) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime.run_prompt(
        prompt="Fix the failing tests, prepare a patch, and run regression checks.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests", "patching"),
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.pack_name == "programming"
    assert report.route is not None
    assert report.route.capability_name == "programming"
    assert report.route.reason.value == "exact_kind_match"
    assert report.task_kind is TaskKind.PROGRAMMING
    assert "Programming pack prepared" in report.task_summary

    assert "programming-plan.json" in report.produced_artifacts
    assert "blackfox-governance-receipts.json" in report.produced_artifacts
    assert report.governance_receipts is not None
    assert report.governance_receipts.receipt_count >= 4
    assert report.governance_receipts.chain_verified is True
    assert report.governance_receipts.brain_receipt_count == 0
    assert report.governance_receipts.brain_receipts == ()

    plan_path = Path(report.artifact_paths["programming-plan.json"])
    plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan_payload["pack_name"] == "programming"
    assert plan_payload["task_id"] == report.task_id
    assert plan_payload["artifact_name"] == "programming-plan.json"
    assert plan_payload["summary"] == report.task_summary

    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["intent_id"] == report.governance_preflight.intent.intent_id
    assert receipt_payload["chain_verified"] is True
    assert receipt_payload["brain_receipt_count"] == 0
    assert receipt_payload["brain_receipts"] == []
    assert receipt_payload["receipt_count"] >= 4

    report_path = Path(report.report_path)
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["task_id"] == report.task_id
    assert report_payload["status"] == "passed"
    assert report_payload["pack_name"] == "programming"
    assert report_payload["produced_artifacts"] == [
        "programming-plan.json",
        "blackfox-governance-receipts.json",
    ]
    assert report_payload["governance_receipts"]["brain_receipt_count"] == 0
