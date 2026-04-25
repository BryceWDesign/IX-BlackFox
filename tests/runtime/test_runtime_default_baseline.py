from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus
from ix_blackfox.sentinel import SentinelContext


def test_default_runtime_can_be_constructed_with_builtin_subsystems(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    sentinel_snapshot = runtime._sentinel.snapshot()  # noqa: SLF001

    assert sentinel_snapshot.contains("governance-contradiction-check") is True
    assert sentinel_snapshot.contains("approval-gate-consistency-check") is True
    assert sentinel_snapshot.contains("task-state-trace-contradiction-check") is True


def test_default_runtime_sentinel_checks_detect_blocked_execution_contradiction(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime._sentinel.evaluate(  # noqa: SLF001
        SentinelContext(
            metadata={
                "governance_observations": (
                    {
                        "decision": "block",
                        "executed": True,
                        "approval_required": False,
                        "approval_satisfied": False,
                    },
                )
            }
        )
    )

    assert report.check_count == 3
    assert report.has_issue_code("sentinel.governance_execution_contradiction") is True
    assert report.has_contradiction_signal() is True


def test_default_runtime_executes_programming_smoke_flow(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime.run_prompt(
        prompt="Fix the failing tests, prepare a patch, and run regression checks.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests", "patching"),
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.task_kind is TaskKind.PROGRAMMING
    assert report.pack_name == "programming"
    assert report.route is not None
    assert report.route.capability_name == "programming"
    assert report.governance_preflight is not None
    assert report.approval_resolution is not None
    assert report.governance_receipts is not None
    assert report.governance_receipts.chain_verified is True
    assert report.governance_receipts.receipt_count >= 4
    assert report.report_path is not None

    assert report.produced_artifacts == (
        "programming-plan.json",
        "blackfox-governance-receipts.json",
    )

    plan_path = Path(report.artifact_paths["programming-plan.json"])
    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    run_report_path = Path(report.report_path)

    assert plan_path.exists() is True
    assert receipt_path.exists() is True
    assert run_report_path.exists() is True

    plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    run_report_payload = json.loads(run_report_path.read_text(encoding="utf-8"))

    assert plan_payload["task_id"] == report.task_id
    assert plan_payload["pack_name"] == "programming"
    assert plan_payload["artifact_name"] == "programming-plan.json"

    assert receipt_payload["intent_id"] == report.governance_preflight.intent.intent_id
    assert receipt_payload["chain_verified"] is True
    assert receipt_payload["receipt_count"] >= 4

    assert run_report_payload["task_id"] == report.task_id
    assert run_report_payload["status"] == "passed"
    assert run_report_payload["pack_name"] == "programming"
    assert run_report_payload["produced_artifacts"] == [
        "programming-plan.json",
        "blackfox-governance-receipts.json",
    ]
