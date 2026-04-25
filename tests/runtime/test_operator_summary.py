from __future__ import annotations

from pathlib import Path

from ix_blackfox.runtime import (
    OperatorSummaryDocument,
    OperatorSummaryFindingSeverity,
    OperatorSummaryRenderer,
    ProgrammingRepairRunReport,
    RepairLoopConfig,
    RepairLoopReceiptLedger,
    RepairLoopStatus,
    RepairLoopTerminalReason,
    RunBundleArtifactKind,
    RunBundleLayout,
    RunBundleWriter,
)
from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchDiff,
    PatchFileChange,
    ToolCapability,
    ToolInvocationRequest,
    ToolInvocationResult,
)


def test_operator_summary_renders_successful_programming_repair_report() -> None:
    report = _make_successful_programming_repair_report()

    document = OperatorSummaryRenderer().render_programming_repair_report(
        report=report,
    )
    markdown = document.to_markdown()

    assert document.run_id == "run-summary"
    assert document.task_id == "task-summary"
    assert document.status == "succeeded"
    assert document.finding_count >= 1
    assert document.error_count == 0
    assert document.warning_count == 0
    assert document.section_titles == (
        "Requested Objective",
        "Repair Loop Outcome",
        "Patch Activity",
        "Test Evidence",
        "Receipt Evidence",
        "Human Review Notes",
    )

    assert "# IX-BlackFox Operator Summary" in markdown
    assert "**Status:** `succeeded`" in markdown
    assert "Repair loop reached a test-passing terminal state." in markdown
    assert "Make tests pass under governed repair." in markdown
    assert "Patch Attempt 1" in markdown
    assert "Test Run 1" in markdown
    assert "Treat the result as verified only for the captured test command" in markdown


def test_operator_summary_renders_failed_programming_repair_report() -> None:
    report = _make_failed_programming_repair_report()

    document = OperatorSummaryRenderer().render_programming_repair_report(
        report=report,
    )
    markdown = document.to_markdown()

    assert document.status == "exhausted"
    assert document.error_count >= 2
    assert document.warning_count >= 1
    assert any(
        finding.code == "repair.not_successful"
        and finding.severity is OperatorSummaryFindingSeverity.ERROR
        for finding in document.findings
    )
    assert "Repair loop did not reach a successful terminal state." in markdown
    assert "Latest parsed test run failed or errored." in markdown
    assert "Do not merge or trust the patch without additional operator review." in markdown


def test_operator_summary_document_round_trips_serialized_payload() -> None:
    document = OperatorSummaryRenderer().render_programming_repair_report(
        report=_make_successful_programming_repair_report(),
    )

    restored = OperatorSummaryDocument.from_dict(document.to_dict())

    assert restored.title == document.title
    assert restored.run_id == document.run_id
    assert restored.task_id == document.task_id
    assert restored.status == document.status
    assert restored.executive_summary == document.executive_summary
    assert restored.section_titles == document.section_titles
    assert restored.finding_count == document.finding_count
    assert restored.to_markdown() == document.to_markdown()


def test_operator_summary_renders_run_bundle_manifest(tmp_path: Path) -> None:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id="run-bundle-summary"),
        task_id="task-bundle-summary",
    )
    writer.write_json(
        kind=RunBundleArtifactKind.RUN_REPORT,
        filename="run-report.json",
        payload={"status": "passed"},
    )
    writer.write_text(
        kind=RunBundleArtifactKind.OPERATOR_SUMMARY,
        filename="operator-summary.md",
        text="# Summary\n",
        media_type="text/markdown",
    )

    document = OperatorSummaryRenderer().render_run_bundle_manifest(
        manifest=writer.manifest,
    )
    markdown = document.to_markdown()

    assert document.run_id == "run-bundle-summary"
    assert document.task_id == "task-bundle-summary"
    assert document.status == "bundle-generated"
    assert document.warning_count == 0
    assert "Run bundle `run-bundle-" in markdown
    assert "| `run_report` | `reports/run-report.json` |" in markdown
    assert "| `operator_summary` | `reports/operator-summary.md` |" in markdown
    assert "The manifest digest binds artifact metadata" in markdown


def _make_successful_programming_repair_report() -> ProgrammingRepairRunReport:
    loop_state = _base_loop_state()
    patch = _patch()
    loop_state = loop_state.start_attempt(patch_diff=patch)
    attempt = loop_state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_patch_request(),
        output={
            "changed_paths": ["tests/test_smoke.py"],
            "patch_id": patch.patch_id,
        },
    )
    loop_state = loop_state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )

    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.PASSED,
        command=("python", "-m", "pytest", "-q"),
        return_code=0,
        timed_out=False,
        duration_seconds=0.11,
        passed=1,
    )
    test_result = ToolInvocationResult.succeeded(
        request=_test_request(),
        output={
            "command": ["python", "-m", "pytest", "-q"],
            "cwd": "/workspace",
            "return_code": 0,
            "stdout": "1 passed",
            "stderr": "",
            "timed_out": False,
            "timeout_seconds": 60.0,
        },
    )
    loop_state = loop_state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )

    repair_receipt_ledger = RepairLoopReceiptLedger()
    repair_receipt_ledger.record_loop_started(state=_base_loop_state())
    repair_receipt_ledger.record_loop_terminated(state=loop_state)

    return ProgrammingRepairRunReport(
        loop_state=loop_state,
        patch_results=(patch_result,),
        test_results=(test_result,),
        parsed_test_runs=(parsed_test_run,),
        repair_receipts=tuple(
            receipt.to_dict()
            for receipt in repair_receipt_ledger.snapshot().receipts
        ),
    )


def _make_failed_programming_repair_report() -> ProgrammingRepairRunReport:
    loop_state = _base_loop_state(config=RepairLoopConfig(max_attempts=1))
    patch = _patch()
    loop_state = loop_state.start_attempt(patch_diff=patch)
    attempt = loop_state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_patch_request(),
        output={
            "changed_paths": ["tests/test_smoke.py"],
            "patch_id": patch.patch_id,
        },
    )
    loop_state = loop_state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )

    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
        timed_out=False,
        duration_seconds=0.11,
        passed=0,
        failed=1,
    )
    test_result = ToolInvocationResult.succeeded(
        request=_test_request(),
        output={
            "command": ["python", "-m", "pytest", "-q"],
            "cwd": "/workspace",
            "return_code": 1,
            "stdout": "1 failed",
            "stderr": "",
            "timed_out": False,
            "timeout_seconds": 60.0,
        },
    )
    loop_state = loop_state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )

    assert loop_state.status is RepairLoopStatus.EXHAUSTED
    assert loop_state.terminal_reason is RepairLoopTerminalReason.MAX_ATTEMPTS_EXHAUSTED

    return ProgrammingRepairRunReport(
        loop_state=loop_state,
        patch_results=(patch_result,),
        test_results=(test_result,),
        parsed_test_runs=(parsed_test_run,),
        repair_receipts=(),
    )


def _base_loop_state(config: RepairLoopConfig | None = None):
    from ix_blackfox.runtime import RepairLoopState

    return RepairLoopState.create(
        task_id="task-summary",
        run_id="run-summary",
        objective="Make tests pass under governed repair.",
        config=config,
    )


def _patch() -> PatchDiff:
    return PatchDiff.create(
        summary="Repair smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_smoke.py",
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )


def _patch_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        task_id="task-summary",
        run_id="run-summary",
    )


def _test_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.run_tests",
        capability=ToolCapability.TEST_EXECUTION,
        task_id="task-summary",
        run_id="run-summary",
    )
