from __future__ import annotations

from ix_blackfox.runtime import (
    RepairLoopReceiptEventType,
    RepairLoopReceiptLedger,
    RepairLoopState,
    RepairLoopStatus,
    RepairLoopTerminalReason,
)
from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchDiff,
    PatchFileChange,
    ToolCapability,
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)


def test_repair_loop_receipt_ledger_records_successful_loop_chain() -> None:
    ledger = RepairLoopReceiptLedger()
    state = RepairLoopState.create(
        task_id="task-repair",
        run_id="run-repair",
        objective="Make tests pass.",
    )
    patch = _make_patch()

    start_receipt = ledger.record_loop_started(state=state)
    state = state.start_attempt(patch_diff=patch)
    attempt_receipt = ledger.record_attempt_started(state=state, patch_diff=patch)

    attempt = state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_make_patch_request(),
        output={"patch_id": patch.patch_id},
    )
    state = state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )
    patch_receipt = ledger.record_patch_result(
        state=state,
        result=patch_result,
    )

    test_result = ToolInvocationResult.succeeded(
        request=_make_test_request(),
        output={"return_code": 0},
    )
    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.PASSED,
        command=("python", "-m", "pytest", "-q"),
        return_code=0,
        timed_out=False,
        passed=3,
    )
    state = state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )
    test_receipt = ledger.record_test_result(
        state=state,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )
    terminal_receipt = ledger.record_loop_terminated(state=state)

    assert ledger.count() == 5
    assert ledger.verify_loop_chain(state.loop_id) is True

    snapshot = ledger.snapshot()
    assert len(snapshot.filter_by_loop(state.loop_id)) == 5
    assert len(snapshot.filter_by_task("task-repair")) == 5
    assert len(snapshot.filter_by_run("run-repair")) == 5
    assert snapshot.latest_for_loop(state.loop_id) == terminal_receipt

    assert start_receipt.previous_receipt_id is None
    assert attempt_receipt.previous_receipt_id == start_receipt.receipt_id
    assert patch_receipt.previous_receipt_id == attempt_receipt.receipt_id
    assert test_receipt.previous_receipt_id == patch_receipt.receipt_id
    assert terminal_receipt.previous_receipt_id == test_receipt.receipt_id

    assert start_receipt.event_type is RepairLoopReceiptEventType.LOOP_STARTED
    assert attempt_receipt.event_type is RepairLoopReceiptEventType.ATTEMPT_STARTED
    assert patch_receipt.event_type is RepairLoopReceiptEventType.PATCH_RESULT_RECORDED
    assert test_receipt.event_type is RepairLoopReceiptEventType.TEST_RESULT_RECORDED
    assert terminal_receipt.event_type is RepairLoopReceiptEventType.LOOP_TERMINATED

    assert terminal_receipt.status is RepairLoopStatus.SUCCEEDED
    assert terminal_receipt.terminal_reason is RepairLoopTerminalReason.TESTS_PASSED
    assert terminal_receipt.metadata["attempts_used"] == 1


def test_repair_loop_receipt_ledger_records_failure_receipt_for_failed_tests() -> None:
    ledger = RepairLoopReceiptLedger()
    state = RepairLoopState.create(
        task_id="task-repair",
        run_id="run-repair",
        objective="Expose failing test receipts.",
    )
    patch = _make_patch()

    ledger.record_loop_started(state=state)
    state = state.start_attempt(patch_diff=patch)
    ledger.record_attempt_started(state=state, patch_diff=patch)

    attempt = state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_make_patch_request(),
        output={"patch_id": patch.patch_id},
    )
    state = state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )
    ledger.record_patch_result(state=state, result=patch_result)

    test_result = ToolInvocationResult.failed(
        request=_make_test_request(),
        status=ToolInvocationStatus.FAILED,
        failure=ToolFailure(
            kind=ToolFailureKind.EXECUTION_ERROR,
            message="Tests failed.",
            retryable=True,
        ),
        output={"return_code": 1},
    )
    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
        timed_out=False,
        passed=2,
        failed=1,
    )
    state = state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )
    failure_receipt = ledger.record_test_result(
        state=state,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )

    assert failure_receipt.event_type is RepairLoopReceiptEventType.FAILURE_RECORDED
    assert failure_receipt.metadata["test_status"] == "failed"
    assert failure_receipt.metadata["failed"] == 1
    assert failure_receipt.metadata["failing_outcomes"] == 1
    assert ledger.verify_loop_chain(state.loop_id) is True


def _make_patch() -> PatchDiff:
    return PatchDiff.create(
        summary="Repair test.",
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_example.py",
                before_text="def test_example() -> None:\n    assert False\n",
                after_text="def test_example() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )


def _make_patch_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        task_id="task-repair",
        run_id="run-repair",
    )


def _make_test_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.run_tests",
        capability=ToolCapability.TEST_EXECUTION,
        task_id="task-repair",
        run_id="run-repair",
    )
