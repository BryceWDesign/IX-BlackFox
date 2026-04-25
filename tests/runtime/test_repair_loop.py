from __future__ import annotations

from ix_blackfox.runtime import (
    RepairLoopConfig,
    RepairLoopStatus,
    RepairLoopTerminalReason,
)
from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchDiff,
    PatchFileChange,
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolCapability,
)


def test_repair_loop_starts_attempt_and_completes_when_tests_pass() -> None:
    loop = _make_loop()
    patch = _make_patch()

    loop = loop.start_attempt(
        patch_diff=patch,
        notes=("Initial controlled repair attempt.",),
    )
    attempt = loop.latest_attempt
    assert attempt is not None

    patch_result = _make_patch_result(
        request=_make_patch_request(),
        status=ToolInvocationStatus.SUCCEEDED,
    )
    loop = loop.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )

    test_request = _make_test_request()
    test_result = ToolInvocationResult.succeeded(
        request=test_request,
        output={"return_code": 0, "passed": True},
    )
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.PASSED,
        command=("python", "-m", "pytest", "-q"),
        return_code=0,
        timed_out=False,
        duration_seconds=0.15,
        passed=3,
    )

    loop = loop.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed,
    )

    assert loop.status is RepairLoopStatus.SUCCEEDED
    assert loop.terminal_reason is RepairLoopTerminalReason.TESTS_PASSED
    assert loop.is_terminal is True
    assert loop.attempts_used == 1
    assert loop.attempts_remaining == 2
    assert loop.latest_attempt is not None
    assert loop.latest_attempt.succeeded is True
    assert loop.findings[-1].code == "repair.tests_passed"


def test_repair_loop_allows_bounded_retry_after_failed_tests() -> None:
    loop = _make_loop(config=RepairLoopConfig(max_attempts=2))

    first_patch = _make_patch(summary="First attempt")
    loop = loop.start_attempt(patch_diff=first_patch)
    first_attempt = loop.latest_attempt
    assert first_attempt is not None

    loop = loop.attach_patch_result(
        attempt_id=first_attempt.attempt_id,
        result=_make_patch_result(
            request=_make_patch_request(),
            status=ToolInvocationStatus.SUCCEEDED,
        ),
    )
    loop = loop.attach_test_result(
        attempt_id=first_attempt.attempt_id,
        result=ToolInvocationResult.failed(
            request=_make_test_request(),
            status=ToolInvocationStatus.FAILED,
            failure=ToolFailure(
                kind=ToolFailureKind.EXECUTION_ERROR,
                message="Tests failed.",
                retryable=True,
            ),
            output={"return_code": 1},
        ),
        parsed_test_run=ParsedTestRun(
            status=ParsedTestRunStatus.FAILED,
            command=("python", "-m", "pytest", "-q"),
            return_code=1,
            timed_out=False,
            failed=1,
            passed=2,
        ),
    )

    assert loop.status is RepairLoopStatus.RUNNING
    assert loop.should_continue is True
    assert loop.can_start_attempt is True
    assert loop.attempts_remaining == 1
    assert loop.findings[-1].code == "repair.tests_failed"

    second_patch = _make_patch(summary="Second attempt")
    loop = loop.start_attempt(patch_diff=second_patch)

    assert loop.attempts_used == 2
    assert loop.attempts_remaining == 0
    assert loop.latest_attempt is not None
    assert loop.latest_attempt.attempt_index == 2


def test_repair_loop_exhausts_attempt_budget_after_repeated_failed_tests() -> None:
    loop = _make_loop(config=RepairLoopConfig(max_attempts=1))
    loop = loop.start_attempt(patch_diff=_make_patch())
    attempt = loop.latest_attempt
    assert attempt is not None

    loop = loop.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=_make_patch_result(
            request=_make_patch_request(),
            status=ToolInvocationStatus.SUCCEEDED,
        ),
    )
    loop = loop.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=ToolInvocationResult.failed(
            request=_make_test_request(),
            status=ToolInvocationStatus.FAILED,
            failure=ToolFailure(
                kind=ToolFailureKind.EXECUTION_ERROR,
                message="Tests failed.",
                retryable=True,
            ),
        ),
        parsed_test_run=ParsedTestRun(
            status=ParsedTestRunStatus.FAILED,
            command=("python", "-m", "pytest", "-q"),
            return_code=1,
            timed_out=False,
            failed=2,
        ),
    )

    assert loop.status is RepairLoopStatus.EXHAUSTED
    assert loop.terminal_reason is RepairLoopTerminalReason.MAX_ATTEMPTS_EXHAUSTED
    assert loop.is_terminal is True
    assert loop.should_continue is False
    assert loop.findings[-1].code == "repair.max_attempts_exhausted"


def test_repair_loop_blocks_when_patch_application_is_blocked() -> None:
    loop = _make_loop()
    loop = loop.start_attempt(patch_diff=_make_patch())
    attempt = loop.latest_attempt
    assert attempt is not None

    blocked_result = _make_patch_result(
        request=_make_patch_request(),
        status=ToolInvocationStatus.BLOCKED,
    )

    loop = loop.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=blocked_result,
    )

    assert loop.status is RepairLoopStatus.BLOCKED
    assert loop.terminal_reason is RepairLoopTerminalReason.PATCH_BLOCKED
    assert loop.is_terminal is True
    assert loop.can_start_attempt is False
    assert loop.latest_attempt is not None
    assert loop.latest_attempt.failed_or_blocked is True
    assert loop.findings[-1].code == "repair.patch_blocked"


def test_repair_loop_round_trips_serialized_state() -> None:
    loop = _make_loop(metadata={"source": "unit-test"})
    loop = loop.start_attempt(
        patch_diff=_make_patch(),
        notes=("Serialize this repair attempt.",),
    )

    restored = type(loop).from_dict(loop.to_dict())

    assert restored.loop_id == loop.loop_id
    assert restored.task_id == "task-repair"
    assert restored.run_id == "run-repair"
    assert restored.objective == "Fix the failing governed runtime tests."
    assert restored.metadata == {"source": "unit-test"}
    assert restored.config.max_attempts == 3
    assert restored.status is RepairLoopStatus.RUNNING
    assert restored.latest_attempt is not None
    assert restored.latest_attempt.patch_diff.summary == "Fix fixture"
    assert restored.latest_attempt.notes == ("Serialize this repair attempt.",)


def test_repair_loop_refuses_new_attempt_when_latest_attempt_is_not_finished() -> None:
    loop = _make_loop()
    loop = loop.start_attempt(patch_diff=_make_patch())

    try:
        loop.start_attempt(patch_diff=_make_patch(summary="Should be refused"))
    except RuntimeError as exc:
        assert "cannot start another attempt" in str(exc)
    else:
        raise AssertionError("Repair loop should refuse overlapping attempts.")


def _make_loop(
    *,
    config: RepairLoopConfig | None = None,
    metadata: dict[str, str] | None = None,
):
    from ix_blackfox.runtime import RepairLoopState

    return RepairLoopState.create(
        task_id="task-repair",
        run_id="run-repair",
        objective="Fix the failing governed runtime tests.",
        config=config,
        metadata=metadata,
    )


def _make_patch(*, summary: str = "Fix fixture") -> PatchDiff:
    return PatchDiff.create(
        summary=summary,
        file_changes=(
            PatchFileChange.modify(
                path="tests/test_example.py",
                before_text="def test_example():\n    assert False\n",
                after_text="def test_example():\n    assert True\n",
            ),
        ),
        created_by="blackfox",
    )


def _make_patch_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        run_id="run-repair",
    )


def _make_test_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.run_tests",
        capability=ToolCapability.TEST_EXECUTION,
        run_id="run-repair",
    )


def _make_patch_result(
    *,
    request: ToolInvocationRequest,
    status: ToolInvocationStatus,
) -> ToolInvocationResult:
    if status is ToolInvocationStatus.SUCCEEDED:
        return ToolInvocationResult.succeeded(
            request=request,
            output={"patch_id": "patch-test", "file_count": 1},
        )

    return ToolInvocationResult.failed(
        request=request,
        status=status,
        failure=ToolFailure(
            kind=ToolFailureKind.EXECUTION_ERROR,
            message="Patch operation did not complete.",
            retryable=False,
        ),
    )
