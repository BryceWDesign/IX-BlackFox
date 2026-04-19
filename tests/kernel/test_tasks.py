from __future__ import annotations

import pytest

from ix_blackfox.kernel import (
    TaskKind,
    TaskPriority,
    TaskRecord,
    TaskRequest,
    TaskState,
)


def test_task_request_create_normalizes_prompt_and_labels() -> None:
    request = TaskRequest.create(
        prompt="  Inspect this codebase for weak points.  ",
        kind=TaskKind.PROGRAMMING,
        priority=TaskPriority.HIGH,
        labels=(" Code ", "security", "code", "", " Security "),
    )

    assert request.task_id.startswith("task-")
    assert request.kind == TaskKind.PROGRAMMING
    assert request.priority == TaskPriority.HIGH
    assert request.input.prompt == "Inspect this codebase for weak points."
    assert request.labels == ("code", "security")


def test_task_input_rejects_empty_prompt() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        TaskRequest.create(prompt="   ")


def test_task_record_happy_path_transitions() -> None:
    request = TaskRequest.create(prompt="Plan a patch.")
    record = TaskRecord(request=request)

    ready = record.mark_ready()
    running = ready.mark_running()
    completed = running.mark_completed(result_summary="Patch plan generated.")

    assert record.state == TaskState.PENDING
    assert ready.state == TaskState.READY
    assert running.state == TaskState.RUNNING
    assert running.started_at is not None
    assert completed.state == TaskState.COMPLETED
    assert completed.finished_at is not None
    assert completed.result_summary == "Patch plan generated."


def test_task_record_failure_requires_running_state() -> None:
    request = TaskRequest.create(prompt="Run tests.")
    record = TaskRecord(request=request)

    with pytest.raises(RuntimeError, match="Cannot transition task"):
        record.mark_failed(error="Tests crashed.")


def test_task_record_failure_requires_error_message() -> None:
    request = TaskRequest.create(prompt="Run static analysis.")
    record = TaskRecord(request=request).mark_running()

    with pytest.raises(ValueError, match="must not be empty"):
        record.mark_failed(error="   ")


def test_task_record_can_cancel_from_running() -> None:
    request = TaskRequest.create(prompt="Profile execution.")
    record = TaskRecord(request=request).mark_running()

    canceled = record.mark_canceled(reason="Operator canceled task.")

    assert canceled.state == TaskState.CANCELED
    assert canceled.finished_at is not None
    assert canceled.result_summary == "Operator canceled task."
