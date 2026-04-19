from __future__ import annotations

import pytest

from ix_blackfox.memory import TraceMemoryStore
from ix_blackfox.sentinel import (
    FailureLoopCheck,
    FailureLoopWindow,
    SentinelContext,
    SentinelSeverity,
)


def test_failure_loop_window_normalizes_configuration() -> None:
    window = FailureLoopWindow(
        lookback_limit=5,
        failure_levels=(" Error ", "critical", "error"),
        failure_stages=(" Forge ", "forge", "eval"),
        trigger_count=3,
    )

    assert window.lookback_limit == 5
    assert window.failure_levels == ("error", "critical")
    assert window.failure_stages == ("forge", "eval")
    assert window.trigger_count == 3


def test_failure_loop_check_returns_no_issue_below_threshold() -> None:
    traces = TraceMemoryStore()
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Build started.",
        level="info",
    )
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Single failure observed.",
        level="error",
    )

    check = FailureLoopCheck(
        window=FailureLoopWindow(
            lookback_limit=5,
            trigger_count=3,
        )
    )

    issues = check.evaluate(SentinelContext(trace_records=traces.snapshot().records))

    assert issues == ()


def test_failure_loop_check_emits_issue_when_threshold_is_met() -> None:
    traces = TraceMemoryStore()
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Patch application failed.",
        level="error",
    )
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Retry patch application failed.",
        level="error",
    )
    traces.append(
        correlation_id="task-002",
        stage="eval",
        message="Regression verification failed.",
        level="critical",
    )

    check = FailureLoopCheck(
        window=FailureLoopWindow(
            lookback_limit=10,
            trigger_count=3,
        )
    )

    issues = check.evaluate(SentinelContext(trace_records=traces.snapshot().records))

    assert len(issues) == 1
    issue = issues[0]
    assert issue.code == "runtime.failure_loop_detected"
    assert issue.severity == SentinelSeverity.ERROR
    assert issue.source == "failure_loop"
    assert issue.data["failure_count"] == 3
    assert issue.data["stages"] == ("eval", "forge")
    assert issue.data["correlation_ids"] == ("task-001", "task-002")
    assert issue.data["recent_messages"] == (
        "Patch application failed.",
        "Retry patch application failed.",
        "Regression verification failed.",
    )


def test_failure_loop_check_honors_stage_filter() -> None:
    traces = TraceMemoryStore()
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Patch failed.",
        level="error",
    )
    traces.append(
        correlation_id="task-001",
        stage="eval",
        message="Eval failed.",
        level="error",
    )
    traces.append(
        correlation_id="task-001",
        stage="forge",
        message="Patch failed again.",
        level="error",
    )

    check = FailureLoopCheck(
        window=FailureLoopWindow(
            lookback_limit=10,
            failure_stages=("forge",),
            trigger_count=2,
        )
    )

    issues = check.evaluate(SentinelContext(trace_records=traces.snapshot().records))

    assert len(issues) == 1
    assert issues[0].data["failure_count"] == 2
    assert issues[0].data["stages"] == ("forge",)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"lookback_limit": 0},
            "lookback limit must be greater than or equal to 1",
        ),
        (
            {"trigger_count": 1},
            "trigger count must be greater than or equal to 2",
        ),
        (
            {"failure_levels": ("error", "   ")},
            "Failure-loop failure level must not be empty",
        ),
        (
            {"failure_stages": ("forge", "   ")},
            "Failure-loop failure stage must not be empty",
        ),
    ],
)
def test_failure_loop_window_rejects_invalid_configuration(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        FailureLoopWindow(**kwargs)
