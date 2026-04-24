from __future__ import annotations

from ix_blackfox.kernel import TaskKind, TaskRecord, TaskRequest
from ix_blackfox.memory import TraceMemoryStore
from ix_blackfox.sentinel import (
    ApprovalGateConsistencyCheck,
    GovernanceExecutionContradictionCheck,
    SentinelContext,
    SentinelRuntime,
    TaskStateTraceContradictionCheck,
    register_default_sentinel_checks,
)


def test_governance_execution_contradiction_check_flags_blocked_but_executed() -> None:
    check = GovernanceExecutionContradictionCheck()

    issues = check.evaluate(
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

    assert len(issues) == 1
    assert issues[0].code == "sentinel.governance_execution_contradiction"
    assert issues[0].severity.value == "error"


def test_approval_gate_consistency_check_flags_unsatisfied_approval_execution() -> None:
    check = ApprovalGateConsistencyCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "governance_observations": (
                    {
                        "decision": "require_review",
                        "executed": True,
                        "approval_required": True,
                        "approval_satisfied": False,
                    },
                )
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "sentinel.approval_gate_contradiction"
    assert issues[0].severity.value == "error"


def test_task_state_trace_contradiction_check_flags_completed_task_with_failure_trace() -> None:
    trace_memory = TraceMemoryStore()
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    ).mark_ready().mark_running().mark_completed(result_summary="Completed.")

    trace_memory.append(
        correlation_id=task.request.task_id,
        stage="pack",
        message="Pack execution failed: timeout",
        level="error",
        source="architecture",
    )

    issues = TaskStateTraceContradictionCheck().evaluate(
        SentinelContext(
            task=task,
            trace_records=trace_memory.snapshot().filter_by_correlation(task.request.task_id),
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "sentinel.task_state_contradiction"
    assert issues[0].severity.value == "warning"


def test_default_sentinel_check_registration_populates_runtime_snapshot() -> None:
    runtime = SentinelRuntime()

    registered = register_default_sentinel_checks(runtime)
    snapshot = runtime.snapshot()

    assert registered == (
        "governance-contradiction-check",
        "approval-gate-consistency-check",
        "task-state-trace-contradiction-check",
    )
    assert snapshot.contains("governance-contradiction-check") is True
    assert snapshot.contains("approval-gate-consistency-check") is True
    assert snapshot.contains("task-state-trace-contradiction-check") is True
