"""
Built-in sentinel checks for IX-BlackFox.

This package exports both the newer modular sentinel checks and the default
runtime checks expected by the public sentinel package.

The default checks live here instead of the legacy sibling module
``sentinel/checks.py`` because Python resolves ``ix_blackfox.sentinel.checks``
to this package when both a package directory and sibling module share the same
name. Keeping these exports in the package fixes import collection for tests and
runtime default registration.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ix_blackfox.sentinel.checks.contradiction import (
    ContradictionAssertion,
    ContradictionCheck,
)
from ix_blackfox.sentinel.checks.failure_loop import (
    FailureLoopCheck,
    FailureLoopWindow,
)
from ix_blackfox.sentinel.checks.governance_consistency import (
    GovernanceConsistencyCheck,
    GovernanceObservation,
)
from ix_blackfox.sentinel.checks.policy import (
    PolicyGuardrailCheck,
    PolicyObservation,
)
from ix_blackfox.sentinel.core import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelRuntime,
    SentinelSeverity,
)


class GovernanceExecutionContradictionCheck(SentinelCheck):
    """
    Detect impossible governance-execution combinations.

    Example contradiction:
    - governance decision is "block"
    - runtime metadata claims the action still executed
    """

    @property
    def check_name(self) -> str:
        return "governance-contradiction-check"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        issues: list[SentinelIssue] = []

        for observation in _governance_observations(context.metadata):
            decision = _normalize_optional_text(observation.get("decision"))
            executed = _coerce_bool(observation.get("executed"))

            if decision == "block" and executed:
                issues.append(
                    SentinelIssue(
                        code="sentinel.governance_execution_contradiction",
                        severity=SentinelSeverity.ERROR,
                        summary="Governance reported a blocked action as executed.",
                        source=self.check_name,
                        details=(
                            "A blocked governance decision and an executed runtime "
                            "action cannot both be true in the same observation."
                        ),
                        data={"observation": dict(observation)},
                    )
                )

        return tuple(issues)


class ApprovalGateConsistencyCheck(SentinelCheck):
    """
    Detect execution that bypassed an unsatisfied approval gate.
    """

    @property
    def check_name(self) -> str:
        return "approval-gate-consistency-check"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        issues: list[SentinelIssue] = []

        for observation in _governance_observations(context.metadata):
            executed = _coerce_bool(observation.get("executed"))
            approval_required = _coerce_bool(observation.get("approval_required"))
            approval_satisfied = _coerce_bool(observation.get("approval_satisfied"))

            if executed and approval_required and not approval_satisfied:
                issues.append(
                    SentinelIssue(
                        code="sentinel.approval_gate_contradiction",
                        severity=SentinelSeverity.ERROR,
                        summary=(
                            "Runtime execution proceeded despite an unsatisfied "
                            "approval gate."
                        ),
                        source=self.check_name,
                        details=(
                            "Governed execution must not proceed when approval is "
                            "required but has not been satisfied."
                        ),
                        data={"observation": dict(observation)},
                    )
                )

        return tuple(issues)


class TaskStateTraceContradictionCheck(SentinelCheck):
    """
    Detect contradictions between task state and emitted trace records.
    """

    @property
    def check_name(self) -> str:
        return "task-state-trace-contradiction-check"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        task = context.task
        if task is None:
            return ()

        trace_messages = tuple(
            _normalize_optional_text(getattr(record, "message", None)) or ""
            for record in context.trace_records
        )
        normalized_messages = tuple(
            message.lower() for message in trace_messages if message
        )

        if not normalized_messages:
            return ()

        task_state = task.state.value
        issues: list[SentinelIssue] = []

        if task_state == "completed" and _contains_failure_signal(normalized_messages):
            issues.append(
                SentinelIssue(
                    code="sentinel.task_state_contradiction",
                    severity=SentinelSeverity.WARNING,
                    summary=(
                        "Task state is completed, but trace records contain "
                        "failure signals."
                    ),
                    source=self.check_name,
                    details=_state_trace_details(
                        task_state=task_state,
                        messages=trace_messages,
                    ),
                    data={"task_state": task_state},
                )
            )

        if task_state == "failed" and _contains_completion_signal(
            normalized_messages
        ):
            issues.append(
                SentinelIssue(
                    code="sentinel.task_state_contradiction",
                    severity=SentinelSeverity.WARNING,
                    summary=(
                        "Task state is failed, but trace records contain "
                        "completion signals."
                    ),
                    source=self.check_name,
                    details=_state_trace_details(
                        task_state=task_state,
                        messages=trace_messages,
                    ),
                    data={"task_state": task_state},
                )
            )

        return tuple(issues)


def register_default_sentinel_checks(runtime: SentinelRuntime) -> tuple[str, ...]:
    """
    Register the default contradiction-oriented sentinel checks.

    Returns the registered check names in deterministic order.
    """
    checks: tuple[SentinelCheck, ...] = (
        GovernanceExecutionContradictionCheck(),
        ApprovalGateConsistencyCheck(),
        TaskStateTraceContradictionCheck(),
    )

    for check in checks:
        runtime.register(check)

    return tuple(check.check_name for check in checks)


def _governance_observations(metadata: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    raw = metadata.get("governance_observations")
    if not isinstance(raw, list | tuple):
        return ()

    observations: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            observations.append(dict(item))
    return tuple(observations)


def _contains_failure_signal(messages: Iterable[str]) -> bool:
    indicators = (
        "failed",
        "execution failed",
        "verification failed",
        "error",
        "blocked",
    )
    return any(
        any(indicator in message for indicator in indicators)
        for message in messages
    )


def _contains_completion_signal(messages: Iterable[str]) -> bool:
    indicators = (
        "completed",
        "execution completed",
        "verification passed",
        "succeeded",
        "finalized with status=passed",
    )
    return any(
        any(indicator in message for indicator in indicators)
        for message in messages
    )


def _state_trace_details(*, task_state: str, messages: tuple[str, ...]) -> str:
    joined = " | ".join(message for message in messages if message)
    if not joined:
        return f"Contradictory trace evidence was observed for task state '{task_state}'."
    return (
        f"Contradictory trace evidence was observed for task state "
        f"'{task_state}': {joined}"
    )


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return False


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


__all__ = [
    "ApprovalGateConsistencyCheck",
    "ContradictionAssertion",
    "ContradictionCheck",
    "FailureLoopCheck",
    "FailureLoopWindow",
    "GovernanceConsistencyCheck",
    "GovernanceExecutionContradictionCheck",
    "GovernanceObservation",
    "PolicyGuardrailCheck",
    "PolicyObservation",
    "TaskStateTraceContradictionCheck",
    "register_default_sentinel_checks",
]
