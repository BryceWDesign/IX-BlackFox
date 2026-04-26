"""
Sentinel subsystem.

Sentinel is the runtime consistency and anomaly-detection layer of
IX-BlackFox. It evaluates trace evidence, governance observations, and
task outcomes to surface contradictions before they become silent
runtime drift.

The current layer provides:
- core sentinel issue and report models
- a deterministic sentinel runtime
- built-in contradiction and approval-gate consistency checks
- a helper to register default checks in one step
"""

from ix_blackfox.sentinel.checks import (
    ApprovalGateConsistencyCheck,
    ContradictionAssertion,
    ContradictionCheck,
    FailureLoopCheck,
    FailureLoopWindow,
    GovernanceConsistencyCheck,
    GovernanceExecutionContradictionCheck,
    GovernanceObservation,
    PolicyGuardrailCheck,
    PolicyObservation,
    TaskStateTraceContradictionCheck,
    register_default_sentinel_checks,
)
from ix_blackfox.sentinel.core import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelReport,
    SentinelRuntime,
    SentinelSeverity,
    SentinelSnapshot,
)

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
    "SentinelCheck",
    "SentinelContext",
    "SentinelIssue",
    "SentinelReport",
    "SentinelRuntime",
    "SentinelSeverity",
    "SentinelSnapshot",
    "TaskStateTraceContradictionCheck",
    "register_default_sentinel_checks",
]
