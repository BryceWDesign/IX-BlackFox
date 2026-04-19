"""
Sentinel subsystem.

Sentinel is the runtime conscience of BlackFox. It detects unstable
plans, contradictions, repeated failure loops, and policy-boundary
violations before damage compounds. The initial core establishes a
stable check protocol, issue model, and evaluation runtime, and the
first built-in checks target contradictory reasoning signals and
repeated failure patterns.
"""

from ix_blackfox.sentinel.checks import (
    ContradictionAssertion,
    ContradictionCheck,
    FailureLoopCheck,
    FailureLoopWindow,
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
    "ContradictionAssertion",
    "ContradictionCheck",
    "FailureLoopCheck",
    "FailureLoopWindow",
    "SentinelCheck",
    "SentinelContext",
    "SentinelIssue",
    "SentinelReport",
    "SentinelRuntime",
    "SentinelSeverity",
    "SentinelSnapshot",
]
