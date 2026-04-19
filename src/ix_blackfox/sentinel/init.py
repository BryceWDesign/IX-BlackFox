"""
Sentinel subsystem.

Sentinel is the runtime conscience of BlackFox. It detects unstable
plans, contradictions, repeated failure loops, and policy-boundary
violations before damage compounds. The initial core establishes a
stable check protocol, issue model, and evaluation runtime.
"""

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
    "SentinelCheck",
    "SentinelContext",
    "SentinelIssue",
    "SentinelReport",
    "SentinelRuntime",
    "SentinelSeverity",
    "SentinelSnapshot",
]
