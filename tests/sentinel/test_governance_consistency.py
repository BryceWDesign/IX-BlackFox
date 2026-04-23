from __future__ import annotations

from ix_blackfox.sentinel import (
    GovernanceConsistencyCheck,
    GovernanceObservation,
    SentinelContext,
    SentinelRuntime,
    SentinelSeverity,
)


def test_governance_consistency_detects_blocked_execution() -> None:
    runtime = SentinelRuntime()
    runtime.register(GovernanceConsistencyCheck())

    report = runtime.evaluate(
        SentinelContext(
            metadata={
                "governance_observations": (
                    GovernanceObservation(
                        action="runtime_pack_dispatch",
                        decision="block",
                        executed=True,
                        approval_required=False,
                        approval_satisfied=False,
                        source="runtime",
                        reason="Blocked by policy.",
                    ),
                )
            }
        )
    )

    assert len(report.issues) == 1
    issue = report.issues[0]
    assert issue.code == "governance.blocked_execution"
    assert issue.severity == SentinelSeverity.CRITICAL


def test_governance_consistency_detects_review_gate_bypass() -> None:
    runtime = SentinelRuntime()
    runtime.register(GovernanceConsistencyCheck())

    report = runtime.evaluate(
        SentinelContext(
            metadata={
                "governance_observations": (
                    {
                        "action": "runtime_pack_dispatch",
                        "decision": "require_review",
                        "executed": True,
                        "approval_required": True,
                        "approval_satisfied": False,
                        "source": "runtime",
                        "reason": "Requires approval.",
                    },
                )
            }
        )
    )

    assert len(report.issues) == 1
    issue = report.issues[0]
    assert issue.code == "governance.review_gate_bypassed"
    assert issue.severity == SentinelSeverity.ERROR


def test_governance_consistency_flags_inconsistent_allow_with_approval_required() -> None:
    runtime = SentinelRuntime()
    runtime.register(GovernanceConsistencyCheck())

    report = runtime.evaluate(
        SentinelContext(
            metadata={
                "governance_observations": (
                    {
                        "action": "runtime_pack_dispatch",
                        "decision": "allow",
                        "executed": False,
                        "approval_required": True,
                        "approval_satisfied": False,
                        "source": "runtime",
                        "reason": "Allowed by policy.",
                    },
                )
            }
        )
    )

    assert len(report.issues) == 1
    issue = report.issues[0]
    assert issue.code == "governance.approval_state_inconsistent"
    assert issue.severity == SentinelSeverity.WARNING
