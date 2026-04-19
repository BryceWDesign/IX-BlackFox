from __future__ import annotations

import pytest

from ix_blackfox.sentinel import (
    PolicyGuardrailCheck,
    PolicyObservation,
    SentinelContext,
    SentinelSeverity,
)


def test_policy_observation_normalizes_fields() -> None:
    observation = PolicyObservation(
        action=" Delete Workspace ",
        decision=" Blocked ",
        executed=True,
        approved=False,
        source=" policy ",
        reason=" destructive operation ",
    )

    assert observation.action == "delete workspace"
    assert observation.decision == "blocked"
    assert observation.executed is True
    assert observation.approved is False
    assert observation.source == "policy"
    assert observation.reason == "destructive operation"


def test_policy_guardrail_detects_execution_after_denial() -> None:
    check = PolicyGuardrailCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "policy_observations": [
                    {
                        "action": "delete workspace",
                        "decision": "denied",
                        "executed": True,
                        "approved": False,
                        "source": "sentinel",
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    issue = issues[0]
    assert issue.code == "policy.execution_after_denial"
    assert issue.severity == SentinelSeverity.CRITICAL
    assert issue.data["action"] == "delete workspace"


def test_policy_guardrail_detects_blocked_action_execution() -> None:
    check = PolicyGuardrailCheck(
        blocked_actions=("Delete Workspace",),
    )

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "policy_observations": [
                    {
                        "action": "delete workspace",
                        "decision": "allowed",
                        "executed": True,
                        "approved": True,
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "policy.blocked_action_executed"
    assert issues[0].severity == SentinelSeverity.CRITICAL


def test_policy_guardrail_warns_on_high_risk_without_approval() -> None:
    check = PolicyGuardrailCheck(
        high_risk_actions=("network egress",),
    )

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "policy_observations": [
                    {
                        "action": "network egress",
                        "decision": "allowed",
                        "executed": True,
                        "approved": False,
                        "reason": "expedited path",
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "policy.high_risk_without_approval"
    assert issues[0].severity == SentinelSeverity.WARNING


def test_policy_guardrail_flags_review_required_without_approval() -> None:
    check = PolicyGuardrailCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "policy_observations": [
                    {
                        "action": "publish artifact",
                        "decision": "review_required",
                        "executed": True,
                        "approved": False,
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "policy.review_required_bypassed"
    assert issues[0].severity == SentinelSeverity.ERROR


def test_policy_guardrail_reports_invalid_payload() -> None:
    check = PolicyGuardrailCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "policy_observations": [
                    {
                        "action": "publish artifact",
                        "executed": True,
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "policy.invalid_observation"
    assert issues[0].severity == SentinelSeverity.ERROR


@pytest.mark.parametrize(
    ("action", "decision", "message"),
    [
        ("   ", "allowed", "Policy observation action must not be empty"),
        ("publish artifact", "   ", "Policy observation decision must not be empty"),
    ],
)
def test_policy_observation_rejects_invalid_identifiers(
    action: str,
    decision: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PolicyObservation(
            action=action,
            decision=decision,
            executed=True,
        )
