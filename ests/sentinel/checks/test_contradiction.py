from __future__ import annotations

import pytest

from ix_blackfox.sentinel import (
    ContradictionAssertion,
    ContradictionCheck,
    SentinelContext,
    SentinelSeverity,
)


def test_contradiction_assertion_normalizes_fields() -> None:
    assertion = ContradictionAssertion(
        subject=" Runtime ",
        predicate=" Mode ",
        value="Strict",
        source=" planner ",
    )

    assert assertion.subject == "runtime"
    assert assertion.predicate == "mode"
    assert assertion.value == "Strict"
    assert assertion.source == "planner"
    assert assertion.normalized_value() == "strict"


def test_contradiction_check_returns_no_issue_for_consistent_assertions() -> None:
    check = ContradictionCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "assertions": [
                    {
                        "subject": "runtime",
                        "predicate": "mode",
                        "value": "strict",
                        "source": "planner",
                    },
                    {
                        "subject": "runtime",
                        "predicate": "mode",
                        "value": " strict ",
                        "source": "switchboard",
                    },
                ]
            }
        )
    )

    assert issues == ()


def test_contradiction_check_emits_warning_for_noncritical_conflict() -> None:
    check = ContradictionCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "assertions": [
                    {
                        "subject": "task",
                        "predicate": "status",
                        "value": "running",
                        "source": "kernel",
                    },
                    {
                        "subject": "task",
                        "predicate": "status",
                        "value": "completed",
                        "source": "forge",
                    },
                ]
            }
        )
    )

    assert len(issues) == 1
    issue = issues[0]
    assert issue.code == "reasoning.contradiction_detected"
    assert issue.severity == SentinelSeverity.WARNING
    assert issue.source == "contradiction"
    assert issue.data["subject"] == "task"
    assert issue.data["predicate"] == "status"
    assert issue.data["values"] == ("completed", "running")


def test_contradiction_check_emits_error_for_critical_predicate() -> None:
    check = ContradictionCheck(
        critical_predicates=("policy_state",),
    )

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "assertions": [
                    {
                        "subject": "runtime",
                        "predicate": "policy_state",
                        "value": "allowed",
                        "source": "policy",
                    },
                    {
                        "subject": "runtime",
                        "predicate": "policy_state",
                        "value": "blocked",
                        "source": "sentinel",
                    },
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].severity == SentinelSeverity.ERROR
    assert issues[0].data["values"] == ("allowed", "blocked")


def test_contradiction_check_reports_invalid_assertion_payload() -> None:
    check = ContradictionCheck()

    issues = check.evaluate(
        SentinelContext(
            metadata={
                "assertions": [
                    {
                        "subject": "runtime",
                        "value": "strict",
                    }
                ]
            }
        )
    )

    assert len(issues) == 1
    assert issues[0].code == "reasoning.invalid_assertion"
    assert issues[0].severity == SentinelSeverity.ERROR


@pytest.mark.parametrize(
    ("subject", "predicate", "message"),
    [
        ("   ", "mode", "Contradiction assertion subject must not be empty"),
        ("runtime", "   ", "Contradiction assertion predicate must not be empty"),
    ],
)
def test_contradiction_assertion_rejects_invalid_identifiers(
    subject: str,
    predicate: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ContradictionAssertion(
            subject=subject,
            predicate=predicate,
            value="strict",
        )
