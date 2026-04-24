from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainEscalationBudget,
    BrainEscalationPolicy,
    BrainEscalationTrigger,
)


def test_escalation_policy_triggers_on_explicit_request_alone() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        explicit_deep_reasoning=True,
        budget=BrainEscalationBudget(max_escalation_hops=2),
    )

    assert decision.should_escalate is True
    assert decision.score == policy.explicit_request_score
    assert decision.trigger_codes() == ("explicit_deep_reasoning_request",)
    assert decision.blocked_by_budget is False
    assert decision.remaining_hops == 2


def test_escalation_policy_combines_low_confidence_and_verification_failure() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        route_confidence=0.41,
        verification_failed=True,
        budget=BrainEscalationBudget(max_escalation_hops=3),
    )

    assert decision.should_escalate is True
    assert decision.score == (
        policy.low_route_confidence_score + policy.verification_failure_score
    )
    assert decision.trigger_codes() == (
        "low_route_confidence",
        "verification_failure",
    )
    assert decision.remaining_hops == 3


def test_escalation_policy_supports_contradiction_and_repeated_failures() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        contradiction_detected=True,
        repeated_failures=3,
        budget=BrainEscalationBudget(max_escalation_hops=4),
    )

    assert decision.should_escalate is True
    assert decision.score == (
        policy.sentinel_contradiction_score + policy.repeated_failures_score
    )
    assert decision.trigger_codes() == (
        "sentinel_contradiction",
        "repeated_failures",
    )


def test_escalation_policy_does_not_escalate_when_score_is_below_threshold() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        approval_required=True,
        budget=BrainEscalationBudget(max_escalation_hops=1),
    )

    assert decision.should_escalate is False
    assert decision.score == policy.policy_review_required_score
    assert decision.trigger_codes() == ("policy_review_required",)


def test_escalation_policy_respects_budget_disable_flag() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        explicit_deep_reasoning=True,
        budget=BrainEscalationBudget(
            allow_reasoning_escalation=False,
            max_escalation_hops=3,
        ),
    )

    assert decision.should_escalate is False
    assert decision.blocked_by_budget is True
    assert decision.blocked_reason == "Escalation budget disabled reasoning escalation."
    assert decision.score == policy.explicit_request_score
    assert decision.remaining_hops == 3


def test_escalation_policy_respects_max_hops() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        explicit_deep_reasoning=True,
        budget=BrainEscalationBudget(max_escalation_hops=1),
        current_escalation_hops=1,
    )

    assert decision.should_escalate is False
    assert decision.blocked_by_budget is True
    assert decision.blocked_reason == "Escalation hop budget is exhausted."
    assert decision.remaining_hops == 0
    assert decision.score == policy.explicit_request_score


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"route_confidence": 1.5},
            "route_confidence must be between 0.0 and 1.0",
        ),
        (
            {"repeated_failures": -1},
            "repeated_failures must be zero or greater",
        ),
        (
            {"current_escalation_hops": -1},
            "current_escalation_hops must be zero or greater",
        ),
    ],
)
def test_escalation_policy_rejects_invalid_inputs(kwargs, message: str) -> None:
    policy = BrainEscalationPolicy()

    with pytest.raises(ValueError, match=message):
        policy.evaluate(**kwargs)


def test_escalation_policy_reason_objects_keep_trigger_metadata() -> None:
    policy = BrainEscalationPolicy()

    decision = policy.evaluate(
        route_confidence=0.33,
        repeated_failures=5,
        budget=BrainEscalationBudget(max_escalation_hops=5),
    )

    assert decision.should_escalate is True
    assert len(decision.reasons) == 2
    assert decision.reasons[0].trigger is BrainEscalationTrigger.LOW_ROUTE_CONFIDENCE
    assert decision.reasons[0].metadata == {
        "route_confidence": 0.33,
        "threshold": policy.route_confidence_threshold,
    }
    assert decision.reasons[1].trigger is BrainEscalationTrigger.REPEATED_FAILURES
    assert decision.reasons[1].metadata == {
        "repeated_failures": 5,
        "threshold": policy.repeated_failure_threshold,
    }
