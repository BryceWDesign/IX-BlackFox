from __future__ import annotations

import pytest

from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    GovernancePolicy,
    PolicyDecisionReason,
    PolicyDecisionType,
    RiskFactor,
    RiskLevel,
)


def test_policy_allows_low_risk_action_by_default() -> None:
    intent = ActionIntent.create(
        task_id="task-1",
        action_kind=ActionKind.TEST_RUN,
        summary="Run unit tests.",
        rationale="Validate repository integrity after a patch.",
        target_locator="tests",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.intent_id == intent.intent_id
    assert decision.decision == PolicyDecisionType.ALLOW
    assert decision.reason == PolicyDecisionReason.LOW_RISK_DEFAULT
    assert decision.matched_rules == ("low-risk-default",)


def test_policy_allows_moderate_risk_by_default() -> None:
    intent = ActionIntent.create(
        task_id="task-2",
        action_kind=ActionKind.COMMAND,
        summary="Run deterministic formatter check.",
        rationale="Verify formatting contract without mutating files.",
        target_locator="src/ix_blackfox",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.MODERATE,
        requires_approval=False,
        factors=(
            RiskFactor(
                code="workspace-read",
                description="Touches repository workspace during verification.",
            ),
        ),
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.decision == PolicyDecisionType.ALLOW
    assert decision.reason == PolicyDecisionReason.MODERATE_RISK_DEFAULT
    assert decision.matched_rules == ("moderate-risk-default",)


def test_policy_requires_review_for_explicit_approval_profile() -> None:
    intent = ActionIntent.create(
        task_id="task-3",
        action_kind=ActionKind.FILE_WRITE,
        summary="Write governed runtime artifact.",
        rationale="Persist a controlled output artifact.",
        target_locator="artifacts/run.json",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.MODERATE,
        requires_approval=True,
        factors=(
            RiskFactor(
                code="artifact-mutation",
                description="Writes a new artifact to persistent storage.",
            ),
        ),
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.decision == PolicyDecisionType.REQUIRE_REVIEW
    assert decision.reason == PolicyDecisionReason.APPROVAL_REQUIRED
    assert decision.matched_rules == ("explicit-approval-required",)


def test_policy_requires_review_for_high_risk_action() -> None:
    intent = ActionIntent.create(
        task_id="task-4",
        action_kind=ActionKind.STATE_MUTATION,
        summary="Mutate persisted runtime state.",
        rationale="Apply a controlled state transition to a sealed record.",
        target_locator="state/runtime.json",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.HIGH,
        requires_approval=False,
        factors=(
            RiskFactor(
                code="state-mutation",
                description="Touches persisted runtime state.",
            ),
        ),
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.decision == PolicyDecisionType.REQUIRE_REVIEW
    assert decision.reason == PolicyDecisionReason.HIGH_RISK_REQUIRES_REVIEW
    assert decision.matched_rules == ("high-risk-review",)


def test_policy_blocks_critical_risk_actions() -> None:
    intent = ActionIntent.create(
        task_id="task-5",
        action_kind=ActionKind.COMMAND,
        summary="Run destructive repository command.",
        rationale="Attempt a high-impact destructive command.",
        target_locator="workspace",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.CRITICAL,
        requires_approval=False,
        factors=(
            RiskFactor(
                code="destructive-operation",
                description="Action may irreversibly mutate tracked workspace state.",
            ),
        ),
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.decision == PolicyDecisionType.BLOCK
    assert decision.reason == PolicyDecisionReason.CRITICAL_RISK_BLOCKED
    assert decision.matched_rules == ("critical-risk-block",)


def test_policy_blocks_configured_action_kind() -> None:
    intent = ActionIntent.create(
        task_id="task-6",
        action_kind=ActionKind.NETWORK_EGRESS,
        summary="Send data to remote endpoint.",
        rationale="Attempt outbound network transmission.",
        target_locator="https://example.invalid/egress",
    )
    profile = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )

    decision = GovernancePolicy().evaluate(intent=intent, risk=profile)

    assert decision.decision == PolicyDecisionType.BLOCK
    assert decision.reason == PolicyDecisionReason.ACTION_KIND_BLOCKED
    assert decision.matched_rules == ("blocked-action-kind", "network_egress")


def test_policy_rejects_intent_and_profile_id_mismatch() -> None:
    intent = ActionIntent.create(
        task_id="task-7",
        action_kind=ActionKind.TEST_RUN,
        summary="Run mismatch check.",
        rationale="Ensure governance evaluation rejects mixed identities.",
        target_locator="tests",
    )
    profile = ActionRiskProfile(
        intent_id="intent-other",
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )

    with pytest.raises(
        ValueError,
        match="same intent_id",
    ):
        GovernancePolicy().evaluate(intent=intent, risk=profile)
