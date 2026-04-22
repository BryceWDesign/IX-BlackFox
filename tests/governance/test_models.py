from __future__ import annotations

import pytest

from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    RiskFactor,
    RiskLevel,
)


def test_action_intent_create_normalizes_fields() -> None:
    intent = ActionIntent.create(
        task_id="  TASK-123  ",
        action_kind=ActionKind.COMMAND,
        summary="  Run repository verification suite.  ",
        rationale="  Verify that the governed patch did not break contracts.  ",
        target_locator=r"  tests\  ",
        requested_by="  forge.runtime  ",
        labels=(" Verification ", "runtime", "", "verification"),
        metadata={"mode": "strict"},
    )

    assert intent.intent_id.startswith("intent-")
    assert intent.task_id == "task-123"
    assert intent.action_kind == ActionKind.COMMAND
    assert intent.summary == "Run repository verification suite."
    assert intent.rationale == "Verify that the governed patch did not break contracts."
    assert intent.target_locator == "tests/"
    assert intent.requested_by == "forge.runtime"
    assert intent.labels == ("verification", "runtime")
    assert intent.metadata == {"mode": "strict"}


def test_action_intent_rejects_empty_summary() -> None:
    with pytest.raises(ValueError, match="summary must not be empty"):
        ActionIntent.create(
            task_id="task-1",
            action_kind=ActionKind.FILE_WRITE,
            summary="   ",
            rationale="Write a governed file.",
            target_locator="src/ix_blackfox/example.py",
        )


def test_risk_factor_normalizes_code_and_description() -> None:
    factor = RiskFactor(
        code="  Requires Review  ",
        description="  This action mutates controlled source files.  ",
    )

    assert factor.code == "requires-review"
    assert factor.description == "This action mutates controlled source files."


def test_action_risk_profile_requires_factor_when_approval_is_required() -> None:
    with pytest.raises(
        ValueError,
        match="Approval-required action risk profiles must include at least one factor",
    ):
        ActionRiskProfile(
            intent_id="intent-1",
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
        )


def test_action_risk_profile_exposes_factor_codes() -> None:
    profile = ActionRiskProfile(
        intent_id="  INTENT-42  ",
        risk_level=RiskLevel.MODERATE,
        requires_approval=True,
        factors=(
            RiskFactor(
                code=" source mutation ",
                description="Touches tracked source files.",
            ),
            RiskFactor(
                code=" operator requested ",
                description="Action was initiated by an operator.",
            ),
        ),
        tags=(" Source ", "review", "source"),
    )

    assert profile.intent_id == "intent-42"
    assert profile.tags == ("source", "review")
    assert profile.factor_codes() == ("source-mutation", "operator-requested")
