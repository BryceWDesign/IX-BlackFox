from __future__ import annotations

import pytest

from ix_blackfox.forge import (
    ForgeExecutionDisposition,
    ForgeExecutionTicketBuilder,
)
from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalState,
    ApprovalStatus,
    GovernancePolicy,
    RiskFactor,
    RiskLevel,
)


def test_execution_ticket_builder_maps_allowed_action_to_ready() -> None:
    intent = ActionIntent.create(
        task_id="task-123",
        action_kind=ActionKind.TEST_RUN,
        summary="Run repository verification suite.",
        rationale="Validate the workspace after a governed patch.",
        target_locator="tests",
        labels=("verification", "runtime"),
    )
    risk = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )
    decision = GovernancePolicy().evaluate(intent=intent, risk=risk)

    ticket = ForgeExecutionTicketBuilder().build(
        intent=intent,
        risk=risk,
        decision=decision,
        metadata={"source": "orchestrator"},
    )

    assert ticket.ticket_id.startswith("ticket-")
    assert ticket.intent_id == intent.intent_id
    assert ticket.task_id == "task-123"
    assert ticket.disposition == ForgeExecutionDisposition.READY
    assert ticket.is_executable is True
    assert ticket.requires_review is False
    assert ticket.summary == "Run repository verification suite."
    assert ticket.target_locator == "tests"
    assert ticket.risk_level == "low"
    assert ticket.policy_decision.value == "allow"
    assert ticket.labels == ("verification", "runtime")
    assert ticket.metadata == {"source": "orchestrator"}


def test_execution_ticket_builder_maps_review_required_action() -> None:
    intent = ActionIntent.create(
        task_id="task-200",
        action_kind=ActionKind.FILE_WRITE,
        summary="Write governed runtime artifact.",
        rationale="Persist a controlled output artifact.",
        target_locator="artifacts/run.json",
    )
    risk = ActionRiskProfile(
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
    decision = GovernancePolicy().evaluate(intent=intent, risk=risk)
    approval_request = ApprovalRequest.create(
        intent_id=intent.intent_id,
        summary="Review controlled artifact write.",
        rationale="Moderate-risk write requires approval.",
        policy_reason=decision.reason.value,
    )
    approval_state = ApprovalState(request=approval_request)

    ticket = ForgeExecutionTicketBuilder().build(
        intent=intent,
        risk=risk,
        decision=decision,
        approvals=(approval_state,),
    )

    assert ticket.disposition == ForgeExecutionDisposition.REVIEW_REQUIRED
    assert ticket.is_executable is False
    assert ticket.requires_review is True
    assert ticket.approval_ids == (approval_request.approval_id,)
    assert ticket.policy_decision.value == "require_review"


def test_execution_ticket_builder_maps_blocked_action() -> None:
    intent = ActionIntent.create(
        task_id="task-300",
        action_kind=ActionKind.NETWORK_EGRESS,
        summary="Send governed output to remote endpoint.",
        rationale="Attempt outbound data transmission.",
        target_locator="https://example.invalid/egress",
    )
    risk = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )
    decision = GovernancePolicy().evaluate(intent=intent, risk=risk)

    ticket = ForgeExecutionTicketBuilder().build(
        intent=intent,
        risk=risk,
        decision=decision,
    )

    assert ticket.disposition == ForgeExecutionDisposition.BLOCKED
    assert ticket.is_executable is False
    assert ticket.requires_review is False
    assert ticket.policy_decision.value == "block"


def test_execution_ticket_builder_rejects_mismatched_intent_and_risk() -> None:
    intent = ActionIntent.create(
        task_id="task-400",
        action_kind=ActionKind.COMMAND,
        summary="Run governed command.",
        rationale="Validate mismatch handling.",
        target_locator="workspace",
    )
    risk = ActionRiskProfile(
        intent_id="intent-other",
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )
    decision = GovernancePolicy().evaluate(
        intent=intent,
        risk=ActionRiskProfile(
            intent_id=intent.intent_id,
            risk_level=RiskLevel.LOW,
            requires_approval=False,
        ),
    )

    with pytest.raises(ValueError, match="same intent_id"):
        ForgeExecutionTicketBuilder().build(
            intent=intent,
            risk=risk,
            decision=decision,
        )


def test_execution_ticket_builder_rejects_mismatched_intent_and_decision() -> None:
    intent = ActionIntent.create(
        task_id="task-500",
        action_kind=ActionKind.TEST_RUN,
        summary="Run governed tests.",
        rationale="Validate identity mismatch.",
        target_locator="tests",
    )
    risk = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
    )
    unrelated_intent = ActionIntent.create(
        task_id="task-other",
        action_kind=ActionKind.TEST_RUN,
        summary="Other governed tests.",
        rationale="Produce unrelated policy decision.",
        target_locator="tests",
    )
    unrelated_decision = GovernancePolicy().evaluate(
        intent=unrelated_intent,
        risk=ActionRiskProfile(
            intent_id=unrelated_intent.intent_id,
            risk_level=RiskLevel.LOW,
            requires_approval=False,
        ),
    )

    with pytest.raises(ValueError, match="same intent_id"):
        ForgeExecutionTicketBuilder().build(
            intent=intent,
            risk=risk,
            decision=unrelated_decision,
        )


def test_execution_ticket_deduplicates_approval_ids_from_states() -> None:
    intent = ActionIntent.create(
        task_id="task-600",
        action_kind=ActionKind.FILE_WRITE,
        summary="Write governed source file.",
        rationale="Controlled source mutation requires approval.",
        target_locator="src/ix_blackfox/example.py",
    )
    risk = ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=RiskLevel.HIGH,
        requires_approval=False,
        factors=(
            RiskFactor(
                code="source-mutation",
                description="Touches tracked source files.",
            ),
        ),
    )
    decision = GovernancePolicy().evaluate(intent=intent, risk=risk)

    approval_request = ApprovalRequest.create(
        intent_id=intent.intent_id,
        summary="Approve source mutation.",
        rationale="Tracked source mutation requires review.",
        policy_reason=decision.reason.value,
    )
    approval_decision = ApprovalDecision.create(
        approval_id=approval_request.approval_id,
        intent_id=approval_request.intent_id,
        status=ApprovalStatus.APPROVED,
        decided_by="maintainer.one",
        note="Approved after review.",
    )
    approval_state = ApprovalState(
        request=approval_request,
        decision=approval_decision,
    )

    ticket = ForgeExecutionTicketBuilder().build(
        intent=intent,
        risk=risk,
        decision=decision,
        approvals=(approval_state, approval_state),
    )

    assert ticket.approval_ids == (approval_request.approval_id,)
