from __future__ import annotations

import sys
from pathlib import Path

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    CommandSpec,
    ForgeWorkspaceManager,
    GovernedForgeCommandRunner,
)
from ix_blackfox.governance import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalState,
    ApprovalStatus,
    GovernanceReceiptLedger,
    ReceiptEventType,
)


def test_governed_command_runner_executes_low_risk_test_command(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    workspace = ForgeWorkspaceManager(config).reserve(prefix="governed-low")
    ledger = GovernanceReceiptLedger()

    result = GovernedForgeCommandRunner().run(
        task_id="task-governed-low",
        workspace=workspace,
        spec=CommandSpec(
            argv=(sys.executable, "-m", "pytest", "--version"),
        ),
        requested_by="runtime.orchestrator",
        receipt_ledger=ledger,
    )

    assert result.executed is True
    assert result.succeeded is True
    assert result.command_result is not None
    assert result.decision.decision.value == "allow"
    assert result.ticket.is_executable is True
    assert ledger.count() == 3

    snapshot = ledger.snapshot()
    events = tuple(record.event_type for record in snapshot.filter_by_intent(result.intent.intent_id))
    assert events == (
        ReceiptEventType.POLICY_ALLOWED,
        ReceiptEventType.EXECUTION_STARTED,
        ReceiptEventType.EXECUTION_COMPLETED,
    )


def test_governed_command_runner_blocks_network_egress_command(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    workspace = ForgeWorkspaceManager(config).reserve(prefix="governed-egress")
    ledger = GovernanceReceiptLedger()

    result = GovernedForgeCommandRunner().run(
        task_id="task-governed-egress",
        workspace=workspace,
        spec=CommandSpec(
            argv=("curl", "https://example.invalid"),
        ),
        receipt_ledger=ledger,
    )

    assert result.executed is False
    assert result.command_result is None
    assert result.decision.decision.value == "block"
    assert result.risk.risk_level.value == "critical"
    assert result.execution_note == "Governance policy blocked command execution."
    assert ledger.count() == 1

    snapshot = ledger.snapshot()
    latest = snapshot.latest_for_intent(result.intent.intent_id)
    assert latest is not None
    assert latest.event_type == ReceiptEventType.POLICY_BLOCKED


def test_governed_command_runner_requires_approval_for_high_risk_command(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    workspace = ForgeWorkspaceManager(config).reserve(prefix="governed-review")
    ledger = GovernanceReceiptLedger()

    result = GovernedForgeCommandRunner().run(
        task_id="task-governed-review",
        workspace=workspace,
        spec=CommandSpec(
            argv=("git", "status"),
        ),
        receipt_ledger=ledger,
    )

    assert result.executed is False
    assert result.approval_satisfied is False
    assert result.decision.decision.value == "require_review"
    assert result.ticket.requires_review is True
    assert result.execution_note == "Command execution requires recorded approval."
    assert ledger.count() == 1

    snapshot = ledger.snapshot()
    latest = snapshot.latest_for_intent(result.intent.intent_id)
    assert latest is not None
    assert latest.event_type == ReceiptEventType.POLICY_REVIEW_REQUIRED


def test_governed_command_runner_executes_reviewed_high_risk_command(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    workspace = ForgeWorkspaceManager(config).reserve(prefix="governed-approved")
    ledger = GovernanceReceiptLedger()
    runner = GovernedForgeCommandRunner()

    preview = runner.run(
        task_id="task-governed-approved",
        workspace=workspace,
        spec=CommandSpec(
            argv=("git", "status"),
        ),
    )

    approval_request = ApprovalRequest.create(
        intent_id=preview.intent.intent_id,
        summary="Approve governed git status command.",
        rationale="High-risk command requires explicit review.",
        policy_reason=preview.decision.reason.value,
    )
    approval_decision = ApprovalDecision.create(
        approval_id=approval_request.approval_id,
        intent_id=approval_request.intent_id,
        status=ApprovalStatus.APPROVED,
        decided_by="maintainer.one",
        note="Approved for controlled execution.",
    )
    approval_state = ApprovalState(
        request=approval_request,
        decision=approval_decision,
    )

    result = runner.run(
        task_id="task-governed-approved",
        workspace=workspace,
        spec=CommandSpec(
            argv=("git", "status"),
        ),
        approvals=(approval_state,),
        receipt_ledger=ledger,
    )

    assert result.executed is True
    assert result.approval_satisfied is True
    assert result.command_result is not None
    assert result.command_result.exit_code == 0
    assert ledger.count() == 4

    snapshot = ledger.snapshot()
    events = tuple(record.event_type for record in snapshot.filter_by_intent(result.intent.intent_id))
    assert events == (
        ReceiptEventType.POLICY_REVIEW_REQUIRED,
        ReceiptEventType.APPROVAL_RECORDED,
        ReceiptEventType.EXECUTION_STARTED,
        ReceiptEventType.EXECUTION_COMPLETED,
    )
