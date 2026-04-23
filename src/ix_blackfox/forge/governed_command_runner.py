from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path

from ix_blackfox.forge.command_runner import (
    CommandResult,
    CommandSpec,
    ForgeCommandRunner,
)
from ix_blackfox.forge.execution_ticket import (
    ForgeExecutionTicket,
    ForgeExecutionTicketBuilder,
)
from ix_blackfox.forge.workspace import WorkspaceReservation
from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    ApprovalState,
    ApprovalStatus,
    GovernancePolicy,
    GovernanceReceiptLedger,
    PolicyDecision,
    ReceiptEventType,
    RiskFactor,
    RiskLevel,
)


@dataclass(frozen=True, slots=True)
class GovernedCommandRunResult:
    """
    Full governed view of one forge command attempt.

    Attributes
    ----------
    spec:
        Original command specification.
    intent:
        Normalized governance action intent for the command.
    risk:
        Derived governance risk profile.
    decision:
        Governance policy decision for the command.
    ticket:
        Governed forge execution ticket.
    command_result:
        Command execution result when the command actually ran.
    executed:
        Whether the underlying command executed.
    approval_satisfied:
        Whether a terminal approved review state was present when
        review-gated execution was required.
    execution_note:
        Short human-readable outcome explanation.
    receipts:
        Governance receipts emitted for this governed attempt.
    """

    spec: CommandSpec
    intent: ActionIntent
    risk: ActionRiskProfile
    decision: PolicyDecision
    ticket: ForgeExecutionTicket
    command_result: CommandResult | None
    executed: bool
    approval_satisfied: bool
    execution_note: str
    receipts: tuple[str, ...] = field(default_factory=tuple)

    @property
    def blocked(self) -> bool:
        """
        Return True when governance prevented command execution.
        """
        return not self.executed

    @property
    def succeeded(self) -> bool:
        """
        Return True when the command executed and exited successfully.
        """
        return (
            self.executed
            and self.command_result is not None
            and self.command_result.succeeded
        )


class GovernedForgeCommandRunner:
    """
    Governance-aware wrapper around forge command execution.

    This runner normalizes command work into governance artifacts,
    evaluates policy before execution, emits receipts, and only dispatches
    the underlying command runner when the action is allowed or when
    review requirements have already been satisfied.
    """

    def __init__(
        self,
        *,
        policy: GovernancePolicy | None = None,
        command_runner: ForgeCommandRunner | None = None,
        ticket_builder: ForgeExecutionTicketBuilder | None = None,
    ) -> None:
        self._policy = policy or GovernancePolicy()
        self._command_runner = command_runner or ForgeCommandRunner()
        self._ticket_builder = ticket_builder or ForgeExecutionTicketBuilder()

    def run(
        self,
        *,
        task_id: str,
        workspace: WorkspaceReservation,
        spec: CommandSpec,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
        approvals: tuple[ApprovalState, ...] = (),
        receipt_ledger: GovernanceReceiptLedger | None = None,
    ) -> GovernedCommandRunResult:
        """
        Evaluate and, when allowed, execute one governed forge command.
        """
        action_kind = _derive_action_kind(spec)
        intent = ActionIntent.create(
            task_id=task_id,
            action_kind=action_kind,
            summary=_build_summary(spec),
            rationale=_build_rationale(spec),
            target_locator=spec.cwd_relative_path,
            requested_by=requested_by,
            labels=_normalize_labels(("forge-command", *labels)),
            metadata=_build_metadata(spec=spec, metadata=metadata),
        )
        intent = replace(
            intent,
            intent_id=_stable_intent_id(
                task_id=task_id, action_kind=action_kind, spec=spec
            ),
        )
        risk = _build_command_risk_profile(
            intent=intent, spec=spec, action_kind=action_kind
        )
        decision = self._policy.evaluate(intent=intent, risk=risk)
        ticket = self._ticket_builder.build(
            intent=intent,
            risk=risk,
            decision=decision,
            approvals=approvals,
            metadata={"command_argv": list(spec.argv)},
        )

        receipt_ids: list[str] = []
        receipt_ids.extend(
            _emit_policy_receipts(
                ledger=receipt_ledger,
                decision=decision,
                ticket=ticket,
            )
        )

        approval_satisfied = _approval_satisfied(
            intent_id=intent.intent_id, approvals=approvals
        )
        if decision.decision.value == "block":
            return GovernedCommandRunResult(
                spec=spec,
                intent=intent,
                risk=risk,
                decision=decision,
                ticket=ticket,
                command_result=None,
                executed=False,
                approval_satisfied=approval_satisfied,
                execution_note="Governance policy blocked command execution.",
                receipts=tuple(receipt_ids),
            )

        if decision.decision.value == "require_review" and not approval_satisfied:
            return GovernedCommandRunResult(
                spec=spec,
                intent=intent,
                risk=risk,
                decision=decision,
                ticket=ticket,
                command_result=None,
                executed=False,
                approval_satisfied=False,
                execution_note="Command execution requires recorded approval.",
                receipts=tuple(receipt_ids),
            )

        if approval_satisfied:
            receipt_ids.extend(
                _emit_approval_receipt(
                    ledger=receipt_ledger,
                    intent_id=intent.intent_id,
                )
            )

        receipt_ids.extend(
            _emit_execution_start_receipt(
                ledger=receipt_ledger,
                intent_id=intent.intent_id,
                spec=spec,
            )
        )

        self._prepare_workspace_for_command(workspace=workspace, spec=spec)
        command_result = self._command_runner.run(
            workspace=workspace,
            spec=spec,
        )

        receipt_ids.extend(
            _emit_execution_outcome_receipt(
                ledger=receipt_ledger,
                intent_id=intent.intent_id,
                command_result=command_result,
            )
        )

        execution_note = (
            "Governed command executed successfully."
            if command_result.succeeded
            else "Governed command executed but returned a nonzero exit code."
        )
        return GovernedCommandRunResult(
            spec=spec,
            intent=intent,
            risk=risk,
            decision=decision,
            ticket=ticket,
            command_result=command_result,
            executed=True,
            approval_satisfied=approval_satisfied,
            execution_note=execution_note,
            receipts=tuple(receipt_ids),
        )

    def _prepare_workspace_for_command(
        self,
        *,
        workspace: WorkspaceReservation,
        spec: CommandSpec,
    ) -> None:
        executable = _command_name(spec)
        normalized_argv = tuple(part.strip().lower() for part in spec.argv)
        if executable != "git" or normalized_argv[:2] != ("git", "status"):
            return

        cwd_path = (workspace.root_path / spec.cwd_relative_path).resolve()
        if (cwd_path / ".git").exists():
            return

        self._command_runner.run(
            workspace=workspace,
            spec=CommandSpec(
                argv=("git", "init", "-q"),
                cwd_relative_path=spec.cwd_relative_path,
                timeout_seconds=spec.timeout_seconds,
            ),
        )


def _stable_intent_id(
    *,
    task_id: str,
    action_kind: ActionKind,
    spec: CommandSpec,
) -> str:
    material = "\n".join(
        [
            task_id.strip().lower(),
            action_kind.value,
            spec.cwd_relative_path.strip().lower(),
            *[part.strip() for part in spec.argv],
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"intent-{digest[:32]}"


def _derive_action_kind(spec: CommandSpec) -> ActionKind:
    executable = _command_name(spec)
    if executable in {"curl", "wget", "scp", "ssh"}:
        return ActionKind.NETWORK_EGRESS
    return ActionKind.COMMAND


def _build_summary(spec: CommandSpec) -> str:
    executable = _command_name(spec)
    return f"Execute forge command '{executable}'."


def _build_rationale(spec: CommandSpec) -> str:
    return (
        "Run a controlled forge command within the reserved workspace "
        "boundary under governance mediation."
    )


def _build_metadata(
    *,
    spec: CommandSpec,
    metadata: dict[str, object] | None,
) -> dict[str, object]:
    payload: dict[str, object] = dict(metadata or {})
    payload.update(
        {
            "argv": list(spec.argv),
            "cwd_relative_path": spec.cwd_relative_path,
            "timeout_seconds": spec.timeout_seconds,
            "env_override_keys": sorted(spec.env_overrides.keys()),
        }
    )
    return payload


def _build_command_risk_profile(
    *,
    intent: ActionIntent,
    spec: CommandSpec,
    action_kind: ActionKind,
) -> ActionRiskProfile:
    risk_level = _derive_risk_level(spec=spec, action_kind=action_kind)
    factors = _derive_risk_factors(
        spec=spec, action_kind=action_kind, risk_level=risk_level
    )
    requires_approval = risk_level == RiskLevel.HIGH

    return ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=risk_level,
        requires_approval=requires_approval,
        factors=tuple(factors),
        tags=_risk_tags(spec=spec, action_kind=action_kind, risk_level=risk_level),
    )


def _derive_risk_level(
    *,
    spec: CommandSpec,
    action_kind: ActionKind,
) -> RiskLevel:
    executable = _command_name(spec)

    if action_kind == ActionKind.NETWORK_EGRESS:
        return RiskLevel.CRITICAL

    if executable in {"git", "rm", "rmdir", "del", "move", "mv"}:
        return RiskLevel.HIGH

    if executable in {"pytest", "ruff", "mypy"}:
        return RiskLevel.LOW

    if executable == Path(spec.argv[0]).name.lower():
        if _is_python_test_command(spec):
            return RiskLevel.LOW

    return RiskLevel.MODERATE


def _derive_risk_factors(
    *,
    spec: CommandSpec,
    action_kind: ActionKind,
    risk_level: RiskLevel,
) -> list[RiskFactor]:
    executable = _command_name(spec)
    factors = [
        RiskFactor(
            code=f"command-{executable}",
            description=(
                f"Forge command invokes the executable '{executable}' inside the "
                "reserved workspace."
            ),
        )
    ]

    if action_kind == ActionKind.NETWORK_EGRESS:
        factors.append(
            RiskFactor(
                code="network-egress-command",
                description="Command may transmit data beyond the workspace boundary.",
            )
        )

    if risk_level == RiskLevel.HIGH:
        factors.append(
            RiskFactor(
                code="review-sensitive-command",
                description="Command crosses the governed review threshold.",
            )
        )

    if risk_level == RiskLevel.CRITICAL:
        factors.append(
            RiskFactor(
                code="critical-command-risk",
                description="Command is blocked by default critical-risk policy.",
            )
        )

    if spec.env_overrides:
        factors.append(
            RiskFactor(
                code="environment-overrides-present",
                description="Command supplies explicit environment variable overrides.",
            )
        )

    return factors


def _risk_tags(
    *,
    spec: CommandSpec,
    action_kind: ActionKind,
    risk_level: RiskLevel,
) -> tuple[str, ...]:
    raw_tags = [
        "forge-command",
        f"risk-{risk_level.value.lower()}",
        f"action-{action_kind.value.lower()}",
        f"cmd-{_command_name(spec)}",
    ]
    return _normalize_labels(tuple(raw_tags))


def _command_name(spec: CommandSpec) -> str:
    return Path(spec.argv[0]).name.strip().lower()


def _is_python_test_command(spec: CommandSpec) -> bool:
    argv = tuple(part.strip() for part in spec.argv)
    if len(argv) < 3:
        return False
    executable = _command_name(spec)
    if not executable.startswith("python"):
        return False
    return argv[1] == "-m" and argv[2] in {"pytest", "unittest"}


def _approval_satisfied(
    *,
    intent_id: str,
    approvals: tuple[ApprovalState, ...],
) -> bool:
    for state in approvals:
        if state.request.intent_id != intent_id:
            continue
        if state.current_status() == ApprovalStatus.APPROVED:
            return True
    return False


def _emit_policy_receipts(
    *,
    ledger: GovernanceReceiptLedger | None,
    decision: PolicyDecision,
    ticket: ForgeExecutionTicket,
) -> list[str]:
    if ledger is None:
        return []

    if decision.decision.value == "allow":
        event_type = ReceiptEventType.POLICY_ALLOWED
    elif decision.decision.value == "require_review":
        event_type = ReceiptEventType.POLICY_REVIEW_REQUIRED
    else:
        event_type = ReceiptEventType.POLICY_BLOCKED

    record = ledger.append(
        intent_id=ticket.intent_id,
        event_type=event_type,
        summary=decision.rationale,
        actor="forge.governed_command",
        metadata={
            "ticket_id": ticket.ticket_id,
            "policy_decision": decision.decision.value,
            "policy_reason": decision.reason.value,
        },
    )
    return [record.receipt_id]


def _emit_approval_receipt(
    *,
    ledger: GovernanceReceiptLedger | None,
    intent_id: str,
) -> list[str]:
    if ledger is None:
        return []

    record = ledger.append(
        intent_id=intent_id,
        event_type=ReceiptEventType.APPROVAL_RECORDED,
        summary="Recorded approval satisfied the review gate for command execution.",
        actor="forge.governed_command",
        metadata={},
    )
    return [record.receipt_id]


def _emit_execution_start_receipt(
    *,
    ledger: GovernanceReceiptLedger | None,
    intent_id: str,
    spec: CommandSpec,
) -> list[str]:
    if ledger is None:
        return []

    record = ledger.append(
        intent_id=intent_id,
        event_type=ReceiptEventType.EXECUTION_STARTED,
        summary="Governed command execution started.",
        actor="forge.governed_command",
        metadata={
            "argv": list(spec.argv),
            "cwd_relative_path": spec.cwd_relative_path,
        },
    )
    return [record.receipt_id]


def _emit_execution_outcome_receipt(
    *,
    ledger: GovernanceReceiptLedger | None,
    intent_id: str,
    command_result: CommandResult,
) -> list[str]:
    if ledger is None:
        return []

    event_type = (
        ReceiptEventType.EXECUTION_COMPLETED
        if command_result.succeeded
        else ReceiptEventType.EXECUTION_FAILED
    )
    record = ledger.append(
        intent_id=intent_id,
        event_type=event_type,
        summary=(
            "Governed command execution completed successfully."
            if command_result.succeeded
            else "Governed command execution completed with a nonzero exit code."
        ),
        actor="forge.governed_command",
        metadata={
            "exit_code": command_result.exit_code,
            "cwd_path": str(command_result.cwd_path),
            "duration_seconds": command_result.duration_seconds,
        },
    )
    return [record.receipt_id]


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = raw_value.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
