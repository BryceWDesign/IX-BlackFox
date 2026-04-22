from __future__ import annotations

from dataclasses import dataclass

from ix_blackfox.forge import ForgeExecutionTicket, ForgeExecutionTicketBuilder
from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    GovernancePolicy,
    PolicyDecision,
    RiskFactor,
    RiskLevel,
)
from ix_blackfox.kernel import TaskKind, TaskRecord
from ix_blackfox.switchboard import RoutingDecision


@dataclass(frozen=True, slots=True)
class RuntimeGovernancePreflightResult:
    """
    Immutable governance preflight result for one runtime task.

    This structure makes the runtime's pre-execution trust decision
    explicit before any pack work begins.
    """

    intent: ActionIntent
    risk: ActionRiskProfile
    decision: PolicyDecision
    ticket: ForgeExecutionTicket

    @property
    def blocked(self) -> bool:
        return self.decision.decision.value == "block"

    @property
    def requires_review(self) -> bool:
        return self.decision.decision.value == "require_review"

    def to_dict(self) -> dict[str, object]:
        return {
            "intent": {
                "intent_id": self.intent.intent_id,
                "task_id": self.intent.task_id,
                "action_kind": self.intent.action_kind.value,
                "summary": self.intent.summary,
                "rationale": self.intent.rationale,
                "target_locator": self.intent.target_locator,
                "requested_at": self.intent.requested_at.isoformat(),
                "requested_by": self.intent.requested_by,
                "labels": self.intent.labels,
                "metadata": self.intent.metadata,
            },
            "risk": {
                "risk_level": self.risk.risk_level.value,
                "requires_approval": self.risk.requires_approval,
                "factor_codes": self.risk.factor_codes(),
                "tags": self.risk.tags,
            },
            "decision": {
                "decision": self.decision.decision.value,
                "reason": self.decision.reason.value,
                "rationale": self.decision.rationale,
                "decided_at": self.decision.decided_at.isoformat(),
                "matched_rules": self.decision.matched_rules,
            },
            "ticket": {
                "ticket_id": self.ticket.ticket_id,
                "disposition": self.ticket.disposition.value,
                "risk_level": self.ticket.risk_level,
                "policy_decision": self.ticket.policy_decision.value,
                "approval_ids": self.ticket.approval_ids,
                "created_at": self.ticket.created_at.isoformat(),
                "labels": self.ticket.labels,
                "metadata": self.ticket.metadata,
            },
        }


class RuntimeGovernancePreflightEngine:
    """
    Deterministic preflight governance for runtime task execution.

    The preflight step governs pack execution intent before any pack is
    loaded or executed. It does not replace later forge governance. It
    establishes whether the runtime should proceed, warn for review, or
    block outright based on explicit task signals.
    """

    _NETWORK_TERMS: tuple[str, ...] = (
        "curl",
        "wget",
        "ssh",
        "scp",
        "remote endpoint",
        "upload to",
        "send to server",
        "network egress",
        "exfiltrate",
    )
    _DESTRUCTIVE_TERMS: tuple[str, ...] = (
        "delete workspace",
        "wipe repository",
        "destroy files",
        "rm -rf",
        "erase source",
        "remove source file",
        "drop database",
    )

    def __init__(
        self,
        *,
        policy: GovernancePolicy | None = None,
        ticket_builder: ForgeExecutionTicketBuilder | None = None,
    ) -> None:
        self._policy = policy or GovernancePolicy()
        self._ticket_builder = ticket_builder or ForgeExecutionTicketBuilder()

    def evaluate(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
    ) -> RuntimeGovernancePreflightResult:
        prompt = task.request.input.prompt.strip().lower()
        labels = task.request.labels

        action_kind = self._derive_action_kind(
            prompt=prompt,
            labels=labels,
        )
        intent = ActionIntent.create(
            task_id=task.request.task_id,
            action_kind=action_kind,
            summary=f"Preflight runtime execution for pack '{route.capability_name}'.",
            rationale=(
                "Evaluate pack execution intent before runtime dispatch so governance "
                "can surface review gates or hard blocks early."
            ),
            target_locator=route.capability_name,
            requested_by="runtime.preflight",
            labels=_normalize_labels(("runtime-preflight", route.capability_name, *labels)),
            metadata={
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "matched_labels": route.matched_labels,
                "attachment_count": len(task.request.input.attachments),
            },
        )
        risk = self._derive_risk_profile(
            intent=intent,
            task=task,
            route=route,
            prompt=prompt,
            labels=labels,
            action_kind=action_kind,
        )
        decision = self._policy.evaluate(intent=intent, risk=risk)
        ticket = self._ticket_builder.build(
            intent=intent,
            risk=risk,
            decision=decision,
            metadata={
                "route_capability": route.capability_name,
                "route_confidence": route.confidence,
            },
        )
        return RuntimeGovernancePreflightResult(
            intent=intent,
            risk=risk,
            decision=decision,
            ticket=ticket,
        )

    def _derive_action_kind(
        self,
        *,
        prompt: str,
        labels: tuple[str, ...],
    ) -> ActionKind:
        if _contains_any(prompt, self._NETWORK_TERMS) or _contains_any_labels(
            labels,
            ("network", "egress", "remote", "upload"),
        ):
            return ActionKind.NETWORK_EGRESS
        if _contains_any(prompt, self._DESTRUCTIVE_TERMS) or _contains_any_labels(
            labels,
            ("destructive", "delete", "wipe"),
        ):
            return ActionKind.STATE_MUTATION
        return ActionKind.ARTIFACT_EXPORT

    def _derive_risk_profile(
        self,
        *,
        intent: ActionIntent,
        task: TaskRecord,
        route: RoutingDecision,
        prompt: str,
        labels: tuple[str, ...],
        action_kind: ActionKind,
    ) -> ActionRiskProfile:
        risk_level = self._derive_risk_level(
            task=task,
            prompt=prompt,
            labels=labels,
            action_kind=action_kind,
        )
        factors = self._derive_risk_factors(
            task=task,
            route=route,
            action_kind=action_kind,
            risk_level=risk_level,
        )
        requires_approval = risk_level == RiskLevel.HIGH

        return ActionRiskProfile(
            intent_id=intent.intent_id,
            risk_level=risk_level,
            requires_approval=requires_approval,
            factors=tuple(factors),
            tags=_risk_tags(
                task=task,
                route=route,
                action_kind=action_kind,
                risk_level=risk_level,
            ),
        )

    def _derive_risk_level(
        self,
        *,
        task: TaskRecord,
        prompt: str,
        labels: tuple[str, ...],
        action_kind: ActionKind,
    ) -> RiskLevel:
        if action_kind == ActionKind.NETWORK_EGRESS:
            return RiskLevel.CRITICAL
        if action_kind == ActionKind.STATE_MUTATION:
            return RiskLevel.HIGH
        if task.request.kind == TaskKind.OPERATIONS:
            return RiskLevel.HIGH
        if task.request.kind == TaskKind.PROGRAMMING:
            return RiskLevel.MODERATE
        if task.request.input.attachments:
            return RiskLevel.MODERATE
        if _contains_any_labels(labels, ("patching", "code", "runtime")):
            return RiskLevel.MODERATE
        if "patch" in prompt or "code" in prompt or "refactor" in prompt:
            return RiskLevel.MODERATE
        return RiskLevel.LOW

    def _derive_risk_factors(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        action_kind: ActionKind,
        risk_level: RiskLevel,
    ) -> list[RiskFactor]:
        factors: list[RiskFactor] = [
            RiskFactor(
                code=f"route-{route.capability_name}",
                description=(
                    f"Runtime selected the '{route.capability_name}' pack during preflight."
                ),
            ),
            RiskFactor(
                code=f"task-kind-{task.request.kind.value}",
                description=(
                    f"Task kind '{task.request.kind.value}' contributed to preflight risk."
                ),
            ),
        ]

        if action_kind == ActionKind.NETWORK_EGRESS:
            factors.append(
                RiskFactor(
                    code="network-egress-requested",
                    description="Task explicitly requested remote transmission behavior.",
                )
            )
        elif action_kind == ActionKind.STATE_MUTATION:
            factors.append(
                RiskFactor(
                    code="destructive-runtime-request",
                    description="Task includes explicit destructive mutation language.",
                )
            )
        else:
            factors.append(
                RiskFactor(
                    code="planning-only-pack-execution",
                    description=(
                        "Selected pack execution is expected to produce planning artifacts "
                        "rather than direct forge mutation."
                    ),
                )
            )

        if task.request.input.attachments:
            factors.append(
                RiskFactor(
                    code="attachments-present",
                    description="Task includes attachments that expand runtime context.",
                )
            )

        if risk_level == RiskLevel.HIGH:
            factors.append(
                RiskFactor(
                    code="review-sensitive-preflight",
                    description="Preflight classified the runtime action as review-sensitive.",
                )
            )
        elif risk_level == RiskLevel.CRITICAL:
            factors.append(
                RiskFactor(
                    code="critical-preflight-block",
                    description="Preflight classified the runtime action as critically unsafe.",
                )
            )

        return factors


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    normalized = text.strip().lower()
    return any(term in normalized for term in terms)


def _contains_any_labels(labels: tuple[str, ...], terms: tuple[str, ...]) -> bool:
    normalized_labels = {label.strip().lower() for label in labels}
    return any(term in normalized_labels for term in terms)


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


def _risk_tags(
    *,
    task: TaskRecord,
    route: RoutingDecision,
    action_kind: ActionKind,
    risk_level: RiskLevel,
) -> tuple[str, ...]:
    raw_tags = (
        "runtime-preflight",
        f"route-{route.capability_name}",
        f"task-{task.request.kind.value.lower()}",
        f"action-{action_kind.value.lower()}",
        f"risk-{risk_level.value.lower()}",
    )
    return _normalize_labels(raw_tags)
