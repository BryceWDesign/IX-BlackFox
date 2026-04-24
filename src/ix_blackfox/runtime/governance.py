from __future__ import annotations

from dataclasses import dataclass

from ix_blackfox.brains import (
    SafeguardAssessment,
    SafeguardDisposition,
    SafeguardFinding,
)
from ix_blackfox.forge import ForgeExecutionTicket, ForgeExecutionTicketBuilder
from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    GovernancePolicy,
    GovernanceSafetyMerge,
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
    safeguard_assessment: SafeguardAssessment | None = None

    @property
    def blocked(self) -> bool:
        return self.decision.decision.value == "block"

    @property
    def requires_review(self) -> bool:
        return self.decision.decision.value == "require_review"

    def to_dict(self) -> dict[str, object]:
        safeguard = None
        if self.safeguard_assessment is not None:
            safeguard = {
                "brain_name": self.safeguard_assessment.brain_name,
                "invocation_id": self.safeguard_assessment.invocation_id,
                "advisory_disposition": self.safeguard_assessment.advisory_disposition.value,
                "highest_severity": None
                if self.safeguard_assessment.highest_severity is None
                else self.safeguard_assessment.highest_severity.value,
                "finding_codes": self.safeguard_assessment.finding_codes(),
                "policy_tags": self.safeguard_assessment.policy_tags(),
                "metadata": self.safeguard_assessment.metadata,
            }

        safety_merge = None
        if self.risk.safety_merge is not None:
            safety_merge = {
                "advisory_disposition": self.risk.safety_merge.advisory_disposition.value,
                "finding_count": self.risk.safety_merge.finding_count,
                "finding_codes": self.risk.safety_merge.finding_codes,
                "policy_tags": self.risk.safety_merge.policy_tags,
                "highest_severity": None
                if self.risk.safety_merge.highest_severity is None
                else self.risk.safety_merge.highest_severity.value,
                "original_risk_level": None
                if self.risk.safety_merge.original_risk_level is None
                else self.risk.safety_merge.original_risk_level.value,
                "merged_risk_level": None
                if self.risk.safety_merge.merged_risk_level is None
                else self.risk.safety_merge.merged_risk_level.value,
                "elevated_risk": self.risk.safety_merge.elevated_risk,
                "forced_review": self.risk.safety_merge.forced_review,
                "rationale": self.risk.safety_merge.rationale,
            }

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
                "safety_merge": safety_merge,
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
            "safeguard_assessment": safeguard,
        }


class RuntimeGovernancePreflightEngine:
    """
    Deterministic preflight governance for runtime task execution.

    The preflight step governs pack execution intent before any pack is
    loaded or executed. It does not replace later forge governance. It
    establishes whether the runtime should proceed, warn for review, or
    block outright based on explicit task signals.

    Semantic safeguard evidence may raise governance scrutiny, but it
    does not replace deterministic policy authority.
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
        safeguard_assessment: SafeguardAssessment | None = None,
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
                "safeguard_present": safeguard_assessment is not None,
            },
        )
        risk = self._derive_risk_profile(
            intent=intent,
            task=task,
            route=route,
            prompt=prompt,
            labels=labels,
            action_kind=action_kind,
            safeguard_assessment=safeguard_assessment,
        )
        decision = self._policy.evaluate(intent=intent, risk=risk)
        ticket = self._ticket_builder.build(
            intent=intent,
            risk=risk,
            decision=decision,
            metadata={
                "route_capability": route.capability_name,
                "route_confidence": route.confidence,
                "safeguard_disposition": None
                if safeguard_assessment is None
                else safeguard_assessment.advisory_disposition.value,
            },
        )
        return RuntimeGovernancePreflightResult(
            intent=intent,
            risk=risk,
            decision=decision,
            ticket=ticket,
            safeguard_assessment=safeguard_assessment,
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
        safeguard_assessment: SafeguardAssessment | None,
    ) -> ActionRiskProfile:
        base_risk_level = self._derive_risk_level(
            task=task,
            prompt=prompt,
            labels=labels,
            action_kind=action_kind,
        )
        factors = self._derive_risk_factors(
            task=task,
            route=route,
            action_kind=action_kind,
            risk_level=base_risk_level,
        )
        requires_approval = base_risk_level == RiskLevel.HIGH
        safety_merge = _merge_safeguard_assessment(
            risk_level=base_risk_level,
            safeguard_assessment=safeguard_assessment,
        )

        merged_risk_level = (
            base_risk_level
            if safety_merge is None or safety_merge.merged_risk_level is None
            else safety_merge.merged_risk_level
        )
        merged_requires_approval = requires_approval or (
            False if safety_merge is None else safety_merge.forced_review
        )
        merged_factors = tuple(
            factors + _safeguard_risk_factors(safeguard_assessment=safeguard_assessment)
        )

        return ActionRiskProfile(
            intent_id=intent.intent_id,
            risk_level=merged_risk_level,
            requires_approval=merged_requires_approval,
            factors=merged_factors,
            tags=_risk_tags(
                task=task,
                route=route,
                action_kind=action_kind,
                risk_level=merged_risk_level,
                safety_merge=safety_merge,
            ),
            safety_merge=safety_merge,
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


def _merge_safeguard_assessment(
    *,
    risk_level: RiskLevel,
    safeguard_assessment: SafeguardAssessment | None,
) -> GovernanceSafetyMerge | None:
    if safeguard_assessment is None:
        return None

    findings = safeguard_assessment.findings
    if not findings and safeguard_assessment.advisory_disposition is SafeguardDisposition.ALLOW:
        return GovernanceSafetyMerge(
            advisory_disposition=SafeguardDisposition.ALLOW,
            finding_count=0,
            original_risk_level=risk_level,
            merged_risk_level=risk_level,
            elevated_risk=False,
            forced_review=False,
            rationale="No safeguard findings were present, so governance risk was unchanged.",
        )

    merged_risk = risk_level
    forced_review = False

    if safeguard_assessment.advisory_disposition is SafeguardDisposition.REVIEW:
        merged_risk = _max_risk_level(risk_level, RiskLevel.HIGH)
        forced_review = True
    elif safeguard_assessment.advisory_disposition is SafeguardDisposition.BLOCK:
        merged_risk = _max_risk_level(risk_level, RiskLevel.HIGH)
        forced_review = True

    elevated_risk = _risk_rank(merged_risk) > _risk_rank(risk_level)
    highest_severity = safeguard_assessment.highest_severity

    if elevated_risk:
        rationale = (
            f"Safeguard disposition '{safeguard_assessment.advisory_disposition.value}' "
            f"elevated governance risk from {risk_level.value} to {merged_risk.value}."
        )
    elif forced_review:
        rationale = (
            f"Safeguard disposition '{safeguard_assessment.advisory_disposition.value}' "
            "did not raise the risk tier further but still forced review semantics."
        )
    else:
        rationale = (
            "Safeguard findings were recorded, but deterministic governance risk was unchanged."
        )

    return GovernanceSafetyMerge(
        advisory_disposition=safeguard_assessment.advisory_disposition,
        finding_count=len(findings),
        finding_codes=safeguard_assessment.finding_codes(),
        policy_tags=safeguard_assessment.policy_tags(),
        highest_severity=highest_severity,
        original_risk_level=risk_level,
        merged_risk_level=merged_risk,
        elevated_risk=elevated_risk,
        forced_review=forced_review,
        rationale=rationale,
    )


def _safeguard_risk_factors(
    *,
    safeguard_assessment: SafeguardAssessment | None,
) -> list[RiskFactor]:
    if safeguard_assessment is None:
        return []

    factors: list[RiskFactor] = []
    if safeguard_assessment.findings:
        factors.append(
            RiskFactor(
                code=f"safeguard-disposition-{safeguard_assessment.advisory_disposition.value}",
                description=(
                    f"Safeguard advisory disposition was "
                    f"'{safeguard_assessment.advisory_disposition.value}'."
                ),
            )
        )
        for finding in safeguard_assessment.findings:
            factors.append(_finding_to_factor(finding))
    return factors


def _finding_to_factor(finding: SafeguardFinding) -> RiskFactor:
    return RiskFactor(
        code=f"safeguard-{finding.code}",
        description=(
            f"Safeguard finding '{finding.code}' "
            f"({finding.severity.value}) recommended semantic scrutiny."
        ),
    )


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
    safety_merge: GovernanceSafetyMerge | None,
) -> tuple[str, ...]:
    extra_tags: tuple[str, ...] = ()
    if safety_merge is not None and safety_merge.has_findings():
        extra_tags = (
            f"safeguard-{safety_merge.advisory_disposition.value}",
            *safety_merge.policy_tags,
        )

    raw_tags = (
        "runtime-preflight",
        f"route-{route.capability_name}",
        f"task-{task.request.kind.value.lower()}",
        f"action-{action_kind.value.lower()}",
        f"risk-{risk_level.value.lower()}",
        *extra_tags,
    )
    return _normalize_labels(raw_tags)


def _max_risk_level(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _risk_rank(left) >= _risk_rank(right) else right


def _risk_rank(level: RiskLevel) -> int:
    order = {
        RiskLevel.LOW: 1,
        RiskLevel.MODERATE: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[level]
