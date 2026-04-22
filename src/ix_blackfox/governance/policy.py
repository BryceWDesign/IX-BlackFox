from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto

from ix_blackfox.governance.models import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    RiskLevel,
)


class PolicyDecisionType(StrEnum):
    """
    Canonical governance outcomes for one proposed action.
    """

    ALLOW = auto()
    REQUIRE_REVIEW = auto()
    BLOCK = auto()


class PolicyDecisionReason(StrEnum):
    """
    Stable reason codes for governance decisions.
    """

    LOW_RISK_DEFAULT = auto()
    MODERATE_RISK_DEFAULT = auto()
    APPROVAL_REQUIRED = auto()
    HIGH_RISK_REQUIRES_REVIEW = auto()
    CRITICAL_RISK_BLOCKED = auto()
    ACTION_KIND_BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """
    Immutable result of evaluating one action intent against policy.

    Attributes
    ----------
    intent_id:
        Normalized action-intent identifier.
    decision:
        Final governance outcome.
    reason:
        Stable reason code for the decision.
    rationale:
        Human-readable explanation of why the decision was made.
    decided_at:
        UTC timestamp when the decision was produced.
    matched_rules:
        Optional normalized rule labels that influenced the decision.
    """

    intent_id: str
    decision: PolicyDecisionType
    reason: PolicyDecisionReason
    rationale: str
    decided_at: datetime
    matched_rules: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_intent_id = _normalize_identifier(self.intent_id, label="intent_id")
        normalized_rationale = self.rationale.strip()
        if not normalized_rationale:
            raise ValueError("Policy decision rationale must not be empty.")

        object.__setattr__(self, "intent_id", normalized_intent_id)
        object.__setattr__(self, "rationale", normalized_rationale)
        object.__setattr__(self, "matched_rules", _normalize_labels(self.matched_rules))


@dataclass(frozen=True, slots=True)
class GovernancePolicy:
    """
    Deterministic governance policy for action-intent evaluation.

    The initial policy model is intentionally simple and explicit:
    - explicitly blocked action kinds are always blocked
    - CRITICAL risk is always blocked
    - HIGH risk requires review
    - any profile marked requires_approval requires review
    - LOW and MODERATE risk are allowed by default

    This policy object is designed to remain deterministic so later
    approval and receipt subsystems can rely on stable semantics.
    """

    blocked_action_kinds: tuple[ActionKind, ...] = field(
        default_factory=lambda: (ActionKind.NETWORK_EGRESS,)
    )
    allow_moderate_risk_by_default: bool = True

    def evaluate(
        self,
        *,
        intent: ActionIntent,
        risk: ActionRiskProfile,
    ) -> PolicyDecision:
        """
        Evaluate one action intent against governance policy.
        """
        normalized_intent_id = _normalize_identifier(intent.intent_id, label="intent_id")
        if normalized_intent_id != risk.intent_id:
            raise ValueError(
                "Action intent and action risk profile must reference the same intent_id."
            )

        if intent.action_kind in self.blocked_action_kinds:
            return PolicyDecision(
                intent_id=normalized_intent_id,
                decision=PolicyDecisionType.BLOCK,
                reason=PolicyDecisionReason.ACTION_KIND_BLOCKED,
                rationale=(
                    f"Action kind '{intent.action_kind.value}' is blocked by governance "
                    "policy."
                ),
                decided_at=_utc_now(),
                matched_rules=("blocked-action-kind", intent.action_kind.value),
            )

        if risk.risk_level == RiskLevel.CRITICAL:
            return PolicyDecision(
                intent_id=normalized_intent_id,
                decision=PolicyDecisionType.BLOCK,
                reason=PolicyDecisionReason.CRITICAL_RISK_BLOCKED,
                rationale="Critical-risk actions are blocked by default governance policy.",
                decided_at=_utc_now(),
                matched_rules=("critical-risk-block",),
            )

        if risk.risk_level == RiskLevel.HIGH:
            return PolicyDecision(
                intent_id=normalized_intent_id,
                decision=PolicyDecisionType.REQUIRE_REVIEW,
                reason=PolicyDecisionReason.HIGH_RISK_REQUIRES_REVIEW,
                rationale="High-risk actions require governance review before execution.",
                decided_at=_utc_now(),
                matched_rules=("high-risk-review",),
            )

        if risk.requires_approval:
            return PolicyDecision(
                intent_id=normalized_intent_id,
                decision=PolicyDecisionType.REQUIRE_REVIEW,
                reason=PolicyDecisionReason.APPROVAL_REQUIRED,
                rationale=(
                    "Action risk profile explicitly requires approval before execution."
                ),
                decided_at=_utc_now(),
                matched_rules=("explicit-approval-required",),
            )

        if risk.risk_level == RiskLevel.MODERATE and self.allow_moderate_risk_by_default:
            return PolicyDecision(
                intent_id=normalized_intent_id,
                decision=PolicyDecisionType.ALLOW,
                reason=PolicyDecisionReason.MODERATE_RISK_DEFAULT,
                rationale="Moderate-risk action is allowed by default governance policy.",
                decided_at=_utc_now(),
                matched_rules=("moderate-risk-default",),
            )

        return PolicyDecision(
            intent_id=normalized_intent_id,
            decision=PolicyDecisionType.ALLOW,
            reason=PolicyDecisionReason.LOW_RISK_DEFAULT,
            rationale="Low-risk action is allowed by default governance policy.",
            decided_at=_utc_now(),
            matched_rules=("low-risk-default",),
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_labels(labels: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_label in labels:
        cleaned = raw_label.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
