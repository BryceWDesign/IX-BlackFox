from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.brains.budgets import BrainEscalationBudget


class BrainEscalationTrigger(StrEnum):
    """
    Canonical triggers that can justify escalation into a heavier
    reasoning lane.
    """

    LOW_ROUTE_CONFIDENCE = auto()
    SENTINEL_CONTRADICTION = auto()
    VERIFICATION_FAILURE = auto()
    REPEATED_FAILURES = auto()
    EXPLICIT_DEEP_REASONING_REQUEST = auto()
    POLICY_REVIEW_REQUIRED = auto()


@dataclass(frozen=True, slots=True)
class BrainEscalationReason:
    """
    One inspectable justification for an escalation decision.

    Attributes
    ----------
    trigger:
        Canonical trigger category.
    score:
        Deterministic score contribution from this reason.
    summary:
        Human-readable explanation.
    metadata:
        Optional structured supporting metadata.
    """

    trigger: BrainEscalationTrigger
    score: int
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.score < 0:
            raise ValueError("score must be zero or greater.")
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class BrainEscalationDecision:
    """
    Deterministic result of evaluating escalation policy.

    Attributes
    ----------
    should_escalate:
        Whether the runtime should escalate into a deeper reasoning lane.
    score:
        Total escalation score from matched reasons.
    reasons:
        Inspectable matched reasons in declaration order.
    blocked_by_budget:
        Whether escalation would have happened but was blocked by budget.
    blocked_reason:
        Human-readable explanation when escalation is blocked by budget.
    current_escalation_hops:
        Number of escalation hops already consumed.
    remaining_hops:
        Remaining escalation hops allowed by budget, if known.
    """

    should_escalate: bool
    score: int
    reasons: tuple[BrainEscalationReason, ...] = field(default_factory=tuple)
    blocked_by_budget: bool = False
    blocked_reason: str | None = None
    current_escalation_hops: int = 0
    remaining_hops: int | None = None

    def __post_init__(self) -> None:
        if self.score < 0:
            raise ValueError("score must be zero or greater.")
        if self.current_escalation_hops < 0:
            raise ValueError("current_escalation_hops must be zero or greater.")
        if self.remaining_hops is not None and self.remaining_hops < 0:
            raise ValueError("remaining_hops must be zero or greater when provided.")
        object.__setattr__(
            self,
            "blocked_reason",
            _normalize_optional_text(self.blocked_reason),
        )
        if self.should_escalate and self.blocked_by_budget:
            raise ValueError("Escalation decisions cannot both escalate and be blocked.")

    def trigger_codes(self) -> tuple[str, ...]:
        """
        Return matched escalation trigger codes in declaration order.
        """
        return tuple(reason.trigger.value for reason in self.reasons)

    @property
    def has_reasons(self) -> bool:
        """
        Return True when one or more escalation reasons were matched.
        """
        return bool(self.reasons)


@dataclass(frozen=True, slots=True)
class BrainEscalationPolicy:
    """
    Deterministic scoring policy for reasoning escalation.

    The policy answers one bounded question:
    should BlackFox move from a normal execution lane into a heavier
    reasoning lane for this task attempt?
    """

    route_confidence_threshold: float = 0.60
    repeated_failure_threshold: int = 2
    minimum_score_to_escalate: int = 50
    low_route_confidence_score: int = 30
    sentinel_contradiction_score: int = 35
    verification_failure_score: int = 35
    repeated_failures_score: int = 30
    explicit_request_score: int = 60
    policy_review_required_score: int = 15

    def __post_init__(self) -> None:
        if not 0.0 <= self.route_confidence_threshold <= 1.0:
            raise ValueError("route_confidence_threshold must be between 0.0 and 1.0.")
        if self.repeated_failure_threshold < 1:
            raise ValueError("repeated_failure_threshold must be at least 1.")
        if self.minimum_score_to_escalate < 1:
            raise ValueError("minimum_score_to_escalate must be at least 1.")
        for field_name in (
            "low_route_confidence_score",
            "sentinel_contradiction_score",
            "verification_failure_score",
            "repeated_failures_score",
            "explicit_request_score",
            "policy_review_required_score",
        ):
            value = getattr(self, field_name)
            if value < 0:
                raise ValueError(f"{field_name} must be zero or greater.")

    def evaluate(
        self,
        *,
        route_confidence: float | None = None,
        contradiction_detected: bool = False,
        verification_failed: bool = False,
        repeated_failures: int = 0,
        explicit_deep_reasoning: bool = False,
        approval_required: bool = False,
        budget: BrainEscalationBudget | None = None,
        current_escalation_hops: int = 0,
    ) -> BrainEscalationDecision:
        """
        Evaluate whether deeper reasoning escalation is justified.
        """
        if route_confidence is not None and not 0.0 <= route_confidence <= 1.0:
            raise ValueError("route_confidence must be between 0.0 and 1.0 when provided.")
        if repeated_failures < 0:
            raise ValueError("repeated_failures must be zero or greater.")
        if current_escalation_hops < 0:
            raise ValueError("current_escalation_hops must be zero or greater.")

        reasons: list[BrainEscalationReason] = []

        if (
            route_confidence is not None
            and route_confidence < self.route_confidence_threshold
        ):
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.LOW_ROUTE_CONFIDENCE,
                    score=self.low_route_confidence_score,
                    summary=(
                        f"Route confidence {route_confidence:.2f} fell below the "
                        f"escalation threshold {self.route_confidence_threshold:.2f}."
                    ),
                    metadata={
                        "route_confidence": route_confidence,
                        "threshold": self.route_confidence_threshold,
                    },
                )
            )

        if contradiction_detected:
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.SENTINEL_CONTRADICTION,
                    score=self.sentinel_contradiction_score,
                    summary=(
                        "Sentinel contradiction signals justified deeper reasoning review."
                    ),
                )
            )

        if verification_failed:
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.VERIFICATION_FAILURE,
                    score=self.verification_failure_score,
                    summary=(
                        "Verification failure justified escalation into a stronger reasoning lane."
                    ),
                )
            )

        if repeated_failures >= self.repeated_failure_threshold:
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.REPEATED_FAILURES,
                    score=self.repeated_failures_score,
                    summary=(
                        f"Repeated failures reached {repeated_failures}, meeting or exceeding "
                        f"the escalation threshold {self.repeated_failure_threshold}."
                    ),
                    metadata={
                        "repeated_failures": repeated_failures,
                        "threshold": self.repeated_failure_threshold,
                    },
                )
            )

        if explicit_deep_reasoning:
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.EXPLICIT_DEEP_REASONING_REQUEST,
                    score=self.explicit_request_score,
                    summary="The task explicitly requested deeper reasoning.",
                )
            )

        if approval_required:
            reasons.append(
                BrainEscalationReason(
                    trigger=BrainEscalationTrigger.POLICY_REVIEW_REQUIRED,
                    score=self.policy_review_required_score,
                    summary="Governance review requirements increased reasoning scrutiny.",
                )
            )

        score = sum(reason.score for reason in reasons)
        remaining_hops = None
        blocked_by_budget = False
        blocked_reason = None

        if budget is not None:
            remaining_hops = max(
                0,
                budget.max_escalation_hops - current_escalation_hops,
            )
            if not budget.allow_reasoning_escalation:
                blocked_by_budget = True
                blocked_reason = "Escalation budget disabled reasoning escalation."
            elif current_escalation_hops >= budget.max_escalation_hops:
                blocked_by_budget = True
                blocked_reason = "Escalation hop budget is exhausted."

        should_escalate = bool(reasons) and score >= self.minimum_score_to_escalate
        if blocked_by_budget:
            should_escalate = False

        return BrainEscalationDecision(
            should_escalate=should_escalate,
            score=score,
            reasons=tuple(reasons),
            blocked_by_budget=blocked_by_budget,
            blocked_reason=blocked_reason,
            current_escalation_hops=current_escalation_hops,
            remaining_hops=remaining_hops,
        )


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
