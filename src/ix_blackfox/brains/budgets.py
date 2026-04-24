from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto


class BrainLatencyClass(StrEnum):
    """
    Coarse latency intent for a routed inference request.
    """

    INTERACTIVE = auto()
    STANDARD = auto()
    DEEP = auto()


class BrainCostClass(StrEnum):
    """
    Coarse cost tier used to constrain brain selection.
    """

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


@dataclass(frozen=True, slots=True)
class BrainLatencyBudget:
    """
    Latency constraints for a brain invocation.

    Attributes
    ----------
    latency_class:
        Coarse latency intent for the request.
    max_seconds:
        Optional hard upper bound for wall-clock inference time.
    target_seconds:
        Optional soft target for preferred latency.
    """

    latency_class: BrainLatencyClass = BrainLatencyClass.STANDARD
    max_seconds: float | None = None
    target_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.max_seconds is not None and self.max_seconds <= 0:
            raise ValueError("max_seconds must be greater than zero when provided.")
        if self.target_seconds is not None and self.target_seconds <= 0:
            raise ValueError("target_seconds must be greater than zero when provided.")
        if (
            self.max_seconds is not None
            and self.target_seconds is not None
            and self.target_seconds > self.max_seconds
        ):
            raise ValueError("target_seconds must be less than or equal to max_seconds.")


@dataclass(frozen=True, slots=True)
class BrainContextBudget:
    """
    Token-budget constraints for one brain invocation.

    Attributes
    ----------
    max_input_tokens:
        Optional hard cap for routed input tokens.
    max_output_tokens:
        Optional hard cap for produced output tokens.
    reserve_output_tokens:
        Reserved output budget to preserve completion space.
    """

    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    reserve_output_tokens: int = 0

    def __post_init__(self) -> None:
        if self.max_input_tokens is not None and self.max_input_tokens <= 0:
            raise ValueError("max_input_tokens must be greater than zero when provided.")
        if self.max_output_tokens is not None and self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be greater than zero when provided.")
        if self.reserve_output_tokens < 0:
            raise ValueError("reserve_output_tokens must be zero or greater.")
        if (
            self.max_output_tokens is not None
            and self.reserve_output_tokens > self.max_output_tokens
        ):
            raise ValueError(
                "reserve_output_tokens must not exceed max_output_tokens."
            )

    @property
    def effective_output_budget(self) -> int | None:
        """
        Return the usable output budget after reserve allocation.
        """
        if self.max_output_tokens is None:
            return None
        return self.max_output_tokens - self.reserve_output_tokens


@dataclass(frozen=True, slots=True)
class BrainEscalationBudget:
    """
    Escalation constraints that govern deeper or broader routing.

    Attributes
    ----------
    allow_reasoning_escalation:
        Whether heavier reasoning brains may be selected.
    allow_remote_escalation:
        Whether routing may move from local to remote/hybrid execution.
    allow_multimodal_escalation:
        Whether routing may switch into multimodal specialists.
    max_escalation_hops:
        Maximum number of routing escalations permitted for one task.
    """

    allow_reasoning_escalation: bool = True
    allow_remote_escalation: bool = True
    allow_multimodal_escalation: bool = True
    max_escalation_hops: int = 1

    def __post_init__(self) -> None:
        if self.max_escalation_hops < 0:
            raise ValueError("max_escalation_hops must be zero or greater.")


@dataclass(frozen=True, slots=True)
class BrainInferenceBudget:
    """
    Full inference budget used to constrain brain selection and execution.

    Attributes
    ----------
    latency:
        Latency limits for the invocation.
    context:
        Context-window limits for routed work.
    escalation:
        Escalation limits for deeper specialist routing.
    max_cost_class:
        Highest permitted coarse cost tier.
    preferred_cost_class:
        Preferred cost tier when multiple eligible brains exist.
    metadata:
        Structured future-facing budget metadata.
    """

    latency: BrainLatencyBudget = field(default_factory=BrainLatencyBudget)
    context: BrainContextBudget = field(default_factory=BrainContextBudget)
    escalation: BrainEscalationBudget = field(default_factory=BrainEscalationBudget)
    max_cost_class: BrainCostClass = BrainCostClass.HIGH
    preferred_cost_class: BrainCostClass = BrainCostClass.MEDIUM
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.max_cost_class not in _cost_classes_up_to(self.max_cost_class):
            raise ValueError("max_cost_class must be a valid BrainCostClass.")
        if self.preferred_cost_class not in _cost_classes_up_to(BrainCostClass.HIGH):
            raise ValueError("preferred_cost_class must be a valid BrainCostClass.")
        if (
            _cost_rank(self.preferred_cost_class)
            > _cost_rank(self.max_cost_class)
        ):
            raise ValueError(
                "preferred_cost_class must not exceed max_cost_class."
            )

    def allows_cost_class(self, cost_class: BrainCostClass) -> bool:
        """
        Return True when the given cost tier is permitted.
        """
        return _cost_rank(cost_class) <= _cost_rank(self.max_cost_class)

    def prefers_cost_class(self, cost_class: BrainCostClass) -> bool:
        """
        Return True when the given cost tier matches the preferred tier.
        """
        return cost_class is self.preferred_cost_class


def _cost_rank(cost_class: BrainCostClass) -> int:
    order = {
        BrainCostClass.LOW: 1,
        BrainCostClass.MEDIUM: 2,
        BrainCostClass.HIGH: 3,
    }
    return order[cost_class]


def _cost_classes_up_to(cost_class: BrainCostClass) -> tuple[BrainCostClass, ...]:
    limit = _cost_rank(cost_class)
    return tuple(
        item
        for item in (
            BrainCostClass.LOW,
            BrainCostClass.MEDIUM,
            BrainCostClass.HIGH,
        )
        if _cost_rank(item) <= limit
    )
