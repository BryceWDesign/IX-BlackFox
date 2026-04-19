from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto

from ix_blackfox.kernel import TaskKind, TaskRequest


class RoutingDecisionReason(StrEnum):
    """
    Canonical reasons for a switchboard routing outcome.
    """

    EXACT_KIND_MATCH = auto()
    LABEL_MATCH = auto()
    FALLBACK = auto()
    NO_MATCH = auto()


@dataclass(frozen=True, slots=True)
class CapabilityRoute:
    """
    A route describing which internal capability can handle a task.

    Attributes
    ----------
    capability_name:
        Stable internal capability identifier.
    supported_kinds:
        Task kinds this capability explicitly supports.
    labels:
        Optional routing labels associated with the capability.
    description:
        Human-readable capability summary.
    is_fallback:
        Whether this capability can serve as a fallback route.
    """

    capability_name: str
    supported_kinds: tuple[TaskKind, ...] = field(default_factory=tuple)
    labels: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""
    is_fallback: bool = False

    def __post_init__(self) -> None:
        normalized_name = self.capability_name.strip().lower()
        if not normalized_name:
            raise ValueError("Capability name must not be empty.")

        normalized_labels = _normalize_labels(self.labels)
        normalized_description = self.description.strip()

        object.__setattr__(self, "capability_name", normalized_name)
        object.__setattr__(self, "labels", normalized_labels)
        object.__setattr__(self, "description", normalized_description)


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """
    Switchboard routing result.

    Attributes
    ----------
    capability_name:
        Selected internal capability identifier.
    confidence:
        Simple normalized routing confidence from 0.0 to 1.0.
    reason:
        Reason category for the decision.
    task_id:
        Task identifier associated with the decision.
    matched_labels:
        Labels that contributed to the decision, if any.
    """

    capability_name: str
    confidence: float
    reason: RoutingDecisionReason
    task_id: str
    matched_labels: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_name = self.capability_name.strip().lower()
        if not normalized_name:
            raise ValueError("Routing decision capability name must not be empty.")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Routing decision confidence must be between 0.0 and 1.0.")

        object.__setattr__(self, "capability_name", normalized_name)
        object.__setattr__(self, "matched_labels", _normalize_labels(self.matched_labels))


def score_route(route: CapabilityRoute, task: TaskRequest) -> RoutingDecision | None:
    """
    Score a route against a task request.

    The current scoring model is intentionally simple and deterministic:
    exact kind matches win, then label matches, then fallback routes.
    """
    if task.kind in route.supported_kinds:
        return RoutingDecision(
            capability_name=route.capability_name,
            confidence=1.0,
            reason=RoutingDecisionReason.EXACT_KIND_MATCH,
            task_id=task.task_id,
        )

    matched_labels = tuple(label for label in task.labels if label in route.labels)
    if matched_labels:
        return RoutingDecision(
            capability_name=route.capability_name,
            confidence=_label_confidence(
                matched_count=len(matched_labels),
                total_route_labels=len(route.labels),
            ),
            reason=RoutingDecisionReason.LABEL_MATCH,
            task_id=task.task_id,
            matched_labels=matched_labels,
        )

    if route.is_fallback:
        return RoutingDecision(
            capability_name=route.capability_name,
            confidence=0.25,
            reason=RoutingDecisionReason.FALLBACK,
            task_id=task.task_id,
        )

    return None


def _label_confidence(*, matched_count: int, total_route_labels: int) -> float:
    if total_route_labels <= 0:
        return 0.5
    confidence = matched_count / total_route_labels
    return max(0.35, min(confidence, 0.95))


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
