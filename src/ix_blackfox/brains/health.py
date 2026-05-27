from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.brains.budgets import BrainCostClass, BrainInferenceBudget
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.profiles import BrainExecutionProfile


class BrainProviderHealthStatus(StrEnum):
    """
    Operator-visible provider health state used before model routing.
    """

    HEALTHY = auto()
    DEGRADED = auto()
    UNAVAILABLE = auto()
    DISABLED = auto()


class BrainProviderTopology(StrEnum):
    """
    Execution topology for a model provider.
    """

    LOCAL = auto()
    REMOTE = auto()


@dataclass(frozen=True, slots=True)
class BrainProviderHealth:
    """
    Provider health snapshot used by Wave 7 budget-aware routing.

    This object does not invoke a model or assert that a provider is safe. It
    records the operator/runtime evidence available to the router so provider
    availability, locality, cost, latency, and token capacity are inspectable.
    """

    provider_name: str
    status: BrainProviderHealthStatus = BrainProviderHealthStatus.HEALTHY
    topology: BrainProviderTopology = BrainProviderTopology.LOCAL
    cost_class: BrainCostClass = BrainCostClass.MEDIUM
    observed_latency_seconds: float | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def assumed_healthy(cls, provider_name: str) -> BrainProviderHealth:
        """
        Build a permissive fallback when no explicit health snapshot exists.

        Existing Wave 6 behavior should not fail just because Wave 7 health
        telemetry has not been configured yet. The fallback remains explicit in
        evidence by carrying an assumption reason.
        """
        return cls(
            provider_name=provider_name,
            status=BrainProviderHealthStatus.HEALTHY,
            reasons=("no provider health snapshot supplied",),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        if self.observed_latency_seconds is not None and self.observed_latency_seconds <= 0:
            raise ValueError(
                "observed_latency_seconds must be greater than zero when provided."
            )
        if self.max_input_tokens is not None and self.max_input_tokens <= 0:
            raise ValueError("max_input_tokens must be greater than zero when provided.")
        if self.max_output_tokens is not None and self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be greater than zero when provided.")
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def available(self) -> bool:
        """
        Return whether the provider is eligible for routing consideration.
        """
        return self.status in (
            BrainProviderHealthStatus.HEALTHY,
            BrainProviderHealthStatus.DEGRADED,
        )

    @property
    def remote(self) -> bool:
        """
        Return True when this provider requires remote execution authority.
        """
        return self.topology is BrainProviderTopology.REMOTE

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable health snapshot.
        """
        return {
            "provider_name": self.provider_name,
            "status": self.status.value,
            "topology": self.topology.value,
            "cost_class": self.cost_class.value,
            "observed_latency_seconds": self.observed_latency_seconds,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "reasons": list(self.reasons),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainProviderHealthRegistry:
    """
    Immutable lookup table of provider health snapshots.
    """

    providers: tuple[BrainProviderHealth, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized: list[BrainProviderHealth] = []
        names: set[str] = set()
        for provider in self.providers:
            if provider.provider_name in names:
                raise ValueError(
                    f"Duplicate provider health snapshot: {provider.provider_name}."
                )
            normalized.append(provider)
            names.add(provider.provider_name)
        object.__setattr__(self, "providers", tuple(normalized))

    def get(self, provider_name: str) -> BrainProviderHealth:
        """
        Return an explicit provider health snapshot or an assumed healthy fallback.
        """
        normalized_name = _normalize_identifier(provider_name, label="provider_name")
        for provider in self.providers:
            if provider.provider_name == normalized_name:
                return provider
        return BrainProviderHealth.assumed_healthy(normalized_name)

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable registry view.
        """
        return {"providers": [provider.to_dict() for provider in self.providers]}


@dataclass(frozen=True, slots=True)
class BrainBudgetHealthEvaluation:
    """
    Budget and health evaluation for one manifest before final routing.
    """

    brain_name: str
    provider_name: str
    eligible: bool
    score_adjustment: int
    health: BrainProviderHealth
    reasons: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "brain_name",
            _normalize_identifier(self.brain_name, label="brain_name"),
        )
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        object.__setattr__(self, "warnings", _normalize_text_tuple(self.warnings))
        if not self.eligible and not self.reasons:
            raise ValueError("ineligible budget health evaluations must include reasons.")

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable evaluation view for routing receipts.
        """
        return {
            "brain_name": self.brain_name,
            "provider_name": self.provider_name,
            "eligible": self.eligible,
            "score_adjustment": self.score_adjustment,
            "health": self.health.to_dict(),
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


class BrainBudgetHealthEvaluator:
    """
    Deterministic provider-health and budget evaluator for Wave 7 routing.
    """

    def evaluate(
        self,
        manifest: BrainManifest,
        execution_profile: BrainExecutionProfile,
        *,
        provider_health: BrainProviderHealth | None = None,
        budget: BrainInferenceBudget | None = None,
    ) -> BrainBudgetHealthEvaluation:
        """
        Evaluate one manifest against provider health and execution budget.
        """
        active_budget = budget or execution_profile.budget
        health = provider_health or BrainProviderHealth.assumed_healthy(
            manifest.provider_name
        )
        reasons: list[str] = []
        warnings: list[str] = []

        _evaluate_provider_allowlist(
            manifest=manifest,
            execution_profile=execution_profile,
            reasons=reasons,
        )
        _evaluate_provider_health(health=health, reasons=reasons, warnings=warnings)
        _evaluate_provider_topology(
            health=health,
            execution_profile=execution_profile,
            budget=active_budget,
            reasons=reasons,
        )
        _evaluate_provider_cost(
            health=health,
            budget=active_budget,
            reasons=reasons,
            warnings=warnings,
        )
        _evaluate_latency(
            health=health,
            budget=active_budget,
            warnings=warnings,
            reasons=reasons,
        )
        _evaluate_context_capacity(
            manifest=manifest,
            health=health,
            budget=active_budget,
            reasons=reasons,
        )

        eligible = not reasons
        return BrainBudgetHealthEvaluation(
            brain_name=manifest.brain_name,
            provider_name=manifest.provider_name,
            eligible=eligible,
            score_adjustment=_score_adjustment(
                health=health,
                execution_profile=execution_profile,
                budget=active_budget,
                eligible=eligible,
                warnings=tuple(warnings),
            ),
            health=health,
            reasons=tuple(reasons),
            warnings=tuple(warnings),
        )


def _evaluate_provider_allowlist(
    *,
    manifest: BrainManifest,
    execution_profile: BrainExecutionProfile,
    reasons: list[str],
) -> None:
    if not execution_profile.permits_provider(manifest.provider_name):
        reasons.append(f"provider is not allowed: {manifest.provider_name}")


def _evaluate_provider_health(
    *,
    health: BrainProviderHealth,
    reasons: list[str],
    warnings: list[str],
) -> None:
    if health.status is BrainProviderHealthStatus.DISABLED:
        reasons.append(f"provider is disabled: {health.provider_name}")
        return
    if health.status is BrainProviderHealthStatus.UNAVAILABLE:
        reasons.append(f"provider is unavailable: {health.provider_name}")
        return
    if health.status is BrainProviderHealthStatus.DEGRADED:
        warnings.append(f"provider is degraded: {health.provider_name}")


def _evaluate_provider_topology(
    *,
    health: BrainProviderHealth,
    execution_profile: BrainExecutionProfile,
    budget: BrainInferenceBudget,
    reasons: list[str],
) -> None:
    if health.remote and not execution_profile.allow_remote:
        reasons.append(f"remote provider is not allowed: {health.provider_name}")
    if not health.remote and not execution_profile.allow_local:
        reasons.append(f"local provider is not allowed: {health.provider_name}")
    if health.remote and not budget.escalation.allow_remote_escalation:
        reasons.append(f"remote escalation is not allowed: {health.provider_name}")


def _evaluate_provider_cost(
    *,
    health: BrainProviderHealth,
    budget: BrainInferenceBudget,
    reasons: list[str],
    warnings: list[str],
) -> None:
    if not budget.allows_cost_class(health.cost_class):
        reasons.append(
            "provider cost class exceeds budget: "
            f"{health.provider_name}={health.cost_class.value}"
        )
        return
    if not budget.prefers_cost_class(health.cost_class):
        warnings.append(
            "provider cost class is allowed but not preferred: "
            f"{health.provider_name}={health.cost_class.value}"
        )


def _evaluate_latency(
    *,
    health: BrainProviderHealth,
    budget: BrainInferenceBudget,
    warnings: list[str],
    reasons: list[str],
) -> None:
    observed = health.observed_latency_seconds
    if observed is None:
        warnings.append(f"provider latency is unknown: {health.provider_name}")
        return
    if budget.latency.max_seconds is not None and observed > budget.latency.max_seconds:
        reasons.append(
            "provider observed latency exceeds budget: "
            f"{health.provider_name}={observed:.3f}s"
        )
        return
    if (
        budget.latency.target_seconds is not None
        and observed > budget.latency.target_seconds
    ):
        warnings.append(
            "provider observed latency exceeds target: "
            f"{health.provider_name}={observed:.3f}s"
        )


def _evaluate_context_capacity(
    *,
    manifest: BrainManifest,
    health: BrainProviderHealth,
    budget: BrainInferenceBudget,
    reasons: list[str],
) -> None:
    declared_context = manifest.profile.context_window
    effective_input_capacity = min(
        declared_context.max_input_tokens,
        health.max_input_tokens or declared_context.max_input_tokens,
    )
    effective_output_capacity = min(
        declared_context.max_output_tokens,
        health.max_output_tokens or declared_context.max_output_tokens,
    )

    if (
        budget.context.max_input_tokens is not None
        and budget.context.max_input_tokens > effective_input_capacity
    ):
        reasons.append(
            "input token budget exceeds provider capacity: "
            f"{budget.context.max_input_tokens}>{effective_input_capacity}"
        )
    if (
        budget.context.max_output_tokens is not None
        and budget.context.max_output_tokens > effective_output_capacity
    ):
        reasons.append(
            "output token budget exceeds provider capacity: "
            f"{budget.context.max_output_tokens}>{effective_output_capacity}"
        )


def _score_adjustment(
    *,
    health: BrainProviderHealth,
    execution_profile: BrainExecutionProfile,
    budget: BrainInferenceBudget,
    eligible: bool,
    warnings: tuple[str, ...],
) -> int:
    if not eligible:
        return 0

    score = 0
    if health.status is BrainProviderHealthStatus.HEALTHY:
        score += 30
    elif health.status is BrainProviderHealthStatus.DEGRADED:
        score += 10

    if execution_profile.prefers_provider(health.provider_name):
        score += 20
    if budget.prefers_cost_class(health.cost_class):
        score += 15
    elif budget.allows_cost_class(health.cost_class):
        score += 5

    if health.observed_latency_seconds is not None:
        if (
            budget.latency.target_seconds is not None
            and health.observed_latency_seconds <= budget.latency.target_seconds
        ):
            score += 15
        elif (
            budget.latency.max_seconds is not None
            and health.observed_latency_seconds <= budget.latency.max_seconds
        ):
            score += 5

    return max(score - (2 * len(warnings)), 0)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
