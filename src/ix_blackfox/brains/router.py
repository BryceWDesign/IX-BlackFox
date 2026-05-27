from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.brains.contracts import BrainCapability, BrainModality
from ix_blackfox.brains.health import (
    BrainBudgetHealthEvaluation,
    BrainBudgetHealthEvaluator,
    BrainProviderHealthRegistry,
)
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.policy import (
    BrainRoutingPolicy,
    BrainRoutingRequest,
    BrainScoreBreakdown,
)
from ix_blackfox.brains.profiles import BrainExecutionProfile
from ix_blackfox.brains.registry import BrainManifestRegistry


@dataclass(frozen=True, slots=True)
class BrainRouteCandidate:
    """
    Inspectable evaluation record for one brain-routing candidate.
    """

    manifest: BrainManifest
    eligible: bool
    score: int
    breakdown: BrainScoreBreakdown = field(default_factory=BrainScoreBreakdown)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    budget_health: BrainBudgetHealthEvaluation | None = None

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable routing-candidate view for evidence reports.
        """
        return {
            "brain_name": self.manifest.brain_name,
            "provider_name": self.manifest.provider_name,
            "model_name": self.manifest.model_name,
            "eligible": self.eligible,
            "score": self.score,
            "breakdown": self.breakdown.to_dict(),
            "reasons": list(self.reasons),
            "budget_health": (
                self.budget_health.to_dict() if self.budget_health is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class BrainRoutingDecision:
    """
    Deterministic routing decision for one brain-selection request.
    """

    request: BrainRoutingRequest
    selected: BrainManifest | None
    candidates: tuple[BrainRouteCandidate, ...]

    @property
    def selected_brain_name(self) -> str | None:
        """
        Return the selected brain name when available.
        """
        if self.selected is None:
            return None
        return self.selected.brain_name

    @property
    def eligible_candidates(self) -> tuple[BrainRouteCandidate, ...]:
        """
        Return only candidates that satisfied routing requirements.
        """
        return tuple(candidate for candidate in self.candidates if candidate.eligible)

    @property
    def rejected_candidates(self) -> tuple[BrainRouteCandidate, ...]:
        """
        Return candidates that were evaluated but not eligible.
        """
        return tuple(candidate for candidate in self.candidates if not candidate.eligible)

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable routing decision for Wave 7 evidence.
        """
        return {
            "request": self.request.to_dict(),
            "selected_brain_name": self.selected_brain_name,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


class BrainRouter:
    """
    Deterministic second-stage router from task requirements to brains.
    """

    def __init__(
        self,
        registry: BrainManifestRegistry,
        *,
        policy: BrainRoutingPolicy | None = None,
        execution_profile: BrainExecutionProfile | None = None,
        provider_health_registry: BrainProviderHealthRegistry | None = None,
        budget_health_evaluator: BrainBudgetHealthEvaluator | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy or BrainRoutingPolicy()
        self._execution_profile = execution_profile or BrainExecutionProfile.local_first()
        self._provider_health_registry = (
            provider_health_registry or BrainProviderHealthRegistry()
        )
        self._budget_health_evaluator = (
            budget_health_evaluator or BrainBudgetHealthEvaluator()
        )

    def route(self, request: BrainRoutingRequest) -> BrainRoutingDecision:
        """
        Evaluate registered manifests and choose the best eligible brain.
        """
        snapshot = self._registry.snapshot()
        candidates = tuple(
            self._evaluate_candidate(manifest, request)
            for manifest in snapshot.manifests
        )
        eligible = [candidate for candidate in candidates if candidate.eligible]
        eligible.sort(
            key=lambda candidate: (
                -candidate.score,
                -int(candidate.manifest.is_default),
                candidate.manifest.brain_name,
            )
        )

        selected = eligible[0].manifest if eligible else None
        ordered_candidates = tuple(
            sorted(
                candidates,
                key=lambda candidate: (
                    -int(candidate.eligible),
                    -candidate.score,
                    -int(candidate.manifest.is_default),
                    candidate.manifest.brain_name,
                ),
            )
        )
        return BrainRoutingDecision(
            request=request,
            selected=selected,
            candidates=ordered_candidates,
        )

    def _evaluate_candidate(
        self,
        manifest: BrainManifest,
        request: BrainRoutingRequest,
    ) -> BrainRouteCandidate:
        reasons: list[str] = []

        if not manifest.supports_role(request.required_role):
            reasons.append(
                f"missing required role: {request.required_role.value}"
            )

        missing_capabilities = _missing_capabilities(manifest, request.required_capabilities)
        for capability in missing_capabilities:
            reasons.append(f"missing required capability: {capability.value}")

        unsupported_modalities = _unsupported_modalities(manifest, request.input_modalities)
        for modality in unsupported_modalities:
            reasons.append(f"unsupported input modality: {modality.value}")

        if reasons:
            return BrainRouteCandidate(
                manifest=manifest,
                eligible=False,
                score=0,
                breakdown=BrainScoreBreakdown(),
                reasons=tuple(reasons),
                budget_health=None,
            )

        breakdown = self._policy.score(manifest, request)
        budget_health = self._budget_health_evaluator.evaluate(
            manifest,
            self._execution_profile,
            provider_health=self._provider_health_registry.get(manifest.provider_name),
        )
        candidate_reasons = tuple(budget_health.reasons)
        eligible = budget_health.eligible
        score = breakdown.total + budget_health.score_adjustment if eligible else 0

        return BrainRouteCandidate(
            manifest=manifest,
            eligible=eligible,
            score=score,
            breakdown=breakdown,
            reasons=candidate_reasons,
            budget_health=budget_health,
        )


def _missing_capabilities(
    manifest: BrainManifest,
    required_capabilities: tuple[BrainCapability, ...],
) -> tuple[BrainCapability, ...]:
    return tuple(
        capability
        for capability in required_capabilities
        if not manifest.declares_capability(capability)
    )


def _unsupported_modalities(
    manifest: BrainManifest,
    input_modalities: tuple[BrainModality, ...],
) -> tuple[BrainModality, ...]:
    return tuple(
        modality for modality in input_modalities if not manifest.accepts_modality(modality)
    )
