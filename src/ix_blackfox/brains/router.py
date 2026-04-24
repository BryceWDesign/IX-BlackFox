from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.brains.contracts import BrainCapability, BrainModality
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.policy import (
    BrainRoutingPolicy,
    BrainRoutingRequest,
    BrainScoreBreakdown,
)
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


class BrainRouter:
    """
    Deterministic second-stage router from task requirements to brains.
    """

    def __init__(
        self,
        registry: BrainManifestRegistry,
        *,
        policy: BrainRoutingPolicy | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy or BrainRoutingPolicy()

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
            )

        breakdown = self._policy.score(manifest, request)
        return BrainRouteCandidate(
            manifest=manifest,
            eligible=True,
            score=breakdown.total,
            breakdown=breakdown,
            reasons=(),
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
