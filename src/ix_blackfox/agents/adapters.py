from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ix_blackfox.agents.capabilities import (
    capability_default_risk_tier,
    capability_requires_human_review,
)
from ix_blackfox.agents.models import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentTrustTier,
)
from ix_blackfox.agents.registry import AgentRegistry, build_agent_registry
from ix_blackfox.brains.contracts import BrainCapability
from ix_blackfox.brains.manifest import BrainManifest, BrainManifestSnapshot
from ix_blackfox.operating.models import OperatingDomain, normalize_identifier


_BRAIN_CAPABILITY_MAP: dict[BrainCapability, tuple[AgentCapability, ...]] = {
    BrainCapability.TEXT_GENERATION: (AgentCapability.PROPOSE_PATCH,),
    BrainCapability.CODE_GENERATION: (AgentCapability.PROPOSE_PATCH,),
    BrainCapability.STRUCTURED_OUTPUT: (AgentCapability.INSPECT_POLICY,),
    BrainCapability.SAFETY_CLASSIFICATION: (AgentCapability.REVIEW_PATCH,),
    BrainCapability.TOOL_PLANNING: (AgentCapability.RUN_TESTS,),
    BrainCapability.LONG_CONTEXT_REASONING: (AgentCapability.READ_WORKSPACE,),
    BrainCapability.VISION_ANALYSIS: (AgentCapability.READ_WORKSPACE,),
}


def brain_manifest_to_agent_identity(
    manifest: BrainManifest,
    *,
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (
        OperatingDomain.POLICY_GOVERNED,
        OperatingDomain.REVIEWABLE,
    ),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentIdentity:
    """Convert a Wave 7 brain manifest into a Wave 11 model-brain agent.

    The adapter is intentionally conservative. A model brain may receive
    proposal, review, inspection, test-planning, or read-style capabilities
    derived from its declared BrainCapability values. It never receives human
    approval, patch-application, secret, mutation, registration, delegation, or
    revocation authority from a BrainManifest.
    """

    capabilities = _agent_capabilities_from_brain_manifest(manifest)
    evidence_ids = tuple(evidence_artifact_ids) or (
        f"brain-manifest-{manifest.brain_name}",
    )
    grants = tuple(
        _grant_for_brain_capability(
            manifest=manifest,
            capability=capability,
            repository_ids=repository_ids,
            domains=domains,
            path_roots=path_roots,
            evidence_artifact_ids=evidence_ids,
        )
        for capability in capabilities
    )

    return AgentIdentity(
        agent_id=f"brain-{manifest.brain_name}",
        display_name=f"Brain: {manifest.brain_name}",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=grants,
        issuer=manifest.provider_name,
        subject=manifest.model_name,
        metadata={
            "adapter": "brain-manifest",
            "brain_name": manifest.brain_name,
            "provider_name": manifest.provider_name,
            "model_name": manifest.model_name,
            "version": manifest.version,
            "roles": [role.value for role in manifest.roles],
            "brain_capabilities": [
                capability.value for capability in manifest.capabilities
            ],
            "labels": list(manifest.labels),
            "preferred_packs": list(manifest.preferred_packs),
            "is_default": manifest.is_default,
        },
    )


def brain_snapshot_to_agent_registry(
    snapshot: BrainManifestSnapshot,
    *,
    registry_id: str = "wave-11-brain-agents",
    repository_ids: Sequence[str] = ("ix-blackfox",),
    domains: Sequence[OperatingDomain] = (
        OperatingDomain.POLICY_GOVERNED,
        OperatingDomain.REVIEWABLE,
    ),
    path_roots: Sequence[str] = ("src/ix_blackfox",),
    evidence_artifact_ids: Sequence[str] = (),
) -> AgentRegistry:
    """Convert a BrainManifestSnapshot into a Wave 11 AgentRegistry."""

    return build_agent_registry(
        registry_id,
        (
            brain_manifest_to_agent_identity(
                manifest,
                repository_ids=repository_ids,
                domains=domains,
                path_roots=path_roots,
                evidence_artifact_ids=evidence_artifact_ids,
            )
            for manifest in snapshot.manifests
        ),
        metadata={
            "adapter": "brain-manifest-snapshot",
            "brain_count": len(snapshot.manifests),
        },
    )


def _agent_capabilities_from_brain_manifest(
    manifest: BrainManifest,
) -> tuple[AgentCapability, ...]:
    mapped: set[AgentCapability] = set()
    for brain_capability in manifest.capabilities:
        mapped.update(_BRAIN_CAPABILITY_MAP[brain_capability])
    return tuple(sorted(mapped, key=lambda capability: capability.value))


def _grant_for_brain_capability(
    *,
    manifest: BrainManifest,
    capability: AgentCapability,
    repository_ids: Sequence[str],
    domains: Sequence[OperatingDomain],
    path_roots: Sequence[str],
    evidence_artifact_ids: Sequence[str],
) -> AgentCapabilityGrant:
    normalized_capability = normalize_identifier(
        capability.value,
        label="capability",
    )
    metadata: dict[str, Any] = {
        "source_brain_name": manifest.brain_name,
        "source_manifest_version": manifest.version,
        "source_brain_capabilities": [
            brain_capability.value for brain_capability in manifest.capabilities
        ],
    }
    return AgentCapabilityGrant(
        grant_id=f"brain-{manifest.brain_name}-{normalized_capability}",
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=tuple(repository_ids),
            domains=tuple(domains),
            pack_ids=manifest.preferred_packs,
            path_roots=tuple(path_roots),
            max_risk_tier=capability_default_risk_tier(capability),
            requires_human_review=capability_requires_human_review(capability),
            evidence_artifact_ids=tuple(evidence_artifact_ids),
            metadata=metadata,
        ),
        rationale=(
            "Derived from a BrainManifest declaration. This grant gives the "
            "model brain scoped participation authority only; it does not grant "
            "human approval, self-approval, mutation, secret, or deployment "
            "authority."
        ),
        metadata=metadata,
    )
