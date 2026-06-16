from __future__ import annotations

from ix_blackfox.agents import (
    AgentCapability,
    AgentKind,
    AgentTrustTier,
    brain_manifest_to_agent_identity,
    brain_snapshot_to_agent_registry,
    validate_agent_capability_posture,
)
from ix_blackfox.brains.contracts import BrainCapability, BrainRole
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.models import BrainContextWindow, BrainModelProfile
from ix_blackfox.brains.registry import BrainManifestRegistry
from ix_blackfox.operating import OperatingDomain


def test_brain_manifest_adapter_creates_governed_model_agent() -> None:
    manifest = _brain_manifest(
        "repair-brain",
        capabilities=(
            BrainCapability.CODE_GENERATION,
            BrainCapability.SAFETY_CLASSIFICATION,
            BrainCapability.TOOL_PLANNING,
        ),
    )

    agent = brain_manifest_to_agent_identity(manifest)

    assert agent.agent_id == "brain-repair-brain"
    assert agent.kind is AgentKind.MODEL_BRAIN
    assert agent.trust_tier is AgentTrustTier.GOVERNED_AUTOMATION
    assert agent.issuer == "local-provider"
    assert agent.subject == "repair-model:1"
    assert set(agent.capabilities) == {
        AgentCapability.PROPOSE_PATCH,
        AgentCapability.REVIEW_PATCH,
        AgentCapability.RUN_TESTS,
    }
    assert agent.metadata["adapter"] == "brain-manifest"
    assert validate_agent_capability_posture(agent).allowed


def test_brain_manifest_adapter_preserves_scope_labels_and_pack_preferences() -> None:
    manifest = _brain_manifest(
        "policy-brain",
        capabilities=(
            BrainCapability.STRUCTURED_OUTPUT,
            BrainCapability.LONG_CONTEXT_REASONING,
        ),
        preferred_packs=("Security Pack", "Compliance Pack"),
        labels=("Policy", "Evidence"),
    )

    agent = brain_manifest_to_agent_identity(
        manifest,
        repository_ids=("IX-BlackFox", "IX-CognitionKernel"),
        domains=(OperatingDomain.REVIEWABLE,),
        path_roots=("src/ix_blackfox/policy",),
        evidence_artifact_ids=("brain-policy-evidence",),
    )

    assert set(agent.capabilities) == {
        AgentCapability.INSPECT_POLICY,
        AgentCapability.READ_WORKSPACE,
    }
    for grant in agent.capability_grants:
        assert grant.scope.repository_ids == (
            "ix-blackfox",
            "ix-cognitionkernel",
        )
        assert grant.scope.domains == (OperatingDomain.REVIEWABLE,)
        assert grant.scope.pack_ids == ("compliance-pack", "security-pack")
        assert grant.scope.path_roots == ("src/ix_blackfox/policy",)
        assert grant.scope.evidence_artifact_ids == ("brain-policy-evidence",)
        assert grant.scope.requires_human_review is False


def test_brain_snapshot_adapter_builds_agent_registry() -> None:
    brain_registry = BrainManifestRegistry()
    brain_registry.register(
        _brain_manifest(
            "primary-brain",
            capabilities=(BrainCapability.TEXT_GENERATION,),
            is_default=True,
        )
    )
    brain_registry.register(
        _brain_manifest(
            "safety-brain",
            capabilities=(BrainCapability.SAFETY_CLASSIFICATION,),
        )
    )

    agent_registry = brain_snapshot_to_agent_registry(brain_registry.snapshot())

    assert agent_registry.registry_id == "wave-11-brain-agents"
    assert agent_registry.agent_ids == ("brain-primary-brain", "brain-safety-brain")
    assert agent_registry.find_by_capability(AgentCapability.PROPOSE_PATCH)
    assert agent_registry.find_by_capability(AgentCapability.REVIEW_PATCH)
    assert agent_registry.snapshot().ready is True
    assert agent_registry.metadata["adapter"] == "brain-manifest-snapshot"


def _brain_manifest(
    brain_name: str,
    *,
    capabilities: tuple[BrainCapability, ...],
    preferred_packs: tuple[str, ...] = (),
    labels: tuple[str, ...] = (),
    is_default: bool = False,
) -> BrainManifest:
    normalized_name = brain_name.strip().lower().replace(" ", "-")
    return BrainManifest(
        brain_name=normalized_name,
        provider_name="local-provider",
        model_name=f"{normalized_name.replace('-', '_')}:1",
        version="1.0",
        profile=BrainModelProfile(
            brain_name=normalized_name,
            roles=(BrainRole.PRIMARY, BrainRole.SAFETY),
            capabilities=capabilities,
            context_window=BrainContextWindow(
                max_input_tokens=8192,
                max_output_tokens=2048,
            ),
            description="Test brain profile for Wave 11 adapter coverage.",
        ),
        description="Test brain manifest for Wave 11 adapter coverage.",
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=is_default,
    )
