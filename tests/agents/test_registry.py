from __future__ import annotations

import pytest

from ix_blackfox.agents import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentRegistry,
    AgentTrustTier,
    CapabilityRiskTier,
    build_agent_registry,
)
from ix_blackfox.operating import OperatingDomain


def test_registry_registers_replaces_and_requires_agents() -> None:
    human = _agent(
        "release-owner", AgentKind.HUMAN_OPERATOR, AgentTrustTier.HUMAN_AUTHORITY
    )
    model = _agent(
        "model-proposer", AgentKind.MODEL_BRAIN, AgentTrustTier.GOVERNED_AUTOMATION
    )
    registry = (
        AgentRegistry(registry_id="Wave 11 Registry").register(human).register(model)
    )

    assert registry.registry_id == "wave-11-registry"
    assert registry.agent_ids == ("model-proposer", "release-owner")
    assert registry.require("Release Owner") == human
    assert registry.lookup("missing-agent") is None
    assert registry.find_by_kind(AgentKind.MODEL_BRAIN) == (model,)

    replacement = _agent(
        "model-proposer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        display_name="Model Proposer v2",
    )
    replaced = registry.replace(replacement)

    assert replaced.require("model-proposer").display_name == "Model Proposer v2"
    assert registry.require("model-proposer").display_name == "model-proposer"


def test_registry_blocks_duplicates_and_missing_replace_targets() -> None:
    human = _agent(
        "release-owner", AgentKind.HUMAN_OPERATOR, AgentTrustTier.HUMAN_AUTHORITY
    )
    registry = AgentRegistry(registry_id="wave-11-registry", agents=(human,))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(human)

    with pytest.raises(ValueError, match="not registered"):
        registry.replace(
            _agent(
                "other-agent",
                AgentKind.SYSTEM_SERVICE,
                AgentTrustTier.GOVERNED_AUTOMATION,
            )
        )

    with pytest.raises(ValueError, match="agent_id values must be unique"):
        AgentRegistry(registry_id="bad-registry", agents=(human, human))

    with pytest.raises(KeyError, match="not registered"):
        registry.require("missing-agent")


def test_registry_find_by_capability_respects_active_only() -> None:
    active = _agent(
        "active-exporter",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        capability=AgentCapability.EXPORT_EVIDENCE,
    )
    suspended = _agent(
        "suspended-exporter",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        capability=AgentCapability.EXPORT_EVIDENCE,
        lifecycle=AgentLifecycleState.SUSPENDED,
    )
    registry = build_agent_registry("wave-11-registry", (active, suspended))

    assert registry.find_by_capability(AgentCapability.EXPORT_EVIDENCE) == (active,)
    assert registry.find_by_capability(
        AgentCapability.EXPORT_EVIDENCE, active_only=False
    ) == (
        active,
        suspended,
    )


def test_registry_snapshot_is_digest_bound_and_reports_policy_findings() -> None:
    human = _agent(
        "release-owner", AgentKind.HUMAN_OPERATOR, AgentTrustTier.HUMAN_AUTHORITY
    )
    model = _agent(
        "model-approver",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.APPROVE_RELEASE,
        tier=CapabilityRiskTier.CRITICAL,
        requires_review=True,
    )
    registry = build_agent_registry("wave-11-registry", (human, model))
    snapshot = registry.snapshot()

    assert snapshot.registry_id == "wave-11-registry"
    assert snapshot.active_agent_count == 2
    assert snapshot.blocking_finding_count >= 1
    assert not snapshot.ready
    assert snapshot.digest == snapshot.to_dict()["digest"]
    assert snapshot.to_dict()["schema_version"] == "wave11.agent_identity_registry.v1"


def test_registry_to_dict_is_stable_for_same_agents() -> None:
    human = _agent(
        "release-owner", AgentKind.HUMAN_OPERATOR, AgentTrustTier.HUMAN_AUTHORITY
    )
    model = _agent(
        "model-proposer", AgentKind.MODEL_BRAIN, AgentTrustTier.GOVERNED_AUTOMATION
    )
    first = build_agent_registry("wave-11-registry", (human, model))
    second = build_agent_registry(" wave 11 registry ", (model, human))

    assert first.digest == second.digest
    assert first.to_dict()["active_agent_count"] == 2


def _agent(
    agent_id: str,
    kind: AgentKind,
    trust_tier: AgentTrustTier,
    *,
    display_name: str | None = None,
    capability: AgentCapability = AgentCapability.PROPOSE_PATCH,
    tier: CapabilityRiskTier = CapabilityRiskTier.LOW,
    requires_review: bool = False,
    lifecycle: AgentLifecycleState = AgentLifecycleState.ACTIVE,
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        display_name=display_name or agent_id,
        kind=kind,
        trust_tier=trust_tier,
        lifecycle_state=lifecycle,
        capability_grants=(
            AgentCapabilityGrant(
                grant_id=f"{agent_id}-{capability.value}",
                capability=capability,
                scope=AgentCapabilityScope(
                    repository_ids=("ix-blackfox",),
                    domains=(OperatingDomain.POLICY_GOVERNED,),
                    max_risk_tier=tier,
                    requires_human_review=requires_review,
                    evidence_artifact_ids=("wave-11-registry-test",),
                ),
            ),
        ),
    )
