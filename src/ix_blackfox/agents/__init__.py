"""Wave 11 agent identity and capability-governance primitives."""

from __future__ import annotations

from ix_blackfox.agents.models import (
    WAVE11_AGENT_IDENTITY_SCHEMA_VERSION,
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
    CapabilityRiskTier,
    normalize_capability_grants,
)

__all__ = [
    "WAVE11_AGENT_IDENTITY_SCHEMA_VERSION",
    "AgentCapability",
    "AgentCapabilityGrant",
    "AgentCapabilityScope",
    "AgentIdentity",
    "AgentKind",
    "AgentLifecycleState",
    "AgentTrustTier",
    "CapabilityRiskTier",
    "normalize_capability_grants",
]
