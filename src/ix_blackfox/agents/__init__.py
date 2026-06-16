"""Wave 11 agent identity and capability-governance primitives."""

from __future__ import annotations

from ix_blackfox.agents.capabilities import (
    HUMAN_ONLY_CAPABILITIES,
    MODEL_DENIED_CAPABILITIES,
    REQUIRES_HUMAN_REVIEW_CAPABILITIES,
    TOOL_DENIED_CAPABILITIES,
    CapabilityFinding,
    CapabilityFindingCode,
    CapabilityPolicyResult,
    capability_default_risk_tier,
    capability_is_human_only,
    capability_requires_human_review,
    validate_agent_capability_posture,
)
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
    "HUMAN_ONLY_CAPABILITIES",
    "MODEL_DENIED_CAPABILITIES",
    "REQUIRES_HUMAN_REVIEW_CAPABILITIES",
    "TOOL_DENIED_CAPABILITIES",
    "CapabilityFinding",
    "CapabilityFindingCode",
    "CapabilityPolicyResult",
    "capability_default_risk_tier",
    "capability_is_human_only",
    "capability_requires_human_review",
    "validate_agent_capability_posture",
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
