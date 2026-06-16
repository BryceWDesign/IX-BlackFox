"""Wave 11 agent identity and capability-governance primitives."""

from __future__ import annotations

from ix_blackfox.agents.authority import (
    AuthorityEvaluation,
    AuthorityFinding,
    AuthorityFindingCode,
    evaluate_human_authority,
)
from ix_blackfox.agents.authorization import (
    AgentAction,
    AgentAuthorizationDecision,
    AgentAuthorizationEvaluator,
    AgentAuthorizationReason,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
    build_decision_id,
)
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
from ix_blackfox.agents.provenance import (
    AgentProvenanceLedger,
    AgentProvenanceRecord,
    build_provenance_record_id,
)
from ix_blackfox.agents.registry import (
    AgentRegistry,
    AgentRegistrySnapshot,
    build_agent_registry,
)

__all__ = [
    "AuthorityEvaluation",
    "AuthorityFinding",
    "AuthorityFindingCode",
    "evaluate_human_authority",
    "AgentAction",
    "AgentAuthorizationDecision",
    "AgentAuthorizationEvaluator",
    "AgentAuthorizationReason",
    "AgentAuthorizationRequest",
    "AgentAuthorizationStatus",
    "AgentAuthorizationTarget",
    "build_decision_id",
    "AgentRegistry",
    "AgentRegistrySnapshot",
    "build_agent_registry",
    "AgentProvenanceLedger",
    "AgentProvenanceRecord",
    "build_provenance_record_id",
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
