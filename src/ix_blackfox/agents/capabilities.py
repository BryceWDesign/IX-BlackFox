from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto

from ix_blackfox.agents.models import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
    CapabilityRiskTier,
)


class CapabilityFindingCode(StrEnum):
    """Deterministic finding codes emitted by Wave 11 capability validation."""

    AGENT_REVOKED = auto()
    AGENT_SUSPENDED = auto()
    UNKNOWN_AGENT_KIND = auto()
    HUMAN_ONLY_CAPABILITY = auto()
    TRUST_TIER_MISMATCH = auto()
    INACTIVE_GRANT = auto()
    RISK_TIER_TOO_LOW = auto()
    HUMAN_REVIEW_REQUIRED = auto()
    TOOL_APPROVAL_BLOCKED = auto()
    MODEL_APPROVAL_BLOCKED = auto()
    SYSTEM_SELF_AUTHORITY_BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class CapabilityFinding:
    """One policy finding attached to an agent capability posture."""

    code: CapabilityFindingCode
    summary: str
    capability: AgentCapability | None = None
    grant_id: str = ""
    blocking: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "summary": self.summary,
            "capability": self.capability.value if self.capability else "",
            "grant_id": self.grant_id,
            "blocking": self.blocking,
        }


@dataclass(frozen=True, slots=True)
class CapabilityPolicyResult:
    """Capability posture result for one registered agent."""

    agent_id: str
    findings: tuple[CapabilityFinding, ...] = ()

    @property
    def blocking_findings(self) -> tuple[CapabilityFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def warning_findings(self) -> tuple[CapabilityFinding, ...]:
        return tuple(finding for finding in self.findings if not finding.blocking)

    @property
    def allowed(self) -> bool:
        return not self.blocking_findings

    def to_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "allowed": self.allowed,
            "blocking_finding_count": len(self.blocking_findings),
            "warning_finding_count": len(self.warning_findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


HUMAN_ONLY_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        AgentCapability.APPROVE_RELEASE,
        AgentCapability.APPROVE_SECURITY,
        AgentCapability.APPROVE_COMPLIANCE,
        AgentCapability.APPROVE_SANDBOX_EGRESS,
        AgentCapability.REGISTER_AGENT,
        AgentCapability.DELEGATE_CAPABILITY,
        AgentCapability.REVOKE_AGENT,
    }
)

REQUIRES_HUMAN_REVIEW_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        AgentCapability.APPLY_PATCH,
        AgentCapability.RUN_PROCESS,
        AgentCapability.WRITE_WORKSPACE,
        AgentCapability.EXPORT_EVIDENCE,
        AgentCapability.MUTATE_SYSTEM,
        AgentCapability.ACCESS_SECRET,
        AgentCapability.ACCESS_NETWORK,
        *HUMAN_ONLY_CAPABILITIES,
    }
)

TOOL_DENIED_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        AgentCapability.APPROVE_RELEASE,
        AgentCapability.APPROVE_SECURITY,
        AgentCapability.APPROVE_COMPLIANCE,
        AgentCapability.APPROVE_SANDBOX_EGRESS,
        AgentCapability.REGISTER_AGENT,
        AgentCapability.DELEGATE_CAPABILITY,
        AgentCapability.REVOKE_AGENT,
        AgentCapability.MUTATE_SYSTEM,
        AgentCapability.ACCESS_SECRET,
    }
)

MODEL_DENIED_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        *HUMAN_ONLY_CAPABILITIES,
        AgentCapability.APPLY_PATCH,
        AgentCapability.MUTATE_SYSTEM,
        AgentCapability.ACCESS_SECRET,
    }
)

_DEFAULT_RISK_TIERS: dict[AgentCapability, CapabilityRiskTier] = {
    AgentCapability.PROPOSE_PATCH: CapabilityRiskTier.LOW,
    AgentCapability.REVIEW_PATCH: CapabilityRiskTier.MEDIUM,
    AgentCapability.APPLY_PATCH: CapabilityRiskTier.HIGH,
    AgentCapability.RUN_TESTS: CapabilityRiskTier.MEDIUM,
    AgentCapability.RUN_PROCESS: CapabilityRiskTier.HIGH,
    AgentCapability.READ_WORKSPACE: CapabilityRiskTier.LOW,
    AgentCapability.WRITE_WORKSPACE: CapabilityRiskTier.HIGH,
    AgentCapability.INSPECT_POLICY: CapabilityRiskTier.LOW,
    AgentCapability.EXPORT_EVIDENCE: CapabilityRiskTier.HIGH,
    AgentCapability.APPROVE_RELEASE: CapabilityRiskTier.CRITICAL,
    AgentCapability.APPROVE_SECURITY: CapabilityRiskTier.CRITICAL,
    AgentCapability.APPROVE_COMPLIANCE: CapabilityRiskTier.CRITICAL,
    AgentCapability.APPROVE_SANDBOX_EGRESS: CapabilityRiskTier.CRITICAL,
    AgentCapability.MUTATE_SYSTEM: CapabilityRiskTier.CRITICAL,
    AgentCapability.ACCESS_SECRET: CapabilityRiskTier.CRITICAL,
    AgentCapability.ACCESS_NETWORK: CapabilityRiskTier.HIGH,
    AgentCapability.REGISTER_AGENT: CapabilityRiskTier.CRITICAL,
    AgentCapability.DELEGATE_CAPABILITY: CapabilityRiskTier.CRITICAL,
    AgentCapability.REVOKE_AGENT: CapabilityRiskTier.CRITICAL,
}

_RISK_ORDER: dict[CapabilityRiskTier, int] = {
    CapabilityRiskTier.LOW: 1,
    CapabilityRiskTier.MEDIUM: 2,
    CapabilityRiskTier.HIGH: 3,
    CapabilityRiskTier.CRITICAL: 4,
}


def capability_default_risk_tier(capability: AgentCapability) -> CapabilityRiskTier:
    """Return the default risk tier for a capability family."""

    return _DEFAULT_RISK_TIERS[capability]


def capability_requires_human_review(capability: AgentCapability) -> bool:
    """Return whether a capability should require human review by default."""

    return capability in REQUIRES_HUMAN_REVIEW_CAPABILITIES


def capability_is_human_only(capability: AgentCapability) -> bool:
    """Return whether only a human authority agent may hold the capability."""

    return capability in HUMAN_ONLY_CAPABILITIES


def validate_agent_capability_posture(agent: AgentIdentity) -> CapabilityPolicyResult:
    """Validate capability grants against Wave 11 identity-bound policy."""

    findings: list[CapabilityFinding] = []

    if agent.lifecycle_state is AgentLifecycleState.REVOKED:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.AGENT_REVOKED,
                summary="Revoked agents may not hold or exercise capability grants.",
                blocking=True,
            )
        )
    elif agent.lifecycle_state is AgentLifecycleState.SUSPENDED:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.AGENT_SUSPENDED,
                summary="Suspended agents require review before capability use.",
            )
        )

    if agent.kind is AgentKind.UNKNOWN:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.UNKNOWN_AGENT_KIND,
                summary="Unknown agent kind cannot be trusted for active authority.",
                blocking=True,
            )
        )

    for grant in agent.capability_grants:
        findings.extend(_validate_grant(agent, grant))

    return CapabilityPolicyResult(
        agent_id=agent.agent_id,
        findings=tuple(sorted(findings, key=lambda item: item.code.value)),
    )


def _validate_grant(
    agent: AgentIdentity,
    grant: AgentCapabilityGrant,
) -> tuple[CapabilityFinding, ...]:
    findings: list[CapabilityFinding] = []

    if not grant.active:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.INACTIVE_GRANT,
                summary="Inactive capability grant is retained for audit only.",
                capability=grant.capability,
                grant_id=grant.grant_id,
            )
        )
        return tuple(findings)

    required_tier = capability_default_risk_tier(grant.capability)
    if _RISK_ORDER[grant.scope.max_risk_tier] < _RISK_ORDER[required_tier]:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.RISK_TIER_TOO_LOW,
                summary=(
                    "Capability grant max_risk_tier is lower than the default "
                    "risk tier required for this capability."
                ),
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    if capability_is_human_only(grant.capability) and not agent.can_hold_human_authority:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.HUMAN_ONLY_CAPABILITY,
                summary="Capability is restricted to active human authority agents.",
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    if (
        grant.capability in REQUIRES_HUMAN_REVIEW_CAPABILITIES
        and not grant.scope.requires_human_review
        and agent.trust_tier is not AgentTrustTier.HUMAN_AUTHORITY
    ):
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.HUMAN_REVIEW_REQUIRED,
                summary="Capability requires a human-review scope boundary.",
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    if agent.kind is AgentKind.TOOL and grant.capability in TOOL_DENIED_CAPABILITIES:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.TOOL_APPROVAL_BLOCKED,
                summary="Tool agents cannot hold approval, secret, mutation, or delegation authority.",
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    if agent.kind is AgentKind.MODEL_BRAIN and grant.capability in MODEL_DENIED_CAPABILITIES:
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.MODEL_APPROVAL_BLOCKED,
                summary="Model agents cannot hold approval, mutation, secret, or delegation authority.",
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    if (
        agent.kind in {AgentKind.SYSTEM_SERVICE, AgentKind.CI_RUNNER}
        and grant.capability in HUMAN_ONLY_CAPABILITIES
    ):
        findings.append(
            CapabilityFinding(
                code=CapabilityFindingCode.SYSTEM_SELF_AUTHORITY_BLOCKED,
                summary="System actors cannot hold human-only authority capabilities.",
                capability=grant.capability,
                grant_id=grant.grant_id,
                blocking=True,
            )
        )

    return tuple(findings)
