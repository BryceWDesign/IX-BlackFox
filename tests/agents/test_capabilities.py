from __future__ import annotations

from ix_blackfox.agents import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentTrustTier,
    CapabilityFindingCode,
    CapabilityPolicyResult,
    CapabilityRiskTier,
    capability_default_risk_tier,
    capability_is_human_only,
    capability_requires_human_review,
    validate_agent_capability_posture,
)
from ix_blackfox.operating import OperatingDomain


def test_capability_catalog_marks_human_only_and_high_risk_authority() -> None:
    assert capability_is_human_only(AgentCapability.APPROVE_RELEASE)
    assert capability_is_human_only(AgentCapability.DELEGATE_CAPABILITY)
    assert not capability_is_human_only(AgentCapability.PROPOSE_PATCH)
    assert capability_requires_human_review(AgentCapability.RUN_PROCESS)
    assert (
        capability_default_risk_tier(AgentCapability.APPROVE_SECURITY)
        is CapabilityRiskTier.CRITICAL
    )


def test_model_brain_can_hold_scoped_proposal_but_not_release_approval() -> None:
    allowed_agent = AgentIdentity(
        agent_id="model-proposer",
        display_name="Model Proposer",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                grant_id="propose-patch",
                capability=AgentCapability.PROPOSE_PATCH,
                tier=CapabilityRiskTier.LOW,
            ),
        ),
    )
    assert validate_agent_capability_posture(allowed_agent).allowed

    blocked_agent = AgentIdentity(
        agent_id="model-approver",
        display_name="Model Approver",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                grant_id="approve-release",
                capability=AgentCapability.APPROVE_RELEASE,
                tier=CapabilityRiskTier.CRITICAL,
                requires_review=True,
            ),
        ),
    )
    result = validate_agent_capability_posture(blocked_agent)

    assert not result.allowed
    assert CapabilityFindingCode.HUMAN_ONLY_CAPABILITY in _codes(result)
    assert CapabilityFindingCode.MODEL_APPROVAL_BLOCKED in _codes(result)


def test_tool_agent_cannot_hold_secret_or_approval_authority() -> None:
    tool_agent = AgentIdentity(
        agent_id="tool-agent",
        display_name="Tool Agent",
        kind=AgentKind.TOOL,
        trust_tier=AgentTrustTier.REGISTERED_TOOL,
        capability_grants=(
            _grant(
                grant_id="access-secret",
                capability=AgentCapability.ACCESS_SECRET,
                tier=CapabilityRiskTier.CRITICAL,
                requires_review=True,
            ),
        ),
    )
    result = validate_agent_capability_posture(tool_agent)

    assert not result.allowed
    assert CapabilityFindingCode.TOOL_APPROVAL_BLOCKED in _codes(result)


def test_non_human_high_risk_capability_requires_review_scope() -> None:
    ci_runner = AgentIdentity(
        agent_id="ci-runner",
        display_name="CI Runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                grant_id="run-process",
                capability=AgentCapability.RUN_PROCESS,
                tier=CapabilityRiskTier.HIGH,
                requires_review=False,
            ),
        ),
    )
    result = validate_agent_capability_posture(ci_runner)

    assert not result.allowed
    assert CapabilityFindingCode.HUMAN_REVIEW_REQUIRED in _codes(result)


def test_grant_risk_tier_must_cover_capability_default_risk() -> None:
    agent = AgentIdentity(
        agent_id="low-tier-runner",
        display_name="Low Tier Runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                grant_id="apply-patch-too-low",
                capability=AgentCapability.APPLY_PATCH,
                tier=CapabilityRiskTier.MEDIUM,
                requires_review=True,
            ),
        ),
    )
    result = validate_agent_capability_posture(agent)

    assert not result.allowed
    assert CapabilityFindingCode.RISK_TIER_TOO_LOW in _codes(result)


def test_human_authority_can_hold_scoped_approval_capability() -> None:
    human = AgentIdentity(
        agent_id="release-owner",
        display_name="Release Owner",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability_grants=(
            _grant(
                grant_id="approve-release",
                capability=AgentCapability.APPROVE_RELEASE,
                tier=CapabilityRiskTier.CRITICAL,
            ),
        ),
    )
    result = validate_agent_capability_posture(human)

    assert result.allowed
    assert result.to_dict()["blocking_finding_count"] == 0


def _grant(
    *,
    grant_id: str,
    capability: AgentCapability,
    tier: CapabilityRiskTier,
    requires_review: bool = False,
) -> AgentCapabilityGrant:
    return AgentCapabilityGrant(
        grant_id=grant_id,
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=("ix-blackfox",),
            domains=(OperatingDomain.POLICY_GOVERNED,),
            max_risk_tier=tier,
            requires_human_review=requires_review,
            evidence_artifact_ids=("wave-11-capability-policy",),
        ),
        rationale="Capability policy test grant.",
    )


def _codes(result: CapabilityPolicyResult) -> set[CapabilityFindingCode]:
    return {finding.code for finding in result.blocking_findings}
