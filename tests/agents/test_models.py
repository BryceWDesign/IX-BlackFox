from __future__ import annotations

import pytest

from ix_blackfox.agents import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
    CapabilityRiskTier,
)
from ix_blackfox.operating import OperatingDomain


def test_agent_identity_normalizes_ids_and_exports_stable_digest() -> None:
    grant = _grant(
        grant_id=" Evidence Export ",
        capability=AgentCapability.EXPORT_EVIDENCE,
        repositories=(" IX-BlackFox ",),
        domains=(OperatingDomain.REVIEWABLE,),
    )
    identity = AgentIdentity(
        agent_id=" Human Reviewer ",
        display_name="  Human   Reviewer  ",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability_grants=(grant,),
        issuer=" Security Team ",
        subject=" reviewer@example.test ",
    )

    same_identity = AgentIdentity(
        agent_id="human-reviewer",
        display_name="Human Reviewer",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability_grants=(grant,),
        issuer="Security Team",
        subject="reviewer@example.test",
    )

    assert identity.agent_id == "human-reviewer"
    assert identity.display_name == "Human Reviewer"
    assert identity.can_hold_human_authority is True
    assert identity.has_capability(AgentCapability.EXPORT_EVIDENCE)
    assert identity.to_dict()["capabilities"] == ["export_evidence"]
    assert identity.digest == same_identity.digest


def test_capability_scope_rejects_unbounded_grants() -> None:
    with pytest.raises(ValueError, match="at least one boundary"):
        AgentCapabilityScope()


def test_agent_identity_rejects_empty_duplicate_and_revoked_active_grants() -> None:
    grant = _grant("approve-release", AgentCapability.APPROVE_RELEASE)

    with pytest.raises(ValueError, match="must not be empty"):
        AgentIdentity(
            agent_id="empty-agent",
            display_name="Empty Agent",
            kind=AgentKind.SYSTEM_SERVICE,
            trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
            capability_grants=(),
        )

    with pytest.raises(ValueError, match="grant_id values must be unique"):
        AgentIdentity(
            agent_id="duplicate-agent",
            display_name="Duplicate Agent",
            kind=AgentKind.HUMAN_OPERATOR,
            trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
            capability_grants=(grant, grant),
        )

    with pytest.raises(ValueError, match="Revoked agents"):
        AgentIdentity(
            agent_id="revoked-agent",
            display_name="Revoked Agent",
            kind=AgentKind.HUMAN_OPERATOR,
            trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
            lifecycle_state=AgentLifecycleState.REVOKED,
            capability_grants=(grant,),
        )


def test_identity_boundary_blocks_non_human_human_authority_and_unknown_trust() -> None:
    grant = _grant("review-patch", AgentCapability.REVIEW_PATCH)

    with pytest.raises(ValueError, match="Only human operators"):
        AgentIdentity(
            agent_id="model-reviewer",
            display_name="Model Reviewer",
            kind=AgentKind.MODEL_BRAIN,
            trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
            capability_grants=(grant,),
        )

    with pytest.raises(ValueError, match="UNKNOWN agent kind"):
        AgentIdentity(
            agent_id="unknown-agent",
            display_name="Unknown Agent",
            kind=AgentKind.UNKNOWN,
            trust_tier=AgentTrustTier.OBSERVER,
            capability_grants=(grant,),
        )


def test_scope_repository_and_domain_coverage_are_deterministic() -> None:
    scope = AgentCapabilityScope(
        repository_ids=("IX-BlackFox",),
        domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
        path_roots=("src/ix_blackfox",),
        max_risk_tier=CapabilityRiskTier.HIGH,
        requires_human_review=True,
        evidence_artifact_ids=("wave-11-authority-record",),
        delegated_by="Platform Security",
    )

    assert scope.repository_ids == ("ix-blackfox",)
    assert scope.path_roots == ("src/ix_blackfox",)
    assert scope.covers_repository(" IX BlackFox ")
    assert not scope.covers_repository("other-repo")
    assert scope.covers_domain(OperatingDomain.REVIEWABLE)
    assert not scope.covers_domain(OperatingDomain.REPLAYABLE)
    assert scope.to_dict()["requires_human_review"] is True


def _grant(
    grant_id: str,
    capability: AgentCapability,
    repositories: tuple[str, ...] = ("ix-blackfox",),
    domains: tuple[OperatingDomain, ...] = (OperatingDomain.POLICY_GOVERNED,),
) -> AgentCapabilityGrant:
    return AgentCapabilityGrant(
        grant_id=grant_id,
        capability=capability,
        scope=AgentCapabilityScope(repository_ids=repositories, domains=domains),
        rationale="Wave 11 scoped authority test grant.",
    )
