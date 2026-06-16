from __future__ import annotations

from ix_blackfox.agents import (
    AgentCapability,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
    review_board_to_agent_registry,
    reviewer_authority_to_agent_identity,
    validate_agent_capability_posture,
)
from ix_blackfox.operating import (
    ApprovalQuorum,
    OperatingDomain,
    OperatingTeam,
    ReviewBoard,
    ReviewerAuthority,
    ReviewerKind,
    TeamRole,
)


def test_reviewer_authority_adapter_creates_human_authority_agent() -> None:
    authority = _authority(
        reviewer_id="Alice Security",
        reviewer_kind=ReviewerKind.HUMAN,
        roles=(TeamRole.SECURITY_REVIEWER,),
        domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MULTI_TEAM),
    )

    agent = reviewer_authority_to_agent_identity(
        authority,
        evidence_artifact_ids=("reviewer-authority-evidence",),
    )

    assert agent.agent_id == "reviewer-alice-security"
    assert agent.kind is AgentKind.HUMAN_OPERATOR
    assert agent.trust_tier is AgentTrustTier.HUMAN_AUTHORITY
    assert agent.can_hold_human_authority is True
    assert set(agent.capabilities) == {
        AgentCapability.APPROVE_SANDBOX_EGRESS,
        AgentCapability.APPROVE_SECURITY,
        AgentCapability.REVIEW_PATCH,
    }
    assert agent.metadata["adapter"] == "reviewer-authority"
    assert validate_agent_capability_posture(agent).allowed

    for grant in agent.capability_grants:
        assert grant.scope.repository_ids == ("ix-blackfox",)
        assert grant.scope.domains == (
            OperatingDomain.MULTI_TEAM,
            OperatingDomain.REVIEWABLE,
        )
        assert grant.scope.evidence_artifact_ids == ("reviewer-authority-evidence",)


def test_reviewer_adapter_preserves_model_reviewer_as_blocking_evidence() -> None:
    authority = _authority(
        reviewer_id="model-reviewer",
        reviewer_kind=ReviewerKind.MODEL,
        roles=(TeamRole.RELEASE_MANAGER,),
    )

    agent = reviewer_authority_to_agent_identity(authority)
    result = validate_agent_capability_posture(agent)

    assert agent.kind is AgentKind.MODEL_BRAIN
    assert agent.trust_tier is AgentTrustTier.GOVERNED_AUTOMATION
    assert AgentCapability.APPROVE_RELEASE in agent.capabilities
    assert not result.allowed
    assert result.blocking_findings


def test_inactive_reviewer_authority_becomes_suspended_agent() -> None:
    authority = _authority(
        reviewer_id="inactive-reviewer",
        reviewer_kind=ReviewerKind.HUMAN,
        roles=(TeamRole.QA_VERIFIER,),
        active=False,
    )

    agent = reviewer_authority_to_agent_identity(authority)

    assert agent.lifecycle_state is AgentLifecycleState.SUSPENDED
    assert agent.kind is AgentKind.HUMAN_OPERATOR
    assert validate_agent_capability_posture(agent).allowed is True
    assert validate_agent_capability_posture(agent).warning_findings


def test_review_board_adapter_builds_reviewer_agent_registry() -> None:
    security_team = OperatingTeam(
        team_id="security-team",
        name="Security Team",
        roles=(TeamRole.SECURITY_REVIEWER,),
        owned_repository_ids=("ix-blackfox",),
    )
    release_team = OperatingTeam(
        team_id="release-team",
        name="Release Team",
        roles=(TeamRole.RELEASE_MANAGER,),
        owned_repository_ids=("ix-blackfox",),
    )
    security = _authority(
        reviewer_id="security-reviewer",
        reviewer_kind=ReviewerKind.HUMAN,
        roles=(TeamRole.SECURITY_REVIEWER,),
        team_id="security-team",
    )
    release = _authority(
        reviewer_id="release-manager",
        reviewer_kind=ReviewerKind.HUMAN,
        roles=(TeamRole.RELEASE_MANAGER,),
        team_id="release-team",
    )
    board = ReviewBoard(
        board_id="wave-11-board",
        teams=(security_team, release_team),
        reviewer_authorities=(security, release),
        quorums=(
            ApprovalQuorum(
                quorum_id="release-quorum",
                repository_ids=("ix-blackfox",),
                domains=(OperatingDomain.REVIEWABLE,),
                required_roles=(TeamRole.SECURITY_REVIEWER, TeamRole.RELEASE_MANAGER),
                minimum_approvals=2,
                required_human_approvals=2,
                required_distinct_teams=2,
            ),
        ),
    )

    registry = review_board_to_agent_registry(board)

    assert registry.registry_id == "wave-11-reviewer-agents"
    assert registry.agent_ids == (
        "reviewer-release-manager",
        "reviewer-security-reviewer",
    )
    assert registry.find_by_capability(AgentCapability.APPROVE_RELEASE)
    assert registry.find_by_capability(AgentCapability.APPROVE_SECURITY)
    assert registry.snapshot().ready is True
    assert registry.metadata["adapter"] == "review-board"
    assert registry.metadata["board_id"] == "wave-11-board"


def _authority(
    *,
    reviewer_id: str,
    reviewer_kind: ReviewerKind,
    roles: tuple[TeamRole, ...],
    domains: tuple[OperatingDomain, ...] = (OperatingDomain.REVIEWABLE,),
    team_id: str = "security-team",
    active: bool = True,
) -> ReviewerAuthority:
    return ReviewerAuthority(
        reviewer_id=reviewer_id,
        reviewer_kind=reviewer_kind,
        team_id=team_id,
        roles=roles,
        approved_repository_ids=("ix-blackfox",),
        approved_domains=domains,
        active=active,
        delegated_by="platform-owner",
    )
