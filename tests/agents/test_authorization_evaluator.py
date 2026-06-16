from __future__ import annotations

from ix_blackfox.agents import (
    AgentAction,
    AgentAuthorizationEvaluator,
    AgentAuthorizationReason,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentRegistry,
    AgentTrustTier,
    CapabilityRiskTier,
)
from ix_blackfox.operating import OperatingDomain


def test_evaluator_allows_scoped_low_risk_model_proposal() -> None:
    agent = _agent(
        agent_id="model-proposer",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.PROPOSE_PATCH,
        tier=CapabilityRiskTier.LOW,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    decision = evaluator.evaluate(
        _request(
            agent_id="model-proposer",
            action=AgentAction.PROPOSE,
            capability=AgentCapability.PROPOSE_PATCH,
            tier=CapabilityRiskTier.LOW,
        ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert decision.status is AgentAuthorizationStatus.ALLOW
    assert decision.reasons == (AgentAuthorizationReason.ALLOWED,)
    assert decision.allowed is True
    assert decision.reviewer_agent_id == ""


def test_evaluator_blocks_unknown_agent() -> None:
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11")
    )

    decision = evaluator.evaluate(
        _request(agent_id="missing-agent"),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert decision.status is AgentAuthorizationStatus.BLOCK
    assert decision.reasons == (AgentAuthorizationReason.UNKNOWN_AGENT,)


def test_evaluator_blocks_missing_capability() -> None:
    agent = _agent(
        agent_id="model-proposer",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.PROPOSE_PATCH,
        tier=CapabilityRiskTier.LOW,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    decision = evaluator.evaluate(
        _request(
            agent_id="model-proposer",
            action=AgentAction.RUN,
            capability=AgentCapability.RUN_TESTS,
            tier=CapabilityRiskTier.MEDIUM,
        ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert decision.status is AgentAuthorizationStatus.BLOCK
    assert decision.reasons == (AgentAuthorizationReason.MISSING_CAPABILITY,)


def test_evaluator_blocks_out_of_scope_repository_and_risk() -> None:
    agent = _agent(
        agent_id="ci-runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.RUN_TESTS,
        tier=CapabilityRiskTier.MEDIUM,
        requires_review=True,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    wrong_repo = evaluator.evaluate(
        _request(
            agent_id="ci-runner",
            action=AgentAction.RUN,
            capability=AgentCapability.RUN_TESTS,
            repository_id="other-repo",
            tier=CapabilityRiskTier.MEDIUM,
            evidence=("ci-evidence",),
        ),
        decided_at="2026-06-15T12:01:00Z",
    )
    excessive_risk = evaluator.evaluate(
        _request(
            agent_id="ci-runner",
            action=AgentAction.RUN,
            capability=AgentCapability.RUN_TESTS,
            tier=CapabilityRiskTier.HIGH,
            evidence=("ci-evidence",),
        ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert wrong_repo.status is AgentAuthorizationStatus.BLOCK
    assert wrong_repo.reasons == (AgentAuthorizationReason.CAPABILITY_OUT_OF_SCOPE,)
    assert excessive_risk.status is AgentAuthorizationStatus.BLOCK
    assert excessive_risk.reasons == (
        AgentAuthorizationReason.CAPABILITY_OUT_OF_SCOPE,
    )


def test_evaluator_requires_review_for_high_risk_non_human_capability() -> None:
    agent = _agent(
        agent_id="ci-runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.RUN_PROCESS,
        tier=CapabilityRiskTier.HIGH,
        requires_review=True,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    decision = evaluator.evaluate(
        _request(
            agent_id="ci-runner",
            action=AgentAction.RUN,
            capability=AgentCapability.RUN_PROCESS,
            tier=CapabilityRiskTier.HIGH,
        ),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id="release-owner",
    )

    assert decision.status is AgentAuthorizationStatus.REQUIRE_REVIEW
    assert AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE in decision.reasons
    assert AgentAuthorizationReason.EVIDENCE_MISSING in decision.reasons
    assert decision.reviewer_agent_id == "release-owner"


def test_evaluator_blocks_policy_invalid_model_approval_grant() -> None:
    agent = _agent(
        agent_id="model-approver",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.APPROVE_RELEASE,
        tier=CapabilityRiskTier.CRITICAL,
        requires_review=True,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    decision = evaluator.evaluate(
        _request(
            agent_id="model-approver",
            action=AgentAction.APPROVE,
            capability=AgentCapability.APPROVE_RELEASE,
            tier=CapabilityRiskTier.CRITICAL,
            evidence=("approval-evidence",),
        ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert decision.status is AgentAuthorizationStatus.BLOCK
    assert decision.reasons == (AgentAuthorizationReason.POLICY_FINDING_BLOCKED,)


def test_evaluator_blocks_revoked_and_reviews_suspended_agents() -> None:
    revoked = _agent(
        agent_id="revoked-agent",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability=AgentCapability.REVIEW_PATCH,
        tier=CapabilityRiskTier.MEDIUM,
        lifecycle=AgentLifecycleState.REVOKED,
        grant_active=False,
    )
    suspended = _agent(
        agent_id="suspended-agent",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability=AgentCapability.REVIEW_PATCH,
        tier=CapabilityRiskTier.MEDIUM,
        lifecycle=AgentLifecycleState.SUSPENDED,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(revoked, suspended))
    )

    revoked_decision = evaluator.evaluate(
        _request(agent_id="revoked-agent", capability=AgentCapability.REVIEW_PATCH),
        decided_at="2026-06-15T12:01:00Z",
    )
    suspended_decision = evaluator.evaluate(
        _request(agent_id="suspended-agent", capability=AgentCapability.REVIEW_PATCH),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert revoked_decision.status is AgentAuthorizationStatus.BLOCK
    assert revoked_decision.reasons == (AgentAuthorizationReason.REVOKED_AGENT,)
    assert suspended_decision.status is AgentAuthorizationStatus.REQUIRE_REVIEW
    assert suspended_decision.reasons == (AgentAuthorizationReason.SUSPENDED_AGENT,)


def test_evaluator_blocks_expired_grants() -> None:
    agent = _agent(
        agent_id="temporary-runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability=AgentCapability.RUN_TESTS,
        tier=CapabilityRiskTier.MEDIUM,
        expires_at="2026-06-15T11:59:00Z",
        requires_review=True,
    )
    evaluator = AgentAuthorizationEvaluator(
        registry=AgentRegistry(registry_id="wave-11", agents=(agent,))
    )

    decision = evaluator.evaluate(
        _request(
            agent_id="temporary-runner",
            action=AgentAction.RUN,
            capability=AgentCapability.RUN_TESTS,
            tier=CapabilityRiskTier.MEDIUM,
            evidence=("ci-evidence",),
        ),
        decided_at="2026-06-15T12:01:00Z",
    )

    assert decision.status is AgentAuthorizationStatus.BLOCK
    assert decision.reasons == (AgentAuthorizationReason.EXPIRED_GRANT,)


def _agent(
    *,
    agent_id: str,
    kind: AgentKind,
    trust_tier: AgentTrustTier,
    capability: AgentCapability,
    tier: CapabilityRiskTier,
    requires_review: bool = False,
    lifecycle: AgentLifecycleState = AgentLifecycleState.ACTIVE,
    grant_active: bool = True,
    expires_at: str = "",
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        display_name=agent_id,
        kind=kind,
        trust_tier=trust_tier,
        lifecycle_state=lifecycle,
        capability_grants=(
            AgentCapabilityGrant(
                grant_id=f"{agent_id}-{capability.value}",
                capability=capability,
                active=grant_active,
                scope=AgentCapabilityScope(
                    repository_ids=("ix-blackfox",),
                    domains=(OperatingDomain.POLICY_GOVERNED,),
                    path_roots=("src/ix_blackfox",),
                    max_risk_tier=tier,
                    requires_human_review=requires_review,
                    evidence_artifact_ids=("wave-11-authz-test",),
                    expires_at=expires_at,
                ),
            ),
        ),
    )


def _request(
    *,
    agent_id: str = "model-proposer",
    action: AgentAction = AgentAction.PROPOSE,
    capability: AgentCapability = AgentCapability.PROPOSE_PATCH,
    repository_id: str = "ix-blackfox",
    tier: CapabilityRiskTier = CapabilityRiskTier.LOW,
    evidence: tuple[str, ...] = (),
) -> AgentAuthorizationRequest:
    return AgentAuthorizationRequest(
        request_id=f"{agent_id}-{action.value}-{capability.value}",
        agent_id=agent_id,
        action=action,
        capability=capability,
        target=AgentAuthorizationTarget(
            repository_id=repository_id,
            domain=OperatingDomain.POLICY_GOVERNED,
            path="src/ix_blackfox/agents/models.py",
            risk_tier=tier,
        ),
        requested_at="2026-06-15T12:00:00Z",
        evidence_artifact_ids=evidence,
        justification="Wave 11 authorization evaluator test request.",
    )
