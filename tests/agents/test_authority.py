from __future__ import annotations

from ix_blackfox.agents import (
    AgentAction,
    AgentAuthorizationDecision,
    AgentAuthorizationReason,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentRegistry,
    AgentTrustTier,
    AuthorityEvaluation,
    AuthorityFindingCode,
    CapabilityRiskTier,
    build_decision_id,
    evaluate_human_authority,
)
from ix_blackfox.operating import OperatingDomain


def test_human_authority_is_preserved_for_separate_human_reviewer() -> None:
    requester = _agent(
        "ci-runner",
        AgentKind.CI_RUNNER,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
        requires_review=True,
    )
    reviewer = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(requester, reviewer))
    request = _request("ci-runner", AgentAction.RUN, AgentCapability.RUN_PROCESS)
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="release-owner",
    )

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is True
    assert evaluation.blocking_findings == ()
    assert AuthorityFindingCode.HUMAN_REVIEW_SATISFIED in _codes(evaluation)
    assert evaluation.to_dict()["digest"] == evaluation.digest


def test_self_approval_is_blocked_even_for_human_requester() -> None:
    requester = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(requester,))
    request = _request(
        "release-owner",
        AgentAction.APPROVE,
        AgentCapability.APPROVE_RELEASE,
    )
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="release-owner",
    )

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is False
    assert AuthorityFindingCode.SELF_APPROVAL_BLOCKED in _codes(evaluation)


def test_model_or_tool_reviewer_does_not_satisfy_human_authority() -> None:
    requester = _agent(
        "ci-runner",
        AgentKind.CI_RUNNER,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
        requires_review=True,
    )
    model_reviewer = _agent(
        "model-reviewer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.REVIEW_PATCH,
        CapabilityRiskTier.MEDIUM,
    )
    registry = AgentRegistry(
        registry_id="wave-11",
        agents=(requester, model_reviewer),
    )
    request = _request("ci-runner", AgentAction.RUN, AgentCapability.RUN_PROCESS)
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="model-reviewer",
    )

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is False
    assert AuthorityFindingCode.REVIEWER_NOT_HUMAN_AUTHORITY in _codes(evaluation)


def test_unknown_reviewer_and_unknown_requester_are_blocked() -> None:
    registry = AgentRegistry(registry_id="wave-11")
    request = _request("missing-agent", AgentAction.RUN, AgentCapability.RUN_PROCESS)
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="missing-reviewer",
    )

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is False
    assert AuthorityFindingCode.REQUESTER_UNKNOWN in _codes(evaluation)
    assert AuthorityFindingCode.REVIEWER_UNKNOWN in _codes(evaluation)


def test_human_only_capability_requested_by_model_is_blocked() -> None:
    model = _agent(
        "model-approver",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.REVIEW_PATCH,
        CapabilityRiskTier.MEDIUM,
    )
    reviewer = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(model, reviewer))
    request = _request(
        "model-approver",
        AgentAction.APPROVE,
        AgentCapability.APPROVE_RELEASE,
    )
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="release-owner",
    )

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is False
    assert AuthorityFindingCode.HUMAN_ONLY_CAPABILITY_BLOCKED in _codes(evaluation)


def test_allow_decision_records_that_human_review_was_not_required() -> None:
    model = _agent(
        "model-proposer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.PROPOSE_PATCH,
        CapabilityRiskTier.LOW,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(model,))
    request = _request(
        "model-proposer",
        AgentAction.PROPOSE,
        AgentCapability.PROPOSE_PATCH,
    )
    decision = _decision(request, AgentAuthorizationStatus.ALLOW)

    evaluation = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    assert evaluation.authority_preserved is True
    assert AuthorityFindingCode.HUMAN_REVIEW_NOT_REQUIRED in _codes(evaluation)


def _agent(
    agent_id: str,
    kind: AgentKind,
    trust_tier: AgentTrustTier,
    capability: AgentCapability,
    tier: CapabilityRiskTier,
    *,
    requires_review: bool = False,
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        display_name=agent_id,
        kind=kind,
        trust_tier=trust_tier,
        capability_grants=(
            AgentCapabilityGrant(
                grant_id=f"{agent_id}-{capability.value}",
                capability=capability,
                scope=AgentCapabilityScope(
                    repository_ids=("ix-blackfox",),
                    domains=(OperatingDomain.POLICY_GOVERNED,),
                    max_risk_tier=tier,
                    requires_human_review=requires_review,
                    evidence_artifact_ids=("wave-11-authority-test",),
                ),
            ),
        ),
    )


def _request(
    agent_id: str,
    action: AgentAction,
    capability: AgentCapability,
) -> AgentAuthorizationRequest:
    return AgentAuthorizationRequest(
        request_id=f"{agent_id}-{action.value}-{capability.value}",
        agent_id=agent_id,
        action=action,
        capability=capability,
        target=AgentAuthorizationTarget(
            repository_id="ix-blackfox",
            domain=OperatingDomain.POLICY_GOVERNED,
            risk_tier=CapabilityRiskTier.HIGH,
        ),
        requested_at="2026-06-15T12:00:00Z",
        evidence_artifact_ids=("wave-11-authority-evidence",),
    )


def _decision(
    request: AgentAuthorizationRequest,
    status: AgentAuthorizationStatus,
    *,
    reviewer_agent_id: str = "",
) -> AgentAuthorizationDecision:
    reason = AgentAuthorizationReason.ALLOWED
    if status is AgentAuthorizationStatus.REQUIRE_REVIEW:
        reason = AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE
    elif status is AgentAuthorizationStatus.BLOCK:
        reason = AgentAuthorizationReason.POLICY_FINDING_BLOCKED
    return AgentAuthorizationDecision(
        decision_id=build_decision_id(request, status),
        request=request,
        status=status,
        reasons=(reason,),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id=reviewer_agent_id,
        evidence_artifact_ids=("wave-11-authority-decision",),
    )


def _codes(evaluation: AuthorityEvaluation) -> set[AuthorityFindingCode]:
    return {finding.code for finding in evaluation.findings}
