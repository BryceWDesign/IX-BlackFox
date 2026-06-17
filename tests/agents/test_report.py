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
    AgentProvenanceLedger,
    AgentReadinessFindingCode,
    AgentReadinessStatus,
    AgentRegistry,
    AgentTrustTier,
    CapabilityRiskTier,
    build_agent_readiness_report,
    build_decision_id,
    evaluate_human_authority,
)
from ix_blackfox.operating import OperatingDomain


def test_agent_readiness_report_is_ready_with_registry_authority_and_provenance() -> None:
    model = _agent(
        "model-proposer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.PROPOSE_PATCH,
        CapabilityRiskTier.LOW,
    )
    human = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(model, human))
    request = _request(
        "model-proposer",
        AgentAction.PROPOSE,
        AgentCapability.PROPOSE_PATCH,
        CapabilityRiskTier.LOW,
    )
    decision = _decision(request, AgentAuthorizationStatus.ALLOW)
    ledger = AgentProvenanceLedger(ledger_id="wave-11-ledger").append(
        decision,
        recorded_at="2026-06-15T12:02:00Z",
    )

    report = build_agent_readiness_report(
        registry=registry,
        authorization_decisions=(decision,),
        provenance_ledger=ledger,
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.READY
    assert report.ready is True
    assert report.blocking_findings == ()
    assert report.to_dict()["digest"] == report.digest
    assert report.to_dict()["provenance_record_count"] == 1


def test_agent_readiness_report_blocks_invalid_registry_policy() -> None:
    registry = AgentRegistry(
        registry_id="wave-11",
        agents=(
            _agent(
                "model-approver",
                AgentKind.MODEL_BRAIN,
                AgentTrustTier.GOVERNED_AUTOMATION,
                AgentCapability.APPROVE_RELEASE,
                CapabilityRiskTier.CRITICAL,
                requires_review=True,
            ),
        ),
    )

    report = build_agent_readiness_report(
        registry=registry,
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.BLOCKED
    assert AgentReadinessFindingCode.REGISTRY_POLICY_BLOCKED in _codes(report)
    assert AgentReadinessFindingCode.NO_ACTIVE_HUMAN_AUTHORITY in _codes(report)


def test_agent_readiness_report_blocks_review_decision_without_authority_evaluation() -> None:
    requester = _agent(
        "ci-runner",
        AgentKind.CI_RUNNER,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
        requires_review=True,
    )
    human = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(requester, human))
    request = _request(
        "ci-runner",
        AgentAction.RUN,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
    )
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="release-owner",
    )
    ledger = AgentProvenanceLedger(ledger_id="wave-11-ledger").append(
        decision,
        recorded_at="2026-06-15T12:02:00Z",
    )

    report = build_agent_readiness_report(
        registry=registry,
        authorization_decisions=(decision,),
        provenance_ledger=ledger,
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.BLOCKED
    assert AgentReadinessFindingCode.REVIEW_DECISION_WITHOUT_AUTHORITY_EVALUATION in (
        _codes(report)
    )


def test_agent_readiness_report_blocks_when_authority_is_not_preserved() -> None:
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
    human = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(
        registry_id="wave-11",
        agents=(requester, model_reviewer, human),
    )
    request = _request(
        "ci-runner",
        AgentAction.RUN,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
    )
    decision = _decision(
        request,
        AgentAuthorizationStatus.REQUIRE_REVIEW,
        reviewer_agent_id="model-reviewer",
    )
    authority = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )
    ledger = AgentProvenanceLedger(ledger_id="wave-11-ledger").append(
        decision,
        recorded_at="2026-06-15T12:02:00Z",
    )

    report = build_agent_readiness_report(
        registry=registry,
        authorization_decisions=(decision,),
        authority_evaluations=(authority,),
        provenance_ledger=ledger,
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.BLOCKED
    assert AgentReadinessFindingCode.AUTHORITY_NOT_PRESERVED in _codes(report)


def test_agent_readiness_report_blocks_decision_without_provenance() -> None:
    model = _agent(
        "model-proposer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.PROPOSE_PATCH,
        CapabilityRiskTier.LOW,
    )
    human = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(model, human))
    request = _request(
        "model-proposer",
        AgentAction.PROPOSE,
        AgentCapability.PROPOSE_PATCH,
        CapabilityRiskTier.LOW,
    )
    decision = _decision(request, AgentAuthorizationStatus.ALLOW)

    report = build_agent_readiness_report(
        registry=registry,
        authorization_decisions=(decision,),
        provenance_ledger=AgentProvenanceLedger(ledger_id="empty-ledger"),
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.BLOCKED
    assert AgentReadinessFindingCode.DECISION_WITHOUT_PROVENANCE in _codes(report)


def test_agent_readiness_report_records_blocked_authorization_as_warning_when_provenance_exists() -> None:
    human = _agent(
        "release-owner",
        AgentKind.HUMAN_OPERATOR,
        AgentTrustTier.HUMAN_AUTHORITY,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(human,))
    request = _request(
        "missing-agent",
        AgentAction.RUN,
        AgentCapability.RUN_PROCESS,
        CapabilityRiskTier.HIGH,
    )
    decision = _decision(request, AgentAuthorizationStatus.BLOCK)
    ledger = AgentProvenanceLedger(ledger_id="wave-11-ledger").append(
        decision,
        recorded_at="2026-06-15T12:02:00Z",
    )

    report = build_agent_readiness_report(
        registry=registry,
        authorization_decisions=(decision,),
        provenance_ledger=ledger,
        generated_at="2026-06-15T12:03:00Z",
    )

    assert report.status is AgentReadinessStatus.WARNING
    assert AgentReadinessFindingCode.BLOCKED_AUTHORIZATION_DECISION_RECORDED in (
        _codes(report)
    )
    assert report.blocking_findings == ()


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
                    evidence_artifact_ids=("wave-11-report-test",),
                ),
            ),
        ),
    )


def _request(
    agent_id: str,
    action: AgentAction,
    capability: AgentCapability,
    tier: CapabilityRiskTier,
) -> AgentAuthorizationRequest:
    return AgentAuthorizationRequest(
        request_id=f"{agent_id}-{action.value}-{capability.value}",
        agent_id=agent_id,
        action=action,
        capability=capability,
        target=AgentAuthorizationTarget(
            repository_id="ix-blackfox",
            domain=OperatingDomain.POLICY_GOVERNED,
            risk_tier=tier,
        ),
        requested_at="2026-06-15T12:00:00Z",
        evidence_artifact_ids=("wave-11-report-request",),
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
        reason = AgentAuthorizationReason.UNKNOWN_AGENT
    return AgentAuthorizationDecision(
        decision_id=build_decision_id(request, status),
        request=request,
        status=status,
        reasons=(reason,),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id=reviewer_agent_id,
        evidence_artifact_ids=("wave-11-report-decision",),
    )


def _codes(report: object) -> set[AgentReadinessFindingCode]:
    return {finding.code for finding in report.findings}
