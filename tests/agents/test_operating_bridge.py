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
    AgentRegistry,
    AgentTrustTier,
    AuthorityFindingCode,
    CapabilityRiskTier,
    WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION,
    agent_registry_to_operating_envelope,
    authorization_decision_to_operating_envelope,
    build_decision_id,
    evaluate_human_authority,
    provenance_record_to_operating_envelope,
)
from ix_blackfox.operating import OperatingArtifactKind, OperatingDisposition, OperatingDomain


def test_agent_registry_exports_ready_operating_envelope() -> None:
    registry = AgentRegistry(
        registry_id="wave-11",
        agents=(
            _agent(
                "release-owner",
                AgentKind.HUMAN_OPERATOR,
                AgentTrustTier.HUMAN_AUTHORITY,
                AgentCapability.APPROVE_RELEASE,
                CapabilityRiskTier.CRITICAL,
            ),
        ),
    )

    envelope = agent_registry_to_operating_envelope(registry)

    assert envelope.schema_version == WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION
    assert envelope.artifact_kind is OperatingArtifactKind.TEAM_AUTHORITY
    assert envelope.disposition is OperatingDisposition.READY
    assert envelope.metadata["ready"] is True
    assert envelope.metadata["active_agent_count"] == 1
    assert envelope.metadata["agent_ids"] == ["release-owner"]


def test_agent_registry_envelope_blocks_policy_invalid_agent() -> None:
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

    envelope = agent_registry_to_operating_envelope(registry)

    assert envelope.disposition is OperatingDisposition.BLOCKED
    assert envelope.blocking_findings
    assert envelope.metadata["blocking_finding_count"] >= 1
    assert envelope.metadata["ready"] is False


def test_authorization_decision_envelope_reports_review_and_authority() -> None:
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
    authority = evaluate_human_authority(
        registry=registry,
        request=request,
        decision=decision,
    )

    envelope = authorization_decision_to_operating_envelope(
        decision,
        authority_evaluation=authority,
    )

    assert envelope.artifact_kind is OperatingArtifactKind.POLICY_EVALUATION
    assert envelope.disposition is OperatingDisposition.WARNING
    assert envelope.metadata["status"] == "require_review"
    assert envelope.metadata["authority_preserved"] is True
    assert envelope.metadata["reviewer_agent_id"] == "release-owner"
    assert not envelope.blocking_findings


def test_authorization_decision_envelope_blocks_failed_authority() -> None:
    requester = _agent(
        "model-approver",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.REVIEW_PATCH,
        CapabilityRiskTier.MEDIUM,
    )
    reviewer = _agent(
        "model-reviewer",
        AgentKind.MODEL_BRAIN,
        AgentTrustTier.GOVERNED_AUTOMATION,
        AgentCapability.REVIEW_PATCH,
        CapabilityRiskTier.MEDIUM,
    )
    registry = AgentRegistry(registry_id="wave-11", agents=(requester, reviewer))
    request = _request(
        "model-approver",
        AgentAction.APPROVE,
        AgentCapability.APPROVE_RELEASE,
        CapabilityRiskTier.CRITICAL,
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

    envelope = authorization_decision_to_operating_envelope(
        decision,
        authority_evaluation=authority,
    )

    assert AuthorityFindingCode.REVIEWER_NOT_HUMAN_AUTHORITY.value in {
        finding.code.split(".")[-1] for finding in envelope.findings
    }
    assert envelope.disposition is OperatingDisposition.BLOCKED
    assert envelope.blocking_findings
    assert envelope.metadata["authority_preserved"] is False


def test_provenance_record_exports_replayable_operating_envelope() -> None:
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
    record = ledger.records[0]

    envelope = provenance_record_to_operating_envelope(record)

    assert envelope.artifact_kind is OperatingArtifactKind.EVIDENCE_MANIFEST
    assert envelope.disposition is OperatingDisposition.READY
    assert envelope.metadata["record_id"] == record.record_id
    assert envelope.metadata["chain_digest"] == record.chain_digest
    assert envelope.metadata["decision_digest"] == decision.digest


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
                    evidence_artifact_ids=("wave-11-operating-bridge-test",),
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
        evidence_artifact_ids=("wave-11-operating-bridge-evidence",),
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
        evidence_artifact_ids=("wave-11-operating-bridge-decision",),
    )
