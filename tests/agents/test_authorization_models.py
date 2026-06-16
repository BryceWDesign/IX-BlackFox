from __future__ import annotations

import pytest

from ix_blackfox.agents import (
    AgentAction,
    AgentAuthorizationDecision,
    AgentAuthorizationReason,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
    AgentCapability,
    CapabilityRiskTier,
    build_decision_id,
)
from ix_blackfox.operating import OperatingDomain


def test_authorization_target_normalizes_scope_and_requires_boundary() -> None:
    target = AgentAuthorizationTarget(
        repository_id=" IX BlackFox ",
        domain=OperatingDomain.REVIEWABLE,
        tool_id=" Test Runner ",
        path="src/ix_blackfox/agents/models.py",
        artifact_ids=(" Evidence One ",),
        risk_tier=CapabilityRiskTier.HIGH,
    )

    assert target.repository_id == "IX BlackFox"
    assert target.tool_id == "Test Runner"
    assert target.path == "src/ix_blackfox/agents/models.py"
    assert target.artifact_ids == ("evidence-one",)
    assert target.bounded is True
    assert target.to_dict()["domain"] == "reviewable"

    with pytest.raises(ValueError, match="target must be bounded"):
        AgentAuthorizationRequest(
            request_id="unbounded-request",
            agent_id="model-agent",
            action=AgentAction.PROPOSE,
            capability=AgentCapability.PROPOSE_PATCH,
            target=AgentAuthorizationTarget(),
            requested_at="2026-06-15T12:00:00Z",
        )


def test_authorization_request_is_digest_bound_and_normalized() -> None:
    request = _request()
    same_request = _request(request_id=" propose patch request ")

    assert request.request_id == "propose-patch-request"
    assert request.agent_id == "model-proposer"
    assert request.evidence_artifact_ids == ("evidence-a",)
    assert request.digest == same_request.digest
    assert request.to_dict()["digest"] == request.digest


def test_authorization_decision_requires_reasons_and_review_identity() -> None:
    request = _request()

    with pytest.raises(ValueError, match="reasons must not be empty"):
        AgentAuthorizationDecision(
            decision_id="bad-decision",
            request=request,
            status=AgentAuthorizationStatus.BLOCK,
            reasons=(),
            decided_at="2026-06-15T12:01:00Z",
        )

    with pytest.raises(ValueError, match="must name a reviewer"):
        AgentAuthorizationDecision(
            decision_id="review-decision",
            request=request,
            status=AgentAuthorizationStatus.REQUIRE_REVIEW,
            reasons=(AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE,),
            decided_at="2026-06-15T12:01:00Z",
        )

    with pytest.raises(ValueError, match="must not imply human review"):
        AgentAuthorizationDecision(
            decision_id="allow-decision",
            request=request,
            status=AgentAuthorizationStatus.ALLOW,
            reasons=(AgentAuthorizationReason.ALLOWED,),
            decided_at="2026-06-15T12:01:00Z",
            reviewer_agent_id="human-reviewer",
        )


def test_authorization_decision_flags_and_stable_decision_id() -> None:
    request = _request()
    decision = AgentAuthorizationDecision(
        decision_id=build_decision_id(request, AgentAuthorizationStatus.REQUIRE_REVIEW),
        request=request,
        status=AgentAuthorizationStatus.REQUIRE_REVIEW,
        reasons=(
            AgentAuthorizationReason.EVIDENCE_MISSING,
            AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE,
            AgentAuthorizationReason.EVIDENCE_MISSING,
        ),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id="human-reviewer",
        evidence_artifact_ids=("decision-evidence",),
    )

    assert decision.decision_id.startswith("agent-auth-")
    assert decision.requires_review is True
    assert decision.allowed is False
    assert decision.blocked is False
    assert decision.reasons == (
        AgentAuthorizationReason.EVIDENCE_MISSING,
        AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE,
    )
    assert decision.to_dict()["digest"] == decision.digest


def _request(request_id: str = "propose-patch-request") -> AgentAuthorizationRequest:
    return AgentAuthorizationRequest(
        request_id=request_id,
        agent_id="Model Proposer",
        action=AgentAction.PROPOSE,
        capability=AgentCapability.PROPOSE_PATCH,
        target=AgentAuthorizationTarget(
            repository_id="ix-blackfox",
            domain=OperatingDomain.POLICY_GOVERNED,
            path="src/ix_blackfox/agents",
            risk_tier=CapabilityRiskTier.LOW,
        ),
        requested_at="2026-06-15T12:00:00Z",
        evidence_artifact_ids=("Evidence A",),
        justification="Scoped proposal request.",
    )
