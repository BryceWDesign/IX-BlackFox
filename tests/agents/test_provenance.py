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
    AgentProvenanceLedger,
    AgentProvenanceRecord,
    CapabilityRiskTier,
    build_decision_id,
    build_provenance_record_id,
)
from ix_blackfox.operating import OperatingDomain


def test_provenance_record_binds_decision_and_evidence_hashes() -> None:
    decision = _decision("model-proposer", AgentAuthorizationStatus.ALLOW)
    record = AgentProvenanceRecord(
        record_id=build_provenance_record_id(decision, 0),
        decision=decision,
        recorded_at="2026-06-15T12:02:00Z",
        evidence_artifact_ids=("extra-evidence",),
    )

    payload = record.to_dict()

    assert record.agent_id == "model-proposer"
    assert payload["request_id"] == decision.request.request_id
    assert payload["decision_id"] == decision.decision_id
    assert payload["decision_digest"] == decision.digest
    assert "decision-evidence" in payload["evidence_artifact_ids"]
    assert "extra-evidence" in payload["evidence_artifact_ids"]
    assert record.chain_digest == payload["chain_digest"]


def test_provenance_ledger_appends_records_with_chain_digest() -> None:
    first = _decision("model-proposer", AgentAuthorizationStatus.ALLOW)
    second = _decision("ci-runner", AgentAuthorizationStatus.REQUIRE_REVIEW)

    ledger = AgentProvenanceLedger(ledger_id="Wave 11 Ledger")
    ledger = ledger.append(first, recorded_at="2026-06-15T12:02:00Z")
    ledger = ledger.append(
        second,
        recorded_at="2026-06-15T12:03:00Z",
        evidence_artifact_ids=("review-evidence",),
    )

    assert ledger.ledger_id == "wave-11-ledger"
    assert ledger.record_count == 2
    assert ledger.chain_valid is True
    assert ledger.records[0].previous_chain_digest == ""
    assert ledger.records[1].previous_chain_digest == ledger.records[0].chain_digest
    assert ledger.head_digest == ledger.records[1].chain_digest
    assert ledger.to_dict()["digest"] == ledger.digest


def test_provenance_ledger_rejects_tampered_previous_digest() -> None:
    first = _decision("model-proposer", AgentAuthorizationStatus.ALLOW)
    second = _decision("ci-runner", AgentAuthorizationStatus.REQUIRE_REVIEW)
    first_record = AgentProvenanceRecord(
        record_id=build_provenance_record_id(first, 0),
        decision=first,
        recorded_at="2026-06-15T12:02:00Z",
    )
    tampered_second = AgentProvenanceRecord(
        record_id=build_provenance_record_id(second, 1),
        decision=second,
        recorded_at="2026-06-15T12:03:00Z",
        previous_chain_digest="not-the-prior-head",
    )

    with pytest.raises(ValueError, match="previous digest mismatch"):
        AgentProvenanceLedger(
            ledger_id="wave-11-ledger",
            records=(first_record, tampered_second),
        )


def test_provenance_ledger_rejects_duplicate_record_ids() -> None:
    decision = _decision("model-proposer", AgentAuthorizationStatus.ALLOW)
    record = AgentProvenanceRecord(
        record_id=build_provenance_record_id(decision, 0),
        decision=decision,
        recorded_at="2026-06-15T12:02:00Z",
    )
    duplicate = AgentProvenanceRecord(
        record_id=record.record_id,
        decision=decision,
        recorded_at="2026-06-15T12:03:00Z",
        previous_chain_digest=record.chain_digest,
    )

    with pytest.raises(ValueError, match="duplicate provenance record id"):
        AgentProvenanceLedger(
            ledger_id="wave-11-ledger",
            records=(record, duplicate),
        )


def test_build_provenance_record_id_rejects_negative_sequence() -> None:
    decision = _decision("model-proposer", AgentAuthorizationStatus.ALLOW)

    with pytest.raises(ValueError, match="sequence_index"):
        build_provenance_record_id(decision, -1)


def _decision(
    agent_id: str,
    status: AgentAuthorizationStatus,
) -> AgentAuthorizationDecision:
    request = AgentAuthorizationRequest(
        request_id=f"{agent_id}-{status.value}",
        agent_id=agent_id,
        action=AgentAction.PROPOSE,
        capability=AgentCapability.PROPOSE_PATCH,
        target=AgentAuthorizationTarget(
            repository_id="ix-blackfox",
            domain=OperatingDomain.POLICY_GOVERNED,
            path="src/ix_blackfox/agents",
            risk_tier=CapabilityRiskTier.LOW,
        ),
        requested_at="2026-06-15T12:00:00Z",
        evidence_artifact_ids=("request-evidence",),
    )
    reviewer = ""
    reason = AgentAuthorizationReason.ALLOWED
    if status is AgentAuthorizationStatus.REQUIRE_REVIEW:
        reviewer = "release-owner"
        reason = AgentAuthorizationReason.REVIEW_REQUIRED_BY_SCOPE
    elif status is AgentAuthorizationStatus.BLOCK:
        reason = AgentAuthorizationReason.POLICY_FINDING_BLOCKED
    return AgentAuthorizationDecision(
        decision_id=build_decision_id(request, status),
        request=request,
        status=status,
        reasons=(reason,),
        decided_at="2026-06-15T12:01:00Z",
        reviewer_agent_id=reviewer,
        evidence_artifact_ids=("decision-evidence",),
    )
