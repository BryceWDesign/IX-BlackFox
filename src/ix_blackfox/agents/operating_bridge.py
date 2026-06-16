from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ix_blackfox.agents.authority import AuthorityEvaluation, AuthorityFinding
from ix_blackfox.agents.authorization import (
    AgentAuthorizationDecision,
    AgentAuthorizationStatus,
)
from ix_blackfox.agents.capabilities import (
    CapabilityFinding,
    CapabilityPolicyResult,
)
from ix_blackfox.agents.provenance import AgentProvenanceRecord
from ix_blackfox.agents.registry import AgentRegistry, AgentRegistrySnapshot
from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
)

WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION = "wave11.agent_operating_bridge.v1"

_AGENT_DOMAINS: tuple[OperatingDomain, ...] = (
    OperatingDomain.MULTI_TEAM,
    OperatingDomain.POLICY_GOVERNED,
    OperatingDomain.REVIEWABLE,
)


def agent_registry_to_operating_envelope(
    registry: AgentRegistry,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> OperatingEnvelope:
    """Export an AgentRegistry snapshot as a Wave 10-compatible envelope."""

    return agent_registry_snapshot_to_operating_envelope(
        registry.snapshot(),
        metadata=metadata,
    )


def agent_registry_snapshot_to_operating_envelope(
    snapshot: AgentRegistrySnapshot,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> OperatingEnvelope:
    """Export an AgentRegistrySnapshot as an operating authority artifact."""

    findings = tuple(
        _finding_from_policy_result(result, finding)
        for result in snapshot.policy_results
        for finding in result.findings
    )
    envelope_metadata: dict[str, Any] = {
        "bridge": "wave11-agent-registry",
        "registry_id": snapshot.registry_id,
        "snapshot_digest": snapshot.digest,
        "ready": snapshot.ready,
        "active_agent_count": snapshot.active_agent_count,
        "revoked_agent_count": snapshot.revoked_agent_count,
        "blocking_finding_count": snapshot.blocking_finding_count,
        "agent_ids": [agent.agent_id for agent in snapshot.agents],
    }
    if metadata:
        envelope_metadata.update(dict(metadata))

    return OperatingEnvelope(
        envelope_id=f"wave11-agent-registry-{snapshot.registry_id}",
        artifact_kind=OperatingArtifactKind.TEAM_AUTHORITY,
        subject=f"Wave 11 agent registry {snapshot.registry_id}",
        schema_version=WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION,
        domains=_AGENT_DOMAINS,
        findings=findings,
        metadata=envelope_metadata,
    )


def authorization_decision_to_operating_envelope(
    decision: AgentAuthorizationDecision,
    *,
    authority_evaluation: AuthorityEvaluation | None = None,
    provenance_record: AgentProvenanceRecord | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> OperatingEnvelope:
    """Export one Wave 11 authorization decision into an operating envelope."""

    findings = list(_findings_from_decision(decision))
    if authority_evaluation is not None:
        findings.extend(_finding_from_authority(item) for item in authority_evaluation.findings)

    envelope_metadata: dict[str, Any] = {
        "bridge": "wave11-agent-authorization",
        "decision_id": decision.decision_id,
        "decision_digest": decision.digest,
        "request_id": decision.request.request_id,
        "request_digest": decision.request.digest,
        "agent_id": decision.request.agent_id,
        "action": decision.request.action.value,
        "capability": decision.request.capability.value,
        "status": decision.status.value,
        "reasons": [reason.value for reason in decision.reasons],
        "reviewer_agent_id": decision.reviewer_agent_id,
        "decision_evidence_artifact_ids": list(decision.evidence_artifact_ids),
    }
    if authority_evaluation is not None:
        envelope_metadata.update(
            {
                "authority_evaluation_digest": authority_evaluation.digest,
                "authority_preserved": authority_evaluation.authority_preserved,
            }
        )
    if provenance_record is not None:
        envelope_metadata.update(
            {
                "provenance_record_id": provenance_record.record_id,
                "provenance_record_digest": provenance_record.record_digest,
                "provenance_chain_digest": provenance_record.chain_digest,
            }
        )
    if metadata:
        envelope_metadata.update(dict(metadata))

    return OperatingEnvelope(
        envelope_id=f"wave11-agent-authorization-{decision.decision_id}",
        artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
        subject=f"Wave 11 authorization decision {decision.decision_id}",
        schema_version=WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION,
        domains=_AGENT_DOMAINS,
        findings=tuple(findings),
        metadata=envelope_metadata,
    )


def provenance_record_to_operating_envelope(
    record: AgentProvenanceRecord,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> OperatingEnvelope:
    """Export one provenance record as an operating evidence artifact."""

    envelope_metadata: dict[str, Any] = {
        "bridge": "wave11-agent-provenance",
        "record_id": record.record_id,
        "record_digest": record.record_digest,
        "decision_id": record.decision.decision_id,
        "decision_digest": record.decision_digest,
        "chain_digest": record.chain_digest,
        "previous_chain_digest": record.previous_chain_digest,
        "agent_id": record.agent_id,
    }
    if metadata:
        envelope_metadata.update(dict(metadata))

    return OperatingEnvelope(
        envelope_id=f"wave11-agent-provenance-{record.record_id}",
        artifact_kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        subject=f"Wave 11 agent provenance {record.record_id}",
        schema_version=WAVE11_OPERATING_BRIDGE_SCHEMA_VERSION,
        domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REPLAYABLE),
        metadata=envelope_metadata,
    )


def _finding_from_policy_result(
    result: CapabilityPolicyResult,
    finding: CapabilityFinding,
) -> OperatingFinding:
    return OperatingFinding(
        code=f"wave11.agent_registry.{finding.code.value}",
        severity=OperatingSeverity.CRITICAL if finding.blocking else OperatingSeverity.MEDIUM,
        summary=finding.summary,
        domains=_AGENT_DOMAINS,
        blocking=finding.blocking,
        metadata={
            "agent_id": result.agent_id,
            "grant_id": finding.grant_id,
            "capability": finding.capability.value if finding.capability else "",
        },
    )


def _findings_from_decision(
    decision: AgentAuthorizationDecision,
) -> tuple[OperatingFinding, ...]:
    if decision.status is AgentAuthorizationStatus.ALLOW:
        return ()

    blocking = decision.status is AgentAuthorizationStatus.BLOCK
    severity = OperatingSeverity.CRITICAL if blocking else OperatingSeverity.MEDIUM
    return (
        OperatingFinding(
            code=f"wave11.agent_authorization.{decision.status.value}",
            severity=severity,
            summary=(
                "Wave 11 authorization blocked the requested actor capability."
                if blocking
                else "Wave 11 authorization requires human review before action."
            ),
            domains=_AGENT_DOMAINS,
            blocking=blocking,
            metadata={
                "decision_id": decision.decision_id,
                "request_id": decision.request.request_id,
                "agent_id": decision.request.agent_id,
                "capability": decision.request.capability.value,
                "reasons": [reason.value for reason in decision.reasons],
            },
        ),
    )


def _finding_from_authority(finding: AuthorityFinding) -> OperatingFinding:
    return OperatingFinding(
        code=f"wave11.agent_authority.{finding.code.value}",
        severity=OperatingSeverity.CRITICAL if finding.blocking else OperatingSeverity.INFO,
        summary=finding.summary,
        domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
        blocking=finding.blocking,
        metadata={
            "agent_id": finding.agent_id,
        },
    )
