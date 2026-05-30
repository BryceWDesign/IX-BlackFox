from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    AssuranceClaimMapping,
    ControlObjectiveMapping,
    HazardControlMapping,
    OperatingDisposition,
    OperatingDomain,
    OperatingSeverity,
    OperatingTraceEdge,
    OperatingTraceNode,
    OperatingTraceabilityMap,
    TraceEdgeKind,
    TraceNodeKind,
)


def test_traceability_map_is_deterministic_and_ready_with_bounded_claims() -> None:
    traceability = _ready_traceability_map()
    same_traceability = OperatingTraceabilityMap(
        traceability_id="wave-10-traceability",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        nodes=tuple(reversed(_ready_nodes())),
        edges=tuple(reversed(_ready_edges())),
        claim_mappings=_ready_claim_mappings(),
        control_mappings=_ready_control_mappings(),
        hazard_mappings=_ready_hazard_mappings(),
    )

    assert traceability.traceability_id == "wave-10-traceability"
    assert traceability.registry_id == "wave-10-registry"
    assert traceability.campaign_id == "wave-10-campaign"
    assert traceability.node_kind_counts["mission_need"] == 1
    assert traceability.evidence_artifact_ids == (
        "human-review-record",
        "wave9-governance-report",
    )
    assert traceability.missing_required_node_kinds == ()
    assert traceability.unsupported_claim_ids == ()
    assert traceability.missing_human_review_claim_ids == ()
    assert traceability.unmapped_control_ids == ()
    assert traceability.unaccepted_high_risk_hazard_ids == ()
    assert traceability.findings == ()
    assert traceability.to_envelope().disposition is OperatingDisposition.READY
    assert traceability.to_dict()["digest"] == same_traceability.to_dict()["digest"]


def test_traceability_map_blocks_missing_required_node_kinds_and_unsupported_claim() -> None:
    traceability = OperatingTraceabilityMap(
        traceability_id="unsupported-claim",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        nodes=(
            OperatingTraceNode(
                node_id="claim",
                kind=TraceNodeKind.ASSURANCE_CLAIM,
                title="Unsupported claim",
                summary="A claim without the required graph context.",
            ),
        ),
        edges=(),
        claim_mappings=(
            AssuranceClaimMapping(
                claim_id="unsupported",
                claim_node_id="claim",
                bounded_claim="This claim is not yet supported by evidence.",
                supporting_node_ids=("claim",),
                required_evidence_artifact_ids=("missing-evidence",),
            ),
        ),
    )

    finding_codes = {finding.code for finding in traceability.findings}
    missing_kinds = {
        finding.metadata.get("node_kind") for finding in traceability.findings
    }
    assert "operating.traceability.missing-required-node-kind" in finding_codes
    assert "operating.traceability.unsupported-assurance-claim" in finding_codes
    assert "operating.traceability.claim-missing-human-review" in finding_codes
    assert {"mission_need", "requirement", "control", "evidence", "human_review"} <= missing_kinds
    assert traceability.unsupported_claim_ids == ("unsupported",)
    assert traceability.missing_human_review_claim_ids == ("unsupported",)
    assert traceability.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_traceability_map_blocks_control_evidence_and_high_risk_acceptance_gaps() -> None:
    nodes = _ready_nodes()
    traceability = OperatingTraceabilityMap(
        traceability_id="mapping-gaps",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        nodes=nodes,
        edges=_ready_edges(),
        claim_mappings=_ready_claim_mappings(),
        control_mappings=(
            ControlObjectiveMapping(
                control_id="missing-control-evidence",
                control_node_id="human-authority-control",
                objective="Require evidence for human authority control.",
                requirement_node_ids=("human-authority-requirement",),
                evidence_artifact_ids=("missing-control-evidence",),
                owner_team_id="platform-security",
            ),
        ),
        hazard_mappings=(
            HazardControlMapping(
                hazard_id="unaccepted-high-risk",
                hazard_node_id="self-approval-hazard",
                control_node_ids=("human-authority-control",),
                mitigation_summary="Block self approval and require human review.",
                evidence_artifact_ids=("wave9-governance-report",),
                residual_risk=OperatingSeverity.HIGH,
            ),
        ),
    )

    finding_codes = {finding.code for finding in traceability.findings}
    assert "operating.traceability.control-missing-evidence" in finding_codes
    assert "operating.traceability.high-risk-hazard-not-human-accepted" in finding_codes
    assert traceability.unmapped_control_ids == ("missing-control-evidence",)
    assert traceability.unaccepted_high_risk_hazard_ids == ("unaccepted-high-risk",)
    assert traceability.to_dict()["disposition"] == "blocked"


def test_traceability_map_blocks_required_edges_without_evidence_binding() -> None:
    edges = (
        OperatingTraceEdge(
            edge_id="approval-without-evidence",
            source_node_id="human-review",
            target_node_id="bounded-operating-claim",
            kind=TraceEdgeKind.APPROVED_BY,
            rationale="Human review must be evidence-bound.",
            evidence_artifact_ids=(),
        ),
        *_ready_edges(),
    )
    traceability = OperatingTraceabilityMap(
        traceability_id="edge-gap",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        nodes=_ready_nodes(),
        edges=edges,
        claim_mappings=_ready_claim_mappings(),
        control_mappings=_ready_control_mappings(),
        hazard_mappings=_ready_hazard_mappings(),
    )

    assert "operating.traceability.required-edge-missing-evidence" in {
        finding.code for finding in traceability.findings
    }
    assert traceability.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_traceability_map_rejects_unknown_edges_and_wrong_mapping_node_kind() -> None:
    with pytest.raises(ValueError, match="unknown node"):
        OperatingTraceabilityMap(
            traceability_id="unknown-edge",
            registry_id="wave-10-registry",
            campaign_id="wave-10-campaign",
            nodes=_ready_nodes(),
            edges=(
                OperatingTraceEdge(
                    edge_id="unknown",
                    source_node_id="missing",
                    target_node_id="bounded-operating-claim",
                    kind=TraceEdgeKind.SUPPORTS,
                    rationale="Unknown edges are invalid.",
                ),
            ),
            claim_mappings=_ready_claim_mappings(),
        )

    with pytest.raises(ValueError, match="must be kind assurance_claim"):
        OperatingTraceabilityMap(
            traceability_id="wrong-kind",
            registry_id="wave-10-registry",
            campaign_id="wave-10-campaign",
            nodes=_ready_nodes(),
            edges=_ready_edges(),
            claim_mappings=(
                AssuranceClaimMapping(
                    claim_id="wrong-kind",
                    claim_node_id="human-authority-requirement",
                    bounded_claim="This should fail because requirements are not claims.",
                    supporting_node_ids=("human-authority-requirement",),
                    required_evidence_artifact_ids=("wave9-governance-report",),
                ),
            ),
        )


def test_traceability_node_and_edge_reject_empty_scope_and_self_edge() -> None:
    with pytest.raises(ValueError, match="summary must not be empty"):
        OperatingTraceNode(
            node_id="bad-node",
            kind=TraceNodeKind.REQUIREMENT,
            title="Bad node",
            summary=" ",
        )

    with pytest.raises(ValueError, match="cannot target the source"):
        OperatingTraceEdge(
            edge_id="self-edge",
            source_node_id="same",
            target_node_id="same",
            kind=TraceEdgeKind.SUPPORTS,
            rationale="Self edges do not add traceability.",
        )


def _ready_traceability_map() -> OperatingTraceabilityMap:
    return OperatingTraceabilityMap(
        traceability_id=" Wave 10 Traceability ",
        registry_id="Wave 10 Registry",
        campaign_id="Wave 10 Campaign",
        nodes=_ready_nodes(),
        edges=_ready_edges(),
        claim_mappings=_ready_claim_mappings(),
        control_mappings=_ready_control_mappings(),
        hazard_mappings=_ready_hazard_mappings(),
    )


def _ready_nodes() -> tuple[OperatingTraceNode, ...]:
    return (
        OperatingTraceNode(
            node_id="mission-need",
            kind=TraceNodeKind.MISSION_NEED,
            title="Govern AI-assisted code change",
            summary="Make AI-assisted engineering changes inspectable, replayable, and human-authorized.",
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
            repository_ids=("ix-blackfox",),
        ),
        OperatingTraceNode(
            node_id="human-authority-requirement",
            kind=TraceNodeKind.REQUIREMENT,
            title="Human authority is mandatory",
            summary="Final operating disposition requires human authority and separation of duties.",
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
            repository_ids=("ix-blackfox",),
        ),
        OperatingTraceNode(
            node_id="wave10-review-scenario",
            kind=TraceNodeKind.SCENARIO,
            title="Wave 10 review scenario",
            summary="A reviewer evaluates registry, campaign, evidence, replay, and traceability evidence.",
            domains=(OperatingDomain.REVIEWABLE,),
        ),
        OperatingTraceNode(
            node_id="self-approval-hazard",
            kind=TraceNodeKind.HAZARD,
            title="Self approval hazard",
            summary="The same actor or model attempts to author and approve a change.",
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
        ),
        OperatingTraceNode(
            node_id="human-authority-control",
            kind=TraceNodeKind.CONTROL,
            title="Human authority control",
            summary="Block model/system/self approval and require digest-bound human review.",
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.POLICY_GOVERNED),
            artifact_ids=("wave9-governance-report",),
            owner_team_id="Platform Security",
        ),
        OperatingTraceNode(
            node_id="governance-evidence",
            kind=TraceNodeKind.EVIDENCE,
            title="Wave 9 governance evidence",
            summary="Governance report and review record attached to the assurance claim.",
            artifact_ids=("wave9-governance-report", "human-review-record"),
        ),
        OperatingTraceNode(
            node_id="human-review",
            kind=TraceNodeKind.HUMAN_REVIEW,
            title="Digest-bound human review",
            summary="Human reviewer evaluates the bundle before any final operating claim.",
            artifact_ids=("human-review-record",),
            owner_team_id="Platform Security",
        ),
        OperatingTraceNode(
            node_id="bounded-operating-claim",
            kind=TraceNodeKind.ASSURANCE_CLAIM,
            title="Bounded Wave 10 operating claim",
            summary="The campaign is traceable, evidence-bound, and reviewable, not certified or autonomous.",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
        ),
    )


def _ready_edges() -> tuple[OperatingTraceEdge, ...]:
    return (
        OperatingTraceEdge(
            edge_id="requirement-satisfies-mission",
            source_node_id="human-authority-requirement",
            target_node_id="mission-need",
            kind=TraceEdgeKind.SATISFIES,
            rationale="Human authority satisfies the mission need for governed AI-assisted engineering.",
        ),
        OperatingTraceEdge(
            edge_id="scenario-tests-requirement",
            source_node_id="wave10-review-scenario",
            target_node_id="human-authority-requirement",
            kind=TraceEdgeKind.TESTED_BY,
            rationale="The review scenario tests whether the human-authority requirement is met.",
            evidence_artifact_ids=("wave9-governance-report",),
        ),
        OperatingTraceEdge(
            edge_id="control-mitigates-hazard",
            source_node_id="human-authority-control",
            target_node_id="self-approval-hazard",
            kind=TraceEdgeKind.MITIGATED_BY,
            rationale="The control mitigates the self-approval hazard.",
            evidence_artifact_ids=("wave9-governance-report",),
        ),
        OperatingTraceEdge(
            edge_id="evidence-supports-control",
            source_node_id="governance-evidence",
            target_node_id="human-authority-control",
            kind=TraceEdgeKind.EVIDENCED_BY,
            rationale="Governance evidence supports the human-authority control.",
            evidence_artifact_ids=("wave9-governance-report",),
        ),
        OperatingTraceEdge(
            edge_id="human-review-approves-claim",
            source_node_id="human-review",
            target_node_id="bounded-operating-claim",
            kind=TraceEdgeKind.APPROVED_BY,
            rationale="The bounded claim is approved only through digest-bound human review.",
            evidence_artifact_ids=("human-review-record",),
        ),
        OperatingTraceEdge(
            edge_id="control-supports-claim",
            source_node_id="human-authority-control",
            target_node_id="bounded-operating-claim",
            kind=TraceEdgeKind.SUPPORTS,
            rationale="The control supports the bounded assurance claim.",
            evidence_artifact_ids=("wave9-governance-report",),
        ),
    )


def _ready_claim_mappings() -> tuple[AssuranceClaimMapping, ...]:
    return (
        AssuranceClaimMapping(
            claim_id="bounded-wave10-operating-claim",
            claim_node_id="bounded-operating-claim",
            bounded_claim="Wave 10 evidence is traceable, reviewable, and human-authorized for this campaign scope only.",
            supporting_node_ids=("mission-need", "human-authority-control", "governance-evidence"),
            required_evidence_artifact_ids=("wave9-governance-report", "human-review-record"),
            required_human_review_node_ids=("human-review",),
            forbidden_claims=("certified compliant", "autonomous authority", "DoD approved"),
        ),
    )


def _ready_control_mappings() -> tuple[ControlObjectiveMapping, ...]:
    return (
        ControlObjectiveMapping(
            control_id="human-authority-control",
            control_node_id="human-authority-control",
            objective="Prevent model, system, or self approval from satisfying final review authority.",
            requirement_node_ids=("human-authority-requirement",),
            evidence_artifact_ids=("wave9-governance-report",),
            owner_team_id="platform-security",
        ),
    )


def _ready_hazard_mappings() -> tuple[HazardControlMapping, ...]:
    return (
        HazardControlMapping(
            hazard_id="self-approval-hazard",
            hazard_node_id="self-approval-hazard",
            control_node_ids=("human-authority-control",),
            mitigation_summary="Block model/system/self approval and require human review.",
            evidence_artifact_ids=("wave9-governance-report",),
            residual_risk=OperatingSeverity.HIGH,
            accepted_by_human_review_node_ids=("human-review",),
        ),
    )
