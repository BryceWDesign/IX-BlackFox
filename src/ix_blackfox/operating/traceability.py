from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple, normalize_text_tuple


class TraceNodeKind(StrEnum):
    """Node families used by the Wave 10 assurance traceability graph."""

    MISSION_NEED = auto()
    REQUIREMENT = auto()
    SCENARIO = auto()
    HAZARD = auto()
    CONTROL = auto()
    EVIDENCE = auto()
    HUMAN_REVIEW = auto()
    ASSURANCE_CLAIM = auto()
    OPERATING_DECISION = auto()
    REPOSITORY = auto()
    WORK_PACKAGE = auto()


class TraceEdgeKind(StrEnum):
    """Typed relation between two assurance traceability nodes."""

    DERIVED_FROM = auto()
    SATISFIES = auto()
    TESTED_BY = auto()
    MITIGATED_BY = auto()
    EVIDENCED_BY = auto()
    APPROVED_BY = auto()
    SUPPORTS = auto()
    CONSTRAINS = auto()
    DEPENDS_ON = auto()
    BLOCKS = auto()


@dataclass(frozen=True, slots=True)
class OperatingTraceNode:
    """A reviewable node in the Wave 10 assurance traceability graph."""

    node_id: str
    kind: TraceNodeKind
    title: str
    summary: str
    domains: tuple[OperatingDomain, ...] = ()
    repository_ids: tuple[str, ...] = ()
    work_package_ids: tuple[str, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    owner_team_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", normalize_identifier(self.node_id, label="node_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(
            self,
            "work_package_ids",
            normalize_identifier_tuple(self.work_package_ids, label="work_package_ids"),
        )
        object.__setattr__(
            self,
            "artifact_ids",
            normalize_identifier_tuple(self.artifact_ids, label="artifact_ids"),
        )
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_optional_text(self.owner_team_id, label="owner_team_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "title": self.title,
            "summary": self.summary,
            "domains": [domain.value for domain in self.domains],
            "repository_ids": list(self.repository_ids),
            "work_package_ids": list(self.work_package_ids),
            "artifact_ids": list(self.artifact_ids),
            "owner_team_id": self.owner_team_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingTraceEdge:
    """Directed traceability relation between two assurance nodes."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    kind: TraceEdgeKind
    rationale: str
    required: bool = True
    evidence_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_id", normalize_identifier(self.edge_id, label="edge_id"))
        object.__setattr__(
            self,
            "source_node_id",
            normalize_identifier(self.source_node_id, label="source_node_id"),
        )
        object.__setattr__(
            self,
            "target_node_id",
            normalize_identifier(self.target_node_id, label="target_node_id"),
        )
        if self.source_node_id == self.target_node_id:
            raise ValueError("OperatingTraceEdge cannot target the source node.")
        object.__setattr__(self, "rationale", normalize_text(self.rationale, label="rationale"))
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_bound(self) -> bool:
        return bool(self.evidence_artifact_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "kind": self.kind.value,
            "rationale": self.rationale,
            "required": self.required,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "evidence_bound": self.evidence_bound,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssuranceClaimMapping:
    """Bounded assurance claim mapped to supporting nodes and required evidence."""

    claim_id: str
    claim_node_id: str
    bounded_claim: str
    supporting_node_ids: tuple[str, ...]
    required_evidence_artifact_ids: tuple[str, ...]
    required_human_review_node_ids: tuple[str, ...] = ()
    forbidden_claims: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", normalize_identifier(self.claim_id, label="claim_id"))
        object.__setattr__(
            self,
            "claim_node_id",
            normalize_identifier(self.claim_node_id, label="claim_node_id"),
        )
        object.__setattr__(
            self,
            "bounded_claim",
            normalize_text(self.bounded_claim, label="bounded_claim"),
        )
        if not self.supporting_node_ids:
            raise ValueError("AssuranceClaimMapping supporting_node_ids must not be empty.")
        if not self.required_evidence_artifact_ids:
            raise ValueError(
                "AssuranceClaimMapping required_evidence_artifact_ids must not be empty."
            )
        object.__setattr__(
            self,
            "supporting_node_ids",
            normalize_identifier_tuple(self.supporting_node_ids, label="supporting_node_ids"),
        )
        object.__setattr__(
            self,
            "required_evidence_artifact_ids",
            normalize_identifier_tuple(
                self.required_evidence_artifact_ids,
                label="required_evidence_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "required_human_review_node_ids",
            normalize_identifier_tuple(
                self.required_human_review_node_ids,
                label="required_human_review_node_ids",
            ),
        )
        object.__setattr__(
            self,
            "forbidden_claims",
            normalize_text_tuple(self.forbidden_claims, label="forbidden_claims"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_node_id": self.claim_node_id,
            "bounded_claim": self.bounded_claim,
            "supporting_node_ids": list(self.supporting_node_ids),
            "required_evidence_artifact_ids": list(self.required_evidence_artifact_ids),
            "required_human_review_node_ids": list(self.required_human_review_node_ids),
            "forbidden_claims": list(self.forbidden_claims),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ControlObjectiveMapping:
    """Control objective mapped to requirements and evidence."""

    control_id: str
    control_node_id: str
    objective: str
    requirement_node_ids: tuple[str, ...]
    evidence_artifact_ids: tuple[str, ...]
    owner_team_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_id", normalize_identifier(self.control_id, label="control_id"))
        object.__setattr__(
            self,
            "control_node_id",
            normalize_identifier(self.control_node_id, label="control_node_id"),
        )
        object.__setattr__(self, "objective", normalize_text(self.objective, label="objective"))
        if not self.requirement_node_ids:
            raise ValueError("ControlObjectiveMapping requirement_node_ids must not be empty.")
        if not self.evidence_artifact_ids:
            raise ValueError("ControlObjectiveMapping evidence_artifact_ids must not be empty.")
        object.__setattr__(
            self,
            "requirement_node_ids",
            normalize_identifier_tuple(self.requirement_node_ids, label="requirement_node_ids"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(
            self,
            "owner_team_id",
            normalize_identifier(self.owner_team_id, label="owner_team_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_node_id": self.control_node_id,
            "objective": self.objective,
            "requirement_node_ids": list(self.requirement_node_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "owner_team_id": self.owner_team_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class HazardControlMapping:
    """Hazard-to-control trace used to keep Wave 10 claims bounded."""

    hazard_id: str
    hazard_node_id: str
    control_node_ids: tuple[str, ...]
    mitigation_summary: str
    evidence_artifact_ids: tuple[str, ...]
    residual_risk: OperatingSeverity = OperatingSeverity.MEDIUM
    accepted_by_human_review_node_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "hazard_id", normalize_identifier(self.hazard_id, label="hazard_id"))
        object.__setattr__(
            self,
            "hazard_node_id",
            normalize_identifier(self.hazard_node_id, label="hazard_node_id"),
        )
        if not self.control_node_ids:
            raise ValueError("HazardControlMapping control_node_ids must not be empty.")
        if not self.evidence_artifact_ids:
            raise ValueError("HazardControlMapping evidence_artifact_ids must not be empty.")
        object.__setattr__(
            self,
            "control_node_ids",
            normalize_identifier_tuple(self.control_node_ids, label="control_node_ids"),
        )
        object.__setattr__(
            self,
            "mitigation_summary",
            normalize_text(self.mitigation_summary, label="mitigation_summary"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(
            self,
            "accepted_by_human_review_node_ids",
            normalize_identifier_tuple(
                self.accepted_by_human_review_node_ids,
                label="accepted_by_human_review_node_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def requires_human_risk_acceptance(self) -> bool:
        return self.residual_risk in {OperatingSeverity.HIGH, OperatingSeverity.CRITICAL}

    def to_dict(self) -> dict[str, Any]:
        return {
            "hazard_id": self.hazard_id,
            "hazard_node_id": self.hazard_node_id,
            "control_node_ids": list(self.control_node_ids),
            "mitigation_summary": self.mitigation_summary,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "residual_risk": self.residual_risk.value,
            "accepted_by_human_review_node_ids": list(self.accepted_by_human_review_node_ids),
            "requires_human_risk_acceptance": self.requires_human_risk_acceptance,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingTraceabilityMap:
    """Wave 10 assurance traceability graph for bounded operating claims."""

    traceability_id: str
    registry_id: str
    campaign_id: str
    nodes: tuple[OperatingTraceNode, ...]
    edges: tuple[OperatingTraceEdge, ...]
    claim_mappings: tuple[AssuranceClaimMapping, ...]
    control_mappings: tuple[ControlObjectiveMapping, ...] = ()
    hazard_mappings: tuple[HazardControlMapping, ...] = ()
    required_node_kinds: tuple[TraceNodeKind, ...] = (
        TraceNodeKind.MISSION_NEED,
        TraceNodeKind.REQUIREMENT,
        TraceNodeKind.CONTROL,
        TraceNodeKind.EVIDENCE,
        TraceNodeKind.HUMAN_REVIEW,
        TraceNodeKind.ASSURANCE_CLAIM,
    )
    generated_by: str = "IX-BlackFox Wave 10 assurance traceability map"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "traceability_id",
            normalize_identifier(self.traceability_id, label="traceability_id"),
        )
        object.__setattr__(self, "registry_id", normalize_identifier(self.registry_id, label="registry_id"))
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
        if not self.nodes:
            raise ValueError("OperatingTraceabilityMap nodes must not be empty.")
        if not self.claim_mappings:
            raise ValueError("OperatingTraceabilityMap claim_mappings must not be empty.")
        nodes = tuple(sorted(self.nodes, key=lambda node: node.node_id))
        node_ids = [node.node_id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("OperatingTraceabilityMap node_id values must be unique.")
        object.__setattr__(self, "nodes", nodes)
        registered_nodes = set(node_ids)
        edges = tuple(sorted(self.edges, key=lambda edge: edge.edge_id))
        edge_ids = [edge.edge_id for edge in edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("OperatingTraceabilityMap edge_id values must be unique.")
        for edge in edges:
            missing = {edge.source_node_id, edge.target_node_id} - registered_nodes
            if missing:
                missing_text = ", ".join(sorted(missing))
                raise ValueError(f"trace edge references unknown node: {missing_text}")
        object.__setattr__(self, "edges", edges)
        object.__setattr__(
            self,
            "claim_mappings",
            sort_unique_by_id(self.claim_mappings, attribute="claim_id", label="claim_id"),
        )
        object.__setattr__(
            self,
            "control_mappings",
            sort_unique_by_id(
                self.control_mappings,
                attribute="control_id",
                label="control_id",
            ),
        )
        object.__setattr__(
            self,
            "hazard_mappings",
            sort_unique_by_id(self.hazard_mappings, attribute="hazard_id", label="hazard_id"),
        )
        object.__setattr__(self, "required_node_kinds", unique_sorted_enum_tuple(self.required_node_kinds))
        self._validate_mapping_references()
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def node_ids(self) -> tuple[str, ...]:
        return tuple(node.node_id for node in self.nodes)

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return normalize_identifier_tuple(
            tuple(artifact_id for node in self.nodes for artifact_id in node.artifact_ids),
            label="artifact_ids",
        )

    @property
    def evidence_artifact_ids(self) -> tuple[str, ...]:
        evidence_nodes = [node for node in self.nodes if node.kind is TraceNodeKind.EVIDENCE]
        return normalize_identifier_tuple(
            tuple(artifact_id for node in evidence_nodes for artifact_id in node.artifact_ids),
            label="evidence_artifact_ids",
        )

    @property
    def node_kind_counts(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in TraceNodeKind}
        for node in self.nodes:
            counts[node.kind.value] += 1
        return {kind: count for kind, count in counts.items() if count > 0}

    @property
    def missing_required_node_kinds(self) -> tuple[TraceNodeKind, ...]:
        present = {node.kind for node in self.nodes}
        return tuple(kind for kind in self.required_node_kinds if kind not in present)

    @property
    def unsupported_claim_ids(self) -> tuple[str, ...]:
        evidence = set(self.evidence_artifact_ids)
        unsupported: list[str] = []
        for mapping in self.claim_mappings:
            if not set(mapping.required_evidence_artifact_ids) <= evidence:
                unsupported.append(mapping.claim_id)
        return tuple(sorted(unsupported))

    @property
    def missing_human_review_claim_ids(self) -> tuple[str, ...]:
        human_review_node_ids = {
            node.node_id for node in self.nodes if node.kind is TraceNodeKind.HUMAN_REVIEW
        }
        missing: list[str] = []
        for mapping in self.claim_mappings:
            if mapping.required_human_review_node_ids:
                if not set(mapping.required_human_review_node_ids) <= human_review_node_ids:
                    missing.append(mapping.claim_id)
            elif not self._has_inbound_edge_of_kind(mapping.claim_node_id, TraceEdgeKind.APPROVED_BY):
                missing.append(mapping.claim_id)
        return tuple(sorted(missing))

    @property
    def unmapped_control_ids(self) -> tuple[str, ...]:
        evidence = set(self.evidence_artifact_ids)
        missing: list[str] = []
        for mapping in self.control_mappings:
            if not set(mapping.evidence_artifact_ids) <= evidence:
                missing.append(mapping.control_id)
        return tuple(sorted(missing))

    @property
    def unaccepted_high_risk_hazard_ids(self) -> tuple[str, ...]:
        human_review_node_ids = {
            node.node_id for node in self.nodes if node.kind is TraceNodeKind.HUMAN_REVIEW
        }
        unaccepted: list[str] = []
        for mapping in self.hazard_mappings:
            if not mapping.requires_human_risk_acceptance:
                continue
            if not set(mapping.accepted_by_human_review_node_ids) <= human_review_node_ids:
                unaccepted.append(mapping.hazard_id)
            elif not mapping.accepted_by_human_review_node_ids:
                unaccepted.append(mapping.hazard_id)
        return tuple(sorted(unaccepted))

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for kind in self.missing_required_node_kinds:
            findings.append(
                self._finding(
                    code="operating.traceability.missing-required-node-kind",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Traceability map is missing required node kind {kind.value}.",
                    metadata={"node_kind": kind.value},
                )
            )
        for claim_id in self.unsupported_claim_ids:
            findings.append(
                self._finding(
                    code="operating.traceability.unsupported-assurance-claim",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Assurance claim {claim_id} is not backed by required evidence artifacts.",
                    metadata={"claim_id": claim_id},
                )
            )
        for claim_id in self.missing_human_review_claim_ids:
            findings.append(
                self._finding(
                    code="operating.traceability.claim-missing-human-review",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Assurance claim {claim_id} is not bound to human review.",
                    metadata={"claim_id": claim_id},
                )
            )
        for control_id in self.unmapped_control_ids:
            findings.append(
                self._finding(
                    code="operating.traceability.control-missing-evidence",
                    severity=OperatingSeverity.HIGH,
                    summary=f"Control objective {control_id} is missing mapped evidence artifacts.",
                    metadata={"control_id": control_id},
                )
            )
        for hazard_id in self.unaccepted_high_risk_hazard_ids:
            findings.append(
                self._finding(
                    code="operating.traceability.high-risk-hazard-not-human-accepted",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"High residual risk hazard {hazard_id} lacks human risk acceptance.",
                    metadata={"hazard_id": hazard_id},
                )
            )
        for edge in self.edges:
            if edge.required and edge.kind in {
                TraceEdgeKind.EVIDENCED_BY,
                TraceEdgeKind.APPROVED_BY,
                TraceEdgeKind.TESTED_BY,
                TraceEdgeKind.MITIGATED_BY,
            } and not edge.evidence_bound:
                findings.append(
                    self._finding(
                        code="operating.traceability.required-edge-missing-evidence",
                        severity=OperatingSeverity.HIGH,
                        summary=f"Required trace edge {edge.edge_id} is not bound to evidence artifacts.",
                        metadata={"edge_id": edge.edge_id, "edge_kind": edge.kind.value},
                    )
                )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def nodes_by_kind(self, kind: TraceNodeKind) -> tuple[OperatingTraceNode, ...]:
        return tuple(node for node in self.nodes if node.kind is kind)

    def outgoing_edges(self, node_id: str) -> tuple[OperatingTraceEdge, ...]:
        normalized = normalize_identifier(node_id, label="node_id")
        return tuple(edge for edge in self.edges if edge.source_node_id == normalized)

    def incoming_edges(self, node_id: str) -> tuple[OperatingTraceEdge, ...]:
        normalized = normalize_identifier(node_id, label="node_id")
        return tuple(edge for edge in self.edges if edge.target_node_id == normalized)

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.traceability_id}-traceability-envelope",
            artifact_kind=OperatingArtifactKind.STANDARDS_CROSSWALK,
            subject=f"Wave 10 assurance traceability map {self.traceability_id}",
            domains=(
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
                OperatingDomain.REVIEWABLE,
            ),
            findings=self.findings,
            metadata={
                "traceability_id": self.traceability_id,
                "registry_id": self.registry_id,
                "campaign_id": self.campaign_id,
                "node_ids": list(self.node_ids),
                "node_kind_counts": self.node_kind_counts,
                "artifact_ids": list(self.artifact_ids),
                "evidence_artifact_ids": list(self.evidence_artifact_ids),
                "claim_ids": [mapping.claim_id for mapping in self.claim_mappings],
                "control_ids": [mapping.control_id for mapping in self.control_mappings],
                "hazard_ids": [mapping.hazard_id for mapping in self.hazard_mappings],
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "traceability_id": self.traceability_id,
            "registry_id": self.registry_id,
            "campaign_id": self.campaign_id,
            "generated_by": self.generated_by,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "claim_mappings": [mapping.to_dict() for mapping in self.claim_mappings],
            "control_mappings": [mapping.to_dict() for mapping in self.control_mappings],
            "hazard_mappings": [mapping.to_dict() for mapping in self.hazard_mappings],
            "required_node_kinds": [kind.value for kind in self.required_node_kinds],
            "node_ids": list(self.node_ids),
            "node_kind_counts": self.node_kind_counts,
            "artifact_ids": list(self.artifact_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "missing_required_node_kinds": [kind.value for kind in self.missing_required_node_kinds],
            "unsupported_claim_ids": list(self.unsupported_claim_ids),
            "missing_human_review_claim_ids": list(self.missing_human_review_claim_ids),
            "unmapped_control_ids": list(self.unmapped_control_ids),
            "unaccepted_high_risk_hazard_ids": list(self.unaccepted_high_risk_hazard_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _validate_mapping_references(self) -> None:
        nodes_by_id = {node.node_id: node for node in self.nodes}
        evidence = set(self.evidence_artifact_ids)
        for mapping in self.claim_mappings:
            self._require_node_kind(mapping.claim_node_id, TraceNodeKind.ASSURANCE_CLAIM, nodes_by_id)
            for node_id in mapping.supporting_node_ids:
                self._require_known_node(node_id, nodes_by_id)
            for node_id in mapping.required_human_review_node_ids:
                self._require_node_kind(node_id, TraceNodeKind.HUMAN_REVIEW, nodes_by_id)
            for artifact_id in mapping.required_evidence_artifact_ids:
                normalize_identifier(artifact_id, label="required_evidence_artifact_ids")
        for mapping in self.control_mappings:
            self._require_node_kind(mapping.control_node_id, TraceNodeKind.CONTROL, nodes_by_id)
            for node_id in mapping.requirement_node_ids:
                self._require_node_kind(node_id, TraceNodeKind.REQUIREMENT, nodes_by_id)
            for artifact_id in mapping.evidence_artifact_ids:
                normalize_identifier(artifact_id, label="evidence_artifact_ids")
        for mapping in self.hazard_mappings:
            self._require_node_kind(mapping.hazard_node_id, TraceNodeKind.HAZARD, nodes_by_id)
            for node_id in mapping.control_node_ids:
                self._require_node_kind(node_id, TraceNodeKind.CONTROL, nodes_by_id)
            for node_id in mapping.accepted_by_human_review_node_ids:
                self._require_node_kind(node_id, TraceNodeKind.HUMAN_REVIEW, nodes_by_id)
            for artifact_id in mapping.evidence_artifact_ids:
                normalize_identifier(artifact_id, label="evidence_artifact_ids")
        _ = evidence

    def _require_known_node(self, node_id: str, nodes_by_id: Mapping[str, OperatingTraceNode]) -> None:
        if node_id not in nodes_by_id:
            raise ValueError(f"mapping references unknown node: {node_id}")

    def _require_node_kind(
        self,
        node_id: str,
        expected_kind: TraceNodeKind,
        nodes_by_id: Mapping[str, OperatingTraceNode],
    ) -> None:
        self._require_known_node(node_id, nodes_by_id)
        if nodes_by_id[node_id].kind is not expected_kind:
            raise ValueError(
                f"node {node_id} must be kind {expected_kind.value}, "
                f"not {nodes_by_id[node_id].kind.value}."
            )

    def _has_inbound_edge_of_kind(self, node_id: str, kind: TraceEdgeKind) -> bool:
        return any(edge.kind is kind for edge in self.incoming_edges(node_id))

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(
                OperatingDomain.POLICY_GOVERNED,
                OperatingDomain.MEASURABLE,
                OperatingDomain.REVIEWABLE,
            ),
            blocking=True,
            metadata={"traceability_id": self.traceability_id, **dict(metadata or {})},
        )


def sort_unique_by_id(
    values: Sequence[Any],
    *,
    attribute: str,
    label: str,
) -> tuple[Any, ...]:
    normalized = tuple(sorted(values, key=lambda value: getattr(value, attribute)))
    identifiers = [getattr(value, attribute) for value in normalized]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"OperatingTraceabilityMap {label} values must be unique.")
    return normalized
