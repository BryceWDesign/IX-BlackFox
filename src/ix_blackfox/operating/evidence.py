from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.audit.models import (
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceSourceWave,
)
from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    OperatingSourceWave,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


@dataclass(frozen=True, slots=True)
class WaveEvidenceRequirement:
    """Required upstream evidence family for Wave 10 operating aggregation."""

    requirement_id: str
    source_wave: OperatingSourceWave
    audit_kinds: tuple[AuditEvidenceKind, ...]
    description: str
    min_count: int = 1
    require_verified: bool = False
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requirement_id",
            normalize_identifier(self.requirement_id, label="requirement_id"),
        )
        if not self.audit_kinds:
            raise ValueError("WaveEvidenceRequirement audit_kinds must not be empty.")
        if self.min_count <= 0:
            raise ValueError("min_count must be greater than zero.")
        object.__setattr__(
            self,
            "audit_kinds",
            tuple(sorted(set(self.audit_kinds), key=lambda kind: kind.value)),
        )
        object.__setattr__(self, "description", normalize_text(self.description, label="description"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def satisfied_by(self, items: Sequence[OperatingEvidenceItem]) -> tuple[OperatingEvidenceItem, ...]:
        matches = tuple(
            item
            for item in items
            if item.source_wave is self.source_wave and item.audit_evidence_kind in self.audit_kinds
        )
        if self.require_verified:
            matches = tuple(item for item in matches if item.verified)
        return tuple(sorted(matches, key=lambda item: item.artifact.artifact_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "source_wave": self.source_wave.value,
            "audit_kinds": [kind.value for kind in self.audit_kinds],
            "description": self.description,
            "min_count": self.min_count,
            "require_verified": self.require_verified,
            "mandatory": self.mandatory,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingEvidenceItem:
    """Wave 5-9 evidence normalized into a Wave 10 operating artifact reference."""

    artifact: OperatingArtifactRef
    audit_evidence_kind: AuditEvidenceKind
    source_wave: OperatingSourceWave
    verified: bool = False
    size_bytes: int = 0
    head_sha: str = ""
    source_schema_version: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.artifact.source_wave is not self.source_wave:
            raise ValueError("artifact source_wave must match OperatingEvidenceItem source_wave.")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative.")
        object.__setattr__(
            self,
            "head_sha",
            normalize_optional_text(self.head_sha, label="head_sha"),
        )
        object.__setattr__(
            self,
            "source_schema_version",
            normalize_optional_text(self.source_schema_version, label="source_schema_version"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def from_audit_artifact(cls, artifact: AuditEvidenceArtifact) -> OperatingEvidenceItem:
        source_wave = operating_source_wave_from_audit(artifact.source_wave)
        return cls(
            artifact=OperatingArtifactRef(
                artifact_id=artifact.artifact_id,
                kind=operating_artifact_kind_from_audit(artifact.kind),
                source_wave=source_wave,
                path=artifact.path,
                sha256=artifact.sha256,
                producer=artifact.producer,
                schema_version=artifact.schema_version,
                metadata={
                    **dict(artifact.metadata),
                    "audit_evidence_kind": artifact.kind.value,
                    "audit_source_wave": artifact.source_wave.value,
                    "head_sha": artifact.head_sha,
                    "size_bytes": artifact.size_bytes,
                    "verified": artifact.verified,
                },
            ),
            audit_evidence_kind=artifact.kind,
            source_wave=source_wave,
            verified=artifact.verified,
            size_bytes=artifact.size_bytes,
            head_sha=artifact.head_sha,
            source_schema_version=artifact.schema_version,
            metadata=dict(artifact.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "audit_evidence_kind": self.audit_evidence_kind.value,
            "source_wave": self.source_wave.value,
            "verified": self.verified,
            "size_bytes": self.size_bytes,
            "head_sha": self.head_sha,
            "source_schema_version": self.source_schema_version,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingEvidenceInventory:
    """Aggregated Wave 5-9 evidence inventory used by Wave 10 campaigns and reports."""

    inventory_id: str
    repository_id: str
    items: tuple[OperatingEvidenceItem, ...]
    requirements: tuple[WaveEvidenceRequirement, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 evidence inventory"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "inventory_id",
            normalize_identifier(self.inventory_id, label="inventory_id"),
        )
        object.__setattr__(
            self,
            "repository_id",
            normalize_identifier(self.repository_id, label="repository_id"),
        )
        items = tuple(sorted(self.items, key=lambda item: item.artifact.artifact_id))
        artifact_ids = [item.artifact.artifact_id for item in items]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("OperatingEvidenceInventory artifact_id values must be unique.")
        object.__setattr__(self, "items", items)
        requirements = tuple(sorted(self.requirements, key=lambda requirement: requirement.requirement_id))
        requirement_ids = [requirement.requirement_id for requirement in requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("OperatingEvidenceInventory requirement_id values must be unique.")
        object.__setattr__(self, "requirements", requirements)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_refs(self) -> tuple[OperatingArtifactRef, ...]:
        return tuple(item.artifact for item in self.items)

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(item.artifact.artifact_id for item in self.items)

    @property
    def verified_artifact_ids(self) -> tuple[str, ...]:
        return tuple(item.artifact.artifact_id for item in self.items if item.verified)

    @property
    def unverified_artifact_ids(self) -> tuple[str, ...]:
        return tuple(item.artifact.artifact_id for item in self.items if not item.verified)

    @property
    def source_waves_present(self) -> tuple[OperatingSourceWave, ...]:
        return unique_sorted_enum_tuple(tuple(item.source_wave for item in self.items))

    @property
    def source_wave_counts(self) -> dict[str, int]:
        counts = {wave.value: 0 for wave in OperatingSourceWave}
        for item in self.items:
            counts[item.source_wave.value] += 1
        return {wave: count for wave, count in counts.items() if count > 0}

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for requirement in self.requirements:
            matches = requirement.satisfied_by(self.items)
            if len(matches) < requirement.min_count and requirement.mandatory:
                findings.append(
                    OperatingFinding(
                        code="operating.evidence.missing-required-wave-evidence",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Evidence requirement {requirement.requirement_id} needs "
                            f"{requirement.min_count} matching artifacts but has {len(matches)}."
                        ),
                        domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                        blocking=True,
                        metadata={
                            "inventory_id": self.inventory_id,
                            "repository_id": self.repository_id,
                            "requirement_id": requirement.requirement_id,
                            "source_wave": requirement.source_wave.value,
                            "audit_kinds": [kind.value for kind in requirement.audit_kinds],
                            "matched_artifact_ids": [item.artifact.artifact_id for item in matches],
                        },
                    )
                )
        for item in self.items:
            if item.size_bytes == 0:
                findings.append(
                    OperatingFinding(
                        code="operating.evidence.unknown-artifact-size",
                        severity=OperatingSeverity.MEDIUM,
                        summary=f"Evidence artifact {item.artifact.artifact_id} has no size binding.",
                        domains=(OperatingDomain.MEASURABLE,),
                        paths=(item.artifact.path,),
                        blocking=False,
                        metadata={
                            "inventory_id": self.inventory_id,
                            "artifact_id": item.artifact.artifact_id,
                        },
                    )
                )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def artifact_ids_for_requirement(self, requirement_id: str) -> tuple[str, ...]:
        normalized = normalize_identifier(requirement_id, label="requirement_id")
        for requirement in self.requirements:
            if requirement.requirement_id == normalized:
                return tuple(item.artifact.artifact_id for item in requirement.satisfied_by(self.items))
        raise KeyError(f"unknown requirement_id: {normalized}")

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.inventory_id}-evidence-inventory-envelope",
            artifact_kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
            subject=f"Wave 10 evidence inventory {self.inventory_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            evidence=self.artifact_refs,
            findings=self.findings,
            metadata={
                "inventory_id": self.inventory_id,
                "repository_id": self.repository_id,
                "artifact_ids": list(self.artifact_ids),
                "verified_artifact_ids": list(self.verified_artifact_ids),
                "unverified_artifact_ids": list(self.unverified_artifact_ids),
                "source_wave_counts": self.source_wave_counts,
                "requirement_ids": [requirement.requirement_id for requirement in self.requirements],
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "inventory_id": self.inventory_id,
            "repository_id": self.repository_id,
            "generated_by": self.generated_by,
            "items": [item.to_dict() for item in self.items],
            "requirements": [requirement.to_dict() for requirement in self.requirements],
            "artifact_ids": list(self.artifact_ids),
            "verified_artifact_ids": list(self.verified_artifact_ids),
            "unverified_artifact_ids": list(self.unverified_artifact_ids),
            "source_waves_present": [wave.value for wave in self.source_waves_present],
            "source_wave_counts": self.source_wave_counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceAggregationResult:
    """Result returned after Wave 5-9 evidence is normalized for Wave 10."""

    inventory: OperatingEvidenceInventory
    ingested_artifact_ids: tuple[str, ...]
    skipped_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ingested_artifact_ids",
            normalize_identifier_tuple(self.ingested_artifact_ids, label="ingested_artifact_ids"),
        )
        object.__setattr__(
            self,
            "skipped_artifact_ids",
            normalize_identifier_tuple(self.skipped_artifact_ids, label="skipped_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.inventory.to_envelope().disposition is not OperatingDisposition.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory.to_dict(),
            "ingested_artifact_ids": list(self.ingested_artifact_ids),
            "skipped_artifact_ids": list(self.skipped_artifact_ids),
            "passed": self.passed,
            "metadata": dict(self.metadata),
        }


def default_wave5_to_wave9_evidence_requirements(
    *,
    require_verified: bool = False,
) -> tuple[WaveEvidenceRequirement, ...]:
    """Return the core upstream evidence families Wave 10 expects to aggregate."""

    return (
        WaveEvidenceRequirement(
            requirement_id="wave5-pr-evidence-pack",
            source_wave=OperatingSourceWave.WAVE5,
            audit_kinds=(AuditEvidenceKind.PR_EVIDENCE_PACK,),
            description="Wave 5 PR evidence pack binding proposed code changes to review.",
            require_verified=require_verified,
        ),
        WaveEvidenceRequirement(
            requirement_id="wave6-sandbox-evidence",
            source_wave=OperatingSourceWave.WAVE6,
            audit_kinds=(
                AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
                AuditEvidenceKind.SANDBOX_RECEIPT_BUNDLE,
            ),
            description="Wave 6 sandbox evidence for isolated execution and adversarial checks.",
            require_verified=require_verified,
        ),
        WaveEvidenceRequirement(
            requirement_id="wave7-model-repair-evidence",
            source_wave=OperatingSourceWave.WAVE7,
            audit_kinds=(AuditEvidenceKind.MODEL_REPAIR_REPORT, AuditEvidenceKind.MODEL_REPAIR_RECEIPT),
            description="Wave 7 model-repair evidence for model routing and repair decisions.",
            require_verified=require_verified,
        ),
        WaveEvidenceRequirement(
            requirement_id="wave8-repository-intelligence-evidence",
            source_wave=OperatingSourceWave.WAVE8,
            audit_kinds=(
                AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
                AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT,
            ),
            description="Wave 8 repository-intelligence evidence for code graph and impact analysis.",
            require_verified=require_verified,
        ),
        WaveEvidenceRequirement(
            requirement_id="wave9-governance-report",
            source_wave=OperatingSourceWave.WAVE9,
            audit_kinds=(AuditEvidenceKind.GOVERNANCE_REPORT,),
            description="Wave 9 governance report binding audit controls, evidence, and signoff.",
            require_verified=require_verified,
        ),
    )


def aggregate_audit_evidence_for_operating_layer(
    *,
    inventory_id: str,
    repository_id: str,
    audit_artifacts: Sequence[AuditEvidenceArtifact],
    requirements: Sequence[WaveEvidenceRequirement] | None = None,
    generated_by: str = "IX-BlackFox Wave 10 evidence aggregator",
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceAggregationResult:
    """Normalize Wave 5-9 audit evidence artifacts into a Wave 10 inventory."""

    items = tuple(
        OperatingEvidenceItem.from_audit_artifact(artifact) for artifact in audit_artifacts
    )
    inventory = OperatingEvidenceInventory(
        inventory_id=inventory_id,
        repository_id=repository_id,
        items=items,
        requirements=tuple(requirements or default_wave5_to_wave9_evidence_requirements()),
        generated_by=generated_by,
        metadata=dict(metadata or {}),
    )
    return EvidenceAggregationResult(
        inventory=inventory,
        ingested_artifact_ids=inventory.artifact_ids,
        metadata={
            "artifact_count": len(items),
            "requirement_count": len(inventory.requirements),
        },
    )


def operating_source_wave_from_audit(source_wave: AuditEvidenceSourceWave) -> OperatingSourceWave:
    mapping: dict[AuditEvidenceSourceWave, OperatingSourceWave] = {
        AuditEvidenceSourceWave.WAVE5: OperatingSourceWave.WAVE5,
        AuditEvidenceSourceWave.WAVE6: OperatingSourceWave.WAVE6,
        AuditEvidenceSourceWave.WAVE7: OperatingSourceWave.WAVE7,
        AuditEvidenceSourceWave.WAVE8: OperatingSourceWave.WAVE8,
        AuditEvidenceSourceWave.WAVE9: OperatingSourceWave.WAVE9,
        AuditEvidenceSourceWave.EXTERNAL: OperatingSourceWave.EXTERNAL,
        AuditEvidenceSourceWave.UNKNOWN: OperatingSourceWave.EXTERNAL,
    }
    return mapping[source_wave]


def operating_artifact_kind_from_audit(kind: AuditEvidenceKind) -> OperatingArtifactKind:
    mapping: dict[AuditEvidenceKind, OperatingArtifactKind] = {
        AuditEvidenceKind.PR_EVIDENCE_PACK: OperatingArtifactKind.REVIEW_BUNDLE,
        AuditEvidenceKind.CI_EVIDENCE: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.APPROVAL_RECORD: OperatingArtifactKind.TEAM_AUTHORITY,
        AuditEvidenceKind.HUMAN_REVIEW: OperatingArtifactKind.TEAM_AUTHORITY,
        AuditEvidenceKind.GOVERNANCE_RECEIPT: OperatingArtifactKind.POLICY_EVALUATION,
        AuditEvidenceKind.SANDBOX_RECEIPT_BUNDLE: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.MODEL_REPAIR_REPORT: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.MODEL_REPAIR_RECEIPT: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.REPOSITORY_EVIDENCE_SNAPSHOT: OperatingArtifactKind.EVIDENCE_MANIFEST,
        AuditEvidenceKind.POLICY_DECISION: OperatingArtifactKind.POLICY_EVALUATION,
        AuditEvidenceKind.ATTESTATION: OperatingArtifactKind.STANDARDS_CROSSWALK,
        AuditEvidenceKind.GOVERNANCE_REPORT: OperatingArtifactKind.OPERATING_REPORT,
        AuditEvidenceKind.OTHER: OperatingArtifactKind.EVIDENCE_MANIFEST,
    }
    return mapping[kind]
