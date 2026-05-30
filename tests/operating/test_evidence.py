from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.audit.models import (
    AuditEvidenceArtifact,
    AuditEvidenceKind,
    AuditEvidenceSourceWave,
)
from ix_blackfox.operating import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingEvidenceInventory,
    OperatingEvidenceItem,
    OperatingSourceWave,
    WaveEvidenceRequirement,
    aggregate_audit_evidence_for_operating_layer,
    default_wave5_to_wave9_evidence_requirements,
    operating_artifact_kind_from_audit,
    operating_source_wave_from_audit,
)


def test_operating_evidence_item_bridges_audit_artifact_without_losing_source_fields() -> None:
    audit = _audit_artifact(
        artifact_id="wave9:governance-report",
        kind=AuditEvidenceKind.GOVERNANCE_REPORT,
        source_wave=AuditEvidenceSourceWave.WAVE9,
        path=".blackfox-artifacts/wave9/governance-report.json",
        verified=True,
    )

    item = OperatingEvidenceItem.from_audit_artifact(audit)

    assert item.artifact.artifact_id == "wave9:governance-report"
    assert item.artifact.kind is OperatingArtifactKind.OPERATING_REPORT
    assert item.source_wave is OperatingSourceWave.WAVE9
    assert item.audit_evidence_kind is AuditEvidenceKind.GOVERNANCE_REPORT
    assert item.verified is True
    assert item.size_bytes == 512
    assert item.head_sha == "a" * 40
    assert item.artifact.metadata["audit_evidence_kind"] == "governance_report"
    assert item.artifact.metadata["audit_source_wave"] == "wave9"


def test_evidence_inventory_is_ready_when_required_wave_evidence_is_present() -> None:
    artifacts = (
        _audit_artifact("wave5-pr", AuditEvidenceKind.PR_EVIDENCE_PACK, AuditEvidenceSourceWave.WAVE5),
        _audit_artifact(
            "wave6-sandbox",
            AuditEvidenceKind.SANDBOX_ADVERSARIAL_REPORT,
            AuditEvidenceSourceWave.WAVE6,
        ),
        _audit_artifact(
            "wave7-repair",
            AuditEvidenceKind.MODEL_REPAIR_REPORT,
            AuditEvidenceSourceWave.WAVE7,
        ),
        _audit_artifact(
            "wave8-repo-intel",
            AuditEvidenceKind.REPOSITORY_INTELLIGENCE_REPORT,
            AuditEvidenceSourceWave.WAVE8,
        ),
        _audit_artifact("wave9-report", AuditEvidenceKind.GOVERNANCE_REPORT, AuditEvidenceSourceWave.WAVE9),
    )

    result = aggregate_audit_evidence_for_operating_layer(
        inventory_id=" Wave 10 Evidence ",
        repository_id=" IX BlackFox ",
        audit_artifacts=artifacts,
    )
    inventory = result.inventory

    assert result.passed is True
    assert inventory.inventory_id == "wave-10-evidence"
    assert inventory.repository_id == "ix-blackfox"
    assert inventory.artifact_ids == (
        "wave5-pr",
        "wave6-sandbox",
        "wave7-repair",
        "wave8-repo-intel",
        "wave9-report",
    )
    assert inventory.source_wave_counts == {
        "wave5": 1,
        "wave6": 1,
        "wave7": 1,
        "wave8": 1,
        "wave9": 1,
    }
    assert inventory.artifact_ids_for_requirement("wave9-governance-report") == ("wave9-report",)
    assert inventory.findings == ()
    assert inventory.to_envelope().disposition is OperatingDisposition.READY
    assert result.to_dict()["ingested_artifact_ids"] == list(inventory.artifact_ids)


def test_evidence_inventory_blocks_missing_required_wave_evidence() -> None:
    result = aggregate_audit_evidence_for_operating_layer(
        inventory_id="missing-evidence",
        repository_id="ix-blackfox",
        audit_artifacts=(
            _audit_artifact("wave9-report", AuditEvidenceKind.GOVERNANCE_REPORT, AuditEvidenceSourceWave.WAVE9),
        ),
    )

    finding_codes = {finding.code for finding in result.inventory.findings}
    missing_ids = {
        finding.metadata["requirement_id"] for finding in result.inventory.findings
    }
    assert finding_codes == {"operating.evidence.missing-required-wave-evidence"}
    assert missing_ids == {
        "wave5-pr-evidence-pack",
        "wave6-sandbox-evidence",
        "wave7-model-repair-evidence",
        "wave8-repository-intelligence-evidence",
    }
    assert result.passed is False
    assert result.inventory.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_evidence_inventory_can_require_verified_artifacts() -> None:
    requirements = (
        WaveEvidenceRequirement(
            requirement_id="verified-wave9-report",
            source_wave=OperatingSourceWave.WAVE9,
            audit_kinds=(AuditEvidenceKind.GOVERNANCE_REPORT,),
            description="Verified Wave 9 report required for final operating gate.",
            require_verified=True,
        ),
    )
    unverified = _audit_artifact(
        "wave9-report",
        AuditEvidenceKind.GOVERNANCE_REPORT,
        AuditEvidenceSourceWave.WAVE9,
        verified=False,
    )

    result = aggregate_audit_evidence_for_operating_layer(
        inventory_id="verified-required",
        repository_id="ix-blackfox",
        audit_artifacts=(unverified,),
        requirements=requirements,
    )

    assert result.inventory.unverified_artifact_ids == ("wave9-report",)
    assert result.inventory.verified_artifact_ids == ()
    assert result.inventory.findings[0].metadata["requirement_id"] == "verified-wave9-report"
    assert result.inventory.to_dict()["disposition"] == "blocked"


def test_evidence_inventory_rejects_duplicate_artifact_ids_and_duplicate_requirements() -> None:
    item = OperatingEvidenceItem.from_audit_artifact(
        _audit_artifact("duplicate", AuditEvidenceKind.GOVERNANCE_REPORT, AuditEvidenceSourceWave.WAVE9)
    )
    requirement = WaveEvidenceRequirement(
        requirement_id="duplicate-requirement",
        source_wave=OperatingSourceWave.WAVE9,
        audit_kinds=(AuditEvidenceKind.GOVERNANCE_REPORT,),
        description="Duplicate requirement should fail.",
    )

    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        OperatingEvidenceInventory(
            inventory_id="duplicate-artifacts",
            repository_id="ix-blackfox",
            items=(item, item),
        )

    with pytest.raises(ValueError, match="requirement_id values must be unique"):
        OperatingEvidenceInventory(
            inventory_id="duplicate-requirements",
            repository_id="ix-blackfox",
            items=(item,),
            requirements=(requirement, requirement),
        )


def test_default_requirements_and_mapping_functions_cover_wave5_to_wave9() -> None:
    requirements = default_wave5_to_wave9_evidence_requirements(require_verified=True)

    assert [requirement.requirement_id for requirement in requirements] == [
        "wave5-pr-evidence-pack",
        "wave6-sandbox-evidence",
        "wave7-model-repair-evidence",
        "wave8-repository-intelligence-evidence",
        "wave9-governance-report",
    ]
    assert all(requirement.require_verified for requirement in requirements)
    assert operating_source_wave_from_audit(AuditEvidenceSourceWave.UNKNOWN) is OperatingSourceWave.EXTERNAL
    assert (
        operating_artifact_kind_from_audit(AuditEvidenceKind.POLICY_DECISION)
        is OperatingArtifactKind.POLICY_EVALUATION
    )


def _audit_artifact(
    artifact_id: str,
    kind: AuditEvidenceKind,
    source_wave: AuditEvidenceSourceWave,
    *,
    path: str | None = None,
    verified: bool = True,
) -> AuditEvidenceArtifact:
    normalized = artifact_id.strip().lower().replace(" ", "-")
    return AuditEvidenceArtifact(
        artifact_id=artifact_id,
        kind=kind,
        source_wave=source_wave,
        path=path or f".blackfox-artifacts/{source_wave.value}/{normalized}.json",
        sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        size_bytes=512,
        producer=f"producer for {source_wave.value}",
        head_sha="a" * 40,
        schema_version=f"{source_wave.value}.{kind.value}.v1",
        verified=verified,
        metadata={"test": True},
    )
