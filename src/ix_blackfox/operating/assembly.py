from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.operating.cloud import (
    CloudFindingResource,
    CloudSecurityFindingExport,
    build_cloud_security_export_from_envelope,
)
from ix_blackfox.operating.export import (
    OperatingExportPack,
    OperatingExportPackValidation,
    build_wave10_local_export_pack,
)
from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingSourceWave,
    digest_payload,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple
from ix_blackfox.operating.report import (
    OperatingReport,
    OperatingReportClaim,
    OperatingReportSection,
    OperatingReportSectionKind,
    OperatingReportValidation,
)
from ix_blackfox.operating.review_bundle import (
    OperatingReviewBundle,
    ReviewBundleArtifact,
    ReviewBundleSection,
    ReviewBundleSectionKind,
)
from ix_blackfox.operating.standards import (
    StandardsCrosswalkReport,
    build_default_wave10_standards_crosswalk,
)

DEFAULT_WAVE10_REPORT_SECTION_KINDS: tuple[OperatingReportSectionKind, ...] = (
    OperatingReportSectionKind.REGISTRY,
    OperatingReportSectionKind.TEAM_AUTHORITY,
    OperatingReportSectionKind.CAMPAIGN_GRAPH,
    OperatingReportSectionKind.EVIDENCE_INVENTORY,
    OperatingReportSectionKind.REPLAY_MANIFEST,
    OperatingReportSectionKind.REPLAY_VALIDATION,
    OperatingReportSectionKind.REVIEW_BUNDLE,
    OperatingReportSectionKind.TRACEABILITY_MAP,
    OperatingReportSectionKind.POLICY_GATE,
    OperatingReportSectionKind.READINESS_GATE,
    OperatingReportSectionKind.TRUST_EVALUATION,
    OperatingReportSectionKind.FALSIFICATION_GATE,
    OperatingReportSectionKind.SCORECARD,
    OperatingReportSectionKind.STANDARDS_CROSSWALK,
    OperatingReportSectionKind.CLOUD_SECURITY_EXPORT,
)


@dataclass(frozen=True, slots=True)
class Wave10AssemblyResult:
    """End-to-end local Wave 10 assembly result.

    This object is a deterministic smoke path across the Wave 10 operating
    layers. It does not certify compliance, call cloud services, upload
    artifacts, or authorize execution.
    """

    assembly_id: str
    report: OperatingReport
    report_validation: OperatingReportValidation
    review_bundle: OperatingReviewBundle
    standards_crosswalk: StandardsCrosswalkReport
    cloud_security_export: CloudSecurityFindingExport
    export_pack: OperatingExportPack
    export_pack_validation: OperatingExportPackValidation
    generated_by: str = "IX-BlackFox Wave 10 assembly smoke path"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "assembly_id",
            normalize_identifier(self.assembly_id, label="assembly_id"),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def dispositions(self) -> dict[str, str]:
        return {
            "report": self.report.disposition.value,
            "report_validation": self.report_validation.disposition.value,
            "review_bundle": self.review_bundle.disposition.value,
            "standards_crosswalk": self.standards_crosswalk.disposition.value,
            "cloud_security_export": self.cloud_security_export.disposition.value,
            "export_pack": self.export_pack.disposition.value,
            "export_pack_validation": self.export_pack_validation.disposition.value,
        }

    @property
    def all_ready(self) -> bool:
        return (
            all(value == OperatingDisposition.READY.value for value in self.dispositions.values())
            and self.report_validation.passed
            and self.export_pack_validation.passed
        )

    @property
    def blocking_findings_count(self) -> int:
        return sum(
            len(envelope.blocking_findings)
            for envelope in (
                self.report.to_envelope(),
                self.report_validation.to_envelope(),
                self.review_bundle.to_envelope(),
                self.standards_crosswalk.to_envelope(),
                self.cloud_security_export.to_envelope(),
                self.export_pack.to_envelope(),
                self.export_pack_validation.to_envelope(),
            )
        )

    @property
    def warning_findings_count(self) -> int:
        return sum(
            len(envelope.warning_findings)
            for envelope in (
                self.report.to_envelope(),
                self.report_validation.to_envelope(),
                self.review_bundle.to_envelope(),
                self.standards_crosswalk.to_envelope(),
                self.cloud_security_export.to_envelope(),
                self.export_pack.to_envelope(),
                self.export_pack_validation.to_envelope(),
            )
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "assembly_id": self.assembly_id,
            "generated_by": self.generated_by,
            "all_ready": self.all_ready,
            "dispositions": self.dispositions,
            "blocking_findings_count": self.blocking_findings_count,
            "warning_findings_count": self.warning_findings_count,
            "report": self.report.to_dict(),
            "report_validation": self.report_validation.to_dict(),
            "review_bundle": self.review_bundle.to_dict(),
            "standards_crosswalk": self.standards_crosswalk.to_dict(),
            "cloud_security_export": self.cloud_security_export.to_dict(),
            "export_pack": self.export_pack.to_dict(include_payload_bodies=False),
            "export_pack_validation": self.export_pack_validation.to_dict(),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_minimal_wave10_operating_assembly(
    *,
    assembly_id: str = "wave10-assembly",
    registry_id: str = "wave10-registry",
    campaign_id: str = "wave10-campaign",
    repository_ids: tuple[str, ...] = ("ix-blackfox",),
    aws_account_id: str = "123456789012",
    aws_region: str = "us-east-1",
    observed_at: str = "2026-05-29T00:00:00Z",
    checked_by: str = "platform-security-reviewer",
) -> Wave10AssemblyResult:
    """Build a compact end-to-end ready Wave 10 operating assembly.

    This is intentionally local and deterministic. It creates enough linked
    evidence to prove the report, report validation, review bundle, standards
    crosswalk, cloud-security local export, export pack, and export validation
    can be assembled together without granting execution authority.
    """

    normalized_repositories = normalize_identifier_tuple(
        repository_ids,
        label="repository_ids",
    )

    sections = tuple(
        build_ready_report_section(section_kind)
        for section_kind in DEFAULT_WAVE10_REPORT_SECTION_KINDS
    )
    artifact_ids = tuple(
        artifact_id
        for section in sections
        for artifact_id in section.artifact_ids
    )

    report = OperatingReport(
        report_id="wave10-operating-report",
        registry_id=registry_id,
        campaign_id=campaign_id,
        repository_ids=normalized_repositories,
        sections=sections,
        claims=(
            OperatingReportClaim(
                claim_id="bounded-wave10-operating-assembly",
                statement=(
                    "Wave 10 evidence is assembled, digest-bound, replayable, "
                    "measurable, and reviewable for this campaign scope only."
                ),
                supported_by_section_ids=tuple(section.section_id for section in sections),
                evidence_artifact_ids=artifact_ids,
            ),
        ),
    )

    report_validation = OperatingReportValidation(
        validation_id="wave10-operating-report-validation",
        report=report,
        expected_digest=report.digest,
        observed_digest=report.digest,
        checked_by=checked_by,
        observed_section_ids=report.section_ids,
    )

    review_bundle = build_minimal_review_bundle(
        campaign_id=campaign_id,
        repository_ids=normalized_repositories,
        checked_by=checked_by,
    )

    standards_crosswalk = build_default_wave10_standards_crosswalk(
        report_id="wave10-standards-crosswalk",
        registry_id=registry_id,
        campaign_id=campaign_id,
        artifact_ids=artifact_ids,
        metric_ids=("policy-controls", "replay-validation", "evidence-trust"),
        human_review_ids=("human-review",),
    )

    cloud_security_export = build_cloud_security_export_from_envelope(
        export_id="wave10-cloud-security-export",
        envelope=report.to_envelope(),
        aws_account_id=aws_account_id,
        region=aws_region,
        observed_at=observed_at,
        resource=CloudFindingResource(
            resource_id=f"arn:aws:codecommit:{aws_region}:{aws_account_id}:ix-blackfox",
            resource_type="AwsCodeRepository",
            region=aws_region,
            details={
                "Other": {
                    "RepositoryName": "IX-BlackFox",
                    "EvidenceScope": "Wave 10 local assembly smoke path",
                },
            },
        ),
    )

    export_pack = build_wave10_local_export_pack(
        pack_id="wave10-local-export-pack",
        report=report,
        review_bundle=review_bundle,
        standards_crosswalk=standards_crosswalk,
        cloud_security_export=cloud_security_export,
        report_validation=report_validation,
    )

    export_pack_validation = OperatingExportPackValidation(
        validation_id="wave10-local-export-pack-validation",
        pack=export_pack,
        expected_manifest_digest=export_pack.manifest_digest,
        observed_manifest_digest=export_pack.manifest_digest,
        observed_payload_sha256={
            payload.payload_id: payload.sha256 for payload in export_pack.payloads
        },
        checked_by=checked_by,
    )

    return Wave10AssemblyResult(
        assembly_id=assembly_id,
        report=report,
        report_validation=report_validation,
        review_bundle=review_bundle,
        standards_crosswalk=standards_crosswalk,
        cloud_security_export=cloud_security_export,
        export_pack=export_pack,
        export_pack_validation=export_pack_validation,
        metadata={
            "registry_id": normalize_identifier(registry_id, label="registry_id"),
            "campaign_id": normalize_identifier(campaign_id, label="campaign_id"),
            "repository_ids": list(normalized_repositories),
            "local_only": True,
        },
    )


def build_ready_report_section(
    section_kind: OperatingReportSectionKind,
) -> OperatingReportSection:
    section_id = section_id_for_report_kind(section_kind)
    artifact_id = f"{section_id}-artifact"
    envelope = OperatingEnvelope(
        envelope_id=f"{section_id}-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject=f"Wave 10 {section_id} evidence section",
        domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
        evidence=(build_artifact_ref(artifact_id),),
    )
    return OperatingReportSection(
        section_id=section_id,
        section_kind=section_kind,
        title=f"Wave 10 {section_id} section",
        envelope=envelope,
        summary="Digest-bound ready section for the Wave 10 operating assembly smoke path.",
        reviewer_actions=("Review the envelope digest and section disposition.",),
    )


def build_minimal_review_bundle(
    *,
    campaign_id: str,
    repository_ids: tuple[str, ...],
    checked_by: str,
) -> OperatingReviewBundle:
    section_specs: tuple[tuple[str, ReviewBundleSectionKind], ...] = (
        ("registry", ReviewBundleSectionKind.REGISTRY),
        ("team-authority", ReviewBundleSectionKind.TEAM_AUTHORITY),
        ("campaign", ReviewBundleSectionKind.CAMPAIGN),
        ("evidence-inventory", ReviewBundleSectionKind.EVIDENCE_INVENTORY),
        ("replay-manifest", ReviewBundleSectionKind.REPLAY_MANIFEST),
    )
    sections: list[ReviewBundleSection] = []
    artifacts: list[ReviewBundleArtifact] = []

    for section_id, section_kind in section_specs:
        artifact = build_artifact_ref(f"review-{section_id}-artifact")
        envelope = OperatingEnvelope(
            envelope_id=f"review-{section_id}-envelope",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            subject=f"Wave 10 review bundle {section_id} evidence",
            domains=(OperatingDomain.REVIEWABLE,),
            evidence=(artifact,),
        )
        sections.append(
            ReviewBundleSection(
                section_id=section_id,
                section_kind=section_kind,
                title=f"Review {section_id}",
                envelope=envelope,
                reviewer_instructions=("Confirm this evidence is digest-bound and human-reviewable.",),
            )
        )
        artifacts.append(
            ReviewBundleArtifact(
                artifact,
                review_note="Review this artifact before treating the bundle as ready.",
            )
        )

    return OperatingReviewBundle(
        bundle_id="wave10-review-bundle",
        campaign_id=campaign_id,
        repository_ids=repository_ids,
        created_by=checked_by,
        sections=tuple(sections),
        artifacts=tuple(artifacts),
        reviewer_questions=(
            "Does this bundle require human authority?",
            "Are the linked artifacts digest-bound?",
            "Is this evidence-only and not execution authority?",
        ),
    )


def build_artifact_ref(artifact_id: str) -> OperatingArtifactRef:
    normalized = normalize_identifier(artifact_id, label="artifact_id")
    return OperatingArtifactRef(
        artifact_id=normalized,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f".blackfox-artifacts/wave10/{normalized}.json",
        sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        producer="IX-BlackFox Wave 10 assembly smoke path",
    )


def section_id_for_report_kind(section_kind: OperatingReportSectionKind) -> str:
    return section_kind.value.replace("_", "-")


def normalize_metadata(values: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in values.items():
        clean_key = normalize_text(str(key), label="metadata_key")
        normalized[clean_key] = normalize_metadata_value(value)
    return dict(sorted(normalized.items()))


def normalize_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Mapping):
        return normalize_metadata(value)
    if isinstance(value, tuple):
        return tuple(normalize_metadata_value(item) for item in value)
    if isinstance(value, list):
        return tuple(normalize_metadata_value(item) for item in value)
    raise ValueError(f"metadata contains unsupported value type: {type(value).__name__}")
