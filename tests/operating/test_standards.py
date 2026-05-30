from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    OperatingDisposition,
    StandardsControlMapping,
    StandardsCrosswalkReport,
    StandardsEvidenceKind,
    StandardsEvidenceReference,
    StandardsFramework,
    StandardsMappingStatus,
    build_default_wave10_standards_crosswalk,
)


def test_default_wave10_standards_crosswalk_is_ready_and_mapping_only() -> None:
    report = build_default_wave10_standards_crosswalk(
        report_id=" Wave 10 Standards ",
        registry_id="Wave 10 Registry",
        campaign_id="Wave 10 Campaign",
        artifact_ids=("wave9-governance-report", "replay-manifest", "scorecard"),
        metric_ids=("policy-controls", "replay-validation", "evidence-trust"),
        human_review_ids=("human-review",),
    )
    same_report = build_default_wave10_standards_crosswalk(
        report_id="wave-10-standards",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        artifact_ids=("scorecard", "wave9-governance-report", "replay-manifest"),
        metric_ids=("evidence-trust", "policy-controls", "replay-validation"),
        human_review_ids=("human-review",),
    )

    assert report.report_id == "wave-10-standards"
    assert report.registry_id == "wave-10-registry"
    assert report.campaign_id == "wave-10-campaign"
    assert report.missing_required_frameworks == ()
    assert report.supported_mapping_ids == (
        "dod-cato-evidence-category-mapping",
        "github-artifact-attestation-reference",
        "nist-ssdf-governed-change-evidence",
        "openssf-scorecard-signal-reference",
        "oscal-assessment-results-style-evidence",
        "sbom-reference-inventory",
        "slsa-provenance-reference",
    )
    assert report.blocking_mapping_ids == ()
    assert report.findings == ()
    assert report.disposition is OperatingDisposition.READY
    assert report.to_envelope().disposition is OperatingDisposition.READY
    assert "does not certify" in report.disclaimer
    assert report.to_dict()["digest"] == same_report.to_dict()["digest"]


def test_standards_crosswalk_blocks_missing_required_frameworks() -> None:
    report = StandardsCrosswalkReport(
        report_id="missing-frameworks",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        mappings=(
            _mapping(
                mapping_id="ssdf-only",
                framework=StandardsFramework.NIST_SSDF,
            ),
        ),
    )

    assert {finding.code for finding in report.findings} == {
        "operating.standards.missing-required-framework",
    }
    assert {
        framework.value for framework in report.missing_required_frameworks
    } == {
        "oscal_assessment_results",
        "dod_cato",
        "slsa_provenance",
        "sbom",
        "github_artifact_attestation",
        "openssf_scorecard",
    }
    assert report.disposition is OperatingDisposition.BLOCKED


def test_standards_mapping_blocks_missing_artifact_metric_review_and_bad_claim_language() -> None:
    mapping = _mapping(
        mapping_id="bad-claim",
        framework=StandardsFramework.DOD_CATO,
        bounded_statement="This system is DoD approved and production ready.",
        required_artifact_ids=("missing-artifact",),
        required_metric_ids=("missing-metric",),
        required_human_review_ids=("missing-review",),
    )

    finding_codes = {finding.code for finding in mapping.findings}
    assert finding_codes == {
        "operating.standards.missing-human-review",
        "operating.standards.missing-required-artifact",
        "operating.standards.missing-required-metric",
        "operating.standards.prohibited-claim-term",
    }
    assert mapping.prohibited_claim_hits == ("dod approved", "production ready")
    assert mapping.blocking_gap is True


def test_standards_mapping_warns_for_partial_or_unverified_evidence() -> None:
    partial = _mapping(
        mapping_id="partial",
        framework=StandardsFramework.OPENSSF_SCORECARD,
        status=StandardsMappingStatus.PARTIAL,
    )
    unverified = _mapping(
        mapping_id="unverified",
        framework=StandardsFramework.SBOM,
        evidence_verified=False,
    )

    assert partial.warning_gap is True
    assert partial.blocking_gap is False
    assert {finding.code for finding in partial.findings} == {
        "operating.standards.partial-mapping",
    }
    assert unverified.warning_gap is True
    assert {finding.code for finding in unverified.findings} == {
        "operating.standards.unverified-evidence",
    }


def test_standards_mapping_blocks_missing_or_not_applicable_mandatory_mapping() -> None:
    missing = _mapping(
        mapping_id="missing",
        framework=StandardsFramework.SLSA_PROVENANCE,
        status=StandardsMappingStatus.MISSING,
    )
    not_applicable = _mapping(
        mapping_id="not-applicable",
        framework=StandardsFramework.GITHUB_ARTIFACT_ATTESTATION,
        status=StandardsMappingStatus.NOT_APPLICABLE,
    )

    assert missing.blocking_gap is True
    assert not_applicable.blocking_gap is True
    assert {finding.code for finding in missing.findings} == {
        "operating.standards.mapping-not-supported",
    }


def test_standards_crosswalk_rejects_duplicate_mapping_and_evidence_ids() -> None:
    mapping = _mapping(mapping_id="duplicate", framework=StandardsFramework.NIST_SSDF)

    with pytest.raises(ValueError, match="mapping_id values must be unique"):
        StandardsCrosswalkReport(
            report_id="duplicate-mappings",
            registry_id="wave10-registry",
            campaign_id="wave10-campaign",
            mappings=(mapping, mapping),
        )

    evidence = _evidence("duplicate")
    with pytest.raises(ValueError, match="evidence_id values must be unique"):
        StandardsControlMapping(
            mapping_id="duplicate-evidence",
            framework=StandardsFramework.NIST_SSDF,
            reference_id="SSDF",
            title="Duplicate evidence",
            bounded_statement="Mapping-ready evidence only.",
            evidence_refs=(evidence, evidence),
        )


def test_standards_evidence_requires_artifact_ids() -> None:
    with pytest.raises(ValueError, match="artifact_ids must not be empty"):
        StandardsEvidenceReference(
            evidence_id="empty",
            evidence_kind=StandardsEvidenceKind.POLICY,
            artifact_ids=(),
            description="Evidence without artifact binding must fail.",
        )


def _mapping(
    *,
    mapping_id: str,
    framework: StandardsFramework,
    bounded_statement: str = "Mapping-ready evidence only for this reviewed campaign scope.",
    required_artifact_ids: tuple[str, ...] = ("wave9-governance-report",),
    required_metric_ids: tuple[str, ...] = ("policy-controls",),
    required_human_review_ids: tuple[str, ...] = ("human-review",),
    status: StandardsMappingStatus = StandardsMappingStatus.SUPPORTED,
    evidence_verified: bool = True,
) -> StandardsControlMapping:
    return StandardsControlMapping(
        mapping_id=mapping_id,
        framework=framework,
        reference_id=f"{framework.value} reference",
        title=f"{framework.value} mapping",
        bounded_statement=bounded_statement,
        evidence_refs=(
            _evidence(
                "evidence",
                verified=evidence_verified,
            ),
        ),
        required_artifact_ids=required_artifact_ids,
        required_metric_ids=required_metric_ids,
        required_human_review_ids=required_human_review_ids,
        status=status,
    )


def _evidence(
    evidence_id: str,
    *,
    verified: bool = True,
) -> StandardsEvidenceReference:
    return StandardsEvidenceReference(
        evidence_id=evidence_id,
        evidence_kind=StandardsEvidenceKind.POLICY,
        artifact_ids=("wave9-governance-report",),
        description="Digest-bound evidence for standards mapping.",
        verified=verified,
        metric_ids=("policy-controls",),
        human_review_ids=("human-review",),
    )
