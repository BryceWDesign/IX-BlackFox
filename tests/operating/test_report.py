from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingReport,
    OperatingReportClaim,
    OperatingReportSection,
    OperatingReportSectionKind,
    OperatingReportValidation,
    OperatingSeverity,
    OperatingSourceWave,
)


def test_operating_report_is_ready_when_all_required_sections_and_claims_are_supported() -> None:
    report = _ready_report()
    same_report = _ready_report(report_id="wave-10-operating-report")

    assert report.report_id == "wave-10-operating-report"
    assert report.registry_id == "wave-10-registry"
    assert report.campaign_id == "wave-10-campaign"
    assert report.repository_ids == ("ix-blackfox",)
    assert report.missing_required_section_kinds == ()
    assert report.blocked_required_section_ids == ()
    assert report.warning_section_ids == ()
    assert report.unsupported_claim_ids == ()
    assert report.claim_ids_with_missing_artifacts == ()
    assert report.prohibited_claim_ids == ()
    assert report.findings == ()
    assert report.disposition is OperatingDisposition.READY
    assert report.to_envelope().disposition is OperatingDisposition.READY
    assert report.executive_summary["section_count"] == 15
    assert report.executive_summary["artifact_count"] == 15
    assert "does not certify" in report.disclaimer
    assert report.to_dict()["digest"] == same_report.to_dict()["digest"]
    assert '"disposition":"ready"' in report.export_json()


def test_operating_report_blocks_missing_required_sections() -> None:
    report = OperatingReport(
        report_id="missing-sections",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        sections=(
            _section("registry", OperatingReportSectionKind.REGISTRY),
        ),
        claims=(
            OperatingReportClaim(
                claim_id="bounded-claim",
                statement="Evidence exists for this reviewed campaign scope only.",
                supported_by_section_ids=("registry",),
                evidence_artifact_ids=("registry-artifact",),
            ),
        ),
    )

    assert "operating.report.missing-required-section" in {
        finding.code for finding in report.findings
    }
    assert OperatingReportSectionKind.TEAM_AUTHORITY in report.missing_required_section_kinds
    assert report.disposition is OperatingDisposition.BLOCKED


def test_operating_report_blocks_blocked_required_section_and_warns_warning_section() -> None:
    blocked = _section(
        "policy-gate",
        OperatingReportSectionKind.POLICY_GATE,
        findings=(
            OperatingFinding(
                code="operating.policy.failed.human-authority-required",
                severity=OperatingSeverity.CRITICAL,
                summary="Human authority is missing.",
                domains=(OperatingDomain.REVIEWABLE,),
                blocking=True,
            ),
        ),
    )
    warning = _section(
        "scorecard",
        OperatingReportSectionKind.SCORECARD,
        findings=(
            OperatingFinding(
                code="operating.scorecard.policy-gap",
                severity=OperatingSeverity.MEDIUM,
                summary="Policy scorecard has warning controls.",
                domains=(OperatingDomain.MEASURABLE,),
                blocking=False,
            ),
        ),
    )
    report = _ready_report(extra_sections=(blocked, warning))

    assert "policy-gate" in report.blocked_required_section_ids
    assert "scorecard" in report.warning_section_ids
    assert {
        "operating.report.blocked-required-section",
        "operating.report.warning-section",
    } <= {finding.code for finding in report.findings}
    assert report.disposition is OperatingDisposition.BLOCKED


def test_operating_report_blocks_unsupported_claim_missing_artifact_and_prohibited_terms() -> None:
    report = OperatingReport(
        report_id="bad-claims",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        sections=_ready_sections(),
        claims=(
            OperatingReportClaim(
                claim_id="unsupported",
                statement="Evidence exists for this reviewed campaign scope only.",
                supported_by_section_ids=("missing-section",),
            ),
            OperatingReportClaim(
                claim_id="missing-artifact",
                statement="Evidence exists for this reviewed campaign scope only.",
                supported_by_section_ids=("registry",),
                evidence_artifact_ids=("missing-artifact",),
            ),
            OperatingReportClaim(
                claim_id="bad-language",
                statement="This is DoD approved and production ready.",
                supported_by_section_ids=("registry",),
            ),
        ),
    )

    finding_codes = {finding.code for finding in report.findings}
    assert {
        "operating.report.unsupported-claim",
        "operating.report.claim-missing-evidence-artifact",
        "operating.report.prohibited-claim-term",
    } <= finding_codes
    assert report.unsupported_claim_ids == ("unsupported",)
    assert report.claim_ids_with_missing_artifacts == ("missing-artifact",)
    assert report.prohibited_claim_ids == ("bad-language",)
    assert report.disposition is OperatingDisposition.BLOCKED


def test_operating_report_validation_passes_matching_digest_and_observed_sections() -> None:
    report = _ready_report()
    validation = OperatingReportValidation(
        validation_id="report-validation",
        report=report,
        expected_digest=report.digest,
        observed_digest=report.digest,
        checked_by="platform security reviewer",
        observed_section_ids=report.section_ids,
    )

    assert validation.digest_matches is True
    assert validation.missing_observed_section_ids == ()
    assert validation.passed is True
    assert validation.disposition is OperatingDisposition.READY
    assert validation.to_envelope().disposition is OperatingDisposition.READY


def test_operating_report_validation_blocks_digest_mismatch_and_missing_sections() -> None:
    report = _ready_report()
    validation = OperatingReportValidation(
        validation_id="bad-report-validation",
        report=report,
        expected_digest=report.digest,
        observed_digest="bad-digest",
        checked_by="platform security reviewer",
        observed_section_ids=("registry",),
    )

    finding_codes = {finding.code for finding in validation.findings}
    assert "operating.report.digest-mismatch" in finding_codes
    assert "operating.report.section-not-observed" in finding_codes
    assert validation.digest_matches is False
    assert "team-authority" in validation.missing_observed_section_ids
    assert validation.passed is False
    assert validation.disposition is OperatingDisposition.BLOCKED


def test_operating_report_rejects_duplicate_sections_duplicate_claims_and_empty_claim_support() -> None:
    section = _section("duplicate", OperatingReportSectionKind.REGISTRY)
    with pytest.raises(ValueError, match="section_id values must be unique"):
        OperatingReport(
            report_id="duplicate-section",
            registry_id="wave10-registry",
            campaign_id="wave10-campaign",
            repository_ids=("ix-blackfox",),
            sections=(section, section),
            claims=(
                OperatingReportClaim(
                    claim_id="bounded",
                    statement="Evidence exists for this reviewed campaign scope only.",
                    supported_by_section_ids=("duplicate",),
                ),
            ),
        )

    claim = OperatingReportClaim(
        claim_id="duplicate",
        statement="Evidence exists for this reviewed campaign scope only.",
        supported_by_section_ids=("registry",),
    )
    with pytest.raises(ValueError, match="claim_id values must be unique"):
        OperatingReport(
            report_id="duplicate-claim",
            registry_id="wave10-registry",
            campaign_id="wave10-campaign",
            repository_ids=("ix-blackfox",),
            sections=_ready_sections(),
            claims=(claim, claim),
        )

    with pytest.raises(ValueError, match="supported_by_section_ids"):
        OperatingReportClaim(
            claim_id="bad-claim",
            statement="Evidence exists for this reviewed campaign scope only.",
            supported_by_section_ids=(),
        )


def _ready_report(
    *,
    report_id: str = " Wave 10 Operating Report ",
    extra_sections: tuple[OperatingReportSection, ...] = (),
) -> OperatingReport:
    sections_by_id = {section.section_id: section for section in _ready_sections()}
    for section in extra_sections:
        sections_by_id[section.section_id] = section

    return OperatingReport(
        report_id=report_id,
        registry_id="Wave 10 Registry",
        campaign_id="Wave 10 Campaign",
        repository_ids=("IX-BlackFox",),
        sections=tuple(sections_by_id.values()),
        claims=(
            OperatingReportClaim(
                claim_id="bounded-wave10-report-claim",
                statement=(
                    "Wave 10 evidence is assembled, digest-bound, replayable, "
                    "measurable, and reviewable for this campaign scope only."
                ),
                supported_by_section_ids=(
                    "registry",
                    "team-authority",
                    "campaign",
                    "evidence-inventory",
                    "replay-manifest",
                    "replay-validation",
                    "review-bundle",
                    "traceability",
                    "policy-gate",
                    "readiness-gate",
                    "trust-evaluation",
                    "falsification-gate",
                    "scorecard",
                    "standards-crosswalk",
                    "cloud-security-export",
                ),
                evidence_artifact_ids=(
                    "registry-artifact",
                    "team-authority-artifact",
                    "campaign-artifact",
                    "evidence-inventory-artifact",
                    "replay-manifest-artifact",
                    "replay-validation-artifact",
                    "review-bundle-artifact",
                    "traceability-artifact",
                    "policy-gate-artifact",
                    "readiness-gate-artifact",
                    "trust-evaluation-artifact",
                    "falsification-gate-artifact",
                    "scorecard-artifact",
                    "standards-crosswalk-artifact",
                    "cloud-security-export-artifact",
                ),
            ),
        ),
    )


def _ready_sections() -> tuple[OperatingReportSection, ...]:
    return (
        _section("registry", OperatingReportSectionKind.REGISTRY),
        _section("team-authority", OperatingReportSectionKind.TEAM_AUTHORITY),
        _section("campaign", OperatingReportSectionKind.CAMPAIGN_GRAPH),
        _section("evidence-inventory", OperatingReportSectionKind.EVIDENCE_INVENTORY),
        _section("replay-manifest", OperatingReportSectionKind.REPLAY_MANIFEST),
        _section("replay-validation", OperatingReportSectionKind.REPLAY_VALIDATION),
        _section("review-bundle", OperatingReportSectionKind.REVIEW_BUNDLE),
        _section("traceability", OperatingReportSectionKind.TRACEABILITY_MAP),
        _section("policy-gate", OperatingReportSectionKind.POLICY_GATE),
        _section("readiness-gate", OperatingReportSectionKind.READINESS_GATE),
        _section("trust-evaluation", OperatingReportSectionKind.TRUST_EVALUATION),
        _section("falsification-gate", OperatingReportSectionKind.FALSIFICATION_GATE),
        _section("scorecard", OperatingReportSectionKind.SCORECARD),
        _section("standards-crosswalk", OperatingReportSectionKind.STANDARDS_CROSSWALK),
        _section("cloud-security-export", OperatingReportSectionKind.CLOUD_SECURITY_EXPORT),
    )


def _section(
    section_id: str,
    section_kind: OperatingReportSectionKind,
    *,
    findings: tuple[OperatingFinding, ...] = (),
) -> OperatingReportSection:
    artifact_id = f"{section_id}-artifact"
    envelope = OperatingEnvelope(
        envelope_id=f"{section_id}-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject=f"{section_id} report section",
        domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
        evidence=(_artifact(artifact_id),),
        findings=findings,
    )
    return OperatingReportSection(
        section_id=section_id,
        section_kind=section_kind,
        title=f"{section_id} section",
        envelope=envelope,
        summary="Digest-bound section for Wave 10 operating report review.",
        reviewer_actions=("Review the section disposition and envelope digest.",),
    )


def _artifact(artifact_id: str) -> OperatingArtifactRef:
    normalized = artifact_id.strip().lower().replace(" ", "-")
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f".blackfox-artifacts/wave10/{normalized}.json",
        sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        producer="IX-BlackFox Wave 10 operating report tests",
    )
