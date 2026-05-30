from __future__ import annotations

import json

import pytest

from ix_blackfox.operating import (
    CloudFindingResource,
    CloudSecurityFindingExport,
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingExportFormat,
    OperatingExportPack,
    OperatingExportPackValidation,
    OperatingExportPayload,
    OperatingFinding,
    OperatingReport,
    OperatingReportClaim,
    OperatingReportSection,
    OperatingReportSectionKind,
    OperatingReportValidation,
    OperatingReviewBundle,
    OperatingSeverity,
    ReviewBundleArtifact,
    ReviewBundleSection,
    ReviewBundleSectionKind,
    StandardsCrosswalkReport,
    build_cloud_security_export_from_envelope,
    build_default_wave10_standards_crosswalk,
    build_wave10_local_export_pack,
)


def test_wave10_local_export_pack_binds_required_payloads_and_digests() -> None:
    report = _report()
    review_bundle = _review_bundle()
    standards = _standards()
    cloud_export = _cloud_export()
    validation = OperatingReportValidation(
        validation_id="report-validation",
        report=report,
        expected_digest=report.digest,
        observed_digest=report.digest,
        checked_by="platform security reviewer",
        observed_section_ids=report.section_ids,
    )

    pack = build_wave10_local_export_pack(
        pack_id=" Wave 10 Export Pack ",
        report=report,
        review_bundle=review_bundle,
        standards_crosswalk=standards,
        cloud_security_export=cloud_export,
        report_validation=validation,
    )
    same_pack = build_wave10_local_export_pack(
        pack_id="wave-10-export-pack",
        report=report,
        review_bundle=review_bundle,
        standards_crosswalk=standards,
        cloud_security_export=cloud_export,
        report_validation=validation,
    )

    assert pack.pack_id == "wave-10-export-pack"
    assert pack.local_only is True
    assert pack.payload_ids == (
        "cloud-security-export-asff",
        "cloud-security-export-index",
        "operating-report",
        "operating-report-validation",
        "review-bundle",
        "standards-crosswalk",
    )
    assert pack.required_payload_ids == pack.payload_ids
    assert pack.missing_required_payload_ids == ()
    assert pack.payload_count_by_kind == {
        "cloud_finding_export": 2,
        "operating_report": 2,
        "review_bundle": 1,
        "standards_crosswalk": 1,
    }
    assert pack.total_size_bytes > 0
    assert pack.findings == ()
    assert pack.disposition is OperatingDisposition.READY
    assert pack.to_envelope().disposition is OperatingDisposition.READY
    assert pack.to_dict()["digest"] == same_pack.to_dict()["digest"]
    assert json.loads(pack.export_manifest_json())["pack_id"] == "wave-10-export-pack"
    assert ".blackfox-artifacts/wave10/operating-report.json" in pack.export_payload_map()


def test_export_pack_validation_passes_matching_manifest_and_payload_digests() -> None:
    pack = _pack()
    observed = {payload.payload_id: payload.sha256 for payload in pack.payloads}

    validation = OperatingExportPackValidation(
        validation_id="export-validation",
        pack=pack,
        expected_manifest_digest=pack.manifest_digest,
        observed_manifest_digest=pack.manifest_digest,
        observed_payload_sha256=observed,
        checked_by="platform security reviewer",
    )

    assert validation.manifest_digest_matches is True
    assert validation.missing_observed_payload_ids == ()
    assert validation.mismatched_payload_ids == ()
    assert validation.unexpected_payload_ids == ()
    assert validation.passed is True
    assert validation.disposition is OperatingDisposition.READY
    assert validation.to_envelope().disposition is OperatingDisposition.READY


def test_export_pack_validation_blocks_manifest_mismatch_missing_payload_and_digest_mismatch() -> None:
    pack = _pack()
    first_payload = pack.payloads[0]
    validation = OperatingExportPackValidation(
        validation_id="bad-export-validation",
        pack=pack,
        expected_manifest_digest=pack.manifest_digest,
        observed_manifest_digest="bad-digest",
        observed_payload_sha256={
            first_payload.payload_id: "0" * 64,
            "unexpected-payload": "1" * 64,
        },
        checked_by="platform security reviewer",
    )

    finding_codes = {finding.code for finding in validation.findings}
    assert "operating.export.manifest-digest-mismatch" in finding_codes
    assert "operating.export.payload-digest-mismatch" in finding_codes
    assert "operating.export.required-payload-not-observed" in finding_codes
    assert "operating.export.unexpected-payload-observed" in finding_codes
    assert first_payload.payload_id in validation.mismatched_payload_ids
    assert validation.passed is False
    assert validation.disposition is OperatingDisposition.BLOCKED


def test_export_pack_blocks_missing_required_payload_and_required_payload_not_listed() -> None:
    payload = OperatingExportPayload(
        payload_id="required-but-unlisted",
        path=".blackfox-artifacts/wave10/required.json",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        content_type="application/json",
        body='{"ok":true}',
        required=True,
    )
    pack = OperatingExportPack(
        pack_id="bad-pack",
        report_id="report",
        campaign_id="campaign",
        repository_ids=("ix-blackfox",),
        payloads=(payload,),
        required_payload_ids=("missing-payload",),
    )

    finding_codes = {finding.code for finding in pack.findings}
    assert finding_codes == {
        "operating.export.missing-required-payload",
        "operating.export.required-payload-not-listed",
    }
    assert pack.missing_required_payload_ids == ("missing-payload",)
    assert pack.disposition is OperatingDisposition.BLOCKED


def test_export_pack_rejects_nonlocal_mode_duplicate_payloads_and_empty_scope() -> None:
    payload = OperatingExportPayload(
        payload_id="payload",
        path=".blackfox-artifacts/wave10/payload.json",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        content_type="application/json",
        body='{"ok":true}',
    )

    with pytest.raises(ValueError, match="local_only"):
        OperatingExportPack(
            pack_id="not-local",
            report_id="report",
            campaign_id="campaign",
            repository_ids=("ix-blackfox",),
            payloads=(payload,),
            required_payload_ids=("payload",),
            local_only=False,
        )

    with pytest.raises(ValueError, match="payload_id values must be unique"):
        OperatingExportPack(
            pack_id="duplicate",
            report_id="report",
            campaign_id="campaign",
            repository_ids=("ix-blackfox",),
            payloads=(payload, payload),
            required_payload_ids=("payload",),
        )

    with pytest.raises(ValueError, match="repository_ids must not be empty"):
        OperatingExportPack(
            pack_id="empty-repositories",
            report_id="report",
            campaign_id="campaign",
            repository_ids=(),
            payloads=(payload,),
            required_payload_ids=("payload",),
        )


def test_export_payload_digest_changes_when_body_changes() -> None:
    first = OperatingExportPayload(
        payload_id="payload",
        path=".blackfox-artifacts/wave10/payload.json",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        content_type="application/json",
        body='{"ok":true}',
        export_format=OperatingExportFormat.JSON_OBJECT,
    )
    second = OperatingExportPayload(
        payload_id="payload",
        path=".blackfox-artifacts/wave10/payload.json",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        content_type="application/json",
        body='{"ok":false}',
        export_format=OperatingExportFormat.JSON_OBJECT,
    )

    assert first.sha256 != second.sha256
    assert first.size_bytes != second.size_bytes
    assert first.artifact.sha256 == first.sha256


def _pack() -> OperatingExportPack:
    return build_wave10_local_export_pack(
        pack_id="wave-10-export-pack",
        report=_report(),
        review_bundle=_review_bundle(),
        standards_crosswalk=_standards(),
        cloud_security_export=_cloud_export(),
    )


def _report() -> OperatingReport:
    section = OperatingReportSection(
        section_id="registry",
        section_kind=OperatingReportSectionKind.REGISTRY,
        title="Registry section",
        envelope=_envelope("registry-envelope", "registry-artifact"),
        summary="Registry evidence.",
    )
    return OperatingReport(
        report_id="wave10-report",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        sections=(section,),
        claims=(
            OperatingReportClaim(
                claim_id="bounded",
                statement="Evidence exists for this reviewed campaign scope only.",
                supported_by_section_ids=("registry",),
                evidence_artifact_ids=("registry-artifact",),
            ),
        ),
        required_section_kinds=(OperatingReportSectionKind.REGISTRY,),
    )


def _review_bundle() -> OperatingReviewBundle:
    artifact = _envelope("review-envelope", "review-artifact").evidence[0]
    section = ReviewBundleSection(
        section_id="registry",
        section_kind=ReviewBundleSectionKind.REGISTRY,
        title="Registry review section",
        envelope=_envelope("review-envelope", "review-artifact"),
        reviewer_instructions=("Review registry evidence.",),
    )
    return OperatingReviewBundle(
        bundle_id="review-bundle",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        created_by="platform security reviewer",
        sections=(section,),
        artifacts=(ReviewBundleArtifact(artifact),),
        required_section_kinds=(ReviewBundleSectionKind.REGISTRY,),
    )


def _standards() -> StandardsCrosswalkReport:
    return build_default_wave10_standards_crosswalk(
        report_id="standards-crosswalk",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        artifact_ids=("registry-artifact",),
        metric_ids=("policy-controls",),
        human_review_ids=("human-review",),
    )


def _cloud_export() -> CloudSecurityFindingExport:
    envelope = OperatingEnvelope(
        envelope_id="cloud-source-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="Cloud export source",
        domains=(OperatingDomain.MEASURABLE,),
        findings=(
            OperatingFinding(
                code="operating.scorecard.policy-gap",
                severity=OperatingSeverity.MEDIUM,
                summary="Policy warning exported for cloud-security review.",
                domains=(OperatingDomain.MEASURABLE,),
                blocking=False,
            ),
        ),
    )
    return build_cloud_security_export_from_envelope(
        export_id="cloud-export",
        envelope=envelope,
        aws_account_id="123456789012",
        region="us-east-1",
        observed_at="2026-05-29T00:00:00Z",
        resource=CloudFindingResource(
            resource_id="arn:aws:codecommit:us-east-1:123456789012:ix-blackfox",
            resource_type="AwsCodeRepository",
            region="us-east-1",
        ),
    )


def _envelope(envelope_id: str, artifact_id: str) -> OperatingEnvelope:
    return OperatingEnvelope(
        envelope_id=envelope_id,
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject=f"{envelope_id} subject",
        domains=(OperatingDomain.REVIEWABLE,),
        evidence=(
            OperatingArtifactRef(
                artifact_id=artifact_id,
                kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
                source_wave=OperatingSourceWave.WAVE10,
                path=f".blackfox-artifacts/wave10/{artifact_id}.json",
                sha256="a" * 64,
                producer="IX-BlackFox export tests",
            ),
        ),
    )
