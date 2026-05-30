from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    DEFAULT_WAVE10_REPORT_SECTION_KINDS,
    OperatingDisposition,
    OperatingReportSectionKind,
    build_minimal_wave10_operating_assembly,
    section_id_for_report_kind,
)


def test_minimal_wave10_operating_assembly_is_ready_and_deterministic() -> None:
    assembly = build_minimal_wave10_operating_assembly(
        assembly_id=" Wave 10 Assembly ",
        registry_id="Wave 10 Registry",
        campaign_id="Wave 10 Campaign",
        repository_ids=("IX-BlackFox",),
    )
    same_assembly = build_minimal_wave10_operating_assembly(
        assembly_id="wave-10-assembly",
        registry_id="wave-10-registry",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
    )

    assert assembly.assembly_id == "wave-10-assembly"
    assert assembly.all_ready is True
    assert assembly.blocking_findings_count == 0
    assert assembly.warning_findings_count == 0
    assert assembly.dispositions == {
        "report": "ready",
        "report_validation": "ready",
        "review_bundle": "ready",
        "standards_crosswalk": "ready",
        "cloud_security_export": "ready",
        "export_pack": "ready",
        "export_pack_validation": "ready",
    }
    assert assembly.report.disposition is OperatingDisposition.READY
    assert assembly.report_validation.passed is True
    assert assembly.export_pack_validation.passed is True
    assert assembly.report.executive_summary["section_count"] == 15
    assert assembly.report.executive_summary["artifact_count"] == 15
    assert assembly.report.missing_required_section_kinds == ()
    assert assembly.export_pack.required_payload_ids == (
        "cloud-security-export-asff",
        "cloud-security-export-index",
        "operating-report",
        "operating-report-validation",
        "review-bundle",
        "standards-crosswalk",
    )
    assert assembly.to_dict()["digest"] == same_assembly.to_dict()["digest"]


def test_minimal_wave10_operating_assembly_preserves_bounded_claim_language() -> None:
    assembly = build_minimal_wave10_operating_assembly()

    report_claim = assembly.report.claims[0]
    assert "campaign scope only" in report_claim.statement
    assert report_claim.prohibited_claim_hits == ()
    assert "does not certify" in assembly.report.disclaimer
    assert assembly.cloud_security_export.local_only is True
    assert assembly.export_pack.local_only is True


def test_minimal_wave10_operating_assembly_links_report_validation_and_export_validation() -> None:
    assembly = build_minimal_wave10_operating_assembly()

    assert assembly.report_validation.expected_digest == assembly.report.digest
    assert assembly.report_validation.observed_digest == assembly.report.digest
    assert assembly.report_validation.observed_section_ids == assembly.report.section_ids
    assert assembly.export_pack_validation.expected_manifest_digest == assembly.export_pack.manifest_digest
    assert assembly.export_pack_validation.observed_manifest_digest == assembly.export_pack.manifest_digest
    assert set(assembly.export_pack_validation.observed_payload_sha256) == set(
        assembly.export_pack.payload_ids
    )


def test_minimal_wave10_operating_assembly_builds_all_required_report_sections() -> None:
    assembly = build_minimal_wave10_operating_assembly()

    expected_section_ids = tuple(
        section_id_for_report_kind(section_kind)
        for section_kind in DEFAULT_WAVE10_REPORT_SECTION_KINDS
    )

    assert assembly.report.section_ids == expected_section_ids
    assert assembly.report.section_kinds_present == tuple(sorted(
        DEFAULT_WAVE10_REPORT_SECTION_KINDS,
        key=lambda kind: kind.value,
    ))
    assert OperatingReportSectionKind.CLOUD_SECURITY_EXPORT in assembly.report.section_kinds_present


def test_minimal_wave10_operating_assembly_rejects_invalid_cloud_account_id() -> None:
    with pytest.raises(ValueError, match="12-digit"):
        build_minimal_wave10_operating_assembly(
            aws_account_id="not-an-account",
        )


def test_section_id_for_report_kind_is_stable_and_hyphenated() -> None:
    assert section_id_for_report_kind(OperatingReportSectionKind.TEAM_AUTHORITY) == "team-authority"
    assert section_id_for_report_kind(OperatingReportSectionKind.CLOUD_SECURITY_EXPORT) == (
        "cloud-security-export"
    )
