from __future__ import annotations

import json

import pytest

from ix_blackfox.operating import (
    ASFF_SCHEMA_VERSION,
    LOCAL_ASFF_EXPORT_FORMAT,
    CloudFindingComplianceStatus,
    CloudFindingResource,
    CloudFindingSeverityLabel,
    CloudSecurityFinding,
    CloudSecurityFindingExport,
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    build_cloud_security_export_from_envelope,
    cloud_compliance_from_disposition,
    cloud_severity_from_operating,
)


def test_cloud_security_finding_from_operating_finding_is_asff_shaped_local_json() -> None:
    finding = OperatingFinding(
        code="operating.policy.failed.human-authority-required",
        severity=OperatingSeverity.CRITICAL,
        summary="Human authority is missing for final Wave 10 readiness.",
        domains=(OperatingDomain.REVIEWABLE,),
        blocking=True,
    )

    cloud_finding = CloudSecurityFinding.from_operating_finding(
        finding=finding,
        source_id="wave10-operating-report",
        aws_account_id="123456789012",
        region="us-east-1",
        observed_at="2026-05-29T00:00:00Z",
        resource=_resource(),
    )
    asff = cloud_finding.to_asff_dict()

    assert asff["SchemaVersion"] == ASFF_SCHEMA_VERSION
    assert asff["Id"] == "wave10-operating-report/operating.policy.failed.human-authority-required"
    assert asff["AwsAccountId"] == "123456789012"
    assert asff["ProductArn"] == (
        "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
    )
    assert asff["Severity"] == {"Label": "CRITICAL", "Normalized": 100}
    assert asff["Compliance"] == {"Status": "FAILED"}
    assert asff["Workflow"] == {"Status": "NEW"}
    assert asff["RecordState"] == "ACTIVE"
    assert asff["Resources"][0]["Type"] == "AwsCodeRepository"
    assert asff["ProductFields"]["ix_blackfox.local_export"] == "true"
    assert asff["ProductFields"]["ix_blackfox.export_format"] == LOCAL_ASFF_EXPORT_FORMAT
    assert cloud_finding.operating_disposition is OperatingDisposition.BLOCKED


def test_cloud_security_export_from_envelope_is_deterministic_and_local_only() -> None:
    envelope = OperatingEnvelope(
        envelope_id="Wave 10 Operating Report",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="Wave 10 operating report",
        domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MEASURABLE),
        findings=(
            OperatingFinding(
                code="operating.replay.required-step-not-executed",
                severity=OperatingSeverity.CRITICAL,
                summary="Required replay step was not executed.",
                domains=(OperatingDomain.REPLAYABLE,),
                blocking=True,
            ),
            OperatingFinding(
                code="operating.scorecard.policy-gap",
                severity=OperatingSeverity.MEDIUM,
                summary="Policy scorecard includes a warning.",
                domains=(OperatingDomain.MEASURABLE,),
                blocking=False,
            ),
        ),
    )

    export = build_cloud_security_export_from_envelope(
        export_id=" Wave 10 Cloud Export ",
        envelope=envelope,
        aws_account_id="123456789012",
        region="us-west-2",
        observed_at="2026-05-29T00:00:00Z",
        resource=_resource(region="us-west-2"),
    )
    same_export = build_cloud_security_export_from_envelope(
        export_id="wave-10-cloud-export",
        envelope=envelope,
        aws_account_id="123456789012",
        region="us-west-2",
        observed_at="2026-05-29T00:00:00Z",
        resource=_resource(region="us-west-2"),
    )

    assert export.export_id == "wave-10-cloud-export"
    assert export.local_only is True
    assert export.finding_ids == (
        "wave-10-operating-report/operating.replay.required-step-not-executed",
        "wave-10-operating-report/operating.scorecard.policy-gap",
    )
    assert export.findings_count_by_severity == {"MEDIUM": 1, "CRITICAL": 1}
    assert export.findings_count_by_compliance == {"WARNING": 1, "FAILED": 1}
    assert export.critical_finding_ids == (
        "wave-10-operating-report/operating.replay.required-step-not-executed",
    )
    assert export.failed_compliance_finding_ids == (
        "wave-10-operating-report/operating.replay.required-step-not-executed",
    )
    assert export.missing_required_finding_ids == ()
    assert export.disposition is OperatingDisposition.WARNING
    assert export.to_envelope().disposition is OperatingDisposition.READY
    assert export.to_dict()["digest"] == same_export.to_dict()["digest"]
    assert json.loads(export.export_asff_json())[0]["SchemaVersion"] == ASFF_SCHEMA_VERSION
    assert json.loads(export.export_json())["export_format"] == LOCAL_ASFF_EXPORT_FORMAT


def test_cloud_security_export_blocks_missing_required_finding_ids() -> None:
    export = CloudSecurityFindingExport(
        export_id="missing-required",
        findings=(),
        required_finding_ids=("required/finding",),
    )

    assert export.missing_required_finding_ids == ("required/finding",)
    assert export.disposition is OperatingDisposition.BLOCKED
    assert export.to_envelope().disposition is OperatingDisposition.BLOCKED
    assert {finding.code for finding in export.findings_for_envelope} == {
        "operating.cloud.missing-required-finding",
    }


def test_cloud_security_export_rejects_live_export_mode_duplicate_ids_and_sensitive_keys() -> None:
    finding = _cloud_finding("finding/one")

    with pytest.raises(ValueError, match="local_only"):
        CloudSecurityFindingExport(
            export_id="not-local",
            findings=(finding,),
            local_only=False,
        )

    with pytest.raises(ValueError, match="finding_id values must be unique"):
        CloudSecurityFindingExport(
            export_id="duplicate",
            findings=(finding, finding),
        )

    with pytest.raises(ValueError, match="product field key is not allowed"):
        CloudSecurityFinding(
            finding_id="sensitive-product-field",
            title="Sensitive product field",
            description="Sensitive keys must never be exported.",
            severity_label=CloudFindingSeverityLabel.HIGH,
            compliance_status=CloudFindingComplianceStatus.FAILED,
            resource=_resource(),
            generator_id="test",
            aws_account_id="123456789012",
            region="us-east-1",
            observed_at="2026-05-29T00:00:00Z",
            product_fields={"aws_secret_access_key": "nope"},
        )

    with pytest.raises(ValueError, match="sensitive key name"):
        CloudFindingResource(
            resource_id="repo",
            resource_type="AwsCodeRepository",
            details={"credential": "nope"},
        )


def test_cloud_mapping_helpers_are_explicit_and_fail_on_bad_account_or_timestamp() -> None:
    assert cloud_severity_from_operating(OperatingSeverity.INFO) is CloudFindingSeverityLabel.INFORMATIONAL
    assert cloud_severity_from_operating(OperatingSeverity.CRITICAL) is CloudFindingSeverityLabel.CRITICAL
    assert cloud_compliance_from_disposition(OperatingDisposition.READY) is CloudFindingComplianceStatus.PASSED
    assert cloud_compliance_from_disposition(OperatingDisposition.WARNING) is CloudFindingComplianceStatus.WARNING
    assert cloud_compliance_from_disposition(OperatingDisposition.BLOCKED) is CloudFindingComplianceStatus.FAILED

    with pytest.raises(ValueError, match="12-digit"):
        _cloud_finding("bad-account", aws_account_id="not-an-account")

    with pytest.raises(ValueError, match="ISO-8601 UTC"):
        _cloud_finding("bad-time", observed_at="2026-05-29")


def test_cloud_security_export_allows_empty_local_exports_when_no_operating_findings_exist() -> None:
    envelope = OperatingEnvelope(
        envelope_id="ready-envelope",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        subject="Ready operating report",
        domains=(OperatingDomain.REVIEWABLE,),
        findings=(),
    )

    export = build_cloud_security_export_from_envelope(
        export_id="empty-ready-export",
        envelope=envelope,
        aws_account_id="123456789012",
        region="us-east-1",
        observed_at="2026-05-29T00:00:00Z",
        resource=_resource(),
    )

    assert export.finding_ids == ()
    assert export.required_finding_ids == ()
    assert export.disposition is OperatingDisposition.READY
    assert export.to_asff_findings() == []


def _resource(*, region: str = "us-east-1") -> CloudFindingResource:
    return CloudFindingResource(
        resource_id="arn:aws:codecommit:us-east-1:123456789012:ix-blackfox",
        resource_type="AwsCodeRepository",
        region=region,
        details={
            "Other": {
                "RepositoryName": "IX-BlackFox",
                "EvidenceScope": "Wave 10 local export",
            },
        },
    )


def _cloud_finding(
    finding_id: str,
    *,
    aws_account_id: str = "123456789012",
    observed_at: str = "2026-05-29T00:00:00Z",
) -> CloudSecurityFinding:
    return CloudSecurityFinding(
        finding_id=finding_id,
        title="Test cloud finding",
        description="Cloud finding used by tests.",
        severity_label=CloudFindingSeverityLabel.HIGH,
        compliance_status=CloudFindingComplianceStatus.FAILED,
        resource=_resource(),
        generator_id="test-generator",
        aws_account_id=aws_account_id,
        region="us-east-1",
        observed_at=observed_at,
    )
