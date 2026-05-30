from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple, normalize_text_tuple


ASFF_SCHEMA_VERSION = "2018-10-08"
LOCAL_ASFF_EXPORT_FORMAT = "aws_security_finding_format.local_json.v1"
_SENSITIVE_KEY_FRAGMENTS = (
    "access_key",
    "secret",
    "password",
    "credential",
    "session_token",
    "private_key",
    "api_key",
)


class CloudFindingSeverityLabel(StrEnum):
    """AWS Security Finding Format-compatible severity labels."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CloudFindingComplianceStatus(StrEnum):
    """AWS Security Finding Format-compatible compliance status labels."""

    PASSED = "PASSED"
    WARNING = "WARNING"
    FAILED = "FAILED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class CloudFindingWorkflowStatus(StrEnum):
    """AWS Security Finding Format-compatible workflow status labels."""

    NEW = "NEW"
    NOTIFIED = "NOTIFIED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class CloudFindingRecordState(StrEnum):
    """AWS Security Finding Format-compatible record state labels."""

    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


@dataclass(frozen=True, slots=True)
class CloudFindingResource:
    """ASFF-shaped resource reference for a local cloud-security finding export."""

    resource_id: str
    resource_type: str
    partition: str = "aws"
    region: str = "us-east-1"
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "resource_id",
            normalize_text(self.resource_id, label="resource_id"),
        )
        object.__setattr__(
            self,
            "resource_type",
            normalize_text(self.resource_type, label="resource_type"),
        )
        object.__setattr__(
            self,
            "partition",
            normalize_identifier(self.partition, label="partition"),
        )
        object.__setattr__(self, "region", normalize_aws_region(self.region))
        safe_details = normalize_json_mapping(self.details, label="details")
        reject_sensitive_mapping_keys(safe_details, label="details")
        object.__setattr__(self, "details", safe_details)

    def to_asff_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "Id": self.resource_id,
            "Type": self.resource_type,
            "Partition": self.partition,
            "Region": self.region,
        }
        if self.details:
            payload["Details"] = dict(self.details)
        return payload

    def to_dict(self) -> dict[str, Any]:
        return self.to_asff_dict()


@dataclass(frozen=True, slots=True)
class CloudSecurityFinding:
    """ASFF-shaped local finding derived from Wave 10 operating evidence.

    This object intentionally does not send anything to AWS. It only creates
    deterministic, local JSON that cloud-security teams can inspect, transform,
    or import through their own approved pipeline.
    """

    finding_id: str
    title: str
    description: str
    severity_label: CloudFindingSeverityLabel
    compliance_status: CloudFindingComplianceStatus
    resource: CloudFindingResource
    generator_id: str
    aws_account_id: str
    region: str
    observed_at: str
    product_name: str = "IX-BlackFox"
    company_name: str = "Bryce Lovell"
    workflow_status: CloudFindingWorkflowStatus = CloudFindingWorkflowStatus.NEW
    record_state: CloudFindingRecordState = CloudFindingRecordState.ACTIVE
    types: tuple[str, ...] = (
        "Software and Configuration Checks/Industry and Regulatory Standards",
    )
    updated_at: str = ""
    product_fields: Mapping[str, str] = field(default_factory=dict)
    operating_disposition: OperatingDisposition = OperatingDisposition.BLOCKED
    operating_finding_code: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "finding_id",
            normalize_finding_id(self.finding_id),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        object.__setattr__(
            self,
            "description",
            normalize_text(self.description, label="description"),
        )
        object.__setattr__(
            self,
            "generator_id",
            normalize_identifier(self.generator_id, label="generator_id"),
        )
        object.__setattr__(
            self,
            "aws_account_id",
            normalize_aws_account_id(self.aws_account_id),
        )
        object.__setattr__(self, "region", normalize_aws_region(self.region))
        object.__setattr__(
            self,
            "observed_at",
            normalize_timestamp_text(self.observed_at, label="observed_at"),
        )
        object.__setattr__(
            self,
            "updated_at",
            normalize_optional_timestamp_text(self.updated_at, label="updated_at"),
        )
        object.__setattr__(
            self,
            "product_name",
            normalize_text(self.product_name, label="product_name"),
        )
        object.__setattr__(
            self,
            "company_name",
            normalize_text(self.company_name, label="company_name"),
        )
        object.__setattr__(self, "types", normalize_text_tuple(self.types, label="types"))
        object.__setattr__(
            self,
            "product_fields",
            normalize_product_fields(self.product_fields),
        )
        object.__setattr__(
            self,
            "operating_finding_code",
            normalize_optional_text(
                self.operating_finding_code,
                label="operating_finding_code",
            ),
        )
        safe_metadata = normalize_json_mapping(self.metadata, label="metadata")
        reject_sensitive_mapping_keys(safe_metadata, label="metadata")
        object.__setattr__(self, "metadata", safe_metadata)

    @classmethod
    def from_operating_finding(
        cls,
        *,
        finding: OperatingFinding,
        source_id: str,
        aws_account_id: str,
        region: str,
        observed_at: str,
        resource: CloudFindingResource,
        product_fields: Mapping[str, str] | None = None,
    ) -> CloudSecurityFinding:
        disposition = (
            OperatingDisposition.BLOCKED if finding.blocking else OperatingDisposition.WARNING
        )
        return cls(
            finding_id=f"{source_id}/{finding.code}",
            title=finding.code,
            description=finding.summary,
            severity_label=cloud_severity_from_operating(finding.severity),
            compliance_status=cloud_compliance_from_disposition(disposition),
            resource=resource,
            generator_id=source_id,
            aws_account_id=aws_account_id,
            region=region,
            observed_at=observed_at,
            product_fields={
                "ix_blackfox.source": source_id,
                "ix_blackfox.operating_finding_code": finding.code,
                "ix_blackfox.operating_severity": finding.severity.value,
                "ix_blackfox.operating_blocking": str(finding.blocking).lower(),
                **dict(product_fields or {}),
            },
            operating_disposition=disposition,
            operating_finding_code=finding.code,
            metadata={"operating_finding": finding.to_dict()},
        )

    @property
    def product_arn(self) -> str:
        return (
            f"arn:aws:securityhub:{self.region}:{self.aws_account_id}:"
            f"product/{self.aws_account_id}/default"
        )

    @property
    def normalized_severity(self) -> int:
        mapping: dict[CloudFindingSeverityLabel, int] = {
            CloudFindingSeverityLabel.INFORMATIONAL: 0,
            CloudFindingSeverityLabel.LOW: 25,
            CloudFindingSeverityLabel.MEDIUM: 50,
            CloudFindingSeverityLabel.HIGH: 75,
            CloudFindingSeverityLabel.CRITICAL: 100,
        }
        return mapping[self.severity_label]

    @property
    def effective_updated_at(self) -> str:
        return self.updated_at or self.observed_at

    def to_asff_dict(self) -> dict[str, Any]:
        product_fields = {
            "ix_blackfox.local_export": "true",
            "ix_blackfox.export_format": LOCAL_ASFF_EXPORT_FORMAT,
            "ix_blackfox.operating_disposition": self.operating_disposition.value,
            **dict(self.product_fields),
        }
        return {
            "SchemaVersion": ASFF_SCHEMA_VERSION,
            "Id": self.finding_id,
            "ProductArn": self.product_arn,
            "ProductName": self.product_name,
            "CompanyName": self.company_name,
            "GeneratorId": self.generator_id,
            "AwsAccountId": self.aws_account_id,
            "Types": list(self.types),
            "FirstObservedAt": self.observed_at,
            "CreatedAt": self.observed_at,
            "UpdatedAt": self.effective_updated_at,
            "Severity": {
                "Label": self.severity_label.value,
                "Normalized": self.normalized_severity,
            },
            "Title": self.title,
            "Description": self.description,
            "Resources": [self.resource.to_asff_dict()],
            "Compliance": {"Status": self.compliance_status.value},
            "Workflow": {"Status": self.workflow_status.value},
            "RecordState": self.record_state.value,
            "ProductFields": product_fields,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity_label": self.severity_label.value,
            "normalized_severity": self.normalized_severity,
            "compliance_status": self.compliance_status.value,
            "workflow_status": self.workflow_status.value,
            "record_state": self.record_state.value,
            "resource": self.resource.to_dict(),
            "generator_id": self.generator_id,
            "aws_account_id": self.aws_account_id,
            "region": self.region,
            "observed_at": self.observed_at,
            "updated_at": self.updated_at,
            "effective_updated_at": self.effective_updated_at,
            "product_name": self.product_name,
            "company_name": self.company_name,
            "types": list(self.types),
            "product_arn": self.product_arn,
            "product_fields": dict(self.product_fields),
            "operating_disposition": self.operating_disposition.value,
            "operating_finding_code": self.operating_finding_code,
            "asff": self.to_asff_dict(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CloudSecurityFindingExport:
    """Deterministic local ASFF-shaped export for cloud-security review."""

    export_id: str
    findings: tuple[CloudSecurityFinding, ...]
    source_envelope_ids: tuple[str, ...] = ()
    required_finding_ids: tuple[str, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 local cloud-security export"
    local_only: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.local_only:
            raise ValueError("CloudSecurityFindingExport must remain local_only.")
        object.__setattr__(
            self,
            "export_id",
            normalize_identifier(self.export_id, label="export_id"),
        )
        findings = tuple(sorted(self.findings, key=lambda finding: finding.finding_id))
        finding_ids = [finding.finding_id for finding in findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("CloudSecurityFindingExport finding_id values must be unique.")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self,
            "source_envelope_ids",
            normalize_identifier_tuple(
                self.source_envelope_ids,
                label="source_envelope_ids",
            ),
        )
        object.__setattr__(
            self,
            "required_finding_ids",
            normalize_finding_id_tuple(
                self.required_finding_ids,
                label="required_finding_ids",
            ),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        safe_metadata = normalize_json_mapping(self.metadata, label="metadata")
        reject_sensitive_mapping_keys(safe_metadata, label="metadata")
        object.__setattr__(self, "metadata", safe_metadata)

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(finding.finding_id for finding in self.findings)

    @property
    def missing_required_finding_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_finding_ids) - set(self.finding_ids)))

    @property
    def critical_finding_ids(self) -> tuple[str, ...]:
        return tuple(
            finding.finding_id
            for finding in self.findings
            if finding.severity_label is CloudFindingSeverityLabel.CRITICAL
        )

    @property
    def failed_compliance_finding_ids(self) -> tuple[str, ...]:
        return tuple(
            finding.finding_id
            for finding in self.findings
            if finding.compliance_status is CloudFindingComplianceStatus.FAILED
        )

    @property
    def findings_count_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in CloudFindingSeverityLabel}
        for finding in self.findings:
            counts[finding.severity_label.value] += 1
        return {severity: count for severity, count in counts.items() if count > 0}

    @property
    def findings_count_by_compliance(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CloudFindingComplianceStatus}
        for finding in self.findings:
            counts[finding.compliance_status.value] += 1
        return {status: count for status, count in counts.items() if count > 0}

    @property
    def findings_summary(self) -> dict[str, Any]:
        return {
            "finding_count": len(self.findings),
            "critical_finding_ids": list(self.critical_finding_ids),
            "failed_compliance_finding_ids": list(self.failed_compliance_finding_ids),
            "severity_counts": self.findings_count_by_severity,
            "compliance_counts": self.findings_count_by_compliance,
            "missing_required_finding_ids": list(self.missing_required_finding_ids),
        }

    @property
    def findings_for_envelope(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for finding_id in self.missing_required_finding_ids:
            findings.append(
                OperatingFinding(
                    code="operating.cloud.missing-required-finding",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Cloud-security export {self.export_id} is missing "
                        f"required finding {finding_id}."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"export_id": self.export_id, "finding_id": finding_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if self.missing_required_finding_ids:
            return OperatingDisposition.BLOCKED
        if self.failed_compliance_finding_ids or self.critical_finding_ids:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_asff_findings(self) -> list[dict[str, Any]]:
        return [finding.to_asff_dict() for finding in self.findings]

    def export_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def export_asff_json(self) -> str:
        return json.dumps(self.to_asff_findings(), sort_keys=True, separators=(",", ":"))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.export_id}-cloud-security-export-envelope",
            artifact_kind=OperatingArtifactKind.CLOUD_FINDING_EXPORT,
            subject=f"Wave 10 local cloud-security finding export {self.export_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            findings=self.findings_for_envelope,
            metadata={
                "export_id": self.export_id,
                "export_format": LOCAL_ASFF_EXPORT_FORMAT,
                "local_only": self.local_only,
                "source_envelope_ids": list(self.source_envelope_ids),
                "finding_ids": list(self.finding_ids),
                "required_finding_ids": list(self.required_finding_ids),
                "findings_summary": self.findings_summary,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "export_id": self.export_id,
            "export_format": LOCAL_ASFF_EXPORT_FORMAT,
            "asff_schema_version": ASFF_SCHEMA_VERSION,
            "generated_by": self.generated_by,
            "local_only": self.local_only,
            "source_envelope_ids": list(self.source_envelope_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "asff_findings": self.to_asff_findings(),
            "finding_ids": list(self.finding_ids),
            "required_finding_ids": list(self.required_finding_ids),
            "findings_summary": self.findings_summary,
            "findings_for_envelope": [
                finding.to_dict() for finding in self.findings_for_envelope
            ],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_cloud_security_export_from_envelope(
    *,
    export_id: str,
    envelope: OperatingEnvelope,
    aws_account_id: str,
    region: str,
    observed_at: str,
    resource: CloudFindingResource,
    product_fields: Mapping[str, str] | None = None,
) -> CloudSecurityFindingExport:
    """Build a deterministic local ASFF-shaped export from an operating envelope."""

    source_id = envelope.envelope_id
    findings = tuple(
        CloudSecurityFinding.from_operating_finding(
            finding=finding,
            source_id=source_id,
            aws_account_id=aws_account_id,
            region=region,
            observed_at=observed_at,
            resource=resource,
            product_fields=product_fields,
        )
        for finding in envelope.findings
    )
    return CloudSecurityFindingExport(
        export_id=export_id,
        findings=findings,
        source_envelope_ids=(envelope.envelope_id,),
        required_finding_ids=tuple(finding.finding_id for finding in findings),
        metadata={
            "source_envelope_disposition": envelope.disposition.value,
            "source_artifact_kind": envelope.artifact_kind.value,
            "source_subject": envelope.subject,
        },
    )


def cloud_severity_from_operating(
    severity: OperatingSeverity,
) -> CloudFindingSeverityLabel:
    mapping: dict[OperatingSeverity, CloudFindingSeverityLabel] = {
        OperatingSeverity.INFO: CloudFindingSeverityLabel.INFORMATIONAL,
        OperatingSeverity.LOW: CloudFindingSeverityLabel.LOW,
        OperatingSeverity.MEDIUM: CloudFindingSeverityLabel.MEDIUM,
        OperatingSeverity.HIGH: CloudFindingSeverityLabel.HIGH,
        OperatingSeverity.CRITICAL: CloudFindingSeverityLabel.CRITICAL,
    }
    return mapping[severity]


def cloud_compliance_from_disposition(
    disposition: OperatingDisposition,
) -> CloudFindingComplianceStatus:
    mapping: dict[OperatingDisposition, CloudFindingComplianceStatus] = {
        OperatingDisposition.READY: CloudFindingComplianceStatus.PASSED,
        OperatingDisposition.WARNING: CloudFindingComplianceStatus.WARNING,
        OperatingDisposition.BLOCKED: CloudFindingComplianceStatus.FAILED,
    }
    return mapping[disposition]


def normalize_aws_account_id(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) != 12 or not cleaned.isdigit():
        raise ValueError("aws_account_id must be a 12-digit account id for ASFF-shaped export.")
    return cleaned


def normalize_aws_region(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("region must not be empty.")
    allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    if any(char not in allowed_chars for char in cleaned):
        raise ValueError("region contains invalid characters.")
    return cleaned


def normalize_finding_id(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("finding_id must not be empty.")
    if ".." in cleaned.split("/"):
        raise ValueError("finding_id must not contain traversal segments.")
    return cleaned


def normalize_finding_id_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_finding_id(value)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def normalize_timestamp_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    if "T" not in cleaned or not cleaned.endswith("Z"):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp ending in Z.")
    return cleaned


def normalize_optional_timestamp_text(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_timestamp_text(value, label=label)


def normalize_product_fields(values: Mapping[str, str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in values.items():
        clean_key = normalize_text(str(key), label="product_field_key")
        if has_sensitive_key_fragment(clean_key):
            raise ValueError(f"product field key is not allowed: {clean_key}")
        fields[clean_key] = normalize_optional_text(str(value), label="product_field_value")
    return dict(sorted(fields.items()))


def normalize_json_mapping(values: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in values.items():
        clean_key = normalize_text(str(key), label=f"{label}_key")
        normalized[clean_key] = normalize_json_value(value, label=label)
    return dict(sorted(normalized.items()))


def normalize_json_value(value: Any, *, label: str) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        nested = normalize_json_mapping(value, label=label)
        reject_sensitive_mapping_keys(nested, label=label)
        return nested
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return tuple(normalize_json_value(item, label=label) for item in value)
    raise ValueError(f"{label} contains a non-JSON-compatible value: {type(value).__name__}")


def reject_sensitive_mapping_keys(values: Mapping[str, Any], *, label: str) -> None:
    for key, value in values.items():
        if has_sensitive_key_fragment(key):
            raise ValueError(f"{label} contains a sensitive key name: {key}")
        if isinstance(value, Mapping):
            reject_sensitive_mapping_keys(value, label=label)


def has_sensitive_key_fragment(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS)
