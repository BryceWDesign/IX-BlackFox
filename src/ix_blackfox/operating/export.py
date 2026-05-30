from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.cloud import CloudSecurityFindingExport
from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    OperatingSourceWave,
    digest_payload,
    normalize_identifier,
    normalize_relative_path,
    normalize_sha256,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple
from ix_blackfox.operating.report import OperatingReport, OperatingReportValidation
from ix_blackfox.operating.review_bundle import OperatingReviewBundle
from ix_blackfox.operating.standards import StandardsCrosswalkReport

LOCAL_EXPORT_SCHEMA_VERSION = "wave10.local_export_pack.v1"


class OperatingExportFormat(StrEnum):
    """Supported local export payload formats."""

    JSON = auto()
    JSON_OBJECT = auto()
    ASFF_JSON = auto()
    MARKDOWN = auto()


@dataclass(frozen=True, slots=True)
class OperatingExportPayload:
    """Single digest-bound payload inside a Wave 10 local export pack."""

    payload_id: str
    path: str
    artifact_kind: OperatingArtifactKind
    content_type: str
    body: str
    export_format: OperatingExportFormat = OperatingExportFormat.JSON_OBJECT
    required: bool = True
    source_artifact_ids: tuple[str, ...] = ()
    source_envelope_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "payload_id",
            normalize_identifier(self.payload_id, label="payload_id"),
        )
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "content_type",
            normalize_text(self.content_type, label="content_type"),
        )
        object.__setattr__(self, "body", normalize_payload_body(self.body))
        object.__setattr__(
            self,
            "source_artifact_ids",
            normalize_identifier_tuple(
                self.source_artifact_ids,
                label="source_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "source_envelope_ids",
            normalize_identifier_tuple(
                self.source_envelope_ids,
                label="source_envelope_ids",
            ),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def format(self) -> OperatingExportFormat:
        return self.export_format

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8")).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.body.encode("utf-8"))

    @property
    def byte_length(self) -> int:
        return self.size_bytes

    @property
    def artifact(self) -> OperatingArtifactRef:
        return self.to_artifact_ref()

    def to_artifact_ref(self) -> OperatingArtifactRef:
        return OperatingArtifactRef(
            artifact_id=self.payload_id,
            kind=self.artifact_kind,
            source_wave=OperatingSourceWave.WAVE10,
            path=self.path,
            sha256=self.sha256,
            producer="IX-BlackFox Wave 10 local export pack",
            schema_version=LOCAL_EXPORT_SCHEMA_VERSION,
            metadata={
                "content_type": self.content_type,
                "export_format": self.export_format.value,
                "required": self.required,
                "size_bytes": self.size_bytes,
                "source_artifact_ids": list(self.source_artifact_ids),
                "source_envelope_ids": list(self.source_envelope_ids),
            },
        )

    def to_dict(self, *, include_body: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "payload_id": self.payload_id,
            "artifact_kind": self.artifact_kind.value,
            "content_type": self.content_type,
            "export_format": self.export_format.value,
            "format": self.export_format.value,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "byte_length": self.byte_length,
            "required": self.required,
            "source_artifact_ids": list(self.source_artifact_ids),
            "source_envelope_ids": list(self.source_envelope_ids),
            "metadata": dict(self.metadata),
        }
        if include_body:
            payload["body"] = self.body
        return payload


@dataclass(frozen=True, slots=True)
class OperatingExportPack:
    """Local, deterministic Wave 10 export pack.

    The export pack is intentionally local-only. It prepares digest-bound JSON
    payloads that humans or approved downstream tooling can review. It does not
    upload to cloud services, grant execution authority, or claim certification.
    """

    pack_id: str
    report_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    payloads: tuple[OperatingExportPayload, ...]
    required_payload_ids: tuple[str, ...] = ()
    generated_by: str = "IX-BlackFox Wave 10 local export pack"
    local_only: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.local_only:
            raise ValueError("OperatingExportPack must remain local_only.")
        object.__setattr__(
            self,
            "pack_id",
            normalize_identifier(self.pack_id, label="pack_id"),
        )
        object.__setattr__(
            self,
            "report_id",
            normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "campaign_id",
            normalize_identifier(self.campaign_id, label="campaign_id"),
        )
        if not self.repository_ids:
            raise ValueError("OperatingExportPack repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        if not self.payloads:
            raise ValueError("OperatingExportPack payloads must not be empty.")
        payloads = tuple(sorted(self.payloads, key=lambda payload: payload.payload_id))
        payload_ids = [payload.payload_id for payload in payloads]
        if len(payload_ids) != len(set(payload_ids)):
            raise ValueError("OperatingExportPack payload_id values must be unique.")
        paths = [payload.path for payload in payloads]
        if len(paths) != len(set(paths)):
            raise ValueError("OperatingExportPack payload paths must be unique.")
        object.__setattr__(self, "payloads", payloads)
        if self.required_payload_ids:
            required_payload_ids = normalize_identifier_tuple(
                self.required_payload_ids,
                label="required_payload_ids",
            )
        else:
            required_payload_ids = tuple(
                payload.payload_id for payload in payloads if payload.required
            )
        object.__setattr__(self, "required_payload_ids", required_payload_ids)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def payload_ids(self) -> tuple[str, ...]:
        return tuple(payload.payload_id for payload in self.payloads)

    @property
    def payload_paths(self) -> tuple[str, ...]:
        return tuple(payload.path for payload in self.payloads)

    @property
    def missing_required_payload_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_payload_ids) - set(self.payload_ids)))

    @property
    def required_payload_ids_not_listed(self) -> tuple[str, ...]:
        required_payloads = {payload.payload_id for payload in self.payloads if payload.required}
        return tuple(sorted(required_payloads - set(self.required_payload_ids)))

    @property
    def payload_count_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for payload in self.payloads:
            kind = payload.artifact_kind.value
            counts[kind] = counts.get(kind, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def total_size_bytes(self) -> int:
        return sum(payload.size_bytes for payload in self.payloads)

    @property
    def total_bytes(self) -> int:
        return self.total_size_bytes

    @property
    def manifest_digest(self) -> str:
        return digest_payload(self.manifest_dict(include_digest=False))

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for payload_id in self.missing_required_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.missing-required-payload",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Operating export pack {self.pack_id} is missing required "
                        f"payload {payload_id}."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"pack_id": self.pack_id, "payload_id": payload_id},
                )
            )
        for payload_id in self.required_payload_ids_not_listed:
            findings.append(
                OperatingFinding(
                    code="operating.export.required-payload-not-listed",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Operating export pack {self.pack_id} contains required "
                        f"payload {payload_id}, but it is not listed as required."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"pack_id": self.pack_id, "payload_id": payload_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False, include_payload_bodies=True))

    def artifact_refs(self) -> tuple[OperatingArtifactRef, ...]:
        return tuple(payload.to_artifact_ref() for payload in self.payloads)

    def manifest_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        manifest: dict[str, Any] = {
            "schema_version": LOCAL_EXPORT_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "report_id": self.report_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "generated_by": self.generated_by,
            "local_only": self.local_only,
            "payload_count": len(self.payloads),
            "payload_ids": list(self.payload_ids),
            "required_payload_ids": list(self.required_payload_ids),
            "missing_required_payload_ids": list(self.missing_required_payload_ids),
            "required_payload_ids_not_listed": list(self.required_payload_ids_not_listed),
            "payload_paths": list(self.payload_paths),
            "payload_count_by_kind": self.payload_count_by_kind,
            "total_size_bytes": self.total_size_bytes,
            "total_bytes": self.total_bytes,
            "payloads": [payload.to_dict(include_body=False) for payload in self.payloads],
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            manifest["manifest_digest"] = self.manifest_digest
        return manifest

    def export_manifest_json(self) -> str:
        return json.dumps(self.manifest_dict(), sort_keys=True, separators=(",", ":"))

    def export_payload_map(self) -> dict[str, str]:
        return {payload.path: payload.body for payload in self.payloads}

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.pack_id}-export-pack-envelope",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            subject=f"Wave 10 local export pack {self.pack_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            evidence=self.artifact_refs(),
            findings=self.findings,
            metadata={
                "pack_id": self.pack_id,
                "report_id": self.report_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "schema_version": LOCAL_EXPORT_SCHEMA_VERSION,
                "local_only": self.local_only,
                "payload_ids": list(self.payload_ids),
                "required_payload_ids": list(self.required_payload_ids),
                "payload_paths": list(self.payload_paths),
                "payload_count_by_kind": self.payload_count_by_kind,
                "total_size_bytes": self.total_size_bytes,
                "manifest_digest": self.manifest_digest,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(
        self,
        *,
        include_digest: bool = True,
        include_payload_bodies: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": LOCAL_EXPORT_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "report_id": self.report_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "generated_by": self.generated_by,
            "local_only": self.local_only,
            "payloads": [
                export_payload.to_dict(include_body=include_payload_bodies)
                for export_payload in self.payloads
            ],
            "payload_ids": list(self.payload_ids),
            "required_payload_ids": list(self.required_payload_ids),
            "missing_required_payload_ids": list(self.missing_required_payload_ids),
            "required_payload_ids_not_listed": list(self.required_payload_ids_not_listed),
            "payload_paths": list(self.payload_paths),
            "payload_count_by_kind": self.payload_count_by_kind,
            "total_size_bytes": self.total_size_bytes,
            "total_bytes": self.total_bytes,
            "manifest": self.manifest_dict(),
            "disposition": self.disposition.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class OperatingExportPackValidation:
    """Validation report for a local Wave 10 export pack."""

    validation_id: str
    pack: OperatingExportPack
    expected_manifest_digest: str
    observed_manifest_digest: str
    observed_payload_sha256: Mapping[str, str]
    checked_by: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "validation_id",
            normalize_identifier(self.validation_id, label="validation_id"),
        )
        object.__setattr__(
            self,
            "expected_manifest_digest",
            normalize_text(self.expected_manifest_digest, label="expected_manifest_digest"),
        )
        object.__setattr__(
            self,
            "observed_manifest_digest",
            normalize_text(self.observed_manifest_digest, label="observed_manifest_digest"),
        )
        object.__setattr__(
            self,
            "observed_payload_sha256",
            normalize_payload_sha256_mapping(self.observed_payload_sha256),
        )
        object.__setattr__(
            self,
            "checked_by",
            normalize_text(self.checked_by, label="checked_by"),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def expected_payload_sha256(self) -> dict[str, str]:
        return {payload.payload_id: payload.sha256 for payload in self.pack.payloads}

    @property
    def missing_observed_payload_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self.pack.required_payload_ids) - set(self.observed_payload_sha256))
        )

    @property
    def missing_payload_ids(self) -> tuple[str, ...]:
        return self.missing_observed_payload_ids

    @property
    def unexpected_payload_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.observed_payload_sha256) - set(self.pack.payload_ids)))

    @property
    def mismatched_payload_ids(self) -> tuple[str, ...]:
        expected = self.expected_payload_sha256
        return tuple(
            sorted(
                payload_id
                for payload_id, expected_sha in expected.items()
                if self.observed_payload_sha256.get(payload_id) not in (None, expected_sha)
            )
        )

    @property
    def manifest_digest_matches(self) -> bool:
        return (
            self.expected_manifest_digest
            == self.observed_manifest_digest
            == self.pack.manifest_digest
        )

    @property
    def payload_sha256_matches(self) -> bool:
        return (
            not self.missing_observed_payload_ids
            and not self.unexpected_payload_ids
            and not self.mismatched_payload_ids
        )

    @property
    def passed(self) -> bool:
        return (
            self.pack.disposition is OperatingDisposition.READY
            and self.manifest_digest_matches
            and self.payload_sha256_matches
        )

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = [*self.pack.findings]
        if not self.manifest_digest_matches:
            findings.append(
                OperatingFinding(
                    code="operating.export.manifest-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Export pack validation {self.validation_id} observed "
                        "a manifest digest mismatch."
                    ),
                    domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "expected_manifest_digest": self.expected_manifest_digest,
                        "observed_manifest_digest": self.observed_manifest_digest,
                        "actual_manifest_digest": self.pack.manifest_digest,
                    },
                )
            )
        for payload_id in self.missing_observed_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.required-payload-not-observed",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Export pack validation {self.validation_id} did not observe "
                        f"required payload {payload_id}."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"payload_id": payload_id},
                )
            )
        for payload_id in self.unexpected_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.unexpected-payload-observed",
                    severity=OperatingSeverity.HIGH,
                    summary=(
                        f"Export pack validation {self.validation_id} observed "
                        f"unexpected payload {payload_id}."
                    ),
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"payload_id": payload_id},
                )
            )
        for payload_id in self.mismatched_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.payload-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary=(
                        f"Export pack validation {self.validation_id} observed "
                        f"a sha256 mismatch for payload {payload_id}."
                    ),
                    domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "payload_id": payload_id,
                        "expected_sha256": self.expected_payload_sha256[payload_id],
                        "observed_sha256": self.observed_payload_sha256[payload_id],
                    },
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> OperatingDisposition:
        return OperatingDisposition.READY if self.passed else OperatingDisposition.BLOCKED

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.validation_id}-export-pack-validation-envelope",
            artifact_kind=OperatingArtifactKind.POLICY_EVALUATION,
            subject=f"Wave 10 local export pack validation {self.validation_id}",
            domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
            findings=self.findings,
            metadata={
                "validation_id": self.validation_id,
                "pack_id": self.pack.pack_id,
                "expected_manifest_digest": self.expected_manifest_digest,
                "observed_manifest_digest": self.observed_manifest_digest,
                "manifest_digest_matches": self.manifest_digest_matches,
                "payload_sha256_matches": self.payload_sha256_matches,
                "missing_observed_payload_ids": list(self.missing_observed_payload_ids),
                "missing_payload_ids": list(self.missing_payload_ids),
                "unexpected_payload_ids": list(self.unexpected_payload_ids),
                "mismatched_payload_ids": list(self.mismatched_payload_ids),
                "passed": self.passed,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "validation_id": self.validation_id,
            "checked_by": self.checked_by,
            "pack_id": self.pack.pack_id,
            "expected_manifest_digest": self.expected_manifest_digest,
            "observed_manifest_digest": self.observed_manifest_digest,
            "manifest_digest_matches": self.manifest_digest_matches,
            "expected_payload_sha256": self.expected_payload_sha256,
            "observed_payload_sha256": dict(self.observed_payload_sha256),
            "payload_sha256_matches": self.payload_sha256_matches,
            "missing_observed_payload_ids": list(self.missing_observed_payload_ids),
            "missing_payload_ids": list(self.missing_payload_ids),
            "unexpected_payload_ids": list(self.unexpected_payload_ids),
            "mismatched_payload_ids": list(self.mismatched_payload_ids),
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_wave10_local_export_pack(
    *,
    pack_id: str,
    report: OperatingReport,
    review_bundle: OperatingReviewBundle,
    standards_crosswalk: StandardsCrosswalkReport,
    cloud_security_export: CloudSecurityFindingExport,
    report_validation: OperatingReportValidation | None = None,
) -> OperatingExportPack:
    """Build a deterministic local export pack from Wave 10 report artifacts."""

    report_section_envelope_ids = tuple(section.envelope.envelope_id for section in report.sections)
    review_section_envelope_ids = tuple(
        section.envelope.envelope_id for section in review_bundle.sections
    )
    payloads: list[OperatingExportPayload] = [
        json_payload(
            payload_id="operating-report",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            body=report.to_dict(),
            path=".blackfox-artifacts/wave10/operating-report.json",
            source_artifact_ids=report.artifact_ids,
            source_envelope_ids=report_section_envelope_ids,
        ),
        json_payload(
            payload_id="review-bundle",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            body=review_bundle.to_dict(),
            path=".blackfox-artifacts/wave10/review-bundle.json",
            source_artifact_ids=review_bundle.artifact_ids,
            source_envelope_ids=review_section_envelope_ids,
        ),
        json_payload(
            payload_id="standards-crosswalk",
            artifact_kind=OperatingArtifactKind.STANDARDS_CROSSWALK,
            body=standards_crosswalk.to_dict(),
            path=".blackfox-artifacts/wave10/standards-crosswalk.json",
            source_artifact_ids=standards_crosswalk.artifact_ids,
        ),
        OperatingExportPayload(
            payload_id="cloud-security-export-asff",
            path=".blackfox-artifacts/wave10/cloud-security-export-asff.json",
            artifact_kind=OperatingArtifactKind.CLOUD_FINDING_EXPORT,
            content_type="application/json",
            body=cloud_security_export.export_asff_json(),
            export_format=OperatingExportFormat.ASFF_JSON,
            source_envelope_ids=cloud_security_export.source_envelope_ids,
            metadata={
                "export_id": cloud_security_export.export_id,
                "finding_ids": list(cloud_security_export.finding_ids),
                "local_only": True,
            },
        ),
        json_payload(
            payload_id="cloud-security-export-index",
            artifact_kind=OperatingArtifactKind.CLOUD_FINDING_EXPORT,
            body=cloud_security_export.to_dict(),
            path=".blackfox-artifacts/wave10/cloud-security-export-index.json",
            source_envelope_ids=cloud_security_export.source_envelope_ids,
        ),
    ]
    if report_validation is not None:
        payloads.append(
            json_payload(
                payload_id="operating-report-validation",
                artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
                body=report_validation.to_dict(),
                path=".blackfox-artifacts/wave10/operating-report-validation.json",
                source_artifact_ids=report.artifact_ids,
                source_envelope_ids=report_section_envelope_ids,
            )
        )
    payloads_tuple = tuple(payloads)
    return OperatingExportPack(
        pack_id=pack_id,
        report_id=report.report_id,
        campaign_id=report.campaign_id,
        repository_ids=report.repository_ids,
        payloads=payloads_tuple,
        required_payload_ids=tuple(payload.payload_id for payload in payloads_tuple),
        metadata={
            "report_id": report.report_id,
            "review_bundle_id": review_bundle.bundle_id,
            "standards_crosswalk_id": standards_crosswalk.report_id,
            "cloud_security_export_id": cloud_security_export.export_id,
            "report_validation_id": (
                report_validation.validation_id if report_validation is not None else ""
            ),
        },
    )


def json_payload(
    *,
    payload_id: str,
    artifact_kind: OperatingArtifactKind,
    body: Mapping[str, Any],
    path: str | None = None,
    source_artifact_ids: Sequence[str] = (),
    source_envelope_ids: Sequence[str] = (),
) -> OperatingExportPayload:
    normalized_payload_id = normalize_identifier(payload_id, label="payload_id")
    return OperatingExportPayload(
        payload_id=normalized_payload_id,
        path=path or f".blackfox-artifacts/wave10/{normalized_payload_id}.json",
        artifact_kind=artifact_kind,
        content_type="application/json",
        body=json.dumps(body, sort_keys=True, separators=(",", ":")),
        export_format=OperatingExportFormat.JSON_OBJECT,
        source_artifact_ids=tuple(source_artifact_ids),
        source_envelope_ids=tuple(source_envelope_ids),
    )


def normalize_payload_body(value: str) -> str:
    if value == "":
        raise ValueError("payload body must not be empty.")
    return value


def normalize_payload_sha256_mapping(values: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for payload_id, sha256 in values.items():
        normalized[normalize_identifier(payload_id, label="payload_id")] = normalize_sha256(
            sha256
        )
    return dict(sorted(normalized.items()))


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
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return tuple(normalize_metadata_value(item) for item in value)
    raise ValueError(f"metadata contains unsupported value type: {type(value).__name__}")
