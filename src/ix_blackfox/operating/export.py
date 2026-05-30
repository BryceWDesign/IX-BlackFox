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
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple, normalize_text_tuple
from ix_blackfox.operating.report import OperatingReport, OperatingReportValidation
from ix_blackfox.operating.review_bundle import OperatingReviewBundle
from ix_blackfox.operating.standards import StandardsCrosswalkReport


class OperatingExportFormat(StrEnum):
    """Local export payload format."""

    JSON_OBJECT = auto()
    JSON_ARRAY = auto()
    TEXT = auto()


@dataclass(frozen=True, slots=True)
class OperatingExportPayload:
    """One deterministic payload included in a local Wave 10 export pack."""

    payload_id: str
    path: str
    artifact_kind: OperatingArtifactKind
    content_type: str
    body: str
    export_format: OperatingExportFormat = OperatingExportFormat.JSON_OBJECT
    source_id: str = ""
    required: bool = True
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
        object.__setattr__(self, "body", normalize_text(self.body, label="body"))
        object.__setattr__(
            self,
            "source_id",
            normalize_optional_identifier(self.source_id, label="source_id"),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def size_bytes(self) -> int:
        return len(self.body.encode("utf-8"))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8")).hexdigest()

    @property
    def artifact(self) -> OperatingArtifactRef:
        return OperatingArtifactRef(
            artifact_id=self.payload_id,
            kind=self.artifact_kind,
            source_wave=OperatingSourceWave.WAVE10,
            path=self.path,
            sha256=self.sha256,
            producer="IX-BlackFox Wave 10 local export pack",
            metadata={
                "content_type": self.content_type,
                "export_format": self.export_format.value,
                "size_bytes": self.size_bytes,
                "source_id": self.source_id,
                "required": self.required,
            },
        )

    def to_manifest_entry(self) -> dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "path": self.path,
            "artifact_kind": self.artifact_kind.value,
            "content_type": self.content_type,
            "export_format": self.export_format.value,
            "source_id": self.source_id,
            "required": self.required,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }

    def to_dict(self, *, include_body: bool = False) -> dict[str, Any]:
        payload = {
            "payload_id": self.payload_id,
            "path": self.path,
            "artifact_kind": self.artifact_kind.value,
            "content_type": self.content_type,
            "export_format": self.export_format.value,
            "source_id": self.source_id,
            "required": self.required,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }
        if include_body:
            payload["body"] = self.body
        return payload


@dataclass(frozen=True, slots=True)
class OperatingExportPack:
    """Deterministic local evidence package for Wave 10 review.

    The pack is an export manifest and payload index only. It does not write
    files, call cloud APIs, send evidence over a network, or authorize execution.
    """

    pack_id: str
    report_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    payloads: tuple[OperatingExportPayload, ...]
    required_payload_ids: tuple[str, ...]
    generated_by: str = "IX-BlackFox Wave 10 local export pack"
    local_only: bool = True
    reviewer_instructions: tuple[str, ...] = (
        "Review the manifest digest before trusting the package.",
        "Verify every required payload digest before using exported evidence.",
        "Treat this package as evidence for review, not as execution authority.",
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.local_only:
            raise ValueError("OperatingExportPack must remain local_only.")
        object.__setattr__(self, "pack_id", normalize_identifier(self.pack_id, label="pack_id"))
        object.__setattr__(self, "report_id", normalize_identifier(self.report_id, label="report_id"))
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
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
        object.__setattr__(self, "payloads", payloads)
        if not self.required_payload_ids:
            raise ValueError("OperatingExportPack required_payload_ids must not be empty.")
        object.__setattr__(
            self,
            "required_payload_ids",
            normalize_identifier_tuple(
                self.required_payload_ids,
                label="required_payload_ids",
            ),
        )
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(
            self,
            "reviewer_instructions",
            normalize_text_tuple(self.reviewer_instructions, label="reviewer_instructions"),
        )
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def payload_ids(self) -> tuple[str, ...]:
        return tuple(payload.payload_id for payload in self.payloads)

    @property
    def required_payloads(self) -> tuple[OperatingExportPayload, ...]:
        required = set(self.required_payload_ids)
        return tuple(payload for payload in self.payloads if payload.payload_id in required)

    @property
    def missing_required_payload_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_payload_ids) - set(self.payload_ids)))

    @property
    def optional_payload_ids(self) -> tuple[str, ...]:
        return tuple(
            payload.payload_id
            for payload in self.payloads
            if payload.payload_id not in set(self.required_payload_ids)
        )

    @property
    def total_size_bytes(self) -> int:
        return sum(payload.size_bytes for payload in self.payloads)

    @property
    def payload_count_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for payload in self.payloads:
            counts[payload.artifact_kind.value] = counts.get(payload.artifact_kind.value, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def manifest(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "report_id": self.report_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "generated_by": self.generated_by,
            "local_only": self.local_only,
            "payloads": [payload.to_manifest_entry() for payload in self.payloads],
            "payload_ids": list(self.payload_ids),
            "required_payload_ids": list(self.required_payload_ids),
            "optional_payload_ids": list(self.optional_payload_ids),
            "missing_required_payload_ids": list(self.missing_required_payload_ids),
            "payload_count_by_kind": self.payload_count_by_kind,
            "total_size_bytes": self.total_size_bytes,
            "reviewer_instructions": list(self.reviewer_instructions),
            "metadata": dict(self.metadata),
        }

    @property
    def manifest_digest(self) -> str:
        return digest_payload(self.manifest)

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []

        for payload_id in self.missing_required_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.missing-required-payload",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating export pack {self.pack_id} is missing required payload {payload_id}.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"pack_id": self.pack_id, "payload_id": payload_id},
                )
            )

        if self.total_size_bytes == 0:
            findings.append(
                OperatingFinding(
                    code="operating.export.empty-payload-body",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Operating export pack {self.pack_id} has no payload bytes.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={"pack_id": self.pack_id},
                )
            )

        for payload in self.payloads:
            if payload.required and payload.payload_id not in set(self.required_payload_ids):
                findings.append(
                    OperatingFinding(
                        code="operating.export.required-payload-not-listed",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Payload {payload.payload_id} is marked required but is "
                            "not listed in required_payload_ids."
                        ),
                        domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                        blocking=True,
                        metadata={"pack_id": self.pack_id, "payload_id": payload.payload_id},
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
        return digest_payload(self.to_dict(include_digest=False, include_payload_bodies=False))

    def export_manifest_json(self) -> str:
        return json.dumps(self.manifest, sort_keys=True, separators=(",", ":"))

    def export_index_json(self) -> str:
        return json.dumps(
            self.to_dict(include_payload_bodies=False),
            sort_keys=True,
            separators=(",", ":"),
        )

    def export_payload_map(self) -> dict[str, str]:
        return {payload.path: payload.body for payload in self.payloads}

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.pack_id}-export-pack-envelope",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            subject=f"Wave 10 local export pack {self.pack_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            evidence=tuple(payload.artifact for payload in self.payloads),
            findings=self.findings,
            metadata={
                "pack_id": self.pack_id,
                "report_id": self.report_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "payload_ids": list(self.payload_ids),
                "required_payload_ids": list(self.required_payload_ids),
                "optional_payload_ids": list(self.optional_payload_ids),
                "missing_required_payload_ids": list(self.missing_required_payload_ids),
                "payload_count_by_kind": self.payload_count_by_kind,
                "total_size_bytes": self.total_size_bytes,
                "manifest_digest": self.manifest_digest,
                "disposition": self.disposition.value,
                "local_only": self.local_only,
            },
        )

    def to_dict(
        self,
        *,
        include_digest: bool = True,
        include_payload_bodies: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "pack_id": self.pack_id,
            "report_id": self.report_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "generated_by": self.generated_by,
            "local_only": self.local_only,
            "manifest": self.manifest,
            "manifest_digest": self.manifest_digest,
            "payloads": [
                item.to_dict(include_body=include_payload_bodies)
                for item in self.payloads
            ],
            "payload_ids": list(self.payload_ids),
            "required_payload_ids": list(self.required_payload_ids),
            "optional_payload_ids": list(self.optional_payload_ids),
            "missing_required_payload_ids": list(self.missing_required_payload_ids),
            "payload_count_by_kind": self.payload_count_by_kind,
            "total_size_bytes": self.total_size_bytes,
            "reviewer_instructions": list(self.reviewer_instructions),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class OperatingExportPackValidation:
    """Validation result for a local Wave 10 export pack."""

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
        observed: dict[str, str] = {}
        for payload_id, sha256 in self.observed_payload_sha256.items():
            observed[normalize_identifier(payload_id, label="payload_id")] = normalize_text(
                sha256,
                label="sha256",
            )
        object.__setattr__(self, "observed_payload_sha256", dict(sorted(observed.items())))
        object.__setattr__(self, "checked_by", normalize_text(self.checked_by, label="checked_by"))
        object.__setattr__(self, "metadata", normalize_metadata(self.metadata))

    @property
    def manifest_digest_matches(self) -> bool:
        return (
            self.expected_manifest_digest
            == self.observed_manifest_digest
            == self.pack.manifest_digest
        )

    @property
    def missing_observed_payload_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.pack.required_payload_ids) - set(self.observed_payload_sha256)))

    @property
    def mismatched_payload_ids(self) -> tuple[str, ...]:
        expected = {payload.payload_id: payload.sha256 for payload in self.pack.payloads}
        return tuple(
            sorted(
                payload_id
                for payload_id, expected_sha in expected.items()
                if payload_id in self.observed_payload_sha256
                and self.observed_payload_sha256[payload_id] != expected_sha
            )
        )

    @property
    def unexpected_payload_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.observed_payload_sha256) - set(self.pack.payload_ids)))

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = [*self.pack.findings]

        if not self.manifest_digest_matches:
            findings.append(
                OperatingFinding(
                    code="operating.export.manifest-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary="Operating export pack manifest digest does not match.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "validation_id": self.validation_id,
                        "pack_id": self.pack.pack_id,
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
                    summary=f"Required export payload {payload_id} was not observed.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "validation_id": self.validation_id,
                        "pack_id": self.pack.pack_id,
                        "payload_id": payload_id,
                    },
                )
            )

        for payload_id in self.mismatched_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.payload-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Export payload {payload_id} digest does not match the manifest.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=True,
                    metadata={
                        "validation_id": self.validation_id,
                        "pack_id": self.pack.pack_id,
                        "payload_id": payload_id,
                    },
                )
            )

        for payload_id in self.unexpected_payload_ids:
            findings.append(
                OperatingFinding(
                    code="operating.export.unexpected-payload-observed",
                    severity=OperatingSeverity.MEDIUM,
                    summary=f"Unexpected export payload {payload_id} was observed.",
                    domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                    blocking=False,
                    metadata={
                        "validation_id": self.validation_id,
                        "pack_id": self.pack.pack_id,
                        "payload_id": payload_id,
                    },
                )
            )

        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def passed(self) -> bool:
        return not any(finding.blocking for finding in self.findings)

    @property
    def disposition(self) -> OperatingDisposition:
        if any(finding.blocking for finding in self.findings):
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.validation_id}-export-pack-validation-envelope",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            subject=f"Wave 10 export pack validation {self.validation_id}",
            domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
            findings=self.findings,
            metadata={
                "validation_id": self.validation_id,
                "pack_id": self.pack.pack_id,
                "checked_by": self.checked_by,
                "manifest_digest_matches": self.manifest_digest_matches,
                "missing_observed_payload_ids": list(self.missing_observed_payload_ids),
                "mismatched_payload_ids": list(self.mismatched_payload_ids),
                "unexpected_payload_ids": list(self.unexpected_payload_ids),
                "passed": self.passed,
                "disposition": self.disposition.value,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "validation_id": self.validation_id,
            "pack": self.pack.to_dict(include_payload_bodies=False),
            "expected_manifest_digest": self.expected_manifest_digest,
            "observed_manifest_digest": self.observed_manifest_digest,
            "observed_payload_sha256": dict(self.observed_payload_sha256),
            "checked_by": self.checked_by,
            "manifest_digest_matches": self.manifest_digest_matches,
            "missing_observed_payload_ids": list(self.missing_observed_payload_ids),
            "mismatched_payload_ids": list(self.mismatched_payload_ids),
            "unexpected_payload_ids": list(self.unexpected_payload_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
            "disposition": self.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }


def build_wave10_local_export_pack(
    *,
    pack_id: str,
    report: OperatingReport,
    review_bundle: OperatingReviewBundle,
    standards_crosswalk: StandardsCrosswalkReport,
    cloud_security_export: CloudSecurityFindingExport,
    report_validation: OperatingReportValidation | None = None,
    extra_payloads: Sequence[OperatingExportPayload] = (),
) -> OperatingExportPack:
    """Build the default local Wave 10 export pack from final dossier artifacts."""

    payloads: list[OperatingExportPayload] = [
        json_payload(
            payload_id="operating-report",
            path=".blackfox-artifacts/wave10/operating-report.json",
            artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
            body=report.to_dict(),
            source_id=report.report_id,
            required=True,
        ),
        json_payload(
            payload_id="review-bundle",
            path=".blackfox-artifacts/wave10/review-bundle.json",
            artifact_kind=OperatingArtifactKind.REVIEW_BUNDLE,
            body=review_bundle.to_dict(),
            source_id=review_bundle.bundle_id,
            required=True,
        ),
        json_payload(
            payload_id="standards-crosswalk",
            path=".blackfox-artifacts/wave10/standards-crosswalk.json",
            artifact_kind=OperatingArtifactKind.STANDARDS_CROSSWALK,
            body=standards_crosswalk.to_dict(),
            source_id=standards_crosswalk.report_id,
            required=True,
        ),
        json_payload(
            payload_id="cloud-security-export-index",
            path=".blackfox-artifacts/wave10/cloud-security-export.json",
            artifact_kind=OperatingArtifactKind.CLOUD_FINDING_EXPORT,
            body=cloud_security_export.to_dict(),
            source_id=cloud_security_export.export_id,
            required=True,
        ),
        OperatingExportPayload(
            payload_id="cloud-security-export-asff",
            path=".blackfox-artifacts/wave10/cloud-security-export.asff.json",
            artifact_kind=OperatingArtifactKind.CLOUD_FINDING_EXPORT,
            content_type="application/json",
            body=cloud_security_export.export_asff_json(),
            export_format=OperatingExportFormat.JSON_ARRAY,
            source_id=cloud_security_export.export_id,
            required=True,
        ),
    ]

    if report_validation is not None:
        payloads.append(
            json_payload(
                payload_id="operating-report-validation",
                path=".blackfox-artifacts/wave10/operating-report-validation.json",
                artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
                body=report_validation.to_dict(),
                source_id=report_validation.validation_id,
                required=True,
            )
        )

    payloads.extend(extra_payloads)

    required_payload_ids = tuple(payload.payload_id for payload in payloads if payload.required)

    return OperatingExportPack(
        pack_id=pack_id,
        report_id=report.report_id,
        campaign_id=report.campaign_id,
        repository_ids=report.repository_ids,
        payloads=tuple(payloads),
        required_payload_ids=required_payload_ids,
        metadata={
            "report_digest": report.digest,
            "review_bundle_digest": review_bundle.digest,
            "standards_crosswalk_digest": standards_crosswalk.to_dict()["digest"],
            "cloud_security_export_digest": cloud_security_export.digest,
            "report_validation_digest": (
                report_validation.to_dict()["digest"] if report_validation is not None else ""
            ),
        },
    )


def json_payload(
    *,
    payload_id: str,
    path: str,
    artifact_kind: OperatingArtifactKind,
    body: Mapping[str, Any],
    source_id: str,
    required: bool,
) -> OperatingExportPayload:
    return OperatingExportPayload(
        payload_id=payload_id,
        path=path,
        artifact_kind=artifact_kind,
        content_type="application/json",
        body=json.dumps(body, sort_keys=True, separators=(",", ":")),
        export_format=OperatingExportFormat.JSON_OBJECT,
        source_id=source_id,
        required=required,
    )


def normalize_optional_identifier(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_identifier(value, label=label)


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
