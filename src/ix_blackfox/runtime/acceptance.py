from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self

from ix_blackfox.runtime.control_plane import EngineeringControlPlaneReport
from ix_blackfox.runtime.run_bundle import (
    RunBundleArtifactKind,
    RunBundleManifest,
)
from ix_blackfox.runtime.verification_summary import VerificationSummaryStatus


class Wave2AcceptanceStatus(StrEnum):
    """
    Final acceptance status for the IX-BlackFox Wave 2 control plane.

    ACCEPTED means the run produced the minimum serious evidence package:
    successful repair loop, verified test evidence, receipt coverage, and the
    expected operator bundle artifacts.

    This is still not a claim that generated code is globally correct. It only
    means the captured run meets the Wave 2 evidence contract.
    """

    ACCEPTED = auto()
    REJECTED = auto()
    INCONCLUSIVE = auto()


class Wave2AcceptanceFindingSeverity(StrEnum):
    """
    Acceptance-finding severity.
    """

    PASS = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class Wave2AcceptanceFinding:
    """
    One acceptance finding produced by the Wave 2 validator.
    """

    code: str
    severity: Wave2AcceptanceFindingSeverity
    summary: str
    detail: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "detail", _normalize_optional_text(self.detail))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def failed(self) -> bool:
        return self.severity is Wave2AcceptanceFindingSeverity.ERROR

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=Wave2AcceptanceFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            detail=_optional_text_from_payload(payload, "detail"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class Wave2AcceptanceReport:
    """
    Machine-readable final acceptance report for a Wave 2 control-plane run.
    """

    report_id: str
    run_id: str
    task_id: str
    status: Wave2AcceptanceStatus
    conclusion: str
    findings: tuple[Wave2AcceptanceFinding, ...]
    checked_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "task_id", _normalize_identifier(self.task_id, label="task_id"))
        object.__setattr__(self, "conclusion", _normalize_text(self.conclusion, label="conclusion"))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.checked_at.tzinfo is None:
            raise ValueError("Wave2AcceptanceReport checked_at must be timezone-aware.")

    @property
    def accepted(self) -> bool:
        return self.status is Wave2AcceptanceStatus.ACCEPTED

    @property
    def rejected(self) -> bool:
        return self.status is Wave2AcceptanceStatus.REJECTED

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is Wave2AcceptanceFindingSeverity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is Wave2AcceptanceFindingSeverity.WARNING
        )

    @property
    def pass_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is Wave2AcceptanceFindingSeverity.PASS
        )

    @property
    def digest(self) -> str:
        payload = {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "conclusion": self.conclusion,
            "findings": [finding.to_dict() for finding in self.findings],
            "checked_at": self.checked_at.isoformat(),
            "metadata": dict(self.metadata),
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def has_finding(self, code: str) -> bool:
        normalized_code = _normalize_token(code, label="code")
        return any(finding.code == normalized_code for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "conclusion": self.conclusion,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "pass_count": self.pass_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "checked_at": self.checked_at.isoformat(),
            "digest": self.digest,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_findings = payload.get("findings", ())
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        findings: list[Wave2AcceptanceFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(Wave2AcceptanceFinding.from_dict(raw_finding))

        return cls(
            report_id=_require_text(payload, "report_id"),
            run_id=_require_text(payload, "run_id"),
            task_id=_require_text(payload, "task_id"),
            status=Wave2AcceptanceStatus(_require_text(payload, "status")),
            conclusion=_require_text(payload, "conclusion"),
            findings=tuple(findings),
            checked_at=_parse_datetime(_require_text(payload, "checked_at")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class Wave2AcceptanceValidator:
    """
    Final validator for the Wave 2 governed engineering control plane.

    The validator checks the control-plane report as evidence, not promises.
    It fails closed when required artifacts, receipts, verification status, or
    test evidence are missing.
    """

    required_artifact_kinds: tuple[RunBundleArtifactKind, ...] = (
        RunBundleArtifactKind.RUN_REPORT,
        RunBundleArtifactKind.OPERATOR_SUMMARY,
        RunBundleArtifactKind.VERIFICATION_SUMMARY,
        RunBundleArtifactKind.TOOL_RECEIPTS,
        RunBundleArtifactKind.REPAIR_RECEIPTS,
        RunBundleArtifactKind.TRACE,
    )
    minimum_tool_receipts: int = 3
    minimum_repair_receipts: int = 3
    require_verified_status: bool = True
    require_successful_repair: bool = True
    require_manifest_file: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_artifact_kinds", tuple(self.required_artifact_kinds))

        if self.minimum_tool_receipts < 0:
            raise ValueError("minimum_tool_receipts must not be negative.")
        if self.minimum_repair_receipts < 0:
            raise ValueError("minimum_repair_receipts must not be negative.")

    def validate_control_plane_report(
        self,
        report: EngineeringControlPlaneReport,
        *,
        check_filesystem: bool = False,
    ) -> Wave2AcceptanceReport:
        findings = list(
            self._findings_for_control_plane_report(
                report,
                check_filesystem=check_filesystem,
            )
        )
        status = self._status_from_findings(findings)
        conclusion = self._conclusion(status=status, findings=findings)

        return Wave2AcceptanceReport(
            report_id=f"wave2-acceptance-{report.run_id}",
            run_id=report.run_id,
            task_id=report.task_id,
            status=status,
            conclusion=conclusion,
            findings=tuple(findings),
            metadata={
                "validator": "wave2-acceptance",
                "verification_status": report.verification_status,
                "tool_receipt_count": report.tool_receipt_count,
                "repair_receipt_count": report.repair_receipt_count,
                "bundle_root": report.bundle_root,
                "check_filesystem": check_filesystem,
            },
        )

    def validate_manifest(
        self,
        *,
        run_id: str,
        task_id: str,
        manifest: RunBundleManifest,
        check_filesystem: bool = False,
    ) -> Wave2AcceptanceReport:
        findings = list(
            self._findings_for_manifest(
                manifest=manifest,
                check_filesystem=check_filesystem,
            )
        )
        status = self._status_from_findings(findings)
        conclusion = self._conclusion(status=status, findings=findings)

        return Wave2AcceptanceReport(
            report_id=f"wave2-acceptance-{run_id}",
            run_id=run_id,
            task_id=task_id,
            status=status,
            conclusion=conclusion,
            findings=tuple(findings),
            metadata={
                "validator": "wave2-acceptance",
                "bundle_root": manifest.root_path,
                "manifest_digest": manifest.digest,
                "check_filesystem": check_filesystem,
            },
        )

    def _findings_for_control_plane_report(
        self,
        report: EngineeringControlPlaneReport,
        *,
        check_filesystem: bool,
    ) -> Iterable[Wave2AcceptanceFinding]:
        if self.require_successful_repair and report.succeeded:
            yield Wave2AcceptanceFinding(
                code="repair.succeeded",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Programming repair report reached a successful terminal state.",
                detail=f"Attempts used: {report.programming_repair_report.attempts_used}.",
            )
        elif self.require_successful_repair:
            yield Wave2AcceptanceFinding(
                code="repair.not_successful",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Programming repair report did not reach a successful terminal state.",
                detail=(
                    "Terminal reason: "
                    f"{report.programming_repair_report.terminal_reason or 'n/a'}."
                ),
            )

        if (
            self.require_verified_status
            and report.verification_summary.status is VerificationSummaryStatus.VERIFIED
        ):
            yield Wave2AcceptanceFinding(
                code="verification.verified",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Verification summary reports verified status.",
                detail=report.verification_summary.conclusion,
                metadata={"verification_digest": report.verification_summary.digest},
            )
        elif self.require_verified_status:
            yield Wave2AcceptanceFinding(
                code="verification.not_verified",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Verification summary does not report verified status.",
                detail=f"Observed status: {report.verification_summary.status.value}.",
            )

        latest_test_run = report.programming_repair_report.latest_test_run
        if latest_test_run is None:
            yield Wave2AcceptanceFinding(
                code="tests.missing",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="No parsed test run is present in the programming repair report.",
            )
        elif latest_test_run.succeeded:
            yield Wave2AcceptanceFinding(
                code="tests.latest_passed",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Latest parsed test run passed.",
                detail=f"Passed test count: {latest_test_run.passed}.",
            )
        else:
            yield Wave2AcceptanceFinding(
                code="tests.latest_not_passing",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Latest parsed test run did not pass.",
                detail=(
                    f"Status: {latest_test_run.status.value}; "
                    f"failing outcomes: {latest_test_run.failing_outcomes}."
                ),
            )

        if report.tool_receipt_count >= self.minimum_tool_receipts:
            yield Wave2AcceptanceFinding(
                code="receipts.tool_count_ok",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Tool receipt count meets the acceptance threshold.",
                detail=f"Observed {report.tool_receipt_count} tool receipt(s).",
            )
        else:
            yield Wave2AcceptanceFinding(
                code="receipts.tool_count_low",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Tool receipt count is below the acceptance threshold.",
                detail=(
                    f"Observed {report.tool_receipt_count}; "
                    f"required {self.minimum_tool_receipts}."
                ),
            )

        if report.repair_receipt_count >= self.minimum_repair_receipts:
            yield Wave2AcceptanceFinding(
                code="receipts.repair_count_ok",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Repair-loop receipt count meets the acceptance threshold.",
                detail=f"Observed {report.repair_receipt_count} repair receipt(s).",
            )
        else:
            yield Wave2AcceptanceFinding(
                code="receipts.repair_count_low",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Repair-loop receipt count is below the acceptance threshold.",
                detail=(
                    f"Observed {report.repair_receipt_count}; "
                    f"required {self.minimum_repair_receipts}."
                ),
            )

        yield from self._findings_for_manifest(
            manifest=report.run_bundle_manifest,
            check_filesystem=check_filesystem,
        )

    def _findings_for_manifest(
        self,
        *,
        manifest: RunBundleManifest,
        check_filesystem: bool,
    ) -> Iterable[Wave2AcceptanceFinding]:
        artifact_kinds = tuple(artifact.kind for artifact in manifest.artifacts)
        artifact_paths = set(manifest.artifact_paths)

        for required_kind in self.required_artifact_kinds:
            if required_kind in artifact_kinds:
                yield Wave2AcceptanceFinding(
                    code=f"bundle.{required_kind.value}_present",
                    severity=Wave2AcceptanceFindingSeverity.PASS,
                    summary=f"Run bundle contains required artifact kind: {required_kind.value}.",
                )
            else:
                yield Wave2AcceptanceFinding(
                    code=f"bundle.{required_kind.value}_missing",
                    severity=Wave2AcceptanceFindingSeverity.ERROR,
                    summary=f"Run bundle is missing required artifact kind: {required_kind.value}.",
                )

        if self.require_manifest_file:
            manifest_path = Path(manifest.root_path) / "manifest.json"
            if check_filesystem:
                if manifest_path.is_file():
                    yield Wave2AcceptanceFinding(
                        code="bundle.manifest_file_present",
                        severity=Wave2AcceptanceFindingSeverity.PASS,
                        summary="Run bundle manifest file exists on disk.",
                        detail=str(manifest_path),
                    )
                else:
                    yield Wave2AcceptanceFinding(
                        code="bundle.manifest_file_missing",
                        severity=Wave2AcceptanceFindingSeverity.ERROR,
                        summary="Run bundle manifest file is missing on disk.",
                        detail=str(manifest_path),
                    )
            else:
                yield Wave2AcceptanceFinding(
                    code="bundle.manifest_file_unchecked",
                    severity=Wave2AcceptanceFindingSeverity.INFO,
                    summary="Run bundle manifest file existence was not checked on disk.",
                    detail="Set check_filesystem=True to verify persisted files.",
                )

        duplicate_paths = tuple(sorted(path for path in artifact_paths if manifest.artifact_paths.count(path) > 1))
        if duplicate_paths:
            yield Wave2AcceptanceFinding(
                code="bundle.duplicate_paths",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Run bundle manifest contains duplicate artifact paths.",
                detail=", ".join(duplicate_paths),
            )
        else:
            yield Wave2AcceptanceFinding(
                code="bundle.paths_unique",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Run bundle manifest artifact paths are unique.",
            )

        if manifest.artifact_count == len(manifest.artifacts):
            yield Wave2AcceptanceFinding(
                code="bundle.artifact_count_matches",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Run bundle artifact count matches manifest entries.",
                detail=f"Artifact count: {manifest.artifact_count}.",
            )
        else:
            yield Wave2AcceptanceFinding(
                code="bundle.artifact_count_mismatch",
                severity=Wave2AcceptanceFindingSeverity.ERROR,
                summary="Run bundle artifact count does not match manifest entries.",
                detail=(
                    f"artifact_count={manifest.artifact_count}; "
                    f"entries={len(manifest.artifacts)}."
                ),
            )

        if check_filesystem:
            yield from self._filesystem_findings(manifest)

    def _filesystem_findings(
        self,
        manifest: RunBundleManifest,
    ) -> Iterable[Wave2AcceptanceFinding]:
        root = Path(manifest.root_path)

        for artifact in manifest.artifacts:
            artifact_path = root / artifact.relative_path
            if not artifact_path.is_file():
                yield Wave2AcceptanceFinding(
                    code="bundle.artifact_file_missing",
                    severity=Wave2AcceptanceFindingSeverity.ERROR,
                    summary="Run bundle artifact file is missing on disk.",
                    detail=artifact.relative_path,
                    metadata={"expected_path": str(artifact_path)},
                )
                continue

            payload = artifact_path.read_bytes()
            actual_digest = hashlib.sha256(payload).hexdigest()
            if actual_digest != artifact.sha256:
                yield Wave2AcceptanceFinding(
                    code="bundle.artifact_digest_mismatch",
                    severity=Wave2AcceptanceFindingSeverity.ERROR,
                    summary="Run bundle artifact digest does not match file bytes.",
                    detail=artifact.relative_path,
                    metadata={
                        "expected_sha256": artifact.sha256,
                        "actual_sha256": actual_digest,
                    },
                )
                continue

            yield Wave2AcceptanceFinding(
                code="bundle.artifact_file_verified",
                severity=Wave2AcceptanceFindingSeverity.PASS,
                summary="Run bundle artifact file exists and matches its digest.",
                detail=artifact.relative_path,
            )

    def _status_from_findings(
        self,
        findings: Iterable[Wave2AcceptanceFinding],
    ) -> Wave2AcceptanceStatus:
        findings_tuple = tuple(findings)
        if any(finding.severity is Wave2AcceptanceFindingSeverity.ERROR for finding in findings_tuple):
            return Wave2AcceptanceStatus.REJECTED
        if any(finding.severity is Wave2AcceptanceFindingSeverity.WARNING for finding in findings_tuple):
            return Wave2AcceptanceStatus.INCONCLUSIVE
        return Wave2AcceptanceStatus.ACCEPTED

    def _conclusion(
        self,
        *,
        status: Wave2AcceptanceStatus,
        findings: Iterable[Wave2AcceptanceFinding],
    ) -> str:
        findings_tuple = tuple(findings)
        error_count = sum(
            1
            for finding in findings_tuple
            if finding.severity is Wave2AcceptanceFindingSeverity.ERROR
        )
        warning_count = sum(
            1
            for finding in findings_tuple
            if finding.severity is Wave2AcceptanceFindingSeverity.WARNING
        )

        if status is Wave2AcceptanceStatus.ACCEPTED:
            return (
                "Wave 2 acceptance passed: the run produced verified test evidence, "
                "receipt coverage, and the required operator bundle artifacts."
            )

        if status is Wave2AcceptanceStatus.REJECTED:
            return (
                "Wave 2 acceptance rejected the run because required evidence is "
                f"missing or failing. Error count: {error_count}."
            )

        return (
            "Wave 2 acceptance is inconclusive. The run has no hard acceptance "
            f"errors, but warning count is {warning_count}."
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Serialized datetimes must be timezone-aware.")
    return parsed
