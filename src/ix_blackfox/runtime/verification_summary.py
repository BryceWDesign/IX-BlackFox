from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self

from ix_blackfox.runtime.programming_repair import ProgrammingRepairRunReport
from ix_blackfox.runtime.run_bundle import RunBundleManifest
from ix_blackfox.tools import ParsedTestRunStatus


class VerificationSummaryStatus(StrEnum):
    """
    Operator-grade verification status for a BlackFox run.

    This is not a claim that generated code is globally correct. It only states
    whether the captured evidence supports the specific run objective, bounded
    tool actions, and recorded test command.
    """

    VERIFIED = auto()
    PARTIAL = auto()
    FAILED = auto()
    BLOCKED = auto()
    INCONCLUSIVE = auto()


class VerificationEvidenceKind(StrEnum):
    """
    Evidence categories used by verification summaries.
    """

    PATCH_RESULT = auto()
    TEST_RESULT = auto()
    PARSED_TEST_RUN = auto()
    TOOL_RECEIPT = auto()
    REPAIR_RECEIPT = auto()
    RUN_BUNDLE_ARTIFACT = auto()
    OPERATOR_SUMMARY = auto()
    MANIFEST = auto()
    GENERIC = auto()


class VerificationFindingSeverity(StrEnum):
    """
    Severity of one verification finding.
    """

    INFO = auto()
    PASS = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """
    One evidence item referenced by a verification summary.
    """

    evidence_id: str
    kind: VerificationEvidenceKind
    summary: str
    reference: str | None = None
    sha256: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_id",
            _normalize_identifier(self.evidence_id, label="evidence_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "reference", _normalize_optional_text(self.reference))
        object.__setattr__(self, "sha256", _normalize_optional_digest(self.sha256))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "summary": self.summary,
            "reference": self.reference,
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            evidence_id=_require_text(payload, "evidence_id"),
            kind=VerificationEvidenceKind(_require_text(payload, "kind")),
            summary=_require_text(payload, "summary"),
            reference=_optional_text_from_payload(payload, "reference"),
            sha256=_optional_text_from_payload(payload, "sha256"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class VerificationFinding:
    """
    One verification finding derived from run evidence.
    """

    code: str
    severity: VerificationFindingSeverity
    summary: str
    detail: str | None = None
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "detail", _normalize_optional_text(self.detail))
        object.__setattr__(self, "evidence_ids", _normalize_identifier_tuple(self.evidence_ids))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "evidence_ids": list(self.evidence_ids),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=VerificationFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            detail=_optional_text_from_payload(payload, "detail"),
            evidence_ids=tuple(
                _coerce_string_list(
                    payload.get("evidence_ids", ()),
                    field_name="evidence_ids",
                )
            ),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    """
    Machine-readable verification summary for a BlackFox run.

    The summary binds verification status to explicit evidence. It is meant to
    be persisted as ``verification/verification-summary.json`` inside the run
    bundle and paired with the human-readable operator summary.
    """

    summary_id: str
    run_id: str
    task_id: str | None
    status: VerificationSummaryStatus
    objective: str
    conclusion: str
    evidence: tuple[VerificationEvidence, ...] = field(default_factory=tuple)
    findings: tuple[VerificationFinding, ...] = field(default_factory=tuple)
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "summary_id",
            _normalize_identifier(self.summary_id, label="summary_id"),
        )
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "task_id", _normalize_optional_identifier(self.task_id))
        object.__setattr__(self, "objective", _normalize_text(self.objective, label="objective"))
        object.__setattr__(self, "conclusion", _normalize_text(self.conclusion, label="conclusion"))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.generated_at.tzinfo is None:
            raise ValueError("VerificationSummary generated_at must be timezone-aware.")

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is VerificationFindingSeverity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is VerificationFindingSeverity.WARNING
        )

    @property
    def digest(self) -> str:
        payload = {
            "summary_id": self.summary_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "objective": self.objective,
            "conclusion": self.conclusion,
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [finding.to_dict() for finding in self.findings],
            "generated_at": self.generated_at.isoformat(),
            "metadata": dict(self.metadata),
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary_id": self.summary_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "objective": self.objective,
            "conclusion": self.conclusion,
            "evidence_count": self.evidence_count,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [finding.to_dict() for finding in self.findings],
            "generated_at": self.generated_at.isoformat(),
            "digest": self.digest,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_evidence = payload.get("evidence", ())
        raw_findings = payload.get("findings", ())

        if not isinstance(raw_evidence, Iterable) or isinstance(raw_evidence, str):
            raise TypeError("evidence must be an iterable of mappings.")
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        evidence: list[VerificationEvidence] = []
        for raw_item in raw_evidence:
            if not isinstance(raw_item, Mapping):
                raise TypeError("evidence must contain only mappings.")
            evidence.append(VerificationEvidence.from_dict(raw_item))

        findings: list[VerificationFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(VerificationFinding.from_dict(raw_finding))

        return cls(
            summary_id=_require_text(payload, "summary_id"),
            run_id=_require_text(payload, "run_id"),
            task_id=_optional_text_from_payload(payload, "task_id"),
            status=VerificationSummaryStatus(_require_text(payload, "status")),
            objective=_require_text(payload, "objective"),
            conclusion=_require_text(payload, "conclusion"),
            evidence=tuple(evidence),
            findings=tuple(findings),
            generated_at=_parse_datetime(_require_text(payload, "generated_at")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class VerificationSummaryRenderer:
    """
    Deterministic renderer for BlackFox verification summaries.

    This renderer converts run evidence into a compact JSON-ready verification
    artifact. It never upgrades a run to verified unless the captured evidence
    shows a successful terminal state and a passing parsed test run.
    """

    product_name: str = "IX-BlackFox"

    def from_programming_repair_report(
        self,
        report: ProgrammingRepairRunReport,
    ) -> VerificationSummary:
        evidence = list(_evidence_from_programming_repair_report(report))
        findings = list(_findings_from_programming_repair_report(report, evidence))

        status = _status_from_programming_repair_report(report)
        conclusion = _conclusion_for_programming_repair_report(report, status)

        return VerificationSummary(
            summary_id=f"verification-{report.loop_state.run_id}",
            run_id=report.loop_state.run_id,
            task_id=report.loop_state.task_id,
            status=status,
            objective=report.loop_state.objective,
            conclusion=conclusion,
            evidence=tuple(evidence),
            findings=tuple(findings),
            metadata={
                "renderer": "verification-summary",
                "product_name": self.product_name,
                "summary_type": "programming_repair",
                "loop_id": report.loop_state.loop_id,
                "terminal_reason": report.terminal_reason,
                "attempts_used": report.attempts_used,
                "attempts_remaining": report.attempts_remaining,
            },
        )

    def from_run_bundle_manifest(
        self,
        manifest: RunBundleManifest,
    ) -> VerificationSummary:
        evidence = tuple(
            VerificationEvidence(
                evidence_id=f"bundle-artifact-{index}",
                kind=VerificationEvidenceKind.RUN_BUNDLE_ARTIFACT,
                summary=f"Run bundle artifact recorded: {artifact.relative_path}",
                reference=artifact.relative_path,
                sha256=artifact.sha256,
                metadata={
                    "artifact_kind": artifact.kind.value,
                    "media_type": artifact.media_type,
                    "size_bytes": artifact.size_bytes,
                },
            )
            for index, artifact in enumerate(manifest.artifacts, start=1)
        )

        findings: list[VerificationFinding] = [
            VerificationFinding(
                code="bundle.manifest_digest",
                severity=VerificationFindingSeverity.INFO,
                summary="Run bundle manifest digest was computed.",
                detail=manifest.digest,
                evidence_ids=tuple(item.evidence_id for item in evidence),
                metadata={
                    "artifact_count": manifest.artifact_count,
                    "manifest_digest": manifest.digest,
                },
            )
        ]

        status = VerificationSummaryStatus.PARTIAL
        conclusion = (
            "Run bundle artifacts were indexed, but this manifest alone does not "
            "prove the run objective succeeded."
        )

        if manifest.artifact_count == 0:
            status = VerificationSummaryStatus.INCONCLUSIVE
            findings.append(
                VerificationFinding(
                    code="bundle.no_artifacts",
                    severity=VerificationFindingSeverity.WARNING,
                    summary="Run bundle manifest contains no artifacts.",
                    detail="Verification requires receipts, reports, tests, or other evidence.",
                )
            )
            conclusion = "Run bundle manifest contains no artifacts to verify."

        return VerificationSummary(
            summary_id=f"verification-{manifest.run_id}",
            run_id=manifest.run_id,
            task_id=manifest.task_id,
            status=status,
            objective="Verify run bundle artifact inventory.",
            conclusion=conclusion,
            evidence=evidence,
            findings=tuple(findings),
            metadata={
                "renderer": "verification-summary",
                "product_name": self.product_name,
                "summary_type": "run_bundle",
                "bundle_id": manifest.bundle_id,
                "manifest_digest": manifest.digest,
                "artifact_count": manifest.artifact_count,
            },
        )


def _evidence_from_programming_repair_report(
    report: ProgrammingRepairRunReport,
) -> Iterable[VerificationEvidence]:
    evidence: list[VerificationEvidence] = []

    for index, result in enumerate(report.patch_results, start=1):
        evidence.append(
            VerificationEvidence(
                evidence_id=f"patch-result-{index}",
                kind=VerificationEvidenceKind.PATCH_RESULT,
                summary=f"Patch tool result {index}: {result.status.value}.",
                reference=result.invocation_id,
                metadata={
                    "tool_id": result.tool_id,
                    "status": result.status.value,
                    "artifact_count": len(result.artifacts),
                    "output_keys": sorted(str(key) for key in result.output.keys()),
                },
            )
        )

    for index, result in enumerate(report.test_results, start=1):
        evidence.append(
            VerificationEvidence(
                evidence_id=f"test-result-{index}",
                kind=VerificationEvidenceKind.TEST_RESULT,
                summary=f"Test tool result {index}: {result.status.value}.",
                reference=result.invocation_id,
                metadata={
                    "tool_id": result.tool_id,
                    "status": result.status.value,
                    "artifact_count": len(result.artifacts),
                    "output_keys": sorted(str(key) for key in result.output.keys()),
                },
            )
        )

    for index, parsed in enumerate(report.parsed_test_runs, start=1):
        evidence.append(
            VerificationEvidence(
                evidence_id=f"parsed-test-run-{index}",
                kind=VerificationEvidenceKind.PARSED_TEST_RUN,
                summary=f"Parsed test run {index}: {parsed.status.value}.",
                reference=parsed.raw_summary_line,
                metadata={
                    "status": parsed.status.value,
                    "passed": parsed.passed,
                    "failed": parsed.failed,
                    "errors": parsed.errors,
                    "warnings": parsed.warnings,
                    "failing_outcomes": parsed.failing_outcomes,
                    "finding_codes": list(parsed.finding_codes),
                },
            )
        )

    for index, receipt in enumerate(report.repair_receipts, start=1):
        digest = receipt.get("chain_digest")
        evidence.append(
            VerificationEvidence(
                evidence_id=f"repair-receipt-{index}",
                kind=VerificationEvidenceKind.REPAIR_RECEIPT,
                summary=f"Repair-loop receipt {index}: {receipt.get('event_type', 'unknown')}.",
                reference=str(receipt.get("receipt_id", "")) or None,
                sha256=digest if isinstance(digest, str) and len(digest) == 64 else None,
                metadata={
                    "event_type": receipt.get("event_type"),
                    "status": receipt.get("status"),
                    "terminal_reason": receipt.get("terminal_reason"),
                },
            )
        )

    return tuple(evidence)


def _findings_from_programming_repair_report(
    report: ProgrammingRepairRunReport,
    evidence: list[VerificationEvidence],
) -> Iterable[VerificationFinding]:
    evidence_ids = tuple(item.evidence_id for item in evidence)

    if report.succeeded:
        yield VerificationFinding(
            code="repair.terminal_success",
            severity=VerificationFindingSeverity.PASS,
            summary="Repair loop reached a successful terminal state.",
            detail=f"Terminal reason: {report.terminal_reason}.",
            evidence_ids=evidence_ids,
        )
    else:
        yield VerificationFinding(
            code="repair.not_verified",
            severity=VerificationFindingSeverity.ERROR,
            summary="Repair loop did not reach a successful terminal state.",
            detail=f"Terminal reason: {report.terminal_reason or 'n/a'}.",
            evidence_ids=evidence_ids,
        )

    latest_test_run = report.latest_test_run
    if latest_test_run is None:
        yield VerificationFinding(
            code="tests.no_parsed_test_run",
            severity=VerificationFindingSeverity.ERROR,
            summary="No parsed test run was attached to the repair report.",
            detail="Verification requires parsed test evidence.",
        )
    elif latest_test_run.status is ParsedTestRunStatus.PASSED:
        yield VerificationFinding(
            code="tests.latest_passed",
            severity=VerificationFindingSeverity.PASS,
            summary="Latest parsed test run passed.",
            detail=f"Passed count: {latest_test_run.passed}.",
            evidence_ids=tuple(
                item.evidence_id
                for item in evidence
                if item.kind is VerificationEvidenceKind.PARSED_TEST_RUN
            ),
        )
    else:
        yield VerificationFinding(
            code="tests.latest_not_passing",
            severity=VerificationFindingSeverity.ERROR,
            summary="Latest parsed test run did not pass.",
            detail=(
                f"Status: {latest_test_run.status.value}; "
                f"failing outcomes: {latest_test_run.failing_outcomes}."
            ),
            evidence_ids=tuple(
                item.evidence_id
                for item in evidence
                if item.kind is VerificationEvidenceKind.PARSED_TEST_RUN
            ),
        )

    if not report.patch_results:
        yield VerificationFinding(
            code="patch.no_results",
            severity=VerificationFindingSeverity.ERROR,
            summary="No patch tool results were recorded.",
        )

    if not report.test_results:
        yield VerificationFinding(
            code="tests.no_tool_results",
            severity=VerificationFindingSeverity.ERROR,
            summary="No test tool results were recorded.",
        )

    if not report.repair_receipts:
        yield VerificationFinding(
            code="receipts.repair_missing",
            severity=VerificationFindingSeverity.WARNING,
            summary="No repair-loop receipts were attached.",
            detail="Attach RepairLoopReceiptLedger for complete loop-control evidence.",
        )


def _status_from_programming_repair_report(
    report: ProgrammingRepairRunReport,
) -> VerificationSummaryStatus:
    latest_test_run = report.latest_test_run

    if report.loop_state.status.value == "blocked":
        return VerificationSummaryStatus.BLOCKED

    if report.succeeded and latest_test_run is not None and latest_test_run.status is ParsedTestRunStatus.PASSED:
        return VerificationSummaryStatus.VERIFIED

    if latest_test_run is None:
        return VerificationSummaryStatus.INCONCLUSIVE

    if latest_test_run.status in {
        ParsedTestRunStatus.FAILED,
        ParsedTestRunStatus.ERRORED,
        ParsedTestRunStatus.TIMED_OUT,
    }:
        return VerificationSummaryStatus.FAILED

    return VerificationSummaryStatus.PARTIAL


def _conclusion_for_programming_repair_report(
    report: ProgrammingRepairRunReport,
    status: VerificationSummaryStatus,
) -> str:
    if status is VerificationSummaryStatus.VERIFIED:
        return (
            "The captured evidence supports the run objective for the recorded "
            "workspace state and test command. This is not a global correctness claim."
        )

    if status is VerificationSummaryStatus.BLOCKED:
        return (
            "The run was blocked before verification could complete. Operator review "
            "is required before retrying."
        )

    if status is VerificationSummaryStatus.FAILED:
        return (
            "The latest parsed test evidence failed or errored. The repair should not "
            "be trusted as complete."
        )

    if status is VerificationSummaryStatus.INCONCLUSIVE:
        return (
            "The run does not include enough parsed test evidence to verify the objective."
        )

    return (
        "The run contains partial evidence, but it does not fully verify the objective."
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label="optional_identifier")


def _normalize_identifier_tuple(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        normalized.append(_normalize_identifier(value, label="evidence_id"))
    return tuple(normalized)


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


def _normalize_optional_digest(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("SHA-256 digest must be 64 hex characters.")
    int(cleaned, 16)
    return cleaned


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_string_list(value: Any, *, field_name: str) -> list[str]:
    if isinstance(value, str):
        raise TypeError(f"{field_name} must be an iterable of strings, not a string.")
    if not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        values.append(item)

    return values


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
