from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self

from ix_blackfox.runtime.programming_repair import ProgrammingRepairRunReport
from ix_blackfox.runtime.run_bundle import RunBundleManifest


class OperatorSummaryFindingSeverity(StrEnum):
    """
    Human-facing severity used in operator summaries.

    This severity is intentionally separate from pytest, sentinel, and policy
    severities. It describes what the operator should do with the summary.
    """

    INFO = auto()
    PASS = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class OperatorSummaryFinding:
    """
    One operator-facing finding.

    Findings are written in plain language so the markdown summary can be handed
    to a reviewer without forcing them to inspect JSON first.
    """

    code: str
    severity: OperatorSummaryFindingSeverity
    summary: str
    detail: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "detail", _normalize_optional_text(self.detail))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_markdown(self) -> str:
        marker = _severity_marker(self.severity)
        line = f"- **{marker} {self.summary}** `[{self.code}]`"
        if self.detail:
            line += f"\n  - {self.detail}"
        return line

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
            severity=OperatorSummaryFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            detail=_optional_text_from_payload(payload, "detail"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class OperatorSummarySection:
    """
    One markdown section inside an operator summary.
    """

    title: str
    body: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _normalize_text(self.title, label="title"))
        object.__setattr__(self, "body", _normalize_text(self.body, label="body"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_markdown(self) -> str:
        return f"## {self.title}\n\n{self.body.strip()}\n"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "body": self.body,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            title=_require_text(payload, "title"),
            body=_require_text(payload, "body"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class OperatorSummaryDocument:
    """
    Operator-readable markdown document for one BlackFox run.

    The document is designed to answer five questions quickly:
    - What was requested?
    - What did BlackFox do?
    - What changed?
    - What evidence exists?
    - What still needs human review?
    """

    title: str
    run_id: str
    task_id: str | None
    status: str
    executive_summary: str
    sections: tuple[OperatorSummarySection, ...] = field(default_factory=tuple)
    findings: tuple[OperatorSummaryFinding, ...] = field(default_factory=tuple)
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _normalize_text(self.title, label="title"))
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "task_id", _normalize_optional_identifier(self.task_id))
        object.__setattr__(self, "status", _normalize_token(self.status, label="status"))
        object.__setattr__(
            self,
            "executive_summary",
            _normalize_text(self.executive_summary, label="executive_summary"),
        )
        object.__setattr__(self, "sections", tuple(self.sections))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.generated_at.tzinfo is None:
            raise ValueError("OperatorSummaryDocument generated_at must be timezone-aware.")

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is OperatorSummaryFindingSeverity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is OperatorSummaryFindingSeverity.WARNING
        )

    @property
    def section_titles(self) -> tuple[str, ...]:
        return tuple(section.title for section in self.sections)

    def to_markdown(self) -> str:
        lines: list[str] = [
            f"# {self.title}",
            "",
            f"- **Run ID:** `{self.run_id}`",
            f"- **Task ID:** `{self.task_id or 'n/a'}`",
            f"- **Status:** `{self.status}`",
            f"- **Generated:** `{self.generated_at.isoformat()}`",
            "",
            "## Executive Summary",
            "",
            self.executive_summary.strip(),
            "",
        ]

        if self.findings:
            lines.extend(
                [
                    "## Operator Findings",
                    "",
                    *[finding.to_markdown() for finding in self.findings],
                    "",
                ]
            )

        for section in self.sections:
            lines.append(section.to_markdown().rstrip())
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status,
            "executive_summary": self.executive_summary,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "sections": [section.to_dict() for section in self.sections],
            "generated_at": self.generated_at.isoformat(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_sections = payload.get("sections", ())
        raw_findings = payload.get("findings", ())

        if not isinstance(raw_sections, Iterable) or isinstance(raw_sections, str):
            raise TypeError("sections must be an iterable of mappings.")
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        sections: list[OperatorSummarySection] = []
        for raw_section in raw_sections:
            if not isinstance(raw_section, Mapping):
                raise TypeError("sections must contain only mappings.")
            sections.append(OperatorSummarySection.from_dict(raw_section))

        findings: list[OperatorSummaryFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(OperatorSummaryFinding.from_dict(raw_finding))

        return cls(
            title=_require_text(payload, "title"),
            run_id=_require_text(payload, "run_id"),
            task_id=_optional_text_from_payload(payload, "task_id"),
            status=_require_text(payload, "status"),
            executive_summary=_require_text(payload, "executive_summary"),
            sections=tuple(sections),
            findings=tuple(findings),
            generated_at=_parse_datetime(_require_text(payload, "generated_at")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class OperatorSummaryRenderer:
    """
    Renderer for operator-readable BlackFox run summaries.

    The renderer keeps markdown generation deterministic and boring. It does not
    replace structured artifacts; it points operators toward them.
    """

    product_name: str = "IX-BlackFox"

    def render_programming_repair_report(
        self,
        *,
        report: ProgrammingRepairRunReport,
        title: str = "IX-BlackFox Operator Summary",
    ) -> OperatorSummaryDocument:
        loop_state = report.loop_state
        latest_test_run = report.latest_test_run
        findings = list(_findings_from_programming_repair_report(report))

        sections = (
            OperatorSummarySection(
                title="Requested Objective",
                body=loop_state.objective,
            ),
            OperatorSummarySection(
                title="Repair Loop Outcome",
                body="\n".join(
                    [
                        f"- Attempts used: `{report.attempts_used}`",
                        f"- Attempts remaining: `{report.attempts_remaining}`",
                        f"- Terminal reason: `{report.terminal_reason or 'n/a'}`",
                        f"- Loop status: `{loop_state.status.value}`",
                    ]
                ),
            ),
            OperatorSummarySection(
                title="Patch Activity",
                body=_patch_activity_markdown(report),
            ),
            OperatorSummarySection(
                title="Test Evidence",
                body=_test_evidence_markdown(report),
            ),
            OperatorSummarySection(
                title="Receipt Evidence",
                body="\n".join(
                    [
                        f"- Repair-loop receipt count: `{len(report.repair_receipts)}`",
                        "- Tool receipts are emitted by governed tool wrappers when a receipt ledger is attached.",
                        "- Patch and test artifacts should be reviewed from the run bundle before trusting the result.",
                    ]
                ),
            ),
            OperatorSummarySection(
                title="Human Review Notes",
                body=_human_review_notes(report),
            ),
        )

        executive_summary = _programming_repair_executive_summary(
            report=report,
            latest_test_run=latest_test_run,
        )

        return OperatorSummaryDocument(
            title=title,
            run_id=loop_state.run_id,
            task_id=loop_state.task_id,
            status=loop_state.status.value,
            executive_summary=executive_summary,
            sections=sections,
            findings=tuple(findings),
            metadata={
                "renderer": "operator-summary",
                "product_name": self.product_name,
                "summary_type": "programming_repair",
                "loop_id": loop_state.loop_id,
            },
        )

    def render_run_bundle_manifest(
        self,
        *,
        manifest: RunBundleManifest,
        title: str = "IX-BlackFox Run Bundle Summary",
    ) -> OperatorSummaryDocument:
        findings = [
            OperatorSummaryFinding(
                code="bundle.manifest_present",
                severity=OperatorSummaryFindingSeverity.INFO,
                summary="Run bundle manifest was generated.",
                detail=f"Manifest tracks {manifest.artifact_count} artifacts.",
                metadata={"artifact_count": manifest.artifact_count},
            )
        ]

        if manifest.artifact_count == 0:
            findings.append(
                OperatorSummaryFinding(
                    code="bundle.no_artifacts",
                    severity=OperatorSummaryFindingSeverity.WARNING,
                    summary="Run bundle manifest contains no artifacts.",
                    detail="A useful operator bundle should include receipts, reports, or verification evidence.",
                )
            )

        sections = (
            OperatorSummarySection(
                title="Bundle Contents",
                body=_bundle_contents_markdown(manifest),
            ),
            OperatorSummarySection(
                title="Bundle Digest",
                body=(
                    "The manifest digest binds artifact metadata into one "
                    f"reviewable hash: `{manifest.digest}`"
                ),
            ),
        )

        return OperatorSummaryDocument(
            title=title,
            run_id=manifest.run_id,
            task_id=manifest.task_id,
            status="bundle-generated",
            executive_summary=(
                f"Run bundle `{manifest.bundle_id}` contains "
                f"{manifest.artifact_count} recorded artifact(s)."
            ),
            sections=sections,
            findings=tuple(findings),
            metadata={
                "renderer": "operator-summary",
                "product_name": self.product_name,
                "summary_type": "run_bundle",
                "bundle_id": manifest.bundle_id,
                "manifest_digest": manifest.digest,
            },
        )


def _programming_repair_executive_summary(
    *,
    report: ProgrammingRepairRunReport,
    latest_test_run: Any,
) -> str:
    if report.succeeded:
        passed_count = latest_test_run.passed if latest_test_run is not None else 0
        return (
            "The governed programming repair loop reached a successful terminal "
            f"state after {report.attempts_used} attempt(s). The latest parsed "
            f"test run reported {passed_count} passing test(s)."
        )

    if report.terminal_reason:
        return (
            "The governed programming repair loop stopped without a successful "
            f"test-passing outcome. Terminal reason: `{report.terminal_reason}`."
        )

    return (
        "The governed programming repair loop produced a non-terminal report. "
        "Operator review is required before trusting or continuing the run."
    )


def _findings_from_programming_repair_report(
    report: ProgrammingRepairRunReport,
) -> Iterable[OperatorSummaryFinding]:
    if report.succeeded:
        yield OperatorSummaryFinding(
            code="repair.tests_passed",
            severity=OperatorSummaryFindingSeverity.PASS,
            summary="Repair loop reached a test-passing terminal state.",
            detail="The latest parsed test run passed.",
        )
    else:
        yield OperatorSummaryFinding(
            code="repair.not_successful",
            severity=OperatorSummaryFindingSeverity.ERROR,
            summary="Repair loop did not reach a successful terminal state.",
            detail=f"Terminal reason: {report.terminal_reason or 'n/a'}.",
        )

    if report.attempts_used == 0:
        yield OperatorSummaryFinding(
            code="repair.no_attempts",
            severity=OperatorSummaryFindingSeverity.WARNING,
            summary="Repair loop did not apply any candidate patches.",
        )

    if report.attempts_remaining == 0 and not report.succeeded:
        yield OperatorSummaryFinding(
            code="repair.attempt_budget_exhausted",
            severity=OperatorSummaryFindingSeverity.ERROR,
            summary="Repair loop has no remaining attempts.",
        )

    if not report.repair_receipts:
        yield OperatorSummaryFinding(
            code="receipts.repair_missing",
            severity=OperatorSummaryFindingSeverity.WARNING,
            summary="No repair-loop receipts were attached to this report.",
            detail="Attach a RepairLoopReceiptLedger for full loop-control evidence.",
        )

    latest_test_run = report.latest_test_run
    if latest_test_run is not None and latest_test_run.failed_or_errored:
        yield OperatorSummaryFinding(
            code="tests.latest_failed",
            severity=OperatorSummaryFindingSeverity.ERROR,
            summary="Latest parsed test run failed or errored.",
            detail=(
                f"Status `{latest_test_run.status.value}` with "
                f"{latest_test_run.failing_outcomes} failing outcome(s)."
            ),
            metadata={
                "test_status": latest_test_run.status.value,
                "failing_outcomes": latest_test_run.failing_outcomes,
            },
        )


def _patch_activity_markdown(report: ProgrammingRepairRunReport) -> str:
    if not report.patch_results:
        return "No patch tool results were recorded."

    lines: list[str] = []
    for index, result in enumerate(report.patch_results, start=1):
        changed_paths = result.output.get("changed_paths", [])
        if isinstance(changed_paths, list):
            paths_text = ", ".join(f"`{path}`" for path in changed_paths) or "n/a"
        else:
            paths_text = "n/a"

        lines.extend(
            [
                f"### Patch Attempt {index}",
                "",
                f"- Tool status: `{result.status.value}`",
                f"- Tool ID: `{result.tool_id}`",
                f"- Invocation ID: `{result.invocation_id}`",
                f"- Changed paths: {paths_text}",
                f"- Artifact count: `{len(result.artifacts)}`",
                "",
            ]
        )

        if result.failure is not None:
            lines.extend(
                [
                    f"- Failure kind: `{result.failure.kind.value}`",
                    f"- Failure message: {result.failure.message}",
                    "",
                ]
            )

    return "\n".join(lines).strip()


def _test_evidence_markdown(report: ProgrammingRepairRunReport) -> str:
    if not report.parsed_test_runs:
        return "No parsed test runs were recorded."

    lines: list[str] = []
    for index, parsed in enumerate(report.parsed_test_runs, start=1):
        lines.extend(
            [
                f"### Test Run {index}",
                "",
                f"- Parsed status: `{parsed.status.value}`",
                f"- Return code: `{parsed.return_code}`",
                f"- Passed: `{parsed.passed}`",
                f"- Failed: `{parsed.failed}`",
                f"- Errors: `{parsed.errors}`",
                f"- Warnings: `{parsed.warnings}`",
                f"- Duration seconds: `{parsed.duration_seconds if parsed.duration_seconds is not None else 'n/a'}`",
                "",
            ]
        )

        if parsed.test_cases:
            lines.append("Failure targets:")
            for test_case in parsed.test_cases:
                lines.append(
                    f"- `{test_case.node_id}` — `{test_case.status}`"
                )
            lines.append("")

    return "\n".join(lines).strip()


def _human_review_notes(report: ProgrammingRepairRunReport) -> str:
    if report.succeeded:
        return "\n".join(
            [
                "- Confirm the patch diff matches the requested objective.",
                "- Review emitted patch/test artifacts before merge.",
                "- Treat the result as verified only for the captured test command and workspace state.",
            ]
        )

    return "\n".join(
        [
            "- Do not merge or trust the patch without additional operator review.",
            "- Inspect the latest failure target and tool failure metadata.",
            "- Provide a corrected candidate patch or expand diagnostics before retrying.",
        ]
    )


def _bundle_contents_markdown(manifest: RunBundleManifest) -> str:
    if not manifest.artifacts:
        return "No artifacts were recorded in this bundle."

    lines = [
        "| Kind | Path | SHA-256 | Size |",
        "|---|---|---:|---:|",
    ]

    for artifact in manifest.artifacts:
        lines.append(
            f"| `{artifact.kind.value}` | `{artifact.relative_path}` | "
            f"`{artifact.sha256}` | `{artifact.size_bytes}` |"
        )

    return "\n".join(lines)


def _severity_marker(severity: OperatorSummaryFindingSeverity) -> str:
    if severity is OperatorSummaryFindingSeverity.PASS:
        return "PASS"
    if severity is OperatorSummaryFindingSeverity.WARNING:
        return "WARN"
    if severity is OperatorSummaryFindingSeverity.ERROR:
        return "ERROR"
    return "INFO"


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label="optional_identifier")


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
