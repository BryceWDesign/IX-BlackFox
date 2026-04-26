from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self

from ix_blackfox.tools.test_runner import TestCommandResult


class ParsedTestRunStatus(StrEnum):
    """
    Normalized status for a parsed test run.
    """

    PASSED = auto()
    FAILED = auto()
    ERRORED = auto()
    TIMED_OUT = auto()
    NO_TESTS = auto()
    UNKNOWN = auto()


class ParsedTestFindingSeverity(StrEnum):
    """
    Severity for parsed test-run findings.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class ParsedTestFinding:
    """
    One structured finding extracted from test command output.
    """

    code: str
    severity: ParsedTestFindingSeverity
    summary: str
    source: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "source", _normalize_optional_text(self.source))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "source": self.source,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=ParsedTestFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            source=_optional_text_from_payload(payload, "source"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ParsedTestCase:
    """
    One parsed test case or failure target.

    Pytest's compact text output does not always list every passing test case.
    This model therefore represents both explicit node ids and failure-summary
    targets. Counts remain authoritative at the run level.
    """

    node_id: str
    status: str
    message: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _normalize_text(self.node_id, label="node_id"))
        object.__setattr__(self, "status", _normalize_token(self.status, label="status"))
        object.__setattr__(self, "message", _normalize_optional_text(self.message))
        object.__setattr__(self, "file_path", _normalize_optional_text(self.file_path))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.line_number is not None and self.line_number <= 0:
            raise ValueError("ParsedTestCase line_number must be positive when provided.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "status": self.status,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        line_number = payload.get("line_number")
        return cls(
            node_id=_require_text(payload, "node_id"),
            status=_require_text(payload, "status"),
            message=_optional_text_from_payload(payload, "message"),
            file_path=_optional_text_from_payload(payload, "file_path"),
            line_number=int(line_number) if line_number is not None else None,
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ParsedTestRun:
    """
    Structured test result parsed from governed test command output.
    """

    status: ParsedTestRunStatus
    command: tuple[str, ...]
    return_code: int
    timed_out: bool
    duration_seconds: float | None = None
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0
    xpassed: int = 0
    warnings: int = 0
    deselected: int = 0
    selected: int | None = None
    test_cases: tuple[ParsedTestCase, ...] = field(default_factory=tuple)
    findings: tuple[ParsedTestFinding, ...] = field(default_factory=tuple)
    raw_summary_line: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "test_cases", tuple(self.test_cases))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "raw_summary_line", _normalize_optional_text(self.raw_summary_line))
        object.__setattr__(self, "metadata", dict(self.metadata))

        for field_name in (
            "passed",
            "failed",
            "errors",
            "skipped",
            "xfailed",
            "xpassed",
            "warnings",
            "deselected",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(f"ParsedTestRun {field_name} must not be negative.")

        if self.selected is not None and self.selected < 0:
            raise ValueError("ParsedTestRun selected must not be negative when provided.")

        if self.duration_seconds is not None and self.duration_seconds < 0:
            raise ValueError("ParsedTestRun duration_seconds must not be negative.")

    @property
    def total_outcomes(self) -> int:
        return (
            self.passed
            + self.failed
            + self.errors
            + self.skipped
            + self.xfailed
            + self.xpassed
        )

    @property
    def failing_outcomes(self) -> int:
        return self.failed + self.errors + self.xpassed

    @property
    def succeeded(self) -> bool:
        return self.status is ParsedTestRunStatus.PASSED

    @property
    def failed_or_errored(self) -> bool:
        return self.status in {
            ParsedTestRunStatus.FAILED,
            ParsedTestRunStatus.ERRORED,
            ParsedTestRunStatus.TIMED_OUT,
        }

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.findings)

    def has_finding(self, code: str) -> bool:
        normalized_code = _normalize_token(code, label="code")
        return normalized_code in self.finding_codes

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "command": list(self.command),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "xfailed": self.xfailed,
            "xpassed": self.xpassed,
            "warnings": self.warnings,
            "deselected": self.deselected,
            "selected": self.selected,
            "total_outcomes": self.total_outcomes,
            "failing_outcomes": self.failing_outcomes,
            "test_cases": [test_case.to_dict() for test_case in self.test_cases],
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_summary_line": self.raw_summary_line,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_test_cases = payload.get("test_cases", ())
        raw_findings = payload.get("findings", ())

        if not isinstance(raw_test_cases, Iterable) or isinstance(raw_test_cases, str):
            raise TypeError("test_cases must be an iterable of mappings.")
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        test_cases: list[ParsedTestCase] = []
        for raw_test_case in raw_test_cases:
            if not isinstance(raw_test_case, Mapping):
                raise TypeError("test_cases must contain only mappings.")
            test_cases.append(ParsedTestCase.from_dict(raw_test_case))

        findings: list[ParsedTestFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(ParsedTestFinding.from_dict(raw_finding))

        selected = payload.get("selected")
        duration_seconds = payload.get("duration_seconds")

        return cls(
            status=ParsedTestRunStatus(_require_text(payload, "status")),
            command=tuple(_coerce_string_list(payload.get("command", ()), field_name="command")),
            return_code=int(payload.get("return_code", 0)),
            timed_out=bool(payload.get("timed_out", False)),
            duration_seconds=(
                float(duration_seconds) if duration_seconds is not None else None
            ),
            passed=int(payload.get("passed", 0)),
            failed=int(payload.get("failed", 0)),
            errors=int(payload.get("errors", 0)),
            skipped=int(payload.get("skipped", 0)),
            xfailed=int(payload.get("xfailed", 0)),
            xpassed=int(payload.get("xpassed", 0)),
            warnings=int(payload.get("warnings", 0)),
            deselected=int(payload.get("deselected", 0)),
            selected=int(selected) if selected is not None else None,
            test_cases=tuple(test_cases),
            findings=tuple(findings),
            raw_summary_line=_optional_text_from_payload(payload, "raw_summary_line"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class PytestTextResultParser:
    """
    Parser for pytest text output captured by the governed test runner.

    The parser intentionally handles common pytest output shapes without trying
    to become a pytest replacement. It extracts:
    - final short test summary counts
    - failure/error targets from summary lines
    - collection errors
    - warning counts
    - timeout and return-code status
    """

    def parse_command_result(self, result: TestCommandResult) -> ParsedTestRun:
        combined_output = _combine_output(result.stdout, result.stderr)
        parsed = self.parse_text(
            text=combined_output,
            command=result.command,
            return_code=result.return_code,
            timed_out=result.timed_out,
        )

        return ParsedTestRun(
            status=(
                ParsedTestRunStatus.TIMED_OUT
                if result.timed_out
                else parsed.status
            ),
            command=parsed.command,
            return_code=parsed.return_code,
            timed_out=result.timed_out,
            duration_seconds=parsed.duration_seconds,
            passed=parsed.passed,
            failed=parsed.failed,
            errors=parsed.errors,
            skipped=parsed.skipped,
            xfailed=parsed.xfailed,
            xpassed=parsed.xpassed,
            warnings=parsed.warnings,
            deselected=parsed.deselected,
            selected=parsed.selected,
            test_cases=parsed.test_cases,
            findings=(
                *parsed.findings,
                *(
                    (
                        ParsedTestFinding(
                            code="pytest.command_timed_out",
                            severity=ParsedTestFindingSeverity.ERROR,
                            summary="The governed test command timed out.",
                            metadata={"timeout_seconds": result.timeout_seconds},
                        ),
                    )
                    if result.timed_out
                    else ()
                ),
            ),
            raw_summary_line=parsed.raw_summary_line,
            metadata={
                **dict(parsed.metadata),
                "cwd": result.cwd,
                "stdout_truncated": result.stdout_truncated,
                "stderr_truncated": result.stderr_truncated,
            },
        )

    def parse_text(
        self,
        *,
        text: str,
        command: tuple[str, ...] = (),
        return_code: int = 0,
        timed_out: bool = False,
    ) -> ParsedTestRun:
        lines = tuple(text.splitlines())
        summary_line = _find_final_summary_line(lines)
        counts = _parse_summary_counts(summary_line)
        duration_seconds = _parse_duration_seconds(summary_line)
        failure_cases = tuple(_parse_failure_summary_cases(lines))
        findings = list(_parse_findings(lines=lines, summary_line=summary_line))

        if summary_line is None:
            findings.append(
                ParsedTestFinding(
                    code="pytest.summary_missing",
                    severity=ParsedTestFindingSeverity.WARNING,
                    summary="Could not find a pytest final summary line.",
                    metadata={"return_code": return_code},
                )
            )

        status = _status_from_counts(
            counts=counts,
            return_code=return_code,
            timed_out=timed_out,
            summary_line=summary_line,
        )

        return ParsedTestRun(
            status=status,
            command=command,
            return_code=return_code,
            timed_out=timed_out,
            duration_seconds=duration_seconds,
            passed=counts["passed"],
            failed=counts["failed"],
            errors=counts["errors"],
            skipped=counts["skipped"],
            xfailed=counts["xfailed"],
            xpassed=counts["xpassed"],
            warnings=counts["warnings"],
            deselected=counts["deselected"],
            selected=counts["selected"] if counts["selected"] else None,
            test_cases=failure_cases,
            findings=tuple(findings),
            raw_summary_line=summary_line,
            metadata={
                "parser": "pytest-text",
                "line_count": len(lines),
            },
        )


def _combine_output(stdout: str, stderr: str) -> str:
    if stdout and stderr:
        return f"{stdout}\n{stderr}"
    return stdout or stderr


def _find_final_summary_line(lines: Iterable[str]) -> str | None:
    candidates: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        lower = stripped.lower()
        if stripped.startswith("=") and stripped.endswith("="):
            if any(token in lower for token in _SUMMARY_TOKENS):
                candidates.append(stripped)
            continue

        if _looks_like_compact_pytest_summary(lower):
            candidates.append(stripped)

    if not candidates:
        return None

    return candidates[-1]


def _looks_like_compact_pytest_summary(line: str) -> bool:
    if " in " not in line or not line.endswith("s"):
        return False
    if not any(token in line for token in _SUMMARY_TOKENS):
        return False
    return re.search(r"\b\d+\s+(passed|failed|errors?|skipped|xfailed|xpassed|warnings?|deselected|selected)\b", line) is not None


def _parse_summary_counts(summary_line: str | None) -> Counter[str]:
    counts: Counter[str] = Counter(
        {
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "warnings": 0,
            "deselected": 0,
            "selected": 0,
        }
    )

    if summary_line is None:
        return counts

    lower = summary_line.lower()
    normalized = lower.replace("=", " ").replace(",", " ")
    for number_text, token in re.findall(r"(\d+)\s+([a-z_]+)", normalized):
        number = int(number_text)
        singular = token.rstrip("s")

        if singular == "passed":
            counts["passed"] += number
        elif singular == "failed":
            counts["failed"] += number
        elif singular == "error":
            counts["errors"] += number
        elif singular == "skipped":
            counts["skipped"] += number
        elif singular == "xfailed":
            counts["xfailed"] += number
        elif singular == "xpassed":
            counts["xpassed"] += number
        elif singular == "warning":
            counts["warnings"] += number
        elif singular == "deselected":
            counts["deselected"] += number
        elif singular == "selected":
            counts["selected"] += number

    return counts


def _parse_duration_seconds(summary_line: str | None) -> float | None:
    if summary_line is None:
        return None

    match = re.search(r"in\s+([0-9]+(?:\.[0-9]+)?)s", summary_line)
    if match is None:
        return None

    return float(match.group(1))


def _parse_failure_summary_cases(lines: Iterable[str]) -> Iterable[ParsedTestCase]:
    cases: list[ParsedTestCase] = []
    in_short_summary = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("=") and "short test summary info" in stripped.lower():
            in_short_summary = True
            continue

        if in_short_summary and stripped.startswith("=") and stripped.endswith("="):
            break

        if not in_short_summary or not stripped:
            continue

        match = re.match(
            r"^(FAILED|ERROR|SKIPPED|XFAILED|XPASSED)\s+(.+?)(?:\s+-\s+(.+))?$",
            stripped,
        )
        if match is None:
            continue

        status = match.group(1).lower()
        node_id = match.group(2).strip()
        message = match.group(3).strip() if match.group(3) else None
        file_path, line_number = _parse_node_location(node_id)

        cases.append(
            ParsedTestCase(
                node_id=node_id,
                status=status,
                message=message,
                file_path=file_path,
                line_number=line_number,
                metadata={"source": "short_test_summary"},
            )
        )

    return tuple(cases)


def _parse_node_location(node_id: str) -> tuple[str | None, int | None]:
    location_match = re.match(r"^(.+?):(\d+)(?:::.*)?$", node_id)
    if location_match is not None:
        return location_match.group(1), int(location_match.group(2))

    if "::" in node_id:
        return node_id.split("::", 1)[0], None

    if node_id.endswith(".py") or "/" in node_id or "\\" in node_id:
        return node_id, None

    return None, None


def _parse_findings(
    *,
    lines: tuple[str, ...],
    summary_line: str | None,
) -> Iterable[ParsedTestFinding]:
    findings: list[ParsedTestFinding] = []

    if any("importerror" in line.lower() for line in lines):
        findings.append(
            ParsedTestFinding(
                code="pytest.import_error",
                severity=ParsedTestFindingSeverity.ERROR,
                summary="Pytest output contains an import error.",
            )
        )

    if any("modulenotfounderror" in line.lower() for line in lines):
        findings.append(
            ParsedTestFinding(
                code="pytest.module_not_found",
                severity=ParsedTestFindingSeverity.ERROR,
                summary="Pytest output contains a missing module error.",
            )
        )

    if any("syntaxerror" in line.lower() for line in lines):
        findings.append(
            ParsedTestFinding(
                code="pytest.syntax_error",
                severity=ParsedTestFindingSeverity.ERROR,
                summary="Pytest output contains a syntax error.",
            )
        )

    if any("interrupted:" in line.lower() for line in lines):
        findings.append(
            ParsedTestFinding(
                code="pytest.collection_interrupted",
                severity=ParsedTestFindingSeverity.ERROR,
                summary="Pytest collection or execution was interrupted.",
            )
        )

    if summary_line is not None and "warning" in summary_line.lower():
        findings.append(
            ParsedTestFinding(
                code="pytest.warnings_present",
                severity=ParsedTestFindingSeverity.WARNING,
                summary="Pytest reported warnings.",
                metadata={"summary_line": summary_line},
            )
        )

    return tuple(_dedupe_findings(findings))


def _status_from_counts(
    *,
    counts: Counter[str],
    return_code: int,
    timed_out: bool,
    summary_line: str | None,
) -> ParsedTestRunStatus:
    if timed_out:
        return ParsedTestRunStatus.TIMED_OUT

    if counts["errors"] > 0:
        return ParsedTestRunStatus.ERRORED

    if counts["failed"] > 0 or counts["xpassed"] > 0:
        return ParsedTestRunStatus.FAILED

    if counts["passed"] > 0 or counts["skipped"] > 0 or counts["xfailed"] > 0:
        return ParsedTestRunStatus.PASSED if return_code == 0 else ParsedTestRunStatus.FAILED

    if summary_line is not None and "no tests ran" in summary_line.lower():
        return ParsedTestRunStatus.NO_TESTS

    if return_code == 5:
        return ParsedTestRunStatus.NO_TESTS

    if return_code != 0:
        return ParsedTestRunStatus.FAILED

    return ParsedTestRunStatus.UNKNOWN


def _dedupe_findings(
    findings: Iterable[ParsedTestFinding],
) -> tuple[ParsedTestFinding, ...]:
    deduped: list[ParsedTestFinding] = []
    seen: set[str] = set()

    for finding in findings:
        if finding.code in seen:
            continue
        deduped.append(finding)
        seen.add(finding.code)

    return tuple(deduped)


_SUMMARY_TOKENS = (
    "passed",
    "failed",
    "error",
    "warning",
    "skipped",
    "xfailed",
    "xpassed",
    "deselected",
    "selected",
    "no tests ran",
)


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
