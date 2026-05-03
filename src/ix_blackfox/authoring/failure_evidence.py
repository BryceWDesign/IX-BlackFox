from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.errors import AuthoringEvidenceError
from ix_blackfox.authoring.models import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
)
from ix_blackfox.tools.test_results import (
    ParsedTestCase,
    ParsedTestFindingSeverity,
    ParsedTestRun,
    ParsedTestRunStatus,
    PytestTextResultParser,
)


class FailureEvidenceKind(StrEnum):
    """
    Normalized evidence category extracted from test output.
    """

    PYTEST_FAILURE = auto()
    PYTEST_ERROR = auto()
    PYTEST_TIMEOUT = auto()
    PYTEST_WARNING = auto()
    PYTEST_SUMMARY = auto()
    OBJECTIVE_ONLY = auto()
    MISSING = auto()


@dataclass(frozen=True, slots=True)
class FailureEvidenceSnippet:
    """
    Bounded snippet of failure evidence safe to pass into later authoring stages.
    """

    snippet_id: str
    kind: FailureEvidenceKind
    text: str
    node_id: str | None = None
    path: str | None = None
    line_number: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "snippet_id",
            _normalize_identifier(self.snippet_id, label="snippet_id"),
        )
        object.__setattr__(self, "text", _normalize_text(self.text, label="text"))
        object.__setattr__(self, "node_id", _normalize_optional_text(self.node_id))
        object.__setattr__(self, "path", _normalize_optional_relative_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.line_number is not None and self.line_number <= 0:
            raise ValueError("FailureEvidenceSnippet line_number must be positive.")

    @classmethod
    def create(
        cls,
        *,
        kind: FailureEvidenceKind,
        text: str,
        node_id: str | None = None,
        path: str | None = None,
        line_number: int | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            snippet_id=f"failure-snippet-{uuid4().hex}",
            kind=kind,
            text=text,
            node_id=node_id,
            path=path,
            line_number=line_number,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet_id": self.snippet_id,
            "kind": self.kind.value,
            "text": self.text,
            "node_id": self.node_id,
            "path": self.path,
            "line_number": self.line_number,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            snippet_id=_require_text(payload, "snippet_id"),
            kind=FailureEvidenceKind(_require_text(payload, "kind")),
            text=_require_text(payload, "text"),
            node_id=_optional_text_from_payload(payload, "node_id"),
            path=_optional_text_from_payload(payload, "path"),
            line_number=_optional_int_from_payload(payload, "line_number"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class FailureEvidenceReport:
    """
    Complete structured output from Wave 3 failure evidence extraction.
    """

    evidence: AuthoringEvidence
    snippets: tuple[FailureEvidenceSnippet, ...] = field(default_factory=tuple)
    failing_node_ids: tuple[str, ...] = field(default_factory=tuple)
    related_paths: tuple[str, ...] = field(default_factory=tuple)
    raw_digest: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        snippets = tuple(self.snippets)
        failing_node_ids = tuple(
            _normalize_text(value, label="failing_node_id")
            for value in self.failing_node_ids
        )
        related_paths = tuple(
            _normalize_relative_path(value)
            for value in self.related_paths
        )

        object.__setattr__(self, "snippets", snippets)
        object.__setattr__(self, "failing_node_ids", failing_node_ids)
        object.__setattr__(self, "related_paths", related_paths)
        object.__setattr__(self, "raw_digest", _normalize_optional_digest(self.raw_digest))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def has_direct_failure_evidence(self) -> bool:
        return self.evidence.strength is AuthoringEvidenceStrength.DIRECT

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": self.evidence.to_dict(),
            "snippets": [snippet.to_dict() for snippet in self.snippets],
            "failing_node_ids": list(self.failing_node_ids),
            "related_paths": list(self.related_paths),
            "raw_digest": self.raw_digest,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_evidence = payload.get("evidence")
        if not isinstance(raw_evidence, Mapping):
            raise TypeError("evidence must be a mapping.")

        raw_snippets = payload.get("snippets", ())
        if not isinstance(raw_snippets, Iterable) or isinstance(raw_snippets, str):
            raise TypeError("snippets must be an iterable of mappings.")

        snippets: list[FailureEvidenceSnippet] = []
        for raw_snippet in raw_snippets:
            if not isinstance(raw_snippet, Mapping):
                raise TypeError("snippets must contain only mappings.")
            snippets.append(FailureEvidenceSnippet.from_dict(raw_snippet))

        return cls(
            evidence=AuthoringEvidence.from_dict(raw_evidence),
            snippets=tuple(snippets),
            failing_node_ids=_coerce_text_tuple(
                payload.get("failing_node_ids", ()),
                field_name="failing_node_ids",
            ),
            related_paths=_coerce_text_tuple(
                payload.get("related_paths", ()),
                field_name="related_paths",
            ),
            raw_digest=_optional_text_from_payload(payload, "raw_digest"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class FailureEvidenceExtractorConfig:
    """
    Limits for converting test output into authoring evidence.
    """

    max_snippets: int = 12
    max_snippet_chars: int = 1_600
    max_summary_chars: int = 1_200

    def __post_init__(self) -> None:
        if self.max_snippets <= 0:
            raise ValueError("max_snippets must be positive.")
        if self.max_snippet_chars <= 0:
            raise ValueError("max_snippet_chars must be positive.")
        if self.max_summary_chars <= 0:
            raise ValueError("max_summary_chars must be positive.")


@dataclass(frozen=True, slots=True)
class FailureEvidenceExtractor:
    """
    Converts parsed or raw pytest output into Wave 3 authoring evidence.

    This extractor does not decide how to repair code. It only turns test output
    into bounded evidence records that later decomposition, hypothesis, and
    patch-authoring stages can use.
    """

    config: FailureEvidenceExtractorConfig = field(
        default_factory=FailureEvidenceExtractorConfig
    )
    parser: PytestTextResultParser = field(default_factory=PytestTextResultParser)

    def from_pytest_text(
        self,
        *,
        text: str,
        command: tuple[str, ...] = (),
        return_code: int = 1,
        timed_out: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> FailureEvidenceReport:
        normalized_text = _normalize_text(text, label="text")
        parsed = self.parser.parse_text(
            text=normalized_text,
            command=command,
            return_code=return_code,
            timed_out=timed_out,
        )
        return self.from_parsed_test_run(
            parsed_test_run=parsed,
            raw_text=normalized_text,
            metadata={
                "source": "pytest_text",
                **dict(metadata or {}),
            },
        )

    def from_parsed_test_run(
        self,
        *,
        parsed_test_run: ParsedTestRun,
        raw_text: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> FailureEvidenceReport:
        if not isinstance(parsed_test_run, ParsedTestRun):
            raise AuthoringEvidenceError("parsed_test_run must be a ParsedTestRun.")

        raw_digest = _sha256_text(raw_text)
        related_paths = _related_paths(parsed_test_run.test_cases)
        failing_node_ids = tuple(
            test_case.node_id
            for test_case in parsed_test_run.test_cases
            if _is_failing_case(test_case)
        )
        snippets = self._build_snippets(
            parsed_test_run=parsed_test_run,
            raw_text=raw_text,
        )
        findings = self._build_findings(
            parsed_test_run=parsed_test_run,
            snippets=snippets,
        )
        strength = _evidence_strength(parsed_test_run)
        summary = _bounded_text(
            _summary_for_parsed_test_run(
                parsed_test_run=parsed_test_run,
                snippets=snippets,
                related_paths=related_paths,
            ),
            max_chars=self.config.max_summary_chars,
        )

        evidence = AuthoringEvidence.create(
            source="pytest",
            strength=strength,
            summary=summary,
            raw_text=raw_text,
            related_paths=related_paths,
            findings=findings,
            metadata={
                "status": parsed_test_run.status.value,
                "command": list(parsed_test_run.command),
                "return_code": parsed_test_run.return_code,
                "timed_out": parsed_test_run.timed_out,
                "passed": parsed_test_run.passed,
                "failed": parsed_test_run.failed,
                "errors": parsed_test_run.errors,
                "warnings": parsed_test_run.warnings,
                "raw_summary_line": parsed_test_run.raw_summary_line,
                **dict(metadata or {}),
            },
        )

        return FailureEvidenceReport(
            evidence=evidence,
            snippets=snippets,
            failing_node_ids=failing_node_ids,
            related_paths=related_paths,
            raw_digest=raw_digest,
            metadata={
                "extractor": "FailureEvidenceExtractor",
                "snippet_count": len(snippets),
                "finding_count": len(findings),
                "evidence_strength": strength.value,
            },
        )

    def from_objective_only(
        self,
        *,
        objective: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> FailureEvidenceReport:
        normalized_objective = _normalize_text(objective, label="objective")
        snippet = FailureEvidenceSnippet.create(
            kind=FailureEvidenceKind.OBJECTIVE_ONLY,
            text=_bounded_text(
                normalized_objective,
                max_chars=self.config.max_snippet_chars,
            ),
            metadata={"source": "operator_objective"},
        )
        finding = AuthoringFinding(
            code="authoring.objective_only_evidence",
            severity=AuthoringFindingSeverity.WARNING,
            summary=(
                "No direct test failure evidence was provided; authoring must "
                "treat the operator objective as weak evidence."
            ),
            metadata={"source": "operator_objective"},
        )
        evidence = AuthoringEvidence.create(
            source="operator_objective",
            strength=AuthoringEvidenceStrength.WEAK,
            summary=_bounded_text(
                f"Objective-only evidence: {normalized_objective}",
                max_chars=self.config.max_summary_chars,
            ),
            raw_text=normalized_objective,
            findings=(finding,),
            metadata=dict(metadata or {}),
        )

        return FailureEvidenceReport(
            evidence=evidence,
            snippets=(snippet,),
            raw_digest=evidence.raw_digest,
            metadata={
                "extractor": "FailureEvidenceExtractor",
                "snippet_count": 1,
                "finding_count": 1,
                "evidence_strength": AuthoringEvidenceStrength.WEAK.value,
            },
        )

    def _build_snippets(
        self,
        *,
        parsed_test_run: ParsedTestRun,
        raw_text: str | None,
    ) -> tuple[FailureEvidenceSnippet, ...]:
        snippets: list[FailureEvidenceSnippet] = []

        for test_case in parsed_test_run.test_cases:
            if len(snippets) >= self.config.max_snippets:
                break
            if not _is_failing_case(test_case):
                continue

            snippet_text = _case_snippet(
                test_case=test_case,
                raw_text=raw_text,
                max_chars=self.config.max_snippet_chars,
            )
            snippets.append(
                FailureEvidenceSnippet.create(
                    kind=_kind_for_test_case(test_case),
                    text=snippet_text,
                    node_id=test_case.node_id,
                    path=test_case.file_path,
                    line_number=test_case.line_number,
                    metadata={
                        "status": test_case.status,
                        "message": test_case.message,
                        **dict(test_case.metadata),
                    },
                )
            )

        if parsed_test_run.timed_out and len(snippets) < self.config.max_snippets:
            snippets.append(
                FailureEvidenceSnippet.create(
                    kind=FailureEvidenceKind.PYTEST_TIMEOUT,
                    text="The governed pytest run timed out.",
                    metadata={
                        "return_code": parsed_test_run.return_code,
                        "command": list(parsed_test_run.command),
                    },
                )
            )

        if (
            not snippets
            and parsed_test_run.raw_summary_line
            and len(snippets) < self.config.max_snippets
        ):
            snippets.append(
                FailureEvidenceSnippet.create(
                    kind=FailureEvidenceKind.PYTEST_SUMMARY,
                    text=parsed_test_run.raw_summary_line,
                    metadata={
                        "status": parsed_test_run.status.value,
                        "return_code": parsed_test_run.return_code,
                    },
                )
            )

        return tuple(snippets)

    def _build_findings(
        self,
        *,
        parsed_test_run: ParsedTestRun,
        snippets: tuple[FailureEvidenceSnippet, ...],
    ) -> tuple[AuthoringFinding, ...]:
        findings: list[AuthoringFinding] = []

        if parsed_test_run.failed > 0:
            findings.append(
                AuthoringFinding(
                    code="pytest.failures_detected",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary=f"Pytest reported {parsed_test_run.failed} failed test outcome(s).",
                    metadata={"failed": parsed_test_run.failed},
                )
            )

        if parsed_test_run.errors > 0:
            findings.append(
                AuthoringFinding(
                    code="pytest.errors_detected",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary=f"Pytest reported {parsed_test_run.errors} error outcome(s).",
                    metadata={"errors": parsed_test_run.errors},
                )
            )

        if parsed_test_run.timed_out:
            findings.append(
                AuthoringFinding(
                    code="pytest.timeout_detected",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Pytest timed out before producing a successful result.",
                    metadata={"return_code": parsed_test_run.return_code},
                )
            )

        if parsed_test_run.status is ParsedTestRunStatus.NO_TESTS:
            findings.append(
                AuthoringFinding(
                    code="pytest.no_tests_detected",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="Pytest did not collect or run tests.",
                    metadata={"return_code": parsed_test_run.return_code},
                )
            )

        if parsed_test_run.status is ParsedTestRunStatus.UNKNOWN:
            findings.append(
                AuthoringFinding(
                    code="pytest.status_unknown",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="Pytest output could not be classified confidently.",
                    metadata={"return_code": parsed_test_run.return_code},
                )
            )

        for parsed_finding in parsed_test_run.findings:
            findings.append(
                AuthoringFinding(
                    code=parsed_finding.code,
                    severity=_map_finding_severity(parsed_finding.severity),
                    summary=parsed_finding.summary,
                    metadata={
                        "source": parsed_finding.source,
                        **dict(parsed_finding.metadata),
                    },
                )
            )

        if not snippets:
            findings.append(
                AuthoringFinding(
                    code="authoring.failure_snippets_missing",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="No bounded failure snippets were extracted from the pytest output.",
                    metadata={"status": parsed_test_run.status.value},
                )
            )

        return _dedupe_findings(findings)


def _summary_for_parsed_test_run(
    *,
    parsed_test_run: ParsedTestRun,
    snippets: tuple[FailureEvidenceSnippet, ...],
    related_paths: tuple[str, ...],
) -> str:
    if parsed_test_run.failed_or_errored:
        parts = [
            (
                "Direct pytest failure evidence extracted: "
                f"status={parsed_test_run.status.value}, "
                f"failed={parsed_test_run.failed}, "
                f"errors={parsed_test_run.errors}, "
                f"return_code={parsed_test_run.return_code}."
            )
        ]

        if related_paths:
            parts.append(f"Related paths: {', '.join(related_paths)}.")

        if snippets:
            node_ids = tuple(snippet.node_id for snippet in snippets if snippet.node_id)
            if node_ids:
                parts.append(f"Failure targets: {', '.join(node_ids)}.")

        if parsed_test_run.raw_summary_line:
            parts.append(f"Summary line: {parsed_test_run.raw_summary_line}")

        return " ".join(parts)

    if parsed_test_run.timed_out:
        return (
            "Direct timeout evidence extracted from pytest run: "
            f"return_code={parsed_test_run.return_code}."
        )

    if parsed_test_run.status is ParsedTestRunStatus.NO_TESTS:
        return (
            "Weak pytest evidence extracted: no tests were collected or executed. "
            f"return_code={parsed_test_run.return_code}."
        )

    if parsed_test_run.status is ParsedTestRunStatus.PASSED:
        return (
            "No failure evidence extracted: pytest status was passed. "
            f"passed={parsed_test_run.passed}, warnings={parsed_test_run.warnings}."
        )

    return (
        "Missing or weak pytest evidence extracted: "
        f"status={parsed_test_run.status.value}, return_code={parsed_test_run.return_code}."
    )


def _evidence_strength(parsed_test_run: ParsedTestRun) -> AuthoringEvidenceStrength:
    if parsed_test_run.failed_or_errored or parsed_test_run.timed_out:
        return AuthoringEvidenceStrength.DIRECT
    if parsed_test_run.status is ParsedTestRunStatus.PASSED:
        return AuthoringEvidenceStrength.MISSING
    return AuthoringEvidenceStrength.WEAK


def _related_paths(test_cases: Iterable[ParsedTestCase]) -> tuple[str, ...]:
    paths: list[str] = []
    seen: set[str] = set()

    for test_case in test_cases:
        if not test_case.file_path:
            continue
        try:
            normalized = _normalize_relative_path(test_case.file_path)
        except ValueError:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        paths.append(normalized)

    return tuple(paths)


def _case_snippet(
    *,
    test_case: ParsedTestCase,
    raw_text: str | None,
    max_chars: int,
) -> str:
    base_parts = [
        f"{test_case.status.upper()} {test_case.node_id}",
    ]
    if test_case.message:
        base_parts.append(test_case.message)

    if raw_text:
        extracted = _extract_raw_snippet(
            raw_text=raw_text,
            test_case=test_case,
            max_chars=max_chars,
        )
        if extracted:
            base_parts.append(extracted)

    return _bounded_text("\n".join(base_parts), max_chars=max_chars)


def _extract_raw_snippet(
    *,
    raw_text: str,
    test_case: ParsedTestCase,
    max_chars: int,
) -> str | None:
    lines = raw_text.splitlines()
    anchors = tuple(
        anchor
        for anchor in (
            test_case.node_id,
            test_case.file_path,
            test_case.message,
        )
        if anchor
    )

    if not anchors:
        return None

    for index, line in enumerate(lines):
        if any(anchor in line for anchor in anchors):
            start = max(0, index - 4)
            end = min(len(lines), index + 12)
            snippet = "\n".join(lines[start:end]).strip()
            if snippet:
                return _bounded_text(snippet, max_chars=max_chars)

    return None


def _kind_for_test_case(test_case: ParsedTestCase) -> FailureEvidenceKind:
    status = test_case.status.strip().lower()
    if status == "error":
        return FailureEvidenceKind.PYTEST_ERROR
    return FailureEvidenceKind.PYTEST_FAILURE


def _is_failing_case(test_case: ParsedTestCase) -> bool:
    return test_case.status.strip().lower() in {"failed", "error", "xpassed"}


def _map_finding_severity(
    severity: ParsedTestFindingSeverity,
) -> AuthoringFindingSeverity:
    if severity is ParsedTestFindingSeverity.ERROR:
        return AuthoringFindingSeverity.ERROR
    if severity is ParsedTestFindingSeverity.WARNING:
        return AuthoringFindingSeverity.WARNING
    return AuthoringFindingSeverity.INFO


def _dedupe_findings(findings: Iterable[AuthoringFinding]) -> tuple[AuthoringFinding, ...]:
    deduped: list[AuthoringFinding] = []
    seen: set[tuple[str, str | None]] = set()

    for finding in findings:
        key = (finding.code, finding.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return tuple(deduped)


def _bounded_text(value: str, *, max_chars: int) -> str:
    cleaned = value.strip()
    if len(cleaned) <= max_chars:
        return cleaned

    suffix = "\n[truncated]"
    return cleaned[: max(0, max_chars - len(suffix))].rstrip() + suffix


def _sha256_text(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
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


def _normalize_optional_relative_path(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_path(value)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path traversal is not allowed: {value!r}")
        parts.append(part)

    if not parts:
        raise ValueError("relative path must not resolve to workspace root.")
    return "/".join(parts)


def _normalize_optional_digest(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or re.search(r"[^0-9a-f]", cleaned):
        raise ValueError("digest must be a 64-character lowercase hexadecimal value.")
    return cleaned


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        result.append(item)
    return tuple(result)


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


def _optional_int_from_payload(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer or None.")
    return value
