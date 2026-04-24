from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from threading import RLock
from typing import Any

from ix_blackfox.kernel import TaskRecord
from ix_blackfox.memory import TraceRecord


class SentinelSeverity(StrEnum):
    """
    Severity levels emitted by sentinel checks.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class SentinelIssue:
    """
    One issue emitted by a sentinel check.

    Attributes
    ----------
    code:
        Stable machine-readable issue code.
    severity:
        Severity level for the issue.
    summary:
        Short human-readable description.
    source:
        Optional source label, usually the sentinel check name.
    details:
        Optional longer-form detail text.
    data:
        Optional structured diagnostic payload.
    """

    code: str
    severity: SentinelSeverity
    summary: str
    source: str | None = None
    details: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_code = _normalize_identifier(self.code, label="issue code")
        normalized_summary = _normalize_text(self.summary, label="issue summary")
        normalized_source = _normalize_optional_text(self.source)
        normalized_details = _normalize_optional_text(self.details)

        object.__setattr__(self, "code", normalized_code)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "details", normalized_details)
        object.__setattr__(self, "data", dict(self.data))


@dataclass(frozen=True, slots=True)
class SentinelContext:
    """
    Runtime context supplied to sentinel checks.

    Attributes
    ----------
    task:
        Optional task under evaluation.
    trace_records:
        Trace records associated with the current evaluation window.
    metadata:
        Optional extra structured context for checks.
    """

    task: TaskRecord | None = None
    trace_records: tuple[TraceRecord, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SentinelReport:
    """
    Aggregated result of running sentinel checks.
    """

    evaluated_at: datetime
    check_count: int
    issues: tuple[SentinelIssue, ...] = field(default_factory=tuple)

    def has_severity(self, severity: SentinelSeverity) -> bool:
        """
        Return True if any issue has the requested severity.
        """
        return any(issue.severity == severity for issue in self.issues)

    def filter_by_severity(
        self,
        severity: SentinelSeverity,
    ) -> tuple[SentinelIssue, ...]:
        """
        Return all issues matching one severity level.
        """
        return tuple(issue for issue in self.issues if issue.severity == severity)

    def highest_severity(self) -> SentinelSeverity | None:
        """
        Return the highest sentinel severity observed, if any.
        """
        order = (
            SentinelSeverity.CRITICAL,
            SentinelSeverity.ERROR,
            SentinelSeverity.WARNING,
            SentinelSeverity.INFO,
        )
        for severity in order:
            if self.has_severity(severity):
                return severity
        return None

    def has_issue_code(self, code: str) -> bool:
        """
        Return True when an issue with the exact code is present.
        """
        normalized_code = _normalize_identifier(code, label="issue code")
        return any(issue.code == normalized_code for issue in self.issues)

    def has_issue_code_fragment(self, fragment: str) -> bool:
        """
        Return True when any issue code contains the supplied fragment.
        """
        normalized_fragment = _normalize_identifier(fragment, label="issue code fragment")
        return any(normalized_fragment in issue.code for issue in self.issues)

    def has_contradiction_signal(self) -> bool:
        """
        Return True when one or more issues indicate contradiction signals.
        """
        return any(
            "contradiction" in issue.code
            or (
                issue.source is not None
                and "contradiction" in issue.source.strip().lower()
            )
            for issue in self.issues
        )


@dataclass(frozen=True, slots=True)
class SentinelSnapshot:
    """
    Immutable view of the registered sentinel checks.
    """

    check_names: tuple[str, ...]

    def contains(self, check_name: str) -> bool:
        """
        Return True if a check name is currently registered.
        """
        normalized_name = _normalize_identifier(check_name, label="check name")
        return normalized_name in self.check_names


class SentinelCheck(ABC):
    """
    Base protocol for executable sentinel checks.
    """

    @property
    @abstractmethod
    def check_name(self) -> str:
        """
        Stable internal check name.
        """

    @abstractmethod
    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        """
        Evaluate runtime context and return zero or more issues.
        """


class SentinelRuntime:
    """
    Deterministic runtime for executing sentinel checks.

    This core isolates check failures and converts them into explicit
    issues so the safety layer remains observable instead of brittle.
    """

    def __init__(self) -> None:
        self._checks: list[SentinelCheck] = []
        self._lock = RLock()

    def register(self, check: SentinelCheck) -> None:
        """
        Register or replace a sentinel check by name.
        """
        normalized_name = _normalize_identifier(check.check_name, label="check name")

        with self._lock:
            for index, existing in enumerate(self._checks):
                if existing.check_name.strip().lower() == normalized_name:
                    self._checks[index] = check
                    return
            self._checks.append(check)

    def unregister(self, check_name: str) -> bool:
        """
        Remove a sentinel check by name.
        """
        normalized_name = _normalize_identifier(check_name, label="check name")

        with self._lock:
            for index, check in enumerate(self._checks):
                if check.check_name.strip().lower() == normalized_name:
                    del self._checks[index]
                    return True
            return False

    def snapshot(self) -> SentinelSnapshot:
        """
        Return an immutable snapshot of registered sentinel checks.
        """
        with self._lock:
            names = tuple(check.check_name.strip().lower() for check in self._checks)
        return SentinelSnapshot(check_names=names)

    def evaluate(self, context: SentinelContext) -> SentinelReport:
        """
        Execute all registered checks and aggregate their issues.
        """
        with self._lock:
            checks = tuple(self._checks)

        issues: list[SentinelIssue] = []
        for check in checks:
            try:
                produced = check.evaluate(context)
            except Exception as exc:  # pragma: no cover - exercised in tests
                issues.append(
                    SentinelIssue(
                        code="sentinel.check_failed",
                        severity=SentinelSeverity.ERROR,
                        summary=(
                            f"Sentinel check '{check.check_name}' raised an exception."
                        ),
                        source=check.check_name,
                        details=str(exc),
                    )
                )
                continue

            issues.extend(produced)

        return SentinelReport(
            evaluated_at=_utc_now(),
            check_count=len(checks),
            issues=tuple(issues),
        )

    def clear(self) -> None:
        """
        Remove all registered checks.
        """
        with self._lock:
            self._checks.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Sentinel {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Sentinel {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
