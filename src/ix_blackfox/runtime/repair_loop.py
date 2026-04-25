from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchDiff,
    ToolInvocationResult,
    ToolInvocationStatus,
)


class RepairLoopStatus(StrEnum):
    """
    High-level lifecycle state for a bounded programming repair loop.
    """

    READY = auto()
    RUNNING = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    BLOCKED = auto()
    EXHAUSTED = auto()


class RepairLoopAttemptStatus(StrEnum):
    """
    Lifecycle state for one patch/test attempt inside the repair loop.
    """

    PLANNED = auto()
    PATCH_APPLIED = auto()
    PATCH_FAILED = auto()
    TEST_PASSED = auto()
    TEST_FAILED = auto()
    BLOCKED = auto()


class RepairLoopTerminalReason(StrEnum):
    """
    Terminal reason for a repair loop that should no longer continue.
    """

    TESTS_PASSED = auto()
    PATCH_BLOCKED = auto()
    PATCH_FAILED = auto()
    TEST_COMMAND_BLOCKED = auto()
    TEST_COMMAND_FAILED = auto()
    MAX_ATTEMPTS_EXHAUSTED = auto()
    OPERATOR_STOPPED = auto()


class RepairLoopFindingSeverity(StrEnum):
    """
    Severity for repair-loop findings.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class RepairLoopConfig:
    """
    Configuration for a bounded programming repair loop.

    The conservative default allows two repair attempts after the initial patch
    proposal. This prevents infinite self-repair behavior and keeps autonomous
    mutation bounded by explicit operator policy.
    """

    max_attempts: int = 3
    stop_on_blocked_patch: bool = True
    stop_on_test_command_blocked: bool = True
    require_test_success_for_completion: bool = True

    def __post_init__(self) -> None:
        if self.max_attempts <= 0:
            raise ValueError("RepairLoopConfig max_attempts must be positive.")
        if self.max_attempts > 10:
            raise ValueError("RepairLoopConfig max_attempts must not exceed 10.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attempts": self.max_attempts,
            "stop_on_blocked_patch": self.stop_on_blocked_patch,
            "stop_on_test_command_blocked": self.stop_on_test_command_blocked,
            "require_test_success_for_completion": (
                self.require_test_success_for_completion
            ),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            max_attempts=int(payload.get("max_attempts", 3)),
            stop_on_blocked_patch=bool(payload.get("stop_on_blocked_patch", True)),
            stop_on_test_command_blocked=bool(
                payload.get("stop_on_test_command_blocked", True)
            ),
            require_test_success_for_completion=bool(
                payload.get("require_test_success_for_completion", True)
            ),
        )


@dataclass(frozen=True, slots=True)
class RepairLoopFinding:
    """
    One structured finding emitted by the repair loop model.
    """

    code: str
    severity: RepairLoopFindingSeverity
    summary: str
    attempt_index: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.attempt_index is not None and self.attempt_index <= 0:
            raise ValueError("RepairLoopFinding attempt_index must be positive.")
        if self.created_at.tzinfo is None:
            raise ValueError("RepairLoopFinding created_at must be timezone-aware.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "attempt_index": self.attempt_index,
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        created_at = payload.get("created_at")
        return cls(
            code=_require_text(payload, "code"),
            severity=RepairLoopFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            attempt_index=(
                int(payload["attempt_index"])
                if payload.get("attempt_index") is not None
                else None
            ),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
            created_at=(
                _parse_datetime(created_at)
                if isinstance(created_at, str)
                else datetime.now(tz=UTC)
            ),
        )


@dataclass(frozen=True, slots=True)
class RepairLoopAttempt:
    """
    One patch/test attempt inside a bounded repair loop.
    """

    attempt_id: str
    attempt_index: int
    patch_diff: PatchDiff
    patch_result: ToolInvocationResult | None = None
    parsed_test_run: ParsedTestRun | None = None
    test_result: ToolInvocationResult | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attempt_id",
            _normalize_identifier(self.attempt_id, label="attempt_id"),
        )
        object.__setattr__(self, "notes", _normalize_notes(self.notes))

        if self.attempt_index <= 0:
            raise ValueError("RepairLoopAttempt attempt_index must be positive.")
        if self.created_at.tzinfo is None:
            raise ValueError("RepairLoopAttempt created_at must be timezone-aware.")
        if self.updated_at.tzinfo is None:
            raise ValueError("RepairLoopAttempt updated_at must be timezone-aware.")
        if self.updated_at < self.created_at:
            raise ValueError("RepairLoopAttempt updated_at cannot predate created_at.")

    @classmethod
    def create(
        cls,
        *,
        attempt_index: int,
        patch_diff: PatchDiff,
        notes: tuple[str, ...] | None = None,
    ) -> Self:
        return cls(
            attempt_id=f"repair-attempt-{uuid4().hex}",
            attempt_index=attempt_index,
            patch_diff=patch_diff,
            notes=tuple(notes or ()),
            created_at=datetime.now(tz=UTC),
            updated_at=datetime.now(tz=UTC),
        )

    @property
    def status(self) -> RepairLoopAttemptStatus:
        if self.patch_result is None:
            return RepairLoopAttemptStatus.PLANNED

        if self.patch_result.status is ToolInvocationStatus.BLOCKED:
            return RepairLoopAttemptStatus.BLOCKED

        if self.patch_result.status is not ToolInvocationStatus.SUCCEEDED:
            return RepairLoopAttemptStatus.PATCH_FAILED

        if self.parsed_test_run is None:
            return RepairLoopAttemptStatus.PATCH_APPLIED

        if self.parsed_test_run.status is ParsedTestRunStatus.PASSED:
            return RepairLoopAttemptStatus.TEST_PASSED

        if self.parsed_test_run.status in {
            ParsedTestRunStatus.FAILED,
            ParsedTestRunStatus.ERRORED,
            ParsedTestRunStatus.TIMED_OUT,
            ParsedTestRunStatus.NO_TESTS,
            ParsedTestRunStatus.UNKNOWN,
        }:
            return RepairLoopAttemptStatus.TEST_FAILED

        return RepairLoopAttemptStatus.TEST_FAILED

    @property
    def succeeded(self) -> bool:
        return self.status is RepairLoopAttemptStatus.TEST_PASSED

    @property
    def failed_or_blocked(self) -> bool:
        return self.status in {
            RepairLoopAttemptStatus.PATCH_FAILED,
            RepairLoopAttemptStatus.TEST_FAILED,
            RepairLoopAttemptStatus.BLOCKED,
        }

    def with_patch_result(self, result: ToolInvocationResult) -> RepairLoopAttempt:
        return replace(
            self,
            patch_result=result,
            updated_at=datetime.now(tz=UTC),
        )

    def with_test_result(
        self,
        *,
        result: ToolInvocationResult,
        parsed_test_run: ParsedTestRun,
    ) -> RepairLoopAttempt:
        return replace(
            self,
            test_result=result,
            parsed_test_run=parsed_test_run,
            updated_at=datetime.now(tz=UTC),
        )

    def with_note(self, note: str) -> RepairLoopAttempt:
        return replace(
            self,
            notes=(*self.notes, _normalize_text(note, label="note")),
            updated_at=datetime.now(tz=UTC),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "attempt_index": self.attempt_index,
            "status": self.status.value,
            "patch_diff": self.patch_diff.to_dict(),
            "patch_result": (
                self.patch_result.to_dict() if self.patch_result is not None else None
            ),
            "test_result": (
                self.test_result.to_dict() if self.test_result is not None else None
            ),
            "parsed_test_run": (
                self.parsed_test_run.to_dict()
                if self.parsed_test_run is not None
                else None
            ),
            "notes": list(self.notes),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        patch_payload = payload.get("patch_diff")
        if not isinstance(patch_payload, Mapping):
            raise TypeError("patch_diff must be a mapping.")

        patch_result_payload = payload.get("patch_result")
        test_result_payload = payload.get("test_result")
        parsed_test_run_payload = payload.get("parsed_test_run")

        return cls(
            attempt_id=_require_text(payload, "attempt_id"),
            attempt_index=int(payload.get("attempt_index", 0)),
            patch_diff=PatchDiff.from_dict(patch_payload),
            patch_result=(
                ToolInvocationResult.from_dict(patch_result_payload)
                if isinstance(patch_result_payload, Mapping)
                else None
            ),
            test_result=(
                ToolInvocationResult.from_dict(test_result_payload)
                if isinstance(test_result_payload, Mapping)
                else None
            ),
            parsed_test_run=(
                ParsedTestRun.from_dict(parsed_test_run_payload)
                if isinstance(parsed_test_run_payload, Mapping)
                else None
            ),
            notes=tuple(_coerce_string_list(payload.get("notes", ()), field_name="notes")),
            created_at=_parse_datetime(_require_text(payload, "created_at")),
            updated_at=_parse_datetime(_require_text(payload, "updated_at")),
        )


@dataclass(frozen=True, slots=True)
class RepairLoopState:
    """
    Immutable state model for the governed patch-test-repair loop.

    This state object records attempts and terminal decisions. The actual tool
    calls happen in later runtime integration; this model keeps the loop bounded,
    replayable, and auditable.
    """

    loop_id: str
    task_id: str
    run_id: str
    objective: str
    config: RepairLoopConfig = field(default_factory=RepairLoopConfig)
    status: RepairLoopStatus = RepairLoopStatus.READY
    attempts: tuple[RepairLoopAttempt, ...] = field(default_factory=tuple)
    findings: tuple[RepairLoopFinding, ...] = field(default_factory=tuple)
    terminal_reason: RepairLoopTerminalReason | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "loop_id",
            _normalize_identifier(self.loop_id, label="loop_id"),
        )
        object.__setattr__(
            self,
            "task_id",
            _normalize_identifier(self.task_id, label="task_id"),
        )
        object.__setattr__(
            self,
            "run_id",
            _normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(
            self,
            "objective",
            _normalize_text(self.objective, label="objective"),
        )
        object.__setattr__(self, "attempts", tuple(self.attempts))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.created_at.tzinfo is None:
            raise ValueError("RepairLoopState created_at must be timezone-aware.")
        if self.updated_at.tzinfo is None:
            raise ValueError("RepairLoopState updated_at must be timezone-aware.")
        if self.updated_at < self.created_at:
            raise ValueError("RepairLoopState updated_at cannot predate created_at.")

        attempt_indexes = [attempt.attempt_index for attempt in self.attempts]
        if attempt_indexes != sorted(attempt_indexes):
            raise ValueError("RepairLoopState attempts must be ordered by attempt_index.")
        if len(set(attempt_indexes)) != len(attempt_indexes):
            raise ValueError("RepairLoopState cannot contain duplicate attempt indexes.")

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        run_id: str,
        objective: str,
        config: RepairLoopConfig | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            loop_id=f"repair-loop-{uuid4().hex}",
            task_id=task_id,
            run_id=run_id,
            objective=objective,
            config=config or RepairLoopConfig(),
            status=RepairLoopStatus.READY,
            attempts=(),
            findings=(),
            terminal_reason=None,
            created_at=datetime.now(tz=UTC),
            updated_at=datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )

    @property
    def attempts_used(self) -> int:
        return len(self.attempts)

    @property
    def attempts_remaining(self) -> int:
        return max(self.config.max_attempts - self.attempts_used, 0)

    @property
    def latest_attempt(self) -> RepairLoopAttempt | None:
        if not self.attempts:
            return None
        return self.attempts[-1]

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            RepairLoopStatus.SUCCEEDED,
            RepairLoopStatus.FAILED,
            RepairLoopStatus.BLOCKED,
            RepairLoopStatus.EXHAUSTED,
        }

    @property
    def can_start_attempt(self) -> bool:
        if self.is_terminal:
            return False
        if self.attempts_remaining <= 0:
            return False
        latest = self.latest_attempt
        if latest is None:
            return True
        return latest.status in {
            RepairLoopAttemptStatus.TEST_FAILED,
            RepairLoopAttemptStatus.PATCH_FAILED,
        }

    @property
    def should_continue(self) -> bool:
        if self.is_terminal:
            return False
        latest = self.latest_attempt
        if latest is None:
            return self.attempts_remaining > 0
        return latest.status is RepairLoopAttemptStatus.TEST_FAILED and self.attempts_remaining > 0

    def start_attempt(
        self,
        *,
        patch_diff: PatchDiff,
        notes: tuple[str, ...] | None = None,
    ) -> RepairLoopState:
        if not self.can_start_attempt:
            raise RuntimeError("Repair loop cannot start another attempt.")

        attempt = RepairLoopAttempt.create(
            attempt_index=self.attempts_used + 1,
            patch_diff=patch_diff,
            notes=notes,
        )

        return replace(
            self,
            status=RepairLoopStatus.RUNNING,
            attempts=(*self.attempts, attempt),
            updated_at=datetime.now(tz=UTC),
        )

    def attach_patch_result(
        self,
        *,
        attempt_id: str,
        result: ToolInvocationResult,
    ) -> RepairLoopState:
        attempt = self._require_latest_attempt(attempt_id)
        updated_attempt = attempt.with_patch_result(result)
        updated_state = self._replace_latest_attempt(updated_attempt)

        if result.status is ToolInvocationStatus.SUCCEEDED:
            return updated_state

        if result.status is ToolInvocationStatus.BLOCKED and self.config.stop_on_blocked_patch:
            return updated_state._terminal(
                status=RepairLoopStatus.BLOCKED,
                reason=RepairLoopTerminalReason.PATCH_BLOCKED,
                finding=RepairLoopFinding(
                    code="repair.patch_blocked",
                    severity=RepairLoopFindingSeverity.ERROR,
                    summary="Patch application was blocked by tool policy or path safety.",
                    attempt_index=attempt.attempt_index,
                    metadata={"tool_status": result.status.value},
                ),
            )

        return updated_state._terminal(
            status=RepairLoopStatus.FAILED,
            reason=RepairLoopTerminalReason.PATCH_FAILED,
            finding=RepairLoopFinding(
                code="repair.patch_failed",
                severity=RepairLoopFindingSeverity.ERROR,
                summary="Patch application failed before tests could run.",
                attempt_index=attempt.attempt_index,
                metadata={"tool_status": result.status.value},
            ),
        )

    def attach_test_result(
        self,
        *,
        attempt_id: str,
        result: ToolInvocationResult,
        parsed_test_run: ParsedTestRun,
    ) -> RepairLoopState:
        attempt = self._require_latest_attempt(attempt_id)
        updated_attempt = attempt.with_test_result(
            result=result,
            parsed_test_run=parsed_test_run,
        )
        updated_state = self._replace_latest_attempt(updated_attempt)

        if parsed_test_run.status is ParsedTestRunStatus.PASSED:
            return updated_state._terminal(
                status=RepairLoopStatus.SUCCEEDED,
                reason=RepairLoopTerminalReason.TESTS_PASSED,
                finding=RepairLoopFinding(
                    code="repair.tests_passed",
                    severity=RepairLoopFindingSeverity.INFO,
                    summary="Repair loop completed because the test suite passed.",
                    attempt_index=attempt.attempt_index,
                    metadata={
                        "passed": parsed_test_run.passed,
                        "duration_seconds": parsed_test_run.duration_seconds,
                    },
                ),
            )

        if (
            result.status is ToolInvocationStatus.BLOCKED
            and self.config.stop_on_test_command_blocked
        ):
            return updated_state._terminal(
                status=RepairLoopStatus.BLOCKED,
                reason=RepairLoopTerminalReason.TEST_COMMAND_BLOCKED,
                finding=RepairLoopFinding(
                    code="repair.test_command_blocked",
                    severity=RepairLoopFindingSeverity.ERROR,
                    summary="Test execution was blocked by policy or workspace safety.",
                    attempt_index=attempt.attempt_index,
                    metadata={"tool_status": result.status.value},
                ),
            )

        failed_state = updated_state.with_finding(
            RepairLoopFinding(
                code="repair.tests_failed",
                severity=RepairLoopFindingSeverity.WARNING,
                summary="Repair attempt did not satisfy the test suite.",
                attempt_index=attempt.attempt_index,
                metadata={
                    "test_status": parsed_test_run.status.value,
                    "failed": parsed_test_run.failed,
                    "errors": parsed_test_run.errors,
                    "failing_outcomes": parsed_test_run.failing_outcomes,
                    "finding_codes": list(parsed_test_run.finding_codes),
                },
            )
        )

        if failed_state.attempts_remaining <= 0:
            return failed_state._terminal(
                status=RepairLoopStatus.EXHAUSTED,
                reason=RepairLoopTerminalReason.MAX_ATTEMPTS_EXHAUSTED,
                finding=RepairLoopFinding(
                    code="repair.max_attempts_exhausted",
                    severity=RepairLoopFindingSeverity.ERROR,
                    summary="Repair loop exhausted the configured attempt budget.",
                    attempt_index=attempt.attempt_index,
                    metadata={"max_attempts": self.config.max_attempts},
                ),
            )

        return failed_state

    def stop_by_operator(self, *, reason: str) -> RepairLoopState:
        return self._terminal(
            status=RepairLoopStatus.FAILED,
            reason=RepairLoopTerminalReason.OPERATOR_STOPPED,
            finding=RepairLoopFinding(
                code="repair.operator_stopped",
                severity=RepairLoopFindingSeverity.WARNING,
                summary=_normalize_text(reason, label="reason"),
            ),
        )

    def with_finding(self, finding: RepairLoopFinding) -> RepairLoopState:
        return replace(
            self,
            findings=(*self.findings, finding),
            updated_at=datetime.now(tz=UTC),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "objective": self.objective,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "attempts_used": self.attempts_used,
            "attempts_remaining": self.attempts_remaining,
            "terminal_reason": (
                self.terminal_reason.value if self.terminal_reason is not None else None
            ),
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "findings": [finding.to_dict() for finding in self.findings],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_config = payload.get("config", {})
        raw_attempts = payload.get("attempts", ())
        raw_findings = payload.get("findings", ())

        if not isinstance(raw_config, Mapping):
            raise TypeError("config must be a mapping.")
        if not isinstance(raw_attempts, Iterable) or isinstance(raw_attempts, str):
            raise TypeError("attempts must be an iterable of mappings.")
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        attempts: list[RepairLoopAttempt] = []
        for raw_attempt in raw_attempts:
            if not isinstance(raw_attempt, Mapping):
                raise TypeError("attempts must contain only mappings.")
            attempts.append(RepairLoopAttempt.from_dict(raw_attempt))

        findings: list[RepairLoopFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(RepairLoopFinding.from_dict(raw_finding))

        terminal_reason = payload.get("terminal_reason")

        return cls(
            loop_id=_require_text(payload, "loop_id"),
            task_id=_require_text(payload, "task_id"),
            run_id=_require_text(payload, "run_id"),
            objective=_require_text(payload, "objective"),
            config=RepairLoopConfig.from_dict(raw_config),
            status=RepairLoopStatus(_require_text(payload, "status")),
            attempts=tuple(attempts),
            findings=tuple(findings),
            terminal_reason=(
                RepairLoopTerminalReason(terminal_reason)
                if isinstance(terminal_reason, str)
                else None
            ),
            created_at=_parse_datetime(_require_text(payload, "created_at")),
            updated_at=_parse_datetime(_require_text(payload, "updated_at")),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )

    def _require_latest_attempt(self, attempt_id: str) -> RepairLoopAttempt:
        latest = self.latest_attempt
        if latest is None:
            raise RuntimeError("Repair loop has no active attempt.")

        normalized_attempt_id = _normalize_identifier(attempt_id, label="attempt_id")
        if latest.attempt_id != normalized_attempt_id:
            raise RuntimeError(
                "Repair loop only allows updating the latest active attempt."
            )

        return latest

    def _replace_latest_attempt(
        self,
        updated_attempt: RepairLoopAttempt,
    ) -> RepairLoopState:
        if not self.attempts:
            raise RuntimeError("Repair loop has no attempts to replace.")

        return replace(
            self,
            attempts=(*self.attempts[:-1], updated_attempt),
            updated_at=datetime.now(tz=UTC),
        )

    def _terminal(
        self,
        *,
        status: RepairLoopStatus,
        reason: RepairLoopTerminalReason,
        finding: RepairLoopFinding,
    ) -> RepairLoopState:
        return replace(
            self,
            status=status,
            terminal_reason=reason,
            findings=(*self.findings, finding),
            updated_at=datetime.now(tz=UTC),
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


def _normalize_notes(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        normalized.append(_normalize_text(value, label="note"))
    return tuple(normalized)


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


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Serialized datetimes must be timezone-aware.")
    return parsed
