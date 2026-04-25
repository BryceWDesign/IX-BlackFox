from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum, StrEnum, auto
from typing import Any
from uuid import uuid4


class TaskKind(StrEnum):
    """
    High-level task categories understood by the BlackFox kernel.
    """

    UNKNOWN = auto()
    PROGRAMMING = auto()
    ARCHITECTURE = auto()
    ANALYSIS = auto()
    RESEARCH = auto()
    EVALUATION = auto()
    OPERATIONS = auto()


class TaskState(StrEnum):
    """
    Lifecycle states for a kernel task.
    """

    PENDING = auto()
    READY = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELED = auto()


class TaskPriority(IntEnum):
    """
    Relative scheduling priority for tasks.

    Lower numeric values represent higher urgency.
    """

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


@dataclass(frozen=True, slots=True)
class TaskInput:
    """
    Raw task intake payload.

    Attributes
    ----------
    prompt:
        Primary user or system instruction.
    metadata:
        Optional intake metadata.
    attachments:
        Optional logical attachment references.
    """

    prompt: str
    metadata: dict[str, Any] = field(default_factory=dict)
    attachments: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_prompt = self.prompt.strip()
        if not normalized_prompt:
            raise ValueError("TaskInput prompt must not be empty.")
        object.__setattr__(self, "prompt", normalized_prompt)


@dataclass(frozen=True, slots=True)
class TaskRequest:
    """
    Immutable task request submitted to the BlackFox kernel.

    Attributes
    ----------
    task_id:
        Stable unique task identifier.
    kind:
        Task category.
    priority:
        Requested scheduling priority.
    input:
        Raw intake payload.
    created_at:
        UTC creation timestamp.
    labels:
        Optional normalized labels for routing or bookkeeping.
    """

    task_id: str
    kind: TaskKind
    priority: TaskPriority
    input: TaskInput
    created_at: datetime
    labels: tuple[str, ...] = field(default_factory=tuple)

    @property
    def prompt(self) -> str:
        """
        Compatibility alias for the normalized task prompt.

        Runtime layers should prefer ``request.input.prompt`` in new code, but
        this read-only alias keeps existing orchestration, governance, and
        receipt code aligned with the canonical ``TaskInput`` payload.
        """
        return self.input.prompt

    @property
    def metadata(self) -> dict[str, Any]:
        """
        Compatibility alias for task intake metadata.

        ``TaskRequest`` stores metadata on ``input.metadata``. Returning a copy
        prevents callers from mutating the frozen task request through the
        nested dictionary while preserving legacy ``request.metadata`` access.
        """
        return dict(self.input.metadata)

    @property
    def attachments(self) -> tuple[str, ...]:
        """
        Compatibility alias for logical task attachment references.
        """
        return self.input.attachments

    @classmethod
    def create(
        cls,
        *,
        prompt: str,
        kind: TaskKind = TaskKind.UNKNOWN,
        priority: TaskPriority = TaskPriority.NORMAL,
        metadata: dict[str, Any] | None = None,
        attachments: tuple[str, ...] | None = None,
        labels: tuple[str, ...] | None = None,
    ) -> TaskRequest:
        """
        Construct a new task request with normalized defaults.
        """
        return cls(
            task_id=f"task-{uuid4().hex}",
            kind=kind,
            priority=priority,
            input=TaskInput(
                prompt=prompt,
                metadata=dict(metadata or {}),
                attachments=tuple(attachments or ()),
            ),
            created_at=_utc_now(),
            labels=_normalize_labels(labels or ()),
        )


@dataclass(frozen=True, slots=True)
class TaskRecord:
    """
    Mutable-state snapshot represented immutably.

    This record is what the kernel can pass between subsystems without
    exposing partially-mutated objects.

    Attributes
    ----------
    request:
        Original task request.
    state:
        Current lifecycle state.
    started_at:
        UTC timestamp when execution began.
    finished_at:
        UTC timestamp when execution ended.
    error:
        Failure message when state is FAILED.
    result_summary:
        Short outcome summary suitable for logs or traces.
    """

    request: TaskRequest
    state: TaskState = TaskState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    result_summary: str | None = None

    def mark_ready(self) -> TaskRecord:
        """
        Mark a pending task as ready for execution.
        """
        self._assert_transition_allowed({TaskState.PENDING}, TaskState.READY)
        return replace(self, state=TaskState.READY)

    def mark_running(self) -> TaskRecord:
        """
        Mark a task as running and stamp its start time.
        """
        self._assert_transition_allowed(
            {TaskState.PENDING, TaskState.READY},
            TaskState.RUNNING,
        )
        return replace(
            self,
            state=TaskState.RUNNING,
            started_at=self.started_at or _utc_now(),
            finished_at=None,
            error=None,
        )

    def mark_completed(self, *, result_summary: str | None = None) -> TaskRecord:
        """
        Mark a running task as completed.
        """
        self._assert_transition_allowed({TaskState.RUNNING}, TaskState.COMPLETED)
        return replace(
            self,
            state=TaskState.COMPLETED,
            finished_at=_utc_now(),
            error=None,
            result_summary=_normalize_optional_text(result_summary),
        )

    def mark_failed(self, *, error: str) -> TaskRecord:
        """
        Mark a running task as failed.
        """
        self._assert_transition_allowed({TaskState.RUNNING}, TaskState.FAILED)

        normalized_error = error.strip()
        if not normalized_error:
            raise ValueError("Task failure error message must not be empty.")

        return replace(
            self,
            state=TaskState.FAILED,
            finished_at=_utc_now(),
            error=normalized_error,
        )

    def mark_canceled(self, *, reason: str | None = None) -> TaskRecord:
        """
        Cancel a task before or during execution.
        """
        self._assert_transition_allowed(
            {TaskState.PENDING, TaskState.READY, TaskState.RUNNING},
            TaskState.CANCELED,
        )
        return replace(
            self,
            state=TaskState.CANCELED,
            finished_at=_utc_now(),
            result_summary=_normalize_optional_text(reason),
        )

    def _assert_transition_allowed(
        self,
        allowed_from: set[TaskState],
        target: TaskState,
    ) -> None:
        if self.state not in allowed_from:
            allowed = ", ".join(sorted(state.value for state in allowed_from))
            raise RuntimeError(
                f"Cannot transition task from {self.state.value!r} "
                f"to {target.value!r}. Allowed from: {allowed}."
            )


def _normalize_labels(labels: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_label in labels:
        cleaned = raw_label.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
