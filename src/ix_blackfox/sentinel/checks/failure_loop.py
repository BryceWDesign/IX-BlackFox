from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Deque

from ix_blackfox.memory import TraceRecord
from ix_blackfox.sentinel.core import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelSeverity,
)


@dataclass(frozen=True, slots=True)
class FailureLoopWindow:
    """
    Configuration for failure-loop detection.

    Attributes
    ----------
    lookback_limit:
        Maximum number of relevant trace records to inspect.
    failure_levels:
        Trace levels considered failures.
    failure_stages:
        Optional stage filter for failure analysis.
    trigger_count:
        Minimum number of failures required to emit an issue.
    """

    lookback_limit: int = 10
    failure_levels: tuple[str, ...] = ("error", "critical")
    failure_stages: tuple[str, ...] = ()
    trigger_count: int = 3

    def __post_init__(self) -> None:
        if self.lookback_limit < 1:
            raise ValueError("Failure-loop lookback limit must be greater than or equal to 1.")
        if self.trigger_count < 2:
            raise ValueError("Failure-loop trigger count must be greater than or equal to 2.")

        normalized_levels = _normalize_identifiers(self.failure_levels, label="failure level")
        normalized_stages = _normalize_identifiers(self.failure_stages, label="failure stage")

        object.__setattr__(self, "failure_levels", normalized_levels)
        object.__setattr__(self, "failure_stages", normalized_stages)


class FailureLoopCheck(SentinelCheck):
    """
    Built-in check that detects repeated recent failure patterns.

    This check looks at recent trace records and emits an issue when the
    number of failure-level records within the configured window reaches
    the trigger threshold.
    """

    def __init__(self, *, window: FailureLoopWindow | None = None) -> None:
        self._window = window or FailureLoopWindow()

    @property
    def check_name(self) -> str:
        return "failure_loop"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        """
        Evaluate trace records for repeated recent failure activity.
        """
        relevant_records = self._collect_relevant_records(context.trace_records)
        failure_records = tuple(
            record
            for record in relevant_records
            if record.level.strip().lower() in self._window.failure_levels
        )

        if len(failure_records) < self._window.trigger_count:
            return ()

        correlation_ids = tuple(
            sorted({record.correlation_id for record in failure_records})
        )
        stages = tuple(sorted({record.stage for record in failure_records}))
        recent_messages = tuple(record.message for record in failure_records[-3:])

        return (
            SentinelIssue(
                code="runtime.failure_loop_detected",
                severity=SentinelSeverity.ERROR,
                summary="Repeated failure pattern detected in recent execution traces.",
                source=self.check_name,
                details=_build_details(
                    failure_count=len(failure_records),
                    stages=stages,
                    correlations=correlation_ids,
                ),
                data={
                    "failure_count": len(failure_records),
                    "trigger_count": self._window.trigger_count,
                    "stages": stages,
                    "correlation_ids": correlation_ids,
                    "recent_messages": recent_messages,
                    "lookback_limit": self._window.lookback_limit,
                },
            ),
        )

    def _collect_relevant_records(
        self,
        records: Iterable[TraceRecord],
    ) -> tuple[TraceRecord, ...]:
        recent: Deque[TraceRecord] = deque(maxlen=self._window.lookback_limit)

        for record in records:
            if self._window.failure_stages and record.stage not in self._window.failure_stages:
                continue
            recent.append(record)

        return tuple(recent)


def _build_details(
    *,
    failure_count: int,
    stages: tuple[str, ...],
    correlations: tuple[str, ...],
) -> str:
    stage_text = ", ".join(stages) if stages else "unknown"
    correlation_text = ", ".join(correlations) if correlations else "unknown"

    return (
        f"Observed {failure_count} recent failure traces across stages "
        f"[{stage_text}] for correlations [{correlation_text}]."
    )


def _normalize_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError(f"Failure-loop {label} must not be empty.")
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
