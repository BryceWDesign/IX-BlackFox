from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from threading import RLock
from typing import Any
from uuid import uuid4

from ix_blackfox.runtime.repair_loop import (
    RepairLoopState,
    RepairLoopStatus,
    RepairLoopTerminalReason,
)
from ix_blackfox.tools.contracts import ToolInvocationResult
from ix_blackfox.tools.patch import PatchDiff
from ix_blackfox.tools.test_results import ParsedTestRun


class RepairLoopReceiptEventType(StrEnum):
    """
    Canonical receipt events for the governed programming repair loop.
    """

    LOOP_STARTED = auto()
    ATTEMPT_STARTED = auto()
    PATCH_RESULT_RECORDED = auto()
    TEST_RESULT_RECORDED = auto()
    LOOP_TERMINATED = auto()
    FAILURE_RECORDED = auto()


@dataclass(frozen=True, slots=True)
class RepairLoopReceipt:
    """
    Tamper-evident receipt for one repair-loop event.

    Repair-loop receipts are intentionally separate from tool receipts. Tool
    receipts prove what a tool did. Repair-loop receipts prove why the bounded
    patch/test loop continued, stopped, succeeded, failed, or blocked.
    """

    receipt_id: str
    loop_id: str
    task_id: str
    run_id: str
    event_type: RepairLoopReceiptEventType
    summary: str
    previous_receipt_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    status: RepairLoopStatus | None = None
    terminal_reason: RepairLoopTerminalReason | None = None
    attempt_id: str | None = None
    attempt_index: int | None = None
    patch_id: str | None = None
    tool_invocation_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_identifier(self.receipt_id, label="receipt_id"),
        )
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
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "attempt_id", _normalize_optional_identifier(self.attempt_id))
        object.__setattr__(self, "patch_id", _normalize_optional_identifier(self.patch_id))
        object.__setattr__(
            self,
            "tool_invocation_id",
            _normalize_optional_identifier(self.tool_invocation_id),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.created_at.tzinfo is None:
            raise ValueError("RepairLoopReceipt created_at must be timezone-aware.")
        if self.attempt_index is not None and self.attempt_index <= 0:
            raise ValueError("RepairLoopReceipt attempt_index must be positive.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "loop_id": self.loop_id,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "event_type": self.event_type.value,
            "summary": self.summary,
            "previous_receipt_id": self.previous_receipt_id,
            "previous_chain_digest": self.previous_chain_digest,
            "chain_digest": self.chain_digest,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value if self.status is not None else None,
            "terminal_reason": (
                self.terminal_reason.value if self.terminal_reason is not None else None
            ),
            "attempt_id": self.attempt_id,
            "attempt_index": self.attempt_index,
            "patch_id": self.patch_id,
            "tool_invocation_id": self.tool_invocation_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RepairLoopReceiptSnapshot:
    """
    Immutable view of repair-loop receipts.
    """

    receipts: tuple[RepairLoopReceipt, ...]

    def filter_by_loop(self, loop_id: str) -> tuple[RepairLoopReceipt, ...]:
        normalized_loop_id = _normalize_identifier(loop_id, label="loop_id")
        return tuple(receipt for receipt in self.receipts if receipt.loop_id == normalized_loop_id)

    def filter_by_run(self, run_id: str) -> tuple[RepairLoopReceipt, ...]:
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        return tuple(receipt for receipt in self.receipts if receipt.run_id == normalized_run_id)

    def filter_by_task(self, task_id: str) -> tuple[RepairLoopReceipt, ...]:
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        return tuple(receipt for receipt in self.receipts if receipt.task_id == normalized_task_id)

    def latest_for_loop(self, loop_id: str) -> RepairLoopReceipt | None:
        receipts = self.filter_by_loop(loop_id)
        if not receipts:
            return None
        return receipts[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_count": len(self.receipts),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }


class RepairLoopReceiptLedger:
    """
    Thread-safe chained receipt ledger for repair-loop decisions.

    The ledger records bounded-loop control decisions:
    - loop start
    - attempt start
    - patch result
    - test result
    - terminal stop condition
    - explicit failure receipt
    """

    def __init__(self) -> None:
        self._receipts: list[RepairLoopReceipt] = []
        self._lock = RLock()

    def record_loop_started(self, *, state: RepairLoopState) -> RepairLoopReceipt:
        return self.append(
            loop_id=state.loop_id,
            task_id=state.task_id,
            run_id=state.run_id,
            event_type=RepairLoopReceiptEventType.LOOP_STARTED,
            summary="Governed programming repair loop started.",
            status=state.status,
            metadata={
                "objective": state.objective,
                "config": state.config.to_dict(),
                "attempts_remaining": state.attempts_remaining,
            },
        )

    def record_attempt_started(
        self,
        *,
        state: RepairLoopState,
        patch_diff: PatchDiff,
    ) -> RepairLoopReceipt:
        attempt = state.latest_attempt
        if attempt is None:
            raise RuntimeError("Cannot record attempt start without an active attempt.")

        return self.append(
            loop_id=state.loop_id,
            task_id=state.task_id,
            run_id=state.run_id,
            event_type=RepairLoopReceiptEventType.ATTEMPT_STARTED,
            summary=f"Repair attempt {attempt.attempt_index} started.",
            status=state.status,
            attempt_id=attempt.attempt_id,
            attempt_index=attempt.attempt_index,
            patch_id=patch_diff.patch_id,
            metadata={
                "patch_digest": patch_diff.digest,
                "changed_paths": list(patch_diff.changed_paths),
                "file_count": patch_diff.file_count,
                "attempts_remaining": state.attempts_remaining,
            },
        )

    def record_patch_result(
        self,
        *,
        state: RepairLoopState,
        result: ToolInvocationResult,
    ) -> RepairLoopReceipt:
        attempt = state.latest_attempt
        if attempt is None:
            raise RuntimeError("Cannot record patch result without an active attempt.")

        event_type = (
            RepairLoopReceiptEventType.FAILURE_RECORDED
            if result.status.value != "succeeded"
            else RepairLoopReceiptEventType.PATCH_RESULT_RECORDED
        )

        return self.append(
            loop_id=state.loop_id,
            task_id=state.task_id,
            run_id=state.run_id,
            event_type=event_type,
            summary=f"Patch result recorded for attempt {attempt.attempt_index}.",
            status=state.status,
            terminal_reason=state.terminal_reason,
            attempt_id=attempt.attempt_id,
            attempt_index=attempt.attempt_index,
            patch_id=attempt.patch_diff.patch_id,
            tool_invocation_id=result.invocation_id,
            metadata={
                "tool_id": result.tool_id,
                "tool_status": result.status.value,
                "failure": result.failure.to_dict() if result.failure else None,
                "output_keys": sorted(str(key) for key in result.output.keys()),
                "artifact_count": len(result.artifacts),
            },
        )

    def record_test_result(
        self,
        *,
        state: RepairLoopState,
        result: ToolInvocationResult,
        parsed_test_run: ParsedTestRun,
    ) -> RepairLoopReceipt:
        attempt = state.latest_attempt
        if attempt is None:
            raise RuntimeError("Cannot record test result without an active attempt.")

        event_type = (
            RepairLoopReceiptEventType.TEST_RESULT_RECORDED
            if parsed_test_run.succeeded
            else RepairLoopReceiptEventType.FAILURE_RECORDED
        )

        return self.append(
            loop_id=state.loop_id,
            task_id=state.task_id,
            run_id=state.run_id,
            event_type=event_type,
            summary=f"Test result recorded for attempt {attempt.attempt_index}.",
            status=state.status,
            terminal_reason=state.terminal_reason,
            attempt_id=attempt.attempt_id,
            attempt_index=attempt.attempt_index,
            patch_id=attempt.patch_diff.patch_id,
            tool_invocation_id=result.invocation_id,
            metadata={
                "tool_id": result.tool_id,
                "tool_status": result.status.value,
                "test_status": parsed_test_run.status.value,
                "passed": parsed_test_run.passed,
                "failed": parsed_test_run.failed,
                "errors": parsed_test_run.errors,
                "failing_outcomes": parsed_test_run.failing_outcomes,
                "finding_codes": list(parsed_test_run.finding_codes),
                "artifact_count": len(result.artifacts),
            },
        )

    def record_loop_terminated(self, *, state: RepairLoopState) -> RepairLoopReceipt:
        if state.terminal_reason is None:
            raise RuntimeError("Cannot record loop termination without terminal_reason.")

        return self.append(
            loop_id=state.loop_id,
            task_id=state.task_id,
            run_id=state.run_id,
            event_type=RepairLoopReceiptEventType.LOOP_TERMINATED,
            summary=(
                "Governed programming repair loop terminated with reason "
                f"'{state.terminal_reason.value}'."
            ),
            status=state.status,
            terminal_reason=state.terminal_reason,
            metadata={
                "attempts_used": state.attempts_used,
                "attempts_remaining": state.attempts_remaining,
                "finding_codes": [finding.code for finding in state.findings],
            },
        )

    def append(
        self,
        *,
        loop_id: str,
        task_id: str,
        run_id: str,
        event_type: RepairLoopReceiptEventType,
        summary: str,
        status: RepairLoopStatus | None = None,
        terminal_reason: RepairLoopTerminalReason | None = None,
        attempt_id: str | None = None,
        attempt_index: int | None = None,
        patch_id: str | None = None,
        tool_invocation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> RepairLoopReceipt:
        normalized_loop_id = _normalize_identifier(loop_id, label="loop_id")
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        normalized_summary = _normalize_text(summary, label="summary")
        normalized_attempt_id = _normalize_optional_identifier(attempt_id)
        normalized_patch_id = _normalize_optional_identifier(patch_id)
        normalized_tool_invocation_id = _normalize_optional_identifier(tool_invocation_id)
        normalized_metadata = dict(metadata or {})

        with self._lock:
            previous = self._latest_for_loop_unlocked(normalized_loop_id)
            previous_receipt_id = None if previous is None else previous.receipt_id
            previous_chain_digest = None if previous is None else previous.chain_digest

            receipt_id = f"repair-receipt-{uuid4().hex}"
            created_at = datetime.now(tz=UTC)
            chain_digest = _compute_chain_digest(
                receipt_id=receipt_id,
                loop_id=normalized_loop_id,
                task_id=normalized_task_id,
                run_id=normalized_run_id,
                event_type=event_type.value,
                summary=normalized_summary,
                previous_chain_digest=previous_chain_digest,
                status=status.value if status is not None else None,
                terminal_reason=(
                    terminal_reason.value if terminal_reason is not None else None
                ),
                attempt_id=normalized_attempt_id,
                attempt_index=attempt_index,
                patch_id=normalized_patch_id,
                tool_invocation_id=normalized_tool_invocation_id,
                metadata=normalized_metadata,
            )

            receipt = RepairLoopReceipt(
                receipt_id=receipt_id,
                loop_id=normalized_loop_id,
                task_id=normalized_task_id,
                run_id=normalized_run_id,
                event_type=event_type,
                summary=normalized_summary,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=chain_digest,
                created_at=created_at,
                status=status,
                terminal_reason=terminal_reason,
                attempt_id=normalized_attempt_id,
                attempt_index=attempt_index,
                patch_id=normalized_patch_id,
                tool_invocation_id=normalized_tool_invocation_id,
                metadata=normalized_metadata,
            )
            self._receipts.append(receipt)
            return receipt

    def snapshot(self) -> RepairLoopReceiptSnapshot:
        with self._lock:
            receipts = tuple(self._receipts)
        return RepairLoopReceiptSnapshot(receipts=receipts)

    def verify_loop_chain(self, loop_id: str) -> bool:
        normalized_loop_id = _normalize_identifier(loop_id, label="loop_id")

        with self._lock:
            receipts = [
                receipt for receipt in self._receipts if receipt.loop_id == normalized_loop_id
            ]

        previous_receipt: RepairLoopReceipt | None = None
        for receipt in receipts:
            expected_previous_receipt_id = (
                None if previous_receipt is None else previous_receipt.receipt_id
            )
            expected_previous_chain_digest = (
                None if previous_receipt is None else previous_receipt.chain_digest
            )

            if receipt.previous_receipt_id != expected_previous_receipt_id:
                return False
            if receipt.previous_chain_digest != expected_previous_chain_digest:
                return False

            expected_digest = _compute_chain_digest(
                receipt_id=receipt.receipt_id,
                loop_id=receipt.loop_id,
                task_id=receipt.task_id,
                run_id=receipt.run_id,
                event_type=receipt.event_type.value,
                summary=receipt.summary,
                previous_chain_digest=receipt.previous_chain_digest,
                status=receipt.status.value if receipt.status is not None else None,
                terminal_reason=(
                    receipt.terminal_reason.value
                    if receipt.terminal_reason is not None
                    else None
                ),
                attempt_id=receipt.attempt_id,
                attempt_index=receipt.attempt_index,
                patch_id=receipt.patch_id,
                tool_invocation_id=receipt.tool_invocation_id,
                metadata=dict(receipt.metadata),
            )
            if receipt.chain_digest != expected_digest:
                return False

            previous_receipt = receipt

        return True

    def count(self) -> int:
        with self._lock:
            return len(self._receipts)

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()

    def _latest_for_loop_unlocked(self, loop_id: str) -> RepairLoopReceipt | None:
        for receipt in reversed(self._receipts):
            if receipt.loop_id == loop_id:
                return receipt
        return None


def _compute_chain_digest(
    *,
    receipt_id: str,
    loop_id: str,
    task_id: str,
    run_id: str,
    event_type: str,
    summary: str,
    previous_chain_digest: str | None,
    status: str | None,
    terminal_reason: str | None,
    attempt_id: str | None,
    attempt_index: int | None,
    patch_id: str | None,
    tool_invocation_id: str | None,
    metadata: Mapping[str, Any],
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "loop_id": loop_id,
        "task_id": task_id,
        "run_id": run_id,
        "event_type": event_type,
        "summary": summary,
        "previous_chain_digest": previous_chain_digest,
        "status": status,
        "terminal_reason": terminal_reason,
        "attempt_id": attempt_id,
        "attempt_index": attempt_index,
        "patch_id": patch_id,
        "tool_invocation_id": tool_invocation_id,
        "metadata": dict(metadata),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label="optional_identifier")


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned
