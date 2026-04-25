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

from ix_blackfox.tools.contracts import (
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)
from ix_blackfox.tools.policy import ToolPolicyDecision, ToolPolicyEvaluation
from ix_blackfox.tools.risk import ToolRiskLevel


class ToolReceiptEventType(StrEnum):
    """
    Canonical receipt events for governed tool invocation.

    These events form the auditable bridge between policy evaluation and tool
    execution. The ledger records what was decided, what was attempted, what
    happened, and which artifacts were produced.
    """

    POLICY_EVALUATED = auto()
    INVOCATION_STARTED = auto()
    INVOCATION_SUCCEEDED = auto()
    INVOCATION_FAILED = auto()
    INVOCATION_BLOCKED = auto()
    INVOCATION_REVIEW_REQUIRED = auto()
    ARTIFACT_EMITTED = auto()


@dataclass(frozen=True, slots=True)
class ToolInvocationReceipt:
    """
    One tamper-evident receipt in a tool-invocation chain.

    Attributes
    ----------
    receipt_id:
        Stable unique receipt identifier.
    invocation_id:
        Tool invocation identifier this receipt belongs to.
    tool_id:
        Stable governed tool identifier.
    event_type:
        Canonical receipt event type.
    summary:
        Human-readable event summary.
    previous_receipt_id:
        Prior receipt identifier in this invocation chain.
    previous_chain_digest:
        Prior chain digest in this invocation chain.
    chain_digest:
        SHA-256 digest binding this receipt to prior chain state.
    created_at:
        UTC timestamp when the receipt was created.
    actor:
        Optional emitting subsystem.
    task_id:
        Optional task identifier associated with the invocation.
    run_id:
        Optional runtime run identifier associated with the invocation.
    policy_decision:
        Optional governed tool policy decision.
    invocation_status:
        Optional terminal invocation status.
    risk_level:
        Optional tool risk level observed at policy time.
    artifact_count:
        Number of artifacts associated with this event.
    metadata:
        Structured event metadata.
    """

    receipt_id: str
    invocation_id: str
    tool_id: str
    event_type: ToolReceiptEventType
    summary: str
    previous_receipt_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    actor: str | None = None
    task_id: str | None = None
    run_id: str | None = None
    policy_decision: ToolPolicyDecision | None = None
    invocation_status: ToolInvocationStatus | None = None
    risk_level: ToolRiskLevel | None = None
    artifact_count: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_identifier(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(
            self,
            "tool_id",
            _normalize_identifier(self.tool_id, label="tool_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "actor", _normalize_optional_identifier(self.actor))
        object.__setattr__(self, "task_id", _normalize_optional_identifier(self.task_id))
        object.__setattr__(self, "run_id", _normalize_optional_identifier(self.run_id))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.created_at.tzinfo is None:
            raise ValueError("ToolInvocationReceipt created_at must be timezone-aware.")
        if self.artifact_count < 0:
            raise ValueError("ToolInvocationReceipt artifact_count must not be negative.")

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable receipt payload.
        """
        return {
            "receipt_id": self.receipt_id,
            "invocation_id": self.invocation_id,
            "tool_id": self.tool_id,
            "event_type": self.event_type.value,
            "summary": self.summary,
            "previous_receipt_id": self.previous_receipt_id,
            "previous_chain_digest": self.previous_chain_digest,
            "chain_digest": self.chain_digest,
            "created_at": self.created_at.isoformat(),
            "actor": self.actor,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "policy_decision": (
                self.policy_decision.value if self.policy_decision is not None else None
            ),
            "invocation_status": (
                self.invocation_status.value
                if self.invocation_status is not None
                else None
            ),
            "risk_level": self.risk_level.value if self.risk_level is not None else None,
            "artifact_count": self.artifact_count,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ToolInvocationReceiptSnapshot:
    """
    Immutable view of stored tool invocation receipts.
    """

    receipts: tuple[ToolInvocationReceipt, ...]

    def filter_by_invocation(
        self,
        invocation_id: str,
    ) -> tuple[ToolInvocationReceipt, ...]:
        normalized_invocation_id = _normalize_identifier(
            invocation_id,
            label="invocation_id",
        )
        return tuple(
            receipt
            for receipt in self.receipts
            if receipt.invocation_id == normalized_invocation_id
        )

    def filter_by_tool(self, tool_id: str) -> tuple[ToolInvocationReceipt, ...]:
        normalized_tool_id = _normalize_identifier(tool_id, label="tool_id")
        return tuple(
            receipt for receipt in self.receipts if receipt.tool_id == normalized_tool_id
        )

    def filter_by_task(self, task_id: str) -> tuple[ToolInvocationReceipt, ...]:
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        return tuple(
            receipt for receipt in self.receipts if receipt.task_id == normalized_task_id
        )

    def filter_by_run(self, run_id: str) -> tuple[ToolInvocationReceipt, ...]:
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        return tuple(receipt for receipt in self.receipts if receipt.run_id == normalized_run_id)

    def latest_for_invocation(self, invocation_id: str) -> ToolInvocationReceipt | None:
        receipts = self.filter_by_invocation(invocation_id)
        if not receipts:
            return None
        return receipts[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_count": len(self.receipts),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }


class ToolInvocationReceiptLedger:
    """
    Thread-safe chained receipt ledger for governed tool invocations.

    Each invocation gets its own chain. The chain proves ordering and makes
    tampering visible by linking each receipt digest to the prior digest.
    """

    def __init__(self) -> None:
        self._receipts: list[ToolInvocationReceipt] = []
        self._lock = RLock()

    def record_policy_evaluation(
        self,
        *,
        evaluation: ToolPolicyEvaluation,
        request: ToolInvocationRequest,
        actor: str = "tools.policy",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolInvocationReceipt:
        """
        Record the policy decision that governs whether a tool may execute.
        """
        event_type = _event_type_for_policy_decision(evaluation.decision)
        summary = (
            f"Tool policy evaluated invocation '{request.invocation_id}' "
            f"as '{evaluation.decision.value}'."
        )

        return self.append(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            event_type=event_type,
            summary=summary,
            actor=actor,
            task_id=request.task_id,
            run_id=request.run_id,
            policy_decision=evaluation.decision,
            risk_level=evaluation.risk_assessment.level,
            metadata={
                "decision": evaluation.decision.value,
                "reason_codes": list(evaluation.reason_codes),
                "risk_score": evaluation.risk_assessment.score,
                "risk_signal_codes": list(evaluation.risk_assessment.signal_codes),
                **dict(metadata or {}),
            },
        )

    def record_invocation_started(
        self,
        *,
        request: ToolInvocationRequest,
        actor: str = "tools.gateway",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolInvocationReceipt:
        """
        Record that an allowed tool invocation began execution.
        """
        return self.append(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            event_type=ToolReceiptEventType.INVOCATION_STARTED,
            summary=f"Tool invocation started for '{request.tool_id}'.",
            actor=actor,
            task_id=request.task_id,
            run_id=request.run_id,
            metadata={
                "capability": request.capability.value,
                "labels": list(request.labels),
                **dict(metadata or {}),
            },
        )

    def record_invocation_result(
        self,
        *,
        result: ToolInvocationResult,
        request: ToolInvocationRequest | None = None,
        actor: str = "tools.gateway",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolInvocationReceipt:
        """
        Record the terminal outcome of a tool invocation.
        """
        event_type = _event_type_for_invocation_status(result.status)
        failure_payload = result.failure.to_dict() if result.failure else None

        return self.append(
            invocation_id=result.invocation_id,
            tool_id=result.tool_id,
            event_type=event_type,
            summary=_summary_for_invocation_status(result.status, result.tool_id),
            actor=actor,
            task_id=request.task_id if request is not None else None,
            run_id=request.run_id if request is not None else None,
            invocation_status=result.status,
            artifact_count=len(result.artifacts),
            metadata={
                "latency_ms": result.latency_ms,
                "output_keys": sorted(str(key) for key in result.output.keys()),
                "artifact_ids": [artifact.artifact_id for artifact in result.artifacts],
                "failure": failure_payload,
                **dict(metadata or {}),
            },
        )

    def record_artifact_emitted(
        self,
        *,
        result: ToolInvocationResult,
        artifact_name: str,
        artifact_uri: str,
        actor: str = "tools.artifacts",
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolInvocationReceipt:
        """
        Record a materialized artifact associated with a tool invocation.
        """
        return self.append(
            invocation_id=result.invocation_id,
            tool_id=result.tool_id,
            event_type=ToolReceiptEventType.ARTIFACT_EMITTED,
            summary=f"Tool artifact emitted: {artifact_name}.",
            actor=actor,
            invocation_status=result.status,
            artifact_count=1,
            metadata={
                "artifact_name": artifact_name,
                "artifact_uri": artifact_uri,
                **dict(metadata or {}),
            },
        )

    def append(
        self,
        *,
        invocation_id: str,
        tool_id: str,
        event_type: ToolReceiptEventType,
        summary: str,
        actor: str | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
        policy_decision: ToolPolicyDecision | None = None,
        invocation_status: ToolInvocationStatus | None = None,
        risk_level: ToolRiskLevel | None = None,
        artifact_count: int = 0,
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolInvocationReceipt:
        """
        Append one receipt to an invocation-specific chain.
        """
        normalized_invocation_id = _normalize_identifier(
            invocation_id,
            label="invocation_id",
        )
        normalized_tool_id = _normalize_identifier(tool_id, label="tool_id")
        normalized_summary = _normalize_text(summary, label="summary")
        normalized_actor = _normalize_optional_identifier(actor)
        normalized_task_id = _normalize_optional_identifier(task_id)
        normalized_run_id = _normalize_optional_identifier(run_id)
        normalized_metadata = dict(metadata or {})

        if artifact_count < 0:
            raise ValueError("artifact_count must not be negative.")

        with self._lock:
            previous = self._latest_for_invocation_unlocked(normalized_invocation_id)
            previous_receipt_id = None if previous is None else previous.receipt_id
            previous_chain_digest = None if previous is None else previous.chain_digest

            receipt_id = f"tool-receipt-{uuid4().hex}"
            created_at = _utc_now()
            chain_digest = _compute_chain_digest(
                receipt_id=receipt_id,
                invocation_id=normalized_invocation_id,
                tool_id=normalized_tool_id,
                event_type=event_type.value,
                summary=normalized_summary,
                previous_chain_digest=previous_chain_digest,
                actor=normalized_actor,
                task_id=normalized_task_id,
                run_id=normalized_run_id,
                policy_decision=(
                    policy_decision.value if policy_decision is not None else None
                ),
                invocation_status=(
                    invocation_status.value if invocation_status is not None else None
                ),
                risk_level=risk_level.value if risk_level is not None else None,
                artifact_count=artifact_count,
                metadata=normalized_metadata,
            )

            receipt = ToolInvocationReceipt(
                receipt_id=receipt_id,
                invocation_id=normalized_invocation_id,
                tool_id=normalized_tool_id,
                event_type=event_type,
                summary=normalized_summary,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=chain_digest,
                created_at=created_at,
                actor=normalized_actor,
                task_id=normalized_task_id,
                run_id=normalized_run_id,
                policy_decision=policy_decision,
                invocation_status=invocation_status,
                risk_level=risk_level,
                artifact_count=artifact_count,
                metadata=normalized_metadata,
            )
            self._receipts.append(receipt)
            return receipt

    def snapshot(self) -> ToolInvocationReceiptSnapshot:
        """
        Return an immutable snapshot of all stored tool receipts.
        """
        with self._lock:
            receipts = tuple(self._receipts)
        return ToolInvocationReceiptSnapshot(receipts=receipts)

    def verify_invocation_chain(self, invocation_id: str) -> bool:
        """
        Verify digest integrity for one invocation-specific receipt chain.
        """
        normalized_invocation_id = _normalize_identifier(
            invocation_id,
            label="invocation_id",
        )

        with self._lock:
            receipts = [
                receipt
                for receipt in self._receipts
                if receipt.invocation_id == normalized_invocation_id
            ]

        previous_receipt: ToolInvocationReceipt | None = None
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

            expected_chain_digest = _compute_chain_digest(
                receipt_id=receipt.receipt_id,
                invocation_id=receipt.invocation_id,
                tool_id=receipt.tool_id,
                event_type=receipt.event_type.value,
                summary=receipt.summary,
                previous_chain_digest=receipt.previous_chain_digest,
                actor=receipt.actor,
                task_id=receipt.task_id,
                run_id=receipt.run_id,
                policy_decision=(
                    receipt.policy_decision.value
                    if receipt.policy_decision is not None
                    else None
                ),
                invocation_status=(
                    receipt.invocation_status.value
                    if receipt.invocation_status is not None
                    else None
                ),
                risk_level=receipt.risk_level.value if receipt.risk_level is not None else None,
                artifact_count=receipt.artifact_count,
                metadata=dict(receipt.metadata),
            )
            if receipt.chain_digest != expected_chain_digest:
                return False

            previous_receipt = receipt

        return True

    def count(self) -> int:
        """
        Return the total number of stored tool receipts.
        """
        with self._lock:
            return len(self._receipts)

    def clear(self) -> None:
        """
        Remove all stored tool receipts.
        """
        with self._lock:
            self._receipts.clear()

    def _latest_for_invocation_unlocked(
        self,
        invocation_id: str,
    ) -> ToolInvocationReceipt | None:
        for receipt in reversed(self._receipts):
            if receipt.invocation_id == invocation_id:
                return receipt
        return None


def _event_type_for_policy_decision(
    decision: ToolPolicyDecision,
) -> ToolReceiptEventType:
    if decision is ToolPolicyDecision.ALLOW:
        return ToolReceiptEventType.POLICY_EVALUATED
    if decision is ToolPolicyDecision.REVIEW_REQUIRED:
        return ToolReceiptEventType.INVOCATION_REVIEW_REQUIRED
    if decision is ToolPolicyDecision.BLOCK:
        return ToolReceiptEventType.INVOCATION_BLOCKED
    return ToolReceiptEventType.POLICY_EVALUATED


def _event_type_for_invocation_status(
    status: ToolInvocationStatus,
) -> ToolReceiptEventType:
    if status is ToolInvocationStatus.SUCCEEDED:
        return ToolReceiptEventType.INVOCATION_SUCCEEDED
    if status is ToolInvocationStatus.BLOCKED:
        return ToolReceiptEventType.INVOCATION_BLOCKED
    if status is ToolInvocationStatus.REVIEW_REQUIRED:
        return ToolReceiptEventType.INVOCATION_REVIEW_REQUIRED
    return ToolReceiptEventType.INVOCATION_FAILED


def _summary_for_invocation_status(status: ToolInvocationStatus, tool_id: str) -> str:
    if status is ToolInvocationStatus.SUCCEEDED:
        return f"Tool invocation succeeded for '{tool_id}'."
    if status is ToolInvocationStatus.BLOCKED:
        return f"Tool invocation blocked for '{tool_id}'."
    if status is ToolInvocationStatus.REVIEW_REQUIRED:
        return f"Tool invocation requires review for '{tool_id}'."
    if status is ToolInvocationStatus.TIMED_OUT:
        return f"Tool invocation timed out for '{tool_id}'."
    return f"Tool invocation failed for '{tool_id}'."


def _compute_chain_digest(
    *,
    receipt_id: str,
    invocation_id: str,
    tool_id: str,
    event_type: str,
    summary: str,
    previous_chain_digest: str | None,
    actor: str | None,
    task_id: str | None,
    run_id: str | None,
    policy_decision: str | None,
    invocation_status: str | None,
    risk_level: str | None,
    artifact_count: int,
    metadata: Mapping[str, Any],
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "invocation_id": invocation_id,
        "tool_id": tool_id,
        "event_type": event_type,
        "summary": summary,
        "previous_chain_digest": previous_chain_digest,
        "actor": actor,
        "task_id": task_id,
        "run_id": run_id,
        "policy_decision": policy_decision,
        "invocation_status": invocation_status,
        "risk_level": risk_level,
        "artifact_count": artifact_count,
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


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
