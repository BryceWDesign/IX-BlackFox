from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from ix_blackfox.brains.contracts import (
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainModality,
)


@dataclass(frozen=True, slots=True)
class BrainInvocationReceipt:
    """
    Immutable auditable record for one brain invocation.
    """

    receipt_id: str
    invocation_id: str
    brain_name: str
    provider_name: str
    model_name: str
    status: BrainInvocationStatus
    task_id: str | None
    pack_name: str | None
    input_modalities: tuple[BrainModality, ...]
    output_modalities: tuple[BrainModality, ...]
    started_at: datetime
    completed_at: datetime
    latency_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    escalation_reason: str | None = None
    safety_labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

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
            "brain_name",
            _normalize_identifier(self.brain_name, label="brain_name"),
        )
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        object.__setattr__(self, "model_name", _normalize_model_name(self.model_name))
        object.__setattr__(
            self,
            "task_id",
            _normalize_optional_identifier(self.task_id, label="task_id"),
        )
        object.__setattr__(
            self,
            "pack_name",
            _normalize_optional_identifier(self.pack_name, label="pack_name"),
        )
        object.__setattr__(
            self,
            "input_modalities",
            _normalize_modalities(self.input_modalities),
        )
        object.__setattr__(
            self,
            "output_modalities",
            _normalize_modalities(self.output_modalities),
        )
        object.__setattr__(
            self,
            "started_at",
            _normalize_datetime(self.started_at),
        )
        object.__setattr__(
            self,
            "completed_at",
            _normalize_datetime(self.completed_at),
        )

        if self.completed_at < self.started_at:
            raise ValueError("completed_at must be greater than or equal to started_at.")
        if self.latency_ms < 0:
            raise ValueError("latency_ms must be zero or greater.")

        normalized_input_tokens = _normalize_optional_token_count(
            self.input_tokens,
            label="input_tokens",
        )
        normalized_output_tokens = _normalize_optional_token_count(
            self.output_tokens,
            label="output_tokens",
        )
        normalized_total_tokens = _normalize_optional_token_count(
            self.total_tokens,
            label="total_tokens",
        )

        if normalized_total_tokens is None:
            if normalized_input_tokens is not None and normalized_output_tokens is not None:
                normalized_total_tokens = normalized_input_tokens + normalized_output_tokens

        if (
            normalized_total_tokens is not None
            and normalized_input_tokens is not None
            and normalized_output_tokens is not None
            and normalized_total_tokens < normalized_input_tokens + normalized_output_tokens
        ):
            raise ValueError(
                "total_tokens must be greater than or equal to input_tokens + output_tokens."
            )

        object.__setattr__(self, "input_tokens", normalized_input_tokens)
        object.__setattr__(self, "output_tokens", normalized_output_tokens)
        object.__setattr__(self, "total_tokens", normalized_total_tokens)
        object.__setattr__(
            self,
            "escalation_reason",
            _normalize_optional_text(self.escalation_reason),
        )
        object.__setattr__(
            self,
            "safety_labels",
            _normalize_labels(self.safety_labels),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, object]:
        """
        Return a serializable view of the receipt.
        """
        return {
            "receipt_id": self.receipt_id,
            "invocation_id": self.invocation_id,
            "brain_name": self.brain_name,
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "status": self.status.value,
            "task_id": self.task_id,
            "pack_name": self.pack_name,
            "input_modalities": [item.value for item in self.input_modalities],
            "output_modalities": [item.value for item in self.output_modalities],
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "latency_ms": self.latency_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "escalation_reason": self.escalation_reason,
            "safety_labels": list(self.safety_labels),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainInvocationReceiptSnapshot:
    """
    Immutable view of stored brain invocation receipts.
    """

    receipts: tuple[BrainInvocationReceipt, ...]

    def filter_by_task(self, task_id: str) -> tuple[BrainInvocationReceipt, ...]:
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        return tuple(
            receipt for receipt in self.receipts if receipt.task_id == normalized_task_id
        )

    def filter_by_invocation(
        self,
        invocation_id: str,
    ) -> tuple[BrainInvocationReceipt, ...]:
        normalized_invocation_id = _normalize_identifier(
            invocation_id,
            label="invocation_id",
        )
        return tuple(
            receipt
            for receipt in self.receipts
            if receipt.invocation_id == normalized_invocation_id
        )

    def filter_by_brain(self, brain_name: str) -> tuple[BrainInvocationReceipt, ...]:
        normalized_brain_name = _normalize_identifier(brain_name, label="brain_name")
        return tuple(
            receipt
            for receipt in self.receipts
            if receipt.brain_name == normalized_brain_name
        )


class BrainInvocationReceiptLedger:
    """
    Thread-safe ledger for auditable brain invocation receipts.
    """

    def __init__(self) -> None:
        self._receipts: list[BrainInvocationReceipt] = []
        self._lock = RLock()

    def append(
        self,
        *,
        request: BrainInvocationRequest,
        result: BrainInvocationResult,
        provider_name: str,
        model_name: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        latency_ms: int | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        total_tokens: int | None = None,
        escalation_reason: str | None = None,
        safety_labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> BrainInvocationReceipt:
        """
        Append a new brain invocation receipt.
        """
        if request.invocation_id != result.invocation_id:
            raise ValueError(
                "Brain invocation request and result must share the same invocation_id."
            )
        if request.brain_name != result.brain_name:
            raise ValueError(
                "Brain invocation request and result must share the same brain_name."
            )

        normalized_started_at = _normalize_datetime(started_at or _utc_now())
        normalized_completed_at = _normalize_datetime(
            completed_at or normalized_started_at
        )

        computed_latency_ms = (
            latency_ms
            if latency_ms is not None
            else max(
                0,
                int(
                    (normalized_completed_at - normalized_started_at).total_seconds()
                    * 1000
                ),
            )
        )

        merged_metadata = dict(metadata or {})
        if request.metadata:
            merged_metadata["request"] = dict(request.metadata)
        if result.metadata:
            merged_metadata["result"] = dict(result.metadata)

        receipt = BrainInvocationReceipt(
            receipt_id=f"brain-receipt-{uuid4().hex}",
            invocation_id=request.invocation_id,
            brain_name=request.brain_name,
            provider_name=provider_name,
            model_name=model_name,
            status=result.status,
            task_id=request.task_id,
            pack_name=request.pack_name,
            input_modalities=request.input_modalities,
            output_modalities=result.output_modalities,
            started_at=normalized_started_at,
            completed_at=normalized_completed_at,
            latency_ms=computed_latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            escalation_reason=escalation_reason,
            safety_labels=safety_labels,
            metadata=merged_metadata,
        )

        with self._lock:
            self._receipts.append(receipt)

        return receipt

    def snapshot(self) -> BrainInvocationReceiptSnapshot:
        with self._lock:
            receipts = tuple(self._receipts)
        return BrainInvocationReceiptSnapshot(receipts=receipts)

    def count(self) -> int:
        with self._lock:
            return len(self._receipts)

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_model_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("model_name must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower().replace(" ", "-")
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_modalities(
    modalities: tuple[BrainModality, ...],
) -> tuple[BrainModality, ...]:
    normalized: list[BrainModality] = []
    seen: set[BrainModality] = set()

    for modality in modalities:
        if modality not in seen:
            normalized.append(modality)
            seen.add(modality)

    return tuple(normalized)


def _normalize_optional_token_count(value: int | None, *, label: str) -> int | None:
    if value is None:
        return None
    if value < 0:
        raise ValueError(f"{label} must be zero or greater when provided.")
    return value


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
