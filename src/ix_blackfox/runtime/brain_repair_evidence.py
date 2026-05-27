from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ix_blackfox.runtime.brain_repair import BrainRepairSelectionReport


class BrainRepairEvidenceEventType(StrEnum):
    """
    Canonical Wave 7 evidence events for model repair selection.
    """

    SELECTION_RECORDED = auto()
    SELECTION_BLOCKED = auto()
    REPORT_EXPORTED = auto()


@dataclass(frozen=True, slots=True)
class BrainRepairEvidenceReceipt:
    """
    Tamper-evident receipt for one Wave 7 model-repair evidence event.

    These receipts prove which model outputs were considered, which candidate
    was selected or blocked, whether separated review was routed, and which
    comparison report digest future reviewers can bind back to the raw evidence.
    """

    receipt_id: str
    run_id: str
    task_id: str
    contract_id: str
    event_type: BrainRepairEvidenceEventType
    summary: str
    previous_receipt_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    selected_source_id: str | None = None
    selected_brain_name: str | None = None
    selected_raw_response_digest: str | None = None
    review_routed: bool = False
    blocked: bool = True
    comparison_result_count: int = 0
    record_count: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_identifier(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "run_id",
            _normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(
            self,
            "task_id",
            _normalize_identifier(self.task_id, label="task_id"),
        )
        object.__setattr__(
            self,
            "contract_id",
            _normalize_identifier(self.contract_id, label="contract_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(
            self,
            "selected_source_id",
            _normalize_optional_identifier(self.selected_source_id),
        )
        object.__setattr__(
            self,
            "selected_brain_name",
            _normalize_optional_identifier(self.selected_brain_name),
        )
        object.__setattr__(
            self,
            "selected_raw_response_digest",
            _normalize_optional_digest(self.selected_raw_response_digest),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.created_at.tzinfo is None:
            raise ValueError("BrainRepairEvidenceReceipt created_at must be timezone-aware.")
        if self.comparison_result_count < 0:
            raise ValueError("comparison_result_count must not be negative.")
        if self.record_count < 0:
            raise ValueError("record_count must not be negative.")
        if self.event_type is BrainRepairEvidenceEventType.SELECTION_RECORDED:
            if self.blocked:
                raise ValueError("selection-recorded receipts must not be blocked.")
            if self.selected_source_id is None:
                raise ValueError("selection-recorded receipts require selected_source_id.")
            if self.selected_brain_name is None:
                raise ValueError("selection-recorded receipts require selected_brain_name.")
            if self.selected_raw_response_digest is None:
                raise ValueError(
                    "selection-recorded receipts require selected_raw_response_digest."
                )

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable receipt view.
        """
        return {
            "receipt_id": self.receipt_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "contract_id": self.contract_id,
            "event_type": self.event_type.value,
            "summary": self.summary,
            "previous_receipt_id": self.previous_receipt_id,
            "previous_chain_digest": self.previous_chain_digest,
            "chain_digest": self.chain_digest,
            "created_at": self.created_at.isoformat(),
            "selected_source_id": self.selected_source_id,
            "selected_brain_name": self.selected_brain_name,
            "selected_raw_response_digest": self.selected_raw_response_digest,
            "review_routed": self.review_routed,
            "blocked": self.blocked,
            "comparison_result_count": self.comparison_result_count,
            "record_count": self.record_count,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainRepairEvidenceSnapshot:
    """
    Immutable view of Wave 7 model-repair evidence receipts.
    """

    receipts: tuple[BrainRepairEvidenceReceipt, ...]

    def filter_by_run(self, run_id: str) -> tuple[BrainRepairEvidenceReceipt, ...]:
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        return tuple(receipt for receipt in self.receipts if receipt.run_id == normalized_run_id)

    def filter_by_task(self, task_id: str) -> tuple[BrainRepairEvidenceReceipt, ...]:
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        return tuple(
            receipt for receipt in self.receipts if receipt.task_id == normalized_task_id
        )

    def filter_by_contract(
        self,
        contract_id: str,
    ) -> tuple[BrainRepairEvidenceReceipt, ...]:
        normalized_contract_id = _normalize_identifier(contract_id, label="contract_id")
        return tuple(
            receipt
            for receipt in self.receipts
            if receipt.contract_id == normalized_contract_id
        )

    def latest_for_run(self, run_id: str) -> BrainRepairEvidenceReceipt | None:
        receipts = self.filter_by_run(run_id)
        if not receipts:
            return None
        return receipts[-1]

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable snapshot view.
        """
        return {
            "receipt_count": len(self.receipts),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }


class BrainRepairEvidenceLedger:
    """
    Thread-safe chained receipt ledger for Wave 7 model repair evidence.
    """

    def __init__(self) -> None:
        self._receipts: list[BrainRepairEvidenceReceipt] = []
        self._lock = RLock()

    def record_selection_report(
        self,
        *,
        run_id: str,
        task_id: str,
        contract_id: str,
        report: BrainRepairSelectionReport,
        metadata: Mapping[str, Any] | None = None,
    ) -> BrainRepairEvidenceReceipt:
        """
        Record model comparison, tribunal routing, and selected/blocked output.
        """
        report_payload = report.to_dict()
        selected_source_id = report_payload["selected_source_id"]
        selected_brain_name = report_payload["selected_brain_name"]
        selected_raw_response_digest = report_payload["selected_raw_response_digest"]
        blocked = bool(report_payload["blocked"])
        event_type = (
            BrainRepairEvidenceEventType.SELECTION_BLOCKED
            if blocked
            else BrainRepairEvidenceEventType.SELECTION_RECORDED
        )
        summary = (
            "Wave 7 model-repair selection was blocked."
            if blocked
            else "Wave 7 model-repair selection was recorded."
        )
        return self.append(
            run_id=run_id,
            task_id=task_id,
            contract_id=contract_id,
            event_type=event_type,
            summary=summary,
            selected_source_id=(
                str(selected_source_id) if selected_source_id is not None else None
            ),
            selected_brain_name=(
                str(selected_brain_name) if selected_brain_name is not None else None
            ),
            selected_raw_response_digest=(
                str(selected_raw_response_digest)
                if selected_raw_response_digest is not None
                else None
            ),
            review_routed=bool(report_payload["review_routed"]),
            blocked=blocked,
            comparison_result_count=len(report.comparison_decision.results),
            record_count=len(report.records),
            metadata={
                "selection_report_digest": _digest_payload(report_payload),
                "comparison_id": report.comparison_decision.request.comparison_id,
                "tribunal_disposition": None
                if report.tribunal_decision is None
                else report.tribunal_decision.disposition.value,
                "source_count": report.metadata.get("source_count"),
                "tribunal_review_required": report.metadata.get(
                    "tribunal_review_required"
                ),
                **dict(metadata or {}),
            },
        )

    def record_exported(
        self,
        *,
        run_id: str,
        task_id: str,
        contract_id: str,
        export_path: str | Path,
        export_digest: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> BrainRepairEvidenceReceipt:
        """
        Record a receipt that binds an exported evidence artifact to the chain.
        """
        return self.append(
            run_id=run_id,
            task_id=task_id,
            contract_id=contract_id,
            event_type=BrainRepairEvidenceEventType.REPORT_EXPORTED,
            summary="Wave 7 model-repair evidence report was exported.",
            selected_source_id=None,
            selected_brain_name=None,
            selected_raw_response_digest=None,
            review_routed=True,
            blocked=False,
            comparison_result_count=0,
            record_count=0,
            metadata={
                "export_path": str(export_path),
                "export_digest": _normalize_digest(export_digest),
                **dict(metadata or {}),
            },
        )

    def append(
        self,
        *,
        run_id: str,
        task_id: str,
        contract_id: str,
        event_type: BrainRepairEvidenceEventType,
        summary: str,
        selected_source_id: str | None,
        selected_brain_name: str | None,
        selected_raw_response_digest: str | None,
        review_routed: bool,
        blocked: bool,
        comparison_result_count: int,
        record_count: int,
        metadata: Mapping[str, Any] | None = None,
    ) -> BrainRepairEvidenceReceipt:
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        normalized_contract_id = _normalize_identifier(contract_id, label="contract_id")
        normalized_summary = _normalize_text(summary, label="summary")
        normalized_selected_source_id = _normalize_optional_identifier(selected_source_id)
        normalized_selected_brain_name = _normalize_optional_identifier(selected_brain_name)
        normalized_selected_digest = _normalize_optional_digest(selected_raw_response_digest)
        normalized_metadata = dict(metadata or {})

        with self._lock:
            previous = self._latest_for_run_unlocked(normalized_run_id)
            previous_receipt_id = None if previous is None else previous.receipt_id
            previous_chain_digest = None if previous is None else previous.chain_digest
            receipt_id = f"wave7-repair-evidence-{uuid4().hex}"
            created_at = datetime.now(tz=UTC)
            chain_digest = _compute_chain_digest(
                receipt_id=receipt_id,
                run_id=normalized_run_id,
                task_id=normalized_task_id,
                contract_id=normalized_contract_id,
                event_type=event_type.value,
                summary=normalized_summary,
                previous_chain_digest=previous_chain_digest,
                selected_source_id=normalized_selected_source_id,
                selected_brain_name=normalized_selected_brain_name,
                selected_raw_response_digest=normalized_selected_digest,
                review_routed=review_routed,
                blocked=blocked,
                comparison_result_count=comparison_result_count,
                record_count=record_count,
                metadata=normalized_metadata,
            )
            receipt = BrainRepairEvidenceReceipt(
                receipt_id=receipt_id,
                run_id=normalized_run_id,
                task_id=normalized_task_id,
                contract_id=normalized_contract_id,
                event_type=event_type,
                summary=normalized_summary,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=chain_digest,
                created_at=created_at,
                selected_source_id=normalized_selected_source_id,
                selected_brain_name=normalized_selected_brain_name,
                selected_raw_response_digest=normalized_selected_digest,
                review_routed=review_routed,
                blocked=blocked,
                comparison_result_count=comparison_result_count,
                record_count=record_count,
                metadata=normalized_metadata,
            )
            self._receipts.append(receipt)
            return receipt

    def snapshot(self) -> BrainRepairEvidenceSnapshot:
        with self._lock:
            receipts = tuple(self._receipts)
        return BrainRepairEvidenceSnapshot(receipts=receipts)

    def verify_run_chain(self, run_id: str) -> bool:
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        with self._lock:
            receipts = [
                receipt
                for receipt in self._receipts
                if receipt.run_id == normalized_run_id
            ]

        previous_receipt: BrainRepairEvidenceReceipt | None = None
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
                run_id=receipt.run_id,
                task_id=receipt.task_id,
                contract_id=receipt.contract_id,
                event_type=receipt.event_type.value,
                summary=receipt.summary,
                previous_chain_digest=receipt.previous_chain_digest,
                selected_source_id=receipt.selected_source_id,
                selected_brain_name=receipt.selected_brain_name,
                selected_raw_response_digest=receipt.selected_raw_response_digest,
                review_routed=receipt.review_routed,
                blocked=receipt.blocked,
                comparison_result_count=receipt.comparison_result_count,
                record_count=receipt.record_count,
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

    def _latest_for_run_unlocked(
        self,
        run_id: str,
    ) -> BrainRepairEvidenceReceipt | None:
        for receipt in reversed(self._receipts):
            if receipt.run_id == run_id:
                return receipt
        return None


@dataclass(frozen=True, slots=True)
class BrainRepairEvidenceExport:
    """
    Result of writing a Wave 7 repair evidence report to disk.
    """

    path: Path
    digest: str
    receipt: BrainRepairEvidenceReceipt
    chain_valid: bool

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable export result.
        """
        return {
            "path": str(self.path),
            "digest": self.digest,
            "receipt": self.receipt.to_dict(),
            "chain_valid": self.chain_valid,
        }


class BrainRepairEvidenceExporter:
    """
    JSON evidence exporter for Wave 7 model-repair selection reports.
    """

    schema_version = "wave7.brain_repair_evidence.v1"

    def export(
        self,
        *,
        path: str | Path,
        run_id: str,
        task_id: str,
        contract_id: str,
        report: BrainRepairSelectionReport,
        ledger: BrainRepairEvidenceLedger,
        metadata: Mapping[str, Any] | None = None,
    ) -> BrainRepairEvidenceExport:
        """
        Write a canonical evidence report and record an export receipt.
        """
        selection_receipt = ledger.record_selection_report(
            run_id=run_id,
            task_id=task_id,
            contract_id=contract_id,
            report=report,
            metadata=metadata,
        )
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        chain_valid = ledger.verify_run_chain(run_id)
        payload = {
            "schema_version": self.schema_version,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "run_id": selection_receipt.run_id,
            "task_id": selection_receipt.task_id,
            "contract_id": selection_receipt.contract_id,
            "chain_valid": chain_valid,
            "receipt": selection_receipt.to_dict(),
            "selection_report": report.to_dict(),
            "metadata": dict(metadata or {}),
        }
        output_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        digest = _digest_path(output_path)
        export_receipt = ledger.record_exported(
            run_id=run_id,
            task_id=task_id,
            contract_id=contract_id,
            export_path=output_path,
            export_digest=digest,
            metadata={"selection_receipt_id": selection_receipt.receipt_id},
        )
        return BrainRepairEvidenceExport(
            path=output_path,
            digest=digest,
            receipt=export_receipt,
            chain_valid=ledger.verify_run_chain(run_id),
        )


def _compute_chain_digest(
    *,
    receipt_id: str,
    run_id: str,
    task_id: str,
    contract_id: str,
    event_type: str,
    summary: str,
    previous_chain_digest: str | None,
    selected_source_id: str | None,
    selected_brain_name: str | None,
    selected_raw_response_digest: str | None,
    review_routed: bool,
    blocked: bool,
    comparison_result_count: int,
    record_count: int,
    metadata: Mapping[str, Any],
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "run_id": run_id,
        "task_id": task_id,
        "contract_id": contract_id,
        "event_type": event_type,
        "summary": summary,
        "previous_chain_digest": previous_chain_digest,
        "selected_source_id": selected_source_id,
        "selected_brain_name": selected_brain_name,
        "selected_raw_response_digest": selected_raw_response_digest,
        "review_routed": review_routed,
        "blocked": blocked,
        "comparison_result_count": comparison_result_count,
        "record_count": record_count,
        "metadata": dict(metadata),
    }
    return _digest_payload(payload)


def _digest_payload(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _digest_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _normalize_optional_digest(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_digest(value)


def _normalize_digest(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("digest values must be 64 lowercase hexadecimal characters.")
    try:
        int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(
            "digest values must be 64 lowercase hexadecimal characters."
        ) from exc
    return cleaned
