from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any

from ix_blackfox.repository.models import (
    RepositoryCodeGraph,
    RepositoryDependencyMap,
    RepositoryImpactReport,
    RepositorySnapshot,
    digest_payload,
    normalize_identifier,
    normalize_sha256,
    normalize_text,
)

if TYPE_CHECKING:
    from ix_blackfox.repository.architecture_memory import ArchitectureMemorySnapshot
    from ix_blackfox.repository.coverage_map import RepositoryCoverageMap


class RepositoryEvidenceEventType(StrEnum):
    INVENTORY_SNAPSHOT = auto()
    CODE_GRAPH_BUILT = auto()
    DEPENDENCY_MAP_BUILT = auto()
    COVERAGE_MAP_BUILT = auto()
    ARCHITECTURE_MEMORY_BOUND = auto()
    IMPACT_ANALYZED = auto()
    REPORT_EXPORTED = auto()


WAVE8_REQUIRED_EVENT_SEQUENCE: tuple[RepositoryEvidenceEventType, ...] = (
    RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
    RepositoryEvidenceEventType.CODE_GRAPH_BUILT,
    RepositoryEvidenceEventType.DEPENDENCY_MAP_BUILT,
    RepositoryEvidenceEventType.COVERAGE_MAP_BUILT,
    RepositoryEvidenceEventType.ARCHITECTURE_MEMORY_BOUND,
    RepositoryEvidenceEventType.IMPACT_ANALYZED,
)


@dataclass(frozen=True, slots=True)
class RepositoryEvidenceReceipt:
    """Digest-chained receipt for one Wave 8 repository-intelligence event."""

    receipt_id: str
    event_type: RepositoryEvidenceEventType
    summary: str
    payload_digest: str
    run_id: str
    sequence_number: int
    previous_receipt_digest: str | None = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            normalize_identifier(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "run_id",
            normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(
            self,
            "summary",
            normalize_text(self.summary, label="summary"),
        )
        object.__setattr__(
            self,
            "payload_digest",
            normalize_sha256(self.payload_digest),
        )
        if self.previous_receipt_digest is not None:
            object.__setattr__(
                self,
                "previous_receipt_digest",
                normalize_sha256(self.previous_receipt_digest),
            )
        if self.sequence_number <= 0:
            raise ValueError("sequence_number must be greater than zero.")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self._payload(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = self._payload(include_digest=False)
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def _payload(self, *, include_digest: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "event_type": self.event_type.value,
            "summary": self.summary,
            "payload_digest": self.payload_digest,
            "run_id": self.run_id,
            "sequence_number": self.sequence_number,
            "previous_receipt_digest": self.previous_receipt_digest,
            "generated_at": self.generated_at.isoformat(),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(slots=True)
class RepositoryEvidenceLedger:
    """Append-only Wave 8 repository-intelligence evidence ledger."""

    run_id: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    _receipts: list[RepositoryEvidenceReceipt] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_id = normalize_identifier(self.run_id, label="run_id")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")

    @property
    def receipt_count(self) -> int:
        return len(self._receipts)

    @property
    def last_receipt_digest(self) -> str | None:
        if not self._receipts:
            return None
        return self._receipts[-1].digest

    def append(
        self,
        *,
        event_type: RepositoryEvidenceEventType,
        summary: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
        generated_at: datetime | None = None,
    ) -> RepositoryEvidenceReceipt:
        sequence_number = len(self._receipts) + 1
        receipt = RepositoryEvidenceReceipt(
            receipt_id=receipt_id_for_event(
                run_id=self.run_id,
                sequence_number=sequence_number,
                event_type=event_type,
            ),
            event_type=event_type,
            summary=summary,
            payload_digest=digest_payload(payload),
            run_id=self.run_id,
            sequence_number=sequence_number,
            previous_receipt_digest=self.last_receipt_digest,
            generated_at=generated_at or datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )
        self._receipts.append(receipt)
        return receipt

    def snapshot(self) -> "RepositoryEvidenceSnapshot":
        return RepositoryEvidenceSnapshot(
            run_id=self.run_id,
            receipts=tuple(self._receipts),
            generated_at=self.generated_at,
        )


@dataclass(frozen=True, slots=True)
class RepositoryEvidenceSnapshot:
    """Serializable Wave 8 evidence ledger snapshot."""

    run_id: str
    receipts: tuple[RepositoryEvidenceReceipt, ...] = ()
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "run_id",
            normalize_identifier(self.run_id, label="run_id"),
        )
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")
        for index, receipt in enumerate(self.receipts, start=1):
            if receipt.run_id != self.run_id:
                raise ValueError("receipt run_id must match snapshot run_id.")
            if receipt.sequence_number != index:
                raise ValueError("receipt sequence_number values must be contiguous.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @property
    def chain_valid(self) -> bool:
        previous_digest: str | None = None
        for receipt in self.receipts:
            if receipt.previous_receipt_digest != previous_digest:
                return False
            previous_digest = receipt.digest
        return True

    @property
    def event_types(self) -> tuple[RepositoryEvidenceEventType, ...]:
        return tuple(receipt.event_type for receipt in self.receipts)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def require_event_sequence(
        self,
        required_sequence: Sequence[RepositoryEvidenceEventType],
    ) -> bool:
        required = tuple(required_sequence)
        if len(self.event_types) < len(required):
            return False
        return self.event_types[: len(required)] == required

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_id": self.run_id,
            "receipt_count": self.receipt_count,
            "chain_valid": self.chain_valid,
            "event_types": [event_type.value for event_type in self.event_types],
            "generated_at": self.generated_at.isoformat(),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_repository_evidence_snapshot(
    *,
    run_id: str,
    snapshot: RepositorySnapshot,
    graph: RepositoryCodeGraph,
    dependency_map: RepositoryDependencyMap,
    coverage_map: RepositoryCoverageMap,
    architecture_memory: ArchitectureMemorySnapshot,
    impact_report: RepositoryImpactReport,
    generated_at: datetime | None = None,
) -> RepositoryEvidenceSnapshot:
    ledger = RepositoryEvidenceLedger(
        run_id=run_id,
        generated_at=generated_at or datetime.now(tz=UTC),
    )

    ledger.append(
        event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
        summary="Repository inventory snapshot generated.",
        payload=snapshot.to_dict(),
        metadata={
            "file_count": snapshot.file_count,
            "snapshot_digest": snapshot.digest,
        },
        generated_at=generated_at,
    )
    ledger.append(
        event_type=RepositoryEvidenceEventType.CODE_GRAPH_BUILT,
        summary="Python code graph generated without importing repository modules.",
        payload=graph.to_dict(),
        metadata={
            "symbol_count": graph.symbol_count,
            "edge_count": graph.edge_count,
            "syntax_error_count": len(graph.syntax_error_paths),
            "graph_digest": graph.digest,
        },
        generated_at=generated_at,
    )
    ledger.append(
        event_type=RepositoryEvidenceEventType.DEPENDENCY_MAP_BUILT,
        summary="Repository dependency map generated.",
        payload=dependency_map.to_dict(),
        metadata={
            "dependency_count": len(dependency_map.dependencies),
            "internal_edge_count": len(dependency_map.internal_edges),
            "sensitive_path_count": len(dependency_map.sensitive_paths),
            "dependency_map_digest": dependency_map.digest,
        },
        generated_at=generated_at,
    )
    ledger.append(
        event_type=RepositoryEvidenceEventType.COVERAGE_MAP_BUILT,
        summary="Source-test and subsystem coverage map generated.",
        payload=coverage_map.to_dict(),
        metadata={
            "link_count": coverage_map.link_count,
            "subsystem_count": coverage_map.subsystem_count,
            "orphan_source_count": len(coverage_map.orphan_source_paths),
            "coverage_map_digest": coverage_map.digest,
        },
        generated_at=generated_at,
    )
    ledger.append(
        event_type=RepositoryEvidenceEventType.ARCHITECTURE_MEMORY_BOUND,
        summary="Architecture memory snapshot bound to repository evidence.",
        payload=architecture_memory.to_dict(),
        metadata={
            "record_count": architecture_memory.record_count,
            "architecture_memory_digest": architecture_memory.digest,
        },
        generated_at=generated_at,
    )
    ledger.append(
        event_type=RepositoryEvidenceEventType.IMPACT_ANALYZED,
        summary="Conservative repository impact analysis generated.",
        payload=impact_report.to_dict(),
        metadata={
            "changed_path_count": len(impact_report.changed_paths),
            "impacted_path_count": len(impact_report.impacted_paths),
            "impacted_test_count": len(impact_report.impacted_tests),
            "requires_human_review": impact_report.requires_human_review,
            "max_severity": impact_report.max_severity.value,
            "impact_report_digest": impact_report.digest,
        },
        generated_at=generated_at,
    )

    return ledger.snapshot()


def validate_repository_evidence_snapshot(
    evidence: RepositoryEvidenceSnapshot,
    *,
    require_wave8_sequence: bool = True,
) -> dict[str, Any]:
    warnings: list[str] = []

    if not evidence.chain_valid:
        warnings.append("Repository evidence receipt chain is invalid.")

    if evidence.receipt_count == 0:
        warnings.append("Repository evidence snapshot contains no receipts.")

    if require_wave8_sequence and not evidence.require_event_sequence(
        WAVE8_REQUIRED_EVENT_SEQUENCE
    ):
        warnings.append("Repository evidence snapshot does not begin with the required Wave 8 event sequence.")

    receipt_digests = [receipt.digest for receipt in evidence.receipts]
    if len(receipt_digests) != len(set(receipt_digests)):
        warnings.append("Repository evidence snapshot contains duplicate receipt digests.")

    return {
        "valid": not warnings,
        "warnings": warnings,
        "run_id": evidence.run_id,
        "receipt_count": evidence.receipt_count,
        "chain_valid": evidence.chain_valid,
        "event_types": [event_type.value for event_type in evidence.event_types],
        "digest": evidence.digest,
    }


def repository_evidence_summary(
    evidence: RepositoryEvidenceSnapshot,
) -> dict[str, Any]:
    validation = validate_repository_evidence_snapshot(evidence)
    return {
        "run_id": evidence.run_id,
        "receipt_count": evidence.receipt_count,
        "chain_valid": evidence.chain_valid,
        "valid": validation["valid"],
        "event_types": [event_type.value for event_type in evidence.event_types],
        "digest": evidence.digest,
        "last_receipt_digest": (
            evidence.receipts[-1].digest if evidence.receipts else None
        ),
    }


def receipt_id_for_event(
    *,
    run_id: str,
    sequence_number: int,
    event_type: RepositoryEvidenceEventType,
) -> str:
    normalized_run_id = normalize_identifier(run_id, label="run_id")
    if sequence_number <= 0:
        raise ValueError("sequence_number must be greater than zero.")
    return normalize_identifier(
        f"{normalized_run_id}-{sequence_number:03d}-{event_type.value}",
        label="receipt_id",
    )
