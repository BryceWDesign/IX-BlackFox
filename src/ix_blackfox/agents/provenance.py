from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.agents.authorization import AgentAuthorizationDecision
from ix_blackfox.operating.models import (
    digest_payload,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


@dataclass(frozen=True, slots=True)
class AgentProvenanceRecord:
    """Tamper-evident record for one Wave 11 authorization decision."""

    record_id: str
    decision: AgentAuthorizationDecision
    recorded_at: str
    previous_chain_digest: str = ""
    evidence_artifact_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "record_id",
            normalize_identifier(self.record_id, label="record_id"),
        )
        object.__setattr__(
            self,
            "recorded_at",
            normalize_text(self.recorded_at, label="recorded_at"),
        )
        object.__setattr__(
            self,
            "previous_chain_digest",
            normalize_optional_text(
                self.previous_chain_digest,
                label="previous_chain_digest",
            ),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                (*self.decision.evidence_artifact_ids, *self.evidence_artifact_ids),
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def agent_id(self) -> str:
        return self.decision.request.agent_id

    @property
    def decision_digest(self) -> str:
        return self.decision.digest

    @property
    def record_digest(self) -> str:
        return digest_payload(self.to_dict(include_digests=False))

    @property
    def chain_digest(self) -> str:
        return digest_payload(
            {
                "record_digest": self.record_digest,
                "previous_chain_digest": self.previous_chain_digest,
            }
        )

    def to_dict(self, *, include_digests: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "record_id": self.record_id,
            "agent_id": self.agent_id,
            "request_id": self.decision.request.request_id,
            "decision_id": self.decision.decision_id,
            "decision_status": self.decision.status.value,
            "decision_reasons": [reason.value for reason in self.decision.reasons],
            "recorded_at": self.recorded_at,
            "previous_chain_digest": self.previous_chain_digest,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "metadata": dict(self.metadata),
        }
        if include_digests:
            payload["decision_digest"] = self.decision_digest
            payload["record_digest"] = self.record_digest
            payload["chain_digest"] = self.chain_digest
        return payload


@dataclass(frozen=True, slots=True)
class AgentProvenanceLedger:
    """Append-only authorization provenance chain."""

    ledger_id: str
    records: tuple[AgentProvenanceRecord, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ledger_id",
            normalize_identifier(self.ledger_id, label="ledger_id"),
        )
        _validate_chain(self.records)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def head_digest(self) -> str:
        if not self.records:
            return ""
        return self.records[-1].chain_digest

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def chain_valid(self) -> bool:
        try:
            _validate_chain(self.records)
        except ValueError:
            return False
        return True

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def append(
        self,
        decision: AgentAuthorizationDecision,
        *,
        recorded_at: str,
        evidence_artifact_ids: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AgentProvenanceLedger:
        record = AgentProvenanceRecord(
            record_id=build_provenance_record_id(decision, self.record_count),
            decision=decision,
            recorded_at=recorded_at,
            previous_chain_digest=self.head_digest,
            evidence_artifact_ids=tuple(evidence_artifact_ids),
            metadata={} if metadata is None else dict(metadata),
        )
        return AgentProvenanceLedger(
            ledger_id=self.ledger_id,
            records=(*self.records, record),
            metadata=self.metadata,
        )

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ledger_id": self.ledger_id,
            "record_count": self.record_count,
            "head_digest": self.head_digest,
            "chain_valid": self.chain_valid,
            "records": [record.to_dict() for record in self.records],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_provenance_record_id(
    decision: AgentAuthorizationDecision,
    sequence_index: int,
) -> str:
    """Build a deterministic provenance record id for one decision."""

    if sequence_index < 0:
        raise ValueError("sequence_index must be non-negative")
    digest = digest_payload(
        {
            "decision_digest": decision.digest,
            "sequence_index": sequence_index,
        }
    )
    return f"agent-prov-{digest[:24]}"


def _validate_chain(records: tuple[AgentProvenanceRecord, ...]) -> None:
    previous = ""
    seen_record_ids: set[str] = set()
    for record in records:
        if record.record_id in seen_record_ids:
            raise ValueError(f"duplicate provenance record id: {record.record_id}")
        if record.previous_chain_digest != previous:
            raise ValueError("provenance chain previous digest mismatch")
        seen_record_ids.add(record.record_id)
        previous = record.chain_digest
