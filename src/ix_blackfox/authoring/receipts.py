from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.models import AuthoringFinding, AuthoringFindingSeverity


class AuthoringReceiptEventType(StrEnum):
    """
    Auditable Wave 3 authoring event type.
    """

    REQUEST_CREATED = auto()
    CONTEXT_COLLECTED = auto()
    EVIDENCE_EXTRACTED = auto()
    DECOMPOSITION_CREATED = auto()
    HYPOTHESES_GENERATED = auto()
    HYPOTHESES_CREATED = auto()
    PROMPT_CONTRACT_RENDERED = auto()
    PROMPT_RENDERED = auto()
    MODEL_RESPONSE_RECEIVED = auto()
    PROPOSAL_RECEIVED = auto()
    RESPONSE_PARSED = auto()
    PROPOSAL_PARSED = auto()
    PROPOSAL_VALIDATED = auto()
    PROPOSAL_REJECTED = auto()
    PATCH_COMPILED = auto()
    POLICY_DECIDED = auto()
    POLICY_EVALUATED = auto()
    CANDIDATES_RANKED = auto()
    CANDIDATE_SELECTED = auto()
    CANDIDATE_REJECTED = auto()
    WAVE2_HANDOFF = auto()
    WAVE2_RESULT = auto()
    ACCEPTANCE_EVALUATED = auto()
    RUN_BLOCKED = auto()
    RUN_REQUIRES_REVIEW = auto()
    RUN_COMPLETED = auto()
    AUTHORING_FAILED = auto()
    RUN_FAILED = auto()


AuthoringReceiptEventKind = AuthoringReceiptEventType


class AuthoringReceiptStatus(StrEnum):
    """
    Review status for one authoring receipt.
    """

    RECORDED = auto()
    REJECTED = auto()
    BLOCKED = auto()
    FAILED = auto()


class AuthoringReceiptSeverity(StrEnum):
    """
    Compatibility severity label for Wave 3 receipts.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class AuthoringReceipt:
    """
    One immutable Wave 3 authoring receipt.

    The receipt supports both the original receipt contract used by the tests
    and the newer event-style runtime contract used by Wave 3 orchestration.
    """

    receipt_id: str
    event_type: AuthoringReceiptEventType
    status: AuthoringReceiptStatus
    subject_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    payload_digest: str | None = None
    parent_chain_digest: str | None = None
    recorded_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    summary: str = "Authoring receipt recorded."
    related_ids: Mapping[str, str] = field(default_factory=dict)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    receipt_digest: str | None = None
    chain_digest: str | None = None
    sequence_number: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_identifier(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "subject_id",
            _normalize_identifier(self.subject_id, label="subject_id"),
        )
        object.__setattr__(
            self,
            "summary",
            _normalize_text(self.summary, label="summary"),
        )
        if self.sequence_number < 1:
            raise ValueError("sequence_number must be 1 or greater.")

        recorded_at = self.recorded_at
        if recorded_at.tzinfo is None:
            recorded_at = recorded_at.replace(tzinfo=UTC)
        object.__setattr__(self, "recorded_at", recorded_at.astimezone(UTC))

        payload = dict(self.payload)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(
            self,
            "parent_chain_digest",
            _normalize_optional_sha256(self.parent_chain_digest),
        )
        object.__setattr__(
            self,
            "related_ids",
            _coerce_string_mapping(self.related_ids),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        computed_payload_digest = digest_payload(payload)
        if (
            self.payload_digest is not None
            and self.payload_digest != computed_payload_digest
        ):
            raise ValueError("payload_digest does not match payload.")
        object.__setattr__(self, "payload_digest", computed_payload_digest)

        computed_receipt_digest = digest_payload(self._receipt_digest_payload())
        if (
            self.receipt_digest is not None
            and self.receipt_digest != computed_receipt_digest
        ):
            raise ValueError("receipt_digest does not match receipt payload.")
        object.__setattr__(self, "receipt_digest", computed_receipt_digest)

        computed_chain_digest = digest_payload(
            {
                "parent_chain_digest": self.parent_chain_digest,
                "receipt_digest": computed_receipt_digest,
                "sequence_number": self.sequence_number,
            }
        )
        object.__setattr__(self, "chain_digest", computed_chain_digest)

    @classmethod
    def create(
        cls,
        *,
        event_kind: AuthoringReceiptEventType,
        severity: AuthoringReceiptSeverity,
        summary: str,
        run_id: str,
        task_id: str,
        sequence_number: int,
        previous_chain_digest: str | None,
        related_ids: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            receipt_id=f"authoring-receipt-{uuid4().hex}",
            event_type=event_kind,
            status=_status_from_severity(severity),
            subject_id=task_id,
            payload=dict(payload or {}),
            parent_chain_digest=previous_chain_digest,
            recorded_at=datetime.now(tz=UTC),
            summary=summary,
            related_ids={
                "run_id": run_id,
                "task_id": task_id,
                **dict(related_ids or {}),
            },
            findings=tuple(findings),
            metadata=dict(metadata or {}),
            sequence_number=sequence_number,
        )

    @property
    def event_kind(self) -> AuthoringReceiptEventType:
        return self.event_type

    @property
    def event_id(self) -> str:
        return self.receipt_id

    @property
    def run_id(self) -> str:
        return self.related_ids.get("run_id", "authoring-run")

    @property
    def task_id(self) -> str:
        return self.related_ids.get("task_id", self.subject_id)

    @property
    def previous_chain_digest(self) -> str | None:
        return self.parent_chain_digest

    @property
    def created_at(self) -> datetime:
        return self.recorded_at

    @property
    def severity(self) -> AuthoringReceiptSeverity:
        if self.status in {
            AuthoringReceiptStatus.BLOCKED,
            AuthoringReceiptStatus.FAILED,
        }:
            return AuthoringReceiptSeverity.ERROR
        if self.status is AuthoringReceiptStatus.REJECTED:
            return AuthoringReceiptSeverity.WARNING
        return AuthoringReceiptSeverity.INFO

    @property
    def has_error(self) -> bool:
        return self.status in {
            AuthoringReceiptStatus.BLOCKED,
            AuthoringReceiptStatus.FAILED,
        } or any(
            finding.severity is AuthoringFindingSeverity.ERROR
            for finding in self.findings
        )

    @property
    def has_warning(self) -> bool:
        return self.status is AuthoringReceiptStatus.REJECTED or any(
            finding.severity is AuthoringFindingSeverity.WARNING
            for finding in self.findings
        )

    def to_dict(self, *, include_chain_digest: bool = True) -> dict[str, Any]:
        payload = {
            "receipt_id": self.receipt_id,
            "event_type": self.event_type.value,
            "event_kind": self.event_type.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "subject_id": self.subject_id,
            "summary": self.summary,
            "payload": _jsonable(self.payload),
            "payload_digest": self.payload_digest,
            "receipt_digest": self.receipt_digest,
            "parent_chain_digest": self.parent_chain_digest,
            "previous_chain_digest": self.parent_chain_digest,
            "recorded_at": self.recorded_at.isoformat(),
            "created_at": self.recorded_at.isoformat(),
            "sequence_number": self.sequence_number,
            "related_ids": dict(self.related_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": _jsonable(dict(self.metadata)),
        }
        if include_chain_digest:
            payload["chain_digest"] = self.chain_digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            receipt_id=_require_text(payload, "receipt_id", fallback_key="event_id"),
            event_type=AuthoringReceiptEventType(
                _require_text(payload, "event_type", fallback_key="event_kind")
            ),
            status=AuthoringReceiptStatus(
                str(
                    payload.get("status")
                    or _status_from_severity_text(
                        str(payload.get("severity", "info"))
                    ).value
                )
            ),
            subject_id=str(
                payload.get("subject_id")
                or payload.get("task_id")
                or "authoring-task"
            ),
            payload=_coerce_mapping(payload.get("payload", {}), field_name="payload"),
            payload_digest=_optional_text_from_payload(payload, "payload_digest"),
            parent_chain_digest=_optional_text_from_payload(
                payload,
                "parent_chain_digest",
                fallback_key="previous_chain_digest",
            ),
            recorded_at=_datetime_from_payload(
                payload,
                "recorded_at",
                fallback_key="created_at",
            ),
            summary=str(payload.get("summary", "Authoring receipt recorded.")),
            related_ids=_coerce_string_mapping(payload.get("related_ids", {})),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
            receipt_digest=_optional_text_from_payload(payload, "receipt_digest"),
            chain_digest=_optional_text_from_payload(payload, "chain_digest"),
            sequence_number=_optional_int_from_payload(payload, "sequence_number") or 1,
        )

    def _receipt_digest_payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "event_type": self.event_type.value,
            "status": self.status.value,
            "subject_id": self.subject_id,
            "summary": self.summary,
            "payload_digest": self.payload_digest,
            "recorded_at": self.recorded_at.isoformat(),
            "sequence_number": self.sequence_number,
            "related_ids": dict(self.related_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": _jsonable(dict(self.metadata)),
        }


AuthoringReceiptEvent = AuthoringReceipt


@dataclass(frozen=True, slots=True)
class AuthoringReceiptSnapshot:
    """
    Immutable snapshot of a Wave 3 authoring receipt chain.
    """

    receipts: tuple[AuthoringReceipt, ...] = field(default_factory=tuple)
    run_id: str = "authoring-run"
    task_id: str = "authoring-task"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        receipts = tuple(self.receipts)
        object.__setattr__(self, "receipts", receipts)
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
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def events(self) -> tuple[AuthoringReceipt, ...]:
        return self.receipts

    @property
    def count(self) -> int:
        return len(self.receipts)

    @property
    def latest_chain_digest(self) -> str | None:
        if not self.receipts:
            return None
        return self.receipts[-1].chain_digest

    @property
    def event_kinds(self) -> tuple[str, ...]:
        return tuple(receipt.event_type.value for receipt in self.receipts)

    @property
    def has_errors(self) -> bool:
        return any(receipt.has_error for receipt in self.receipts)

    @property
    def has_warnings(self) -> bool:
        return any(receipt.has_warning for receipt in self.receipts)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def verify_chain(self) -> bool:
        expected_parent: str | None = None
        for receipt in self.receipts:
            if receipt.parent_chain_digest != expected_parent:
                return False
            expected_parent = receipt.chain_digest
        return True

    def filter_by_event(
        self,
        event_type: AuthoringReceiptEventType,
    ) -> tuple[AuthoringReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts if receipt.event_type is event_type
        )

    def filter_by_subject(self, subject_id: str) -> tuple[AuthoringReceipt, ...]:
        normalized = _normalize_identifier(subject_id, label="subject_id")
        return tuple(
            receipt for receipt in self.receipts if receipt.subject_id == normalized
        )

    def has_event(self, event_type: AuthoringReceiptEventType) -> bool:
        return bool(self.filter_by_event(event_type))

    def require_event(self, event_type: AuthoringReceiptEventType) -> AuthoringReceipt:
        matches = self.filter_by_event(event_type)
        if not matches:
            raise LookupError(
                f"Missing required authoring receipt event: {event_type.value}"
            )
        return matches[0]

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "count": self.count,
            "receipt_count": self.count,
            "latest_chain_digest": self.latest_chain_digest,
            "event_kinds": list(self.event_kinds),
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
            "events": [receipt.to_dict() for receipt in self.receipts],
            "metadata": _jsonable(dict(self.metadata)),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_receipts = payload.get("receipts", payload.get("events", ()))
        return cls(
            receipts=_load_receipts(raw_receipts),
            run_id=str(payload.get("run_id", "authoring-run")),
            task_id=str(payload.get("task_id", "authoring-task")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
        )


@dataclass(slots=True)
class AuthoringReceiptLedger:
    """
    Append-only in-memory Wave 3 authoring receipt ledger.
    """

    run_id: str = "authoring-run"
    task_id: str = "authoring-task"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    _receipts: list[AuthoringReceipt] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_id = _normalize_identifier(self.run_id, label="run_id")
        self.task_id = _normalize_identifier(self.task_id, label="task_id")
        self.metadata = dict(self.metadata)
        self._receipts = list(self._receipts)

    @property
    def receipts(self) -> tuple[AuthoringReceipt, ...]:
        return tuple(self._receipts)

    @property
    def events(self) -> tuple[AuthoringReceipt, ...]:
        return self.receipts

    @property
    def next_sequence_number(self) -> int:
        return len(self._receipts) + 1

    @property
    def latest_chain_digest(self) -> str | None:
        if not self._receipts:
            return None
        return self._receipts[-1].chain_digest

    def append(
        self,
        *,
        event_type: AuthoringReceiptEventType,
        subject_id: str,
        payload: Mapping[str, Any] | None = None,
        status: AuthoringReceiptStatus = AuthoringReceiptStatus.RECORDED,
        recorded_at: datetime | None = None,
        summary: str = "Authoring receipt recorded.",
        related_ids: Mapping[str, str] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        receipt = AuthoringReceipt(
            receipt_id=f"authoring-receipt-{uuid4().hex}",
            event_type=event_type,
            status=status,
            subject_id=subject_id,
            payload=dict(payload or {}),
            parent_chain_digest=self.latest_chain_digest,
            recorded_at=recorded_at or datetime.now(tz=UTC),
            summary=summary,
            related_ids={
                "run_id": self.run_id,
                "task_id": self.task_id,
                **dict(related_ids or {}),
            },
            findings=tuple(findings),
            metadata=dict(metadata or {}),
            sequence_number=self.next_sequence_number,
        )
        self._receipts.append(receipt)
        return receipt

    def record(
        self,
        *,
        event_kind: AuthoringReceiptEventType,
        summary: str,
        severity: AuthoringReceiptSeverity = AuthoringReceiptSeverity.INFO,
        related_ids: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=event_kind,
            subject_id=dict(related_ids or {}).get("request_id", self.task_id),
            payload=dict(payload or {}),
            status=_status_from_severity(severity),
            summary=summary,
            related_ids=related_ids,
            findings=findings,
            metadata=metadata,
        )

    def record_payload(
        self,
        *,
        event_kind: AuthoringReceiptEventType,
        summary: str,
        payload_object: Any,
        severity: AuthoringReceiptSeverity = AuthoringReceiptSeverity.INFO,
        related_ids: Mapping[str, str] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.record(
            event_kind=event_kind,
            severity=severity,
            summary=summary,
            related_ids=related_ids,
            payload=_payload_from_object(payload_object),
            findings=findings,
            metadata=metadata,
        )

    def record_context_collected(
        self,
        *,
        request_id: str,
        snapshot: Any,
    ) -> AuthoringReceipt:
        context = getattr(snapshot, "context", None)
        context_digest = getattr(context, "digest", None)
        metadata = {"context_digest": context_digest} if context_digest is not None else {}
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.CONTEXT_COLLECTED,
            summary="Bounded Wave 3 repository context was collected.",
            payload_object=snapshot,
            related_ids={"request_id": request_id},
            metadata=metadata,
        )

    def record_evidence_extracted(
        self,
        *,
        request_id: str,
        report: Any,
    ) -> AuthoringReceipt:
        evidence = getattr(report, "evidence", None)
        strength = getattr(evidence, "strength", None)
        strength_value = getattr(strength, "value", None)
        metadata = (
            {"evidence_strength": strength_value}
            if strength_value is not None
            else {}
        )
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.EVIDENCE_EXTRACTED,
            summary="Wave 3 failure evidence was extracted.",
            payload_object=report,
            related_ids={"request_id": request_id},
            metadata=metadata,
        )

    def record_decomposition_created(
        self,
        *,
        request_id: str,
        plan: Any,
    ) -> AuthoringReceipt:
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.DECOMPOSITION_CREATED,
            summary="Wave 3 repair task decomposition was created.",
            payload_object=plan,
            related_ids={"request_id": request_id},
        )

    def record_hypotheses_generated(
        self,
        *,
        request_id: str,
        report: Any,
    ) -> AuthoringReceipt:
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.HYPOTHESES_GENERATED,
            summary="Wave 3 repair hypotheses were generated.",
            payload_object=report,
            related_ids={"request_id": request_id},
        )

    def record_prompt_contract_rendered(
        self,
        *,
        request_id: str,
        contract: Any,
    ) -> AuthoringReceipt:
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.PROMPT_CONTRACT_RENDERED,
            summary="Wave 3 patch-authoring prompt contract was rendered.",
            payload_object=contract,
            related_ids={"request_id": request_id},
        )

    def record_model_response_received(
        self,
        *,
        request_id: str,
        raw_response: str,
        provider_name: str | None = None,
        model_name: str | None = None,
    ) -> AuthoringReceipt:
        raw_digest = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
        return self.record(
            event_kind=AuthoringReceiptEventType.MODEL_RESPONSE_RECEIVED,
            summary="Untrusted Wave 3 proposal response was received.",
            related_ids={"request_id": request_id},
            payload={
                "raw_response_digest": raw_digest,
                "raw_response_chars": len(raw_response),
                "provider_name": provider_name,
                "model_name": model_name,
            },
            metadata={"raw_response_digest": raw_digest},
        )

    def record_response_parsed(
        self,
        *,
        request_id: str,
        proposal: Any,
    ) -> AuthoringReceipt:
        findings = tuple(getattr(proposal, "findings", ()))
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.RESPONSE_PARSED,
            summary="Wave 3 proposal response parsed into a strict contract.",
            payload_object=proposal,
            related_ids={
                "request_id": request_id,
                "proposal_id": str(getattr(proposal, "proposal_id", "unknown")),
            },
            findings=findings,
            severity=receipt_severity_from_findings(findings),
        )

    def record_proposal_validated(
        self,
        *,
        request_id: str,
        proposal: Any,
    ) -> AuthoringReceipt:
        findings = tuple(getattr(proposal, "findings", ()))
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.PROPOSAL_VALIDATED,
            summary="Wave 3 proposal passed parser-level validation.",
            payload_object=proposal,
            related_ids={
                "request_id": request_id,
                "proposal_id": str(getattr(proposal, "proposal_id", "unknown")),
            },
            findings=findings,
            severity=receipt_severity_from_findings(findings),
        )

    def record_patch_compiled(
        self,
        *,
        request_id: str,
        candidate: Any,
    ) -> AuthoringReceipt:
        findings = tuple(
            finding.to_authoring_finding()
            for finding in getattr(candidate, "findings", ())
            if hasattr(finding, "to_authoring_finding")
        )
        candidate_id = str(getattr(candidate, "candidate_id", "unknown"))
        return self.record_payload(
            event_kind=AuthoringReceiptEventType.PATCH_COMPILED,
            summary="Wave 3 proposal compiled into a governed PatchDiff candidate.",
            payload_object=candidate,
            related_ids={
                "request_id": request_id,
                "candidate_id": candidate_id,
                "proposal_id": str(getattr(candidate, "proposal_id", "unknown")),
            },
            findings=findings,
            severity=receipt_severity_from_findings(findings),
            metadata={"candidate_id": candidate_id},
        )

    def record_policy_decided(
        self,
        *,
        request_id: str,
        report: Any,
    ) -> AuthoringReceipt:
        findings = tuple(getattr(report, "authoring_findings", ()))
        decision = getattr(report, "decision", None)
        decision_value = str(getattr(decision, "value", decision or "unknown"))
        status = AuthoringReceiptStatus.RECORDED
        if decision_value == "block":
            status = AuthoringReceiptStatus.BLOCKED
        elif decision_value == "require_review":
            status = AuthoringReceiptStatus.REJECTED
        return self.append(
            event_type=AuthoringReceiptEventType.POLICY_DECIDED,
            subject_id=request_id,
            payload=_payload_from_object(report),
            status=status,
            summary="Wave 3 authoring policy gate evaluated a candidate.",
            related_ids={
                "request_id": request_id,
                "policy_report_id": str(getattr(report, "report_id", "unknown")),
                "proposal_id": str(getattr(report, "proposal_id", "unknown")),
            },
            findings=findings,
            metadata={"policy_decision": decision_value},
        )

    def record_candidate_selected(
        self,
        *,
        request_id: str,
        selected_candidate_id: str,
        candidate_ids: Iterable[str],
        selection_reason: str,
    ) -> AuthoringReceipt:
        candidate_id_tuple = tuple(candidate_ids)
        if selected_candidate_id not in candidate_id_tuple:
            raise ValueError("selected_candidate_id must be present in candidate_ids.")
        return self.append(
            event_type=AuthoringReceiptEventType.CANDIDATE_SELECTED,
            subject_id=request_id,
            payload={
                "selected_candidate_id": selected_candidate_id,
                "candidate_ids": list(candidate_id_tuple),
                "selection_reason": selection_reason,
            },
            summary="Wave 3 candidate was selected for governed Wave 2 handoff.",
            related_ids={
                "request_id": request_id,
                "selected_candidate_id": selected_candidate_id,
            },
            metadata={"selected_candidate_id": selected_candidate_id},
        )

    def record_candidate_rejected(
        self,
        *,
        request_id: str,
        candidate_id: str,
        rejection_phase: str,
        rejection_reason: str,
        proposal_digest: str | None = None,
        affected_paths: Iterable[str] = (),
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.CANDIDATE_REJECTED,
            subject_id=request_id,
            payload={
                "candidate_id": candidate_id,
                "rejection_phase": rejection_phase,
                "rejection_reason": rejection_reason,
                "proposal_digest": proposal_digest,
                "affected_paths": list(affected_paths),
            },
            status=AuthoringReceiptStatus.REJECTED,
            summary="Wave 3 candidate was rejected before Wave 2 handoff.",
            related_ids={"request_id": request_id, "candidate_id": candidate_id},
            metadata={"candidate_id": candidate_id, "rejection_phase": rejection_phase},
        )

    def record_authoring_failed(
        self,
        *,
        request_id: str,
        failure_phase: str,
        failure_reason: str,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.AUTHORING_FAILED,
            subject_id=request_id,
            payload={"failure_phase": failure_phase, "failure_reason": failure_reason},
            status=AuthoringReceiptStatus.FAILED,
            summary="Wave 3 authoring failed before a governed handoff.",
            related_ids={"request_id": request_id},
            metadata={"failure_phase": failure_phase},
        )

    def snapshot(self) -> AuthoringReceiptSnapshot:
        return AuthoringReceiptSnapshot(
            receipts=tuple(self._receipts),
            run_id=self.run_id,
            task_id=self.task_id,
            metadata={"ledger": "AuthoringReceiptLedger", **dict(self.metadata)},
        )

    def clear(self) -> None:
        self._receipts.clear()

    def to_dict(self) -> dict[str, Any]:
        return self.snapshot().to_dict()


def receipt_severity_from_findings(
    findings: Iterable[AuthoringFinding],
) -> AuthoringReceiptSeverity:
    finding_tuple = tuple(findings)
    if any(
        finding.severity is AuthoringFindingSeverity.ERROR
        for finding in finding_tuple
    ):
        return AuthoringReceiptSeverity.ERROR
    if any(
        finding.severity is AuthoringFindingSeverity.WARNING
        for finding in finding_tuple
    ):
        return AuthoringReceiptSeverity.WARNING
    return AuthoringReceiptSeverity.INFO


def digest_payload(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _payload_from_object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)

    to_manifest_dict = getattr(value, "to_manifest_dict", None)
    if callable(to_manifest_dict):
        payload = to_manifest_dict()
        if isinstance(payload, Mapping):
            return dict(payload)

    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return dict(payload)

    return {"value": _jsonable(value)}


def _load_findings(value: Any) -> tuple[AuthoringFinding, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("findings must be an iterable of mappings.")

    findings: list[AuthoringFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(AuthoringFinding.from_dict(item))
    return tuple(findings)


def _load_receipts(value: Any) -> tuple[AuthoringReceipt, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("receipts must be an iterable of mappings.")

    receipts: list[AuthoringReceipt] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("receipts must contain only mappings.")
        receipts.append(AuthoringReceipt.from_dict(item))
    return tuple(receipts)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(nested) for key, nested in value.items()}
    if isinstance(value, tuple | list):
        return [_jsonable(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(_jsonable(item) for item in value)
    return value


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        _jsonable(dict(payload)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "_")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _datetime_from_payload(
    payload: Mapping[str, Any],
    key: str,
    *,
    fallback_key: str | None = None,
) -> datetime:
    value = payload.get(key)
    if value is None and fallback_key is not None:
        value = payload.get(fallback_key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be an ISO datetime string.")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_string_mapping(value: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise TypeError("related_ids must map strings to strings.")
        result[key] = item
    return result


def _require_text(
    payload: Mapping[str, Any],
    key: str,
    *,
    fallback_key: str | None = None,
) -> str:
    value = payload.get(key)
    if value is None and fallback_key is not None:
        value = payload.get(fallback_key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value


def _optional_int_from_payload(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer or None.")
    return value


def _optional_text_from_payload(
    payload: Mapping[str, Any],
    key: str,
    *,
    fallback_key: str | None = None,
) -> str | None:
    value = payload.get(key)
    if value is None and fallback_key is not None:
        value = payload.get(fallback_key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _status_from_severity(severity: AuthoringReceiptSeverity) -> AuthoringReceiptStatus:
    if severity is AuthoringReceiptSeverity.ERROR:
        return AuthoringReceiptStatus.FAILED
    if severity is AuthoringReceiptSeverity.WARNING:
        return AuthoringReceiptStatus.REJECTED
    return AuthoringReceiptStatus.RECORDED


def _status_from_severity_text(value: str) -> AuthoringReceiptStatus:
    try:
        return _status_from_severity(AuthoringReceiptSeverity(value))
    except ValueError:
        return AuthoringReceiptStatus.RECORDED
