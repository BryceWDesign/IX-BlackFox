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


class AuthoringReceiptEventKind(StrEnum):
    """
    Auditable Wave 3 authoring event kind.
    """

    REQUEST_CREATED = auto()
    CONTEXT_COLLECTED = auto()
    EVIDENCE_EXTRACTED = auto()
    DECOMPOSITION_CREATED = auto()
    HYPOTHESES_CREATED = auto()
    PROMPT_RENDERED = auto()
    MODEL_RESPONSE_RECEIVED = auto()
    PROPOSAL_RECEIVED = auto()
    PROPOSAL_PARSED = auto()
    PROPOSAL_VALIDATED = auto()
    PROPOSAL_REJECTED = auto()
    PATCH_COMPILED = auto()
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
    RUN_FAILED = auto()


class AuthoringReceiptSeverity(StrEnum):
    """
    Receipt event severity for review and evidence bundles.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class AuthoringReceiptEvent:
    """
    One immutable Wave 3 authoring receipt event.
    """

    event_id: str
    event_kind: AuthoringReceiptEventKind
    severity: AuthoringReceiptSeverity
    summary: str
    created_at: datetime
    run_id: str
    task_id: str
    sequence_number: int
    previous_chain_digest: str | None = None
    payload_digest: str | None = None
    chain_digest: str | None = None
    related_ids: Mapping[str, str] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "event_id", _normalize_identifier(self.event_id, label="event_id")
        )
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(
            self, "run_id", _normalize_identifier(self.run_id, label="run_id")
        )
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        if self.sequence_number < 1:
            raise ValueError("sequence_number must be 1 or greater.")

        created_at = self.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        object.__setattr__(self, "created_at", created_at.astimezone(UTC))

        related_ids = {
            _normalize_token(key, label="related_id_key"): _normalize_text(
                value, label="related_id_value"
            )
            for key, value in self.related_ids.items()
        }
        object.__setattr__(self, "related_ids", related_ids)
        object.__setattr__(self, "payload", dict(self.payload))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))
        object.__setattr__(
            self,
            "previous_chain_digest",
            _normalize_optional_sha256(self.previous_chain_digest),
        )

        payload_digest = self.payload_digest or _sha256_json(self._payload_for_digest())
        object.__setattr__(self, "payload_digest", _normalize_sha256(payload_digest))

        chain_digest = self.chain_digest or _sha256_json(self._chain_payload())
        object.__setattr__(self, "chain_digest", _normalize_sha256(chain_digest))

    @classmethod
    def create(
        cls,
        *,
        event_kind: AuthoringReceiptEventKind,
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
            event_id=f"authoring-receipt-{uuid4().hex}",
            event_kind=event_kind,
            severity=severity,
            summary=summary,
            created_at=datetime.now(tz=UTC),
            run_id=run_id,
            task_id=task_id,
            sequence_number=sequence_number,
            previous_chain_digest=previous_chain_digest,
            related_ids=dict(related_ids or {}),
            payload=dict(payload or {}),
            findings=tuple(findings),
            metadata=dict(metadata or {}),
        )

    @property
    def has_error(self) -> bool:
        return self.severity is AuthoringReceiptSeverity.ERROR or any(
            finding.severity is AuthoringFindingSeverity.ERROR
            for finding in self.findings
        )

    @property
    def has_warning(self) -> bool:
        return self.severity is AuthoringReceiptSeverity.WARNING or any(
            finding.severity is AuthoringFindingSeverity.WARNING
            for finding in self.findings
        )

    def to_dict(self, *, include_chain_digest: bool = True) -> dict[str, Any]:
        payload = {
            "event_id": self.event_id,
            "event_kind": self.event_kind.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "created_at": self.created_at.isoformat(),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "sequence_number": self.sequence_number,
            "previous_chain_digest": self.previous_chain_digest,
            "payload_digest": self.payload_digest,
            "related_ids": dict(self.related_ids),
            "payload": _jsonable(self.payload),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": _jsonable(dict(self.metadata)),
        }
        if include_chain_digest:
            payload["chain_digest"] = self.chain_digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            event_id=_require_text(payload, "event_id"),
            event_kind=AuthoringReceiptEventKind(_require_text(payload, "event_kind")),
            severity=AuthoringReceiptSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            created_at=_datetime_from_payload(payload, "created_at"),
            run_id=_require_text(payload, "run_id"),
            task_id=_require_text(payload, "task_id"),
            sequence_number=_require_int(payload, "sequence_number"),
            previous_chain_digest=_optional_text_from_payload(
                payload, "previous_chain_digest"
            ),
            payload_digest=_optional_text_from_payload(payload, "payload_digest"),
            chain_digest=_optional_text_from_payload(payload, "chain_digest"),
            related_ids=_coerce_string_mapping(
                payload.get("related_ids", {}),
                field_name="related_ids",
            ),
            payload=_coerce_mapping(payload.get("payload", {}), field_name="payload"),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )

    def _payload_for_digest(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_kind": self.event_kind.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "created_at": self.created_at.isoformat(),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "sequence_number": self.sequence_number,
            "related_ids": dict(self.related_ids),
            "payload": _jsonable(self.payload),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": _jsonable(dict(self.metadata)),
        }

    def _chain_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "previous_chain_digest": self.previous_chain_digest,
            "payload_digest": self.payload_digest,
        }


@dataclass(frozen=True, slots=True)
class AuthoringReceiptSnapshot:
    """
    Immutable snapshot of a Wave 3 receipt chain.
    """

    run_id: str
    task_id: str
    events: tuple[AuthoringReceiptEvent, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "run_id", _normalize_identifier(self.run_id, label="run_id")
        )
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "metadata", dict(self.metadata))
        self._validate_chain()

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def latest_chain_digest(self) -> str | None:
        if not self.events:
            return None
        return self.events[-1].chain_digest

    @property
    def event_kinds(self) -> tuple[str, ...]:
        return tuple(event.event_kind.value for event in self.events)

    @property
    def has_errors(self) -> bool:
        return any(event.has_error for event in self.events)

    @property
    def has_warnings(self) -> bool:
        return any(event.has_warning for event in self.events)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def verify_chain(self) -> bool:
        try:
            self._validate_chain()
        except ValueError:
            return False
        return True

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "count": self.count,
            "latest_chain_digest": self.latest_chain_digest,
            "event_kinds": list(self.event_kinds),
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
            "events": [event.to_dict() for event in self.events],
            "metadata": _jsonable(dict(self.metadata)),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            run_id=_require_text(payload, "run_id"),
            task_id=_require_text(payload, "task_id"),
            events=_load_events(payload.get("events", ())),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )

    def _validate_chain(self) -> None:
        expected_previous: str | None = None

        for expected_sequence, event in enumerate(self.events, start=1):
            if event.run_id != self.run_id:
                raise ValueError("Receipt event run_id does not match snapshot run_id.")
            if event.task_id != self.task_id:
                raise ValueError(
                    "Receipt event task_id does not match snapshot task_id."
                )
            if event.sequence_number != expected_sequence:
                raise ValueError("Receipt sequence numbers must be contiguous.")
            if event.previous_chain_digest != expected_previous:
                raise ValueError(
                    "Receipt event previous_chain_digest does not match chain."
                )
            expected_previous = event.chain_digest


@dataclass(slots=True)
class AuthoringReceiptLedger:
    """
    Append-only in-memory Wave 3 authoring receipt ledger.
    """

    run_id: str = "authoring-run"
    task_id: str = "authoring-task"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    _events: list[AuthoringReceiptEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_id = _normalize_identifier(self.run_id, label="run_id")
        self.task_id = _normalize_identifier(self.task_id, label="task_id")
        self.metadata = dict(self.metadata)
        self._events = list(self._events)

    @property
    def events(self) -> tuple[AuthoringReceiptEvent, ...]:
        return tuple(self._events)

    @property
    def next_sequence_number(self) -> int:
        return len(self._events) + 1

    @property
    def latest_chain_digest(self) -> str | None:
        if not self._events:
            return None
        return self._events[-1].chain_digest

    def record(
        self,
        *,
        event_kind: AuthoringReceiptEventKind,
        summary: str,
        severity: AuthoringReceiptSeverity = AuthoringReceiptSeverity.INFO,
        related_ids: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceiptEvent:
        event = AuthoringReceiptEvent.create(
            event_kind=event_kind,
            severity=severity,
            summary=summary,
            run_id=self.run_id,
            task_id=self.task_id,
            sequence_number=self.next_sequence_number,
            previous_chain_digest=self.latest_chain_digest,
            related_ids=dict(related_ids or {}),
            payload=dict(payload or {}),
            findings=tuple(findings),
            metadata=dict(metadata or {}),
        )
        self._events.append(event)
        return event

    def record_payload(
        self,
        *,
        event_kind: AuthoringReceiptEventKind,
        summary: str,
        payload_object: Any,
        severity: AuthoringReceiptSeverity = AuthoringReceiptSeverity.INFO,
        related_ids: Mapping[str, str] | None = None,
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceiptEvent:
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
        self, *, request_id: str, snapshot: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.CONTEXT_COLLECTED,
            summary="Bounded Wave 3 repository context was collected.",
            payload_object=snapshot,
            related_ids={"request_id": request_id},
        )

    def record_evidence_extracted(
        self, *, request_id: str, report: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.EVIDENCE_EXTRACTED,
            summary="Wave 3 failure evidence was extracted.",
            payload_object=report,
            related_ids={"request_id": request_id},
        )

    def record_decomposition_created(
        self, *, request_id: str, plan: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.DECOMPOSITION_CREATED,
            summary="Wave 3 repair task decomposition was created.",
            payload_object=plan,
            related_ids={"request_id": request_id},
        )

    def record_hypotheses_generated(
        self, *, request_id: str, report: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.HYPOTHESES_CREATED,
            summary="Wave 3 repair hypotheses were generated.",
            payload_object=report,
            related_ids={"request_id": request_id},
        )

    def record_prompt_contract_rendered(
        self, *, request_id: str, contract: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.PROMPT_RENDERED,
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
    ) -> AuthoringReceiptEvent:
        digest = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
        return self.record(
            event_kind=AuthoringReceiptEventKind.MODEL_RESPONSE_RECEIVED,
            summary="Untrusted Wave 3 proposal response was received.",
            related_ids={"request_id": request_id},
            payload={
                "raw_response_digest": digest,
                "raw_response_chars": len(raw_response),
                "provider_name": provider_name,
                "model_name": model_name,
            },
        )

    def record_response_parsed(
        self, *, request_id: str, proposal: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.PROPOSAL_PARSED,
            summary="Wave 3 proposal response parsed into a strict contract.",
            payload_object=proposal,
            related_ids={
                "request_id": request_id,
                "proposal_id": str(getattr(proposal, "proposal_id", "unknown")),
            },
            findings=tuple(getattr(proposal, "findings", ())),
        )

    def record_proposal_validated(
        self, *, request_id: str, proposal: Any
    ) -> AuthoringReceiptEvent:
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.PROPOSAL_VALIDATED,
            summary="Wave 3 proposal passed parser-level validation.",
            payload_object=proposal,
            related_ids={
                "request_id": request_id,
                "proposal_id": str(getattr(proposal, "proposal_id", "unknown")),
            },
            findings=tuple(getattr(proposal, "findings", ())),
        )

    def record_patch_compiled(
        self, *, request_id: str, candidate: Any
    ) -> AuthoringReceiptEvent:
        findings = tuple(
            finding.to_authoring_finding()
            for finding in getattr(candidate, "findings", ())
            if hasattr(finding, "to_authoring_finding")
        )
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.PATCH_COMPILED,
            summary="Wave 3 proposal compiled into a governed PatchDiff candidate.",
            payload_object=candidate,
            related_ids={
                "request_id": request_id,
                "candidate_id": str(getattr(candidate, "candidate_id", "unknown")),
                "proposal_id": str(getattr(candidate, "proposal_id", "unknown")),
            },
            findings=findings,
            severity=receipt_severity_from_findings(findings),
        )

    def record_policy_decided(
        self, *, request_id: str, report: Any
    ) -> AuthoringReceiptEvent:
        findings = tuple(getattr(report, "authoring_findings", ()))
        return self.record_payload(
            event_kind=AuthoringReceiptEventKind.POLICY_EVALUATED,
            summary="Wave 3 authoring policy gate evaluated a candidate.",
            payload_object=report,
            related_ids={
                "request_id": request_id,
                "policy_report_id": str(getattr(report, "report_id", "unknown")),
                "proposal_id": str(getattr(report, "proposal_id", "unknown")),
            },
            findings=findings,
            severity=receipt_severity_from_findings(findings),
        )

    def record_candidate_selected(
        self,
        *,
        request_id: str,
        selected_candidate_id: str,
        candidate_ids: Iterable[str],
        selection_reason: str,
    ) -> AuthoringReceiptEvent:
        return self.record(
            event_kind=AuthoringReceiptEventKind.CANDIDATE_SELECTED,
            summary="Wave 3 candidate was selected for governed Wave 2 handoff.",
            related_ids={
                "request_id": request_id,
                "selected_candidate_id": selected_candidate_id,
            },
            payload={
                "selected_candidate_id": selected_candidate_id,
                "candidate_ids": list(candidate_ids),
                "selection_reason": selection_reason,
            },
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
    ) -> AuthoringReceiptEvent:
        return self.record(
            event_kind=AuthoringReceiptEventKind.CANDIDATE_REJECTED,
            severity=AuthoringReceiptSeverity.WARNING,
            summary="Wave 3 candidate was rejected before Wave 2 handoff.",
            related_ids={
                "request_id": request_id,
                "candidate_id": candidate_id,
            },
            payload={
                "candidate_id": candidate_id,
                "rejection_phase": rejection_phase,
                "rejection_reason": rejection_reason,
                "proposal_digest": proposal_digest,
                "affected_paths": list(affected_paths),
            },
        )

    def record_authoring_failed(
        self,
        *,
        request_id: str,
        failure_phase: str,
        failure_reason: str,
    ) -> AuthoringReceiptEvent:
        return self.record(
            event_kind=AuthoringReceiptEventKind.RUN_FAILED,
            severity=AuthoringReceiptSeverity.ERROR,
            summary="Wave 3 authoring failed before a governed handoff.",
            related_ids={"request_id": request_id},
            payload={
                "failure_phase": failure_phase,
                "failure_reason": failure_reason,
            },
        )

    def snapshot(self) -> AuthoringReceiptSnapshot:
        return AuthoringReceiptSnapshot(
            run_id=self.run_id,
            task_id=self.task_id,
            events=tuple(self._events),
            metadata={
                "ledger": "AuthoringReceiptLedger",
                **dict(self.metadata),
            },
        )

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


def _load_events(value: Any) -> tuple[AuthoringReceiptEvent, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("events must be an iterable of mappings.")

    events: list[AuthoringReceiptEvent] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("events must contain only mappings.")
        events.append(AuthoringReceiptEvent.from_dict(item))
    return tuple(events)


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


def _sha256_json(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        _jsonable(dict(payload)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


def _datetime_from_payload(payload: Mapping[str, Any], key: str) -> datetime:
    value = payload.get(key)
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


def _coerce_string_mapping(value: Any, *, field_name: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")

    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise TypeError(f"{field_name} must map strings to strings.")
        result[key] = item

    return result


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
