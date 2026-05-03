from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from threading import RLock
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.context import AuthoringContextSnapshot
from ix_blackfox.authoring.decomposition import RepairDecompositionPlan
from ix_blackfox.authoring.failure_evidence import FailureEvidenceReport
from ix_blackfox.authoring.hypotheses import RepairHypothesisReport
from ix_blackfox.authoring.patch_compiler import CompiledPatchCandidate
from ix_blackfox.authoring.policy import AuthoringPolicyReport
from ix_blackfox.authoring.prompt_contract import PatchAuthoringPromptContract
from ix_blackfox.authoring.response_parser import PatchAuthoringProposal


class AuthoringReceiptEventType(StrEnum):
    """
    Wave 3 authoring receipt event types.

    These events cover the authoring trust surface before a candidate reaches
    the existing Wave 2 patch-test-verify runtime.
    """

    CONTEXT_COLLECTED = auto()
    EVIDENCE_EXTRACTED = auto()
    DECOMPOSITION_CREATED = auto()
    HYPOTHESES_GENERATED = auto()
    PROMPT_CONTRACT_RENDERED = auto()
    MODEL_RESPONSE_RECEIVED = auto()
    RESPONSE_PARSED = auto()
    PROPOSAL_VALIDATED = auto()
    PATCH_COMPILED = auto()
    POLICY_DECIDED = auto()
    CANDIDATE_SELECTED = auto()
    CANDIDATE_REJECTED = auto()
    AUTHORING_FAILED = auto()


class AuthoringReceiptStatus(StrEnum):
    """
    Status attached to one Wave 3 authoring receipt.
    """

    RECORDED = auto()
    REJECTED = auto()
    BLOCKED = auto()
    FAILED = auto()


@dataclass(frozen=True, slots=True)
class AuthoringReceipt:
    """
    Immutable auditable record for one Wave 3 authoring event.

    The receipt stores a canonical payload digest, a parent chain digest, and a
    receipt digest. This makes the authoring event sequence reviewable without
    pretending to be a complete supply-chain signing system.
    """

    receipt_id: str
    event_type: AuthoringReceiptEventType
    status: AuthoringReceiptStatus
    subject_id: str
    payload: Mapping[str, Any]
    payload_digest: str
    parent_chain_digest: str | None
    recorded_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)

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
        payload = dict(self.payload)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "payload_digest", _normalize_sha256(self.payload_digest))
        object.__setattr__(
            self,
            "parent_chain_digest",
            _normalize_optional_sha256(self.parent_chain_digest),
        )
        object.__setattr__(self, "recorded_at", _normalize_datetime(self.recorded_at))
        object.__setattr__(self, "metadata", dict(self.metadata))

        computed_payload_digest = digest_payload(payload)
        if computed_payload_digest != self.payload_digest:
            raise ValueError(
                "payload_digest does not match the canonical payload digest."
            )

    @property
    def receipt_digest(self) -> str:
        """
        Digest of this receipt excluding the derived receipt_digest field itself.
        """
        return digest_payload(self._digest_payload())

    @property
    def chain_digest(self) -> str:
        """
        Digest chaining the parent chain digest and this receipt digest.
        """
        return digest_payload(
            {
                "parent_chain_digest": self.parent_chain_digest,
                "receipt_digest": self.receipt_digest,
            }
        )

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "event_type": self.event_type.value,
            "status": self.status.value,
            "subject_id": self.subject_id,
            "payload": dict(self.payload),
            "payload_digest": self.payload_digest,
            "parent_chain_digest": self.parent_chain_digest,
            "recorded_at": self.recorded_at.isoformat(),
            "metadata": dict(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._digest_payload()
        payload["receipt_digest"] = self.receipt_digest
        payload["chain_digest"] = self.chain_digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_payload = payload.get("payload")
        if not isinstance(raw_payload, Mapping):
            raise TypeError("payload must be a mapping.")

        return cls(
            receipt_id=_require_text(payload, "receipt_id"),
            event_type=AuthoringReceiptEventType(_require_text(payload, "event_type")),
            status=AuthoringReceiptStatus(_require_text(payload, "status")),
            subject_id=_require_text(payload, "subject_id"),
            payload=dict(raw_payload),
            payload_digest=_require_text(payload, "payload_digest"),
            parent_chain_digest=_optional_text_from_payload(payload, "parent_chain_digest"),
            recorded_at=_datetime_from_payload(payload, "recorded_at"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class AuthoringReceiptSnapshot:
    """
    Immutable view of Wave 3 authoring receipts.
    """

    receipts: tuple[AuthoringReceipt, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipts", tuple(self.receipts))

    @property
    def count(self) -> int:
        return len(self.receipts)

    @property
    def latest_chain_digest(self) -> str | None:
        if not self.receipts:
            return None
        return self.receipts[-1].chain_digest

    @property
    def event_types(self) -> tuple[AuthoringReceiptEventType, ...]:
        return tuple(receipt.event_type for receipt in self.receipts)

    @property
    def subject_ids(self) -> tuple[str, ...]:
        subject_ids: list[str] = []
        seen: set[str] = set()

        for receipt in self.receipts:
            if receipt.subject_id in seen:
                continue
            seen.add(receipt.subject_id)
            subject_ids.append(receipt.subject_id)

        return tuple(subject_ids)

    def filter_by_event(
        self,
        event_type: AuthoringReceiptEventType,
    ) -> tuple[AuthoringReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts if receipt.event_type is event_type
        )

    def filter_by_subject(self, subject_id: str) -> tuple[AuthoringReceipt, ...]:
        normalized_subject_id = _normalize_identifier(subject_id, label="subject_id")
        return tuple(
            receipt
            for receipt in self.receipts
            if receipt.subject_id == normalized_subject_id
        )

    def require_event(self, event_type: AuthoringReceiptEventType) -> AuthoringReceipt:
        matches = self.filter_by_event(event_type)
        if not matches:
            raise LookupError(f"Missing required authoring receipt event: {event_type.value}")
        return matches[-1]

    def has_event(self, event_type: AuthoringReceiptEventType) -> bool:
        return bool(self.filter_by_event(event_type))

    def verify_chain(self) -> bool:
        parent: str | None = None

        for receipt in self.receipts:
            if receipt.parent_chain_digest != parent:
                return False
            if receipt.payload_digest != digest_payload(dict(receipt.payload)):
                return False
            parent = receipt.chain_digest

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "latest_chain_digest": self.latest_chain_digest,
            "event_types": [event_type.value for event_type in self.event_types],
            "subject_ids": list(self.subject_ids),
            "chain_valid": self.verify_chain(),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_receipts = payload.get("receipts", ())
        if isinstance(raw_receipts, str) or not isinstance(raw_receipts, Iterable):
            raise TypeError("receipts must be an iterable of mappings.")

        receipts: list[AuthoringReceipt] = []
        for raw_receipt in raw_receipts:
            if not isinstance(raw_receipt, Mapping):
                raise TypeError("receipts must contain only mappings.")
            receipts.append(AuthoringReceipt.from_dict(raw_receipt))

        return cls(receipts=tuple(receipts))


class AuthoringReceiptLedger:
    """
    Thread-safe ledger for Wave 3 authoring receipts.

    The ledger is intentionally local and deterministic. It does not replace
    runtime or tool receipts. It records the authoring path that produced,
    rejected, selected, compiled, or policy-gated patch candidates.
    """

    def __init__(self) -> None:
        self._receipts: list[AuthoringReceipt] = []
        self._lock = RLock()

    def append(
        self,
        *,
        event_type: AuthoringReceiptEventType,
        subject_id: str,
        payload: Mapping[str, Any],
        status: AuthoringReceiptStatus = AuthoringReceiptStatus.RECORDED,
        recorded_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        """
        Append a raw authoring receipt event.
        """
        normalized_payload = dict(payload)
        with self._lock:
            parent_chain_digest = (
                None if not self._receipts else self._receipts[-1].chain_digest
            )
            receipt = AuthoringReceipt(
                receipt_id=f"authoring-receipt-{uuid4().hex}",
                event_type=event_type,
                status=status,
                subject_id=subject_id,
                payload=normalized_payload,
                payload_digest=digest_payload(normalized_payload),
                parent_chain_digest=parent_chain_digest,
                recorded_at=recorded_at or datetime.now(tz=UTC),
                metadata=dict(metadata or {}),
            )
            self._receipts.append(receipt)
            return receipt

    def record_context_collected(
        self,
        *,
        request_id: str,
        snapshot: AuthoringContextSnapshot,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
            subject_id=request_id,
            payload=snapshot.to_manifest_dict(),
            metadata={
                "stage": "context_collection",
                "context_id": snapshot.context.context_id,
                "context_digest": snapshot.context.digest,
                **dict(metadata or {}),
            },
        )

    def record_evidence_extracted(
        self,
        *,
        request_id: str,
        report: FailureEvidenceReport,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.EVIDENCE_EXTRACTED,
            subject_id=request_id,
            payload=report.to_dict(),
            metadata={
                "stage": "evidence_extraction",
                "evidence_id": report.evidence.evidence_id,
                "evidence_strength": report.evidence.strength.value,
                **dict(metadata or {}),
            },
        )

    def record_decomposition_created(
        self,
        *,
        request_id: str,
        plan: RepairDecompositionPlan,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.DECOMPOSITION_CREATED,
            subject_id=request_id,
            payload=plan.to_dict(),
            metadata={
                "stage": "task_decomposition",
                "plan_id": plan.plan_id,
                "risk_level": plan.risk_level.value,
                **dict(metadata or {}),
            },
        )

    def record_hypotheses_generated(
        self,
        *,
        request_id: str,
        report: RepairHypothesisReport,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.HYPOTHESES_GENERATED,
            subject_id=request_id,
            payload=report.to_dict(),
            metadata={
                "stage": "repair_hypotheses",
                "report_id": report.report_id,
                "selected_hypothesis_id": report.selected_hypothesis_id,
                **dict(metadata or {}),
            },
        )

    def record_prompt_contract_rendered(
        self,
        *,
        request_id: str,
        contract: PatchAuthoringPromptContract,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.PROMPT_CONTRACT_RENDERED,
            subject_id=request_id,
            payload=contract.to_dict(),
            metadata={
                "stage": "prompt_contract",
                "contract_id": contract.contract_id,
                "contract_digest": contract.digest,
                **dict(metadata or {}),
            },
        )

    def record_model_response_received(
        self,
        *,
        request_id: str,
        raw_response: str,
        provider_name: str | None = None,
        model_name: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        normalized_response = raw_response.strip()
        response_digest = hashlib.sha256(normalized_response.encode("utf-8")).hexdigest()
        return self.append(
            event_type=AuthoringReceiptEventType.MODEL_RESPONSE_RECEIVED,
            subject_id=request_id,
            payload={
                "raw_response_digest": response_digest,
                "raw_response_bytes": len(normalized_response.encode("utf-8")),
                "provider_name": provider_name,
                "model_name": model_name,
            },
            metadata={
                "stage": "model_response",
                "raw_response_digest": response_digest,
                **dict(metadata or {}),
            },
        )

    def record_response_parsed(
        self,
        *,
        request_id: str,
        proposal: PatchAuthoringProposal,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.RESPONSE_PARSED,
            subject_id=request_id,
            payload=proposal.to_dict(),
            metadata={
                "stage": "response_parsing",
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "raw_digest": proposal.raw_digest,
                **dict(metadata or {}),
            },
        )

    def record_proposal_validated(
        self,
        *,
        request_id: str,
        proposal: PatchAuthoringProposal,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.PROPOSAL_VALIDATED,
            subject_id=request_id,
            payload={
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "raw_digest": proposal.raw_digest,
                "affected_paths": list(proposal.affected_paths),
                "mutation_count": len(proposal.mutations),
                "confidence": proposal.confidence,
                "findings": [finding.to_dict() for finding in proposal.findings],
            },
            metadata={
                "stage": "proposal_validation",
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                **dict(metadata or {}),
            },
        )

    def record_patch_compiled(
        self,
        *,
        request_id: str,
        candidate: CompiledPatchCandidate,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.PATCH_COMPILED,
            subject_id=request_id,
            payload=candidate.to_dict(),
            metadata={
                "stage": "patch_compilation",
                "candidate_id": candidate.candidate_id,
                "patch_id": candidate.patch_id,
                "patch_digest": candidate.patch_digest,
                **dict(metadata or {}),
            },
        )

    def record_policy_decided(
        self,
        *,
        request_id: str,
        report: AuthoringPolicyReport,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        status = AuthoringReceiptStatus.RECORDED
        if report.blocked:
            status = AuthoringReceiptStatus.BLOCKED
        elif report.requires_review:
            status = AuthoringReceiptStatus.REJECTED

        return self.append(
            event_type=AuthoringReceiptEventType.POLICY_DECIDED,
            subject_id=request_id,
            payload=report.to_dict(),
            status=status,
            metadata={
                "stage": "authoring_policy",
                "policy_report_id": report.report_id,
                "policy_decision": report.decision.value,
                **dict(metadata or {}),
            },
        )

    def record_candidate_selected(
        self,
        *,
        request_id: str,
        selected_candidate_id: str,
        candidate_ids: Iterable[str],
        selection_reason: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        normalized_candidate_ids = tuple(
            _normalize_identifier(candidate_id, label="candidate_id")
            for candidate_id in candidate_ids
        )
        normalized_selected = _normalize_identifier(
            selected_candidate_id,
            label="selected_candidate_id",
        )
        if normalized_selected not in normalized_candidate_ids:
            raise ValueError("selected_candidate_id must be present in candidate_ids.")

        return self.append(
            event_type=AuthoringReceiptEventType.CANDIDATE_SELECTED,
            subject_id=request_id,
            payload={
                "selected_candidate_id": normalized_selected,
                "candidate_ids": list(normalized_candidate_ids),
                "selection_reason": _normalize_text(selection_reason, label="selection_reason"),
            },
            metadata={
                "stage": "candidate_selection",
                "selected_candidate_id": normalized_selected,
                **dict(metadata or {}),
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
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        normalized_candidate_id = _normalize_identifier(candidate_id, label="candidate_id")
        return self.append(
            event_type=AuthoringReceiptEventType.CANDIDATE_REJECTED,
            subject_id=request_id,
            payload={
                "candidate_id": normalized_candidate_id,
                "rejection_phase": _normalize_token(rejection_phase, label="rejection_phase"),
                "rejection_reason": _normalize_text(rejection_reason, label="rejection_reason"),
                "proposal_digest": _normalize_optional_sha256(proposal_digest),
                "affected_paths": [
                    _normalize_relative_path(path) for path in affected_paths
                ],
            },
            status=AuthoringReceiptStatus.REJECTED,
            metadata={
                "stage": "candidate_rejection",
                "candidate_id": normalized_candidate_id,
                **dict(metadata or {}),
            },
        )

    def record_authoring_failed(
        self,
        *,
        request_id: str,
        failure_phase: str,
        failure_reason: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoringReceipt:
        return self.append(
            event_type=AuthoringReceiptEventType.AUTHORING_FAILED,
            subject_id=request_id,
            payload={
                "failure_phase": _normalize_token(failure_phase, label="failure_phase"),
                "failure_reason": _normalize_text(failure_reason, label="failure_reason"),
            },
            status=AuthoringReceiptStatus.FAILED,
            metadata={
                "stage": "authoring_failure",
                **dict(metadata or {}),
            },
        )

    def snapshot(self) -> AuthoringReceiptSnapshot:
        with self._lock:
            return AuthoringReceiptSnapshot(receipts=tuple(self._receipts))

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()


def digest_payload(payload: Mapping[str, Any]) -> str:
    """
    Return a canonical SHA-256 digest for a JSON-compatible mapping.
    """
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        _to_jsonable(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _to_jsonable(nested) for key, nested in value.items()}
    if isinstance(value, tuple | list):
        return [_to_jsonable(item) for item in value]
    return value


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path traversal is not allowed: {value!r}")
        parts.append(part)

    if not parts:
        raise ValueError("relative path must not resolve to workspace root.")
    return "/".join(parts)


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _datetime_from_payload(payload: Mapping[str, Any], key: str) -> datetime:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be an ISO datetime string.")
    return _normalize_datetime(datetime.fromisoformat(value))


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
