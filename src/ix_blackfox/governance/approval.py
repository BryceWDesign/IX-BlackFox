from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


class ApprovalStatus(StrEnum):
    """
    Lifecycle states for a governed approval request.
    """

    PENDING = auto()
    APPROVED = auto()
    REJECTED = auto()
    CANCELED = auto()


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """
    Immutable approval request for one governed action intent.

    Attributes
    ----------
    approval_id:
        Stable unique approval identifier.
    intent_id:
        Action-intent identifier this approval request governs.
    requested_at:
        UTC timestamp when review was requested.
    requested_by:
        Optional operator or subsystem requesting approval.
    summary:
        Short human-readable request summary.
    rationale:
        Why approval is being requested.
    policy_reason:
        Stable policy reason that triggered review.
    required_roles:
        Optional normalized reviewer role labels.
    evidence_refs:
        Optional normalized evidence references attached to the request.
    metadata:
        Optional structured metadata.
    """

    approval_id: str
    intent_id: str
    requested_at: datetime
    requested_by: str | None
    summary: str
    rationale: str
    policy_reason: str
    required_roles: tuple[str, ...] = field(default_factory=tuple)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        intent_id: str,
        summary: str,
        rationale: str,
        policy_reason: str,
        requested_by: str | None = None,
        required_roles: tuple[str, ...] | None = None,
        evidence_refs: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        """
        Construct a normalized approval request.
        """
        return cls(
            approval_id=f"approval-{uuid4().hex}",
            intent_id=_normalize_identifier(intent_id, label="intent_id"),
            requested_at=_utc_now(),
            requested_by=_normalize_optional_text(requested_by),
            summary=_normalize_text(summary, label="summary"),
            rationale=_normalize_text(rationale, label="rationale"),
            policy_reason=_normalize_identifier(policy_reason, label="policy_reason"),
            required_roles=_normalize_labels(required_roles or ()),
            evidence_refs=_normalize_refs(evidence_refs or ()),
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """
    Immutable approval decision bound to one approval request.

    Attributes
    ----------
    approval_id:
        Approval identifier this decision resolves.
    intent_id:
        Action-intent identifier the approval belongs to.
    status:
        Terminal approval outcome.
    decided_at:
        UTC timestamp when the decision was made.
    decided_by:
        Reviewer or subsystem that made the decision.
    note:
        Short human-readable decision note.
    evidence_refs:
        Optional normalized evidence references attached to the decision.
    """

    approval_id: str
    intent_id: str
    status: ApprovalStatus
    decided_at: datetime
    decided_by: str
    note: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def create(
        cls,
        *,
        approval_id: str,
        intent_id: str,
        status: ApprovalStatus,
        decided_by: str,
        note: str,
        evidence_refs: tuple[str, ...] | None = None,
    ) -> ApprovalDecision:
        """
        Construct a normalized approval decision.
        """
        return cls(
            approval_id=_normalize_identifier(approval_id, label="approval_id"),
            intent_id=_normalize_identifier(intent_id, label="intent_id"),
            status=status,
            decided_at=_utc_now(),
            decided_by=_normalize_text(decided_by, label="decided_by"),
            note=_normalize_text(note, label="note"),
            evidence_refs=_normalize_refs(evidence_refs or ()),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "approval_id",
            _normalize_identifier(self.approval_id, label="approval_id"),
        )
        object.__setattr__(
            self,
            "intent_id",
            _normalize_identifier(self.intent_id, label="intent_id"),
        )
        object.__setattr__(
            self,
            "decided_by",
            _normalize_text(self.decided_by, label="decided_by"),
        )
        object.__setattr__(self, "note", _normalize_text(self.note, label="note"))
        object.__setattr__(self, "evidence_refs", _normalize_refs(self.evidence_refs))

        if self.status == ApprovalStatus.PENDING:
            raise ValueError("Approval decisions must resolve to a terminal status.")


@dataclass(frozen=True, slots=True)
class ApprovalState:
    """
    Persisted approval state for one governed action.

    Attributes
    ----------
    request:
        Original approval request.
    decision:
        Optional terminal decision when the request has been resolved.
    """

    request: ApprovalRequest
    decision: ApprovalDecision | None = None

    def current_status(self) -> ApprovalStatus:
        """
        Return the effective approval status for the state.
        """
        if self.decision is None:
            return ApprovalStatus.PENDING
        return self.decision.status

    def with_decision(self, decision: ApprovalDecision) -> ApprovalState:
        """
        Return a new state resolved by the supplied decision.
        """
        if self.decision is not None:
            raise ValueError("Approval state has already been resolved.")
        if decision.approval_id != self.request.approval_id:
            raise ValueError("Approval decision must reference the same approval_id.")
        if decision.intent_id != self.request.intent_id:
            raise ValueError("Approval decision must reference the same intent_id.")
        return replace(self, decision=decision)


class GovernanceApprovalStore:
    """
    Disk-backed store for approval requests and decisions.

    The store persists approval state as JSON and keeps each approval
    keyed by approval identifier. It is intentionally simple so later
    runtime integration can rely on deterministic behavior without
    introducing external services.
    """

    def __init__(self, *, root_dir: Path) -> None:
        self._root_dir = root_dir.resolve()
        self._lock = RLock()
        self._root_dir.mkdir(parents=True, exist_ok=True)

    def put_request(self, request: ApprovalRequest) -> ApprovalState:
        """
        Persist a new approval request.
        """
        state = ApprovalState(request=request, decision=None)
        path = self._entry_path(request.approval_id)

        with self._lock:
            if path.exists():
                raise ValueError(
                    f"Approval request '{request.approval_id}' already exists."
                )
            _write_state(path=path, state=state)

        return state

    def resolve(self, decision: ApprovalDecision) -> ApprovalState:
        """
        Persist a terminal decision for an existing approval request.
        """
        with self._lock:
            state = self.get(decision.approval_id)
            if state is None:
                raise KeyError(
                    f"Approval request '{decision.approval_id}' does not exist."
                )
            resolved = state.with_decision(decision)
            _write_state(path=self._entry_path(decision.approval_id), state=resolved)
            return resolved

    def get(self, approval_id: str) -> ApprovalState | None:
        """
        Read one approval state by approval identifier.
        """
        normalized_approval_id = _normalize_identifier(approval_id, label="approval_id")
        path = self._entry_path(normalized_approval_id)

        with self._lock:
            if not path.exists():
                return None
            raw = json.loads(path.read_text(encoding="utf-8"))

        return _decode_state(raw)

    def find_by_intent(self, intent_id: str) -> tuple[ApprovalState, ...]:
        """
        Return all approval states for one action intent.
        """
        normalized_intent_id = _normalize_identifier(intent_id, label="intent_id")

        with self._lock:
            states = [
                _decode_state(json.loads(path.read_text(encoding="utf-8")))
                for path in sorted(self._root_dir.glob("*.json"))
            ]

        matching = [
            state for state in states if state.request.intent_id == normalized_intent_id
        ]
        return tuple(
            sorted(
                matching,
                key=lambda state: (
                    state.request.requested_at,
                    state.request.approval_id,
                ),
            )
        )

    def keys(self) -> tuple[str, ...]:
        """
        Return all stored approval identifiers in sorted order.
        """
        with self._lock:
            return tuple(sorted(path.stem for path in self._root_dir.glob("*.json")))

    def clear(self) -> None:
        """
        Remove all stored approval entries.
        """
        with self._lock:
            for path in self._root_dir.glob("*.json"):
                path.unlink()

    def _entry_path(self, approval_id: str) -> Path:
        return self._root_dir / f"{approval_id}.json"


def _write_state(*, path: Path, state: ApprovalState) -> None:
    payload = {
        "request": {
            "approval_id": state.request.approval_id,
            "intent_id": state.request.intent_id,
            "requested_at": state.request.requested_at.isoformat(),
            "requested_by": state.request.requested_by,
            "summary": state.request.summary,
            "rationale": state.request.rationale,
            "policy_reason": state.request.policy_reason,
            "required_roles": list(state.request.required_roles),
            "evidence_refs": list(state.request.evidence_refs),
            "metadata": state.request.metadata,
        },
        "decision": None
        if state.decision is None
        else {
            "approval_id": state.decision.approval_id,
            "intent_id": state.decision.intent_id,
            "status": state.decision.status.value,
            "decided_at": state.decision.decided_at.isoformat(),
            "decided_by": state.decision.decided_by,
            "note": state.decision.note,
            "evidence_refs": list(state.decision.evidence_refs),
        },
    }

    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _decode_state(raw: dict[str, Any]) -> ApprovalState:
    try:
        request_raw = raw["request"]
        request = ApprovalRequest(
            approval_id=_normalize_identifier(
                str(request_raw["approval_id"]),
                label="approval_id",
            ),
            intent_id=_normalize_identifier(str(request_raw["intent_id"]), label="intent_id"),
            requested_at=_parse_datetime(str(request_raw["requested_at"])),
            requested_by=_normalize_optional_text(request_raw.get("requested_by")),
            summary=_normalize_text(str(request_raw["summary"]), label="summary"),
            rationale=_normalize_text(str(request_raw["rationale"]), label="rationale"),
            policy_reason=_normalize_identifier(
                str(request_raw["policy_reason"]),
                label="policy_reason",
            ),
            required_roles=_normalize_labels(tuple(request_raw.get("required_roles", ()))),
            evidence_refs=_normalize_refs(tuple(request_raw.get("evidence_refs", ()))),
            metadata=dict(request_raw.get("metadata", {})),
        )

        decision_raw = raw.get("decision")
        if decision_raw is None:
            return ApprovalState(request=request)

        decision = ApprovalDecision(
            approval_id=_normalize_identifier(
                str(decision_raw["approval_id"]),
                label="approval_id",
            ),
            intent_id=_normalize_identifier(str(decision_raw["intent_id"]), label="intent_id"),
            status=ApprovalStatus(str(decision_raw["status"])),
            decided_at=_parse_datetime(str(decision_raw["decided_at"])),
            decided_by=_normalize_text(str(decision_raw["decided_by"]), label="decided_by"),
            note=_normalize_text(str(decision_raw["note"]), label="note"),
            evidence_refs=_normalize_refs(tuple(decision_raw.get("evidence_refs", ()))),
        )
        return ApprovalState(request=request, decision=decision)
    except KeyError as exc:
        raise ValueError(f"Stored approval state is malformed: missing field {exc!s}.") from exc
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Stored approval state is invalid: {exc}") from exc


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    return cleaned


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = raw_value.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = raw_value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
