from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from uuid import uuid4

from ix_blackfox.governance import (
    ActionIntent,
    ActionRiskProfile,
    ApprovalState,
    PolicyDecision,
    PolicyDecisionType,
)


class ForgeExecutionDisposition(StrEnum):
    """
    High-level readiness state for one governed forge action.
    """

    READY = auto()
    REVIEW_REQUIRED = auto()
    BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class ForgeExecutionTicket:
    """
    Governed forge execution ticket.

    Tickets are the bridge between governance evaluation and future forge
    execution. They make one proposed action explicit, classified, and
    ready for later runtime mediation without executing anything yet.

    Attributes
    ----------
    ticket_id:
        Stable unique execution-ticket identifier.
    intent_id:
        Action-intent identifier this ticket represents.
    task_id:
        Task identifier that originated the action.
    disposition:
        Whether the action is ready, review-required, or blocked.
    summary:
        Short human-readable action summary.
    rationale:
        Why this action is being proposed.
    target_locator:
        Stable logical target reference such as a path or subsystem name.
    risk_level:
        Normalized governance risk level copied from the risk profile.
    policy_decision:
        Canonical governance decision bound to the action.
    approval_ids:
        Any approval records currently associated with the action.
    created_at:
        UTC timestamp when the ticket was built.
    labels:
        Optional normalized labels copied from the originating action.
    metadata:
        Optional structured metadata payload.
    """

    ticket_id: str
    intent_id: str
    task_id: str
    disposition: ForgeExecutionDisposition
    summary: str
    rationale: str
    target_locator: str
    risk_level: str
    policy_decision: PolicyDecisionType
    approval_ids: tuple[str, ...]
    created_at: datetime
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ticket_id",
            _normalize_identifier(self.ticket_id, label="ticket_id"),
        )
        object.__setattr__(
            self,
            "intent_id",
            _normalize_identifier(self.intent_id, label="intent_id"),
        )
        object.__setattr__(
            self,
            "task_id",
            _normalize_identifier(self.task_id, label="task_id"),
        )
        object.__setattr__(
            self,
            "summary",
            _normalize_text(self.summary, label="summary"),
        )
        object.__setattr__(
            self,
            "rationale",
            _normalize_text(self.rationale, label="rationale"),
        )
        object.__setattr__(
            self,
            "target_locator",
            _normalize_target_locator(self.target_locator),
        )
        object.__setattr__(
            self,
            "risk_level",
            _normalize_identifier(self.risk_level, label="risk_level"),
        )
        object.__setattr__(self, "approval_ids", _normalize_approval_ids(self.approval_ids))
        object.__setattr__(self, "labels", _normalize_labels(self.labels))

    @property
    def is_executable(self) -> bool:
        """
        Return True when the ticket is ready for controlled execution.
        """
        return self.disposition == ForgeExecutionDisposition.READY

    @property
    def requires_review(self) -> bool:
        """
        Return True when the ticket requires approval or manual review.
        """
        return self.disposition == ForgeExecutionDisposition.REVIEW_REQUIRED


class ForgeExecutionTicketBuilder:
    """
    Deterministic builder for forge execution tickets.

    The builder translates governance outputs into a forge-facing
    readiness artifact that later runtime layers can use for execution
    orchestration, approval checks, and receipt emission.
    """

    def build(
        self,
        *,
        intent: ActionIntent,
        risk: ActionRiskProfile,
        decision: PolicyDecision,
        approvals: tuple[ApprovalState, ...] = (),
        metadata: dict[str, object] | None = None,
    ) -> ForgeExecutionTicket:
        """
        Build one governed forge execution ticket.
        """
        if risk.intent_id != intent.intent_id:
            raise ValueError("Action intent and risk profile must share the same intent_id.")
        if decision.intent_id != intent.intent_id:
            raise ValueError("Action intent and policy decision must share the same intent_id.")

        approval_ids = tuple(state.request.approval_id for state in approvals)
        return ForgeExecutionTicket(
            ticket_id=f"ticket-{uuid4().hex}",
            intent_id=intent.intent_id,
            task_id=intent.task_id,
            disposition=_map_disposition(decision.decision),
            summary=intent.summary,
            rationale=intent.rationale,
            target_locator=intent.target_locator,
            risk_level=risk.risk_level.value,
            policy_decision=decision.decision,
            approval_ids=approval_ids,
            created_at=_utc_now(),
            labels=intent.labels,
            metadata=dict(metadata or {}),
        )


def _map_disposition(decision: PolicyDecisionType) -> ForgeExecutionDisposition:
    if decision == PolicyDecisionType.ALLOW:
        return ForgeExecutionDisposition.READY
    if decision == PolicyDecisionType.REQUIRE_REVIEW:
        return ForgeExecutionDisposition.REVIEW_REQUIRED
    return ForgeExecutionDisposition.BLOCKED


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


def _normalize_target_locator(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("target_locator must not be empty.")
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


def _normalize_approval_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = _normalize_identifier(raw_value, label="approval_id")
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
