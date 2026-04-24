from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any
from uuid import uuid4

from ix_blackfox.brains import SafeguardDisposition, SafeguardFindingSeverity


class ActionKind(StrEnum):
    """
    High-level governed action categories understood by BlackFox.
    """

    PATCH_PLAN = auto()
    FILE_WRITE = auto()
    COMMAND = auto()
    TEST_RUN = auto()
    STATE_MUTATION = auto()
    ARTIFACT_EXPORT = auto()
    NETWORK_EGRESS = auto()


class RiskLevel(StrEnum):
    """
    Canonical governance risk levels.

    The ordering is semantic rather than numeric. Policy layers can map
    these levels to approval requirements or hard blocks later.
    """

    LOW = auto()
    MODERATE = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class ActionIntent:
    """
    One normalized action proposal.

    Attributes
    ----------
    intent_id:
        Stable unique action-intent identifier.
    task_id:
        Task identifier that originated the action.
    action_kind:
        High-level governed action category.
    summary:
        Short human-readable action summary.
    rationale:
        Why this action is being proposed.
    target_locator:
        Stable logical target reference, such as a relative path or
        subsystem identifier.
    requested_at:
        UTC timestamp when the action was proposed.
    requested_by:
        Optional operator or subsystem label that proposed the action.
    labels:
        Optional normalized routing or policy labels.
    metadata:
        Optional structured metadata attached to the action proposal.
    """

    intent_id: str
    task_id: str
    action_kind: ActionKind
    summary: str
    rationale: str
    target_locator: str
    requested_at: datetime
    requested_by: str | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        action_kind: ActionKind,
        summary: str,
        rationale: str,
        target_locator: str,
        requested_by: str | None = None,
        labels: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ActionIntent:
        """
        Construct a new normalized action intent.
        """
        return cls(
            intent_id=f"intent-{uuid4().hex}",
            task_id=_normalize_identifier(task_id, label="task_id"),
            action_kind=action_kind,
            summary=_normalize_text(summary, label="summary"),
            rationale=_normalize_text(rationale, label="rationale"),
            target_locator=_normalize_target_locator(target_locator),
            requested_at=_utc_now(),
            requested_by=_normalize_optional_text(requested_by),
            labels=_normalize_labels(labels or ()),
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """
    One explicit reason contributing to an action risk profile.

    Attributes
    ----------
    code:
        Stable short risk code.
    description:
        Human-readable explanation of the factor.
    """

    code: str
    description: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "code",
            _normalize_identifier(self.code, label="risk factor code"),
        )
        object.__setattr__(
            self,
            "description",
            _normalize_text(self.description, label="risk factor description"),
        )


@dataclass(frozen=True, slots=True)
class GovernanceSafetyMerge:
    """
    Immutable record of how safeguard evidence influenced governance risk.

    Attributes
    ----------
    advisory_disposition:
        Advisory semantic-safety disposition emitted by the safeguard lane.
    finding_count:
        Number of safeguard findings considered during merge.
    finding_codes:
        Stable safeguard finding codes in declaration order.
    policy_tags:
        Stable safeguard policy tags in declaration order.
    highest_severity:
        Highest safeguard finding severity when present.
    original_risk_level:
        Risk level before semantic safety merge.
    merged_risk_level:
        Risk level after semantic safety merge.
    elevated_risk:
        Whether risk increased because of safeguard evidence.
    forced_review:
        Whether semantic evidence forced review semantics.
    rationale:
        Human-readable explanation of the merge outcome.
    """

    advisory_disposition: SafeguardDisposition
    finding_count: int
    finding_codes: tuple[str, ...] = field(default_factory=tuple)
    policy_tags: tuple[str, ...] = field(default_factory=tuple)
    highest_severity: SafeguardFindingSeverity | None = None
    original_risk_level: RiskLevel | None = None
    merged_risk_level: RiskLevel | None = None
    elevated_risk: bool = False
    forced_review: bool = False
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.finding_count < 0:
            raise ValueError("finding_count must be zero or greater.")
        if self.finding_count == 0 and self.advisory_disposition is not SafeguardDisposition.ALLOW:
            raise ValueError(
                "Safety merges without findings must use advisory_disposition=ALLOW."
            )

        object.__setattr__(self, "finding_codes", _normalize_labels(self.finding_codes))
        object.__setattr__(self, "policy_tags", _normalize_labels(self.policy_tags))
        object.__setattr__(self, "rationale", _normalize_optional_text(self.rationale) or "")

    def has_findings(self) -> bool:
        """
        Return True when this merge carries one or more safeguard findings.
        """
        return self.finding_count > 0


@dataclass(frozen=True, slots=True)
class ActionRiskProfile:
    """
    Normalized governance risk view for one action intent.

    Attributes
    ----------
    intent_id:
        Action-intent identifier this profile belongs to.
    risk_level:
        Canonical governance risk level.
    requires_approval:
        Whether policy should require a recorded approval before
        execution may proceed.
    factors:
        Explicit factors supporting the risk classification.
    tags:
        Optional normalized tags for later policy matching.
    safety_merge:
        Optional semantic-safety merge record used to explain how the
        safeguard lane influenced the final risk view.
    """

    intent_id: str
    risk_level: RiskLevel
    requires_approval: bool
    factors: tuple[RiskFactor, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    safety_merge: GovernanceSafetyMerge | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "intent_id",
            _normalize_identifier(self.intent_id, label="intent_id"),
        )
        object.__setattr__(self, "tags", _normalize_labels(self.tags))

        if self.requires_approval and not self.factors:
            raise ValueError(
                "Approval-required action risk profiles must include at least one factor."
            )

    def factor_codes(self) -> tuple[str, ...]:
        """
        Return normalized risk-factor codes in declaration order.
        """
        return tuple(factor.code for factor in self.factors)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_target_locator(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("target_locator must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned


def _normalize_labels(labels: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_label in labels:
        cleaned = raw_label.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
