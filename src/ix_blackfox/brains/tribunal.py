from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.brains.comparison import BrainComparisonCandidate


class BrainTribunalRoleKind(StrEnum):
    """
    Separated Wave 7 model roles used around repair intelligence.
    """

    GENERATOR = auto()
    CRITIC = auto()
    SECURITY_REVIEWER = auto()
    POLICY_REVIEWER = auto()
    EVIDENCE_REVIEWER = auto()
    HUMAN_REVIEW_COORDINATOR = auto()


class BrainTribunalAction(StrEnum):
    """
    Action a tribunal assignment may be asked to perform.
    """

    GENERATE = auto()
    REVIEW = auto()
    APPROVE = auto()


class BrainTribunalDisposition(StrEnum):
    """
    Terminal tribunal routing disposition.
    """

    ROUTED = auto()
    BLOCKED = auto()
    REVIEW_REQUIRED = auto()


@dataclass(frozen=True, slots=True)
class BrainTribunalIdentity:
    """
    Stable identity for a model, provider, or explicit human operator.
    """

    brain_name: str
    provider_name: str
    model_name: str
    human_operator: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_candidate(
        cls,
        candidate: BrainComparisonCandidate,
        *,
        human_operator: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> BrainTribunalIdentity:
        """
        Build a tribunal identity from a comparison candidate.
        """
        return cls(
            brain_name=candidate.brain_name,
            provider_name=candidate.provider_name,
            model_name=candidate.model_name,
            human_operator=human_operator,
            metadata=dict(metadata or {}),
        )

    def __post_init__(self) -> None:
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
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def model_identity_key(self) -> tuple[str, str]:
        """
        Return the provider/model pair used to detect same-model review.
        """
        return (self.provider_name, self.model_name)

    def same_model_as(self, other: BrainTribunalIdentity) -> bool:
        """
        Return whether two identities refer to the same provider/model pair.
        """
        return self.model_identity_key == other.model_identity_key

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable identity view for evidence receipts.
        """
        return {
            "brain_name": self.brain_name,
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "human_operator": self.human_operator,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainTribunalRole:
    """
    One separated role in the Wave 7 model tribunal.
    """

    role_id: str
    role_kind: BrainTribunalRoleKind
    description: str
    may_generate: bool = False
    may_review: bool = False
    may_approve: bool = False
    human_authority_role: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "role_id",
            _normalize_identifier(self.role_id, label="role_id"),
        )
        object.__setattr__(
            self,
            "description",
            _normalize_required_text(self.description, label="description"),
        )
        if self.human_authority_role and self.may_generate:
            raise ValueError("human authority roles cannot also generate model output.")
        if self.may_approve and not self.human_authority_role:
            raise ValueError("only human authority roles may approve tribunal output.")
        if not (self.may_generate or self.may_review or self.may_approve):
            raise ValueError("tribunal roles must allow at least one action.")

    def can_perform(self, action: BrainTribunalAction) -> bool:
        """
        Return whether this role is allowed to perform an action.
        """
        if action is BrainTribunalAction.GENERATE:
            return self.may_generate
        if action is BrainTribunalAction.REVIEW:
            return self.may_review
        return self.may_approve

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable role view.
        """
        return {
            "role_id": self.role_id,
            "role_kind": self.role_kind.value,
            "description": self.description,
            "may_generate": self.may_generate,
            "may_review": self.may_review,
            "may_approve": self.may_approve,
            "human_authority_role": self.human_authority_role,
        }


@dataclass(frozen=True, slots=True)
class BrainTribunalAssignment:
    """
    Assignment of a model or human operator identity to one separated role.
    """

    assignment_id: str
    role: BrainTribunalRole
    identity: BrainTribunalIdentity
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "assignment_id",
            _normalize_identifier(self.assignment_id, label="assignment_id"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.role.human_authority_role and not self.identity.human_operator:
            raise ValueError(
                "human authority roles must be assigned to a human operator identity."
            )
        if self.identity.human_operator and not self.role.human_authority_role:
            raise ValueError(
                "human operator identities must use a human authority role."
            )

    def can_perform(self, action: BrainTribunalAction) -> bool:
        """
        Return whether this enabled assignment can perform an action.
        """
        return self.enabled and self.role.can_perform(action)

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable assignment view.
        """
        return {
            "assignment_id": self.assignment_id,
            "role": self.role.to_dict(),
            "identity": self.identity.to_dict(),
            "enabled": self.enabled,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainTribunalPolicy:
    """
    Conservative role-separation policy for Wave 7 repair review.
    """

    block_same_brain_for_review: bool = True
    block_same_model_for_review: bool = True
    block_originating_role_for_review: bool = True
    require_human_for_approval: bool = True


@dataclass(frozen=True, slots=True)
class BrainTribunalReviewRequest:
    """
    Request to route a repair candidate through separated model review.
    """

    request_id: str
    generated_by: BrainTribunalIdentity
    action: BrainTribunalAction = BrainTribunalAction.REVIEW
    originating_role_id: str | None = None
    required_role_kinds: tuple[BrainTribunalRoleKind, ...] = field(default_factory=tuple)
    human_authority_required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_id",
            _normalize_identifier(self.request_id, label="request_id"),
        )
        object.__setattr__(
            self,
            "originating_role_id",
            _normalize_optional_identifier(
                self.originating_role_id,
                label="originating_role_id",
            ),
        )
        object.__setattr__(
            self,
            "required_role_kinds",
            _normalize_role_kinds(self.required_role_kinds),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable review request.
        """
        return {
            "request_id": self.request_id,
            "generated_by": self.generated_by.to_dict(),
            "action": self.action.value,
            "originating_role_id": self.originating_role_id,
            "required_role_kinds": [role.value for role in self.required_role_kinds],
            "human_authority_required": self.human_authority_required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainTribunalFinding:
    """
    Per-assignment tribunal eligibility finding.
    """

    assignment: BrainTribunalAssignment
    eligible: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        if not self.eligible and not self.reasons:
            raise ValueError("ineligible tribunal findings must include reasons.")

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable finding view.
        """
        return {
            "assignment": self.assignment.to_dict(),
            "eligible": self.eligible,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class BrainTribunalDecision:
    """
    Final role-separation routing decision for one repair candidate.
    """

    request: BrainTribunalReviewRequest
    disposition: BrainTribunalDisposition
    selected_assignment: BrainTribunalAssignment | None
    findings: tuple[BrainTribunalFinding, ...]
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        if self.disposition is BrainTribunalDisposition.ROUTED:
            if self.selected_assignment is None:
                raise ValueError("routed tribunal decisions require a selected assignment.")
        elif self.selected_assignment is not None:
            raise ValueError("non-routed tribunal decisions must not select an assignment.")
        if not self.reasons:
            raise ValueError("tribunal decisions must include reasons.")

    @property
    def selected_brain_name(self) -> str | None:
        """
        Return the selected brain name when a reviewer was routed.
        """
        if self.selected_assignment is None:
            return None
        return self.selected_assignment.identity.brain_name

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable tribunal decision for evidence receipts.
        """
        return {
            "request": self.request.to_dict(),
            "disposition": self.disposition.value,
            "selected_assignment": (
                self.selected_assignment.to_dict()
                if self.selected_assignment is not None
                else None
            ),
            "selected_brain_name": self.selected_brain_name,
            "findings": [finding.to_dict() for finding in self.findings],
            "reasons": list(self.reasons),
        }


class BrainModelTribunal:
    """
    Deterministic Wave 7 tribunal enforcing role separation before review.
    """

    def __init__(self, policy: BrainTribunalPolicy | None = None) -> None:
        self._policy = policy or BrainTribunalPolicy()

    def route_review(
        self,
        request: BrainTribunalReviewRequest,
        assignments: tuple[BrainTribunalAssignment, ...],
    ) -> BrainTribunalDecision:
        """
        Route a generated candidate to an eligible separated reviewer.
        """
        findings = tuple(
            self._evaluate_assignment(request=request, assignment=assignment)
            for assignment in assignments
        )
        eligible = sorted(
            (finding.assignment for finding in findings if finding.eligible),
            key=_assignment_sort_key,
        )
        if eligible:
            return BrainTribunalDecision(
                request=request,
                disposition=BrainTribunalDisposition.ROUTED,
                selected_assignment=eligible[0],
                findings=findings,
                reasons=("selected separated tribunal assignment",),
            )

        disposition = (
            BrainTribunalDisposition.REVIEW_REQUIRED
            if request.human_authority_required
            or (
                request.action is BrainTribunalAction.APPROVE
                and self._policy.require_human_for_approval
            )
            else BrainTribunalDisposition.BLOCKED
        )
        return BrainTribunalDecision(
            request=request,
            disposition=disposition,
            selected_assignment=None,
            findings=findings,
            reasons=("no eligible separated tribunal assignment",),
        )

    def _evaluate_assignment(
        self,
        *,
        request: BrainTribunalReviewRequest,
        assignment: BrainTribunalAssignment,
    ) -> BrainTribunalFinding:
        reasons: list[str] = []

        if not assignment.enabled:
            reasons.append(f"assignment is disabled: {assignment.assignment_id}")
        if not assignment.role.can_perform(request.action):
            reasons.append(
                f"role cannot perform action: {assignment.role.role_id}={request.action.value}"
            )
        if (
            request.required_role_kinds
            and assignment.role.role_kind not in request.required_role_kinds
        ):
            reasons.append(
                "role kind is not allowed: " f"{assignment.role.role_kind.value}"
            )
        if request.human_authority_required and not assignment.role.human_authority_role:
            reasons.append(
                "human authority is required for this tribunal request"
            )
        if (
            request.action is BrainTribunalAction.APPROVE
            and self._policy.require_human_for_approval
            and not assignment.role.human_authority_role
        ):
            reasons.append("approval requires a human authority role")
        if (
            self._policy.block_same_brain_for_review
            and request.action is not BrainTribunalAction.GENERATE
            and assignment.identity.brain_name == request.generated_by.brain_name
        ):
            reasons.append(
                f"self-review blocked for brain: {assignment.identity.brain_name}"
            )
        if (
            self._policy.block_same_model_for_review
            and request.action is not BrainTribunalAction.GENERATE
            and assignment.identity.same_model_as(request.generated_by)
        ):
            reasons.append(
                "self-review blocked for provider/model: "
                f"{assignment.identity.provider_name}/{assignment.identity.model_name}"
            )
        if (
            self._policy.block_originating_role_for_review
            and request.action is not BrainTribunalAction.GENERATE
            and request.originating_role_id is not None
            and assignment.role.role_id == request.originating_role_id
        ):
            reasons.append(
                f"originating role cannot review itself: {assignment.role.role_id}"
            )

        return BrainTribunalFinding(
            assignment=assignment,
            eligible=not reasons,
            reasons=tuple(reasons),
        )


def _assignment_sort_key(
    assignment: BrainTribunalAssignment,
) -> tuple[int, str, str, str]:
    return (
        -int(assignment.role.human_authority_role),
        assignment.assignment_id,
        assignment.identity.brain_name,
        assignment.identity.model_name,
    )


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


def _normalize_required_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_role_kinds(
    values: tuple[BrainTribunalRoleKind, ...],
) -> tuple[BrainTribunalRoleKind, ...]:
    normalized: list[BrainTribunalRoleKind] = []
    seen: set[BrainTribunalRoleKind] = set()

    for value in values:
        if value not in seen:
            normalized.append(value)
            seen.add(value)

    return tuple(normalized)
