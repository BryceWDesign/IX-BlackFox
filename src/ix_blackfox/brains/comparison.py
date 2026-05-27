from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from hashlib import sha256
from typing import Any
from uuid import uuid4

from ix_blackfox.brains.contracts import BrainCapability, BrainRole


class BrainComparisonDisposition(StrEnum):
    """
    Terminal comparison disposition for one model candidate.
    """

    SELECTED = auto()
    REJECTED = auto()
    BLOCKED = auto()


@dataclass(frozen=True, slots=True)
class BrainComparisonScore:
    """
    Transparent score components for comparing model outputs.

    The score is intentionally criterion-based rather than model-specific so
    Wave 7 repair intelligence can compare local, hosted, or future providers
    without giving any provider hidden authority.
    """

    correctness_score: int = 0
    evidence_score: int = 0
    safety_score: int = 0
    policy_score: int = 0
    maintainability_score: int = 0
    latency_score: int = 0
    penalty_score: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_bounded_score(self.correctness_score, label="correctness_score")
        _validate_bounded_score(self.evidence_score, label="evidence_score")
        _validate_bounded_score(self.safety_score, label="safety_score")
        _validate_bounded_score(self.policy_score, label="policy_score")
        _validate_bounded_score(
            self.maintainability_score,
            label="maintainability_score",
        )
        _validate_bounded_score(self.latency_score, label="latency_score")
        if self.penalty_score < 0:
            raise ValueError("penalty_score must be zero or greater.")
        object.__setattr__(self, "notes", _normalize_text_tuple(self.notes))

    @property
    def positive_total(self) -> int:
        """
        Return the total before penalties are applied.
        """
        return (
            self.correctness_score
            + self.evidence_score
            + self.safety_score
            + self.policy_score
            + self.maintainability_score
            + self.latency_score
        )

    @property
    def total(self) -> int:
        """
        Return the final comparison score after penalties.
        """
        return self.positive_total - self.penalty_score

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable score view for future receipts.
        """
        return {
            "correctness_score": self.correctness_score,
            "evidence_score": self.evidence_score,
            "safety_score": self.safety_score,
            "policy_score": self.policy_score,
            "maintainability_score": self.maintainability_score,
            "latency_score": self.latency_score,
            "penalty_score": self.penalty_score,
            "positive_total": self.positive_total,
            "total": self.total,
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class BrainComparisonRequest:
    """
    Auditable request describing why model outputs are being compared.
    """

    comparison_id: str
    required_role: BrainRole
    required_capabilities: tuple[BrainCapability, ...] = field(default_factory=tuple)
    task_id: str | None = None
    pack_name: str | None = None
    criteria: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        required_role: BrainRole,
        required_capabilities: tuple[BrainCapability, ...] | None = None,
        task_id: str | None = None,
        pack_name: str | None = None,
        criteria: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BrainComparisonRequest:
        """
        Construct a comparison request with a stable generated identifier.
        """
        return cls(
            comparison_id=f"brain-comparison-{uuid4().hex}",
            required_role=required_role,
            required_capabilities=tuple(required_capabilities or ()),
            task_id=task_id,
            pack_name=pack_name,
            criteria=tuple(criteria or ()),
            metadata=dict(metadata or {}),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "comparison_id",
            _normalize_identifier(self.comparison_id, label="comparison_id"),
        )
        object.__setattr__(
            self,
            "required_capabilities",
            _normalize_capabilities(self.required_capabilities),
        )
        object.__setattr__(
            self,
            "task_id",
            _normalize_optional_identifier(self.task_id, label="task_id"),
        )
        object.__setattr__(
            self,
            "pack_name",
            _normalize_optional_identifier(self.pack_name, label="pack_name"),
        )
        object.__setattr__(self, "criteria", _normalize_text_tuple(self.criteria))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable request view for future receipts.
        """
        return {
            "comparison_id": self.comparison_id,
            "required_role": self.required_role.value,
            "required_capabilities": [
                capability.value for capability in self.required_capabilities
            ],
            "task_id": self.task_id,
            "pack_name": self.pack_name,
            "criteria": list(self.criteria),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainComparisonCandidate:
    """
    One normalized model output submitted for comparison.
    """

    brain_name: str
    provider_name: str
    model_name: str
    role: BrainRole
    score: BrainComparisonScore
    output_text: str | None = None
    invocation_id: str | None = None
    eligible: bool = True
    reasons: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

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
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_optional_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(self, "output_text", _normalize_optional_text(self.output_text))
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.eligible and self.output_text is None:
            raise ValueError("eligible comparison candidates must include output_text.")
        if not self.eligible and not self.reasons:
            raise ValueError("ineligible comparison candidates must include reasons.")

    @property
    def output_digest(self) -> str | None:
        """
        Return a deterministic SHA-256 digest for the candidate output.
        """
        if self.output_text is None:
            return None
        return sha256(self.output_text.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable candidate view for future receipts.
        """
        return {
            "brain_name": self.brain_name,
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "role": self.role.value,
            "score": self.score.to_dict(),
            "output_digest": self.output_digest,
            "invocation_id": self.invocation_id,
            "eligible": self.eligible,
            "reasons": list(self.reasons),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BrainComparisonResult:
    """
    Final comparison finding for one candidate.
    """

    candidate: BrainComparisonCandidate
    disposition: BrainComparisonDisposition
    rank: int | None
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", _normalize_text_tuple(self.reasons))
        if self.rank is not None and self.rank <= 0:
            raise ValueError("rank must be greater than zero when provided.")
        if self.disposition is BrainComparisonDisposition.SELECTED and self.rank != 1:
            raise ValueError("selected comparison results must have rank 1.")
        if self.disposition is BrainComparisonDisposition.BLOCKED and self.rank is not None:
            raise ValueError("blocked comparison results must not have a rank.")
        if not self.reasons:
            raise ValueError("comparison results must include at least one reason.")

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable comparison result.
        """
        return {
            "candidate": self.candidate.to_dict(),
            "disposition": self.disposition.value,
            "rank": self.rank,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class BrainComparisonDecision:
    """
    Immutable selected/rejected model comparison decision.
    """

    request: BrainComparisonRequest
    results: tuple[BrainComparisonResult, ...]

    @property
    def selected(self) -> BrainComparisonResult | None:
        """
        Return the selected comparison result when one exists.
        """
        for result in self.results:
            if result.disposition is BrainComparisonDisposition.SELECTED:
                return result
        return None

    @property
    def selected_brain_name(self) -> str | None:
        """
        Return the selected brain name when one exists.
        """
        selected = self.selected
        if selected is None:
            return None
        return selected.candidate.brain_name

    @property
    def rejected(self) -> tuple[BrainComparisonResult, ...]:
        """
        Return candidates that were eligible but not selected.
        """
        return tuple(
            result
            for result in self.results
            if result.disposition is BrainComparisonDisposition.REJECTED
        )

    @property
    def blocked(self) -> tuple[BrainComparisonResult, ...]:
        """
        Return candidates blocked before selection.
        """
        return tuple(
            result
            for result in self.results
            if result.disposition is BrainComparisonDisposition.BLOCKED
        )

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable decision view for future receipts.
        """
        return {
            "request": self.request.to_dict(),
            "selected_brain_name": self.selected_brain_name,
            "results": [result.to_dict() for result in self.results],
        }


class BrainModelComparator:
    """
    Deterministic comparator for provider-agnostic model outputs.

    This class intentionally does not invoke models. It compares already-produced
    candidate outputs and emits auditable selected/rejected findings that later
    Wave 7 repair orchestration can bind into receipts.
    """

    def compare(
        self,
        request: BrainComparisonRequest,
        candidates: tuple[BrainComparisonCandidate, ...],
    ) -> BrainComparisonDecision:
        """
        Compare candidates and return a deterministic decision.
        """
        blocked_results = tuple(
            BrainComparisonResult(
                candidate=candidate,
                disposition=BrainComparisonDisposition.BLOCKED,
                rank=None,
                reasons=candidate.reasons,
            )
            for candidate in candidates
            if not candidate.eligible
        )
        eligible_candidates = tuple(candidate for candidate in candidates if candidate.eligible)
        ranked_candidates = tuple(sorted(eligible_candidates, key=_candidate_sort_key))

        selected_candidate = ranked_candidates[0] if ranked_candidates else None
        ranked_results: list[BrainComparisonResult] = []

        for index, candidate in enumerate(ranked_candidates, start=1):
            if candidate is selected_candidate:
                ranked_results.append(
                    BrainComparisonResult(
                        candidate=candidate,
                        disposition=BrainComparisonDisposition.SELECTED,
                        rank=1,
                        reasons=("highest deterministic comparison score",),
                    )
                )
                continue

            ranked_results.append(
                BrainComparisonResult(
                    candidate=candidate,
                    disposition=BrainComparisonDisposition.REJECTED,
                    rank=index,
                    reasons=_rejection_reasons(
                        candidate=candidate,
                        selected_candidate=selected_candidate,
                    ),
                )
            )

        return BrainComparisonDecision(
            request=request,
            results=tuple(ranked_results) + blocked_results,
        )


def _candidate_sort_key(
    candidate: BrainComparisonCandidate,
) -> tuple[int, int, int, str, str, str, str]:
    return (
        -candidate.score.total,
        -candidate.score.safety_score,
        -candidate.score.evidence_score,
        candidate.brain_name,
        candidate.provider_name,
        candidate.model_name,
        candidate.invocation_id or "",
    )


def _rejection_reasons(
    *,
    candidate: BrainComparisonCandidate,
    selected_candidate: BrainComparisonCandidate | None,
) -> tuple[str, ...]:
    if selected_candidate is None:
        return ("no selected comparison candidate was available",)
    if candidate.score.total == selected_candidate.score.total:
        return ("lost deterministic tie-break against selected candidate",)
    return ("lower comparison score than selected candidate",)


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


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


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


def _normalize_capabilities(
    values: tuple[BrainCapability, ...],
) -> tuple[BrainCapability, ...]:
    normalized: list[BrainCapability] = []
    seen: set[BrainCapability] = set()

    for value in values:
        if value not in seen:
            normalized.append(value)
            seen.add(value)

    return tuple(normalized)


def _validate_bounded_score(value: int, *, label: str) -> None:
    if value < 0 or value > 100:
        raise ValueError(f"{label} must be between 0 and 100.")
