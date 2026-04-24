from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any
from uuid import uuid4


class PolicyAdvisoryDisposition(StrEnum):
    """
    Advisory policy disposition emitted by the policy reasoning lane.

    Deterministic governance remains sovereign. This disposition is
    explanatory and supportive, not authoritative.
    """

    ALLOW = auto()
    REVIEW = auto()
    BLOCK = auto()


@dataclass(frozen=True, slots=True)
class PolicyAdvisoryNote:
    """
    One structured policy-advisory note.

    Attributes
    ----------
    note_id:
        Stable note identifier.
    code:
        Stable short advisory note code.
    summary:
        Human-readable note summary.
    policy_tags:
        Optional normalized policy tags attached to the note.
    confidence:
        Confidence score from 0.0 to 1.0.
    metadata:
        Optional structured metadata.
    """

    note_id: str
    code: str
    summary: str
    policy_tags: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        code: str,
        summary: str,
        policy_tags: tuple[str, ...] | None = None,
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyAdvisoryNote:
        """
        Construct a new advisory note with a generated identifier.
        """
        return cls(
            note_id=f"policy-note-{uuid4().hex}",
            code=code,
            summary=summary,
            policy_tags=tuple(policy_tags or ()),
            confidence=confidence,
            metadata=dict(metadata or {}),
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "note_id", _normalize_identifier(self.note_id, label="note_id"))
        object.__setattr__(self, "code", _normalize_identifier(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "policy_tags", _normalize_identifiers(self.policy_tags))
        object.__setattr__(self, "confidence", _normalize_probability(self.confidence, label="confidence"))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class PolicyAdvisoryAssessment:
    """
    Structured advisory policy reasoning result for one invocation.

    Attributes
    ----------
    brain_name:
        Stable policy brain identifier.
    invocation_id:
        Stable invocation identifier.
    advisory_disposition:
        Advisory disposition from the policy reasoning lane.
    rationale:
        Human-readable top-level rationale.
    notes:
        Structured advisory notes.
    metadata:
        Optional structured metadata.
    """

    brain_name: str
    invocation_id: str
    advisory_disposition: PolicyAdvisoryDisposition
    rationale: str
    notes: tuple[PolicyAdvisoryNote, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "brain_name", _normalize_identifier(self.brain_name, label="brain_name"))
        object.__setattr__(self, "invocation_id", _normalize_identifier(self.invocation_id, label="invocation_id"))
        object.__setattr__(self, "rationale", _normalize_text(self.rationale, label="rationale"))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.notes and self.advisory_disposition is not PolicyAdvisoryDisposition.ALLOW:
            raise ValueError(
                "Assessments without notes must use advisory_disposition=ALLOW."
            )

    @classmethod
    def create(
        cls,
        *,
        brain_name: str,
        invocation_id: str,
        advisory_disposition: PolicyAdvisoryDisposition,
        rationale: str,
        notes: tuple[PolicyAdvisoryNote, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyAdvisoryAssessment:
        """
        Construct a normalized advisory assessment.
        """
        return cls(
            brain_name=brain_name,
            invocation_id=invocation_id,
            advisory_disposition=advisory_disposition,
            rationale=rationale,
            notes=tuple(notes or ()),
            metadata=dict(metadata or {}),
        )

    def note_codes(self) -> tuple[str, ...]:
        """
        Return advisory note codes in declaration order.
        """
        return tuple(note.code for note in self.notes)

    def policy_tags(self) -> tuple[str, ...]:
        """
        Return unique policy tags across all notes in stable order.
        """
        collected: list[str] = []
        seen: set[str] = set()

        for note in self.notes:
            for tag in note.policy_tags:
                if tag not in seen:
                    collected.append(tag)
                    seen.add(tag)

        return tuple(collected)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_identifiers(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower().replace(" ", "-")
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_probability(value: float, *, label: str) -> float:
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError(f"{label} must be between 0.0 and 1.0.")
    return normalized
