from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.brains.contracts import BrainCapability, BrainModality, BrainRole
from ix_blackfox.brains.manifest import BrainManifest


@dataclass(frozen=True, slots=True)
class BrainRoutingRequest:
    """
    Normalized request for selecting the best brain for one runtime task.

    Attributes
    ----------
    required_role:
        Mandatory cognitive role the selected brain must support.
    required_capabilities:
        Capabilities the selected brain must declare.
    input_modalities:
        Modalities carried by the task.
    pack_name:
        Optional originating pack name.
    preferred_labels:
        Optional preferred routing labels.
    metadata:
        Structured routing metadata reserved for later policy expansion.
    """

    required_role: BrainRole
    required_capabilities: tuple[BrainCapability, ...] = field(default_factory=tuple)
    input_modalities: tuple[BrainModality, ...] = field(
        default_factory=lambda: (BrainModality.TEXT,)
    )
    pack_name: str | None = None
    preferred_labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "required_capabilities",
            _normalize_capabilities(self.required_capabilities),
        )
        object.__setattr__(
            self,
            "input_modalities",
            _normalize_modalities(self.input_modalities),
        )
        object.__setattr__(
            self,
            "pack_name",
            _normalize_optional_identifier(self.pack_name),
        )
        object.__setattr__(
            self,
            "preferred_labels",
            _normalize_identifiers(self.preferred_labels),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class BrainScoreBreakdown:
    """
    Transparent score components for one routing candidate.
    """

    role_score: int = 0
    capability_score: int = 0
    modality_score: int = 0
    pack_score: int = 0
    label_score: int = 0
    default_score: int = 0
    penalties: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        """
        Return the total score after penalties.
        """
        return (
            self.role_score
            + self.capability_score
            + self.modality_score
            + self.pack_score
            + self.label_score
            + self.default_score
        )


@dataclass(frozen=True, slots=True)
class BrainRoutingPolicy:
    """
    Deterministic policy for scoring eligible brains.
    """

    role_weight: int = 100
    capability_weight: int = 20
    modality_weight: int = 10
    preferred_pack_bonus: int = 25
    preferred_label_bonus: int = 5
    default_bonus: int = 8

    def score(
        self,
        manifest: BrainManifest,
        request: BrainRoutingRequest,
    ) -> BrainScoreBreakdown:
        """
        Compute a deterministic score for an already-eligible candidate.
        """
        role_score = self.role_weight if manifest.supports_role(request.required_role) else 0
        capability_score = self.capability_weight * len(request.required_capabilities)
        modality_score = self.modality_weight * len(request.input_modalities)
        pack_score = (
            self.preferred_pack_bonus
            if request.pack_name is not None and manifest.prefers_pack(request.pack_name)
            else 0
        )
        label_score = self.preferred_label_bonus * _count_shared_labels(
            manifest.labels,
            request.preferred_labels,
        )
        default_score = self.default_bonus if manifest.is_default else 0

        return BrainScoreBreakdown(
            role_score=role_score,
            capability_score=capability_score,
            modality_score=modality_score,
            pack_score=pack_score,
            label_score=label_score,
            default_score=default_score,
        )


def _count_shared_labels(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    if not left or not right:
        return 0
    return len(set(left).intersection(right))


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError("pack_name must not be empty when provided.")
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


def _normalize_modalities(
    values: tuple[BrainModality, ...],
) -> tuple[BrainModality, ...]:
    normalized: list[BrainModality] = []
    seen: set[BrainModality] = set()

    for value in values:
        if value not in seen:
            normalized.append(value)
            seen.add(value)

    if not normalized:
        raise ValueError("input_modalities must declare at least one modality.")

    return tuple(normalized)
