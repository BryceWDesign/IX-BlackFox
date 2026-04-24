from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.brains.contracts import BrainCapability, BrainModality, BrainRole
from ix_blackfox.brains.models import BrainModelProfile


@dataclass(frozen=True, slots=True)
class BrainManifest:
    """
    Declarative manifest describing one registered BlackFox brain.

    Attributes
    ----------
    brain_name:
        Stable internal brain identifier.
    provider_name:
        Stable provider identifier such as ollama or vllm.
    model_name:
        Provider-facing model name.
    version:
        Brain manifest version string.
    profile:
        Provider-agnostic model profile for this brain.
    description:
        Human-readable summary.
    labels:
        Optional routing labels associated with this brain.
    preferred_packs:
        Optional pack names this brain is especially suited for.
    is_default:
        Whether this brain may serve as a default execution candidate.
    """

    brain_name: str
    provider_name: str
    model_name: str
    version: str
    profile: BrainModelProfile
    description: str = ""
    labels: tuple[str, ...] = field(default_factory=tuple)
    preferred_packs: tuple[str, ...] = field(default_factory=tuple)
    is_default: bool = False

    def __post_init__(self) -> None:
        normalized_brain_name = _normalize_identifier(self.brain_name, label="brain name")
        normalized_provider_name = _normalize_identifier(
            self.provider_name,
            label="provider name",
        )
        normalized_model_name = _normalize_model_name(self.model_name)
        normalized_version = self.version.strip()
        normalized_description = self.description.strip()
        normalized_labels = _normalize_identifiers(self.labels, label="label")
        normalized_preferred_packs = _normalize_identifiers(
            self.preferred_packs,
            label="preferred pack",
        )

        if not normalized_version:
            raise ValueError("Brain version must not be empty.")
        if self.profile.brain_name != normalized_brain_name:
            raise ValueError(
                "Brain manifest brain_name must match profile.brain_name."
            )

        object.__setattr__(self, "brain_name", normalized_brain_name)
        object.__setattr__(self, "provider_name", normalized_provider_name)
        object.__setattr__(self, "model_name", normalized_model_name)
        object.__setattr__(self, "version", normalized_version)
        object.__setattr__(self, "description", normalized_description)
        object.__setattr__(self, "labels", normalized_labels)
        object.__setattr__(self, "preferred_packs", normalized_preferred_packs)

    @property
    def roles(self) -> tuple[BrainRole, ...]:
        """
        Return declared cognitive roles from the embedded profile.
        """
        return self.profile.roles

    @property
    def capabilities(self) -> tuple[BrainCapability, ...]:
        """
        Return declared capabilities from the embedded profile.
        """
        return self.profile.capabilities

    def supports_role(self, role: BrainRole) -> bool:
        """
        Return True when this brain may serve the given role.
        """
        return self.profile.supports_role(role)

    def declares_capability(self, capability: BrainCapability) -> bool:
        """
        Return True when this brain declares the given capability.
        """
        return self.profile.declares_capability(capability)

    def accepts_modality(self, modality: BrainModality) -> bool:
        """
        Return True when this brain accepts the given input modality.
        """
        return self.profile.accepts_modality(modality)

    def prefers_pack(self, pack_name: str) -> bool:
        """
        Return True when this brain explicitly prefers the given pack.
        """
        normalized_pack_name = _normalize_identifier(pack_name, label="pack name")
        return normalized_pack_name in self.preferred_packs


@dataclass(frozen=True, slots=True)
class BrainManifestSnapshot:
    """
    Immutable view of registered brain manifests.
    """

    manifests: tuple[BrainManifest, ...]

    def names(self) -> tuple[str, ...]:
        """
        Return registered brain names in insertion order.
        """
        return tuple(manifest.brain_name for manifest in self.manifests)

    def get(self, brain_name: str) -> BrainManifest | None:
        """
        Retrieve a manifest by brain name.
        """
        normalized_name = _normalize_identifier(brain_name, label="brain name")
        for manifest in self.manifests:
            if manifest.brain_name == normalized_name:
                return manifest
        return None

    def defaults(self) -> tuple[BrainManifest, ...]:
        """
        Return manifests marked as default candidates.
        """
        return tuple(manifest for manifest in self.manifests if manifest.is_default)

    def find_by_role(self, role: BrainRole) -> tuple[BrainManifest, ...]:
        """
        Return manifests that support the given role.
        """
        return tuple(manifest for manifest in self.manifests if manifest.supports_role(role))

    def find_by_capability(
        self,
        capability: BrainCapability,
    ) -> tuple[BrainManifest, ...]:
        """
        Return manifests that declare the given capability.
        """
        return tuple(
            manifest
            for manifest in self.manifests
            if manifest.declares_capability(capability)
        )

    def find_for_pack(self, pack_name: str) -> tuple[BrainManifest, ...]:
        """
        Return manifests that explicitly prefer the given pack.
        """
        normalized_pack_name = _normalize_identifier(pack_name, label="pack name")
        return tuple(
            manifest
            for manifest in self.manifests
            if normalized_pack_name in manifest.preferred_packs
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"Brain {label} must not be empty.")
    return cleaned


def _normalize_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_identifier(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_model_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Brain model name must not be empty.")
    return cleaned
