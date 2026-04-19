from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto

from ix_blackfox.kernel import TaskKind


class PackCapabilityType(StrEnum):
    """
    High-level capability categories exposed by a BlackFox pack.
    """

    REASONING = auto()
    TOOLING = auto()
    RETRIEVAL = auto()
    VALIDATION = auto()
    MEMORY = auto()
    ORCHESTRATION = auto()


@dataclass(frozen=True, slots=True)
class PackCapability:
    """
    One declared capability provided by a pack.

    Attributes
    ----------
    name:
        Stable internal capability name.
    capability_type:
        Broad category for the capability.
    description:
        Human-readable summary of what the capability does.
    """

    name: str
    capability_type: PackCapabilityType
    description: str = ""

    def __post_init__(self) -> None:
        normalized_name = _normalize_identifier(self.name, label="capability name")
        normalized_description = self.description.strip()

        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "description", normalized_description)


@dataclass(frozen=True, slots=True)
class PackManifest:
    """
    Declarative manifest describing one BlackFox internal pack.

    Attributes
    ----------
    pack_name:
        Stable internal pack identifier.
    version:
        Pack version string.
    description:
        Human-readable pack summary.
    supported_kinds:
        Task kinds this pack is intended to handle.
    labels:
        Routing labels associated with this pack.
    capabilities:
        Concrete capabilities exposed by this pack.
    dependencies:
        Names of other packs this pack depends on.
    entrypoint:
        Import path for the pack runtime implementation.
    is_default:
        Whether the pack may be treated as a default general-purpose pack.
    """

    pack_name: str
    version: str
    description: str = ""
    supported_kinds: tuple[TaskKind, ...] = field(default_factory=tuple)
    labels: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[PackCapability, ...] = field(default_factory=tuple)
    dependencies: tuple[str, ...] = field(default_factory=tuple)
    entrypoint: str | None = None
    is_default: bool = False

    def __post_init__(self) -> None:
        normalized_name = _normalize_identifier(self.pack_name, label="pack name")
        normalized_version = self.version.strip()
        if not normalized_version:
            raise ValueError("Pack version must not be empty.")

        normalized_description = self.description.strip()
        normalized_labels = _normalize_identifiers(self.labels, label="label")
        normalized_dependencies = _normalize_identifiers(
            self.dependencies,
            label="dependency",
        )
        normalized_entrypoint = _normalize_optional_text(self.entrypoint)

        object.__setattr__(self, "pack_name", normalized_name)
        object.__setattr__(self, "version", normalized_version)
        object.__setattr__(self, "description", normalized_description)
        object.__setattr__(self, "labels", normalized_labels)
        object.__setattr__(self, "dependencies", normalized_dependencies)
        object.__setattr__(self, "entrypoint", normalized_entrypoint)

    def supports_task_kind(self, kind: TaskKind) -> bool:
        """
        Return True if the manifest explicitly supports the given task kind.
        """
        return kind in self.supported_kinds

    def declares_capability(self, capability_name: str) -> bool:
        """
        Return True if the manifest declares a capability by name.
        """
        normalized_name = _normalize_identifier(
            capability_name,
            label="capability name",
        )
        return any(capability.name == normalized_name for capability in self.capabilities)


@dataclass(frozen=True, slots=True)
class PackManifestSnapshot:
    """
    Immutable view of registered pack manifests.
    """

    manifests: tuple[PackManifest, ...]

    def names(self) -> tuple[str, ...]:
        """
        Return manifest names in insertion order.
        """
        return tuple(manifest.pack_name for manifest in self.manifests)

    def get(self, pack_name: str) -> PackManifest | None:
        """
        Retrieve a manifest by pack name.
        """
        normalized_name = _normalize_identifier(pack_name, label="pack name")
        for manifest in self.manifests:
            if manifest.pack_name == normalized_name:
                return manifest
        return None


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Pack {label} must not be empty.")
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


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
