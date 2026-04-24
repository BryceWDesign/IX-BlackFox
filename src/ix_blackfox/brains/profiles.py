from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto

from ix_blackfox.brains.budgets import BrainInferenceBudget


class BrainExecutionMode(StrEnum):
    """
    High-level execution topology for a runtime profile.
    """

    LOCAL = auto()
    HYBRID = auto()
    REMOTE = auto()


@dataclass(frozen=True, slots=True)
class BrainExecutionProfile:
    """
    Operator-facing execution profile for brain routing.

    Attributes
    ----------
    profile_name:
        Stable profile identifier.
    mode:
        High-level execution topology.
    budget:
        Explicit inference budget carried by the profile.
    allowed_providers:
        Optional allowlist of providers.
    preferred_providers:
        Optional ordered provider preference list.
    allow_local:
        Whether local providers may be used.
    allow_remote:
        Whether remote providers may be used.
    allow_streaming:
        Whether streaming-capable brains are allowed to use streaming mode.
    metadata:
        Structured future-facing profile metadata.
    """

    profile_name: str
    mode: BrainExecutionMode
    budget: BrainInferenceBudget = field(default_factory=BrainInferenceBudget)
    allowed_providers: tuple[str, ...] = field(default_factory=tuple)
    preferred_providers: tuple[str, ...] = field(default_factory=tuple)
    allow_local: bool = True
    allow_remote: bool = False
    allow_streaming: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_profile_name = _normalize_identifier(
            self.profile_name,
            label="profile_name",
        )
        normalized_allowed_providers = _normalize_identifiers(self.allowed_providers)
        normalized_preferred_providers = _normalize_identifiers(
            self.preferred_providers
        )

        if self.mode is BrainExecutionMode.LOCAL and self.allow_remote:
            raise ValueError("LOCAL execution profiles must not allow remote execution.")
        if self.mode is BrainExecutionMode.REMOTE and not self.allow_remote:
            raise ValueError("REMOTE execution profiles must allow remote execution.")
        if self.mode is BrainExecutionMode.REMOTE and self.allow_local:
            raise ValueError("REMOTE execution profiles must not allow local execution.")
        if self.mode is BrainExecutionMode.HYBRID and not self.allow_remote:
            raise ValueError("HYBRID execution profiles must allow remote execution.")
        if self.mode is BrainExecutionMode.HYBRID and not self.allow_local:
            raise ValueError("HYBRID execution profiles must allow local execution.")

        if normalized_preferred_providers:
            missing = tuple(
                provider
                for provider in normalized_preferred_providers
                if normalized_allowed_providers and provider not in normalized_allowed_providers
            )
            if missing:
                raise ValueError(
                    "preferred_providers must be a subset of allowed_providers when an allowlist is provided."
                )

        object.__setattr__(self, "profile_name", normalized_profile_name)
        object.__setattr__(self, "allowed_providers", normalized_allowed_providers)
        object.__setattr__(self, "preferred_providers", normalized_preferred_providers)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def local_first(
        cls,
        *,
        profile_name: str = "local-first",
        budget: BrainInferenceBudget | None = None,
        allowed_providers: tuple[str, ...] = (),
        preferred_providers: tuple[str, ...] = (),
        allow_streaming: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> BrainExecutionProfile:
        """
        Build a strictly local execution profile.
        """
        return cls(
            profile_name=profile_name,
            mode=BrainExecutionMode.LOCAL,
            budget=budget or BrainInferenceBudget(),
            allowed_providers=allowed_providers,
            preferred_providers=preferred_providers,
            allow_local=True,
            allow_remote=False,
            allow_streaming=allow_streaming,
            metadata=metadata or {},
        )

    @classmethod
    def hybrid(
        cls,
        *,
        profile_name: str = "hybrid",
        budget: BrainInferenceBudget | None = None,
        allowed_providers: tuple[str, ...] = (),
        preferred_providers: tuple[str, ...] = (),
        allow_streaming: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> BrainExecutionProfile:
        """
        Build a hybrid local-plus-remote execution profile.
        """
        return cls(
            profile_name=profile_name,
            mode=BrainExecutionMode.HYBRID,
            budget=budget or BrainInferenceBudget(),
            allowed_providers=allowed_providers,
            preferred_providers=preferred_providers,
            allow_local=True,
            allow_remote=True,
            allow_streaming=allow_streaming,
            metadata=metadata or {},
        )

    @classmethod
    def remote_only(
        cls,
        *,
        profile_name: str = "remote-only",
        budget: BrainInferenceBudget | None = None,
        allowed_providers: tuple[str, ...] = (),
        preferred_providers: tuple[str, ...] = (),
        allow_streaming: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> BrainExecutionProfile:
        """
        Build a strictly remote execution profile.
        """
        return cls(
            profile_name=profile_name,
            mode=BrainExecutionMode.REMOTE,
            budget=budget or BrainInferenceBudget(),
            allowed_providers=allowed_providers,
            preferred_providers=preferred_providers,
            allow_local=False,
            allow_remote=True,
            allow_streaming=allow_streaming,
            metadata=metadata or {},
        )

    def permits_provider(self, provider_name: str) -> bool:
        """
        Return True when the provider is permitted by this profile.
        """
        normalized_provider = _normalize_identifier(
            provider_name,
            label="provider_name",
        )
        if not self.allowed_providers:
            return True
        return normalized_provider in self.allowed_providers

    def prefers_provider(self, provider_name: str) -> bool:
        """
        Return True when the provider is explicitly preferred.
        """
        normalized_provider = _normalize_identifier(
            provider_name,
            label="provider_name",
        )
        return normalized_provider in self.preferred_providers


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
