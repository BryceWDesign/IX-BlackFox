from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path

from ix_blackfox.brains.contracts import BrainRole
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.profiles import BrainExecutionProfile


class BrainProviderKind(StrEnum):
    """
    Supported provider families for the BlackFox brain plane.
    """

    OPENAI_COMPATIBLE = auto()
    OLLAMA = auto()
    VLLM = auto()


@dataclass(frozen=True, slots=True)
class AppPaths:
    """
    Canonical runtime paths for IX-BlackFox.

    Attributes
    ----------
    root_dir:
        Repository or deployment root.
    state_dir:
        Durable local application state.
    runtime_dir:
        Transient runtime files.
    artifacts_dir:
        Generated artifacts and outputs.
    logs_dir:
        Log file location.
    temp_dir:
        Temporary working directory for short-lived files.
    """

    root_dir: Path
    state_dir: Path
    runtime_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    temp_dir: Path

    def ensure_exists(self) -> None:
        """
        Create the runtime directory tree if it does not already exist.
        """
        for directory in (
            self.state_dir,
            self.runtime_dir,
            self.artifacts_dir,
            self.logs_dir,
            self.temp_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class BrainProviderConfig:
    """
    Typed configuration for one inference provider.

    Attributes
    ----------
    provider_name:
        Stable provider identifier used by manifests and runtime routing.
    provider_kind:
        Provider family such as ollama, vllm, or openai-compatible.
    base_url:
        Provider base URL.
    enabled:
        Whether the provider should be considered available for routing.
    api_key_env_var:
        Optional environment variable name used to resolve a secret at runtime.
    default_timeout_seconds:
        Default wall-clock timeout for provider invocations.
    endpoint_path:
        Optional provider-specific primary inference path override.
    health_path:
        Optional provider-specific health path override.
    models_path:
        Optional provider-specific models inventory path override.
    metadata:
        Structured future-facing provider metadata.
    """

    provider_name: str
    provider_kind: BrainProviderKind
    base_url: str
    enabled: bool = True
    api_key_env_var: str | None = None
    default_timeout_seconds: float = 60.0
    endpoint_path: str | None = None
    health_path: str | None = None
    models_path: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_provider_name = _normalize_identifier(
            self.provider_name,
            label="provider_name",
        )
        normalized_base_url = self.base_url.strip().rstrip("/")
        normalized_api_key_env_var = _normalize_optional_env_var(self.api_key_env_var)
        normalized_endpoint_path = _normalize_optional_path(self.endpoint_path)
        normalized_health_path = _normalize_optional_path(self.health_path)
        normalized_models_path = _normalize_optional_path(self.models_path)

        if not normalized_base_url:
            raise ValueError("base_url must not be empty.")
        if self.default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be greater than zero.")

        object.__setattr__(self, "provider_name", normalized_provider_name)
        object.__setattr__(self, "base_url", normalized_base_url)
        object.__setattr__(self, "api_key_env_var", normalized_api_key_env_var)
        object.__setattr__(self, "endpoint_path", normalized_endpoint_path)
        object.__setattr__(self, "health_path", normalized_health_path)
        object.__setattr__(self, "models_path", normalized_models_path)
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class BrainDefaultRouting:
    """
    Typed default routing hints for the brain plane.

    Attributes
    ----------
    default_brain_name:
        Optional overall default brain name.
    role_overrides:
        Optional role-to-brain override map.
    pack_overrides:
        Optional pack-to-brain override map.
    """

    default_brain_name: str | None = None
    role_overrides: dict[BrainRole, str] = field(default_factory=dict)
    pack_overrides: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_default_brain_name = _normalize_optional_identifier(
            self.default_brain_name,
            label="default_brain_name",
        )
        normalized_role_overrides = {
            role: _normalize_identifier(brain_name, label=f"role_overrides[{role.value}]")
            for role, brain_name in self.role_overrides.items()
        }
        normalized_pack_overrides = {
            _normalize_identifier(pack_name, label="pack_overrides key"): _normalize_identifier(
                brain_name,
                label=f"pack_overrides[{pack_name}]",
            )
            for pack_name, brain_name in self.pack_overrides.items()
        }

        object.__setattr__(self, "default_brain_name", normalized_default_brain_name)
        object.__setattr__(self, "role_overrides", normalized_role_overrides)
        object.__setattr__(self, "pack_overrides", normalized_pack_overrides)

    def brain_for_role(self, role: BrainRole) -> str | None:
        """
        Return the configured brain override for a role, if present.
        """
        return self.role_overrides.get(role)

    def brain_for_pack(self, pack_name: str) -> str | None:
        """
        Return the configured brain override for a pack, if present.
        """
        normalized_pack_name = _normalize_identifier(pack_name, label="pack_name")
        return self.pack_overrides.get(normalized_pack_name)


@dataclass(frozen=True, slots=True)
class BrainRuntimeConfig:
    """
    Full typed runtime configuration for the BlackFox brain plane.

    Attributes
    ----------
    execution_profile:
        Active execution topology and budget profile.
    providers:
        Configured inference providers.
    manifests:
        Registered brain manifests available to the runtime.
    routing:
        Default routing hints and overrides.
    """

    execution_profile: BrainExecutionProfile = field(
        default_factory=BrainExecutionProfile.local_first
    )
    providers: tuple[BrainProviderConfig, ...] = field(default_factory=tuple)
    manifests: tuple[BrainManifest, ...] = field(default_factory=tuple)
    routing: BrainDefaultRouting = field(default_factory=BrainDefaultRouting)

    def __post_init__(self) -> None:
        provider_names = [provider.provider_name for provider in self.providers]
        if len(provider_names) != len(set(provider_names)):
            raise ValueError("BrainRuntimeConfig provider names must be unique.")

        manifest_names = [manifest.brain_name for manifest in self.manifests]
        if len(manifest_names) != len(set(manifest_names)):
            raise ValueError("BrainRuntimeConfig manifest names must be unique.")

        known_providers = {provider.provider_name for provider in self.providers}
        for manifest in self.manifests:
            if manifest.provider_name not in known_providers:
                raise ValueError(
                    "Every configured brain manifest must reference a configured provider."
                )

        if self.manifests:
            known_brains = {manifest.brain_name for manifest in self.manifests}
            if (
                self.routing.default_brain_name is not None
                and self.routing.default_brain_name not in known_brains
            ):
                raise ValueError(
                    "routing.default_brain_name must reference a configured brain manifest."
                )
            for brain_name in self.routing.role_overrides.values():
                if brain_name not in known_brains:
                    raise ValueError(
                        "routing.role_overrides must reference configured brain manifests."
                    )
            for brain_name in self.routing.pack_overrides.values():
                if brain_name not in known_brains:
                    raise ValueError(
                        "routing.pack_overrides must reference configured brain manifests."
                    )

    def get_provider(self, provider_name: str) -> BrainProviderConfig | None:
        """
        Return a configured provider by stable name.
        """
        normalized_provider_name = _normalize_identifier(
            provider_name,
            label="provider_name",
        )
        for provider in self.providers:
            if provider.provider_name == normalized_provider_name:
                return provider
        return None

    def get_manifest(self, brain_name: str) -> BrainManifest | None:
        """
        Return a configured brain manifest by stable name.
        """
        normalized_brain_name = _normalize_identifier(brain_name, label="brain_name")
        for manifest in self.manifests:
            if manifest.brain_name == normalized_brain_name:
                return manifest
        return None


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """
    Typed runtime configuration for IX-BlackFox.

    Attributes
    ----------
    app_name:
        Stable application identifier.
    environment:
        Runtime environment label, such as development, test, or production.
    log_level:
        Normalized application log level.
    debug:
        Whether debug mode is enabled.
    paths:
        Resolved runtime paths.
    brains:
        Typed multi-brain configuration.
    config_file:
        Optional configuration file path that contributed values.
    """

    app_name: str
    environment: str
    log_level: str
    debug: bool
    paths: AppPaths
    brains: BrainRuntimeConfig = field(default_factory=BrainRuntimeConfig)
    config_file: Path | None = None


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_optional_env_var(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_optional_path(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned
