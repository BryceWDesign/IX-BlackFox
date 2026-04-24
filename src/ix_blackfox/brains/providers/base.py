from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ix_blackfox.brains.contracts import (
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainModality,
)
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.providers.errors import (
    BrainProviderConfigurationError,
    BrainProviderError,
    BrainProviderInvocationError,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
)
from ix_blackfox.exceptions import ErrorContext


@dataclass(frozen=True, slots=True)
class BrainProviderHealth:
    """
    Provider health snapshot.

    Attributes
    ----------
    provider_name:
        Stable provider identifier.
    is_available:
        Whether the provider is currently able to serve requests.
    checked_at:
        UTC timestamp when the health probe completed.
    message:
        Human-readable health summary.
    latency_ms:
        Optional probe latency in milliseconds.
    metadata:
        Optional structured provider health metadata.
    """

    provider_name: str
    is_available: bool
    checked_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    message: str = ""
    latency_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        object.__setattr__(self, "checked_at", _normalize_datetime(self.checked_at))
        object.__setattr__(self, "message", self.message.strip())
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency_ms must be zero or greater when provided.")


@dataclass(frozen=True, slots=True)
class BrainProviderUsage:
    """
    Normalized provider usage metrics.

    Attributes
    ----------
    input_tokens:
        Optional input token count.
    output_tokens:
        Optional output token count.
    total_tokens:
        Optional total token count.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        normalized_input_tokens = _normalize_optional_count(
            self.input_tokens,
            label="input_tokens",
        )
        normalized_output_tokens = _normalize_optional_count(
            self.output_tokens,
            label="output_tokens",
        )
        normalized_total_tokens = _normalize_optional_count(
            self.total_tokens,
            label="total_tokens",
        )

        if normalized_total_tokens is None:
            if normalized_input_tokens is not None and normalized_output_tokens is not None:
                normalized_total_tokens = normalized_input_tokens + normalized_output_tokens

        if (
            normalized_total_tokens is not None
            and normalized_input_tokens is not None
            and normalized_output_tokens is not None
            and normalized_total_tokens < normalized_input_tokens + normalized_output_tokens
        ):
            raise ValueError(
                "total_tokens must be greater than or equal to input_tokens + output_tokens."
            )

        object.__setattr__(self, "input_tokens", normalized_input_tokens)
        object.__setattr__(self, "output_tokens", normalized_output_tokens)
        object.__setattr__(self, "total_tokens", normalized_total_tokens)


@dataclass(frozen=True, slots=True)
class BrainProviderInvocation:
    """
    Normalized provider invocation envelope.

    Attributes
    ----------
    manifest:
        Registered brain manifest that selected the provider.
    request:
        Provider-agnostic brain invocation request.
    timeout_seconds:
        Optional wall-clock timeout budget.
    stream:
        Whether streaming mode is requested.
    metadata:
        Optional provider-neutral invocation metadata.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    timeout_seconds: float | None = None
    stream: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero when provided.")
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.request.brain_name != self.manifest.brain_name:
            raise ValueError(
                "BrainProviderInvocation request.brain_name must match manifest.brain_name."
            )
        unsupported_modalities = tuple(
            modality
            for modality in self.request.input_modalities
            if not self.manifest.accepts_modality(modality)
        )
        if unsupported_modalities:
            raise ValueError(
                "BrainProviderInvocation request includes unsupported input modalities."
            )


@dataclass(frozen=True, slots=True)
class BrainProviderResponse:
    """
    Normalized provider response envelope.

    Attributes
    ----------
    provider_name:
        Stable provider identifier.
    model_name:
        Provider-facing model identifier.
    result:
        Provider-agnostic brain invocation result.
    usage:
        Optional normalized provider usage metrics.
    latency_ms:
        Optional observed invocation latency.
    metadata:
        Optional structured provider response metadata.
    """

    provider_name: str
    model_name: str
    result: BrainInvocationResult
    usage: BrainProviderUsage = field(default_factory=BrainProviderUsage)
    latency_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_name",
            _normalize_identifier(self.provider_name, label="provider_name"),
        )
        model_name = self.model_name.strip()
        if not model_name:
            raise ValueError("model_name must not be empty.")
        object.__setattr__(self, "model_name", model_name)
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency_ms must be zero or greater when provided.")


class BrainProvider(ABC):
    """
    Abstract base for all brain-plane inference providers.

    Concrete adapters are responsible for translating between BlackFox's
    normalized invocation contracts and backend-specific request and
    response protocols.
    """

    def __init__(self, *, provider_name: str) -> None:
        self._provider_name = _normalize_identifier(
            provider_name,
            label="provider_name",
        )

    @property
    def provider_name(self) -> str:
        """
        Return the stable provider identifier.
        """
        return self._provider_name

    @abstractmethod
    def health_check(self) -> BrainProviderHealth:
        """
        Probe provider availability and return a normalized health snapshot.
        """

    @abstractmethod
    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        """
        Execute a normalized provider invocation.
        """

    def supports_manifest(self, manifest: BrainManifest) -> bool:
        """
        Return True when the manifest is owned by this provider.
        """
        return manifest.provider_name == self.provider_name

    def validate_invocation(self, invocation: BrainProviderInvocation) -> None:
        """
        Validate that the invocation can be served by this provider.
        """
        if not self.supports_manifest(invocation.manifest):
            raise BrainProviderConfigurationError(
                "Brain manifest provider_name does not match the selected provider.",
                context=self._context(
                    operation="validate_invocation",
                    correlation_id=invocation.request.invocation_id,
                    data={
                        "manifest_provider_name": invocation.manifest.provider_name,
                        "provider_name": self.provider_name,
                        "brain_name": invocation.manifest.brain_name,
                    },
                ),
            )

        if invocation.request.brain_name != invocation.manifest.brain_name:
            raise BrainProviderConfigurationError(
                "Brain invocation request does not match the selected manifest.",
                context=self._context(
                    operation="validate_invocation",
                    correlation_id=invocation.request.invocation_id,
                    data={
                        "request_brain_name": invocation.request.brain_name,
                        "manifest_brain_name": invocation.manifest.brain_name,
                    },
                ),
            )

        unsupported_modalities = tuple(
            modality.value
            for modality in invocation.request.input_modalities
            if not invocation.manifest.accepts_modality(modality)
        )
        if unsupported_modalities:
            raise BrainProviderConfigurationError(
                "Brain invocation includes modalities unsupported by the selected manifest.",
                context=self._context(
                    operation="validate_invocation",
                    correlation_id=invocation.request.invocation_id,
                    data={
                        "brain_name": invocation.manifest.brain_name,
                        "unsupported_modalities": list(unsupported_modalities),
                    },
                ),
            )

    def unavailable_health(
        self,
        *,
        message: str,
        latency_ms: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BrainProviderHealth:
        """
        Build a normalized unavailable health snapshot.
        """
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=False,
            message=message,
            latency_ms=latency_ms,
            metadata=metadata or {},
        )

    def wrap_error(
        self,
        error: Exception,
        *,
        operation: str,
        correlation_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> BrainProviderError:
        """
        Convert arbitrary provider-side exceptions into the BlackFox taxonomy.
        """
        if isinstance(error, BrainProviderError):
            return error

        context = self._context(
            operation=operation,
            correlation_id=correlation_id,
            data=data,
        )

        if isinstance(error, TimeoutError):
            return BrainProviderTimeoutError(str(error), context=context)

        if isinstance(error, (ConnectionError, OSError)):
            return BrainProviderUnavailableError(str(error), context=context)

        return BrainProviderInvocationError(str(error), context=context)

    def _context(
        self,
        *,
        operation: str,
        correlation_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> ErrorContext:
        return ErrorContext(
            component=f"brain_provider.{self.provider_name}",
            operation=operation,
            correlation_id=correlation_id,
            data=dict(data or {}),
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_count(value: int | None, *, label: str) -> int | None:
    if value is None:
        return None
    if value < 0:
        raise ValueError(f"{label} must be zero or greater when provided.")
    return value


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
