from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import RuntimeConfig
from ix_blackfox.kernel import SharedStateStore, TaskRecord


@dataclass(frozen=True, slots=True)
class PackBrainContext:
    """
    Primary-brain context made visible to a pack at execution time.

    Attributes
    ----------
    brain_name:
        Stable selected brain identifier.
    provider_name:
        Selected provider identifier.
    model_name:
        Provider-facing model identifier.
    invocation_id:
        Stable brain invocation identifier.
    rendered_prompt:
        Rendered prompt envelope prepared for the provider.
    invoked:
        Whether a provider call was actually attempted.
    result_status:
        Final normalized invocation status when available.
    output_text:
        Optional primary model output when available.
    failure_message:
        Optional failure summary when invocation did not succeed.
    """

    brain_name: str
    provider_name: str
    model_name: str
    invocation_id: str
    rendered_prompt: str
    invoked: bool = False
    result_status: str | None = None
    output_text: str | None = None
    failure_message: str | None = None

    def __post_init__(self) -> None:
        normalized_brain_name = _normalize_identifier(self.brain_name, label="brain_name")
        normalized_provider_name = _normalize_identifier(
            self.provider_name,
            label="provider_name",
        )
        normalized_model_name = self.model_name.strip()
        normalized_invocation_id = _normalize_identifier(
            self.invocation_id,
            label="invocation_id",
        )
        normalized_rendered_prompt = self.rendered_prompt.strip()
        normalized_result_status = _normalize_optional_identifier(
            self.result_status,
            label="result_status",
        )
        normalized_output_text = _normalize_optional_text(self.output_text)
        normalized_failure_message = _normalize_optional_text(self.failure_message)

        if not normalized_model_name:
            raise ValueError("model_name must not be empty.")
        if not normalized_rendered_prompt:
            raise ValueError("rendered_prompt must not be empty.")

        object.__setattr__(self, "brain_name", normalized_brain_name)
        object.__setattr__(self, "provider_name", normalized_provider_name)
        object.__setattr__(self, "model_name", normalized_model_name)
        object.__setattr__(self, "invocation_id", normalized_invocation_id)
        object.__setattr__(self, "rendered_prompt", normalized_rendered_prompt)
        object.__setattr__(self, "result_status", normalized_result_status)
        object.__setattr__(self, "output_text", normalized_output_text)
        object.__setattr__(self, "failure_message", normalized_failure_message)


@dataclass(frozen=True, slots=True)
class PackContext:
    """
    Runtime context supplied to a pack during execution.

    Attributes
    ----------
    config:
        Active BlackFox runtime configuration.
    bus:
        Internal event bus used for coordination and trace publication.
    shared_state:
        Shared kernel state store.
    brain:
        Optional primary-brain invocation context prepared before pack execution.
    metadata:
        Optional extra context for future dependency injection.
    """

    config: RuntimeConfig
    bus: InMemoryEventBus
    shared_state: SharedStateStore
    brain: PackBrainContext | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PackExecutionResult:
    """
    Normalized result returned by a pack execution.

    Attributes
    ----------
    summary:
        Short human-readable outcome summary.
    artifacts:
        Logical artifact references produced by the pack.
    metrics:
        Optional execution metrics or counters.
    data:
        Optional structured result payload.
    """

    summary: str
    artifacts: tuple[str, ...] = field(default_factory=tuple)
    metrics: dict[str, float | int | str | bool] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_summary = self.summary.strip()
        if not normalized_summary:
            raise ValueError("Pack execution summary must not be empty.")

        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "artifacts", _normalize_strings(self.artifacts))


class BasePack(ABC):
    """
    Base protocol for executable BlackFox packs.

    Concrete packs implement a stable `execute` method so the kernel can
    invoke them consistently regardless of domain.
    """

    @property
    @abstractmethod
    def pack_name(self) -> str:
        """
        Stable internal pack name.
        """

    @abstractmethod
    def execute(
        self,
        *,
        task: TaskRecord,
        context: PackContext,
    ) -> PackExecutionResult:
        """
        Execute pack logic against a kernel task record.
        """


def _normalize_strings(values: tuple[str, ...]) -> tuple[str, ...]:
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


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
