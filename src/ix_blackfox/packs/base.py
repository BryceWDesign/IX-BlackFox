from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import RuntimeConfig
from ix_blackfox.kernel import SharedStateStore, TaskRecord


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
    metadata:
        Optional extra context for future dependency injection.
    """

    config: RuntimeConfig
    bus: InMemoryEventBus
    shared_state: SharedStateStore
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
