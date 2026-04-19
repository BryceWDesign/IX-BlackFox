from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ErrorContext:
    """
    Structured context attached to a BlackFox exception.

    Attributes
    ----------
    component:
        Logical subsystem name such as kernel, forge, sentinel, or eval.
    operation:
        Short operation label describing what was happening.
    correlation_id:
        Optional task, trace, or session identifier.
    data:
        Optional structured metadata for diagnostics.
    """

    component: str
    operation: str
    correlation_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_component = _normalize_identifier(
            self.component,
            label="component",
        )
        normalized_operation = _normalize_identifier(
            self.operation,
            label="operation",
        )
        normalized_correlation_id = _normalize_optional_text(self.correlation_id)

        object.__setattr__(self, "component", normalized_component)
        object.__setattr__(self, "operation", normalized_operation)
        object.__setattr__(self, "correlation_id", normalized_correlation_id)


class BlackFoxError(RuntimeError):
    """
    Base runtime error for IX-BlackFox.

    The goal of this taxonomy is to preserve a single root exception type
    while still allowing callers to branch by operational category.
    """

    def __init__(
        self,
        message: str,
        *,
        context: ErrorContext | None = None,
    ) -> None:
        normalized_message = _normalize_text(message, label="message")
        super().__init__(normalized_message)
        self._message = normalized_message
        self._context = context

    @property
    def message(self) -> str:
        """
        Return the normalized exception message.
        """
        return self._message

    @property
    def context(self) -> ErrorContext | None:
        """
        Return optional structured error context.
        """
        return self._context

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the exception into a structured dictionary.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self._message,
            "context": None if self._context is None else {
                "component": self._context.component,
                "operation": self._context.operation,
                "correlation_id": self._context.correlation_id,
                "data": self._context.data,
            },
        }

    def __str__(self) -> str:
        if self._context is None:
            return self._message

        parts = [
            self._message,
            f"component={self._context.component}",
            f"operation={self._context.operation}",
        ]
        if self._context.correlation_id is not None:
            parts.append(f"correlation_id={self._context.correlation_id}")
        return " | ".join(parts)


class ConfigurationError(BlackFoxError):
    """
    Raised when configuration loading, normalization, or validation fails.
    """


class KernelError(BlackFoxError):
    """
    Raised for kernel lifecycle, scheduling, or shared-state failures.
    """


class SwitchboardError(BlackFoxError):
    """
    Raised for capability routing or arbitration failures.
    """


class PackError(BlackFoxError):
    """
    Raised for pack manifest, loading, or execution failures.
    """


class MemoryError(BlackFoxError):
    """
    Raised for memory-layer read, write, or promotion failures.
    """


class VaultError(BlackFoxError):
    """
    Raised for vault sealing, provenance, or integrity failures.
    """


class SentinelError(BlackFoxError):
    """
    Raised for sentinel registration, evaluation, or check failures.
    """


class ForgeError(BlackFoxError):
    """
    Raised for forge workspace, execution, or analysis failures.
    """


class EvaluationError(BlackFoxError):
    """
    Raised for benchmark, evidence, evaluation, or verification failures.
    """


class ObservabilityError(BlackFoxError):
    """
    Raised for structured logging or runtime observability failures.
    """


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"BlackFox error {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"BlackFox error {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
