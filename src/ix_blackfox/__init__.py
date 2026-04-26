"""
IX-BlackFox package root.

BlackFox is a programming-first intelligence runtime built around a single
kernel, tiered memory, internal specialist packs, controlled execution, and
auditable traces.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from ix_blackfox.exceptions import (
    BlackFoxError,
    ConfigurationError,
    ErrorContext,
    EvaluationError,
    ForgeError,
    KernelError,
    MemoryError,
    ObservabilityError,
    PackError,
    SentinelError,
    SwitchboardError,
    VaultError,
)

_RUNTIME_EXPORTS = {
    "BlackFoxRuntime": "ix_blackfox.runtime.orchestrator",
    "RuntimeRunReport": "ix_blackfox.runtime.orchestrator",
    "RuntimeRunStatus": "ix_blackfox.runtime.orchestrator",
}

__all__ = [
    "BlackFoxError",
    "ConfigurationError",
    "ErrorContext",
    "EvaluationError",
    "ForgeError",
    "KernelError",
    "MemoryError",
    "ObservabilityError",
    "PackError",
    "SentinelError",
    "SwitchboardError",
    "VaultError",
    "BlackFoxRuntime",
    "RuntimeRunReport",
    "RuntimeRunStatus",
]


def __getattr__(name: str) -> Any:
    try:
        module_name = _RUNTIME_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value
