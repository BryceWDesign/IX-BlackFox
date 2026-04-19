"""
IX-BlackFox package root.

BlackFox is a programming-first intelligence runtime built around a
single kernel, tiered memory, internal specialist packs, controlled
execution, and auditable traces.

The public package surface remains intentionally small until the core
runtime contracts are in place.
"""

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
]
