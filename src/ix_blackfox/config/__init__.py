"""
Configuration subsystem for IX-BlackFox.

This package owns runtime configuration loading, normalization, and path
resolution. The goal is to keep configuration explicit, typed, and easy
to override without scattering environment lookups throughout the codebase.
"""

from ix_blackfox.config.loader import load_runtime_config
from ix_blackfox.config.models import (
    AppPaths,
    BrainDefaultRouting,
    BrainProviderConfig,
    BrainProviderKind,
    BrainRuntimeConfig,
    RuntimeConfig,
)

__all__ = [
    "AppPaths",
    "BrainDefaultRouting",
    "BrainProviderConfig",
    "BrainProviderKind",
    "BrainRuntimeConfig",
    "RuntimeConfig",
    "load_runtime_config",
]
