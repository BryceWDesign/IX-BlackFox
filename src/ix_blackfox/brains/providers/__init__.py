from __future__ import annotations

"""
Provider abstraction layer for IX-BlackFox brains.

This package defines the stable provider interface that concrete
adapters such as Ollama, vLLM, and OpenAI-compatible backends will
implement in later commits.
"""

from ix_blackfox.brains.providers.base import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
    BrainProviderUsage,
)
from ix_blackfox.brains.providers.errors import (
    BrainProviderConfigurationError,
    BrainProviderError,
    BrainProviderInvocationError,
    BrainProviderProtocolError,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
)
from ix_blackfox.brains.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "BrainProvider",
    "BrainProviderConfigurationError",
    "BrainProviderError",
    "BrainProviderHealth",
    "BrainProviderInvocation",
    "BrainProviderInvocationError",
    "BrainProviderProtocolError",
    "BrainProviderResponse",
    "BrainProviderTimeoutError",
    "BrainProviderUnavailableError",
    "BrainProviderUsage",
    "OpenAICompatibleProvider",
]
