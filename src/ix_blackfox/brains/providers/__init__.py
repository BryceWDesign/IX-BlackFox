from __future__ import annotations

"""
Provider abstraction layer for IX-BlackFox brains.

This package defines the stable provider interface that concrete
adapters such as Ollama, vLLM, and OpenAI-compatible backends will
implement.
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
from ix_blackfox.brains.providers.factory import BrainProviderFactory
from ix_blackfox.brains.providers.http_transport import (
    JsonGetTransport,
    JsonPostTransport,
    build_json_get_transport,
    build_json_post_transport,
)
from ix_blackfox.brains.providers.ollama import OllamaProvider
from ix_blackfox.brains.providers.openai_compatible import OpenAICompatibleProvider
from ix_blackfox.brains.providers.vllm import VLLMProvider

__all__ = [
    "BrainProvider",
    "BrainProviderConfigurationError",
    "BrainProviderError",
    "BrainProviderFactory",
    "BrainProviderHealth",
    "BrainProviderInvocation",
    "BrainProviderInvocationError",
    "BrainProviderProtocolError",
    "BrainProviderResponse",
    "BrainProviderTimeoutError",
    "BrainProviderUnavailableError",
    "BrainProviderUsage",
    "JsonGetTransport",
    "JsonPostTransport",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "VLLMProvider",
    "build_json_get_transport",
    "build_json_post_transport",
]
