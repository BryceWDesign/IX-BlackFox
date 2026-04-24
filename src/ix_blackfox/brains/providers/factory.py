from __future__ import annotations

from collections.abc import Mapping
from typing import Callable

from ix_blackfox.brains.providers.base import BrainProvider
from ix_blackfox.brains.providers.http_transport import (
    JsonGetTransport,
    JsonPostTransport,
    build_json_get_transport,
    build_json_post_transport,
)
from ix_blackfox.brains.providers.ollama import OllamaProvider
from ix_blackfox.brains.providers.openai_compatible import OpenAICompatibleProvider
from ix_blackfox.brains.providers.vllm import VLLMProvider
from ix_blackfox.config.models import BrainProviderConfig, BrainProviderKind

PostTransportBuilder = Callable[[], JsonPostTransport]
GetTransportBuilder = Callable[[], JsonGetTransport]


class BrainProviderFactory:
    """
    Build concrete provider instances from typed runtime configuration.
    """

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        post_transport_builder: PostTransportBuilder | None = None,
        get_transport_builder: GetTransportBuilder | None = None,
    ) -> None:
        self._env = dict(env or {})
        self._post_transport_builder = post_transport_builder or build_json_post_transport
        self._get_transport_builder = get_transport_builder or build_json_get_transport

    def build_many(
        self,
        provider_configs: tuple[BrainProviderConfig, ...],
    ) -> dict[str, BrainProvider]:
        """
        Build all enabled providers from a tuple of provider configs.
        """
        providers: dict[str, BrainProvider] = {}

        for provider_config in provider_configs:
            if not provider_config.enabled:
                continue

            provider = self.build(provider_config)
            if provider.provider_name in providers:
                raise ValueError(
                    f"Duplicate provider instance for '{provider.provider_name}'."
                )
            providers[provider.provider_name] = provider

        return providers

    def build(self, provider_config: BrainProviderConfig) -> BrainProvider:
        """
        Build one concrete provider instance from typed config.
        """
        api_key = self._resolve_api_key(provider_config)

        if provider_config.provider_kind is BrainProviderKind.OLLAMA:
            kwargs = {
                "base_url": provider_config.base_url,
                "api_key": api_key,
                "provider_name": provider_config.provider_name,
                "transport": self._post_transport_builder(),
                "health_transport": self._get_transport_builder(),
                "default_timeout_seconds": provider_config.default_timeout_seconds,
            }
            if provider_config.endpoint_path is not None:
                kwargs["chat_path"] = provider_config.endpoint_path
            if provider_config.health_path is not None:
                kwargs["tags_path"] = provider_config.health_path
            return OllamaProvider(**kwargs)

        if provider_config.provider_kind is BrainProviderKind.OPENAI_COMPATIBLE:
            kwargs = {
                "base_url": provider_config.base_url,
                "api_key": api_key,
                "provider_name": provider_config.provider_name,
                "transport": self._post_transport_builder(),
                "health_transport": self._get_transport_builder(),
                "default_timeout_seconds": provider_config.default_timeout_seconds,
            }
            if provider_config.endpoint_path is not None:
                kwargs["endpoint_path"] = provider_config.endpoint_path
            if provider_config.health_path is not None:
                kwargs["health_path"] = provider_config.health_path
            return OpenAICompatibleProvider(**kwargs)

        if provider_config.provider_kind is BrainProviderKind.VLLM:
            kwargs = {
                "base_url": provider_config.base_url,
                "api_key": api_key,
                "provider_name": provider_config.provider_name,
                "transport": self._post_transport_builder(),
                "models_transport": self._get_transport_builder(),
                "health_transport": self._get_transport_builder(),
                "default_timeout_seconds": provider_config.default_timeout_seconds,
            }
            if provider_config.endpoint_path is not None:
                kwargs["endpoint_path"] = provider_config.endpoint_path
            if provider_config.health_path is not None:
                kwargs["health_path"] = provider_config.health_path
            if provider_config.models_path is not None:
                kwargs["models_path"] = provider_config.models_path
            return VLLMProvider(**kwargs)

        raise ValueError(
            f"Unsupported provider kind '{provider_config.provider_kind.value}'."
        )

    def _resolve_api_key(self, provider_config: BrainProviderConfig) -> str | None:
        env_var = provider_config.api_key_env_var
        if env_var is None:
            return None

        value = self._env.get(env_var)
        if value is None:
            return None

        cleaned = value.strip()
        return cleaned or None
