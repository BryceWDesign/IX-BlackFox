from __future__ import annotations

from ix_blackfox.brains.providers import (
    BrainProviderFactory,
    OllamaProvider,
    OpenAICompatibleProvider,
    VLLMProvider,
)
from ix_blackfox.config.models import BrainProviderConfig, BrainProviderKind


def test_provider_factory_builds_enabled_provider_instances_and_resolves_api_keys() -> None:
    factory = BrainProviderFactory(
        env={
            "OLLAMA_API_KEY": "ollama-secret",
            "REMOTE_API_KEY": "remote-secret",
        }
    )
    configs = (
        BrainProviderConfig(
            provider_name="ollama",
            provider_kind=BrainProviderKind.OLLAMA,
            base_url=" http://localhost:11434/ ",
            api_key_env_var="OLLAMA_API_KEY",
            endpoint_path="api/chat",
            health_path="api/tags",
        ),
        BrainProviderConfig(
            provider_name="OpenAI Compatible",
            provider_kind=BrainProviderKind.OPENAI_COMPATIBLE,
            base_url=" https://llm.example.com/ ",
            api_key_env_var="REMOTE_API_KEY",
            endpoint_path="v1/chat/completions",
            health_path="status",
        ),
        BrainProviderConfig(
            provider_name="vLLM",
            provider_kind=BrainProviderKind.VLLM,
            base_url=" https://vllm.example.com/ ",
            endpoint_path="/v1/chat/completions",
            health_path="/healthz",
            models_path="v1/models",
        ),
        BrainProviderConfig(
            provider_name="disabled-provider",
            provider_kind=BrainProviderKind.OLLAMA,
            base_url="http://disabled.example.com",
            enabled=False,
        ),
    )

    providers = factory.build_many(configs)

    assert tuple(providers.keys()) == (
        "ollama",
        "openai-compatible",
        "vllm",
    )

    ollama = providers["ollama"]
    assert isinstance(ollama, OllamaProvider)
    assert ollama.base_url == "http://localhost:11434"
    assert ollama.chat_url == "http://localhost:11434/api/chat"
    assert ollama.tags_url == "http://localhost:11434/api/tags"
    assert ollama._build_headers()["Authorization"] == "Bearer ollama-secret"  # noqa: SLF001

    remote = providers["openai-compatible"]
    assert isinstance(remote, OpenAICompatibleProvider)
    assert remote.base_url == "https://llm.example.com"
    assert remote.endpoint_url == "https://llm.example.com/v1/chat/completions"
    assert remote.health_url == "https://llm.example.com/status"
    assert remote._build_headers()["Authorization"] == "Bearer remote-secret"  # noqa: SLF001

    vllm = providers["vllm"]
    assert isinstance(vllm, VLLMProvider)
    assert vllm.base_url == "https://vllm.example.com"
    assert vllm.endpoint_url == "https://vllm.example.com/v1/chat/completions"
    assert vllm.health_url == "https://vllm.example.com/healthz"
    assert vllm.models_url == "https://vllm.example.com/v1/models"
    assert "Authorization" not in vllm._build_headers()  # noqa: SLF001


def test_provider_factory_builds_single_provider_with_default_paths() -> None:
    factory = BrainProviderFactory(env={})
    config = BrainProviderConfig(
        provider_name="ollama",
        provider_kind=BrainProviderKind.OLLAMA,
        base_url="http://localhost:11434",
    )

    provider = factory.build(config)

    assert isinstance(provider, OllamaProvider)
    assert provider.base_url == "http://localhost:11434"
    assert provider.chat_url == "http://localhost:11434/api/chat"
    assert provider.tags_url == "http://localhost:11434/api/tags"
