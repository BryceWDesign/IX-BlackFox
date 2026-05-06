from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainInvocationRequest,
    BrainManifest,
    BrainMessage,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainRole,
)
from ix_blackfox.brains.providers import (
    BrainProviderInvocationError,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
    VLLMProvider,
)
from ix_blackfox.brains.providers.base import BrainProviderInvocation


def test_vllm_provider_builds_payload_with_extra_body_and_stream_options() -> None:
    captured: dict[str, object] = {}

    def transport(
        url: str,
        headers: dict[str, str],
        payload: dict[str, object],
        timeout_seconds: float | None,
    ) -> dict[str, object]:
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = payload
        captured["timeout_seconds"] = timeout_seconds
        return {
            "id": "chatcmpl-vllm-123",
            "model": "gpt-oss:20b",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "Patch prepared."},
                            {"type": "text", "text": "Verification path noted."},
                        ],
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 60,
                "total_tokens": 210,
            },
        }

    provider = VLLMProvider(
        base_url=" http://localhost:8000/ ",
        api_key=" test-key ",
        transport=transport,
    )
    manifest = _make_manifest()
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Prepare the patch.",
        messages=(
            BrainMessage(role="system", content="You are rigorous."),
            BrainMessage(role="user", content="Inspect the repo first."),
        ),
        metadata={
            "temperature": 0.1,
            "top_p": 0.95,
            "max_output_tokens": 512,
            "seed": 7,
            "stream_options": {"include_usage": True},
            "extra_body": {
                "priority": 3,
                "top_k": 40,
            },
        },
    )
    invocation = BrainProviderInvocation(
        manifest=manifest,
        request=request,
        timeout_seconds=25.0,
    )

    response = provider.invoke(invocation)
    payload = captured["payload"]

    assert captured["url"] == "http://localhost:8000/v1/chat/completions"
    assert captured["headers"] == {
        "Content-Type": "application/json",
        "Authorization": "Bearer test-key",
    }
    assert captured["timeout_seconds"] == 25.0
    assert payload == {
        "model": "gpt-oss:20b",
        "messages": [
            {"role": "system", "content": "You are rigorous."},
            {"role": "user", "content": "Inspect the repo first."},
            {"role": "user", "content": "Prepare the patch."},
        ],
        "stream": False,
        "temperature": 0.1,
        "top_p": 0.95,
        "max_tokens": 512,
        "seed": 7,
        "stream_options": {"include_usage": True},
        "priority": 3,
        "top_k": 40,
    }
    assert response.result.output_text == "Patch prepared.\nVerification path noted."
    assert response.usage.total_tokens == 210
    assert response.metadata["finish_reason"] == "stop"


def test_vllm_provider_health_check_prefers_model_inventory_probe() -> None:
    provider = VLLMProvider(
        base_url="http://localhost:8000",
        models_transport=lambda url, headers, timeout: {
            "data": [
                {"id": "gpt-oss:20b"},
                {"id": "qwen2.5-vl:7b"},
            ],
            "latency_ms": 14,
        },
    )

    health = provider.health_check()

    assert health.provider_name == "vllm"
    assert health.is_available is True
    assert health.message == "healthy (2 model(s) visible)"
    assert health.latency_ms == 14
    assert health.metadata == {
        "model_ids": ("gpt-oss:20b", "qwen2.5-vl:7b"),
    }


def test_vllm_provider_falls_back_to_openai_health_probe_when_models_probe_missing() -> None:
    provider = VLLMProvider(
        base_url="http://localhost:8000",
        health_transport=lambda url, headers, timeout: {
            "ok": True,
            "message": "healthy",
            "latency_ms": 9,
            "metadata": {
                "url": url,
                "timeout": timeout,
            },
        },
    )

    health = provider.health_check()

    assert health.provider_name == "vllm"
    assert health.is_available is True
    assert health.message == "healthy"
    assert health.latency_ms == 9
    assert health.metadata == {
        "url": "http://localhost:8000/health",
        "timeout": 60.0,
    }


def test_vllm_provider_rejects_non_dict_extra_body() -> None:
    provider = VLLMProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {},
    )
    manifest = _make_manifest()
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Proceed.",
        metadata={"extra_body": "not-a-dict"},
    )
    invocation = BrainProviderInvocation(manifest=manifest, request=request)

    with pytest.raises(ValueError, match="extra_body"):
        provider.build_payload(invocation)


def test_vllm_provider_raises_for_error_payload_and_transport_failures() -> None:
    error_provider = VLLMProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {
            "error": {
                "message": "Model overloaded.",
            }
        },
    )
    timeout_provider = VLLMProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: (_ for _ in ()).throw(TimeoutError("Timed out.")),
    )
    unavailable_provider = VLLMProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: (_ for _ in ()).throw(ConnectionError("Offline.")),
    )
    manifest = _make_manifest()
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Proceed.",
    )
    invocation = BrainProviderInvocation(manifest=manifest, request=request)

    with pytest.raises(BrainProviderInvocationError, match="Model overloaded"):
        error_provider.invoke(invocation)

    with pytest.raises(BrainProviderTimeoutError, match="Timed out"):
        timeout_provider.invoke(invocation)

    with pytest.raises(BrainProviderUnavailableError, match="Offline"):
        unavailable_provider.invoke(invocation)


def _make_manifest(
    *,
    brain_name: str = "gpt-oss-20b",
    model_name: str = "gpt-oss:20b",
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
    role: BrainRole = BrainRole.PRIMARY,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name="vllm",
        model_name=model_name,
        version="0.1.0",
        is_default=True,
        profile=BrainModelProfile(
            brain_name=brain_name,
            roles=(role,),
            capabilities=(capability,),
            context_window=BrainContextWindow(
                max_input_tokens=32768,
                max_output_tokens=4096,
            ),
            modalities=BrainModalityProfile(
                input_modalities=input_modalities,
                output_modalities=(BrainModality.TEXT,),
            ),
        ),
    )
