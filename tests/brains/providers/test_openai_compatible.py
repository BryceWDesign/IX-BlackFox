from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainFailureKind,
    BrainInvocationRequest,
    BrainManifest,
    BrainMessage,
    BrainModelProfile,
    BrainModality,
    BrainModalityProfile,
    BrainRole,
)
from ix_blackfox.brains.providers import (
    BrainProviderConfigurationError,
    BrainProviderInvocationError,
    BrainProviderProtocolError,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
    OpenAICompatibleProvider,
)
from ix_blackfox.brains.providers.base import BrainProviderInvocation


def test_openai_compatible_provider_builds_payload_with_messages_and_prompt() -> None:
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
            "id": "chatcmpl-123",
            "model": "gpt-oss:20b",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Patch ready.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "total_tokens": 140,
            },
        }

    provider = OpenAICompatibleProvider(
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
    }
    assert response.result.output_text == "Patch ready."
    assert response.usage.total_tokens == 140
    assert response.metadata["finish_reason"] == "stop"


def test_openai_compatible_provider_normalizes_refusal_response() -> None:
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {
            "id": "chatcmpl-456",
            "model": "gpt-oss-safeguard:20b",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "refusal": "This request is blocked by policy.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 80,
                "completion_tokens": 0,
                "total_tokens": 80,
            },
        },
    )
    manifest = _make_manifest(
        brain_name="gpt-oss-safeguard-20b",
        model_name="gpt-oss-safeguard:20b",
        capability=BrainCapability.SAFETY_CLASSIFICATION,
        role=BrainRole.SAFETY,
    )
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-safeguard-20b",
        role=BrainRole.SAFETY,
        prompt="Classify the safety risk.",
    )
    invocation = BrainProviderInvocation(manifest=manifest, request=request)

    response = provider.invoke(invocation)

    assert response.result.status.value == "refused"
    assert response.result.failure is not None
    assert response.result.failure.kind is BrainFailureKind.POLICY_BLOCKED
    assert response.result.failure.message == "This request is blocked by policy."
    assert response.result.output_text is None
    assert response.usage.total_tokens == 80


def test_openai_compatible_provider_health_check_uses_probe_transport() -> None:
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        health_transport=lambda url, headers, timeout: {
            "ok": True,
            "message": "healthy",
            "latency_ms": 9,
            "metadata": {
                "url": url,
                "timeout": timeout,
                "has_auth": "Authorization" in headers,
            },
        },
    )

    health = provider.health_check()

    assert health.provider_name == "openai-compatible"
    assert health.is_available is True
    assert health.message == "healthy"
    assert health.latency_ms == 9
    assert health.metadata == {
        "url": "http://localhost:8000/health",
        "timeout": 60.0,
        "has_auth": False,
    }


def test_openai_compatible_provider_rejects_non_text_payload_builds() -> None:
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {},
    )
    manifest = _make_manifest(
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Inspect the screenshot.",
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )
    invocation = BrainProviderInvocation(manifest=manifest, request=request)

    with pytest.raises(
        BrainProviderConfigurationError,
        match="text-only invocation payloads",
    ):
        provider.build_payload(invocation)


def test_openai_compatible_provider_raises_for_error_payload_and_protocol_issues() -> None:
    error_provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {
            "error": {
                "message": "Model overloaded.",
            }
        },
    )
    protocol_provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: {
            "id": "chatcmpl-789",
            "model": "gpt-oss:20b",
            "choices": [],
        },
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

    with pytest.raises(
        BrainProviderProtocolError,
        match="at least one choice",
    ):
        protocol_provider.invoke(invocation)


def test_openai_compatible_provider_wraps_transport_failures() -> None:
    timeout_provider = OpenAICompatibleProvider(
        base_url="http://localhost:8000",
        transport=lambda *_args: (_ for _ in ()).throw(TimeoutError("Timed out.")),
    )
    unavailable_provider = OpenAICompatibleProvider(
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
        provider_name="openai-compatible",
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
