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
    OllamaProvider,
)
from ix_blackfox.brains.providers.base import BrainProviderInvocation


def test_ollama_provider_builds_text_payload_and_normalizes_response() -> None:
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
            "model": "gpt-oss:20b",
            "created_at": "2026-04-23T12:00:00Z",
            "message": {
                "role": "assistant",
                "content": "Patch prepared.",
                "thinking": "Checked likely failure modes.",
            },
            "done": True,
            "done_reason": "stop",
            "total_duration": 2500000000,
            "load_duration": 100000000,
            "prompt_eval_count": 120,
            "prompt_eval_duration": 300000000,
            "eval_count": 80,
            "eval_duration": 900000000,
        }

    provider = OllamaProvider(
        base_url=" http://localhost:11434/ ",
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
            "keep_alive": "5m",
            "think": "medium",
            "response_format": "json",
        },
    )
    invocation = BrainProviderInvocation(
        manifest=manifest,
        request=request,
        timeout_seconds=25.0,
    )

    response = provider.invoke(invocation)
    payload = captured["payload"]

    assert captured["url"] == "http://localhost:11434/api/chat"
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
        "format": "json",
        "options": {
            "temperature": 0.1,
            "top_p": 0.95,
            "seed": 7,
            "num_predict": 512,
        },
        "think": "medium",
        "keep_alive": "5m",
    }
    assert response.result.output_text == "Patch prepared."
    assert response.result.metadata["thinking"] == "Checked likely failure modes."
    assert response.usage.input_tokens == 120
    assert response.usage.output_tokens == 80
    assert response.usage.total_tokens == 200
    assert response.latency_ms == 2500
    assert response.metadata["done_reason"] == "stop"


def test_ollama_provider_builds_image_payload_when_images_are_supplied() -> None:
    provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: {
            "model": "qwen2.5vl:7b",
            "message": {
                "role": "assistant",
                "content": "The screenshot shows a blocked modal.",
            },
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 90,
            "eval_count": 25,
        },
    )
    manifest = _make_manifest(
        brain_name="qwen-vision",
        model_name="qwen2.5vl:7b",
        role=BrainRole.MULTIMODAL,
        capability=BrainCapability.VISION_ANALYSIS,
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )
    request = BrainInvocationRequest.create(
        brain_name="qwen-vision",
        role=BrainRole.MULTIMODAL,
        prompt="Inspect the screenshot.",
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
        metadata={"images": ["base64-image-1"]},
    )
    invocation = BrainProviderInvocation(manifest=manifest, request=request)

    payload = provider.build_payload(invocation)
    response = provider.invoke(invocation)

    assert payload["messages"] == [
        {
            "role": "user",
            "content": "Inspect the screenshot.",
            "images": ["base64-image-1"],
        }
    ]
    assert response.result.status.value == "succeeded"
    assert response.result.output_text == "The screenshot shows a blocked modal."
    assert response.usage.total_tokens == 115


def test_ollama_provider_health_check_uses_tags_transport() -> None:
    provider = OllamaProvider(
        base_url="http://localhost:11434",
        health_transport=lambda url, headers, timeout: {
            "models": [
                {"name": "gpt-oss:20b"},
                {"name": "qwen2.5vl:7b"},
            ],
            "latency_ms": 11,
        },
    )

    health = provider.health_check()

    assert health.provider_name == "ollama"
    assert health.is_available is True
    assert health.latency_ms == 11
    assert health.metadata == {
        "model_names": ["gpt-oss:20b", "qwen2.5vl:7b"],
    }


def test_ollama_provider_rejects_missing_image_payload_or_wrong_modality() -> None:
    provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: {},
    )
    manifest = _make_manifest(
        brain_name="qwen-vision",
        model_name="qwen2.5vl:7b",
        role=BrainRole.MULTIMODAL,
        capability=BrainCapability.VISION_ANALYSIS,
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )

    missing_images_request = BrainInvocationRequest.create(
        brain_name="qwen-vision",
        role=BrainRole.MULTIMODAL,
        prompt="Inspect the screenshot.",
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )
    missing_images_invocation = BrainProviderInvocation(
        manifest=manifest,
        request=missing_images_request,
    )

    with pytest.raises(
        BrainProviderConfigurationError,
        match="require request.metadata\\['images'\\]",
    ):
        provider.build_payload(missing_images_invocation)

    wrong_modality_request = BrainInvocationRequest.create(
        brain_name="qwen-vision",
        role=BrainRole.MULTIMODAL,
        prompt="Inspect the screenshot.",
        input_modalities=(BrainModality.TEXT,),
        metadata={"images": ["base64-image-1"]},
    )
    wrong_modality_invocation = BrainProviderInvocation(
        manifest=manifest,
        request=wrong_modality_request,
    )

    with pytest.raises(
        BrainProviderConfigurationError,
        match="require image modality",
    ):
        provider.build_payload(wrong_modality_invocation)


def test_ollama_provider_raises_for_error_payload_and_protocol_issues() -> None:
    error_provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: {
            "error": "Model overloaded.",
        },
    )
    protocol_provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: {
            "model": "gpt-oss:20b",
            "done": True,
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
        match="message object",
    ):
        protocol_provider.invoke(invocation)


def test_ollama_provider_wraps_transport_failures() -> None:
    timeout_provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: (_ for _ in ()).throw(TimeoutError("Timed out.")),
    )
    unavailable_provider = OllamaProvider(
        base_url="http://localhost:11434",
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


def test_ollama_provider_normalizes_empty_content_as_refusal() -> None:
    provider = OllamaProvider(
        base_url="http://localhost:11434",
        transport=lambda *_args: {
            "model": "gpt-oss-safeguard:20b",
            "message": {
                "role": "assistant",
                "content": "",
            },
            "done": True,
            "done_reason": "blocked",
            "prompt_eval_count": 50,
            "eval_count": 0,
        },
    )
    manifest = _make_manifest(
        brain_name="gpt-oss-safeguard-20b",
        model_name="gpt-oss-safeguard:20b",
        role=BrainRole.SAFETY,
        capability=BrainCapability.SAFETY_CLASSIFICATION,
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
    assert response.result.failure.message == "blocked"
    assert response.usage.total_tokens == 50


def _make_manifest(
    *,
    brain_name: str = "gpt-oss-20b",
    model_name: str = "gpt-oss:20b",
    role: BrainRole = BrainRole.PRIMARY,
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name="ollama",
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
