from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainFailure,
    BrainFailureKind,
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainManifest,
    BrainModelProfile,
    BrainModality,
    BrainModalityProfile,
    BrainRole,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderConfigurationError,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderInvocationError,
    BrainProviderResponse,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
    BrainProviderUsage,
)


class DummyProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            checked_at=datetime(2026, 4, 23, 12, 0, tzinfo=UTC),
            message="healthy",
            latency_ms=12,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text="Provider completed the request.",
                output_modalities=(BrainModality.TEXT,),
            ),
            usage=BrainProviderUsage(input_tokens=100, output_tokens=40),
            latency_ms=125,
            metadata={"backend": "dummy"},
        )


def test_provider_health_and_usage_normalize_and_validate() -> None:
    health = BrainProviderHealth(
        provider_name=" Ollama ",
        is_available=True,
        checked_at=datetime(2026, 4, 23, 12, 0),
        message="  healthy  ",
        latency_ms=8,
        metadata={"probe": "ping"},
    )
    usage = BrainProviderUsage(input_tokens=10, output_tokens=20)

    assert health.provider_name == "ollama"
    assert health.checked_at.tzinfo is not None
    assert health.message == "healthy"
    assert health.latency_ms == 8
    assert health.metadata == {"probe": "ping"}
    assert usage.total_tokens == 30

    with pytest.raises(ValueError, match="latency_ms"):
        BrainProviderHealth(provider_name="ollama", is_available=False, latency_ms=-1)

    with pytest.raises(ValueError, match="total_tokens"):
        BrainProviderUsage(input_tokens=5, output_tokens=5, total_tokens=9)


def test_provider_invocation_and_response_work_for_matching_manifest() -> None:
    provider = DummyProvider()
    manifest = _make_manifest(provider_name="ollama")
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Solve the task.",
        task_id="task-123",
        pack_name="programming",
    )
    invocation = BrainProviderInvocation(
        manifest=manifest,
        request=request,
        timeout_seconds=30.0,
        metadata={"attempt": "first"},
    )

    response = provider.invoke(invocation)

    assert provider.health_check().is_available is True
    assert response.provider_name == "ollama"
    assert response.model_name == "gpt-oss:20b"
    assert response.result.status is BrainInvocationStatus.SUCCEEDED
    assert response.result.output_text == "Provider completed the request."
    assert response.usage.total_tokens == 140
    assert response.metadata == {"backend": "dummy"}


def test_provider_validate_invocation_rejects_provider_mismatch() -> None:
    provider = DummyProvider()
    manifest = _make_manifest(provider_name="vllm")
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Solve the task.",
    )
    invocation = BrainProviderInvocation(
        manifest=manifest,
        request=request,
    )

    with pytest.raises(BrainProviderConfigurationError, match="provider_name"):
        provider.validate_invocation(invocation)


def test_provider_invocation_rejects_unsupported_modalities_early() -> None:
    manifest = _make_manifest(
        provider_name="ollama",
        input_modalities=(BrainModality.TEXT,),
    )
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Inspect this screenshot.",
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )

    with pytest.raises(ValueError, match="unsupported input modalities"):
        BrainProviderInvocation(
            manifest=manifest,
            request=request,
        )


def test_provider_wrap_error_maps_timeout_unavailable_and_generic_errors() -> None:
    provider = DummyProvider()

    timeout_error = provider.wrap_error(
        TimeoutError("Provider timed out."),
        operation="invoke",
        correlation_id="brain-call-1",
    )
    unavailable_error = provider.wrap_error(
        ConnectionError("Connection refused."),
        operation="health_check",
        correlation_id="brain-call-2",
    )
    generic_error = provider.wrap_error(
        RuntimeError("Unexpected failure."),
        operation="invoke",
        correlation_id="brain-call-3",
        data={"phase": "decode"},
    )

    assert isinstance(timeout_error, BrainProviderTimeoutError)
    assert timeout_error.context is not None
    assert timeout_error.context.component == "brain_provider.ollama"
    assert timeout_error.context.operation == "invoke"

    assert isinstance(unavailable_error, BrainProviderUnavailableError)
    assert unavailable_error.context is not None
    assert unavailable_error.context.operation == "health_check"

    assert isinstance(generic_error, BrainProviderInvocationError)
    assert generic_error.context is not None
    assert generic_error.context.data == {"phase": "decode"}


def test_provider_response_validates_latency_and_model_name() -> None:
    result = BrainInvocationResult(
        invocation_id="brain-call-123",
        brain_name="gpt-oss-20b",
        status=BrainInvocationStatus.REFUSED,
        failure=BrainFailure(
            kind=BrainFailureKind.POLICY_BLOCKED,
            message="Blocked by policy.",
        ),
    )

    response = BrainProviderResponse(
        provider_name=" ollama ",
        model_name=" gpt-oss:20b ",
        result=result,
        latency_ms=0,
    )

    assert response.provider_name == "ollama"
    assert response.model_name == "gpt-oss:20b"
    assert response.result.status is BrainInvocationStatus.REFUSED

    with pytest.raises(ValueError, match="model_name"):
        BrainProviderResponse(
            provider_name="ollama",
            model_name="   ",
            result=result,
        )

    with pytest.raises(ValueError, match="latency_ms"):
        BrainProviderResponse(
            provider_name="ollama",
            model_name="gpt-oss:20b",
            result=result,
            latency_ms=-5,
        )


def _make_manifest(
    *,
    provider_name: str,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
) -> BrainManifest:
    return BrainManifest(
        brain_name="gpt-oss-20b",
        provider_name=provider_name,
        model_name="gpt-oss:20b",
        version="0.1.0",
        is_default=True,
        profile=BrainModelProfile(
            brain_name="gpt-oss-20b",
            roles=(BrainRole.PRIMARY,),
            capabilities=(
                BrainCapability.TEXT_GENERATION,
                BrainCapability.CODE_GENERATION,
            ),
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
