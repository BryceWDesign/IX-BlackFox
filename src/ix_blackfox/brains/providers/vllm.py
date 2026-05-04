from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from ix_blackfox.brains.providers.base import (
    BrainProviderHealth,
    BrainProviderInvocation,
)
from ix_blackfox.brains.providers.openai_compatible import (
    OpenAICompatibleProvider,
    OpenAIHealthTransport,
    OpenAITransport,
)

VLLMModelsTransport = Callable[[str, dict[str, str], float | None], dict[str, Any]]


class VLLMProvider(OpenAICompatibleProvider):
    """
    Provider adapter for vLLM deployments that expose OpenAI-compatible
    inference endpoints plus vLLM-specific availability surfaces.

    This adapter inherits the OpenAI-compatible request/response path,
    then adds:
    - vLLM model inventory probing through /v1/models
    - vLLM-specific extra_body merging
    - optional stream_options forwarding
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        provider_name: str = "vllm",
        endpoint_path: str = "/v1/chat/completions",
        models_path: str = "/v1/models",
        health_path: str = "/health",
        transport: OpenAITransport | None = None,
        models_transport: VLLMModelsTransport | None = None,
        health_transport: OpenAIHealthTransport | None = None,
        default_timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(
            base_url=base_url,
            api_key=api_key,
            provider_name=provider_name,
            endpoint_path=endpoint_path,
            health_path=health_path,
            transport=transport,
            health_transport=health_transport,
            default_timeout_seconds=default_timeout_seconds,
        )
        self._models_path = _normalize_path(models_path, label="models_path")
        self._models_transport = models_transport

    @property
    def models_url(self) -> str:
        """
        Return the normalized vLLM model inventory endpoint URL.
        """
        return f"{self.base_url}{self._models_path}"

    def health_check(self) -> BrainProviderHealth:
        """
        Prefer the vLLM model inventory endpoint for availability probing.

        If no model transport is configured, fall back to the inherited
        OpenAI-compatible health check behavior.
        """
        if self._models_transport is None:
            return super().health_check()

        started = perf_counter()
        try:
            payload = self._models_transport(
                self.models_url,
                self._build_headers(),
                self._default_timeout_seconds,
            )
        except (
            Exception
        ) as error:  # pragma: no cover - exercised via wrapped error tests
            wrapped = self.wrap_error(
                error,
                operation="health_check",
                data={"url": self.models_url},
            )
            return self.unavailable_health(
                message=wrapped.message,
                metadata=wrapped.to_dict(),
            )

        latency_ms = max(0, int((perf_counter() - started) * 1000))
        models = _extract_models(payload)
        is_available = bool(models)
        message = (
            f"healthy ({len(models)} model(s) visible)"
            if is_available
            else "vLLM model inventory probe returned no visible models."
        )

        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=is_available,
            checked_at=datetime.now(tz=UTC),
            message=message,
            latency_ms=int(payload.get("latency_ms", latency_ms)),
            metadata={"model_ids": models},
        )

    def build_payload(self, invocation: BrainProviderInvocation) -> dict[str, Any]:
        """
        Extend the inherited OpenAI-compatible payload with vLLM-specific
        forwarding knobs.
        """
        payload = super().build_payload(invocation)
        request_metadata = invocation.request.metadata

        if "stream_options" in request_metadata:
            payload["stream_options"] = request_metadata["stream_options"]

        extra_body = request_metadata.get("extra_body")
        if extra_body is not None:
            if not isinstance(extra_body, dict):
                raise ValueError("request.metadata['extra_body'] must be a dictionary.")
            payload.update(extra_body)

        return payload


def _extract_models(payload: dict[str, Any]) -> tuple[str, ...]:
    data = payload.get("data")
    if not isinstance(data, list):
        return ()

    model_ids: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = _normalize_optional_text(item.get("id"))
        if model_id is not None:
            model_ids.append(model_id)

    return tuple(model_ids)


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _normalize_path(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned
