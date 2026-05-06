from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from ix_blackfox.brains.contracts import (
    BrainFailure,
    BrainFailureKind,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainMessage,
    BrainModality,
)
from ix_blackfox.brains.providers.base import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
    BrainProviderUsage,
)
from ix_blackfox.brains.providers.errors import (
    BrainProviderConfigurationError,
    BrainProviderInvocationError,
    BrainProviderProtocolError,
    BrainProviderUnavailableError,
)

OpenAITransport = Callable[[str, dict[str, str], dict[str, Any], float | None], dict[str, Any]]
OpenAIHealthTransport = Callable[[str, dict[str, str], float | None], dict[str, Any]]


class OpenAICompatibleProvider(BrainProvider):
    """
    Provider adapter for OpenAI-compatible chat-completions endpoints.

    This adapter is intentionally transport-agnostic. Callers inject a
    simple transport callable so the runtime can use requests, httpx, a
    local gateway, or test doubles without coupling the provider layer
    to a specific HTTP client in this commit.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        provider_name: str = "openai-compatible",
        endpoint_path: str = "/v1/chat/completions",
        health_path: str = "/health",
        transport: OpenAITransport | None = None,
        health_transport: OpenAIHealthTransport | None = None,
        default_timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(provider_name=provider_name)

        normalized_base_url = base_url.strip().rstrip("/")
        normalized_endpoint_path = _normalize_path(
            endpoint_path,
            label="endpoint_path",
        )
        normalized_health_path = _normalize_path(
            health_path,
            label="health_path",
        )

        if not normalized_base_url:
            raise ValueError("base_url must not be empty.")
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be greater than zero.")

        self._base_url = normalized_base_url
        self._api_key = _normalize_optional_text(api_key)
        self._endpoint_path = normalized_endpoint_path
        self._health_path = normalized_health_path
        self._transport = transport
        self._health_transport = health_transport
        self._default_timeout_seconds = default_timeout_seconds

    @property
    def base_url(self) -> str:
        """
        Return the normalized provider base URL.
        """
        return self._base_url

    @property
    def endpoint_url(self) -> str:
        """
        Return the normalized chat-completions endpoint URL.
        """
        return f"{self._base_url}{self._endpoint_path}"

    @property
    def health_url(self) -> str:
        """
        Return the normalized health endpoint URL.
        """
        return f"{self._base_url}{self._health_path}"

    def health_check(self) -> BrainProviderHealth:
        """
        Probe the configured health endpoint.
        """
        if self._health_transport is None:
            return self.unavailable_health(
                message="OpenAI-compatible health transport is not configured.",
            )

        started = perf_counter()
        try:
            payload = self._health_transport(
                self.health_url,
                self._build_headers(),
                self._default_timeout_seconds,
            )
        except Exception as error:  # pragma: no cover - exercised by tests via wrap_error
            wrapped = self.wrap_error(
                error,
                operation="health_check",
                data={"url": self.health_url},
            )
            return self.unavailable_health(
                message=wrapped.message,
                metadata=wrapped.to_dict(),
            )

        latency_ms = max(0, int((perf_counter() - started) * 1000))
        is_available = bool(payload.get("ok", True))
        message = str(payload.get("message", "healthy")).strip() or "healthy"
        metadata = dict(payload.get("metadata", {}))

        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=is_available,
            checked_at=datetime.now(tz=UTC),
            message=message,
            latency_ms=int(payload.get("latency_ms", latency_ms)),
            metadata=metadata,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        """
        Execute a normalized chat-completions request against an
        OpenAI-compatible backend.
        """
        self.validate_invocation(invocation)

        if self._transport is None:
            raise BrainProviderUnavailableError(
                "OpenAI-compatible transport is not configured.",
                context=self._context(
                    operation="invoke",
                    correlation_id=invocation.request.invocation_id,
                    data={
                        "brain_name": invocation.request.brain_name,
                        "url": self.endpoint_url,
                    },
                ),
            )

        payload = self.build_payload(invocation)
        timeout_seconds = (
            invocation.timeout_seconds
            if invocation.timeout_seconds is not None
            else self._default_timeout_seconds
        )

        started = perf_counter()
        try:
            raw_response = self._transport(
                self.endpoint_url,
                self._build_headers(),
                payload,
                timeout_seconds,
            )
        except Exception as error:
            raise self.wrap_error(
                error,
                operation="invoke",
                correlation_id=invocation.request.invocation_id,
                data={
                    "brain_name": invocation.request.brain_name,
                    "url": self.endpoint_url,
                    "model_name": invocation.manifest.model_name,
                },
            ) from error

        latency_ms = max(0, int((perf_counter() - started) * 1000))
        return self.normalize_response(
            raw_response,
            invocation=invocation,
            latency_ms=latency_ms,
        )

    def build_payload(self, invocation: BrainProviderInvocation) -> dict[str, Any]:
        """
        Build an OpenAI-compatible chat-completions payload.
        """
        request = invocation.request

        if any(modality is not BrainModality.TEXT for modality in request.input_modalities):
            raise BrainProviderConfigurationError(
                "OpenAI-compatible provider currently supports text-only invocation payloads.",
                context=self._context(
                    operation="build_payload",
                    correlation_id=request.invocation_id,
                    data={
                        "brain_name": request.brain_name,
                        "input_modalities": [modality.value for modality in request.input_modalities],
                    },
                ),
            )

        messages = self._build_messages(
            prompt=request.prompt,
            messages=request.messages,
        )
        payload: dict[str, Any] = {
            "model": invocation.manifest.model_name,
            "messages": messages,
            "stream": invocation.stream,
        }

        request_metadata = request.metadata
        if "temperature" in request_metadata:
            payload["temperature"] = request_metadata["temperature"]
        if "top_p" in request_metadata:
            payload["top_p"] = request_metadata["top_p"]
        if "max_output_tokens" in request_metadata:
            payload["max_tokens"] = request_metadata["max_output_tokens"]
        if "response_format" in request_metadata:
            payload["response_format"] = request_metadata["response_format"]
        if "seed" in request_metadata:
            payload["seed"] = request_metadata["seed"]

        return payload

    def normalize_response(
        self,
        raw_response: dict[str, Any],
        *,
        invocation: BrainProviderInvocation,
        latency_ms: int,
    ) -> BrainProviderResponse:
        """
        Normalize an OpenAI-compatible chat-completions response into
        BlackFox brain-provider contracts.
        """
        if not isinstance(raw_response, dict):
            raise BrainProviderProtocolError(
                "OpenAI-compatible provider response must be a dictionary.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"response_type": type(raw_response).__name__},
                ),
            )

        if "error" in raw_response:
            error_payload = raw_response["error"]
            message = _extract_error_message(error_payload)
            raise BrainProviderInvocationError(
                message,
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"error_payload": error_payload},
                ),
            )

        choices = raw_response.get("choices")
        if not isinstance(choices, list) or not choices:
            raise BrainProviderProtocolError(
                "OpenAI-compatible provider response must include at least one choice.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"response_keys": sorted(raw_response.keys())},
                ),
            )

        choice = choices[0]
        if not isinstance(choice, dict):
            raise BrainProviderProtocolError(
                "OpenAI-compatible provider choice must be a dictionary.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                ),
            )

        message_payload = choice.get("message")
        if not isinstance(message_payload, dict):
            raise BrainProviderProtocolError(
                "OpenAI-compatible provider choice must include a message object.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                ),
            )

        refusal_text = _normalize_optional_text(message_payload.get("refusal"))
        content_text = _extract_content_text(message_payload.get("content"))
        finish_reason = _normalize_optional_text(choice.get("finish_reason"))

        if refusal_text:
            result = BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.REFUSED,
                output_text=None,
                output_modalities=(),
                failure=BrainFailure(
                    kind=BrainFailureKind.POLICY_BLOCKED,
                    message=refusal_text,
                ),
                metadata={"finish_reason": finish_reason} if finish_reason else {},
            )
        elif content_text:
            result = BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text=content_text,
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": finish_reason} if finish_reason else {},
            )
        else:
            raise BrainProviderProtocolError(
                "OpenAI-compatible provider choice did not include assistant content or refusal text.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"finish_reason": finish_reason},
                ),
            )

        usage_payload = raw_response.get("usage", {})
        usage = BrainProviderUsage(
            input_tokens=_normalize_optional_int(usage_payload.get("prompt_tokens")),
            output_tokens=_normalize_optional_int(usage_payload.get("completion_tokens")),
            total_tokens=_normalize_optional_int(usage_payload.get("total_tokens")),
        )

        model_name = str(raw_response.get("model", invocation.manifest.model_name)).strip()
        if not model_name:
            model_name = invocation.manifest.model_name

        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=model_name,
            result=result,
            usage=usage,
            latency_ms=latency_ms,
            metadata={
                "choice_index": 0,
                "finish_reason": finish_reason,
                "response_id": _normalize_optional_text(raw_response.get("id")),
            },
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _build_messages(
        self,
        *,
        prompt: str,
        messages: tuple[BrainMessage, ...],
    ) -> list[dict[str, str]]:
        normalized_messages = [
            {
                "role": message.role,
                "content": message.content,
            }
            for message in messages
        ]

        if not normalized_messages:
            normalized_messages.append({"role": "user", "content": prompt})
            return normalized_messages

        last = normalized_messages[-1]
        if not (last["role"] == "user" and last["content"] == prompt):
            normalized_messages.append({"role": "user", "content": prompt})

        return normalized_messages


def _extract_error_message(error_payload: Any) -> str:
    if isinstance(error_payload, dict):
        message = _normalize_optional_text(error_payload.get("message"))
        if message:
            return message
    return "OpenAI-compatible provider returned an error payload."


def _extract_content_text(content: Any) -> str | None:
    if isinstance(content, str):
        return _normalize_optional_text(content)

    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict):
                item_type = str(item.get("type", "")).strip().lower()
                if item_type in {"text", "output_text"}:
                    text = _normalize_optional_text(item.get("text"))
                    if text:
                        chunks.append(text)
                        continue
                    nested_text = item.get("text")
                    if isinstance(nested_text, dict):
                        text_value = _normalize_optional_text(nested_text.get("value"))
                        if text_value:
                            chunks.append(text_value)
        if chunks:
            return "\n".join(chunks)

    return None


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _normalize_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("Boolean values are not valid integer counts.")
    return int(value)


def _normalize_path(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned
