from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Callable

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

OllamaTransport = Callable[[str, dict[str, str], dict[str, Any], float | None], dict[str, Any]]
OllamaHealthTransport = Callable[[str, dict[str, str], float | None], dict[str, Any]]


class OllamaProvider(BrainProvider):
    """
    Provider adapter for Ollama's native API.

    This adapter is transport-agnostic. A caller injects small transport
    callables so later runtime layers can decide whether to use requests,
    httpx, local gateways, or test doubles.
    """

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,
        provider_name: str = "ollama",
        chat_path: str = "/api/chat",
        tags_path: str = "/api/tags",
        transport: OllamaTransport | None = None,
        health_transport: OllamaHealthTransport | None = None,
        default_timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(provider_name=provider_name)

        normalized_base_url = base_url.strip().rstrip("/")
        if not normalized_base_url:
            raise ValueError("base_url must not be empty.")
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be greater than zero.")

        self._base_url = normalized_base_url
        self._api_key = _normalize_optional_text(api_key)
        self._chat_path = _normalize_path(chat_path, label="chat_path")
        self._tags_path = _normalize_path(tags_path, label="tags_path")
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
    def chat_url(self) -> str:
        """
        Return the normalized Ollama chat endpoint URL.
        """
        return f"{self._base_url}{self._chat_path}"

    @property
    def tags_url(self) -> str:
        """
        Return the normalized Ollama model-tags endpoint URL.
        """
        return f"{self._base_url}{self._tags_path}"

    def health_check(self) -> BrainProviderHealth:
        """
        Probe the Ollama tags endpoint as a lightweight health check.
        """
        if self._health_transport is None:
            return self.unavailable_health(
                message="Ollama health transport is not configured.",
            )

        started = perf_counter()
        try:
            payload = self._health_transport(
                self.tags_url,
                self._build_headers(),
                self._default_timeout_seconds,
            )
        except Exception as error:  # pragma: no cover - exercised by wrap_error tests
            wrapped = self.wrap_error(
                error,
                operation="health_check",
                data={"url": self.tags_url},
            )
            return self.unavailable_health(
                message=wrapped.message,
                metadata=wrapped.to_dict(),
            )

        latency_ms = max(0, int((perf_counter() - started) * 1000))
        models = payload.get("models")
        is_available = isinstance(models, list)
        message = (
            f"healthy ({len(models)} model(s) visible)"
            if is_available
            else "Ollama health probe did not return a models list."
        )

        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=is_available,
            checked_at=datetime.now(tz=UTC),
            message=message,
            latency_ms=int(payload.get("latency_ms", latency_ms)),
            metadata={
                "model_names": _extract_model_names(models if isinstance(models, list) else []),
            },
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        """
        Execute a normalized chat request against Ollama's /api/chat endpoint.
        """
        self.validate_invocation(invocation)

        if self._transport is None:
            raise BrainProviderUnavailableError(
                "Ollama transport is not configured.",
                context=self._context(
                    operation="invoke",
                    correlation_id=invocation.request.invocation_id,
                    data={
                        "brain_name": invocation.request.brain_name,
                        "url": self.chat_url,
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
                self.chat_url,
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
                    "url": self.chat_url,
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
        Build an Ollama /api/chat payload from a normalized invocation.
        """
        request = invocation.request
        images = _normalize_images(request.metadata.get("images"))

        if BrainModality.IMAGE in request.input_modalities and not images:
            raise BrainProviderConfigurationError(
                "Ollama image-capable invocations require request.metadata['images'].",
                context=self._context(
                    operation="build_payload",
                    correlation_id=request.invocation_id,
                    data={
                        "brain_name": request.brain_name,
                        "input_modalities": [item.value for item in request.input_modalities],
                    },
                ),
            )

        if images and BrainModality.IMAGE not in request.input_modalities:
            raise BrainProviderConfigurationError(
                "Ollama image payloads require image modality in the invocation request.",
                context=self._context(
                    operation="build_payload",
                    correlation_id=request.invocation_id,
                    data={"brain_name": request.brain_name},
                ),
            )

        payload: dict[str, Any] = {
            "model": invocation.manifest.model_name,
            "messages": self._build_messages(
                prompt=request.prompt,
                messages=request.messages,
                images=images,
            ),
            "stream": invocation.stream,
        }

        request_metadata = request.metadata

        response_format = request_metadata.get("response_format")
        if response_format is not None:
            payload["format"] = response_format

        options: dict[str, Any] = {}
        if "temperature" in request_metadata:
            options["temperature"] = request_metadata["temperature"]
        if "top_p" in request_metadata:
            options["top_p"] = request_metadata["top_p"]
        if "seed" in request_metadata:
            options["seed"] = request_metadata["seed"]
        if "stop" in request_metadata:
            options["stop"] = request_metadata["stop"]
        if "max_output_tokens" in request_metadata:
            options["num_predict"] = request_metadata["max_output_tokens"]

        if options:
            payload["options"] = options

        if "think" in request_metadata:
            payload["think"] = request_metadata["think"]
        if "tools" in request_metadata:
            payload["tools"] = request_metadata["tools"]
        if "keep_alive" in request_metadata:
            payload["keep_alive"] = request_metadata["keep_alive"]

        return payload

    def normalize_response(
        self,
        raw_response: dict[str, Any],
        *,
        invocation: BrainProviderInvocation,
        latency_ms: int,
    ) -> BrainProviderResponse:
        """
        Normalize an Ollama chat response into BlackFox provider contracts.
        """
        if not isinstance(raw_response, dict):
            raise BrainProviderProtocolError(
                "Ollama provider response must be a dictionary.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"response_type": type(raw_response).__name__},
                ),
            )

        error_text = _normalize_optional_text(raw_response.get("error"))
        if error_text:
            raise BrainProviderInvocationError(
                error_text,
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"response_keys": sorted(raw_response.keys())},
                ),
            )

        message_payload = raw_response.get("message")
        if not isinstance(message_payload, dict):
            raise BrainProviderProtocolError(
                "Ollama response must include a message object.",
                context=self._context(
                    operation="normalize_response",
                    correlation_id=invocation.request.invocation_id,
                    data={"response_keys": sorted(raw_response.keys())},
                ),
            )

        content_text = _normalize_optional_text(message_payload.get("content"))
        done_reason = _normalize_optional_text(raw_response.get("done_reason"))
        thinking_text = _normalize_optional_text(message_payload.get("thinking"))
        tool_calls = message_payload.get("tool_calls")

        if content_text:
            result = BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text=content_text,
                output_modalities=(BrainModality.TEXT,),
                metadata=_compact_metadata(
                    done_reason=done_reason,
                    thinking=thinking_text,
                    tool_calls=tool_calls,
                ),
            )
        else:
            refusal_message = (
                done_reason
                or "Ollama response did not include assistant content."
            )
            result = BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.REFUSED,
                output_text=None,
                output_modalities=(),
                failure=BrainFailure(
                    kind=BrainFailureKind.POLICY_BLOCKED,
                    message=refusal_message,
                ),
                metadata=_compact_metadata(
                    done_reason=done_reason,
                    thinking=thinking_text,
                    tool_calls=tool_calls,
                ),
            )

        usage = BrainProviderUsage(
            input_tokens=_normalize_optional_int(raw_response.get("prompt_eval_count")),
            output_tokens=_normalize_optional_int(raw_response.get("eval_count")),
            total_tokens=None,
        )

        total_duration_ns = _normalize_optional_int(raw_response.get("total_duration"))
        observed_latency_ms = (
            max(0, int(total_duration_ns / 1_000_000))
            if total_duration_ns is not None
            else latency_ms
        )

        model_name = _normalize_optional_text(raw_response.get("model"))
        if model_name is None:
            model_name = invocation.manifest.model_name

        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=model_name,
            result=result,
            usage=usage,
            latency_ms=observed_latency_ms,
            metadata=_compact_metadata(
                created_at=_normalize_optional_text(raw_response.get("created_at")),
                done_reason=done_reason,
                load_duration=_normalize_optional_int(raw_response.get("load_duration")),
                prompt_eval_duration=_normalize_optional_int(
                    raw_response.get("prompt_eval_duration")
                ),
                eval_duration=_normalize_optional_int(raw_response.get("eval_duration")),
            ),
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
        images: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        normalized_messages: list[dict[str, Any]] = [
            {
                "role": message.role,
                "content": message.content,
            }
            for message in messages
        ]

        if not normalized_messages:
            user_message: dict[str, Any] = {"role": "user", "content": prompt}
            if images:
                user_message["images"] = list(images)
            normalized_messages.append(user_message)
            return normalized_messages

        last = normalized_messages[-1]
        if not (last["role"] == "user" and last["content"] == prompt):
            user_message = {"role": "user", "content": prompt}
            if images:
                user_message["images"] = list(images)
            normalized_messages.append(user_message)
            return normalized_messages

        if images:
            updated_last = dict(last)
            updated_last["images"] = list(images)
            normalized_messages[-1] = updated_last

        return normalized_messages


def _compact_metadata(**kwargs: Any) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key, value in kwargs.items():
        if value is None:
            continue
        compact[key] = value
    return compact


def _extract_model_names(models: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = _normalize_optional_text(model.get("name"))
        if name:
            names.append(name)
    return names


def _normalize_images(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()

    if not isinstance(value, (list, tuple)):
        raise ValueError("request.metadata['images'] must be a list or tuple when provided.")

    images: list[str] = []
    for item in value:
        normalized = _normalize_optional_text(item)
        if normalized is None:
            continue
        images.append(normalized)

    return tuple(images)


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
