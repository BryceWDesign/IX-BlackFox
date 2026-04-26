from __future__ import annotations

from dataclasses import dataclass

from ix_blackfox.brains.contracts import BrainInvocationRequest, BrainMessage
from ix_blackfox.brains.renderers.message_normalizer import (
    BrainMessageNormalizer,
    NormalizedConversation,
)

_HARMONY_START = "<|start|>"
_HARMONY_END = "<|end|>"
_HARMONY_MESSAGE = "<|message|>"
_HARMONY_CHANNEL = "<|channel|>"


@dataclass(frozen=True, slots=True)
class HarmonyRenderConfig:
    """
    Configuration for Harmony-oriented message rendering.

    Attributes
    ----------
    assistant_channel:
        Channel used when rendering assistant turns.
    tool_channel:
        Channel used when rendering tool turns.
    append_generation_prompt:
        Whether to append an empty assistant generation preamble.
    """

    assistant_channel: str = "final"
    tool_channel: str = "commentary"
    append_generation_prompt: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "assistant_channel",
            _normalize_channel(self.assistant_channel, label="assistant_channel"),
        )
        object.__setattr__(
            self,
            "tool_channel",
            _normalize_channel(self.tool_channel, label="tool_channel"),
        )


class HarmonyRenderer:
    """
    Render normalized conversations into a Harmony-style text envelope.

    This layer is intentionally provider-neutral. It gives BlackFox one
    stable place to produce a disciplined serialized transcript for
    models or gateways that expect Harmony-like role/channel markers.
    """

    def render_conversation(
        self,
        conversation: NormalizedConversation,
        *,
        config: HarmonyRenderConfig | None = None,
    ) -> str:
        """
        Render a normalized conversation into Harmony-style text.
        """
        active_config = config or HarmonyRenderConfig()
        rendered_parts = [
            self.render_message(message, config=active_config)
            for message in conversation.messages
        ]

        if active_config.append_generation_prompt:
            rendered_parts.append(
                (
                    f"{_HARMONY_START}assistant"
                    f"{_HARMONY_CHANNEL}{active_config.assistant_channel}"
                    f"{_HARMONY_MESSAGE}\n"
                )
            )

        return "\n".join(rendered_parts)

    def render_request(
        self,
        request: BrainInvocationRequest,
        *,
        system_prompt: str | None = None,
        developer_prompt: str | None = None,
        normalizer: BrainMessageNormalizer | None = None,
        config: HarmonyRenderConfig | None = None,
    ) -> str:
        """
        Normalize and render a brain invocation request in one step.
        """
        active_normalizer = normalizer or BrainMessageNormalizer()
        conversation = active_normalizer.normalize_request(
            request,
            system_prompt=system_prompt,
            developer_prompt=developer_prompt,
            coalesce_adjacent=False,
        )
        return self.render_conversation(conversation, config=config)

    def render_message(
        self,
        message: BrainMessage,
        *,
        config: HarmonyRenderConfig,
    ) -> str:
        """
        Render a single normalized message.
        """
        role = message.role
        if role in {"system", "developer", "user"}:
            return (
                f"{_HARMONY_START}{role}{_HARMONY_MESSAGE}\n"
                f"{message.content}\n"
                f"{_HARMONY_END}"
            )

        if role == "assistant":
            return (
                f"{_HARMONY_START}assistant"
                f"{_HARMONY_CHANNEL}{config.assistant_channel}"
                f"{_HARMONY_MESSAGE}\n"
                f"{message.content}\n"
                f"{_HARMONY_END}"
            )

        if role == "tool":
            return (
                f"{_HARMONY_START}tool"
                f"{_HARMONY_CHANNEL}{config.tool_channel}"
                f"{_HARMONY_MESSAGE}\n"
                f"{message.content}\n"
                f"{_HARMONY_END}"
            )

        raise ValueError(f"Unsupported Harmony message role: {role!r}.")


class PlainTranscriptRenderer:
    """
    Conservative fallback renderer for degraded-mode operation.

    This avoids special token envelopes and instead emits a plain,
    reviewable transcript with explicit role headers.
    """

    def render_conversation(self, conversation: NormalizedConversation) -> str:
        """
        Render a normalized conversation as a simple transcript.
        """
        blocks = [
            self.render_message(message)
            for message in conversation.messages
        ]
        return "\n\n".join(blocks)

    def render_request(
        self,
        request: BrainInvocationRequest,
        *,
        system_prompt: str | None = None,
        developer_prompt: str | None = None,
        normalizer: BrainMessageNormalizer | None = None,
    ) -> str:
        """
        Normalize and render a brain invocation request as plain text.
        """
        active_normalizer = normalizer or BrainMessageNormalizer()
        conversation = active_normalizer.normalize_request(
            request,
            system_prompt=system_prompt,
            developer_prompt=developer_prompt,
        )
        return self.render_conversation(conversation)

    def render_message(self, message: BrainMessage) -> str:
        """
        Render a single message as a labeled transcript block.
        """
        label = message.role.upper().replace("-", " ")
        return f"[{label}]\n{message.content}"
        

def _normalize_channel(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned
