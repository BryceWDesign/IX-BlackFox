from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainInvocationRequest,
    BrainMessage,
    BrainMessageNormalizer,
    BrainModality,
    BrainRole,
    HarmonyRenderConfig,
    HarmonyRenderer,
    NormalizedConversation,
    PlainTranscriptRenderer,
)


def test_message_normalizer_injects_system_and_developer_prompts() -> None:
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Prepare the patch.",
        messages=(
            BrainMessage(role="assistant", content="Prior analysis complete."),
        ),
    )

    conversation = BrainMessageNormalizer().normalize_request(
        request,
        system_prompt="Global system rule.",
        developer_prompt="Use deterministic reasoning.",
    )

    assert tuple(message.role for message in conversation.messages) == (
        "system",
        "developer",
        "assistant",
        "user",
    )
    assert conversation.messages[0].content == "Global system rule."
    assert conversation.messages[1].content == "Use deterministic reasoning."
    assert conversation.messages[-1].content == "Prepare the patch."
    assert conversation.metadata["brain_name"] == "gpt-oss-20b"


def test_message_normalizer_coalesces_adjacent_roles_without_dup_prompt() -> None:
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Prepare the patch.",
        messages=(
            BrainMessage(role="user", content="Inspect the repo first."),
            BrainMessage(role="user", content="Check verification paths."),
            BrainMessage(role="user", content="Prepare the patch."),
        ),
    )

    conversation = BrainMessageNormalizer().normalize_request(request)

    assert len(conversation.messages) == 1
    assert conversation.messages[0].role == "user"
    assert conversation.messages[0].content == (
        "Inspect the repo first.\n\n"
        "Check verification paths.\n\n"
        "Prepare the patch."
    )
    assert conversation.messages[0].metadata["merged_message_count"] == 3


def test_normalized_conversation_rejects_unsupported_roles() -> None:
    with pytest.raises(ValueError, match="Unsupported normalized message role"):
        NormalizedConversation(
            messages=(
                BrainMessage(role="critic", content="Unsupported role."),
            ),
            input_modalities=(BrainModality.TEXT,),
        )


def test_harmony_renderer_emits_role_and_channel_markers() -> None:
    conversation = NormalizedConversation(
        messages=(
            BrainMessage(role="system", content="System rule."),
            BrainMessage(role="developer", content="Developer rule."),
            BrainMessage(role="user", content="Inspect the repo."),
            BrainMessage(role="assistant", content="Analysis complete."),
            BrainMessage(role="tool", content="pytest -q"),
        ),
    )

    rendered = HarmonyRenderer().render_conversation(
        conversation,
        config=HarmonyRenderConfig(
            assistant_channel="final",
            tool_channel="analysis",
            append_generation_prompt=True,
        ),
    )

    assert rendered == (
        "<|start|>system<|message|>\n"
        "System rule.\n"
        "<|end|>\n"
        "<|start|>developer<|message|>\n"
        "Developer rule.\n"
        "<|end|>\n"
        "<|start|>user<|message|>\n"
        "Inspect the repo.\n"
        "<|end|>\n"
        "<|start|>assistant<|channel|>final<|message|>\n"
        "Analysis complete.\n"
        "<|end|>\n"
        "<|start|>tool<|channel|>analysis<|message|>\n"
        "pytest -q\n"
        "<|end|>\n"
        "<|start|>assistant<|channel|>final<|message|>\n"
    )


def test_harmony_renderer_can_render_request_directly() -> None:
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Prepare the patch.",
        messages=(
            BrainMessage(role="user", content="Inspect the repo first."),
        ),
    )

    rendered = HarmonyRenderer().render_request(
        request,
        developer_prompt="Be deterministic.",
        config=HarmonyRenderConfig(append_generation_prompt=False),
    )

    assert rendered == (
        "<|start|>developer<|message|>\n"
        "Be deterministic.\n"
        "<|end|>\n"
        "<|start|>user<|message|>\n"
        "Inspect the repo first.\n"
        "<|end|>\n"
        "<|start|>user<|message|>\n"
        "Prepare the patch.\n"
        "<|end|>"
    )


def test_plain_transcript_renderer_provides_safe_fallback() -> None:
    conversation = NormalizedConversation(
        messages=(
            BrainMessage(role="system", content="System rule."),
            BrainMessage(role="user", content="Inspect the repo."),
            BrainMessage(role="assistant", content="Analysis complete."),
        ),
    )

    rendered = PlainTranscriptRenderer().render_conversation(conversation)

    assert rendered == (
        "[SYSTEM]\n"
        "System rule.\n\n"
        "[USER]\n"
        "Inspect the repo.\n\n"
        "[ASSISTANT]\n"
        "Analysis complete."
    )
