from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.brains.contracts import (
    BrainInvocationRequest,
    BrainMessage,
    BrainModality,
)

_ALLOWED_MESSAGE_ROLES = frozenset(
    {
        "system",
        "developer",
        "user",
        "assistant",
        "tool",
    }
)


@dataclass(frozen=True, slots=True)
class NormalizedConversation:
    """
    Stable internal conversation shape used before provider rendering.

    Attributes
    ----------
    messages:
        Normalized ordered messages.
    input_modalities:
        Modalities associated with the conversation.
    metadata:
        Structured rendering metadata carried forward for later layers.
    """

    messages: tuple[BrainMessage, ...]
    input_modalities: tuple[BrainModality, ...] = field(
        default_factory=lambda: (BrainModality.TEXT,)
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("NormalizedConversation must include at least one message.")

        normalized_modalities = _normalize_modalities(self.input_modalities)
        object.__setattr__(self, "input_modalities", normalized_modalities)
        object.__setattr__(self, "metadata", dict(self.metadata))

        for message in self.messages:
            if message.role not in _ALLOWED_MESSAGE_ROLES:
                raise ValueError(
                    f"Unsupported normalized message role: {message.role!r}."
                )

    @property
    def last_message(self) -> BrainMessage:
        """
        Return the final normalized message.
        """
        return self.messages[-1]

    def contains_role(self, role: str) -> bool:
        """
        Return True when the conversation includes the given role.
        """
        normalized_role = _normalize_role(role)
        return any(message.role == normalized_role for message in self.messages)


class BrainMessageNormalizer:
    """
    Normalize provider-agnostic message state before rendering.

    The normalizer is deliberately strict:
    - only stable roles are allowed
    - duplicate adjacent roles can be coalesced
    - the primary prompt is guaranteed to appear as a terminal user turn
      unless the request already ends with the same user message
    """

    def normalize_request(
        self,
        request: BrainInvocationRequest,
        *,
        system_prompt: str | None = None,
        developer_prompt: str | None = None,
        coalesce_adjacent: bool = True,
        ensure_terminal_user_prompt: bool = True,
    ) -> NormalizedConversation:
        """
        Build a normalized conversation from a brain invocation request.
        """
        seed_messages: list[BrainMessage] = []

        if system_prompt is not None and system_prompt.strip():
            seed_messages.append(
                BrainMessage(role="system", content=system_prompt.strip())
            )

        if developer_prompt is not None and developer_prompt.strip():
            seed_messages.append(
                BrainMessage(role="developer", content=developer_prompt.strip())
            )

        seed_messages.extend(request.messages)

        if ensure_terminal_user_prompt or not seed_messages:
            if not self._has_terminal_user_prompt(seed_messages, request.prompt):
                seed_messages.append(
                    BrainMessage(role="user", content=request.prompt)
                )

        normalized_messages = self.normalize_messages(
            tuple(seed_messages),
            coalesce_adjacent=coalesce_adjacent,
        )

        return NormalizedConversation(
            messages=normalized_messages,
            input_modalities=request.input_modalities,
            metadata={
                "brain_name": request.brain_name,
                "invocation_id": request.invocation_id,
                "task_id": request.task_id,
                "pack_name": request.pack_name,
                "labels": request.labels,
            },
        )

    def normalize_messages(
        self,
        messages: tuple[BrainMessage, ...],
        *,
        coalesce_adjacent: bool = True,
    ) -> tuple[BrainMessage, ...]:
        """
        Validate and optionally coalesce a tuple of BrainMessage objects.
        """
        validated = tuple(self._validate_message(message) for message in messages)
        if not validated:
            raise ValueError("At least one message is required for normalization.")

        if not coalesce_adjacent:
            return validated

        return self.coalesce_messages(validated)

    def coalesce_messages(
        self,
        messages: tuple[BrainMessage, ...],
    ) -> tuple[BrainMessage, ...]:
        """
        Merge adjacent messages with the same role into single turns.
        """
        if not messages:
            return ()

        merged: list[BrainMessage] = [messages[0]]

        for message in messages[1:]:
            previous = merged[-1]
            if message.role != previous.role:
                merged.append(message)
                continue

            combined_metadata = dict(previous.metadata)
            combined_metadata.update(message.metadata)
            combined_metadata["merged_message_count"] = (
                int(previous.metadata.get("merged_message_count", 1)) + 1
            )

            merged[-1] = BrainMessage(
                role=previous.role,
                content=f"{previous.content}\n\n{message.content}",
                metadata=combined_metadata,
            )

        return tuple(merged)

    def _validate_message(self, message: BrainMessage) -> BrainMessage:
        normalized_role = _normalize_role(message.role)
        if normalized_role not in _ALLOWED_MESSAGE_ROLES:
            raise ValueError(
                f"Unsupported normalized message role: {normalized_role!r}."
            )

        return BrainMessage(
            role=normalized_role,
            content=message.content,
            metadata=message.metadata,
        )

    def _has_terminal_user_prompt(
        self,
        messages: list[BrainMessage],
        prompt: str,
    ) -> bool:
        if not messages:
            return False
        last = messages[-1]
        return last.role == "user" and last.content == prompt


def _normalize_role(role: str) -> str:
    cleaned = role.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError("Message role must not be empty.")
    return cleaned


def _normalize_modalities(
    input_modalities: tuple[BrainModality, ...],
) -> tuple[BrainModality, ...]:
    normalized: list[BrainModality] = []
    seen: set[BrainModality] = set()

    for modality in input_modalities:
        if modality not in seen:
            normalized.append(modality)
            seen.add(modality)

    if not normalized:
        raise ValueError("NormalizedConversation must declare at least one modality.")

    return tuple(normalized)
