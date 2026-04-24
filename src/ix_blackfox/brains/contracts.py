from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any
from uuid import uuid4


class BrainRole(StrEnum):
    """
    High-level cognitive roles a BlackFox brain may serve.
    """

    PRIMARY = auto()
    SAFETY = auto()
    REASONING = auto()
    MULTIMODAL = auto()
    RETRIEVAL = auto()
    TOOLING = auto()


class BrainCapability(StrEnum):
    """
    Stable capability identifiers exposed by a brain.
    """

    TEXT_GENERATION = auto()
    CODE_GENERATION = auto()
    STRUCTURED_OUTPUT = auto()
    SAFETY_CLASSIFICATION = auto()
    TOOL_PLANNING = auto()
    LONG_CONTEXT_REASONING = auto()
    VISION_ANALYSIS = auto()


class BrainModality(StrEnum):
    """
    Canonical input and output modalities for brain invocation.
    """

    TEXT = auto()
    IMAGE = auto()
    AUDIO = auto()
    FILE = auto()
    JSON = auto()


class BrainInvocationStatus(StrEnum):
    """
    Terminal status for one brain invocation.
    """

    SUCCEEDED = auto()
    FAILED = auto()
    REFUSED = auto()


class BrainFailureKind(StrEnum):
    """
    Normalized failure categories for provider-agnostic brain calls.
    """

    INVALID_REQUEST = auto()
    POLICY_BLOCKED = auto()
    PROVIDER_UNAVAILABLE = auto()
    TIMEOUT = auto()
    EXECUTION_ERROR = auto()
    UNSUPPORTED_MODALITY = auto()


@dataclass(frozen=True, slots=True)
class BrainMessage:
    """
    One normalized message passed into or produced by a brain.

    Attributes
    ----------
    role:
        Stable speaker role such as system, user, or assistant.
    content:
        Primary textual content.
    metadata:
        Optional structured message metadata.
    """

    role: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _normalize_identifier(self.role, label="role"))
        object.__setattr__(self, "content", _normalize_text(self.content, label="content"))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class BrainInvocationRequest:
    """
    Provider-agnostic request to invoke one brain.

    Attributes
    ----------
    invocation_id:
        Stable unique invocation identifier.
    brain_name:
        Stable target brain identifier.
    role:
        Why this brain is being invoked in the runtime.
    prompt:
        Primary normalized prompt.
    messages:
        Optional conversational context.
    input_modalities:
        Modalities carried by the request.
    task_id:
        Optional originating task identifier.
    pack_name:
        Optional originating pack identifier.
    labels:
        Optional routing or policy labels.
    metadata:
        Structured provider-agnostic request metadata.
    """

    invocation_id: str
    brain_name: str
    role: BrainRole
    prompt: str
    messages: tuple[BrainMessage, ...] = field(default_factory=tuple)
    input_modalities: tuple[BrainModality, ...] = field(
        default_factory=lambda: (BrainModality.TEXT,)
    )
    task_id: str | None = None
    pack_name: str | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        brain_name: str,
        role: BrainRole,
        prompt: str,
        messages: tuple[BrainMessage, ...] | None = None,
        input_modalities: tuple[BrainModality, ...] | None = None,
        task_id: str | None = None,
        pack_name: str | None = None,
        labels: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BrainInvocationRequest:
        """
        Construct a new normalized brain invocation request.
        """
        return cls(
            invocation_id=f"brain-call-{uuid4().hex}",
            brain_name=_normalize_identifier(brain_name, label="brain_name"),
            role=role,
            prompt=_normalize_text(prompt, label="prompt"),
            messages=tuple(messages or ()),
            input_modalities=_normalize_modalities(
                input_modalities or (BrainModality.TEXT,)
            ),
            task_id=_normalize_optional_identifier(task_id, label="task_id"),
            pack_name=_normalize_optional_identifier(pack_name, label="pack_name"),
            labels=_normalize_labels(labels or ()),
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class BrainFailure:
    """
    Provider-agnostic failure detail for one brain invocation.

    Attributes
    ----------
    kind:
        Stable failure category.
    message:
        Human-readable failure explanation.
    retryable:
        Whether a higher layer may retry safely.
    metadata:
        Optional structured failure metadata.
    """

    kind: BrainFailureKind
    message: str
    retryable: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", _normalize_text(self.message, label="message"))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class BrainInvocationResult:
    """
    Provider-agnostic terminal result from one brain invocation.

    Attributes
    ----------
    invocation_id:
        Invocation identifier this result belongs to.
    brain_name:
        Stable source brain identifier.
    status:
        Terminal invocation status.
    output_text:
        Primary textual output from the brain when available.
    output_modalities:
        Modalities emitted by the brain.
    failure:
        Optional normalized failure detail.
    metadata:
        Structured result metadata.
    """

    invocation_id: str
    brain_name: str
    status: BrainInvocationStatus
    output_text: str | None = None
    output_modalities: tuple[BrainModality, ...] = field(default_factory=tuple)
    failure: BrainFailure | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(
            self,
            "brain_name",
            _normalize_identifier(self.brain_name, label="brain_name"),
        )
        object.__setattr__(
            self,
            "output_text",
            _normalize_optional_text(self.output_text),
        )
        object.__setattr__(
            self,
            "output_modalities",
            _normalize_modalities(self.output_modalities),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.status is BrainInvocationStatus.SUCCEEDED:
            if not self.output_text:
                raise ValueError("Successful brain invocations must include output_text.")
            if self.failure is not None:
                raise ValueError(
                    "Successful brain invocations must not include failure details."
                )

        if self.status in {
            BrainInvocationStatus.FAILED,
            BrainInvocationStatus.REFUSED,
        } and self.failure is None:
            raise ValueError(
                "Failed or refused brain invocations must include failure details."
            )

        if self.failure is not None and self.status is BrainInvocationStatus.SUCCEEDED:
            raise ValueError("Successful brain invocations cannot include failure details.")

    @property
    def succeeded(self) -> bool:
        """
        Return True when the invocation completed successfully.
        """
        return self.status is BrainInvocationStatus.SUCCEEDED


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_modalities(
    modalities: tuple[BrainModality, ...],
) -> tuple[BrainModality, ...]:
    normalized: list[BrainModality] = []
    seen: set[BrainModality] = set()

    for modality in modalities:
        if modality not in seen:
            normalized.append(modality)
            seen.add(modality)

    return tuple(normalized)
