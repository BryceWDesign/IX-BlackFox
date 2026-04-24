from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.brains.contracts import BrainCapability, BrainModality, BrainRole


@dataclass(frozen=True, slots=True)
class BrainContextWindow:
    """
    Context-window limits exposed by a brain.

    Attributes
    ----------
    max_input_tokens:
        Maximum accepted input-token budget.
    max_output_tokens:
        Maximum supported output-token budget.
    """

    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        if self.max_input_tokens <= 0:
            raise ValueError("max_input_tokens must be greater than zero.")
        if self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be greater than zero.")


@dataclass(frozen=True, slots=True)
class BrainExecutionLimits:
    """
    Operational guardrails for invoking one brain.

    Attributes
    ----------
    max_concurrent_invocations:
        Maximum allowed in-flight invocations.
    timeout_seconds:
        Optional hard timeout budget.
    max_tool_calls:
        Optional limit on downstream tool actions.
    """

    max_concurrent_invocations: int = 1
    timeout_seconds: float | None = None
    max_tool_calls: int | None = None

    def __post_init__(self) -> None:
        if self.max_concurrent_invocations <= 0:
            raise ValueError("max_concurrent_invocations must be greater than zero.")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero when provided.")
        if self.max_tool_calls is not None and self.max_tool_calls < 0:
            raise ValueError("max_tool_calls must be zero or greater when provided.")


@dataclass(frozen=True, slots=True)
class BrainModalityProfile:
    """
    Declared modality behavior for a brain.

    Attributes
    ----------
    input_modalities:
        Modalities the brain can ingest.
    output_modalities:
        Modalities the brain can emit.
    supports_streaming:
        Whether token or chunk streaming is supported.
    supports_structured_output:
        Whether structured responses are a declared capability.
    supports_tool_use:
        Whether the brain may participate in tool-planning flows.
    """

    input_modalities: tuple[BrainModality, ...] = field(
        default_factory=lambda: (BrainModality.TEXT,)
    )
    output_modalities: tuple[BrainModality, ...] = field(
        default_factory=lambda: (BrainModality.TEXT,)
    )
    supports_streaming: bool = False
    supports_structured_output: bool = False
    supports_tool_use: bool = False

    def __post_init__(self) -> None:
        normalized_inputs = _normalize_modalities(self.input_modalities, label="input")
        normalized_outputs = _normalize_modalities(self.output_modalities, label="output")

        object.__setattr__(self, "input_modalities", normalized_inputs)
        object.__setattr__(self, "output_modalities", normalized_outputs)


@dataclass(frozen=True, slots=True)
class BrainModelProfile:
    """
    Provider-agnostic declared shape of one brain.

    This is not yet a runtime manifest. It is the normalized capability,
    modality, and operating-limit contract that later manifests and
    registries will build on.

    Attributes
    ----------
    brain_name:
        Stable internal brain identifier.
    roles:
        Cognitive roles the brain may serve.
    capabilities:
        Stable declared capabilities.
    context_window:
        Token-context limits.
    modalities:
        Input and output modality declarations.
    limits:
        Operational invocation limits.
    description:
        Human-readable summary.
    """

    brain_name: str
    roles: tuple[BrainRole, ...]
    capabilities: tuple[BrainCapability, ...]
    context_window: BrainContextWindow
    modalities: BrainModalityProfile = field(default_factory=BrainModalityProfile)
    limits: BrainExecutionLimits = field(default_factory=BrainExecutionLimits)
    description: str = ""

    def __post_init__(self) -> None:
        normalized_name = _normalize_identifier(self.brain_name, label="brain_name")
        normalized_roles = _normalize_roles(self.roles)
        normalized_capabilities = _normalize_capabilities(self.capabilities)
        normalized_description = self.description.strip()

        if not normalized_roles:
            raise ValueError("BrainModelProfile must declare at least one role.")
        if not normalized_capabilities:
            raise ValueError("BrainModelProfile must declare at least one capability.")
        if not any(
            capability is BrainCapability.STRUCTURED_OUTPUT
            for capability in normalized_capabilities
        ) and self.modalities.supports_structured_output:
            raise ValueError(
                "supports_structured_output requires the structured_output capability."
            )
        if not any(
            capability is BrainCapability.TOOL_PLANNING
            for capability in normalized_capabilities
        ) and self.modalities.supports_tool_use:
            raise ValueError(
                "supports_tool_use requires the tool_planning capability."
            )

        object.__setattr__(self, "brain_name", normalized_name)
        object.__setattr__(self, "roles", normalized_roles)
        object.__setattr__(self, "capabilities", normalized_capabilities)
        object.__setattr__(self, "description", normalized_description)

    def supports_role(self, role: BrainRole) -> bool:
        """
        Return True when the brain may serve the given cognitive role.
        """
        return role in self.roles

    def declares_capability(self, capability: BrainCapability) -> bool:
        """
        Return True when the brain declares the given capability.
        """
        return capability in self.capabilities

    def accepts_modality(self, modality: BrainModality) -> bool:
        """
        Return True when the brain accepts the given input modality.
        """
        return modality in self.modalities.input_modalities

    def emits_modality(self, modality: BrainModality) -> bool:
        """
        Return True when the brain may emit the given output modality.
        """
        return modality in self.modalities.output_modalities


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_roles(roles: tuple[BrainRole, ...]) -> tuple[BrainRole, ...]:
    normalized: list[BrainRole] = []
    seen: set[BrainRole] = set()

    for role in roles:
        if role not in seen:
            normalized.append(role)
            seen.add(role)

    return tuple(normalized)


def _normalize_capabilities(
    capabilities: tuple[BrainCapability, ...],
) -> tuple[BrainCapability, ...]:
    normalized: list[BrainCapability] = []
    seen: set[BrainCapability] = set()

    for capability in capabilities:
        if capability not in seen:
            normalized.append(capability)
            seen.add(capability)

    return tuple(normalized)


def _normalize_modalities(
    modalities: tuple[BrainModality, ...],
    *,
    label: str,
) -> tuple[BrainModality, ...]:
    normalized: list[BrainModality] = []
    seen: set[BrainModality] = set()

    for modality in modalities:
        if modality not in seen:
            normalized.append(modality)
            seen.add(modality)

    if not normalized:
        raise ValueError(f"{label}_modalities must declare at least one modality.")

    return tuple(normalized)
