from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.brains.contracts import BrainCapability, BrainModality, BrainRole
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.models import (
    BrainContextWindow,
    BrainExecutionLimits,
    BrainModalityProfile,
    BrainModelProfile,
)


@dataclass(frozen=True, slots=True)
class BrainCatalog:
    """
    Immutable built-in brain catalog with default routing hints.

    Attributes
    ----------
    manifests:
        Registered built-in manifests in deterministic order.
    default_brain_name:
        Stable default execution brain identifier.
    role_defaults:
        Optional role-to-brain default mapping.
    pack_defaults:
        Optional pack-to-brain default mapping.
    metadata:
        Optional catalog metadata for later runtime layers.
    """

    manifests: tuple[BrainManifest, ...]
    default_brain_name: str
    role_defaults: dict[BrainRole, str] = field(default_factory=dict)
    pack_defaults: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.manifests:
            raise ValueError("BrainCatalog must include at least one manifest.")

        manifest_names = [manifest.brain_name for manifest in self.manifests]
        if len(manifest_names) != len(set(manifest_names)):
            raise ValueError("BrainCatalog manifest names must be unique.")

        normalized_default_brain_name = _normalize_identifier(
            self.default_brain_name,
            label="default_brain_name",
        )
        known_brains = set(manifest_names)
        if normalized_default_brain_name not in known_brains:
            raise ValueError(
                "BrainCatalog default_brain_name must reference a known manifest."
            )

        normalized_role_defaults = {
            role: _normalize_identifier(
                brain_name,
                label=f"role_defaults[{role.value}]",
            )
            for role, brain_name in self.role_defaults.items()
        }
        normalized_pack_defaults = {
            _normalize_identifier(pack_name, label="pack_defaults key"): _normalize_identifier(
                brain_name,
                label=f"pack_defaults[{pack_name}]",
            )
            for pack_name, brain_name in self.pack_defaults.items()
        }

        for brain_name in normalized_role_defaults.values():
            if brain_name not in known_brains:
                raise ValueError(
                    "BrainCatalog role_defaults must reference known manifests."
                )

        for brain_name in normalized_pack_defaults.values():
            if brain_name not in known_brains:
                raise ValueError(
                    "BrainCatalog pack_defaults must reference known manifests."
                )

        object.__setattr__(self, "default_brain_name", normalized_default_brain_name)
        object.__setattr__(self, "role_defaults", normalized_role_defaults)
        object.__setattr__(self, "pack_defaults", normalized_pack_defaults)
        object.__setattr__(self, "metadata", dict(self.metadata))

    def get_manifest(self, brain_name: str) -> BrainManifest | None:
        """
        Return a manifest by stable brain identifier.
        """
        normalized_brain_name = _normalize_identifier(brain_name, label="brain_name")
        for manifest in self.manifests:
            if manifest.brain_name == normalized_brain_name:
                return manifest
        return None

    def default_manifest(self) -> BrainManifest:
        """
        Return the default execution brain manifest.
        """
        manifest = self.get_manifest(self.default_brain_name)
        if manifest is None:  # pragma: no cover - guarded by __post_init__
            raise LookupError("Default brain manifest is missing from the catalog.")
        return manifest

    def brain_for_role(self, role: BrainRole) -> str | None:
        """
        Return the default brain for a role, if declared.
        """
        return self.role_defaults.get(role)

    def brain_for_pack(self, pack_name: str) -> str | None:
        """
        Return the default brain for a pack, if declared.
        """
        normalized_pack_name = _normalize_identifier(pack_name, label="pack_name")
        return self.pack_defaults.get(normalized_pack_name)


def build_primary_gpt_oss_manifest(
    *,
    provider_name: str = "ollama",
    model_name: str = "gpt-oss:20b",
    version: str = "0.1.0",
    description: str = "Primary local execution and reasoning brain.",
    preferred_packs: tuple[str, ...] = ("programming", "architecture"),
    labels: tuple[str, ...] = ("primary", "gpt-oss", "reasoning", "local"),
    max_input_tokens: int = 32768,
    max_output_tokens: int = 4096,
    max_concurrent_invocations: int = 2,
    timeout_seconds: float = 45.0,
    max_tool_calls: int = 8,
) -> BrainManifest:
    """
    Build the default `gpt-oss-20b` primary brain manifest.

    This is the Wave 1 anchor brain for:
    - primary task execution
    - code generation
    - long-context reasoning
    - structured output and tool planning
    """
    return BrainManifest(
        brain_name="gpt-oss-20b",
        provider_name=provider_name,
        model_name=model_name,
        version=version,
        description=description,
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=True,
        profile=BrainModelProfile(
            brain_name="gpt-oss-20b",
            roles=(BrainRole.PRIMARY, BrainRole.REASONING),
            capabilities=(
                BrainCapability.TEXT_GENERATION,
                BrainCapability.CODE_GENERATION,
                BrainCapability.STRUCTURED_OUTPUT,
                BrainCapability.TOOL_PLANNING,
                BrainCapability.LONG_CONTEXT_REASONING,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            ),
            modalities=BrainModalityProfile(
                input_modalities=(BrainModality.TEXT,),
                output_modalities=(BrainModality.TEXT, BrainModality.JSON),
                supports_streaming=True,
                supports_structured_output=True,
                supports_tool_use=True,
            ),
            limits=BrainExecutionLimits(
                max_concurrent_invocations=max_concurrent_invocations,
                timeout_seconds=timeout_seconds,
                max_tool_calls=max_tool_calls,
            ),
            description=description,
        ),
    )


def build_reasoner_gpt_oss_manifest(
    *,
    provider_name: str = "openai-compatible",
    model_name: str = "gpt-oss:120b",
    version: str = "0.1.0",
    description: str = "Escalated deep-reasoning coprocessor for hard cases.",
    preferred_packs: tuple[str, ...] = ("programming", "architecture"),
    labels: tuple[str, ...] = ("reasoner", "deep-reasoning", "escalation", "remote"),
    max_input_tokens: int = 65536,
    max_output_tokens: int = 4096,
    max_concurrent_invocations: int = 1,
    timeout_seconds: float = 60.0,
    max_tool_calls: int = 0,
) -> BrainManifest:
    """
    Build the default `gpt-oss-reasoner-120b` deep-reasoning manifest.

    This is the Wave 1 escalation lane for:
    - low-confidence routing follow-up
    - contradiction-heavy reasoning
    - failed verification review
    """
    return BrainManifest(
        brain_name="gpt-oss-reasoner-120b",
        provider_name=provider_name,
        model_name=model_name,
        version=version,
        description=description,
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=False,
        profile=BrainModelProfile(
            brain_name="gpt-oss-reasoner-120b",
            roles=(BrainRole.REASONING,),
            capabilities=(
                BrainCapability.TEXT_GENERATION,
                BrainCapability.STRUCTURED_OUTPUT,
                BrainCapability.LONG_CONTEXT_REASONING,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            ),
            modalities=BrainModalityProfile(
                input_modalities=(BrainModality.TEXT,),
                output_modalities=(BrainModality.TEXT, BrainModality.JSON),
                supports_streaming=False,
                supports_structured_output=True,
                supports_tool_use=False,
            ),
            limits=BrainExecutionLimits(
                max_concurrent_invocations=max_concurrent_invocations,
                timeout_seconds=timeout_seconds,
                max_tool_calls=max_tool_calls,
            ),
            description=description,
        ),
    )


def build_policy_gpt_oss_manifest(
    *,
    provider_name: str = "ollama",
    model_name: str = "gpt-oss-policy:20b",
    version: str = "0.1.0",
    description: str = "Advisory policy reasoning coprocessor for governed execution review.",
    preferred_packs: tuple[str, ...] = ("programming", "architecture"),
    labels: tuple[str, ...] = ("policy", "advisory", "governance-review", "local"),
    max_input_tokens: int = 32768,
    max_output_tokens: int = 2048,
    max_concurrent_invocations: int = 2,
    timeout_seconds: float = 30.0,
) -> BrainManifest:
    """
    Build the default `gpt-oss-policy-20b` policy-advisory manifest.

    This is the Wave 1 policy reasoning lane for:
    - advisory policy interpretation
    - structured rationale beside deterministic governance
    - review semantics that do not override hard policy authority
    """
    return BrainManifest(
        brain_name="gpt-oss-policy-20b",
        provider_name=provider_name,
        model_name=model_name,
        version=version,
        description=description,
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=False,
        profile=BrainModelProfile(
            brain_name="gpt-oss-policy-20b",
            roles=(BrainRole.REASONING,),
            capabilities=(
                BrainCapability.STRUCTURED_OUTPUT,
                BrainCapability.LONG_CONTEXT_REASONING,
                BrainCapability.TEXT_GENERATION,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            ),
            modalities=BrainModalityProfile(
                input_modalities=(BrainModality.TEXT,),
                output_modalities=(BrainModality.TEXT, BrainModality.JSON),
                supports_streaming=False,
                supports_structured_output=True,
                supports_tool_use=False,
            ),
            limits=BrainExecutionLimits(
                max_concurrent_invocations=max_concurrent_invocations,
                timeout_seconds=timeout_seconds,
                max_tool_calls=0,
            ),
            description=description,
        ),
    )


def build_safeguard_gpt_oss_manifest(
    *,
    provider_name: str = "ollama",
    model_name: str = "gpt-oss-safeguard:20b",
    version: str = "0.1.0",
    description: str = "Semantic safety coprocessor for advisory policy findings.",
    preferred_packs: tuple[str, ...] = ("programming", "architecture"),
    labels: tuple[str, ...] = ("safeguard", "safety", "semantic-policy", "local"),
    max_input_tokens: int = 32768,
    max_output_tokens: int = 2048,
    max_concurrent_invocations: int = 2,
    timeout_seconds: float = 30.0,
) -> BrainManifest:
    """
    Build the default `gpt-oss-safeguard-20b` safeguard manifest.

    This is the Wave 1 semantic safety lane for:
    - advisory safety classification
    - structured safety findings
    - review/block recommendations under deterministic governance
    """
    return BrainManifest(
        brain_name="gpt-oss-safeguard-20b",
        provider_name=provider_name,
        model_name=model_name,
        version=version,
        description=description,
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=False,
        profile=BrainModelProfile(
            brain_name="gpt-oss-safeguard-20b",
            roles=(BrainRole.SAFETY,),
            capabilities=(
                BrainCapability.SAFETY_CLASSIFICATION,
                BrainCapability.STRUCTURED_OUTPUT,
                BrainCapability.LONG_CONTEXT_REASONING,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            ),
            modalities=BrainModalityProfile(
                input_modalities=(BrainModality.TEXT,),
                output_modalities=(BrainModality.TEXT, BrainModality.JSON),
                supports_streaming=False,
                supports_structured_output=True,
                supports_tool_use=False,
            ),
            limits=BrainExecutionLimits(
                max_concurrent_invocations=max_concurrent_invocations,
                timeout_seconds=timeout_seconds,
                max_tool_calls=0,
            ),
            description=description,
        ),
    )


def build_vision_qwen_manifest(
    *,
    provider_name: str = "vllm",
    model_name: str = "qwen2.5-vl:7b",
    version: str = "0.1.0",
    description: str = "Vision coprocessor for screenshots, UI inspection, and multimodal review.",
    preferred_packs: tuple[str, ...] = ("architecture", "programming"),
    labels: tuple[str, ...] = ("vision", "multimodal", "ui-review", "local"),
    max_input_tokens: int = 65536,
    max_output_tokens: int = 4096,
    max_concurrent_invocations: int = 2,
    timeout_seconds: float = 45.0,
) -> BrainManifest:
    """
    Build the default `qwen-vision` multimodal manifest.

    This is the Wave 1 vision lane for:
    - screenshot inspection
    - UI state review
    - multimodal architecture and debugging support
    """
    return BrainManifest(
        brain_name="qwen-vision",
        provider_name=provider_name,
        model_name=model_name,
        version=version,
        description=description,
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=False,
        profile=BrainModelProfile(
            brain_name="qwen-vision",
            roles=(BrainRole.MULTIMODAL,),
            capabilities=(
                BrainCapability.VISION_ANALYSIS,
                BrainCapability.STRUCTURED_OUTPUT,
                BrainCapability.TEXT_GENERATION,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            ),
            modalities=BrainModalityProfile(
                input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
                output_modalities=(BrainModality.TEXT, BrainModality.JSON),
                supports_streaming=False,
                supports_structured_output=True,
                supports_tool_use=False,
            ),
            limits=BrainExecutionLimits(
                max_concurrent_invocations=max_concurrent_invocations,
                timeout_seconds=timeout_seconds,
                max_tool_calls=0,
            ),
            description=description,
        ),
    )


def build_primary_brain_catalog(
    *,
    provider_name: str = "ollama",
    model_name: str = "gpt-oss:20b",
    version: str = "0.1.0",
) -> BrainCatalog:
    """
    Build the default Wave 1 primary-brain catalog.

    The resulting catalog declares `gpt-oss-20b` as the default brain
    for:
    - primary execution
    - reasoning tasks
    - programming pack work
    - architecture pack work
    """
    primary_manifest = build_primary_gpt_oss_manifest(
        provider_name=provider_name,
        model_name=model_name,
        version=version,
    )

    return BrainCatalog(
        manifests=(primary_manifest,),
        default_brain_name=primary_manifest.brain_name,
        role_defaults={
            BrainRole.PRIMARY: primary_manifest.brain_name,
            BrainRole.REASONING: primary_manifest.brain_name,
        },
        pack_defaults={
            "programming": primary_manifest.brain_name,
            "architecture": primary_manifest.brain_name,
        },
        metadata={
            "catalog_name": "wave1-primary",
            "catalog_version": version,
        },
    )


def build_reasoning_brain_catalog(
    *,
    provider_name: str = "openai-compatible",
    model_name: str = "gpt-oss:120b",
    version: str = "0.1.0",
) -> BrainCatalog:
    """
    Build the default Wave 1 escalation-reasoning catalog.

    The resulting catalog declares `gpt-oss-reasoner-120b` as the default
    brain for deep reasoning escalation.
    """
    reasoner_manifest = build_reasoner_gpt_oss_manifest(
        provider_name=provider_name,
        model_name=model_name,
        version=version,
    )

    return BrainCatalog(
        manifests=(reasoner_manifest,),
        default_brain_name=reasoner_manifest.brain_name,
        role_defaults={
            BrainRole.REASONING: reasoner_manifest.brain_name,
        },
        pack_defaults={
            "programming": reasoner_manifest.brain_name,
            "architecture": reasoner_manifest.brain_name,
        },
        metadata={
            "catalog_name": "wave1-reasoning",
            "catalog_version": version,
            "reasoning_brain_name": reasoner_manifest.brain_name,
        },
    )


def build_wave1_core_brain_catalog(
    *,
    primary_provider_name: str = "ollama",
    primary_model_name: str = "gpt-oss:20b",
    safeguard_provider_name: str = "ollama",
    safeguard_model_name: str = "gpt-oss-safeguard:20b",
    version: str = "0.1.0",
) -> BrainCatalog:
    """
    Build the default Wave 1 core multi-brain catalog.

    This catalog includes:
    - the primary `gpt-oss-20b` execution lane
    - the `gpt-oss-safeguard-20b` semantic safety lane
    """
    primary_manifest = build_primary_gpt_oss_manifest(
        provider_name=primary_provider_name,
        model_name=primary_model_name,
        version=version,
    )
    safeguard_manifest = build_safeguard_gpt_oss_manifest(
        provider_name=safeguard_provider_name,
        model_name=safeguard_model_name,
        version=version,
    )

    return BrainCatalog(
        manifests=(primary_manifest, safeguard_manifest),
        default_brain_name=primary_manifest.brain_name,
        role_defaults={
            BrainRole.PRIMARY: primary_manifest.brain_name,
            BrainRole.REASONING: primary_manifest.brain_name,
            BrainRole.SAFETY: safeguard_manifest.brain_name,
        },
        pack_defaults={
            "programming": primary_manifest.brain_name,
            "architecture": primary_manifest.brain_name,
        },
        metadata={
            "catalog_name": "wave1-core",
            "catalog_version": version,
        },
    )


def build_wave1_extended_brain_catalog(
    *,
    primary_provider_name: str = "ollama",
    primary_model_name: str = "gpt-oss:20b",
    safeguard_provider_name: str = "ollama",
    safeguard_model_name: str = "gpt-oss-safeguard:20b",
    vision_provider_name: str = "vllm",
    vision_model_name: str = "qwen2.5-vl:7b",
    version: str = "0.1.0",
) -> BrainCatalog:
    """
    Build the default Wave 1 extended multi-brain catalog.

    This catalog includes:
    - the primary execution lane
    - the semantic safeguard lane
    - the multimodal vision lane
    """
    primary_manifest = build_primary_gpt_oss_manifest(
        provider_name=primary_provider_name,
        model_name=primary_model_name,
        version=version,
    )
    safeguard_manifest = build_safeguard_gpt_oss_manifest(
        provider_name=safeguard_provider_name,
        model_name=safeguard_model_name,
        version=version,
    )
    vision_manifest = build_vision_qwen_manifest(
        provider_name=vision_provider_name,
        model_name=vision_model_name,
        version=version,
    )

    return BrainCatalog(
        manifests=(primary_manifest, safeguard_manifest, vision_manifest),
        default_brain_name=primary_manifest.brain_name,
        role_defaults={
            BrainRole.PRIMARY: primary_manifest.brain_name,
            BrainRole.REASONING: primary_manifest.brain_name,
            BrainRole.SAFETY: safeguard_manifest.brain_name,
            BrainRole.MULTIMODAL: vision_manifest.brain_name,
        },
        pack_defaults={
            "programming": primary_manifest.brain_name,
            "architecture": primary_manifest.brain_name,
            "ui-review": vision_manifest.brain_name,
        },
        metadata={
            "catalog_name": "wave1-extended",
            "catalog_version": version,
        },
    )


def build_wave1_operating_catalog(
    *,
    primary_provider_name: str = "ollama",
    primary_model_name: str = "gpt-oss:20b",
    policy_provider_name: str = "ollama",
    policy_model_name: str = "gpt-oss-policy:20b",
    safeguard_provider_name: str = "ollama",
    safeguard_model_name: str = "gpt-oss-safeguard:20b",
    vision_provider_name: str = "vllm",
    vision_model_name: str = "qwen2.5-vl:7b",
    version: str = "0.1.0",
) -> BrainCatalog:
    """
    Build the default Wave 1 operating-system-style brain catalog.

    This catalog includes:
    - the primary execution lane
    - the advisory policy reasoning lane
    - the semantic safeguard lane
    - the multimodal vision lane
    """
    primary_manifest = build_primary_gpt_oss_manifest(
        provider_name=primary_provider_name,
        model_name=primary_model_name,
        version=version,
    )
    policy_manifest = build_policy_gpt_oss_manifest(
        provider_name=policy_provider_name,
        model_name=policy_model_name,
        version=version,
    )
    safeguard_manifest = build_safeguard_gpt_oss_manifest(
        provider_name=safeguard_provider_name,
        model_name=safeguard_model_name,
        version=version,
    )
    vision_manifest = build_vision_qwen_manifest(
        provider_name=vision_provider_name,
        model_name=vision_model_name,
        version=version,
    )

    return BrainCatalog(
        manifests=(
            primary_manifest,
            policy_manifest,
            safeguard_manifest,
            vision_manifest,
        ),
        default_brain_name=primary_manifest.brain_name,
        role_defaults={
            BrainRole.PRIMARY: primary_manifest.brain_name,
            BrainRole.REASONING: primary_manifest.brain_name,
            BrainRole.SAFETY: safeguard_manifest.brain_name,
            BrainRole.MULTIMODAL: vision_manifest.brain_name,
        },
        pack_defaults={
            "programming": primary_manifest.brain_name,
            "architecture": primary_manifest.brain_name,
            "ui-review": vision_manifest.brain_name,
        },
        metadata={
            "catalog_name": "wave1-operating",
            "catalog_version": version,
            "policy_brain_name": policy_manifest.brain_name,
        },
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned
