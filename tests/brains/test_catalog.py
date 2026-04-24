from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainCatalog,
    BrainRole,
    build_policy_gpt_oss_manifest,
    build_primary_brain_catalog,
    build_primary_gpt_oss_manifest,
    build_safeguard_gpt_oss_manifest,
    build_vision_qwen_manifest,
    build_wave1_core_brain_catalog,
    build_wave1_extended_brain_catalog,
    build_wave1_operating_catalog,
)


def test_build_primary_gpt_oss_manifest_declares_wave1_primary_defaults() -> None:
    manifest = build_primary_gpt_oss_manifest()

    assert manifest.brain_name == "gpt-oss-20b"
    assert manifest.provider_name == "ollama"
    assert manifest.model_name == "gpt-oss:20b"
    assert manifest.is_default is True
    assert manifest.roles == (BrainRole.PRIMARY, BrainRole.REASONING)
    assert manifest.capabilities == (
        BrainCapability.TEXT_GENERATION,
        BrainCapability.CODE_GENERATION,
        BrainCapability.STRUCTURED_OUTPUT,
        BrainCapability.TOOL_PLANNING,
        BrainCapability.LONG_CONTEXT_REASONING,
    )
    assert manifest.prefers_pack(" programming ") is True
    assert manifest.prefers_pack("architecture") is True
    assert manifest.labels == ("primary", "gpt-oss", "reasoning", "local")
    assert manifest.profile.modalities.supports_streaming is True
    assert manifest.profile.modalities.supports_structured_output is True
    assert manifest.profile.modalities.supports_tool_use is True
    assert manifest.profile.limits.max_tool_calls == 8


def test_build_policy_gpt_oss_manifest_declares_wave1_policy_defaults() -> None:
    manifest = build_policy_gpt_oss_manifest()

    assert manifest.brain_name == "gpt-oss-policy-20b"
    assert manifest.provider_name == "ollama"
    assert manifest.model_name == "gpt-oss-policy:20b"
    assert manifest.is_default is False
    assert manifest.roles == (BrainRole.REASONING,)
    assert manifest.capabilities == (
        BrainCapability.STRUCTURED_OUTPUT,
        BrainCapability.LONG_CONTEXT_REASONING,
        BrainCapability.TEXT_GENERATION,
    )
    assert manifest.prefers_pack(" programming ") is True
    assert manifest.labels == ("policy", "advisory", "governance-review", "local")
    assert manifest.profile.modalities.supports_streaming is False
    assert manifest.profile.modalities.supports_structured_output is True
    assert manifest.profile.modalities.supports_tool_use is False
    assert manifest.profile.limits.max_tool_calls == 0


def test_build_safeguard_gpt_oss_manifest_declares_wave1_safeguard_defaults() -> None:
    manifest = build_safeguard_gpt_oss_manifest()

    assert manifest.brain_name == "gpt-oss-safeguard-20b"
    assert manifest.provider_name == "ollama"
    assert manifest.model_name == "gpt-oss-safeguard:20b"
    assert manifest.is_default is False
    assert manifest.roles == (BrainRole.SAFETY,)
    assert manifest.capabilities == (
        BrainCapability.SAFETY_CLASSIFICATION,
        BrainCapability.STRUCTURED_OUTPUT,
        BrainCapability.LONG_CONTEXT_REASONING,
    )
    assert manifest.prefers_pack(" programming ") is True
    assert manifest.labels == ("safeguard", "safety", "semantic-policy", "local")
    assert manifest.profile.modalities.supports_streaming is False
    assert manifest.profile.modalities.supports_structured_output is True
    assert manifest.profile.modalities.supports_tool_use is False
    assert manifest.profile.limits.max_tool_calls == 0


def test_build_vision_qwen_manifest_declares_wave1_multimodal_defaults() -> None:
    manifest = build_vision_qwen_manifest()

    assert manifest.brain_name == "qwen-vision"
    assert manifest.provider_name == "vllm"
    assert manifest.model_name == "qwen2.5-vl:7b"
    assert manifest.is_default is False
    assert manifest.roles == (BrainRole.MULTIMODAL,)
    assert manifest.capabilities == (
        BrainCapability.VISION_ANALYSIS,
        BrainCapability.STRUCTURED_OUTPUT,
        BrainCapability.TEXT_GENERATION,
    )
    assert manifest.prefers_pack(" architecture ") is True
    assert manifest.prefers_pack("programming") is True
    assert manifest.labels == ("vision", "multimodal", "ui-review", "local")
    assert manifest.profile.modalities.input_modalities == (
        manifest.profile.modalities.input_modalities[0],
        manifest.profile.modalities.input_modalities[1],
    )
    assert tuple(modality.value for modality in manifest.profile.modalities.input_modalities) == (
        "text",
        "image",
    )
    assert manifest.profile.modalities.supports_structured_output is True
    assert manifest.profile.modalities.supports_tool_use is False


def test_build_primary_gpt_oss_manifest_allows_provider_override() -> None:
    manifest = build_primary_gpt_oss_manifest(
        provider_name=" vLLM ",
        model_name=" openai/gpt-oss-20b ",
        version="0.2.0",
    )

    assert manifest.provider_name == "vllm"
    assert manifest.model_name == "openai/gpt-oss-20b"
    assert manifest.version == "0.2.0"


def test_build_primary_brain_catalog_maps_roles_and_packs_to_gpt_oss() -> None:
    catalog = build_primary_brain_catalog()

    default_manifest = catalog.default_manifest()

    assert default_manifest.brain_name == "gpt-oss-20b"
    assert catalog.default_brain_name == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.PRIMARY) == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.REASONING) == "gpt-oss-20b"
    assert catalog.brain_for_pack(" programming ") == "gpt-oss-20b"
    assert catalog.brain_for_pack("architecture") == "gpt-oss-20b"
    assert catalog.metadata == {
        "catalog_name": "wave1-primary",
        "catalog_version": "0.1.0",
    }


def test_build_wave1_core_brain_catalog_includes_primary_and_safeguard() -> None:
    catalog = build_wave1_core_brain_catalog()

    assert tuple(manifest.brain_name for manifest in catalog.manifests) == (
        "gpt-oss-20b",
        "gpt-oss-safeguard-20b",
    )
    assert catalog.default_brain_name == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.PRIMARY) == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.REASONING) == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.SAFETY) == "gpt-oss-safeguard-20b"
    assert catalog.brain_for_pack("programming") == "gpt-oss-20b"
    assert catalog.metadata == {
        "catalog_name": "wave1-core",
        "catalog_version": "0.1.0",
    }


def test_build_wave1_extended_brain_catalog_includes_multimodal_lane() -> None:
    catalog = build_wave1_extended_brain_catalog()

    assert tuple(manifest.brain_name for manifest in catalog.manifests) == (
        "gpt-oss-20b",
        "gpt-oss-safeguard-20b",
        "qwen-vision",
    )
    assert catalog.default_brain_name == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.PRIMARY) == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.SAFETY) == "gpt-oss-safeguard-20b"
    assert catalog.brain_for_role(BrainRole.MULTIMODAL) == "qwen-vision"
    assert catalog.brain_for_pack("ui-review") == "qwen-vision"
    assert catalog.metadata == {
        "catalog_name": "wave1-extended",
        "catalog_version": "0.1.0",
    }


def test_build_wave1_operating_catalog_includes_policy_lane() -> None:
    catalog = build_wave1_operating_catalog()

    assert tuple(manifest.brain_name for manifest in catalog.manifests) == (
        "gpt-oss-20b",
        "gpt-oss-policy-20b",
        "gpt-oss-safeguard-20b",
        "qwen-vision",
    )
    assert catalog.default_brain_name == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.PRIMARY) == "gpt-oss-20b"
    assert catalog.brain_for_role(BrainRole.SAFETY) == "gpt-oss-safeguard-20b"
    assert catalog.brain_for_role(BrainRole.MULTIMODAL) == "qwen-vision"
    assert catalog.metadata == {
        "catalog_name": "wave1-operating",
        "catalog_version": "0.1.0",
        "policy_brain_name": "gpt-oss-policy-20b",
    }


def test_brain_catalog_validates_known_defaults() -> None:
    manifest = build_primary_gpt_oss_manifest()

    with pytest.raises(ValueError, match="default_brain_name"):
        BrainCatalog(
            manifests=(manifest,),
            default_brain_name="missing-brain",
        )

    with pytest.raises(ValueError, match="role_defaults"):
        BrainCatalog(
            manifests=(manifest,),
            default_brain_name=manifest.brain_name,
            role_defaults={BrainRole.PRIMARY: "missing-brain"},
        )

    with pytest.raises(ValueError, match="pack_defaults"):
        BrainCatalog(
            manifests=(manifest,),
            default_brain_name=manifest.brain_name,
            pack_defaults={"programming": "missing-brain"},
        )
