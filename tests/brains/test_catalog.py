from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainCatalog,
    BrainRole,
    build_primary_brain_catalog,
    build_primary_gpt_oss_manifest,
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
    assert manifest.accepts_modality.__self__ is manifest  # type: ignore[attr-defined]
    assert manifest.accepts_modality.__func__ is not None  # type: ignore[attr-defined]
    assert manifest.accepts_modality.__name__ == "accepts_modality"  # type: ignore[attr-defined]
    assert manifest.prefers_pack(" programming ") is True
    assert manifest.prefers_pack("architecture") is True
    assert manifest.labels == ("primary", "gpt-oss", "reasoning", "local")
    assert manifest.profile.modalities.supports_streaming is True
    assert manifest.profile.modalities.supports_structured_output is True
    assert manifest.profile.modalities.supports_tool_use is True
    assert manifest.profile.limits.max_tool_calls == 8


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
