from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainManifest,
    BrainManifestRegistry,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainRole,
)


def test_brain_manifest_normalizes_fields_and_uses_profile() -> None:
    manifest = BrainManifest(
        brain_name=" GPT OSS 20B ",
        provider_name=" Ollama ",
        model_name="  gpt-oss:20b  ",
        version="0.1.0",
        description="  Primary local execution brain.  ",
        labels=(" local ", "primary", "local"),
        preferred_packs=(" Programming ", " Architecture ", "programming"),
        is_default=True,
        profile=BrainModelProfile(
            brain_name="gpt-oss-20b",
            roles=(BrainRole.PRIMARY, BrainRole.REASONING),
            capabilities=(
                BrainCapability.TEXT_GENERATION,
                BrainCapability.CODE_GENERATION,
            ),
            context_window=BrainContextWindow(
                max_input_tokens=32768,
                max_output_tokens=4096,
            ),
        ),
    )

    assert manifest.brain_name == "gpt-oss-20b"
    assert manifest.provider_name == "ollama"
    assert manifest.model_name == "gpt-oss:20b"
    assert manifest.description == "Primary local execution brain."
    assert manifest.labels == ("local", "primary")
    assert manifest.preferred_packs == ("programming", "architecture")
    assert manifest.is_default is True
    assert manifest.roles == (BrainRole.PRIMARY, BrainRole.REASONING)
    assert manifest.supports_role(BrainRole.PRIMARY) is True
    assert manifest.declares_capability(BrainCapability.CODE_GENERATION) is True
    assert manifest.accepts_modality(BrainModality.TEXT) is True
    assert manifest.prefers_pack(" programming ") is True


def test_brain_manifest_registry_registers_replaces_and_queries() -> None:
    registry = BrainManifestRegistry()
    registry.register(
        BrainManifest(
            brain_name="gpt-oss-20b",
            provider_name="ollama",
            model_name="gpt-oss:20b",
            version="0.1.0",
            is_default=True,
            preferred_packs=("programming",),
            profile=BrainModelProfile(
                brain_name="gpt-oss-20b",
                roles=(BrainRole.PRIMARY,),
                capabilities=(BrainCapability.CODE_GENERATION,),
                context_window=BrainContextWindow(
                    max_input_tokens=32768,
                    max_output_tokens=4096,
                ),
            ),
        )
    )
    registry.register(
        BrainManifest(
            brain_name="qwen3.5-vision",
            provider_name="vllm",
            model_name="Qwen3.5-27B",
            version="0.1.0",
            preferred_packs=("architecture",),
            profile=BrainModelProfile(
                brain_name="qwen3.5-vision",
                roles=(BrainRole.MULTIMODAL,),
                capabilities=(BrainCapability.VISION_ANALYSIS,),
                context_window=BrainContextWindow(
                    max_input_tokens=65536,
                    max_output_tokens=4096,
                ),
                modalities=BrainModalityProfile(
                    input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
                ),
            ),
        )
    )
    registry.register(
        BrainManifest(
            brain_name="gpt-oss-20b",
            provider_name="ollama",
            model_name="gpt-oss:20b-q8",
            version="0.2.0",
            is_default=True,
            preferred_packs=("programming",),
            profile=BrainModelProfile(
                brain_name="gpt-oss-20b",
                roles=(BrainRole.PRIMARY,),
                capabilities=(
                    BrainCapability.TEXT_GENERATION,
                    BrainCapability.CODE_GENERATION,
                ),
                context_window=BrainContextWindow(
                    max_input_tokens=65536,
                    max_output_tokens=8192,
                ),
            ),
        )
    )

    snapshot = registry.snapshot()

    assert snapshot.names() == ("gpt-oss-20b", "qwen3.5-vision")
    assert registry.get(" GPT OSS 20B ") is not None
    assert registry.get("gpt-oss-20b").version == "0.2.0"
    assert tuple(item.brain_name for item in registry.defaults()) == ("gpt-oss-20b",)
    assert tuple(item.brain_name for item in registry.find_by_role(BrainRole.MULTIMODAL)) == (
        "qwen3.5-vision",
    )
    assert tuple(
        item.brain_name
        for item in registry.find_by_capability(BrainCapability.CODE_GENERATION)
    ) == ("gpt-oss-20b",)
    assert tuple(item.brain_name for item in registry.find_for_pack(" architecture ")) == (
        "qwen3.5-vision",
    )
    assert tuple(item.brain_name for item in snapshot.find_for_pack("programming")) == (
        "gpt-oss-20b",
    )


def test_brain_manifest_registry_unregister_and_clear() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="gpt-oss-20b"))
    registry.register(
        _make_manifest(
            brain_name="qwen3.5-vision",
            provider_name="vllm",
            model_name="Qwen3.5-27B",
            role=BrainRole.MULTIMODAL,
            capability=BrainCapability.VISION_ANALYSIS,
        )
    )

    assert registry.unregister("gpt-oss-20b") is True
    assert registry.unregister("gpt-oss-20b") is False

    registry.clear()
    assert registry.snapshot().manifests == ()


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: BrainManifest(
                brain_name="   ",
                provider_name="ollama",
                model_name="gpt-oss:20b",
                version="0.1.0",
                profile=_make_profile(brain_name="placeholder"),
            ),
            "Brain brain name must not be empty",
        ),
        (
            lambda: BrainManifest(
                brain_name="gpt-oss-20b",
                provider_name="   ",
                model_name="gpt-oss:20b",
                version="0.1.0",
                profile=_make_profile(brain_name="gpt-oss-20b"),
            ),
            "Brain provider name must not be empty",
        ),
        (
            lambda: BrainManifest(
                brain_name="gpt-oss-20b",
                provider_name="ollama",
                model_name="   ",
                version="0.1.0",
                profile=_make_profile(brain_name="gpt-oss-20b"),
            ),
            "Brain model name must not be empty",
        ),
        (
            lambda: BrainManifest(
                brain_name="gpt-oss-20b",
                provider_name="ollama",
                model_name="gpt-oss:20b",
                version="   ",
                profile=_make_profile(brain_name="gpt-oss-20b"),
            ),
            "Brain version must not be empty",
        ),
        (
            lambda: BrainManifest(
                brain_name="gpt-oss-20b",
                provider_name="ollama",
                model_name="gpt-oss:20b",
                version="0.1.0",
                profile=_make_profile(brain_name="qwen3.5-vision"),
            ),
            "must match profile.brain_name",
        ),
    ],
)
def test_invalid_brain_manifest_inputs_raise(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()


def test_snapshot_helpers_return_expected_views() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="gpt-oss-20b", is_default=True))
    registry.register(
        _make_manifest(
            brain_name="gpt-oss-safeguard-20b",
            role=BrainRole.SAFETY,
            capability=BrainCapability.SAFETY_CLASSIFICATION,
        )
    )

    snapshot = registry.snapshot()

    assert snapshot.get("gpt-oss-safeguard-20b") is not None
    assert tuple(item.brain_name for item in snapshot.defaults()) == ("gpt-oss-20b",)
    assert tuple(item.brain_name for item in snapshot.find_by_role(BrainRole.SAFETY)) == (
        "gpt-oss-safeguard-20b",
    )
    assert tuple(
        item.brain_name
        for item in snapshot.find_by_capability(BrainCapability.SAFETY_CLASSIFICATION)
    ) == ("gpt-oss-safeguard-20b",)


def _make_manifest(
    *,
    brain_name: str,
    provider_name: str = "ollama",
    model_name: str = "gpt-oss:20b",
    role: BrainRole = BrainRole.PRIMARY,
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
    is_default: bool = False,
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name=provider_name,
        model_name=model_name,
        version="0.1.0",
        preferred_packs=("programming",),
        is_default=is_default,
        profile=_make_profile(
            brain_name=brain_name,
            role=role,
            capability=capability,
        ),
    )


def _make_profile(
    *,
    brain_name: str,
    role: BrainRole = BrainRole.PRIMARY,
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
) -> BrainModelProfile:
    return BrainModelProfile(
        brain_name=brain_name,
        roles=(role,),
        capabilities=(capability,),
        context_window=BrainContextWindow(
            max_input_tokens=32768,
            max_output_tokens=4096,
        ),
    )
