from __future__ import annotations

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainManifest,
    BrainManifestRegistry,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainRole,
    BrainRouter,
    BrainRoutingPolicy,
    BrainRoutingRequest,
)


def test_router_prefers_pack_specific_brain_over_generic_default() -> None:
    registry = BrainManifestRegistry()
    registry.register(
        _make_manifest(
            brain_name="gpt-oss-20b",
            is_default=True,
            capability=BrainCapability.CODE_GENERATION,
            labels=("general",),
        )
    )
    registry.register(
        _make_manifest(
            brain_name="gpt-oss-20b-programming",
            preferred_packs=("programming",),
            capability=BrainCapability.CODE_GENERATION,
            labels=("coding",),
        )
    )

    decision = BrainRouter(registry).route(
        BrainRoutingRequest(
            required_role=BrainRole.PRIMARY,
            required_capabilities=(BrainCapability.CODE_GENERATION,),
            pack_name=" Programming ",
        )
    )

    assert decision.selected_brain_name == "gpt-oss-20b-programming"
    assert tuple(candidate.manifest.brain_name for candidate in decision.eligible_candidates) == (
        "gpt-oss-20b-programming",
        "gpt-oss-20b",
    )
    assert decision.eligible_candidates[0].score > decision.eligible_candidates[1].score


def test_router_routes_multimodal_requests_to_image_capable_brain() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="gpt-oss-20b"))
    registry.register(
        _make_manifest(
            brain_name="qwen3.5-vision",
            role=BrainRole.MULTIMODAL,
            capability=BrainCapability.VISION_ANALYSIS,
            input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
        )
    )

    decision = BrainRouter(registry).route(
        BrainRoutingRequest(
            required_role=BrainRole.MULTIMODAL,
            required_capabilities=(BrainCapability.VISION_ANALYSIS,),
            input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
        )
    )

    assert decision.selected_brain_name == "qwen3.5-vision"
    assert decision.candidates[0].manifest.brain_name == "qwen3.5-vision"
    assert decision.candidates[1].eligible is False
    assert "missing required role: multimodal" in decision.candidates[1].reasons


def test_router_returns_no_selection_when_requirements_are_unmet() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="gpt-oss-20b"))

    decision = BrainRouter(registry).route(
        BrainRoutingRequest(
            required_role=BrainRole.SAFETY,
            required_capabilities=(BrainCapability.SAFETY_CLASSIFICATION,),
        )
    )

    assert decision.selected is None
    assert decision.selected_brain_name is None
    assert decision.candidates[0].eligible is False
    assert "missing required role: safety" in decision.candidates[0].reasons
    assert "missing required capability: safety_classification" in decision.candidates[0].reasons


def test_router_uses_label_bonus_and_default_tie_break_deterministically() -> None:
    registry = BrainManifestRegistry()
    registry.register(
        _make_manifest(
            brain_name="brain-b",
            labels=("trusted",),
        )
    )
    registry.register(
        _make_manifest(
            brain_name="brain-a",
            is_default=True,
            labels=("trusted",),
        )
    )

    decision = BrainRouter(
        registry,
        policy=BrainRoutingPolicy(default_bonus=8, preferred_label_bonus=5),
    ).route(
        BrainRoutingRequest(
            required_role=BrainRole.PRIMARY,
            required_capabilities=(BrainCapability.TEXT_GENERATION,),
            preferred_labels=(" trusted ",),
        )
    )

    assert decision.selected_brain_name == "brain-a"
    assert tuple(candidate.manifest.brain_name for candidate in decision.eligible_candidates) == (
        "brain-a",
        "brain-b",
    )
    assert decision.eligible_candidates[0].breakdown.default_score == 8
    assert decision.eligible_candidates[0].breakdown.label_score == 5


def test_routing_request_normalizes_pack_name_labels_and_modalities() -> None:
    request = BrainRoutingRequest(
        required_role=BrainRole.PRIMARY,
        required_capabilities=(
            BrainCapability.TEXT_GENERATION,
            BrainCapability.TEXT_GENERATION,
        ),
        input_modalities=(BrainModality.TEXT, BrainModality.TEXT),
        pack_name=" Programming ",
        preferred_labels=(" local ", "local", " general "),
        metadata={"temperature": 0},
    )

    assert request.required_capabilities == (BrainCapability.TEXT_GENERATION,)
    assert request.input_modalities == (BrainModality.TEXT,)
    assert request.pack_name == "programming"
    assert request.preferred_labels == ("local", "general")
    assert request.metadata == {"temperature": 0}


def _make_manifest(
    *,
    brain_name: str,
    role: BrainRole = BrainRole.PRIMARY,
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
    labels: tuple[str, ...] = (),
    preferred_packs: tuple[str, ...] = (),
    is_default: bool = False,
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name="ollama",
        model_name=brain_name,
        version="0.1.0",
        labels=labels,
        preferred_packs=preferred_packs,
        is_default=is_default,
        profile=BrainModelProfile(
            brain_name=brain_name,
            roles=(role,),
            capabilities=(capability,),
            context_window=BrainContextWindow(
                max_input_tokens=32768,
                max_output_tokens=4096,
            ),
            modalities=BrainModalityProfile(input_modalities=input_modalities),
        ),
    )
