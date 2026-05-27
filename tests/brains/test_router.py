from __future__ import annotations

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainExecutionProfile,
    BrainManifest,
    BrainManifestRegistry,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainProviderHealth,
    BrainProviderHealthRegistry,
    BrainProviderHealthStatus,
    BrainProviderTopology,
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


def test_router_attaches_budget_health_evidence_to_candidates() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="local-repair"))

    decision = BrainRouter(registry).route(
        BrainRoutingRequest(required_role=BrainRole.PRIMARY)
    )

    candidate = decision.candidates[0]
    payload = decision.to_dict()

    assert candidate.budget_health is not None
    assert candidate.budget_health.eligible is True
    assert candidate.budget_health.provider_name == "ollama"
    assert payload["selected_brain_name"] == "local-repair"
    assert payload["candidates"][0]["budget_health"]["eligible"] is True


def test_router_blocks_unavailable_provider_before_selection() -> None:
    registry = BrainManifestRegistry()
    registry.register(
        _make_manifest(
            brain_name="remote-default",
            provider_name="openai-compatible",
            is_default=True,
        )
    )
    registry.register(_make_manifest(brain_name="local-fallback", provider_name="ollama"))
    health_registry = BrainProviderHealthRegistry(
        providers=(
            BrainProviderHealth(
                provider_name="openai-compatible",
                status=BrainProviderHealthStatus.UNAVAILABLE,
                topology=BrainProviderTopology.REMOTE,
            ),
            BrainProviderHealth(provider_name="ollama"),
        )
    )

    decision = BrainRouter(
        registry,
        execution_profile=BrainExecutionProfile.hybrid(),
        provider_health_registry=health_registry,
    ).route(BrainRoutingRequest(required_role=BrainRole.PRIMARY))

    assert decision.selected_brain_name == "local-fallback"
    rejected = decision.rejected_candidates[0]
    assert rejected.manifest.brain_name == "remote-default"
    assert rejected.budget_health is not None
    assert rejected.budget_health.eligible is False
    assert "provider is unavailable: openai-compatible" in rejected.reasons


def test_router_prefers_healthier_preferred_provider_when_base_scores_match() -> None:
    registry = BrainManifestRegistry()
    registry.register(_make_manifest(brain_name="vllm-repair", provider_name="vllm"))
    registry.register(_make_manifest(brain_name="ollama-repair", provider_name="ollama"))
    health_registry = BrainProviderHealthRegistry(
        providers=(
            BrainProviderHealth(
                provider_name="vllm",
                observed_latency_seconds=4.0,
            ),
            BrainProviderHealth(
                provider_name="ollama",
                observed_latency_seconds=1.0,
            ),
        )
    )

    decision = BrainRouter(
        registry,
        execution_profile=BrainExecutionProfile.local_first(
            allowed_providers=("vllm", "ollama"),
            preferred_providers=("ollama",),
        ),
        provider_health_registry=health_registry,
    ).route(BrainRoutingRequest(required_role=BrainRole.PRIMARY))

    assert decision.selected_brain_name == "ollama-repair"
    assert decision.eligible_candidates[0].score > decision.eligible_candidates[1].score
    assert decision.eligible_candidates[0].budget_health is not None
    assert decision.eligible_candidates[0].budget_health.score_adjustment > (
        decision.eligible_candidates[1].budget_health.score_adjustment
    )


def test_router_blocks_remote_provider_when_profile_is_local_only() -> None:
    registry = BrainManifestRegistry()
    registry.register(
        _make_manifest(
            brain_name="remote-repair",
            provider_name="openai-compatible",
        )
    )
    health_registry = BrainProviderHealthRegistry(
        providers=(
            BrainProviderHealth(
                provider_name="openai-compatible",
                topology=BrainProviderTopology.REMOTE,
            ),
        )
    )

    decision = BrainRouter(
        registry,
        execution_profile=BrainExecutionProfile.local_first(),
        provider_health_registry=health_registry,
    ).route(BrainRoutingRequest(required_role=BrainRole.PRIMARY))

    assert decision.selected is None
    assert decision.rejected_candidates[0].manifest.brain_name == "remote-repair"
    assert "remote provider is not allowed: openai-compatible" in (
        decision.rejected_candidates[0].reasons
    )


def _make_manifest(
    *,
    brain_name: str,
    provider_name: str = "ollama",
    role: BrainRole = BrainRole.PRIMARY,
    capability: BrainCapability = BrainCapability.TEXT_GENERATION,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
    labels: tuple[str, ...] = (),
    preferred_packs: tuple[str, ...] = (),
    is_default: bool = False,
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name=provider_name,
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
