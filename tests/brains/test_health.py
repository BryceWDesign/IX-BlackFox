from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainBudgetHealthEvaluator,
    BrainCapability,
    BrainContextBudget,
    BrainContextWindow,
    BrainCostClass,
    BrainEscalationBudget,
    BrainExecutionProfile,
    BrainInferenceBudget,
    BrainLatencyBudget,
    BrainManifest,
    BrainModalityProfile,
    BrainModelProfile,
    BrainProviderHealth,
    BrainProviderHealthRegistry,
    BrainProviderHealthStatus,
    BrainProviderTopology,
    BrainRole,
)


def test_provider_health_normalizes_names_and_serializes() -> None:
    health = BrainProviderHealth(
        provider_name=" OpenAI Compatible ",
        status=BrainProviderHealthStatus.DEGRADED,
        topology=BrainProviderTopology.REMOTE,
        cost_class=BrainCostClass.HIGH,
        observed_latency_seconds=4.5,
        max_input_tokens=65536,
        max_output_tokens=4096,
        reasons=(" transient errors ", "transient errors", " "),
        metadata={"region": "us"},
    )

    assert health.provider_name == "openai-compatible"
    assert health.available is True
    assert health.remote is True
    assert health.reasons == ("transient errors",)
    assert health.to_dict()["status"] == "degraded"
    assert health.to_dict()["topology"] == "remote"


def test_provider_health_rejects_invalid_measurements() -> None:
    with pytest.raises(ValueError, match="observed_latency_seconds"):
        BrainProviderHealth(provider_name="ollama", observed_latency_seconds=0)

    with pytest.raises(ValueError, match="max_input_tokens"):
        BrainProviderHealth(provider_name="ollama", max_input_tokens=-1)

    with pytest.raises(ValueError, match="max_output_tokens"):
        BrainProviderHealth(provider_name="ollama", max_output_tokens=0)


def test_health_registry_returns_configured_or_assumed_provider() -> None:
    registry = BrainProviderHealthRegistry(
        providers=(
            BrainProviderHealth(
                provider_name="ollama",
                observed_latency_seconds=2.0,
            ),
        )
    )

    configured = registry.get(" Ollama ")
    assumed = registry.get("vllm")

    assert configured.provider_name == "ollama"
    assert configured.reasons == ()
    assert assumed.provider_name == "vllm"
    assert assumed.status is BrainProviderHealthStatus.HEALTHY
    assert assumed.reasons == ("no provider health snapshot supplied",)


def test_health_registry_rejects_duplicate_providers() -> None:
    with pytest.raises(ValueError, match="Duplicate provider health snapshot"):
        BrainProviderHealthRegistry(
            providers=(
                BrainProviderHealth(provider_name="ollama"),
                BrainProviderHealth(provider_name=" Ollama "),
            )
        )


def test_evaluator_accepts_healthy_local_preferred_provider() -> None:
    manifest = _manifest(provider_name="ollama")
    profile = BrainExecutionProfile.local_first(
        allowed_providers=("ollama",),
        preferred_providers=("ollama",),
        budget=_budget(),
    )
    health = BrainProviderHealth(
        provider_name="ollama",
        status=BrainProviderHealthStatus.HEALTHY,
        topology=BrainProviderTopology.LOCAL,
        cost_class=BrainCostClass.LOW,
        observed_latency_seconds=2.0,
        max_input_tokens=32768,
        max_output_tokens=4096,
    )

    evaluation = BrainBudgetHealthEvaluator().evaluate(
        manifest,
        profile,
        provider_health=health,
    )

    assert evaluation.eligible is True
    assert evaluation.reasons == ()
    assert evaluation.score_adjustment > 0
    assert evaluation.provider_name == "ollama"
    assert evaluation.to_dict()["eligible"] is True


def test_evaluator_blocks_provider_outside_allowlist() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="vllm"),
        BrainExecutionProfile.local_first(
            allowed_providers=("ollama",),
            budget=_budget(),
        ),
        provider_health=BrainProviderHealth(provider_name="vllm"),
    )

    assert evaluation.eligible is False
    assert "provider is not allowed: vllm" in evaluation.reasons
    assert evaluation.score_adjustment == 0


def test_evaluator_blocks_unavailable_and_disabled_providers() -> None:
    manifest = _manifest(provider_name="ollama")
    profile = BrainExecutionProfile.local_first(budget=_budget())

    unavailable = BrainBudgetHealthEvaluator().evaluate(
        manifest,
        profile,
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            status=BrainProviderHealthStatus.UNAVAILABLE,
        ),
    )
    disabled = BrainBudgetHealthEvaluator().evaluate(
        manifest,
        profile,
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            status=BrainProviderHealthStatus.DISABLED,
        ),
    )

    assert unavailable.eligible is False
    assert "provider is unavailable: ollama" in unavailable.reasons
    assert disabled.eligible is False
    assert "provider is disabled: ollama" in disabled.reasons


def test_evaluator_warns_but_allows_degraded_provider() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="ollama"),
        BrainExecutionProfile.local_first(budget=_budget()),
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            status=BrainProviderHealthStatus.DEGRADED,
            observed_latency_seconds=2.0,
        ),
    )

    assert evaluation.eligible is True
    assert "provider is degraded: ollama" in evaluation.warnings
    assert evaluation.score_adjustment > 0


def test_evaluator_blocks_remote_provider_without_remote_authority() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="openai-compatible"),
        BrainExecutionProfile.local_first(budget=_budget()),
        provider_health=BrainProviderHealth(
            provider_name="openai-compatible",
            topology=BrainProviderTopology.REMOTE,
        ),
    )

    assert evaluation.eligible is False
    assert "remote provider is not allowed: openai-compatible" in evaluation.reasons


def test_evaluator_blocks_remote_provider_when_escalation_budget_denies_remote() -> None:
    budget = _budget(
        escalation=BrainEscalationBudget(allow_remote_escalation=False),
    )
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="openai-compatible"),
        BrainExecutionProfile.hybrid(budget=budget),
        provider_health=BrainProviderHealth(
            provider_name="openai-compatible",
            topology=BrainProviderTopology.REMOTE,
        ),
    )

    assert evaluation.eligible is False
    assert "remote escalation is not allowed: openai-compatible" in evaluation.reasons


def test_evaluator_blocks_cost_class_above_budget() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="openai-compatible"),
        BrainExecutionProfile.hybrid(
            budget=_budget(max_cost_class=BrainCostClass.MEDIUM),
        ),
        provider_health=BrainProviderHealth(
            provider_name="openai-compatible",
            topology=BrainProviderTopology.REMOTE,
            cost_class=BrainCostClass.HIGH,
        ),
    )

    assert evaluation.eligible is False
    assert (
        "provider cost class exceeds budget: openai-compatible=high"
        in evaluation.reasons
    )


def test_evaluator_warns_when_cost_class_is_allowed_but_not_preferred() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="ollama"),
        BrainExecutionProfile.local_first(
            budget=_budget(
                max_cost_class=BrainCostClass.MEDIUM,
                preferred_cost_class=BrainCostClass.LOW,
            )
        ),
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            cost_class=BrainCostClass.MEDIUM,
            observed_latency_seconds=2.0,
        ),
    )

    assert evaluation.eligible is True
    assert "provider cost class is allowed but not preferred: ollama=medium" in (
        evaluation.warnings
    )


def test_evaluator_blocks_latency_above_max_and_warns_above_target() -> None:
    slow = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="ollama"),
        BrainExecutionProfile.local_first(budget=_budget()),
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            observed_latency_seconds=11.0,
        ),
    )
    above_target = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="ollama"),
        BrainExecutionProfile.local_first(budget=_budget()),
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            observed_latency_seconds=6.0,
        ),
    )

    assert slow.eligible is False
    assert "provider observed latency exceeds budget: ollama=11.000s" in slow.reasons
    assert above_target.eligible is True
    assert "provider observed latency exceeds target: ollama=6.000s" in (
        above_target.warnings
    )


def test_evaluator_warns_when_latency_is_unknown() -> None:
    evaluation = BrainBudgetHealthEvaluator().evaluate(
        _manifest(provider_name="ollama"),
        BrainExecutionProfile.local_first(budget=_budget()),
        provider_health=BrainProviderHealth(provider_name="ollama"),
    )

    assert evaluation.eligible is True
    assert "provider latency is unknown: ollama" in evaluation.warnings


def test_evaluator_blocks_context_budget_above_manifest_or_provider_capacity() -> None:
    manifest = _manifest(provider_name="ollama", input_tokens=4096, output_tokens=1024)
    profile = BrainExecutionProfile.local_first(
        budget=_budget(
            context=BrainContextBudget(
                max_input_tokens=8192,
                max_output_tokens=2048,
            )
        )
    )

    evaluation = BrainBudgetHealthEvaluator().evaluate(
        manifest,
        profile,
        provider_health=BrainProviderHealth(
            provider_name="ollama",
            max_input_tokens=4096,
            max_output_tokens=1024,
        ),
    )

    assert evaluation.eligible is False
    assert "input token budget exceeds provider capacity: 8192>4096" in (
        evaluation.reasons
    )
    assert "output token budget exceeds provider capacity: 2048>1024" in (
        evaluation.reasons
    )


def _budget(
    *,
    latency: BrainLatencyBudget | None = None,
    context: BrainContextBudget | None = None,
    escalation: BrainEscalationBudget | None = None,
    max_cost_class: BrainCostClass = BrainCostClass.HIGH,
    preferred_cost_class: BrainCostClass = BrainCostClass.LOW,
) -> BrainInferenceBudget:
    return BrainInferenceBudget(
        latency=latency or BrainLatencyBudget(max_seconds=10.0, target_seconds=5.0),
        context=context
        or BrainContextBudget(max_input_tokens=32768, max_output_tokens=4096),
        escalation=escalation or BrainEscalationBudget(),
        max_cost_class=max_cost_class,
        preferred_cost_class=preferred_cost_class,
    )


def _manifest(
    *,
    brain_name: str = "repair-brain",
    provider_name: str,
    input_tokens: int = 32768,
    output_tokens: int = 4096,
) -> BrainManifest:
    return BrainManifest(
        brain_name=brain_name,
        provider_name=provider_name,
        model_name="repair-model",
        version="0.1.0",
        profile=BrainModelProfile(
            brain_name=brain_name,
            roles=(BrainRole.PRIMARY,),
            capabilities=(BrainCapability.CODE_GENERATION,),
            context_window=BrainContextWindow(
                max_input_tokens=input_tokens,
                max_output_tokens=output_tokens,
            ),
            modalities=BrainModalityProfile(),
        ),
    )
