from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainContextBudget,
    BrainCostClass,
    BrainEscalationBudget,
    BrainExecutionMode,
    BrainExecutionProfile,
    BrainInferenceBudget,
    BrainLatencyBudget,
    BrainLatencyClass,
)


def test_latency_budget_validates_bounds() -> None:
    budget = BrainLatencyBudget(
        latency_class=BrainLatencyClass.INTERACTIVE,
        max_seconds=4.0,
        target_seconds=2.5,
    )

    assert budget.latency_class is BrainLatencyClass.INTERACTIVE
    assert budget.max_seconds == 4.0
    assert budget.target_seconds == 2.5

    with pytest.raises(ValueError, match="max_seconds"):
        BrainLatencyBudget(max_seconds=0)

    with pytest.raises(ValueError, match="target_seconds"):
        BrainLatencyBudget(target_seconds=0)

    with pytest.raises(ValueError, match="less than or equal to max_seconds"):
        BrainLatencyBudget(max_seconds=2.0, target_seconds=3.0)


def test_context_budget_computes_effective_output_budget() -> None:
    budget = BrainContextBudget(
        max_input_tokens=8192,
        max_output_tokens=2048,
        reserve_output_tokens=256,
    )

    assert budget.max_input_tokens == 8192
    assert budget.max_output_tokens == 2048
    assert budget.reserve_output_tokens == 256
    assert budget.effective_output_budget == 1792

    with pytest.raises(ValueError, match="max_input_tokens"):
        BrainContextBudget(max_input_tokens=0)

    with pytest.raises(ValueError, match="must not exceed max_output_tokens"):
        BrainContextBudget(max_output_tokens=128, reserve_output_tokens=256)


def test_escalation_budget_rejects_negative_hops() -> None:
    budget = BrainEscalationBudget(
        allow_reasoning_escalation=True,
        allow_remote_escalation=False,
        allow_multimodal_escalation=True,
        max_escalation_hops=2,
    )

    assert budget.max_escalation_hops == 2
    assert budget.allow_remote_escalation is False

    with pytest.raises(ValueError, match="max_escalation_hops"):
        BrainEscalationBudget(max_escalation_hops=-1)


def test_inference_budget_respects_cost_class_ceiling() -> None:
    budget = BrainInferenceBudget(
        latency=BrainLatencyBudget(
            latency_class=BrainLatencyClass.STANDARD,
            max_seconds=12.0,
            target_seconds=6.0,
        ),
        context=BrainContextBudget(
            max_input_tokens=16384,
            max_output_tokens=4096,
            reserve_output_tokens=512,
        ),
        escalation=BrainEscalationBudget(max_escalation_hops=1),
        max_cost_class=BrainCostClass.MEDIUM,
        preferred_cost_class=BrainCostClass.LOW,
        metadata={"profile": "balanced"},
    )

    assert budget.latency.max_seconds == 12.0
    assert budget.context.effective_output_budget == 3584
    assert budget.allows_cost_class(BrainCostClass.LOW) is True
    assert budget.allows_cost_class(BrainCostClass.MEDIUM) is True
    assert budget.allows_cost_class(BrainCostClass.HIGH) is False
    assert budget.prefers_cost_class(BrainCostClass.LOW) is True
    assert budget.metadata == {"profile": "balanced"}

    with pytest.raises(ValueError, match="must not exceed max_cost_class"):
        BrainInferenceBudget(
            max_cost_class=BrainCostClass.LOW,
            preferred_cost_class=BrainCostClass.HIGH,
        )


def test_execution_profile_factories_and_provider_rules() -> None:
    local_profile = BrainExecutionProfile.local_first(
        profile_name=" Local Dev ",
        allowed_providers=(" Ollama ", "vLLM"),
        preferred_providers=("ollama",),
        allow_streaming=True,
    )
    hybrid_profile = BrainExecutionProfile.hybrid(
        profile_name="Hybrid Build",
        allowed_providers=("ollama", "openai-compatible"),
        preferred_providers=("openai-compatible",),
    )
    remote_profile = BrainExecutionProfile.remote_only(
        profile_name="Remote Ops",
        allowed_providers=("openai-compatible",),
        preferred_providers=("openai-compatible",),
    )

    assert local_profile.profile_name == "local-dev"
    assert local_profile.mode is BrainExecutionMode.LOCAL
    assert local_profile.allow_local is True
    assert local_profile.allow_remote is False
    assert local_profile.permits_provider(" ollama ") is True
    assert local_profile.prefers_provider("ollama") is True
    assert local_profile.allow_streaming is True

    assert hybrid_profile.mode is BrainExecutionMode.HYBRID
    assert hybrid_profile.allow_local is True
    assert hybrid_profile.allow_remote is True
    assert hybrid_profile.permits_provider("openai compatible") is True

    assert remote_profile.mode is BrainExecutionMode.REMOTE
    assert remote_profile.allow_local is False
    assert remote_profile.allow_remote is True
    assert remote_profile.permits_provider("openai-compatible") is True


def test_execution_profile_validates_mode_and_provider_constraints() -> None:
    with pytest.raises(ValueError, match="LOCAL execution profiles"):
        BrainExecutionProfile(
            profile_name="bad-local",
            mode=BrainExecutionMode.LOCAL,
            allow_local=True,
            allow_remote=True,
        )

    with pytest.raises(ValueError, match="REMOTE execution profiles must allow remote"):
        BrainExecutionProfile(
            profile_name="bad-remote",
            mode=BrainExecutionMode.REMOTE,
            allow_local=False,
            allow_remote=False,
        )

    with pytest.raises(ValueError, match="REMOTE execution profiles must not allow local"):
        BrainExecutionProfile(
            profile_name="bad-remote-2",
            mode=BrainExecutionMode.REMOTE,
            allow_local=True,
            allow_remote=True,
        )

    with pytest.raises(ValueError, match="HYBRID execution profiles must allow local"):
        BrainExecutionProfile(
            profile_name="bad-hybrid",
            mode=BrainExecutionMode.HYBRID,
            allow_local=False,
            allow_remote=True,
        )

    with pytest.raises(ValueError, match="subset of allowed_providers"):
        BrainExecutionProfile.local_first(
            profile_name="bad-providers",
            allowed_providers=("ollama",),
            preferred_providers=("vllm",),
        )
