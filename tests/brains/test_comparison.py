from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainComparisonCandidate,
    BrainComparisonDecision,
    BrainComparisonDisposition,
    BrainComparisonRequest,
    BrainComparisonResult,
    BrainComparisonScore,
    BrainModelComparator,
    BrainRole,
)


def test_comparison_request_normalizes_ids_capabilities_and_criteria() -> None:
    request = BrainComparisonRequest(
        comparison_id=" Comparison 1 ",
        required_role=BrainRole.PRIMARY,
        required_capabilities=(
            BrainCapability.CODE_GENERATION,
            BrainCapability.CODE_GENERATION,
        ),
        task_id=" Task 7 ",
        pack_name=" Programming ",
        criteria=(" evidence-backed ", "evidence-backed", " "),
        metadata={"repo": "ix-blackfox"},
    )

    assert request.comparison_id == "comparison-1"
    assert request.required_capabilities == (BrainCapability.CODE_GENERATION,)
    assert request.task_id == "task-7"
    assert request.pack_name == "programming"
    assert request.criteria == ("evidence-backed",)
    assert request.metadata == {"repo": "ix-blackfox"}


def test_comparison_score_totals_positive_components_and_penalty() -> None:
    score = BrainComparisonScore(
        correctness_score=90,
        evidence_score=80,
        safety_score=100,
        policy_score=95,
        maintainability_score=70,
        latency_score=15,
        penalty_score=20,
        notes=("reviewable", "reviewable", " "),
    )

    assert score.positive_total == 450
    assert score.total == 430
    assert score.notes == ("reviewable",)
    assert score.to_dict()["total"] == 430


def test_comparison_score_rejects_unbounded_component_values() -> None:
    with pytest.raises(ValueError, match="correctness_score must be between 0 and 100"):
        BrainComparisonScore(correctness_score=101)

    with pytest.raises(ValueError, match="penalty_score must be zero or greater"):
        BrainComparisonScore(penalty_score=-1)


def test_candidate_requires_output_when_eligible() -> None:
    with pytest.raises(
        ValueError,
        match="eligible comparison candidates must include output_text",
    ):
        BrainComparisonCandidate(
            brain_name="generator",
            provider_name="ollama",
            model_name="gpt-oss:20b",
            role=BrainRole.PRIMARY,
            score=BrainComparisonScore(),
        )


def test_candidate_requires_reasons_when_ineligible() -> None:
    with pytest.raises(
        ValueError,
        match="ineligible comparison candidates must include reasons",
    ):
        BrainComparisonCandidate(
            brain_name="unavailable",
            provider_name="vllm",
            model_name="repair-model",
            role=BrainRole.PRIMARY,
            score=BrainComparisonScore(),
            eligible=False,
        )


def test_candidate_normalizes_names_and_hashes_output() -> None:
    candidate = _candidate(
        brain_name=" Local Repair ",
        provider_name=" Ollama ",
        model_name=" gpt-oss:20b ",
        output_text="  patch candidate  ",
    )

    assert candidate.brain_name == "local-repair"
    assert candidate.provider_name == "ollama"
    assert candidate.model_name == "gpt-oss:20b"
    assert candidate.output_text == "patch candidate"
    assert candidate.output_digest is not None
    assert len(candidate.output_digest) == 64


def test_comparator_selects_highest_score_and_rejects_lower_candidates() -> None:
    request = _request()
    selected = _candidate(
        brain_name="reasoner",
        score=BrainComparisonScore(
            correctness_score=90,
            evidence_score=90,
            safety_score=95,
            policy_score=90,
        ),
    )
    rejected = _candidate(
        brain_name="fast-local",
        score=BrainComparisonScore(
            correctness_score=60,
            evidence_score=70,
            safety_score=80,
            policy_score=80,
            latency_score=25,
        ),
    )

    decision = BrainModelComparator().compare(request, (rejected, selected))

    assert decision.selected_brain_name == "reasoner"
    assert decision.results[0].candidate.brain_name == "reasoner"
    assert decision.results[0].disposition is BrainComparisonDisposition.SELECTED
    assert decision.rejected[0].candidate.brain_name == "fast-local"
    assert decision.rejected[0].reasons == (
        "lower comparison score than selected candidate",
    )


def test_comparator_blocks_ineligible_candidates_without_rank() -> None:
    request = _request()
    blocked = BrainComparisonCandidate(
        brain_name="remote-repair",
        provider_name="openai-compatible",
        model_name="remote-model",
        role=BrainRole.PRIMARY,
        score=BrainComparisonScore(correctness_score=90),
        eligible=False,
        reasons=("provider health gate failed",),
    )
    selected = _candidate(
        brain_name="local-repair",
        score=BrainComparisonScore(correctness_score=70, safety_score=80),
    )

    decision = BrainModelComparator().compare(request, (blocked, selected))

    assert decision.selected_brain_name == "local-repair"
    assert decision.blocked[0].candidate.brain_name == "remote-repair"
    assert decision.blocked[0].rank is None
    assert decision.blocked[0].reasons == ("provider health gate failed",)


def test_comparator_uses_deterministic_tie_break_when_scores_match() -> None:
    request = _request()
    alpha = _candidate(
        brain_name="alpha-model",
        score=BrainComparisonScore(correctness_score=80, safety_score=90),
    )
    beta = _candidate(
        brain_name="beta-model",
        score=BrainComparisonScore(correctness_score=80, safety_score=90),
    )

    decision = BrainModelComparator().compare(request, (beta, alpha))

    assert decision.selected_brain_name == "alpha-model"
    assert decision.rejected[0].candidate.brain_name == "beta-model"
    assert decision.rejected[0].reasons == (
        "lost deterministic tie-break against selected candidate",
    )


def test_comparator_prefers_higher_safety_score_when_total_scores_match() -> None:
    request = _request()
    safer = _candidate(
        brain_name="safer-model",
        score=BrainComparisonScore(correctness_score=70, safety_score=100),
    )
    less_safe = _candidate(
        brain_name="less-safe-model",
        score=BrainComparisonScore(correctness_score=100, safety_score=70),
    )

    decision = BrainModelComparator().compare(request, (less_safe, safer))

    assert decision.selected_brain_name == "safer-model"


def test_comparator_returns_no_selection_when_all_candidates_are_blocked() -> None:
    request = _request()
    blocked = BrainComparisonCandidate(
        brain_name="blocked-model",
        provider_name="ollama",
        model_name="blocked",
        role=BrainRole.PRIMARY,
        score=BrainComparisonScore(correctness_score=80),
        eligible=False,
        reasons=("budget exceeded",),
    )

    decision = BrainModelComparator().compare(request, (blocked,))

    assert decision.selected is None
    assert decision.selected_brain_name is None
    assert decision.rejected == ()
    assert decision.blocked[0].candidate.brain_name == "blocked-model"


def test_comparison_result_requires_reasons_and_valid_rank() -> None:
    candidate = _candidate()

    with pytest.raises(ValueError, match="comparison results must include"):
        BrainComparisonResult(
            candidate=candidate,
            disposition=BrainComparisonDisposition.REJECTED,
            rank=2,
        )

    with pytest.raises(ValueError, match="selected comparison results must have rank 1"):
        BrainComparisonResult(
            candidate=candidate,
            disposition=BrainComparisonDisposition.SELECTED,
            rank=2,
            reasons=("bad rank",),
        )


def test_decision_serializes_selected_rejected_and_blocked_results() -> None:
    request = _request()
    selected = _candidate(brain_name="selected-model")
    blocked = BrainComparisonCandidate(
        brain_name="blocked-model",
        provider_name="vllm",
        model_name="blocked",
        role=BrainRole.PRIMARY,
        score=BrainComparisonScore(),
        eligible=False,
        reasons=("provider unavailable",),
    )
    decision: BrainComparisonDecision = BrainModelComparator().compare(
        request,
        (blocked, selected),
    )

    payload = decision.to_dict()

    assert payload["selected_brain_name"] == "selected-model"
    assert payload["request"] == request.to_dict()
    assert isinstance(payload["results"], list)
    assert payload["results"][0]["disposition"] == "selected"
    assert payload["results"][1]["disposition"] == "blocked"


def _request() -> BrainComparisonRequest:
    return BrainComparisonRequest(
        comparison_id="comparison-1",
        required_role=BrainRole.PRIMARY,
        required_capabilities=(BrainCapability.CODE_GENERATION,),
        task_id="task-1",
        pack_name="programming",
        criteria=("correct", "safe", "evidence-backed"),
    )


def _candidate(
    *,
    brain_name: str = "candidate-model",
    provider_name: str = "ollama",
    model_name: str = "gpt-oss:20b",
    role: BrainRole = BrainRole.PRIMARY,
    score: BrainComparisonScore | None = None,
    output_text: str = "patch candidate",
) -> BrainComparisonCandidate:
    return BrainComparisonCandidate(
        brain_name=brain_name,
        provider_name=provider_name,
        model_name=model_name,
        role=role,
        score=score or BrainComparisonScore(correctness_score=80, safety_score=90),
        output_text=output_text,
    )
