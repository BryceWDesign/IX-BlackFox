from __future__ import annotations

from collections.abc import Iterable

from ix_blackfox.authoring import (
    AuthoringMode,
    PatchAuthoringPromptContract,
    PatchAuthoringResponseSchema,
    PromptContractMessage,
    PromptMessageRole,
)
from ix_blackfox.brains import (
    BrainComparisonScore,
    BrainRole,
    BrainTribunalAssignment,
    BrainTribunalIdentity,
    BrainTribunalRole,
    BrainTribunalRoleKind,
)
from ix_blackfox.runtime import (
    BrainRepairCandidateSource,
    MultiBrainRepairProposalProvider,
    StaticPatchProposalProvider,
)


class ExplodingProposalProvider:
    provider_name = "exploding-provider"
    model_name = "exploding-model"

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        raise RuntimeError("provider exploded")


def test_multi_brain_repair_provider_selects_highest_scored_proposal() -> None:
    provider = MultiBrainRepairProposalProvider(
        sources=(
            _source(
                source_id="fast-local",
                raw_response='{"proposal_id":"fast"}',
                score=BrainComparisonScore(correctness_score=60, safety_score=80),
            ),
            _source(
                source_id="reasoned-local",
                raw_response='{"proposal_id":"reasoned"}',
                score=BrainComparisonScore(correctness_score=95, safety_score=95),
            ),
        ),
        tribunal_assignments=(_critic_assignment(),),
    )

    report = provider.select(_contract())

    assert report.selected_raw_response == '{"proposal_id":"reasoned"}'
    assert tuple(provider.generate(_contract())) == ('{"proposal_id":"reasoned"}',)
    assert report.comparison_decision.selected_brain_name == "reasoned-local-proposal-1"
    assert report.tribunal_decision is not None
    assert report.tribunal_decision.selected_brain_name == "critic-brain"
    assert report.to_dict()["selected_source_id"] == "reasoned-local"


def test_multi_brain_repair_provider_blocks_without_separated_reviewer() -> None:
    generator = _source(
        source_id="generator",
        raw_response='{"proposal_id":"self-reviewed"}',
        provider_name="ollama",
        model_name="gpt-oss:20b",
        score=BrainComparisonScore(correctness_score=90, safety_score=90),
    )
    self_reviewer = BrainTribunalAssignment(
        assignment_id="self-reviewer",
        role=_critic_role(),
        identity=BrainTribunalIdentity(
            brain_name="generator-brain",
            provider_name="ollama",
            model_name="gpt-oss:20b",
        ),
    )
    provider = MultiBrainRepairProposalProvider(
        sources=(generator,),
        tribunal_assignments=(self_reviewer,),
    )

    report = provider.select(_contract())

    assert report.selected_raw_response is None
    assert tuple(provider.generate(_contract())) == ()
    assert report.blocked is True
    assert report.tribunal_decision is not None
    assert report.tribunal_decision.selected_assignment is None
    assert "self-review blocked for provider/model: ollama/gpt-oss:20b" in (
        report.tribunal_decision.findings[0].reasons
    )


def test_multi_brain_repair_provider_can_compare_without_tribunal_requirement() -> None:
    provider = MultiBrainRepairProposalProvider(
        sources=(
            _source(
                source_id="solo",
                raw_response='{"proposal_id":"solo"}',
                score=BrainComparisonScore(correctness_score=70, safety_score=90),
            ),
        ),
        require_tribunal_review=False,
    )

    report = provider.select(_contract())

    assert report.selected_raw_response == '{"proposal_id":"solo"}'
    assert report.tribunal_decision is None
    assert report.review_routed is True


def test_multi_brain_repair_provider_records_provider_failures_as_blocked_candidates() -> None:
    provider = MultiBrainRepairProposalProvider(
        sources=(
            BrainRepairCandidateSource(
                source_id="broken",
                provider=ExplodingProposalProvider(),
                brain_name="broken-brain",
                provider_name="broken-provider",
                model_name="broken-model",
                score=BrainComparisonScore(correctness_score=100),
            ),
            _source(
                source_id="fallback",
                raw_response='{"proposal_id":"fallback"}',
                score=BrainComparisonScore(correctness_score=50, safety_score=80),
            ),
        ),
        tribunal_assignments=(_critic_assignment(),),
    )

    report = provider.select(_contract())

    assert report.selected_raw_response == '{"proposal_id":"fallback"}'
    assert report.comparison_decision.blocked[0].candidate.brain_name == (
        "broken-proposal-1"
    )
    assert report.records[0].error == "provider exploded"


def test_multi_brain_repair_provider_returns_empty_when_every_source_is_blocked() -> None:
    provider = MultiBrainRepairProposalProvider(
        sources=(
            BrainRepairCandidateSource(
                source_id="broken",
                provider=ExplodingProposalProvider(),
                brain_name="broken-brain",
                provider_name="broken-provider",
                model_name="broken-model",
            ),
        ),
        tribunal_assignments=(_critic_assignment(),),
    )

    report = provider.select(_contract())

    assert report.selected_raw_response is None
    assert tuple(provider.generate(_contract())) == ()
    assert report.comparison_decision.selected is None
    assert report.comparison_decision.blocked[0].reasons == ("provider exploded",)


def test_multi_brain_repair_provider_caps_responses_per_source() -> None:
    source = BrainRepairCandidateSource(
        source_id="multi-output",
        provider=StaticPatchProposalProvider(
            responses=(
                '{"proposal_id":"first"}',
                '{"proposal_id":"second"}',
            )
        ),
        brain_name="multi-output-brain",
        provider_name="static",
        model_name="static-model",
        score=BrainComparisonScore(correctness_score=80, safety_score=80),
    )
    provider = MultiBrainRepairProposalProvider(
        sources=(source,),
        tribunal_assignments=(_critic_assignment(),),
        max_responses_per_source=1,
    )

    report = provider.select(_contract())

    assert len(report.records) == 1
    assert report.records[0].raw_response == '{"proposal_id":"first"}'


def _source(
    *,
    source_id: str,
    raw_response: str,
    provider_name: str = "ollama",
    model_name: str | None = None,
    score: BrainComparisonScore,
) -> BrainRepairCandidateSource:
    return BrainRepairCandidateSource(
        source_id=source_id,
        provider=StaticPatchProposalProvider(
            responses=(raw_response,),
            provider_name=provider_name,
            model_name=model_name or f"{source_id}-model",
        ),
        brain_name=f"{source_id}-brain",
        provider_name=provider_name,
        model_name=model_name or f"{source_id}-model",
        role=BrainRole.PRIMARY,
        score=score,
    )


def _critic_assignment() -> BrainTribunalAssignment:
    return BrainTribunalAssignment(
        assignment_id="critic-assignment",
        role=_critic_role(),
        identity=BrainTribunalIdentity(
            brain_name="critic-brain",
            provider_name="vllm",
            model_name="critic-model",
        ),
    )


def _critic_role() -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id="critic-role",
        role_kind=BrainTribunalRoleKind.CRITIC,
        description="Reviews generated repair candidates.",
        may_review=True,
    )


def _contract() -> PatchAuthoringPromptContract:
    return PatchAuthoringPromptContract(
        contract_id="contract-1",
        request_id="request-1",
        objective_id="objective-1",
        prompt_version="wave3-patch-authoring-v1",
        mode=AuthoringMode.MODEL_ASSISTED,
        messages=(
            PromptContractMessage(
                role=PromptMessageRole.SYSTEM,
                content="System rules.",
            ),
            PromptContractMessage(
                role=PromptMessageRole.USER,
                content="User repair request.",
            ),
        ),
        response_schema=PatchAuthoringResponseSchema(),
        context_digest="0" * 64,
        evidence_digest="1" * 64,
    )
