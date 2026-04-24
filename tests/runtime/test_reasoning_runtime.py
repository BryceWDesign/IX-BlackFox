from __future__ import annotations

from pathlib import Path

from ix_blackfox.brains import (
    BrainInvocationReceiptLedger,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainModality,
    BrainRole,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
    BrainProviderUsage,
)
from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import TaskKind, TaskRecord, TaskRequest
from ix_blackfox.runtime import EscalatedReasoningRuntime
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class SuccessfulReasoningProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="openai-compatible")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=18,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text=(
                    '{"summary":"Route confidence and verification state justify deeper review.",'
                    '"key_points":["Low route confidence was observed.","Verification failed."],'
                    '"recommended_action":"Escalate to a deeper reasoning pass before mutation.",'
                    '"confidence":0.81,'
                    '"metadata":{"lane":"deep-reasoning"}}'
                ),
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=122,
                output_tokens=63,
            ),
            latency_ms=236,
            metadata={"backend": "dummy-reasoner"},
        )


def test_reasoning_plan_uses_wave1_reasoner_defaults(tmp_path: Path) -> None:
    runtime = EscalatedReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Patch the architecture runtime after failed verification.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture", "verification"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.44,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )

    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        escalation_score=70,
        trigger_codes=("verification_failure", "low_route_confidence"),
        verification_status="failed",
        sentinel_issue_codes=("sentinel.task_state_contradiction",),
        prior_failure_message="Verification failed after pack execution.",
    )

    assert plan.manifest.brain_name == "gpt-oss-reasoner-120b"
    assert plan.manifest.provider_name == "openai-compatible"
    assert plan.manifest.model_name == "gpt-oss:120b"
    assert plan.request.brain_name == "gpt-oss-reasoner-120b"
    assert plan.request.role is BrainRole.REASONING
    assert plan.request.pack_name == "architecture"
    assert plan.request.task_id == task.request.task_id
    assert plan.escalation_score == 70
    assert plan.trigger_codes == ("verification_failure", "low_route_confidence")
    assert plan.request.metadata["response_format"] == {"type": "json_object"}
    assert "Perform escalated deep reasoning for this task." in plan.request.prompt
    assert "Prior failure context:" in plan.request.prompt
    assert "deep reasoning escalation coprocessor" in plan.rendered_prompt.lower()


def test_reasoning_invoke_success_records_receipt_and_parses_output(
    tmp_path: Path,
) -> None:
    runtime = EscalatedReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Patch the architecture runtime after failed verification.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture", "verification"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.44,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        escalation_score=70,
        trigger_codes=("verification_failure", "low_route_confidence"),
    )
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={"openai-compatible": SuccessfulReasoningProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.SUCCEEDED
    assert outcome.summary == "Route confidence and verification state justify deeper review."
    assert outcome.parsed_output is not None
    assert outcome.parsed_output["recommended_action"] == (
        "Escalate to a deeper reasoning pass before mutation."
    )
    assert outcome.receipt is not None
    assert outcome.receipt.brain_name == "gpt-oss-reasoner-120b"
    assert outcome.receipt.provider_name == "openai-compatible"
    assert outcome.receipt.model_name == "gpt-oss:120b"
    assert outcome.receipt.task_id == task.request.task_id
    assert outcome.receipt.pack_name == "architecture"
    assert outcome.receipt.total_tokens == 185
    assert ledger.count() == 1


def test_reasoning_invoke_skips_when_provider_missing(tmp_path: Path) -> None:
    runtime = EscalatedReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Patch the architecture runtime after failed verification.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture", "verification"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.44,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        escalation_score=70,
        trigger_codes=("verification_failure",),
    )
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={},
        receipt_ledger=ledger,
    )

    assert outcome.skipped is True
    assert outcome.invoked is False
    assert outcome.succeeded is False
    assert outcome.result is None
    assert outcome.parsed_output is None
    assert outcome.receipt is None
    assert outcome.provider_name == "openai-compatible"
    assert "not configured" in (outcome.failure_message or "")
    assert ledger.count() == 0
