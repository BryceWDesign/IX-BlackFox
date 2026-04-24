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
from ix_blackfox.runtime import VisionRuntime
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class SuccessfulVisionProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="vllm")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=12,
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
                    '{"summary":"Blocked modal detected.","observations":["A blocking modal '
                    'covers the primary action button."],"risks":["User cannot proceed."],'
                    '"recommended_next_checks":["Inspect modal-dismiss conditions."],'
                    '"metadata":{"screen":"settings"}}'
                ),
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=95,
                output_tokens=58,
            ),
            latency_ms=140,
            metadata={"backend": "dummy-vision"},
        )


def test_vision_plan_uses_wave1_multimodal_defaults(tmp_path: Path) -> None:
    runtime = VisionRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the UI screenshot and explain why the user is blocked.",
            kind=TaskKind.ARCHITECTURE,
            labels=("ui", "architecture"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.86,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )

    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        images=("base64-image-1",),
        question="What is preventing the user from proceeding?",
    )

    assert plan.manifest.brain_name == "qwen-vision"
    assert plan.manifest.provider_name == "vllm"
    assert plan.manifest.model_name == "qwen2.5-vl:7b"
    assert plan.request.brain_name == "qwen-vision"
    assert plan.request.role is BrainRole.MULTIMODAL
    assert plan.request.pack_name == "architecture"
    assert plan.request.task_id == task.request.task_id
    assert plan.request.input_modalities == (
        BrainModality.TEXT,
        BrainModality.IMAGE,
    )
    assert plan.request.metadata["image_count"] == 1
    assert plan.request.metadata["response_format"] == {"type": "json_object"}
    assert plan.source_pack_name == "architecture"
    assert plan.route_capability_name == "architecture"
    assert plan.image_count == 1
    assert "Return strict JSON with this shape:" in plan.request.prompt
    assert "Specific question:" in plan.request.prompt
    assert "multimodal vision coprocessor" in plan.rendered_prompt.lower()


def test_vision_invoke_success_records_receipt(tmp_path: Path) -> None:
    runtime = VisionRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the UI screenshot and explain why the user is blocked.",
            kind=TaskKind.ARCHITECTURE,
            labels=("ui", "architecture"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.86,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        images=("base64-image-1",),
    )
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={"vllm": SuccessfulVisionProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.SUCCEEDED
    assert outcome.observation_text is not None
    assert "Blocked modal detected" in outcome.observation_text
    assert outcome.receipt is not None
    assert outcome.receipt.brain_name == "qwen-vision"
    assert outcome.receipt.provider_name == "vllm"
    assert outcome.receipt.model_name == "qwen2.5-vl:7b"
    assert outcome.receipt.task_id == task.request.task_id
    assert outcome.receipt.pack_name == "architecture"
    assert outcome.receipt.total_tokens == 153
    assert ledger.count() == 1


def test_vision_invoke_skips_when_provider_missing(tmp_path: Path) -> None:
    runtime = VisionRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the UI screenshot and explain why the user is blocked.",
            kind=TaskKind.ARCHITECTURE,
            labels=("ui", "architecture"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.86,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        images=("base64-image-1",),
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
    assert outcome.receipt is None
    assert outcome.provider_name == "vllm"
    assert "not configured" in (outcome.failure_message or "")
    assert ledger.count() == 0
