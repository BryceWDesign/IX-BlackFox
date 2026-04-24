from __future__ import annotations

import json
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
from ix_blackfox.runtime import PolicyReasoningRuntime
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class SuccessfulPolicyReasoningProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=10,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        payload = {
            "advisory_disposition": "review",
            "rationale": "The request crosses a sensitive architectural boundary and should be reviewed.",
            "notes": [
                {
                    "code": "sensitive-boundary-review",
                    "summary": "Sensitive architectural boundary detected.",
                    "policy_tags": ["review", "sensitive-boundary"],
                    "confidence": 0.86,
                }
            ],
            "metadata": {"lane": "policy-advisory"},
        }
        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text=json.dumps(payload),
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=84,
                output_tokens=46,
            ),
            latency_ms=118,
            metadata={"backend": "dummy-policy"},
        )


def test_policy_reasoning_plan_uses_wave1_policy_defaults(tmp_path: Path) -> None:
    runtime = PolicyReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture", "ui"),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )

    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="architecture",
        candidate_output="Boundary summary draft.",
        vision_observation="A blocking modal overlaps the main action area.",
    )

    assert plan.manifest.brain_name == "gpt-oss-policy-20b"
    assert plan.manifest.provider_name == "ollama"
    assert plan.manifest.model_name == "gpt-oss-policy:20b"
    assert plan.request.brain_name == "gpt-oss-policy-20b"
    assert plan.request.role is BrainRole.REASONING
    assert plan.request.pack_name == "architecture"
    assert plan.request.task_id == task.request.task_id
    assert plan.request.metadata["response_format"] == {"type": "json_object"}
    assert plan.source_pack_name == "architecture"
    assert plan.route_capability_name == "architecture"
    assert "Return strict JSON with this shape:" in plan.request.prompt
    assert "Candidate output under policy review:" in plan.request.prompt
    assert "Vision observation context:" in plan.request.prompt
    assert "advisory policy reasoning coprocessor" in plan.rendered_prompt.lower()


def test_policy_reasoning_invoke_success_normalizes_assessment_and_receipt(
    tmp_path: Path,
) -> None:
    runtime = PolicyReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="architecture")
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={"ollama": SuccessfulPolicyReasoningProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.SUCCEEDED
    assert outcome.assessment is not None
    assert outcome.assessment.brain_name == "gpt-oss-policy-20b"
    assert outcome.assessment.advisory_disposition.value == "review"
    assert outcome.assessment.note_codes() == ("sensitive-boundary-review",)
    assert outcome.assessment.policy_tags() == ("review", "sensitive-boundary")
    assert outcome.receipt is not None
    assert outcome.receipt.provider_name == "ollama"
    assert outcome.receipt.model_name == "gpt-oss-policy:20b"
    assert outcome.receipt.task_id == task.request.task_id
    assert outcome.receipt.pack_name == "architecture"
    assert outcome.receipt.safety_labels == ("review", "sensitive-boundary")
    assert outcome.receipt.total_tokens == 130
    assert ledger.count() == 1


def test_policy_reasoning_invoke_skips_when_provider_missing(tmp_path: Path) -> None:
    runtime = PolicyReasoningRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="architecture")
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
    assert outcome.assessment is None
    assert outcome.receipt is None
    assert ledger.count() == 0
