from __future__ import annotations

from pathlib import Path

from ix_blackfox.brains import (
    BrainFailure,
    BrainFailureKind,
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
    BrainProviderUnavailableError,
    BrainProviderUsage,
)
from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import TaskKind, TaskRecord, TaskRequest
from ix_blackfox.runtime import PrimaryBrainRuntime
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class SuccessfulPrimaryProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=8,
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
                output_text="Primary brain completed the programming task.",
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=120,
                output_tokens=40,
            ),
            latency_ms=125,
            metadata={"backend": "dummy-success"},
        )


class UnavailablePrimaryProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=False,
            message="offline",
            latency_ms=0,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        raise BrainProviderUnavailableError("Local provider is offline.")


def test_primary_brain_plan_for_programming_task_uses_gpt_oss_defaults(
    tmp_path: Path,
) -> None:
    runtime = PrimaryBrainRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests, inspect the repo, and prepare a patch.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "tests", "patching"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )

    plan = runtime.plan(task=task, route=route, pack_name="programming")

    assert plan.manifest.brain_name == "gpt-oss-20b"
    assert plan.manifest.provider_name == "ollama"
    assert plan.manifest.model_name == "gpt-oss:20b"
    assert plan.required_capabilities == (
        plan.required_capabilities[0],
        plan.required_capabilities[1],
        plan.required_capabilities[2],
    )
    assert tuple(capability.value for capability in plan.required_capabilities) == (
        "text_generation",
        "code_generation",
        "tool_planning",
    )
    assert plan.request.brain_name == "gpt-oss-20b"
    assert plan.request.pack_name == "programming"
    assert plan.request.task_id == task.request.task_id
    assert plan.request.metadata["route_capability_name"] == "programming"
    assert plan.request.metadata["task_kind"] == "programming"
    assert plan.rendered_prompt.startswith("<|start|>developer<|message|>")
    assert "Operate as the default BlackFox primary programming brain." in plan.rendered_prompt
    assert "Fix the failing tests, inspect the repo, and prepare a patch." in plan.rendered_prompt


def test_primary_brain_invoke_success_records_receipt(tmp_path: Path) -> None:
    runtime = PrimaryBrainRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests and prepare a patch.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "patching"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="programming")
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={"ollama": SuccessfulPrimaryProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.SUCCEEDED
    assert outcome.result.output_text == "Primary brain completed the programming task."
    assert outcome.receipt is not None
    assert outcome.receipt.brain_name == "gpt-oss-20b"
    assert outcome.receipt.provider_name == "ollama"
    assert outcome.receipt.model_name == "gpt-oss:20b"
    assert outcome.receipt.task_id == task.request.task_id
    assert outcome.receipt.pack_name == "programming"
    assert outcome.receipt.input_tokens == 120
    assert outcome.receipt.output_tokens == 40
    assert outcome.receipt.total_tokens == 160
    assert outcome.receipt.metadata["backend"] == "dummy-success"
    assert outcome.receipt.metadata["result"] == {"finish_reason": "stop"}
    assert ledger.count() == 1
    assert ledger.snapshot().filter_by_task(task.request.task_id)[0] == outcome.receipt


def test_primary_brain_invoke_skips_when_provider_is_not_configured(
    tmp_path: Path,
) -> None:
    runtime = PrimaryBrainRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests and prepare a patch.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "patching"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="programming")
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
    assert outcome.provider_name == "ollama"
    assert "not configured" in (outcome.failure_message or "")
    assert ledger.count() == 0


def test_primary_brain_invoke_records_failed_receipt_when_provider_errors(
    tmp_path: Path,
) -> None:
    runtime = PrimaryBrainRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests and prepare a patch.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "patching"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="programming")
    ledger = BrainInvocationReceiptLedger()

    outcome = runtime.invoke(
        plan=plan,
        providers={"ollama": UnavailablePrimaryProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.skipped is False
    assert outcome.invoked is True
    assert outcome.succeeded is False
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.FAILED
    assert outcome.result.failure is not None
    assert outcome.result.failure.kind is BrainFailureKind.PROVIDER_UNAVAILABLE
    assert "offline" in outcome.result.failure.message.lower()
    assert outcome.failure_message is not None
    assert "offline" in outcome.failure_message.lower()
    assert outcome.receipt is not None
    assert outcome.receipt.status is BrainInvocationStatus.FAILED
    assert ledger.count() == 1
