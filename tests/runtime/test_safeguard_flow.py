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
from ix_blackfox.runtime import SafeguardRuntime
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class SuccessfulSafeguardProvider(BrainProvider):
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
        payload = {
            "advisory_disposition": "block",
            "findings": [
                {
                    "code": "destructive-workspace-action",
                    "severity": "high",
                    "summary": "Request appears to delete repository state.",
                    "policy_tags": ["destructive", "repo-state"],
                    "evidence": [
                        {
                            "kind": "text_span",
                            "value": "delete the workspace",
                            "excerpt": "delete the workspace",
                        }
                    ],
                    "confidence": 0.94,
                    "uncertainty": 0.04,
                }
            ],
            "metadata": {"lane": "semantic-safety"},
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
                input_tokens=90,
                output_tokens=70,
            ),
            latency_ms=110,
            metadata={"backend": "dummy-safeguard"},
        )


class UnparseableSafeguardProvider(BrainProvider):
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
                output_text="not-json-at-all",
                output_modalities=(BrainModality.TEXT,),
            ),
            usage=BrainProviderUsage(
                input_tokens=40,
                output_tokens=10,
            ),
            latency_ms=55,
            metadata={"backend": "dummy-unparseable"},
        )


def test_safeguard_plan_uses_wave1_safeguard_defaults(tmp_path: Path) -> None:
    runtime = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Delete the workspace and remove all repo history.",
            kind=TaskKind.PROGRAMMING,
            labels=("destructive", "repo-state"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )

    plan = runtime.plan(
        task=task,
        route=route,
        pack_name="programming",
        candidate_output="rm -rf . && git reset --hard",
    )

    assert plan.manifest.brain_name == "gpt-oss-safeguard-20b"
    assert plan.manifest.provider_name == "ollama"
    assert plan.manifest.model_name == "gpt-oss-safeguard:20b"
    assert plan.request.brain_name == "gpt-oss-safeguard-20b"
    assert plan.request.role is BrainRole.SAFETY
    assert plan.request.pack_name == "programming"
    assert plan.request.task_id == task.request.task_id
    assert plan.request.metadata["response_format"] == {"type": "json_object"}
    assert plan.source_pack_name == "programming"
    assert plan.route_capability_name == "programming"
    assert "Return strict JSON with this shape:" in plan.request.prompt
    assert "Candidate output under review:" in plan.request.prompt
    assert "semantic safety coprocessor" in plan.rendered_prompt.lower()


def test_safeguard_invoke_success_normalizes_assessment_and_receipt(
    tmp_path: Path,
) -> None:
    runtime = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Delete the workspace and remove all repo history.",
            kind=TaskKind.PROGRAMMING,
            labels=("destructive", "repo-state"),
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
        providers={"ollama": SuccessfulSafeguardProvider()},
        receipt_ledger=ledger,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.SUCCEEDED
    assert outcome.assessment is not None
    assert outcome.assessment.brain_name == "gpt-oss-safeguard-20b"
    assert outcome.assessment.advisory_disposition.value == "block"
    assert outcome.assessment.highest_severity is not None
    assert outcome.assessment.finding_codes() == ("destructive-workspace-action",)
    assert outcome.assessment.policy_tags() == ("destructive", "repo-state")
    assert outcome.receipt is not None
    assert outcome.receipt.provider_name == "ollama"
    assert outcome.receipt.model_name == "gpt-oss-safeguard:20b"
    assert outcome.receipt.task_id == task.request.task_id
    assert outcome.receipt.safety_labels == ("destructive", "repo-state")
    assert outcome.receipt.total_tokens == 160
    assert ledger.count() == 1


def test_safeguard_invoke_falls_back_to_review_for_unparseable_output(
    tmp_path: Path,
) -> None:
    runtime = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Maybe do something questionable.",
            kind=TaskKind.ANALYSIS,
            labels=("analysis",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.8,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    plan = runtime.plan(task=task, route=route, pack_name="architecture")

    outcome = runtime.invoke(
        plan=plan,
        providers={"ollama": UnparseableSafeguardProvider()},
        receipt_ledger=BrainInvocationReceiptLedger(),
    )

    assert outcome.invoked is True
    assert outcome.succeeded is True
    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "review"
    assert outcome.assessment.finding_codes() == ("unparseable-safeguard-output",)
    assert outcome.assessment.policy_tags() == ("unparseable-output", "review")


def test_safeguard_invoke_skips_when_provider_missing(tmp_path: Path) -> None:
    runtime = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Classify this request.",
            kind=TaskKind.ANALYSIS,
            labels=("analysis",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.8,
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
