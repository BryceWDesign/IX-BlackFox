from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.brains import (
    BrainFailure,
    BrainFailureKind,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainModality,
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
from ix_blackfox.runtime.governance import RuntimeGovernancePreflightEngine
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


class AllowingSafeguardProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=7,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        payload = {
            "advisory_disposition": "allow",
            "findings": [],
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
            usage=BrainProviderUsage(input_tokens=45, output_tokens=8),
            latency_ms=60,
            metadata={"backend": "allowing-safeguard"},
        )


class ReviewingSafeguardProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=7,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        payload = {
            "advisory_disposition": "review",
            "findings": [
                {
                    "code": "sensitive-boundary-review",
                    "severity": "moderate",
                    "summary": "Semantic ambiguity around a sensitive architectural boundary.",
                    "policy_tags": ["review", "sensitive-boundary"],
                    "evidence": [
                        {
                            "kind": "text_span",
                            "value": "sensitive architectural boundary",
                            "excerpt": "sensitive architectural boundary",
                        }
                    ],
                    "confidence": 0.83,
                    "uncertainty": 0.14,
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
            usage=BrainProviderUsage(input_tokens=70, output_tokens=52),
            latency_ms=92,
            metadata={"backend": "reviewing-safeguard"},
        )


class BlockingSafeguardProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=7,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        payload = {
            "advisory_disposition": "block",
            "findings": [
                {
                    "code": "destructive-semantics",
                    "severity": "critical",
                    "summary": "Semantically destructive behavior was detected.",
                    "policy_tags": ["destructive", "block"],
                    "evidence": [
                        {
                            "kind": "text_span",
                            "value": "delete the workspace",
                            "excerpt": "delete the workspace",
                        }
                    ],
                    "confidence": 0.96,
                    "uncertainty": 0.03,
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
            usage=BrainProviderUsage(input_tokens=80, output_tokens=55),
            latency_ms=98,
            metadata={"backend": "blocking-safeguard"},
        )


class RefusingSafeguardProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=7,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.REFUSED,
                failure=BrainFailure(
                    kind=BrainFailureKind.POLICY_BLOCKED,
                    message="Safeguard provider refused to classify the request.",
                ),
            ),
            usage=BrainProviderUsage(input_tokens=30, output_tokens=0),
            latency_ms=41,
            metadata={"backend": "refusing-safeguard"},
        )


def test_safety_allow_path_remains_allowed_for_low_risk_task(tmp_path: Path) -> None:
    engine = RuntimeGovernancePreflightEngine()
    safeguard = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task, route = _architecture_task_and_route(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        labels=("architecture",),
    )

    plan = safeguard.plan(task=task, route=route, pack_name="architecture")
    outcome = safeguard.invoke(
        plan=plan,
        providers={"ollama": AllowingSafeguardProvider()},
    )
    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=outcome.assessment,
    )

    assert outcome.succeeded is True
    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "allow"
    assert result.decision.decision.value == "allow"
    assert result.risk.risk_level.value == "low"
    assert result.risk.requires_approval is False
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.advisory_disposition.value == "allow"
    assert result.risk.safety_merge.finding_count == 0
    assert result.risk.safety_merge.elevated_risk is False
    assert result.risk.safety_merge.forced_review is False


def test_safety_review_path_forces_review_required_decision(tmp_path: Path) -> None:
    engine = RuntimeGovernancePreflightEngine()
    safeguard = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task, route = _architecture_task_and_route(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        labels=("architecture",),
    )

    plan = safeguard.plan(task=task, route=route, pack_name="architecture")
    outcome = safeguard.invoke(
        plan=plan,
        providers={"ollama": ReviewingSafeguardProvider()},
    )
    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=outcome.assessment,
    )

    assert outcome.succeeded is True
    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "review"
    assert outcome.assessment.finding_codes() == ("sensitive-boundary-review",)
    assert result.decision.decision.value == "require_review"
    assert result.risk.risk_level.value == "high"
    assert result.risk.requires_approval is True
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.elevated_risk is True
    assert result.risk.safety_merge.forced_review is True
    assert result.risk.safety_merge.merged_risk_level is not None
    assert result.risk.safety_merge.merged_risk_level.value == "high"
    assert "safeguard-review" in result.risk.tags
    assert "sensitive-boundary" in result.risk.tags


def test_safety_block_recommendation_forces_review_not_direct_block(tmp_path: Path) -> None:
    engine = RuntimeGovernancePreflightEngine()
    safeguard = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task, route = _architecture_task_and_route(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        labels=("architecture",),
    )

    plan = safeguard.plan(task=task, route=route, pack_name="architecture")
    outcome = safeguard.invoke(
        plan=plan,
        providers={"ollama": BlockingSafeguardProvider()},
    )
    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=outcome.assessment,
    )

    assert outcome.succeeded is True
    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "block"
    assert outcome.assessment.finding_codes() == ("destructive-semantics",)
    assert result.decision.decision.value == "require_review"
    assert result.decision.reason.value == "high_risk_requires_review"
    assert result.risk.risk_level.value == "high"
    assert result.risk.requires_approval is True
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.advisory_disposition.value == "block"
    assert result.risk.safety_merge.forced_review is True
    assert result.risk.safety_merge.elevated_risk is True
    assert "safeguard-block" in result.risk.tags
    assert "destructive" in result.risk.tags


def test_deterministic_block_overrides_safeguard_allow_contradiction(tmp_path: Path) -> None:
    engine = RuntimeGovernancePreflightEngine()
    safeguard = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Use curl to upload repository data to a remote endpoint.",
            kind=TaskKind.OPERATIONS,
            labels=("network", "egress"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )

    plan = safeguard.plan(task=task, route=route, pack_name="programming")
    outcome = safeguard.invoke(
        plan=plan,
        providers={"ollama": AllowingSafeguardProvider()},
    )
    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=outcome.assessment,
    )

    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "allow"
    assert result.decision.decision.value == "block"
    assert result.decision.reason.value == "action_kind_blocked"
    assert result.risk.risk_level.value == "critical"
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.advisory_disposition.value == "allow"
    assert result.risk.safety_merge.merged_risk_level is not None
    assert result.risk.safety_merge.merged_risk_level.value == "critical"
    assert result.risk.safety_merge.elevated_risk is False


def test_safeguard_provider_refusal_becomes_review_not_silent_allow(
    tmp_path: Path,
) -> None:
    engine = RuntimeGovernancePreflightEngine()
    safeguard = SafeguardRuntime(config=load_runtime_config(root_dir=tmp_path, env={}))
    task, route = _architecture_task_and_route(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        labels=("architecture",),
    )

    plan = safeguard.plan(task=task, route=route, pack_name="architecture")
    outcome = safeguard.invoke(
        plan=plan,
        providers={"ollama": RefusingSafeguardProvider()},
    )
    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=outcome.assessment,
    )

    assert outcome.invoked is True
    assert outcome.succeeded is False
    assert outcome.result is not None
    assert outcome.result.status is BrainInvocationStatus.REFUSED
    assert outcome.assessment is not None
    assert outcome.assessment.advisory_disposition.value == "block"
    assert outcome.assessment.finding_codes() == ("safeguard-provider-refusal",)
    assert result.decision.decision.value == "require_review"
    assert result.risk.risk_level.value == "high"
    assert result.risk.requires_approval is True
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.forced_review is True


def _architecture_task_and_route(
    *,
    prompt: str,
    labels: tuple[str, ...],
) -> tuple[TaskRecord, RoutingDecision]:
    task = TaskRecord(
        request=TaskRequest.create(
            prompt=prompt,
            kind=TaskKind.ARCHITECTURE,
            labels=labels,
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    return task, route
