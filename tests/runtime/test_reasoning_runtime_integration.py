from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.brains import (
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
from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


class SuccessfulReasoningOnlyProvider(BrainProvider):
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
                    '{"summary":"Deep reasoning confirms the architectural path should be reviewed carefully.",'
                    '"key_points":["The user explicitly requested heavier reasoning."],'
                    '"recommended_action":"Perform a deeper review before making structural changes.",'
                    '"confidence":0.84,'
                    '"metadata":{"lane":"deep-reasoning"}}'
                ),
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=116,
                output_tokens=52,
            ),
            latency_ms=221,
            metadata={"backend": "integration-reasoner"},
        )


def test_runtime_integrates_reasoning_lane_into_report_and_receipts(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {  # noqa: SLF001
        "openai-compatible": SuccessfulReasoningOnlyProvider()
    }

    report = runtime.run_prompt(
        prompt="Think hard about the architecture and summarize the subsystem boundaries.",
        kind=TaskKind.ARCHITECTURE,
        labels=("architecture",),
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.pack_name == "architecture"
    assert report.escalation_decision is not None
    assert report.escalation_decision.should_escalate is True
    assert report.escalation_decision.trigger_codes() == (
        "explicit_deep_reasoning_request",
    )

    assert report.reasoning_outcome is not None
    assert report.reasoning_outcome["brain_name"] == "gpt-oss-reasoner-120b"
    assert report.reasoning_outcome["provider_name"] == "openai-compatible"
    assert report.reasoning_outcome["escalation_score"] == 60
    assert report.reasoning_outcome["trigger_codes"] == [
        "explicit_deep_reasoning_request"
    ]
    assert report.reasoning_outcome["invoked"] is True
    assert report.reasoning_outcome["succeeded"] is True
    assert (
        report.reasoning_outcome["summary"]
        == "Deep reasoning confirms the architectural path should be reviewed carefully."
    )

    assert report.governance_receipts is not None
    assert report.governance_receipts.brain_receipt_count == 1
    assert report.governance_receipts.brain_receipts[0]["brain_name"] == (
        "gpt-oss-reasoner-120b"
    )
    assert report.governance_receipts.brain_receipts[0]["provider_name"] == (
        "openai-compatible"
    )

    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["brain_receipt_count"] == 1
    assert receipt_payload["brain_receipts"][0]["brain_name"] == (
        "gpt-oss-reasoner-120b"
    )

    report_path = Path(report.report_path)
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["status"] == "passed"
    assert report_payload["pack_name"] == "architecture"
    assert report_payload["reasoning_outcome"] is not None
    assert report_payload["reasoning_outcome"]["brain_name"] == "gpt-oss-reasoner-120b"
    assert report_payload["reasoning_outcome"]["escalation_score"] == 60
    assert report_payload["reasoning_outcome"]["succeeded"] is True
