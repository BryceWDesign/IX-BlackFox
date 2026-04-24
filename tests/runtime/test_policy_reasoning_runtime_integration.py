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


class UnifiedOllamaPolicyProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="ollama")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=9,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        brain_name = invocation.request.brain_name

        if brain_name == "gpt-oss-policy-20b":
            payload = {
                "advisory_disposition": "review",
                "rationale": (
                    "The request crosses a sensitive architectural boundary and "
                    "should be reviewed."
                ),
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
            output_text = json.dumps(payload)
            usage = BrainProviderUsage(input_tokens=84, output_tokens=46)
            latency_ms = 118
        elif brain_name == "gpt-oss-safeguard-20b":
            payload = {
                "advisory_disposition": "allow",
                "findings": [],
                "metadata": {"lane": "semantic-safety"},
            }
            output_text = json.dumps(payload)
            usage = BrainProviderUsage(input_tokens=40, output_tokens=8)
            latency_ms = 61
        else:
            output_text = "Primary brain completed the architecture task."
            usage = BrainProviderUsage(input_tokens=72, output_tokens=22)
            latency_ms = 104

        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=BrainInvocationStatus.SUCCEEDED,
                output_text=output_text,
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=usage,
            latency_ms=latency_ms,
            metadata={"backend": "integration-policy"},
        )


def test_runtime_integrates_policy_reasoning_lane_into_report_and_pack_flow(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {"ollama": UnifiedOllamaPolicyProvider()}  # noqa: SLF001

    report = runtime.run_prompt(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        kind=TaskKind.ARCHITECTURE,
        labels=("architecture",),
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.pack_name == "architecture"
    assert report.policy_advisory is not None
    assert report.policy_advisory.brain_name == "gpt-oss-policy-20b"
    assert report.policy_advisory.advisory_disposition.value == "review"
    assert report.policy_advisory.note_codes() == ("sensitive-boundary-review",)
    assert report.policy_advisory.policy_tags() == ("review", "sensitive-boundary")

    assert report.governance_preflight is not None
    assert report.governance_preflight.requires_review is False
    assert report.governance_preflight.blocked is False

    assert report.governance_receipts is not None
    assert report.governance_receipts.brain_receipt_count == 3
    assert any(
        receipt["brain_name"] == "gpt-oss-policy-20b"
        for receipt in report.governance_receipts.brain_receipts
    )

    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["brain_receipt_count"] == 3
    assert any(
        receipt["brain_name"] == "gpt-oss-policy-20b"
        for receipt in receipt_payload["brain_receipts"]
    )

    report_path = Path(report.report_path)
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["status"] == "passed"
    assert report_payload["pack_name"] == "architecture"
    assert report_payload["policy_advisory"] is not None
    assert report_payload["policy_advisory"]["brain_name"] == "gpt-oss-policy-20b"
    assert report_payload["policy_advisory"]["advisory_disposition"] == "review"
    assert report_payload["policy_advisory"]["note_codes"] == [
        "sensitive-boundary-review"
    ]
    assert report_payload["governance_preflight"]["decision"]["decision"] == "allow"
