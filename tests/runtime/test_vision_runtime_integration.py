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


class SuccessfulVisionOnlyProvider(BrainProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="vllm")

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=11,
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
                    '{"summary":"Blocking modal detected.","observations":["A modal overlays the '
                    'primary action area."],"risks":["The user cannot continue."],'
                    '"recommended_next_checks":["Inspect modal-dismiss logic."],'
                    '"metadata":{"screen":"settings"}}'
                ),
                output_modalities=(BrainModality.TEXT,),
                metadata={"finish_reason": "stop"},
            ),
            usage=BrainProviderUsage(
                input_tokens=88,
                output_tokens=44,
            ),
            latency_ms=132,
            metadata={"backend": "integration-vision"},
        )


def test_runtime_integrates_vision_lane_into_report_and_pack_flow(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {"vllm": SuccessfulVisionOnlyProvider()}  # noqa: SLF001

    report = runtime.run_prompt(
        prompt="Inspect the UI screenshot and explain why the user is blocked.",
        kind=TaskKind.ARCHITECTURE,
        labels=("ui", "architecture"),
        metadata={
            "vision_images": ("base64-image-1",),
            "vision_question": "What is preventing the user from proceeding?",
        },
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.pack_name == "architecture"
    assert report.vision_outcome is not None
    assert report.vision_outcome["brain_name"] == "qwen-vision"
    assert report.vision_outcome["provider_name"] == "vllm"
    assert report.vision_outcome["image_count"] == 1
    assert report.vision_outcome["invoked"] is True
    assert report.vision_outcome["succeeded"] is True
    assert "Blocking modal detected" in report.vision_outcome["observation_text"]

    assert report.governance_receipts is not None
    assert report.governance_receipts.brain_receipt_count == 1
    assert report.governance_receipts.brain_receipts[0]["brain_name"] == "qwen-vision"
    assert report.governance_receipts.brain_receipts[0]["provider_name"] == "vllm"

    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["brain_receipt_count"] == 1
    assert receipt_payload["brain_receipts"][0]["brain_name"] == "qwen-vision"

    report_path = Path(report.report_path)
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["status"] == "passed"
    assert report_payload["pack_name"] == "architecture"
    assert report_payload["vision_outcome"] is not None
    assert report_payload["vision_outcome"]["brain_name"] == "qwen-vision"
    assert report_payload["vision_outcome"]["image_count"] == 1
    assert report_payload["vision_outcome"]["succeeded"] is True
