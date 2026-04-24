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


class UnifiedOllamaReadinessProvider(BrainProvider):
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
        brain_name = invocation.request.brain_name

        if brain_name == "gpt-oss-policy-20b":
            output_text = json.dumps(
                {
                    "advisory_disposition": "allow",
                    "rationale": "No additional policy concerns were detected.",
                    "notes": [],
                    "metadata": {"lane": "policy-advisory"},
                }
            )
            usage = BrainProviderUsage(input_tokens=52, output_tokens=18)
            latency_ms = 84
        elif brain_name == "gpt-oss-safeguard-20b":
            output_text = json.dumps(
                {
                    "advisory_disposition": "allow",
                    "findings": [],
                    "metadata": {"lane": "semantic-safety"},
                }
            )
            usage = BrainProviderUsage(input_tokens=41, output_tokens=8)
            latency_ms = 63
        else:
            output_text = "Primary brain completed the architecture task."
            usage = BrainProviderUsage(input_tokens=66, output_tokens=24)
            latency_ms = 97

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
            metadata={"backend": "integration-readiness"},
        )


def test_runtime_serializes_degraded_readiness_without_downgrading_run_status(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {"ollama": UnifiedOllamaReadinessProvider()}  # noqa: SLF001

    report = runtime.run_prompt(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        kind=TaskKind.ARCHITECTURE,
        labels=("architecture",),
    )

    assert report.status is RuntimeRunStatus.PASSED
    assert report.pack_name == "architecture"
    assert report.readiness_report is not None
    assert report.readiness_report.status.value == "degraded"
    assert report.readiness_report.available_lane_count == 3
    assert report.readiness_report.total_lane_count == 5
    assert report.readiness_report.unavailable_lanes() == ("vision", "reasoning")
    assert report.readiness_report.critical_failures() == ()
    assert report.readiness_report.issue_codes == (
        "runtime.readiness.provider_missing.vision",
        "runtime.readiness.provider_missing.reasoning",
    )
    assert (
        report.readiness_report.summary()
        == "Runtime degraded: unavailable lanes -> vision, reasoning."
    )

    report_path = Path(report.report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert payload["status"] == "passed"
    assert payload["readiness_report"] is not None
    assert payload["readiness_report"]["status"] == "degraded"
    assert payload["readiness_report"]["available_lane_count"] == 3
    assert payload["readiness_report"]["total_lane_count"] == 5
    assert payload["readiness_report"]["unavailable_lanes"] == ["vision", "reasoning"]
    assert payload["readiness_report"]["critical_failures"] == []
    assert payload["readiness_report"]["issue_codes"] == [
        "runtime.readiness.provider_missing.vision",
        "runtime.readiness.provider_missing.reasoning",
    ]
    assert len(payload["readiness_report"]["lane_checks"]) == 5
