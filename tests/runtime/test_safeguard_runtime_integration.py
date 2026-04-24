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


class ReviewingSafeguardProvider(BrainProvider):
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
                    "confidence": 0.84,
                    "uncertainty": 0.12,
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
                input_tokens=72,
                output_tokens=54,
            ),
            latency_ms=96,
            metadata={"backend": "integration-review-safeguard"},
        )


def test_runtime_integrates_safeguard_assessment_into_governance_and_report(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {"ollama": ReviewingSafeguardProvider()}  # noqa: SLF001

    report = runtime.run_prompt(
        prompt="Inspect the architecture and summarize the subsystem boundaries.",
        kind=TaskKind.ARCHITECTURE,
        labels=("architecture",),
    )

    assert report.status is RuntimeRunStatus.NEEDS_REVIEW
    assert report.pack_name is None
    assert report.safeguard_assessment is not None
    assert report.safeguard_assessment.advisory_disposition.value == "review"
    assert report.safeguard_assessment.finding_codes() == ("sensitive-boundary-review",)
    assert report.safeguard_assessment.policy_tags() == ("review", "sensitive-boundary")

    assert report.governance_preflight is not None
    assert report.governance_preflight.requires_review is True
    assert report.governance_preflight.safeguard_assessment is not None
    assert report.governance_preflight.risk.safety_merge is not None
    assert report.governance_preflight.risk.safety_merge.advisory_disposition.value == "review"
    assert report.governance_preflight.risk.safety_merge.forced_review is True
    assert report.governance_preflight.risk.safety_merge.finding_count == 1

    assert report.approval_resolution is not None
    assert report.approval_resolution.required is True
    assert report.approval_resolution.satisfied is False

    assert report.governance_receipts is not None
    assert report.governance_receipts.brain_receipt_count == 1
    assert report.governance_receipts.brain_receipts[0]["brain_name"] == "gpt-oss-safeguard-20b"
    assert report.governance_receipts.brain_receipts[0]["provider_name"] == "ollama"

    receipt_path = Path(report.artifact_paths["blackfox-governance-receipts.json"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_payload["brain_receipt_count"] == 1
    assert receipt_payload["brain_receipts"][0]["brain_name"] == "gpt-oss-safeguard-20b"

    report_path = Path(report.report_path)
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_payload["status"] == "needs_review"
    assert report_payload["pack_name"] is None
    assert report_payload["safeguard_assessment"] is not None
    assert report_payload["safeguard_assessment"]["advisory_disposition"] == "review"
    assert report_payload["safeguard_assessment"]["finding_codes"] == [
        "sensitive-boundary-review"
    ]
    assert report_payload["governance_preflight"]["safeguard_assessment"] is not None
    assert (
        report_payload["governance_preflight"]["safeguard_assessment"]["advisory_disposition"]
        == "review"
    )
