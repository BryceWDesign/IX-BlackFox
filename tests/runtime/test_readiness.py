from __future__ import annotations

from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
)
from ix_blackfox.runtime import (
    RuntimeReadinessInspector,
    RuntimeReadinessStatus,
)


class DummyHealthyProvider(BrainProvider):
    def __init__(self, provider_name: str) -> None:
        super().__init__(provider_name=provider_name)

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            message="healthy",
            latency_ms=12,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        raise NotImplementedError


class DummyUnhealthyProvider(BrainProvider):
    def __init__(self, provider_name: str) -> None:
        super().__init__(provider_name=provider_name)

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=False,
            message="backend unavailable",
            latency_ms=None,
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        raise NotImplementedError


def test_readiness_report_is_ready_when_all_expected_lanes_are_available() -> None:
    inspector = RuntimeReadinessInspector()

    report = inspector.inspect(
        providers={
            "ollama": DummyHealthyProvider("ollama"),
            "vllm": DummyHealthyProvider("vllm"),
            "openai-compatible": DummyHealthyProvider("openai-compatible"),
        }
    )

    assert report.status is RuntimeReadinessStatus.READY
    assert report.available_lane_count == 5
    assert report.total_lane_count == 5
    assert report.unavailable_lanes() == ()
    assert report.critical_failures() == ()
    assert report.issue_codes == ()
    assert report.summary() == "Runtime ready: 5/5 brain lanes available."


def test_readiness_report_is_degraded_when_noncritical_lanes_are_missing() -> None:
    inspector = RuntimeReadinessInspector()

    report = inspector.inspect(
        providers={
            "ollama": DummyHealthyProvider("ollama"),
        }
    )

    assert report.status is RuntimeReadinessStatus.DEGRADED
    assert report.available_lane_count == 3
    assert report.total_lane_count == 5
    assert report.unavailable_lanes() == ("vision", "reasoning")
    assert report.critical_failures() == ()
    assert report.issue_codes == (
        "runtime.readiness.provider_missing.vision",
        "runtime.readiness.provider_missing.reasoning",
    )
    assert report.summary() == "Runtime degraded: unavailable lanes -> vision, reasoning."


def test_readiness_report_is_unavailable_when_primary_lane_is_unhealthy() -> None:
    inspector = RuntimeReadinessInspector()

    report = inspector.inspect(
        providers={
            "ollama": DummyUnhealthyProvider("ollama"),
            "vllm": DummyHealthyProvider("vllm"),
            "openai-compatible": DummyHealthyProvider("openai-compatible"),
        }
    )

    assert report.status is RuntimeReadinessStatus.UNAVAILABLE
    assert report.available_lane_count == 2
    assert report.total_lane_count == 5
    assert report.unavailable_lanes() == ("primary", "policy", "safeguard")
    assert report.critical_failures() == ("primary",)
    assert report.issue_codes == (
        "runtime.readiness.provider_unhealthy.primary",
        "runtime.readiness.provider_unhealthy.policy",
        "runtime.readiness.provider_unhealthy.safeguard",
    )
    assert report.summary() == "Runtime unavailable: critical lane failure in primary."
