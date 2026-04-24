from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
)
from ix_blackfox.runtime import (
    BlackFoxRuntime,
    RuntimeDoctor,
    RuntimeReadinessStatus,
    runtime_doctor_main,
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


def test_runtime_doctor_inspect_reports_ready_runtime(tmp_path: Path) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._brain_providers = {  # noqa: SLF001
        "ollama": DummyHealthyProvider("ollama"),
        "vllm": DummyHealthyProvider("vllm"),
        "openai-compatible": DummyHealthyProvider("openai-compatible"),
    }

    report = RuntimeDoctor(runtime=runtime).inspect()

    assert report.readiness_report.status is RuntimeReadinessStatus.READY
    assert report.configured_providers == (
        "ollama",
        "openai-compatible",
        "vllm",
    )
    assert report.runtime_paths["root_dir"] == str(tmp_path.resolve())
    assert report.runtime_paths["artifacts_dir"].endswith("artifacts")
    assert report.recommendations == (
        "Runtime is fully ready. No corrective action is required.",
    )

    payload = report.to_dict()
    assert payload["readiness_report"]["status"] == "ready"
    assert payload["readiness_report"]["available_lane_count"] == 5
    assert payload["configured_providers"] == [
        "ollama",
        "openai-compatible",
        "vllm",
    ]


def test_runtime_doctor_cli_writes_json_and_returns_unavailable(tmp_path: Path) -> None:
    output_path = tmp_path / "doctor-report.json"

    exit_code = runtime_doctor_main(
        ["--root-dir", str(tmp_path), "--output", str(output_path)]
    )

    assert exit_code == 2
    assert output_path.exists() is True

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["readiness_report"]["status"] == "unavailable"
    assert payload["readiness_report"]["critical_failures"] == ["primary"]
    assert payload["recommendations"] == [
        "Configure provider 'ollama' for the 'primary' lane.",
        "Configure provider 'ollama' for the 'policy' lane.",
        "Configure provider 'ollama' for the 'safeguard' lane.",
        "Configure provider 'vllm' for the 'vision' lane.",
        "Configure provider 'openai-compatible' for the 'reasoning' lane.",
    ]
