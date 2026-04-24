from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.brains.contracts import BrainCapability, BrainModality, BrainRole
from ix_blackfox.brains.profiles import BrainExecutionMode
from ix_blackfox.config.loader import load_runtime_config
from ix_blackfox.config.models import BrainProviderKind


def test_load_runtime_config_defaults_include_empty_brain_plane(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})

    assert config.brains.execution_profile.mode is BrainExecutionMode.LOCAL
    assert config.brains.execution_profile.profile_name == "local-first"
    assert config.brains.providers == ()
    assert config.brains.manifests == ()
    assert config.brains.routing.default_brain_name is None


def test_load_runtime_config_parses_brain_sections_from_toml(tmp_path: Path) -> None:
    config_file = tmp_path / "blackfox.toml"
    config_file.write_text(
        """
[tool."ix-blackfox".brains.execution]
mode = "hybrid"
profile_name = "Lab Hybrid"
allow_streaming = true
allowed_providers = ["ollama", "vllm"]
preferred_providers = ["vllm"]

[tool."ix-blackfox".brains.execution.budget.latency]
latency_class = "interactive"
max_seconds = 9.5
target_seconds = 4.0

[tool."ix-blackfox".brains.execution.budget.context]
max_input_tokens = 24576
max_output_tokens = 4096
reserve_output_tokens = 256

[tool."ix-blackfox".brains.execution.budget.escalation]
allow_reasoning_escalation = true
allow_remote_escalation = true
allow_multimodal_escalation = true
max_escalation_hops = 2

[tool."ix-blackfox".brains.execution.budget]
max_cost_class = "high"
preferred_cost_class = "medium"

[[tool."ix-blackfox".brains.providers]]
provider_name = "ollama"
provider_kind = "ollama"
base_url = "http://localhost:11434"
enabled = true
default_timeout_seconds = 45.0
health_path = "/api/tags"
endpoint_path = "/api/chat"

[[tool."ix-blackfox".brains.providers]]
provider_name = "vllm"
provider_kind = "vllm"
base_url = "http://localhost:8000"
enabled = true
default_timeout_seconds = 60.0
health_path = "/health"
endpoint_path = "/v1/chat/completions"
models_path = "/v1/models"

[[tool."ix-blackfox".brains.manifests]]
brain_name = "gpt-oss-20b"
provider_name = "ollama"
model_name = "gpt-oss:20b"
version = "0.1.0"
description = "Primary local reasoning brain."
roles = ["primary", "reasoning"]
capabilities = ["text_generation", "code_generation"]
input_modalities = ["text"]
output_modalities = ["text"]
preferred_packs = ["programming"]
labels = ["local", "primary"]
is_default = true
max_input_tokens = 32768
max_output_tokens = 4096
supports_streaming = true
max_concurrent_invocations = 2
timeout_seconds = 45.0
max_tool_calls = 4

[[tool."ix-blackfox".brains.manifests]]
brain_name = "qwen-vision"
provider_name = "vllm"
model_name = "qwen2.5-vl:7b"
version = "0.1.0"
description = "Vision specialist."
roles = ["multimodal"]
capabilities = ["vision_analysis", "structured_output"]
input_modalities = ["text", "image"]
output_modalities = ["text", "json"]
preferred_packs = ["architecture"]
labels = ["vision"]
max_input_tokens = 65536
max_output_tokens = 4096
supports_structured_output = true

[tool."ix-blackfox".brains.routing]
default_brain_name = "gpt-oss-20b"
role_overrides = { safety = "gpt-oss-20b", multimodal = "qwen-vision" }
pack_overrides = { architecture = "qwen-vision" }
        """.strip(),
        encoding="utf-8",
    )

    config = load_runtime_config(root_dir=tmp_path, env={}, config_file=config_file)

    assert config.brains.execution_profile.mode is BrainExecutionMode.HYBRID
    assert config.brains.execution_profile.profile_name == "lab-hybrid"
    assert config.brains.execution_profile.allow_remote is True
    assert config.brains.execution_profile.allow_local is True
    assert config.brains.execution_profile.allow_streaming is True
    assert config.brains.execution_profile.allowed_providers == ("ollama", "vllm")
    assert config.brains.execution_profile.preferred_providers == ("vllm",)
    assert config.brains.execution_profile.budget.latency.max_seconds == 9.5
    assert config.brains.execution_profile.budget.context.effective_output_budget == 3840
    assert config.brains.execution_profile.budget.escalation.max_escalation_hops == 2

    assert len(config.brains.providers) == 2
    assert config.brains.providers[0].provider_kind is BrainProviderKind.OLLAMA
    assert config.brains.providers[1].models_path == "/v1/models"

    assert len(config.brains.manifests) == 2
    primary = config.brains.get_manifest("gpt-oss-20b")
    vision = config.brains.get_manifest("qwen vision")
    assert primary is not None
    assert primary.supports_role(BrainRole.PRIMARY) is True
    assert primary.declares_capability(BrainCapability.CODE_GENERATION) is True
    assert primary.profile.modalities.supports_streaming is True
    assert primary.profile.limits.max_tool_calls == 4

    assert vision is not None
    assert vision.accepts_modality(BrainModality.IMAGE) is True
    assert vision.profile.modalities.supports_structured_output is True
    assert config.brains.routing.default_brain_name == "gpt-oss-20b"
    assert config.brains.routing.brain_for_role(BrainRole.MULTIMODAL) == "qwen-vision"
    assert config.brains.routing.brain_for_pack("architecture") == "qwen-vision"


def test_load_runtime_config_allows_env_overrides_for_brain_profile_and_provider_urls(
    tmp_path: Path,
) -> None:
    env = {
        "BLACKFOX_BRAIN_EXECUTION_MODE": "remote",
        "BLACKFOX_BRAIN_PROFILE_NAME": "Remote Ops",
        "BLACKFOX_BRAIN_ALLOWED_PROVIDERS": "openai-compatible,vllm",
        "BLACKFOX_BRAIN_PREFERRED_PROVIDERS": "vllm",
        "BLACKFOX_BRAIN_ALLOW_STREAMING": "true",
        "BLACKFOX_OLLAMA_BASE_URL": "http://localhost:11434",
        "BLACKFOX_VLLM_BASE_URL": "http://localhost:8000",
    }

    config = load_runtime_config(root_dir=tmp_path, env=env)

    assert config.brains.execution_profile.mode is BrainExecutionMode.REMOTE
    assert config.brains.execution_profile.profile_name == "remote-ops"
    assert config.brains.execution_profile.allow_local is False
    assert config.brains.execution_profile.allow_remote is True
    assert config.brains.execution_profile.allow_streaming is True
    assert config.brains.execution_profile.allowed_providers == (
        "openai-compatible",
        "vllm",
    )
    assert config.brains.execution_profile.preferred_providers == ("vllm",)
    assert tuple(provider.provider_name for provider in config.brains.providers) == (
        "ollama",
        "vllm",
    )


@pytest.mark.parametrize(
    ("toml_text", "message"),
    [
        (
            """
[[tool."ix-blackfox".brains.providers]]
provider_name = "ollama"
provider_kind = "invalid-kind"
base_url = "http://localhost:11434"
            """.strip(),
            "Unsupported brain provider kind",
        ),
        (
            """
[[tool."ix-blackfox".brains.manifests]]
brain_name = "gpt-oss-20b"
provider_name = "missing-provider"
model_name = "gpt-oss:20b"
version = "0.1.0"
roles = ["primary"]
capabilities = ["text_generation"]
max_input_tokens = 32768
max_output_tokens = 4096
            """.strip(),
            "reference a configured provider",
        ),
        (
            """
[[tool."ix-blackfox".brains.providers]]
provider_name = "ollama"
provider_kind = "ollama"
base_url = "http://localhost:11434"

[[tool."ix-blackfox".brains.manifests]]
brain_name = "gpt-oss-20b"
provider_name = "ollama"
model_name = "gpt-oss:20b"
version = "0.1.0"
roles = ["primary"]
capabilities = ["text_generation"]
max_input_tokens = 32768
max_output_tokens = 4096

[tool."ix-blackfox".brains.routing]
default_brain_name = "missing-brain"
            """.strip(),
            "default_brain_name must reference a configured brain manifest",
        ),
    ],
)
def test_invalid_brain_config_values_raise(
    tmp_path: Path,
    toml_text: str,
    message: str,
) -> None:
    config_file = tmp_path / "blackfox.toml"
    config_file.write_text(toml_text, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_runtime_config(root_dir=tmp_path, env={}, config_file=config_file)
