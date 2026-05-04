from __future__ import annotations

import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ix_blackfox.brains.budgets import (
    BrainContextBudget,
    BrainCostClass,
    BrainEscalationBudget,
    BrainInferenceBudget,
    BrainLatencyBudget,
    BrainLatencyClass,
)
from ix_blackfox.brains.contracts import (
    BrainCapability,
    BrainModality,
    BrainRole,
)
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.models import (
    BrainContextWindow,
    BrainExecutionLimits,
    BrainModalityProfile,
    BrainModelProfile,
)
from ix_blackfox.brains.profiles import BrainExecutionMode, BrainExecutionProfile
from ix_blackfox.config.models import (
    AppPaths,
    BrainDefaultRouting,
    BrainProviderConfig,
    BrainProviderKind,
    BrainRuntimeConfig,
    RuntimeConfig,
)

ENV_PREFIX = "BLACKFOX_"
DEFAULT_APP_NAME = "IX-BlackFox"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_LOG_LEVEL = "INFO"
VALID_ENVIRONMENTS = frozenset({"development", "test", "production"})
VALID_LOG_LEVELS = frozenset(
    {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
)


def load_runtime_config(
    *,
    root_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    config_file: Path | None = None,
) -> RuntimeConfig:
    """
    Load and normalize runtime configuration.

    Precedence is:
    1. Explicit function arguments
    2. Environment variables
    3. Optional TOML configuration file
    4. Built-in defaults
    """
    env_map = dict(env or {})
    file_data = _load_file_data(config_file)
    runtime_values = _extract_runtime_section(file_data)
    brain_values = _extract_brains_section(file_data)

    resolved_root = _resolve_root_dir(root_dir, env_map, runtime_values)
    paths = _build_paths(resolved_root, env_map, runtime_values)

    environment = _normalize_environment(
        _pick_value("environment", env_map, runtime_values, DEFAULT_ENVIRONMENT)
    )
    log_level = _normalize_log_level(
        _pick_value("log_level", env_map, runtime_values, DEFAULT_LOG_LEVEL)
    )
    debug = _parse_bool(_pick_value("debug", env_map, runtime_values, False))
    brains = _build_brain_runtime_config(env_map, brain_values)

    return RuntimeConfig(
        app_name=DEFAULT_APP_NAME,
        environment=environment,
        log_level=log_level,
        debug=debug,
        paths=paths,
        brains=brains,
        config_file=config_file,
    )


def _resolve_root_dir(
    root_dir: Path | None,
    env: Mapping[str, str],
    file_values: Mapping[str, Any],
) -> Path:
    if root_dir is not None:
        return root_dir.resolve()

    explicit_root = _pick_value("root_dir", env, file_values, None)
    if explicit_root is not None:
        return Path(str(explicit_root)).expanduser().resolve()

    return Path.cwd().resolve()


def _build_paths(
    root_dir: Path,
    env: Mapping[str, str],
    file_values: Mapping[str, Any],
) -> AppPaths:
    state_dir = _resolve_child_path(
        root_dir, _pick_value("state_dir", env, file_values, ".blackfox")
    )
    runtime_dir = _resolve_child_path(
        root_dir, _pick_value("runtime_dir", env, file_values, "runtime")
    )
    artifacts_dir = _resolve_child_path(
        root_dir, _pick_value("artifacts_dir", env, file_values, "artifacts")
    )
    logs_dir = _resolve_child_path(
        root_dir, _pick_value("logs_dir", env, file_values, "logs")
    )
    temp_dir = _resolve_child_path(
        root_dir, _pick_value("temp_dir", env, file_values, "tmp")
    )

    return AppPaths(
        root_dir=root_dir,
        state_dir=state_dir,
        runtime_dir=runtime_dir,
        artifacts_dir=artifacts_dir,
        logs_dir=logs_dir,
        temp_dir=temp_dir,
    )


def _build_brain_runtime_config(
    env: Mapping[str, str],
    brain_values: Mapping[str, Any],
) -> BrainRuntimeConfig:
    execution_values = _mapping_or_empty(brain_values.get("execution"))
    provider_values = _sequence_or_empty(brain_values.get("providers"))
    manifest_values = _sequence_or_empty(brain_values.get("manifests"))
    routing_values = _mapping_or_empty(brain_values.get("routing"))

    execution_profile = _build_execution_profile(env, execution_values)
    providers = _build_provider_configs(env, provider_values)
    manifests = _build_brain_manifests(manifest_values)
    routing = _build_default_routing(env, routing_values)

    return BrainRuntimeConfig(
        execution_profile=execution_profile,
        providers=providers,
        manifests=manifests,
        routing=routing,
    )


def _build_execution_profile(
    env: Mapping[str, str],
    execution_values: Mapping[str, Any],
) -> BrainExecutionProfile:
    mode = _parse_execution_mode(
        _pick_brain_value(
            "execution_mode",
            env,
            execution_values,
            execution_values.get("mode", BrainExecutionMode.LOCAL.value),
        )
    )
    profile_name = str(
        _pick_brain_value(
            "profile_name",
            env,
            execution_values,
            execution_values.get("profile_name", _default_profile_name(mode)),
        )
    )
    allow_streaming = _parse_bool(
        _pick_brain_value(
            "allow_streaming",
            env,
            execution_values,
            execution_values.get("allow_streaming", False),
        )
    )

    allowed_providers = _parse_identifier_sequence(
        _pick_brain_value(
            "allowed_providers",
            env,
            execution_values,
            execution_values.get("allowed_providers", ()),
        )
    )
    preferred_providers = _parse_identifier_sequence(
        _pick_brain_value(
            "preferred_providers",
            env,
            execution_values,
            execution_values.get("preferred_providers", ()),
        )
    )
    budget_values = _mapping_or_empty(execution_values.get("budget"))
    budget = _build_inference_budget(budget_values)

    if mode is BrainExecutionMode.LOCAL:
        return BrainExecutionProfile.local_first(
            profile_name=profile_name,
            budget=budget,
            allowed_providers=allowed_providers,
            preferred_providers=preferred_providers,
            allow_streaming=allow_streaming,
        )
    if mode is BrainExecutionMode.HYBRID:
        return BrainExecutionProfile.hybrid(
            profile_name=profile_name,
            budget=budget,
            allowed_providers=allowed_providers,
            preferred_providers=preferred_providers,
            allow_streaming=allow_streaming,
        )
    return BrainExecutionProfile.remote_only(
        profile_name=profile_name,
        budget=budget,
        allowed_providers=allowed_providers,
        preferred_providers=preferred_providers,
        allow_streaming=allow_streaming,
    )


def _build_inference_budget(budget_values: Mapping[str, Any]) -> BrainInferenceBudget:
    latency_values = _mapping_or_empty(budget_values.get("latency"))
    context_values = _mapping_or_empty(budget_values.get("context"))
    escalation_values = _mapping_or_empty(budget_values.get("escalation"))

    return BrainInferenceBudget(
        latency=BrainLatencyBudget(
            latency_class=_parse_latency_class(
                latency_values.get("latency_class", BrainLatencyClass.STANDARD.value)
            ),
            max_seconds=_optional_float(latency_values.get("max_seconds")),
            target_seconds=_optional_float(latency_values.get("target_seconds")),
        ),
        context=BrainContextBudget(
            max_input_tokens=_optional_int(context_values.get("max_input_tokens")),
            max_output_tokens=_optional_int(context_values.get("max_output_tokens")),
            reserve_output_tokens=int(context_values.get("reserve_output_tokens", 0)),
        ),
        escalation=BrainEscalationBudget(
            allow_reasoning_escalation=_parse_bool(
                escalation_values.get("allow_reasoning_escalation", True)
            ),
            allow_remote_escalation=_parse_bool(
                escalation_values.get("allow_remote_escalation", True)
            ),
            allow_multimodal_escalation=_parse_bool(
                escalation_values.get("allow_multimodal_escalation", True)
            ),
            max_escalation_hops=int(escalation_values.get("max_escalation_hops", 1)),
        ),
        max_cost_class=_parse_cost_class(
            budget_values.get("max_cost_class", BrainCostClass.HIGH.value)
        ),
        preferred_cost_class=_parse_cost_class(
            budget_values.get("preferred_cost_class", BrainCostClass.MEDIUM.value)
        ),
        metadata={
            str(key): str(value)
            for key, value in _mapping_or_empty(budget_values.get("metadata")).items()
        },
    )


def _build_provider_configs(
    env: Mapping[str, str],
    provider_values: tuple[Any, ...],
) -> tuple[BrainProviderConfig, ...]:
    configs: list[BrainProviderConfig] = []
    configured_names: set[str] = set()

    for raw in provider_values:
        if not isinstance(raw, Mapping):
            raise ValueError("Each brains.providers entry must be a table/object.")

        provider_name = _require_text(raw.get("provider_name"), label="provider_name")
        provider_kind = _parse_provider_kind(raw.get("provider_kind", provider_name))
        normalized_provider_name = _normalize_identifier(
            provider_name, label="provider_name"
        )
        configured_names.add(normalized_provider_name)

        env_base_url = _provider_base_url_from_env(env, provider_name, provider_kind)
        base_url = str(raw.get("base_url", env_base_url or "")).strip()
        configs.append(
            BrainProviderConfig(
                provider_name=provider_name,
                provider_kind=provider_kind,
                base_url=base_url,
                enabled=_parse_bool(raw.get("enabled", True)),
                api_key_env_var=_optional_text(raw.get("api_key_env_var")),
                default_timeout_seconds=float(raw.get("default_timeout_seconds", 60.0)),
                endpoint_path=_optional_text(raw.get("endpoint_path")),
                health_path=_optional_text(raw.get("health_path")),
                models_path=_optional_text(raw.get("models_path")),
                metadata={
                    str(key): str(value)
                    for key, value in _mapping_or_empty(raw.get("metadata")).items()
                },
            )
        )

    for inferred_name, inferred_kind in (
        ("ollama", BrainProviderKind.OLLAMA),
        ("vllm", BrainProviderKind.VLLM),
        ("openai-compatible", BrainProviderKind.OPENAI_COMPATIBLE),
    ):
        if inferred_name in configured_names:
            continue
        env_base_url = _provider_base_url_from_env(env, inferred_name, inferred_kind)
        if env_base_url is None:
            continue
        configs.append(
            BrainProviderConfig(
                provider_name=inferred_name,
                provider_kind=inferred_kind,
                base_url=env_base_url,
            )
        )

    return tuple(configs)


def _build_brain_manifests(
    manifest_values: tuple[Any, ...],
) -> tuple[BrainManifest, ...]:
    manifests: list[BrainManifest] = []

    for raw in manifest_values:
        if not isinstance(raw, Mapping):
            raise ValueError("Each brains.manifests entry must be a table/object.")

        brain_name = _require_text(raw.get("brain_name"), label="brain_name")
        provider_name = _require_text(raw.get("provider_name"), label="provider_name")
        model_name = _require_text(raw.get("model_name"), label="model_name")
        version = _require_text(raw.get("version", "0.1.0"), label="version")

        roles = tuple(
            _parse_brain_role(item) for item in _parse_sequence(raw.get("roles"))
        )
        capabilities = tuple(
            _parse_brain_capability(item)
            for item in _parse_sequence(raw.get("capabilities"))
        )
        input_modalities = tuple(
            _parse_brain_modality(item)
            for item in _parse_sequence(
                raw.get("input_modalities", (BrainModality.TEXT.value,))
            )
        )
        output_modalities = tuple(
            _parse_brain_modality(item)
            for item in _parse_sequence(
                raw.get("output_modalities", (BrainModality.TEXT.value,))
            )
        )

        manifests.append(
            BrainManifest(
                brain_name=brain_name,
                provider_name=provider_name,
                model_name=model_name,
                version=version,
                description=_optional_text(raw.get("description")) or "",
                labels=_parse_identifier_sequence(raw.get("labels", ())),
                preferred_packs=_parse_identifier_sequence(
                    raw.get("preferred_packs", ())
                ),
                is_default=_parse_bool(raw.get("is_default", False)),
                profile=BrainModelProfile(
                    brain_name=brain_name,
                    roles=roles,
                    capabilities=capabilities,
                    context_window=BrainContextWindow(
                        max_input_tokens=_require_int(
                            raw.get("max_input_tokens"), label="max_input_tokens"
                        ),
                        max_output_tokens=_require_int(
                            raw.get("max_output_tokens"), label="max_output_tokens"
                        ),
                    ),
                    modalities=BrainModalityProfile(
                        input_modalities=input_modalities,
                        output_modalities=output_modalities,
                        supports_streaming=_parse_bool(
                            raw.get("supports_streaming", False)
                        ),
                        supports_structured_output=_parse_bool(
                            raw.get("supports_structured_output", False)
                        ),
                        supports_tool_use=_parse_bool(
                            raw.get("supports_tool_use", False)
                        ),
                    ),
                    limits=BrainExecutionLimits(
                        max_concurrent_invocations=int(
                            raw.get("max_concurrent_invocations", 1)
                        ),
                        timeout_seconds=_optional_float(raw.get("timeout_seconds")),
                        max_tool_calls=_optional_int(raw.get("max_tool_calls")),
                    ),
                    description=_optional_text(raw.get("description")) or "",
                ),
            )
        )

    return tuple(manifests)


def _build_default_routing(
    env: Mapping[str, str],
    routing_values: Mapping[str, Any],
) -> BrainDefaultRouting:
    role_overrides_raw = _mapping_or_empty(routing_values.get("role_overrides"))
    pack_overrides_raw = _mapping_or_empty(routing_values.get("pack_overrides"))

    return BrainDefaultRouting(
        default_brain_name=_optional_text(
            _pick_brain_value(
                "default",
                env,
                routing_values,
                routing_values.get("default_brain_name"),
            )
        ),
        role_overrides={
            _parse_brain_role(role_name): str(brain_name)
            for role_name, brain_name in role_overrides_raw.items()
        },
        pack_overrides={
            str(pack_name): str(brain_name)
            for pack_name, brain_name in pack_overrides_raw.items()
        },
    )


def _resolve_child_path(root_dir: Path, raw_path: Any) -> Path:
    candidate = Path(str(raw_path)).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (root_dir / candidate).resolve()


def _pick_value(
    key: str,
    env: Mapping[str, str],
    file_values: Mapping[str, Any],
    default: Any,
) -> Any:
    env_key = f"{ENV_PREFIX}{key.upper()}"
    if env_key in env:
        return env[env_key]
    if key in file_values:
        return file_values[key]
    return default


def _pick_brain_value(
    key: str,
    env: Mapping[str, str],
    section_values: Mapping[str, Any],
    default: Any,
) -> Any:
    env_key = f"{ENV_PREFIX}BRAIN_{key.upper()}"
    if env_key in env:
        return env[env_key]
    if key in section_values:
        return section_values[key]
    return default


def _provider_base_url_from_env(
    env: Mapping[str, str],
    provider_name: str,
    provider_kind: BrainProviderKind,
) -> str | None:
    keys = [
        f"{ENV_PREFIX}{_normalize_env_token(provider_name)}_BASE_URL",
        f"{ENV_PREFIX}{_normalize_env_token(provider_kind.value)}_BASE_URL",
    ]
    for key in keys:
        value = env.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _normalize_environment(raw_value: Any) -> str:
    normalized = str(raw_value).strip().lower()
    if normalized not in VALID_ENVIRONMENTS:
        valid = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise ValueError(
            f"Unsupported environment '{raw_value}'. Expected one of: {valid}."
        )
    return normalized


def _normalize_log_level(raw_value: Any) -> str:
    normalized = str(raw_value).strip().upper()
    if normalized not in VALID_LOG_LEVELS:
        valid = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ValueError(
            f"Unsupported log level '{raw_value}'. Expected one of: {valid}."
        )
    return normalized


def _parse_bool(raw_value: Any) -> bool:
    if isinstance(raw_value, bool):
        return raw_value

    normalized = str(raw_value).strip().lower()
    truthy = {"1", "true", "yes", "on"}
    falsy = {"0", "false", "no", "off"}

    if normalized in truthy:
        return True
    if normalized in falsy:
        return False

    raise ValueError(f"Cannot interpret boolean value from: {raw_value!r}")


def _load_file_data(config_file: Path | None) -> dict[str, Any]:
    if config_file is None:
        return {}

    return tomllib.loads(config_file.read_text(encoding="utf-8"))


def _extract_runtime_section(data: Mapping[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []

    tool_section = data.get("tool")
    if isinstance(tool_section, Mapping):
        for tool_key in ("ix-blackfox", "ix_blackfox"):
            section = tool_section.get(tool_key)
            if isinstance(section, Mapping):
                runtime = section.get("runtime")
                if isinstance(runtime, Mapping):
                    candidates.append(dict(runtime))

    for root_key in ("ix-blackfox", "ix_blackfox"):
        section = data.get(root_key)
        if isinstance(section, Mapping):
            runtime = section.get("runtime")
            if isinstance(runtime, Mapping):
                candidates.append(dict(runtime))

    if not candidates:
        return {}

    return candidates[0]


def _extract_brains_section(data: Mapping[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []

    tool_section = data.get("tool")
    if isinstance(tool_section, Mapping):
        for tool_key in ("ix-blackfox", "ix_blackfox"):
            section = tool_section.get(tool_key)
            if isinstance(section, Mapping):
                brains = section.get("brains")
                if isinstance(brains, Mapping):
                    candidates.append(dict(brains))

    for root_key in ("ix-blackfox", "ix_blackfox"):
        section = data.get(root_key)
        if isinstance(section, Mapping):
            brains = section.get("brains")
            if isinstance(brains, Mapping):
                candidates.append(dict(brains))

    if not candidates:
        return {}

    return candidates[0]


def _mapping_or_empty(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _sequence_or_empty(value: Any) -> tuple[Any, ...]:
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, tuple):
        return value
    return ()


def _parse_sequence(value: Any) -> tuple[Any, ...]:
    if isinstance(value, list | tuple):
        return tuple(value)
    if value is None:
        return ()
    return (value,)


def _parse_identifier_sequence(value: Any) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    raw_items: tuple[Any, ...]
    if isinstance(value, str):
        raw_items = tuple(part for part in value.split(",") if part.strip())
    else:
        raw_items = _parse_sequence(value)

    for item in raw_items:
        cleaned = _normalize_identifier(str(item), label="identifier")
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _parse_execution_mode(raw_value: Any) -> BrainExecutionMode:
    normalized = str(raw_value).strip().lower().replace("-", "_")
    mapping = {
        BrainExecutionMode.LOCAL.value: BrainExecutionMode.LOCAL,
        BrainExecutionMode.HYBRID.value: BrainExecutionMode.HYBRID,
        BrainExecutionMode.REMOTE.value: BrainExecutionMode.REMOTE,
    }
    if normalized not in mapping:
        raise ValueError("Unsupported brain execution mode.")
    return mapping[normalized]


def _parse_latency_class(raw_value: Any) -> BrainLatencyClass:
    normalized = str(raw_value).strip().lower()
    mapping = {
        BrainLatencyClass.INTERACTIVE.value: BrainLatencyClass.INTERACTIVE,
        BrainLatencyClass.STANDARD.value: BrainLatencyClass.STANDARD,
        BrainLatencyClass.DEEP.value: BrainLatencyClass.DEEP,
    }
    if normalized not in mapping:
        raise ValueError("Unsupported brain latency class.")
    return mapping[normalized]


def _parse_cost_class(raw_value: Any) -> BrainCostClass:
    normalized = str(raw_value).strip().lower()
    mapping = {
        BrainCostClass.LOW.value: BrainCostClass.LOW,
        BrainCostClass.MEDIUM.value: BrainCostClass.MEDIUM,
        BrainCostClass.HIGH.value: BrainCostClass.HIGH,
    }
    if normalized not in mapping:
        raise ValueError("Unsupported brain cost class.")
    return mapping[normalized]


def _parse_provider_kind(raw_value: Any) -> BrainProviderKind:
    normalized = str(raw_value).strip().lower().replace("-", "_")
    mapping = {
        BrainProviderKind.OPENAI_COMPATIBLE.value: BrainProviderKind.OPENAI_COMPATIBLE,
        BrainProviderKind.OLLAMA.value: BrainProviderKind.OLLAMA,
        BrainProviderKind.VLLM.value: BrainProviderKind.VLLM,
        "openai-compatible": BrainProviderKind.OPENAI_COMPATIBLE,
        "openai_compatible": BrainProviderKind.OPENAI_COMPATIBLE,
    }
    if normalized not in mapping:
        raise ValueError("Unsupported brain provider kind.")
    return mapping[normalized]


def _parse_brain_role(raw_value: Any) -> BrainRole:
    normalized = str(raw_value).strip().lower()
    mapping = {role.value: role for role in BrainRole}
    if normalized not in mapping:
        raise ValueError("Unsupported brain role.")
    return mapping[normalized]


def _parse_brain_capability(raw_value: Any) -> BrainCapability:
    normalized = str(raw_value).strip().lower()
    mapping = {capability.value: capability for capability in BrainCapability}
    if normalized not in mapping:
        raise ValueError("Unsupported brain capability.")
    return mapping[normalized]


def _parse_brain_modality(raw_value: Any) -> BrainModality:
    normalized = str(raw_value).strip().lower()
    mapping = {modality.value: modality for modality in BrainModality}
    if normalized not in mapping:
        raise ValueError("Unsupported brain modality.")
    return mapping[normalized]


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _require_int(value: Any, *, label: str) -> int:
    if value is None:
        raise ValueError(f"{label} must not be empty.")
    return int(value)


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _require_text(value: Any, *, label: str) -> str:
    cleaned = _optional_text(value)
    if cleaned is None:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_env_token(value: str) -> str:
    return value.strip().upper().replace("-", "_").replace(" ", "_")


def _default_profile_name(mode: BrainExecutionMode) -> str:
    mapping = {
        BrainExecutionMode.LOCAL: "local-first",
        BrainExecutionMode.HYBRID: "hybrid",
        BrainExecutionMode.REMOTE: "remote-only",
    }
    return mapping[mode]
