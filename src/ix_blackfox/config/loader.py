from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
import tomllib

from ix_blackfox.config.models import AppPaths, RuntimeConfig

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

    Parameters
    ----------
    root_dir:
        Optional explicit root directory.
    env:
        Optional environment mapping. Useful for tests.
    config_file:
        Optional TOML configuration file.

    Returns
    -------
    RuntimeConfig
        Normalized application configuration.
    """
    env_map = dict(env or {})
    file_values = _load_file_values(config_file)

    resolved_root = _resolve_root_dir(root_dir, env_map, file_values)
    paths = _build_paths(resolved_root, env_map, file_values)

    environment = _normalize_environment(
        _pick_value("environment", env_map, file_values, DEFAULT_ENVIRONMENT)
    )
    log_level = _normalize_log_level(
        _pick_value("log_level", env_map, file_values, DEFAULT_LOG_LEVEL)
    )
    debug = _parse_bool(_pick_value("debug", env_map, file_values, False))

    return RuntimeConfig(
        app_name=DEFAULT_APP_NAME,
        environment=environment,
        log_level=log_level,
        debug=debug,
        paths=paths,
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


def _load_file_values(config_file: Path | None) -> dict[str, Any]:
    if config_file is None:
        return {}

    data = tomllib.loads(config_file.read_text(encoding="utf-8"))
    return _extract_runtime_section(data)


def _extract_runtime_section(data: Mapping[str, Any]) -> dict[str, Any]:
    """
    Extract a runtime configuration section from TOML data.

    Supported locations:
    - [tool."ix-blackfox".runtime]
    - [tool.ix_blackfox.runtime]
    - [ix_blackfox.runtime]
    - ["ix-blackfox".runtime]
    """
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
