from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config.loader import load_runtime_config


def test_load_runtime_config_defaults(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})

    assert config.app_name == "IX-BlackFox"
    assert config.environment == "development"
    assert config.log_level == "INFO"
    assert config.debug is False
    assert config.paths.root_dir == tmp_path.resolve()
    assert config.paths.state_dir == (tmp_path / ".blackfox").resolve()
    assert config.paths.runtime_dir == (tmp_path / "runtime").resolve()
    assert config.paths.artifacts_dir == (tmp_path / "artifacts").resolve()
    assert config.paths.logs_dir == (tmp_path / "logs").resolve()
    assert config.paths.temp_dir == (tmp_path / "tmp").resolve()


def test_load_runtime_config_env_overrides_file(tmp_path: Path) -> None:
    config_file = tmp_path / "blackfox.toml"
    config_file.write_text(
        """
[tool."ix-blackfox".runtime]
environment = "production"
log_level = "warning"
debug = false
state_dir = ".state-file"
        """.strip(),
        encoding="utf-8",
    )

    env = {
        "BLACKFOX_ENVIRONMENT": "test",
        "BLACKFOX_LOG_LEVEL": "debug",
        "BLACKFOX_DEBUG": "true",
        "BLACKFOX_STATE_DIR": ".state-env",
    }

    config = load_runtime_config(root_dir=tmp_path, env=env, config_file=config_file)

    assert config.environment == "test"
    assert config.log_level == "DEBUG"
    assert config.debug is True
    assert config.paths.state_dir == (tmp_path / ".state-env").resolve()


def test_load_runtime_config_creates_expected_directories(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})

    config.paths.ensure_exists()

    assert config.paths.state_dir.is_dir()
    assert config.paths.runtime_dir.is_dir()
    assert config.paths.artifacts_dir.is_dir()
    assert config.paths.logs_dir.is_dir()
    assert config.paths.temp_dir.is_dir()


@pytest.mark.parametrize(
    ("env", "expected_message"),
    [
        ({"BLACKFOX_ENVIRONMENT": "invalid"}, "Unsupported environment"),
        ({"BLACKFOX_LOG_LEVEL": "trace"}, "Unsupported log level"),
        ({"BLACKFOX_DEBUG": "maybe"}, "Cannot interpret boolean value"),
    ],
)
def test_invalid_config_values_raise(
    tmp_path: Path,
    env: dict[str, str],
    expected_message: str,
) -> None:
    with pytest.raises(ValueError, match=expected_message):
        load_runtime_config(root_dir=tmp_path, env=env)
