from pathlib import Path

import pytest

from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.wave15_demo import _wave15_config


def test_wave15_federated_config_requires_bound_registered_agent(tmp_path: Path) -> None:
    jwks = tmp_path / "jwks.json"
    jwks.write_text('{"keys": []}', encoding="utf-8")
    text = _wave15_config(9001, jwks).replace(
        'subject = "workload/coding-agent-07"\nagent_id = "coding-agent-07"',
        'subject = "workload/coding-agent-07"\nagent_id = "unknown-agent"',
        1,
    )
    path = tmp_path / "gateway.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="unregistered agents"):
        load_gateway_config(path)


def test_wave15_federated_required_does_not_require_static_agent_secret(tmp_path: Path) -> None:
    jwks = tmp_path / "jwks.json"
    jwks.write_text('{"keys": []}', encoding="utf-8")
    path = tmp_path / "gateway.toml"
    path.write_text(_wave15_config(9001, jwks), encoding="utf-8")
    config = load_gateway_config(path)
    assert config.identity_mode == "federated_required"
    assert config.identity_require_delegation is True
    assert config.agent_credentials == ()
    assert len(config.identity_providers) == 1
    assert len(config.identity_bindings) == 1
