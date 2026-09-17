from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.live_gateway.config import load_gateway_config


def _example_path() -> Path:
    return Path(__file__).resolve().parents[2] / "examples" / "wave14" / "blackfox.gateway.toml"


def test_example_wave14_config_loads_real_route_and_bounded_agent() -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_gateway_config(root / "examples" / "wave14" / "blackfox.gateway.toml")

    assert config.mcp is not None
    assert config.api is not None
    assert config.agent_credentials[0].agent_id == "coding-agent-07"
    assert config.agent_credentials[0].secret_env == "BLACKFOX_WAVE14_AGENT_TOKEN"
    assert config.server.operator_token_env == "BLACKFOX_WAVE14_OPERATOR_TOKEN"
    assert config.server.allowed_origins == ()
    assert config.mcp.passthrough_methods == (
        "initialize",
        "notifications/initialized",
        "ping",
        "server/discover",
        "tools/list",
    )
    assert config.trusted_issuers[0].allowed_kinds == ("test_result",)
    assert config.trusted_issuers[1].allowed_kinds == ("human_approval",)
    policy = config.evidence_policy_for("protected-write")
    assert policy is not None
    assert policy.single_use_kinds == ("human_approval",)
    assert config.route_for("filesystem.write_file") is not None
    agent = config.agent_registry.require("coding-agent-07")
    assert agent.active is True
    grant = agent.grants_for(next(iter(agent.capabilities)))[0]
    assert grant.scope.requires_human_review is True
    assert grant.scope.path_roots == ("docs",)


def test_gateway_config_requires_at_least_one_live_upstream(tmp_path: Path) -> None:
    source = _example_path().read_text(encoding="utf-8")
    source = source.replace(
        '[mcp]\nupstream_url = "http://127.0.0.1:9001/mcp"\npassthrough_methods = ["initialize", "notifications/initialized", "ping", "server/discover", "tools/list"]\n\n',
        "",
    ).replace(
        '[api]\nbase_url = "http://127.0.0.1:9001"\n\n',
        "",
    )
    target = tmp_path / "gateway.toml"
    target.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="at least one live MCP or API upstream"):
        load_gateway_config(target)


def test_gateway_config_rejects_non_table_mcp_and_api(tmp_path: Path) -> None:
    source = _example_path().read_text(encoding="utf-8")
    mcp_section = (
        '[mcp]\n'
        'upstream_url = "http://127.0.0.1:9001/mcp"\n'
        'passthrough_methods = ["initialize", "notifications/initialized", "ping", "server/discover", "tools/list"]\n\n'
    )
    api_section = '[api]\nbase_url = "http://127.0.0.1:9001"\n\n'

    bad_mcp = 'mcp = "not-a-table"\n' + source.replace(mcp_section, "")
    target = tmp_path / "bad-mcp.toml"
    target.write_text(bad_mcp, encoding="utf-8")
    with pytest.raises(ValueError, match="mcp must be a TOML table"):
        load_gateway_config(target)

    bad_api = 'api = "not-a-table"\n' + source.replace(api_section, "")
    target = tmp_path / "bad-api.toml"
    target.write_text(bad_api, encoding="utf-8")
    with pytest.raises(ValueError, match="api must be a TOML table"):
        load_gateway_config(target)


def test_gateway_config_rejects_ambiguous_security_boolean_strings(tmp_path: Path) -> None:
    source = _example_path().read_text(encoding="utf-8")
    target = tmp_path / "bad-bool.toml"
    target.write_text(
        source.replace("require_signature = true", 'require_signature = "false"'),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="require_signature must be a TOML boolean"):
        load_gateway_config(target)


def test_gateway_config_rejects_api_route_traversal_and_encoded_paths(tmp_path: Path) -> None:
    source = _example_path().read_text(encoding="utf-8")
    traversal = tmp_path / "traversal.toml"
    traversal.write_text(
        source.replace('api_path = "/tools/write"', 'api_path = "/tools/../admin"'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dot path segments"):
        load_gateway_config(traversal)

    encoded = tmp_path / "encoded.toml"
    encoded.write_text(
        source.replace('api_path = "/tools/write"', 'api_path = "/tools/%2e%2e/admin"'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="percent encoding"):
        load_gateway_config(encoded)


def test_gateway_config_rejects_api_base_query_or_fragment(tmp_path: Path) -> None:
    source = _example_path().read_text(encoding="utf-8")
    target = tmp_path / "bad-api-base.toml"
    target.write_text(
        source.replace(
            'base_url = "http://127.0.0.1:9001"',
            'base_url = "http://127.0.0.1:9001/base?token=inline"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="api.base_url must not contain"):
        load_gateway_config(target)
