from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ix_blackfox.integration_mesh.config import AuditSink, Connector, MeshConfig
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://localhost:9001",
        "http://127.0.0.1:9001",
        "https://name:password@example.com",
        "https://example.com?token=secret",
        "https://example.com/#fragment",
        "https://example.com/../other",
        "https://example.com/%2fother",
        "https://example.com/\\other",
        "https://example.com/space here",
        "//example.com",
        "file:///etc/passwd",
        "https://example.com:99999",
        "https://example.com:0",
    ],
)
def test_unsafe_destinations_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        Connector("connector", url)


def test_loopback_requires_explicit_literal_exception() -> None:
    assert Connector("test", "http://127.0.0.1:9001", allow_loopback_http=True)
    assert Connector("test", "http://[::1]:9001", allow_loopback_http=True)
    with pytest.raises(ValueError):
        Connector("test", "http://localhost:9001", allow_loopback_http=True)
    with pytest.raises(ValueError):
        Connector("test", "http://10.0.0.1:9001", allow_loopback_http=True)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "unknown"},
        {"credential_env": "bad env"},
        {"connector_id": "../escape"},
        {"auth_scheme": "Raw\r\nHost:x"},
        {"github_api_version": "\nsecret"},
        {"kind": "jira_issue"},
        {"allow_loopback_http": "true"},
    ],
)
def test_invalid_connector_contract(changes: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError)):
        Connector(
            **({"connector_id": "test", "base_url": "https://example.com"} | changes)
        )


def test_mesh_rejects_unsigned_unknown_or_mutable_routes(
    gateway: LiveAuthorityGateway,
) -> None:
    with pytest.raises(ValueError):
        replace(gateway.config, receipt_signing=None)
    with pytest.raises(ValueError):
        replace(
            gateway.config,
            routes=(replace(gateway.config.routes[0], connector_id="unknown"),),
        )
    with pytest.raises(ValueError):
        replace(
            gateway.config,
            routes=(replace(gateway.config.routes[0], repository_argument="repo"),),
        )
    with pytest.raises(ValueError):
        replace(
            gateway.config,
            routes=(
                replace(
                    gateway.config.routes[0], api_path="/repos/other/repo/check-runs"
                ),
            ),
        )


def test_config_unknown_fields_duplicate_ids_and_budgets(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        MeshConfig.parse({"unknown": True}, tmp_path)
    c = Connector("test", "https://example.com")
    with pytest.raises(ValueError):
        MeshConfig(tmp_path / "db", (c, c))
    with pytest.raises(ValueError):
        MeshConfig(tmp_path / "db", (c,), timeout_seconds=float("nan"))
    with pytest.raises(ValueError):
        AuditSink("sink", "https://example.com", max_attempts=0)


def test_readiness_rechecks_connector_credentials(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert gateway.status()["ready"] and gateway.status()["wave"] == 17
    monkeypatch.delenv("BLACKFOX_GITHUB_TOKEN")
    status = gateway.status()
    assert not status["ready"] and not status["mesh_credentials_ready"]


def test_example_routes_have_service_write_capability() -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_gateway_config(root / "examples/wave17/blackfox.gateway.toml")
    assert len(config.routes) == 4 and all(
        r.capability == "service_write" for r in config.routes
    )


@pytest.mark.parametrize("url", ["https://example.com?", "https://example.com#"])
def test_empty_url_delimiters_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        Connector("test", url)


def test_typed_timeouts_and_mcp_post_are_enforced(tmp_path: Path) -> None:
    for value in [True, "15"]:
        with pytest.raises(ValueError):
            MeshConfig.parse({"timeout_seconds": value}, tmp_path)
    with pytest.raises(ValueError):
        MeshConfig(tmp_path / "db", (), timeout_seconds=True)
    with pytest.raises(ValueError):
        Connector("mcp", "https://example.com/mcp", kind="mcp").validate_route(
            "", "PUT", "example/repo"
        )
