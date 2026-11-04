from __future__ import annotations

import json
from typing import Any

import pytest

from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.upstream import UpstreamResponse

from .conftest import authorized


def test_named_mcp_initialization_routes_session_and_isolates_credentials(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    seen = []

    def send(**kw: Any) -> UpstreamResponse:
        seen.append(kw)
        assert kw["url"] == "http://127.0.0.1:1/mcp"
        assert kw["headers"]["Authorization"] == "Bearer " + "m" * 64
        assert "X-BlackFox-Agent-Token" not in kw["headers"]
        return UpstreamResponse(
            200,
            (("Mcp-Session-Id", "session-17"), ("Content-Type", "application/json")),
            b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}',
        )

    monkeypatch.setattr("ix_blackfox.integration_mesh.mcp.request_upstream", send)
    headers = {
        "X-BlackFox-Agent-Id": "engineering-agent",
        "X-BlackFox-Agent-Token": "a" * 64,
    }
    response = gateway.handle_mcp(
        payload=payload,
        headers=headers,
        raw_body=json.dumps(payload).encode(),
        connector_id="mcp-tools",
    )
    assert (
        response.status == 200
        and dict(response.headers)["Mcp-Session-Id"] == "session-17"
    )
    headers["X-BlackFox-Agent-Token"] = "wrong"
    assert (
        gateway.handle_mcp(
            payload=payload,
            headers=headers,
            raw_body=json.dumps(payload).encode(),
            connector_id="mcp-tools",
        ).status
        == 401
    )
    assert len(seen) == 1


@pytest.mark.parametrize("connector", ["service", "missing"])
def test_invalid_named_mcp_destination_refused(
    gateway: LiveAuthorityGateway, connector: str
) -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert (
        gateway.handle_mcp(
            payload=payload,
            headers={},
            raw_body=json.dumps(payload).encode(),
            connector_id=connector,
        ).status
        == 404
    )


def test_named_mcp_cannot_call_a_tool_on_another_connector(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway, protocol="mcp/2025-03-26")
    mcp = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": payload["tool_name"],
            "arguments": payload["arguments"],
            "_meta": {
                "io.ix-blackfox/agentId": payload["agent_id"],
                "io.ix-blackfox/evidenceRefs": payload["context"]["evidence_refs"],
            },
        },
    }
    headers["MCP-Protocol-Version"] = "2025-03-26"
    seen = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: seen.append(kw),
    )
    assert (
        gateway.handle_mcp(
            payload=mcp,
            headers=headers,
            raw_body=json.dumps(mcp).encode(),
            connector_id="mcp-tools",
        ).status
        == 403
    )
    assert not seen


def test_lifecycle_only_allows_discovery_and_rejects_header_injection(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {
        "X-BlackFox-Agent-Id": "engineering-agent",
        "X-BlackFox-Agent-Token": "a" * 64,
        "MCP-Protocol-Version": "2025-03-26",
    }
    seen = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.mcp.request_upstream",
        lambda **kw: seen.append(kw),
    )
    payload = {"jsonrpc": "2.0", "id": 1, "method": "resources/write", "params": {}}
    response = gateway.handle_mcp(
        payload=payload,
        headers=headers,
        raw_body=json.dumps(payload).encode(),
        connector_id="mcp-tools",
    )
    assert response.status == 403
    payload["method"] = "ping"
    headers["Mcp-Session-Id"] = "session\r\nAuthorization: secret"
    response = gateway.handle_mcp(
        payload=payload,
        headers=headers,
        raw_body=json.dumps(payload).encode(),
        connector_id="mcp-tools",
    )
    assert response.status == 400 and not seen
