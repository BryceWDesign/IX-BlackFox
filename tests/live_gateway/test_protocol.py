from __future__ import annotations

import pytest

from ix_blackfox.live_gateway.protocol import McpProtocolError, validate_mcp_request


def _payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "filesystem.write_file",
            "arguments": {"path": "docs/a.txt"},
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
        },
    }


def test_modern_mcp_tool_call_requires_matching_method_and_name_headers() -> None:
    info = validate_mcp_request(
        _payload(),
        {
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "filesystem.write_file",
        },
    )
    assert info.modern is True
    assert info.name == "filesystem.write_file"


def test_modern_mcp_rejects_header_body_mismatch() -> None:
    with pytest.raises(McpProtocolError) as exc_info:
        validate_mcp_request(
            _payload(),
            {
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "other.tool",
            },
        )
    assert exc_info.value.code == -32020


def test_legacy_streamable_http_request_does_not_require_modern_routing_headers() -> None:
    info = validate_mcp_request(
        _payload(),
        {"MCP-Protocol-Version": "2025-11-25"},
    )
    assert info.modern is False
    assert info.protocol_version == "2025-11-25"


@pytest.mark.parametrize(
    ("method", "field", "value"),
    (("prompts/get", "name", "security-review"), ("resources/read", "uri", "file:///repo/README.md")),
)
def test_modern_mcp_name_bearing_methods_require_matching_name_header(
    method: str, field: str, value: str
) -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": method,
        "params": {
            field: value,
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
        },
    }
    info = validate_mcp_request(
        payload,
        {
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": method,
            "Mcp-Name": value,
        },
    )
    assert info.name == value

    with pytest.raises(McpProtocolError) as exc_info:
        validate_mcp_request(
            payload,
            {
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": method,
                "Mcp-Name": "different",
            },
        )
    assert exc_info.value.code == -32020


def test_modern_mcp_requires_protocol_version_body_header_binding() -> None:
    payload = _payload()
    params = payload["params"]
    assert isinstance(params, dict)
    params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}
    with pytest.raises(McpProtocolError, match="disagrees") as exc_info:
        validate_mcp_request(
            payload,
            {
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "filesystem.write_file",
            },
        )
    assert exc_info.value.code == -32020


def test_modern_mcp_accepts_base64_sentinel_name() -> None:
    info = validate_mcp_request(
        _payload(),
        {
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "=?base64?ZmlsZXN5c3RlbS53cml0ZV9maWxl?=",
        },
    )
    assert info.name == "filesystem.write_file"


def test_modern_mcp_removed_initialize_is_rejected() -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "initialize",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
    }
    with pytest.raises(McpProtocolError) as exc_info:
        validate_mcp_request(
            payload,
            {
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "initialize",
            },
        )
    assert exc_info.value.code == -32601
    assert exc_info.value.http_status == 404
