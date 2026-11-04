from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ix_blackfox.authority_crypto.encoding import canonical_bytes, strict_json
from ix_blackfox.integration_mesh.config import Connector
from ix_blackfox.live_gateway.upstream import UpstreamTransportError, request_upstream

if TYPE_CHECKING:
    from ix_blackfox.live_gateway.service import (
        GatewayHttpResponse,
        LiveAuthorityGateway,
    )

LIFECYCLE_METHODS = frozenset(
    {"initialize", "notifications/initialized", "ping", "tools/list"}
)


def transport_headers(
    headers: Mapping[str, str], names: tuple[str, ...] = ()
) -> dict[str, str]:
    result = {}
    for name in ("mcp-protocol-version", "mcp-session-id", *names):
        value = next((v for k, v in headers.items() if k.lower() == name.lower()), "")
        if value:
            if len(value) > 8192 or any(ord(c) < 32 or ord(c) >= 127 for c in value):
                raise ValueError("Invalid bounded MCP transport header.")
            result[name] = value
    return result


def lifecycle(
    gateway: LiveAuthorityGateway,
    connector: Connector,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
) -> GatewayHttpResponse:
    """Proxy allowlisted MCP lifecycle requests to one authenticated named server."""
    from ix_blackfox.live_gateway.service import GatewayHttpResponse, _json_response

    assert gateway.config.mesh is not None
    if payload.get("method") not in LIFECYCLE_METHODS:
        return _json_response(
            403,
            {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {
                    "code": -32601,
                    "message": "Named MCP lifecycle method is not permitted.",
                },
            },
        )
    try:
        gateway.validate_mesh_credentials((connector,))
        outbound = connector.headers()
    except ValueError:
        return _json_response(
            503, {"error": "Named MCP connector credential unavailable."}
        )
    try:
        outbound.update(transport_headers(headers))
    except ValueError:
        return _json_response(400, {"error": "Invalid MCP transport metadata."})
    sanitized = dict(payload)
    params = sanitized.get("params", {})
    if isinstance(params, Mapping):
        sanitized["params"] = {k: v for k, v in params.items() if k != "_meta"}
    try:
        response = request_upstream(
            url=connector.base_url,
            method="POST",
            headers=outbound,
            body=canonical_bytes(sanitized),
            timeout_seconds=gateway.config.mesh.timeout_seconds,
            max_response_bytes=gateway.config.server.max_response_bytes,
        )
    except UpstreamTransportError:
        return _json_response(502, {"error": "Named MCP lifecycle transport failed."})
    if response.body:
        try:
            reply = strict_json(response.body)
            if reply.get("jsonrpc") != "2.0" or reply.get("id") != payload.get("id"):
                raise ValueError("Mismatched JSON-RPC response.")
        except ValueError:
            return _json_response(
                502,
                {"error": "Named MCP server did not return a matching JSON response."},
            )
    selected_headers = tuple(
        (k, v)
        for k, v in response.headers
        if k.lower() in {"content-type", "mcp-session-id", "mcp-protocol-version"}
    )
    return GatewayHttpResponse(response.status, selected_headers, response.body)
