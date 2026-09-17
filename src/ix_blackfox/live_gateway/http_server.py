from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import unquote

from ix_blackfox.live_gateway.service import GatewayHttpResponse, LiveAuthorityGateway


class BlackFoxGatewayHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], gateway: LiveAuthorityGateway) -> None:
        self.gateway = gateway
        super().__init__(server_address, BlackFoxGatewayRequestHandler)


class BlackFoxGatewayRequestHandler(BaseHTTPRequestHandler):
    """Minimal standard-library HTTP surface for the Wave 14 live gateway."""

    server_version = "IX-BlackFox-Wave14/0.2"
    protocol_version = "HTTP/1.1"

    @property
    def gateway(self) -> LiveAuthorityGateway:
        return cast(BlackFoxGatewayHttpServer, self.server).gateway

    def do_GET(self) -> None:  # noqa: N802
        duplicates = _duplicate_sensitive_headers(tuple(self.headers.items()))
        if duplicates:
            self._send_json(400, {"error": "duplicate security-sensitive headers are not accepted", "headers": list(duplicates)})
            return
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok", "wave": 14})
            return
        if self.path == "/readyz":
            payload = self.gateway.status()
            status = 200 if payload["ready"] else 503
            self._send_json(
                status,
                {
                    "status": "ready" if payload["ready"] else "not_ready",
                    "ready": bool(payload["ready"]),
                    "wave": 14,
                },
            )
            return
        if self.path == "/v1/status":
            if not self.gateway.operator_authorized(self._request_headers()):
                self._send_json(401, {"error": "operator authentication required"})
                return
            payload = self.gateway.status()
            status = 200 if payload["ready"] else 503
            self._send_json(status, payload)
            return
        if self.path == "/v1/receipts/verify":
            if not self.gateway.operator_authorized(self._request_headers()):
                self._send_json(401, {"error": "operator authentication required"})
                return
            self._send_json(200, self.gateway.receipt_store.verify_chain().to_dict())
            return
        prefix = "/v1/receipts/"
        if self.path.startswith(prefix):
            if not self.gateway.operator_authorized(self._request_headers()):
                self._send_json(401, {"error": "operator authentication required"})
                return
            receipt_id = unquote(self.path[len(prefix) :])
            receipt = self.gateway.receipt_store.get(receipt_id)
            if receipt is None:
                self._send_json(404, {"error": "receipt not found"})
            else:
                self._send_json(200, receipt)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        duplicates = _duplicate_sensitive_headers(tuple(self.headers.items()))
        if duplicates:
            self._send_json(400, {"error": "duplicate security-sensitive headers are not accepted", "headers": list(duplicates)})
            return
        if self.path == "/mcp":
            origin = self.headers.get("Origin")
            if origin is not None and not self.gateway.config.origin_allowed(origin):
                self._send_json(403, {"error": "MCP Origin is not allowed"})
                return
        try:
            raw = self._read_body()
        except RequestBodyError as exc:
            self._send_json(exc.status, {"error": str(exc)})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "request body must be valid UTF-8 JSON"})
            return
        if not isinstance(payload, Mapping):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return

        headers = self._request_headers()
        if self.path == "/mcp":
            response = self.gateway.handle_mcp(
                payload=payload,
                headers=headers,
                raw_body=raw,
            )
            self._send_gateway_response(response)
            return
        if self.path == "/v1/invoke":
            response = self.gateway.handle_api(payload=payload, headers=headers)
            self._send_gateway_response(response)
            return
        if self.path == "/v1/subject":
            self._handle_subject(payload)
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:
        # Keep gateway stdout deterministic for CI and operator JSON output.
        return

    def _handle_subject(self, payload: Mapping[str, Any]) -> None:
        agent_id = payload.get("agent_id")
        tool_name = payload.get("tool_name")
        arguments = payload.get("arguments", {})
        protocol = payload.get("protocol", "blackfox-api/v1")
        if not isinstance(agent_id, str) or not agent_id.strip():
            self._send_json(400, {"error": "agent_id is required"})
            return
        if not isinstance(tool_name, str) or not tool_name.strip():
            self._send_json(400, {"error": "tool_name is required"})
            return
        if not isinstance(arguments, Mapping):
            self._send_json(400, {"error": "arguments must be an object"})
            return
        if not isinstance(protocol, str) or not protocol.strip():
            self._send_json(400, {"error": "protocol must be a string"})
            return
        authenticated_agent, authentication_error = self.gateway.authenticate_agent(
            headers=self._request_headers(),
            claimed_agent_id=agent_id,
        )
        if authentication_error:
            self._send_json(401, {"error": authentication_error})
            return
        try:
            subject = self.gateway.build_subject(
                agent_id=authenticated_agent,
                tool_name=tool_name,
                arguments=arguments,
                protocol=protocol,
            )
        except (KeyError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, subject.to_dict())

    def _request_headers(self) -> dict[str, str]:
        return {key: value for key, value in self.headers.items()}

    def _read_body(self) -> bytes:
        content_lengths = tuple(self.headers.get_all("Content-Length") or ())
        transfer_encoding = self.headers.get("Transfer-Encoding") or ""
        length = _validated_content_length(
            content_length_values=content_lengths,
            transfer_encoding=transfer_encoding,
            max_request_bytes=self.gateway.config.server.max_request_bytes,
        )
        body = self.rfile.read(length)
        if len(body) != length:
            raise RequestBodyError(400, "request body ended before Content-Length bytes were received")
        return body

    def _send_gateway_response(self, response: GatewayHttpResponse) -> None:
        self.send_response(response.status)
        seen_content_type = False
        for key, value in response.headers:
            if key.lower() in {"content-length", "connection", "transfer-encoding"}:
                continue
            if key.lower() == "content-type":
                seen_content_type = True
            self.send_header(key, value)
        if not seen_content_type:
            self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response.body)

    def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = (json.dumps(dict(payload), sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class RequestBodyError(ValueError):
    """HTTP request-body framing error with an explicit response status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _duplicate_sensitive_headers(
    header_items: Sequence[tuple[str, str]],
) -> tuple[str, ...]:
    """Return duplicated singleton headers that affect gateway authority.

    Authentication, routing, origin, and MCP authority metadata are required to
    have exactly one interpretation. Rejecting duplicate values before they are
    collapsed into a mapping prevents ambiguous requests from being evaluated
    differently by clients, intermediaries, or the gateway.
    """

    counts: dict[str, int] = {}
    for raw_name, _value in header_items:
        name = raw_name.strip().lower()
        if not name:
            continue
        sensitive = (
            name in {"authorization", "origin", "host", "content-length", "transfer-encoding"}
            or name.startswith("x-blackfox-")
            or name.startswith("mcp-")
        )
        if sensitive:
            counts[name] = counts.get(name, 0) + 1
    return tuple(sorted(name for name, count in counts.items() if count > 1))


def _validated_content_length(
    *,
    content_length_values: Sequence[str],
    transfer_encoding: str,
    max_request_bytes: int,
) -> int:
    """Validate deterministic request framing before reading a gateway body.

    Wave 14 intentionally accepts fixed-length request bodies only. Rejecting
    Transfer-Encoding and ambiguous/multiple Content-Length fields prevents the
    gateway and any intermediary/upstream from disagreeing about body framing.
    """

    if transfer_encoding.strip():
        raise RequestBodyError(400, "Transfer-Encoding is not accepted by the Wave 14 gateway")
    if not content_length_values:
        raise RequestBodyError(411, "Content-Length is required")
    if len(content_length_values) != 1:
        raise RequestBodyError(400, "exactly one Content-Length header is required")
    value = content_length_values[0].strip()
    if not value or not value.isascii() or not value.isdecimal():
        raise RequestBodyError(400, "Content-Length must be a non-negative decimal integer")
    length = int(value, 10)
    if length > max_request_bytes:
        raise RequestBodyError(413, "request body exceeds configured size limit")
    return length


def serve_gateway(gateway: LiveAuthorityGateway) -> None:
    """Serve the configured Wave 14 gateway until interrupted.

    The public server entry point is fail-closed: it refuses to bind a network
    listener when configured credentials/evidence keys are missing or weak,
    credential material collides, or the durable receipt chain does not verify.
    """

    status = gateway.status()
    if not status["ready"]:
        raise RuntimeError(
            "Wave 14 gateway is not ready; run `blackfox gateway check` and "
            "resolve readiness failures before serving."
        )

    config = gateway.config.server
    server = BlackFoxGatewayHttpServer((config.host, config.port), gateway)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
