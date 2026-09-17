from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MCP_MODERN_VERSION = "2026-07-28"
MCP_LEGACY_VERSIONS = frozenset({"2025-11-25", "2025-06-18", "2025-03-26"})
_MCP_NAME_FIELDS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}
_MCP_PROTOCOL_META_KEY = "io.modelcontextprotocol/protocolVersion"
_MCP_MODERN_REMOVED_METHODS = frozenset({"initialize", "notifications/initialized"})
_BASE64_PREFIX = "=?base64?"
_BASE64_SUFFIX = "?="


class McpProtocolError(Exception):
    """Typed MCP protocol failure that remains a normal mutable exception.

    Exception tracebacks are mutable runtime state; using a frozen/slotted dataclass
    for an Exception breaks traceback propagation on Python 3.13.
    """

    def __init__(self, code: int, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class McpRequestInfo:
    method: str
    name: str
    protocol_version: str
    request_id: Any
    modern: bool


def validate_mcp_request(
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
) -> McpRequestInfo:
    """Validate the transport/body bindings that BlackFox relies on for MCP policy.

    The 2026-07-28 Streamable HTTP profile makes requests self-describing and
    requires method/name/protocol metadata to agree across headers and the JSON-RPC
    body. BlackFox rejects disagreement before any authority evaluation or upstream
    network call so routing metadata cannot be spoofed independently from the body.
    """

    if payload.get("jsonrpc") != "2.0":
        raise McpProtocolError(-32600, "JSON-RPC version must be 2.0.")
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise McpProtocolError(-32600, "JSON-RPC method is required.")

    params = payload.get("params", {})
    if not isinstance(params, Mapping):
        raise McpProtocolError(-32602, "JSON-RPC params must be an object.")

    header_version = _header(headers, "MCP-Protocol-Version")
    if header_version and header_version not in MCP_LEGACY_VERSIONS | {MCP_MODERN_VERSION}:
        raise McpProtocolError(
            -32022,
            f"Unsupported MCP protocol version: {header_version}.",
        )
    modern = header_version == MCP_MODERN_VERSION
    protocol_version = header_version or "2025-03-26"

    name = ""
    name_field = _MCP_NAME_FIELDS.get(method)
    if name_field:
        raw_name = params.get(name_field)
        if isinstance(raw_name, str):
            name = raw_name

    if modern:
        metadata = params.get("_meta", {})
        if not isinstance(metadata, Mapping):
            raise McpProtocolError(
                -32020,
                "Modern MCP params._meta must be an object containing protocol metadata.",
            )
        body_version = metadata.get(_MCP_PROTOCOL_META_KEY)
        if body_version != MCP_MODERN_VERSION:
            raise McpProtocolError(
                -32020,
                "MCP-Protocol-Version header is missing from or disagrees with params._meta.",
            )

        if method in _MCP_MODERN_REMOVED_METHODS:
            raise McpProtocolError(
                -32601,
                f"MCP method {method!r} is not defined by the stateless 2026-07-28 profile.",
                http_status=404,
            )

        method_header = _header(headers, "Mcp-Method")
        if not method_header or method_header != method:
            raise McpProtocolError(
                -32020,
                "Mcp-Method header is missing or disagrees with the JSON-RPC body.",
            )
        if name_field:
            present, raw_name_header = _header_value(headers, "Mcp-Name")
            if not present:
                raise McpProtocolError(
                    -32020,
                    "Mcp-Name header is missing or disagrees with the JSON-RPC body.",
                )
            decoded_name = decode_mcp_header_value(raw_name_header, label="Mcp-Name")
            if not name or decoded_name != name:
                raise McpProtocolError(
                    -32020,
                    "Mcp-Name header is missing or disagrees with the JSON-RPC body.",
                )

    return McpRequestInfo(
        method=method,
        name=name,
        protocol_version=protocol_version,
        request_id=payload.get("id"),
        modern=modern,
    )


def decode_mcp_header_value(value: str, *, label: str) -> str:
    """Decode one MCP header value using the 2026-07-28 sentinel rules.

    Plain values must be safe HTTP field-value text. Values wrapped with the exact
    ``=?base64?...?=`` sentinel are strictly base64-decoded and then UTF-8-decoded.
    """

    if value.startswith(_BASE64_PREFIX) and value.endswith(_BASE64_SUFFIX):
        encoded = value[len(_BASE64_PREFIX) : -len(_BASE64_SUFFIX)]
        try:
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
            return raw.decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error, ValueError) as exc:
            raise McpProtocolError(
                -32020,
                f"{label} contains malformed MCP base64 sentinel encoding.",
            ) from exc

    for character in value:
        codepoint = ord(character)
        if character == "\t":
            continue
        if codepoint < 0x20 or codepoint > 0x7E:
            raise McpProtocolError(
                -32020,
                f"{label} contains characters that are not valid in an MCP HTTP header value.",
            )
    return value


def jsonrpc_error(
    request_id: Any,
    *,
    code: int,
    message: str,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _header(headers: Mapping[str, str], name: str) -> str:
    present, value = _header_value(headers, name)
    return value.strip() if present else ""


def _header_value(headers: Mapping[str, str], name: str) -> tuple[bool, str]:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return True, value
    return False, ""
