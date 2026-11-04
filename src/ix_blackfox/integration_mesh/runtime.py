from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    digest,
    strict_json,
)
from ix_blackfox.authority_crypto.verification import verify_receipt
from ix_blackfox.integration_mesh.ledger import MeshLedger
from ix_blackfox.integration_mesh.mcp import transport_headers
from ix_blackfox.live_gateway.upstream import UpstreamTransportError, request_upstream

if TYPE_CHECKING:
    from ix_blackfox.live_gateway.service import (
        GatewayHttpResponse,
        LiveAuthorityGateway,
        PreparedAuthorityRequest,
    )


def dispatch(
    gateway: LiveAuthorityGateway,
    prepared: PreparedAuthorityRequest,
    arguments: Mapping[str, Any],
    headers: Mapping[str, str],
    mcp_payload: Mapping[str, Any] | None = None,
) -> GatewayHttpResponse:
    """Execute a mesh route only through the existing authority and signing gates."""
    from ix_blackfox.live_gateway.service import (
        GatewayHttpResponse,
        ReceiptWriteError,
        _json_response,
    )

    config = gateway.config.mesh
    assert config is not None
    connector = config.connector(prepared.route.connector_id)
    key = next(
        (v for k, v in headers.items() if k.lower() == "x-blackfox-idempotency-key"), ""
    )

    request_id = ""

    def error(
        status: int, message: str, state: str = "not_attempted"
    ) -> GatewayHttpResponse:
        body: dict[str, Any] = {
            "error": message,
            "execution_state": state,
            "retry_safe": False,
        }
        if state == "not_attempted" and gateway.receipt_store.signing is not None:
            denial = gateway._append_preexecution_failure(
                agent_id=prepared.subject.agent_id,
                tool_name=prepared.route.tool_name,
                protocol=prepared.subject.protocol,
                reason=message,
                reason_code="mesh_dispatch_blocked",
            )
            body["receipt_id"] = denial["receipt_id"]
        if request_id:
            body["request_id"] = request_id
        if mcp_payload is not None:
            body = {
                "jsonrpc": "2.0",
                "id": mcp_payload.get("id"),
                "error": {"code": -32057, "message": message, "data": body},
            }
        return _json_response(status, body)

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", key):
        return error(
            400, "A bounded X-BlackFox-Idempotency-Key is required for mesh commands."
        )
    if gateway.receipt_store.signing is None:
        return error(503, "Mesh commands require signed authority receipts.")
    if (connector.kind == "mcp") != (mcp_payload is not None):
        return error(400, "Connector transport does not match the request protocol.")
    arguments = strict_json(canonical_bytes(dict(arguments)))
    body = dict(arguments) if mcp_payload is not None else arguments.get("payload")
    if not isinstance(body, dict):
        return error(400, "HTTP mesh arguments require a payload object.")
    try:
        connector.validate_body(body, prepared.subject.revision)
    except ValueError:
        return error(400, "Connector payload failed validation.")
    try:
        outbound = connector.headers()
        gateway.validate_mesh_credentials((connector,))
    except ValueError:
        return error(503, "Connector credentials failed validation.")
    if mcp_payload is not None:
        try:
            outbound.update(
                transport_headers(
                    headers,
                    tuple(
                        binding.full_header_name
                        for binding in prepared.route.mcp_header_bindings
                    ),
                )
            )
        except ValueError:
            return error(400, "Invalid MCP transport metadata.")
    request_id = digest(
        {
            "agent_id": prepared.subject.agent_id,
            "connector_id": connector.connector_id,
            "tool_name": prepared.route.tool_name,
            "key": key,
        }
    )
    ledger = MeshLedger(config.database)
    state, cached = ledger.reserve(request_id, prepared.subject.digest)
    if state == "conflict":
        return error(
            409, "Request key was already bound to a different authority subject."
        )
    if state == "reserved":
        return error(
            409,
            "Request is reserved; reconcile its signed receipts before further action.",
            "outcome_unknown",
        )

    def response_for(
        receipt: dict[str, Any], raw_upstream: bytes, replay: bool = False
    ) -> GatewayHttpResponse:
        assert gateway.receipt_store.signing is not None
        signed = verify_receipt(receipt, gateway.receipt_store.signing.current_policy())
        if (
            signed["record_type"] != "outcome"
            or signed["execution_state"] != "response_received"
            or signed["subject"]["digest"] != prepared.subject.digest
            or signed["upstream_response_sha256"]
            != (hashlib.sha256(raw_upstream).hexdigest() if raw_upstream else "")
        ):
            raise AuthorityProofError("Cached result differs from signed outcome.")
        response_headers = [
            ("Content-Type", "application/json"),
            ("X-BlackFox-Receipt-Id", str(signed["receipt_id"])),
            ("X-BlackFox-Request-Id", request_id),
        ]
        if replay:
            response_headers.append(("X-BlackFox-Replayed", "true"))
        if mcp_payload is not None:
            result = strict_json(raw_upstream)
            if result.get("jsonrpc") != "2.0" or ("result" in result) == (
                "error" in result
            ):
                raise ValueError("Invalid MCP JSON-RPC result.")
            if not replay and result.get("id") != mcp_payload.get("id"):
                raise ValueError("Mismatched MCP response id.")
            result["id"] = mcp_payload.get("id")
        else:
            try:
                content = json.loads(raw_upstream)
                canonical_bytes(content)
            except (ValueError, UnicodeError):
                content = {"body_base64": base64.b64encode(raw_upstream).decode()}
            result = {
                "status": "upstream_response_received",
                "execution_state": "response_received",
                "request_id": request_id,
                "receipt_id": signed["receipt_id"],
                "authorization_receipt_id": signed["authorization_receipt_id"],
                "subject_digest": prepared.subject.digest,
                "upstream_status": signed["upstream_status"],
                "result": content,
            }
        return GatewayHttpResponse(
            200
            if mcp_payload is None and signed["upstream_status"] == 204
            else signed["upstream_status"],
            tuple(response_headers),
            canonical_bytes(result),
        )

    if cached is not None:
        try:
            cached_receipt = gateway.receipt_store.get(cached["receipt_id"])
            if cached_receipt is None:
                raise AuthorityProofError("Cached outcome receipt is unavailable.")
            return response_for(
                cached_receipt,
                base64.b64decode(cached["body_base64"], validate=True),
                True,
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise AuthorityProofError(
                "Cached result is malformed or unverifiable."
            ) from exc
    prepared, claims, replayed = gateway._claim_single_use_evidence(prepared)
    if replayed:
        return error(409, "Single-use authority evidence was already consumed.")
    authorization = gateway._commit_authorization(prepared, claims)
    assert authorization is not None
    ledger.authorized(request_id, str(authorization["receipt_id"]))
    gateway._revalidate_before_dispatch(prepared, headers, arguments, authorization)
    outbound.update(
        {
            "X-BlackFox-Authority": "allow",
            "X-BlackFox-Subject-Digest": prepared.subject.digest,
            "X-BlackFox-Authorization-Receipt": str(authorization["receipt_id"]),
            "Idempotency-Key": request_id,
        }
    )
    if mcp_payload is not None:
        # Rebuild the envelope; credentials and local evidence metadata never leave ingress.
        raw_body = canonical_bytes(
            {
                "jsonrpc": "2.0",
                "id": mcp_payload.get("id"),
                "method": "tools/call",
                "params": {"name": prepared.route.tool_name, "arguments": body},
            }
        )
    else:
        raw_body = canonical_bytes(body)
    url = connector.base_url + prepared.route.api_path
    try:
        upstream = request_upstream(
            url=url,
            method=prepared.route.api_method,
            headers=outbound,
            body=raw_body,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=gateway.config.server.max_response_bytes,
        )
    except UpstreamTransportError:
        gateway._append_receipt(
            prepared=prepared,
            upstream_attempted=True,
            upstream_status=0,
            upstream_body=b"",
            upstream_error="Mesh transport failed; remote outcome is unknown.",
            single_use_evidence_claims=claims,
            authorization=authorization,
        )
        return error(
            502,
            "Mesh transport failed; request will not be automatically repeated.",
            "outcome_unknown",
        )
    receipt = gateway._append_receipt(
        prepared=prepared,
        upstream_attempted=True,
        upstream_status=upstream.status,
        upstream_body=upstream.body,
        upstream_error="",
        single_use_evidence_claims=claims,
        authorization=authorization,
    )
    try:
        response = response_for(receipt, upstream.body)
    except (ValueError, UnicodeError):
        return error(
            502,
            "Upstream response is invalid for the configured transport.",
            "response_received",
        )
    try:
        ledger.complete(
            request_id,
            {
                "receipt_id": receipt["receipt_id"],
                "body_base64": base64.b64encode(upstream.body).decode(),
            },
        )
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise ReceiptWriteError(True, str(authorization["receipt_id"])) from exc
    return response
