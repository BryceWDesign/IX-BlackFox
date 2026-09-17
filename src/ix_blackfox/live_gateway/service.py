from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

from ix_blackfox.agents.authorization import AgentAuthorizationEvaluator
from ix_blackfox.live_gateway.authority import (
    evaluate_live_authority,
    no_evidence_policy,
)
from ix_blackfox.live_gateway.config import GatewayConfig, ToolRoute
from ix_blackfox.live_gateway.evidence import EvidencePolicy, EvidenceStore
from ix_blackfox.live_gateway.models import (
    AuthoritySubject,
    EvidenceIssue,
    LiveAuthorityDecision,
    LiveAuthorityStatus,
)
from ix_blackfox.live_gateway.protocol import (
    McpProtocolError,
    decode_mcp_header_value,
    jsonrpc_error,
    validate_mcp_request,
)
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.upstream import (
    UpstreamResponse,
    UpstreamTransportError,
    request_upstream,
)
from ix_blackfox.operating.models import digest_payload, normalize_identifier
from ix_blackfox.tools.contracts import ToolInvocationRequest


@dataclass(frozen=True, slots=True)
class GatewayHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True, slots=True)
class PreparedAuthorityRequest:
    route: ToolRoute
    subject: AuthoritySubject
    invocation: ToolInvocationRequest
    evidence_ids: tuple[str, ...]
    evidence_policy: EvidencePolicy
    decision: LiveAuthorityDecision


@dataclass(slots=True)
class LiveAuthorityGateway:
    """Network-facing Wave 14 authority gateway with fail-closed pre-tool enforcement."""

    config: GatewayConfig
    evaluator: AgentAuthorizationEvaluator
    evidence_store: EvidenceStore
    receipt_store: AuthorityReceiptStore
    agent_tokens: Mapping[str, bytes]
    operator_token: bytes

    @classmethod
    def from_config(cls, config: GatewayConfig) -> LiveAuthorityGateway:
        return cls(
            config=config,
            evaluator=AgentAuthorizationEvaluator(config.agent_registry),
            evidence_store=EvidenceStore(
                root=config.evidence_root,
                trusted_keys=config.trusted_key_material(),
                trusted_issuer_kinds=config.trusted_issuer_kind_map(),
            ),
            receipt_store=AuthorityReceiptStore(config.receipt_database),
            agent_tokens=config.agent_token_material(),
            operator_token=config.operator_token_material(),
        )

    def status(self) -> dict[str, Any]:
        chain = self.receipt_store.verify_chain()
        missing_keys = [
            f"{issuer.issuer}:{issuer.key_id}"
            for issuer in self.config.trusted_issuers
            if (issuer.issuer, issuer.key_id) not in self.evidence_store.trusted_keys
        ]
        weak_keys = [
            f"{issuer.issuer}:{issuer.key_id}"
            for issuer in self.config.trusted_issuers
            if 0 < len(self.evidence_store.trusted_keys.get((issuer.issuer, issuer.key_id), b"")) < 32
        ]
        missing_agent_credentials = [
            credential.agent_id
            for credential in self.config.agent_credentials
            if credential.agent_id not in self.agent_tokens
        ]
        weak_agent_credentials = sorted(
            agent_id for agent_id, token in self.agent_tokens.items() if len(token) < 32
        )
        duplicate_agent_token_bindings = _duplicate_token_bindings(self.agent_tokens)
        operator_token_missing = not self.operator_token
        operator_token_weak = bool(self.operator_token) and len(self.operator_token) < 32
        credential_material_collisions = _credential_material_collisions(
            evidence_keys=self.evidence_store.trusted_keys,
            agent_tokens=self.agent_tokens,
            operator_token=self.operator_token,
        )
        return {
            "wave": 14,
            "mode": "live_authority_gateway",
            "mcp_configured": self.config.mcp is not None,
            "api_configured": self.config.api is not None,
            "configured_route_count": len(self.config.routes),
            "registered_agent_count": len(self.config.agent_registry.agents),
            "trusted_issuer_count": len(self.config.trusted_issuers),
            "loaded_trusted_key_count": len(self.evidence_store.trusted_keys),
            "missing_trusted_key_bindings": missing_keys,
            "weak_trusted_key_bindings": weak_keys,
            "configured_agent_credential_count": len(self.config.agent_credentials),
            "loaded_agent_credential_count": len(self.agent_tokens),
            "missing_agent_credentials": missing_agent_credentials,
            "weak_agent_credentials": weak_agent_credentials,
            "duplicate_agent_token_bindings": duplicate_agent_token_bindings,
            "operator_token_missing": operator_token_missing,
            "operator_token_weak": operator_token_weak,
            "credential_material_collisions": credential_material_collisions,
            "receipt_chain": chain.to_dict(),
            "ready": (
                chain.passed
                and not missing_keys
                and not weak_keys
                and not missing_agent_credentials
                and not weak_agent_credentials
                and not duplicate_agent_token_bindings
                and not operator_token_missing
                and not operator_token_weak
                and not credential_material_collisions
            ),
        }

    def build_subject(
        self,
        *,
        agent_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        protocol: str,
    ) -> AuthoritySubject:
        route = self._require_route(tool_name)
        normalized_agent = normalize_identifier(agent_id, label="agent_id")
        repository_id = route.repository_id
        if route.repository_argument:
            candidate = arguments.get(route.repository_argument)
            if isinstance(candidate, str) and candidate.strip():
                repository_id = candidate.strip()
        revision = (
            _argument_text(arguments, route.revision_argument)
            if route.revision_argument
            else ""
        )
        path = _argument_text(arguments, route.path_argument) if route.path_argument else ""
        if route.path_argument and not path:
            raise ValueError(
                f"Configured route {route.tool_name!r} requires a non-empty "
                f"{route.path_argument!r} tool argument for scope enforcement."
            )
        policy = self.config.evidence_policy_for(route.evidence_policy_id)
        effective_policy = policy or no_evidence_policy()
        if policy is not None and policy.require_revision_match and not revision:
            raise ValueError(
                f"Configured evidence policy {policy.policy_id!r} requires a non-empty "
                f"{route.revision_argument!r} tool argument."
            )
        agent = self.config.agent_registry.lookup(normalized_agent)
        if agent is None:
            raise ValueError(f"Unregistered Wave 14 agent identity: {normalized_agent}.")
        trusted_issuers = [
            {
                "issuer": issuer.issuer,
                "key_id": issuer.key_id,
                "allowed_kinds": list(issuer.allowed_kinds),
            }
            for issuer in self.config.trusted_issuers
            if not effective_policy.allowed_issuers
            or issuer.issuer in effective_policy.allowed_issuers
        ]
        authority_context_digest = digest_payload(
            {
                "agent_identity_digest": agent.digest,
                "route": route.to_dict(),
                "evidence_policy": effective_policy.to_dict(),
                "trusted_issuers": trusted_issuers,
            }
        )
        return AuthoritySubject(
            agent_id=normalized_agent,
            tool_name=route.tool_name,
            capability=route.capability.value,
            repository_id=repository_id,
            revision=revision,
            path=path,
            arguments_digest=digest_payload(dict(arguments)),
            authority_context_digest=authority_context_digest,
            protocol=protocol,
            metadata={"evidence_policy_id": effective_policy.policy_id},
        )

    def prepare_authority(
        self,
        *,
        agent_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        evidence_ids: Sequence[str],
        protocol: str,
    ) -> PreparedAuthorityRequest:
        route = self._require_route(tool_name)
        subject = self.build_subject(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            protocol=protocol,
        )
        internal_arguments = dict(arguments)
        if subject.path:
            internal_arguments["path"] = subject.path
        invocation = ToolInvocationRequest.create(
            tool_id=route.tool_name,
            capability=route.capability,
            arguments=internal_arguments,
            requested_by=subject.agent_id,
            metadata={
                "repository_id": subject.repository_id,
                "operating_domain": route.operating_domain.value,
                "agent_risk_tier": route.risk_tier.value,
                "wave14_revision": subject.revision,
                "wave14_subject_digest": subject.digest,
            },
        )
        policy = self.config.evidence_policy_for(route.evidence_policy_id)
        if policy is None:
            policy = no_evidence_policy()
        decision = evaluate_live_authority(
            evaluator=self.evaluator,
            evidence_store=self.evidence_store,
            subject=subject,
            invocation=invocation,
            evidence_policy=policy,
            evidence_ids=tuple(evidence_ids),
        )
        return PreparedAuthorityRequest(
            route=route,
            subject=subject,
            invocation=invocation,
            evidence_ids=tuple(evidence_ids),
            evidence_policy=policy,
            decision=decision,
        )

    def handle_mcp(
        self,
        *,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
        raw_body: bytes,
    ) -> GatewayHttpResponse:
        try:
            info = validate_mcp_request(payload, headers)
        except McpProtocolError as exc:
            return _json_response(
                exc.http_status,
                jsonrpc_error(payload.get("id"), code=exc.code, message=exc.message),
            )

        if self.config.mcp is None:
            return _json_response(
                503,
                jsonrpc_error(
                    info.request_id,
                    code=-32053,
                    message="MCP upstream is not configured.",
                ),
            )

        params = payload.get("params", {})
        if not isinstance(params, Mapping):
            return _json_response(
                400,
                jsonrpc_error(
                    info.request_id,
                    code=-32602,
                    message="MCP params must be an object.",
                ),
            )

        claimed_agent_id, identity_error = _resolve_agent_id(headers, params)
        if identity_error:
            receipt = self._append_preexecution_failure(
                agent_id=claimed_agent_id,
                tool_name=info.name or info.method,
                protocol=f"mcp/{info.protocol_version}",
                reason=identity_error,
                reason_code="agent_identity_claim_invalid",
            )
            return _json_response(
                400,
                jsonrpc_error(
                    info.request_id,
                    code=-32050,
                    message=identity_error,
                    data={"receipt_id": receipt["receipt_id"]},
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        # Authenticate every MCP connection before either governed tool execution or
        # configured passthrough.  A caller cannot use discovery/list/ping as an
        # unauthenticated tunnel to the fixed upstream.
        agent_id, authentication_error = self.authenticate_agent(
            headers=headers,
            claimed_agent_id=claimed_agent_id,
        )
        if authentication_error:
            receipt = self._append_preexecution_failure(
                agent_id=claimed_agent_id,
                tool_name=info.name or info.method,
                protocol=f"mcp/{info.protocol_version}",
                reason=authentication_error,
                reason_code="agent_authentication_failed",
            )
            return _json_response(
                401,
                jsonrpc_error(
                    info.request_id,
                    code=-32054,
                    message=authentication_error,
                    data={"receipt_id": receipt["receipt_id"]},
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        if info.method != "tools/call":
            if info.method not in self.config.mcp.passthrough_methods:
                receipt = self._append_preexecution_failure(
                    agent_id=agent_id,
                    tool_name=info.method,
                    protocol=f"mcp/{info.protocol_version}",
                    reason="MCP method is not allowlisted for passthrough by the gateway.",
                    reason_code="mcp_passthrough_method_blocked",
                )
                return _json_response(
                    403,
                    jsonrpc_error(
                        info.request_id,
                        code=-32050,
                        message="MCP method is not permitted through this authority gateway.",
                        data={"receipt_id": receipt["receipt_id"]},
                    ),
                    extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
                )
            return self._proxy_mcp_passthrough(raw_body=raw_body, headers=headers)

        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            return _json_response(
                400,
                jsonrpc_error(
                    info.request_id,
                    code=-32602,
                    message="Tool arguments must be an object.",
                ),
            )
        try:
            evidence_ids = _bounded_evidence_ids(_resolve_evidence_ids(headers, params))
            route = self._require_route(info.name)
            _validate_mcp_parameter_headers(
                route=route,
                arguments=arguments,
                headers=headers,
                require_configured_mirrors=info.modern,
            )
            prepared = self.prepare_authority(
                agent_id=agent_id,
                tool_name=info.name,
                arguments=arguments,
                evidence_ids=evidence_ids,
                protocol=f"mcp/{info.protocol_version}",
            )
        except McpProtocolError as exc:
            receipt = self._append_preexecution_failure(
                agent_id=agent_id,
                tool_name=info.name,
                protocol=f"mcp/{info.protocol_version}",
                reason=exc.message,
                reason_code="mcp_parameter_header_mismatch",
            )
            return _json_response(
                exc.http_status,
                jsonrpc_error(
                    info.request_id,
                    code=exc.code,
                    message=exc.message,
                    data={"receipt_id": receipt["receipt_id"]},
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )
        except (KeyError, ValueError) as exc:
            receipt = self._append_preexecution_failure(
                agent_id=agent_id,
                tool_name=info.name,
                protocol=f"mcp/{info.protocol_version}",
                reason=str(exc),
            )
            return _json_response(
                403,
                jsonrpc_error(
                    info.request_id,
                    code=-32050,
                    message="Tool is not configured for BlackFox authority enforcement.",
                    data={"receipt_id": receipt["receipt_id"], "detail": str(exc)},
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        if not prepared.decision.allowed:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=False,
                upstream_status=0,
                upstream_body=b"",
                upstream_error="",
            )
            code, message, status = _denial_response(prepared.decision.status)
            return _json_response(
                status,
                jsonrpc_error(
                    info.request_id,
                    code=code,
                    message=message,
                    data={
                        "receipt_id": receipt["receipt_id"],
                        "authority": prepared.decision.to_dict(),
                    },
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        prepared, claimed_evidence, replayed_evidence = self._claim_single_use_evidence(
            prepared
        )
        if replayed_evidence:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=False,
                upstream_status=0,
                upstream_body=b"",
                upstream_error="single-use evidence was already claimed",
            )
            return _json_response(
                409,
                jsonrpc_error(
                    info.request_id,
                    code=-32055,
                    message="Single-use authority evidence has already been consumed or reserved.",
                    data={
                        "receipt_id": receipt["receipt_id"],
                        "replayed_evidence_ids": list(replayed_evidence),
                        "authority": prepared.decision.to_dict(),
                    },
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        forwarded_headers = _forward_request_headers(headers)
        forwarded_headers["X-BlackFox-Authority"] = "allow"
        forwarded_headers["X-BlackFox-Subject-Digest"] = prepared.subject.digest
        try:
            upstream = request_upstream(
                url=self.config.mcp.upstream_url,
                method="POST",
                headers=forwarded_headers,
                body=raw_body,
                timeout_seconds=self.config.server.upstream_timeout_seconds,
                max_response_bytes=self.config.server.max_response_bytes,
            )
        except UpstreamTransportError as exc:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=True,
                upstream_status=0,
                upstream_body=b"",
                upstream_error=str(exc),
                single_use_evidence_claims=claimed_evidence,
            )
            return _json_response(
                502,
                jsonrpc_error(
                    info.request_id,
                    code=-32053,
                    message="Configured MCP upstream failed.",
                    data={
                        "receipt_id": receipt["receipt_id"],
                        "detail": str(exc),
                        "execution_state": "outcome_unknown",
                    },
                ),
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        receipt = self._append_receipt(
            prepared=prepared,
            upstream_attempted=True,
            upstream_status=upstream.status,
            upstream_body=upstream.body,
            upstream_error="",
            single_use_evidence_claims=claimed_evidence,
        )
        response_headers = _forward_response_headers(upstream)
        response_headers["X-BlackFox-Receipt-Id"] = str(receipt["receipt_id"])
        response_headers["X-BlackFox-Authority"] = "allow"
        return GatewayHttpResponse(
            status=upstream.status,
            headers=tuple(response_headers.items()),
            body=upstream.body,
        )

    def handle_api(
        self,
        *,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> GatewayHttpResponse:
        tool_name = payload.get("tool_name")
        arguments = payload.get("arguments", {})
        context = payload.get("context", {})
        if not isinstance(tool_name, str) or not tool_name.strip():
            return _json_response(400, {"error": "tool_name is required"})
        if not isinstance(arguments, Mapping):
            return _json_response(400, {"error": "arguments must be an object"})
        if not isinstance(context, Mapping):
            return _json_response(400, {"error": "context must be an object"})
        body_agent = payload.get("agent_id", "")
        if not isinstance(body_agent, str):
            return _json_response(400, {"error": "agent_id must be a string"})
        header_agent = _header(headers, "X-BlackFox-Agent-Id")
        try:
            normalized_header_agent = (
                normalize_identifier(header_agent, label="agent_id") if header_agent else ""
            )
            normalized_body_agent = (
                normalize_identifier(body_agent, label="agent_id") if body_agent else ""
            )
        except ValueError as exc:
            return _json_response(400, {"error": "invalid agent identity", "detail": str(exc)})
        if (
            normalized_header_agent
            and normalized_body_agent
            and normalized_header_agent != normalized_body_agent
        ):
            return _json_response(400, {"error": "agent identity header/body mismatch"})
        claimed_agent_id = normalized_body_agent or normalized_header_agent
        agent_id, authentication_error = self.authenticate_agent(
            headers=headers,
            claimed_agent_id=claimed_agent_id,
        )
        if authentication_error:
            receipt = self._append_preexecution_failure(
                agent_id=claimed_agent_id,
                tool_name=tool_name,
                protocol="blackfox-api/v1",
                reason=authentication_error,
                reason_code="agent_authentication_failed",
            )
            return _json_response(
                401,
                {
                    "error": authentication_error,
                    "receipt_id": receipt["receipt_id"],
                    "execution_state": "not_attempted",
                },
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )
        evidence_ids = _string_sequence(context.get("evidence_refs", ()))
        header_evidence = _header(headers, "X-BlackFox-Evidence")
        if header_evidence:
            evidence_ids = tuple(
                dict.fromkeys((*evidence_ids, *_split_evidence_header(header_evidence)))
            )

        try:
            evidence_ids = _bounded_evidence_ids(evidence_ids)
            prepared = self.prepare_authority(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                evidence_ids=evidence_ids,
                protocol="blackfox-api/v1",
            )
        except (KeyError, ValueError) as exc:
            receipt = self._append_preexecution_failure(
                agent_id=agent_id,
                tool_name=tool_name,
                protocol="blackfox-api/v1",
                reason=str(exc),
            )
            return _json_response(403, {"error": "authority preparation failed", "detail": str(exc), "receipt_id": receipt["receipt_id"]})

        if not prepared.decision.allowed:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=False,
                upstream_status=0,
                upstream_body=b"",
                upstream_error="",
            )
            _, message, status = _denial_response(prepared.decision.status)
            return _json_response(
                status,
                {
                    "status": prepared.decision.status.value,
                    "message": message,
                    "receipt_id": receipt["receipt_id"],
                    "authority": prepared.decision.to_dict(),
                    "execution_state": "not_attempted",
                },
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        if self.config.api is None or not prepared.route.api_path:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=False,
                upstream_status=0,
                upstream_body=b"",
                upstream_error="API upstream route is not configured",
            )
            return _json_response(503, {"error": "API upstream route is not configured", "receipt_id": receipt["receipt_id"]})

        prepared, claimed_evidence, replayed_evidence = self._claim_single_use_evidence(prepared)
        if replayed_evidence:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=False,
                upstream_status=0,
                upstream_body=b"",
                upstream_error="single-use evidence was already claimed",
            )
            return _json_response(
                409,
                {
                    "status": prepared.decision.status.value,
                    "error": "single-use authority evidence has already been consumed or reserved",
                    "replayed_evidence_ids": list(replayed_evidence),
                    "receipt_id": receipt["receipt_id"],
                    "authority": prepared.decision.to_dict(),
                    "execution_state": "not_attempted",
                },
                extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
            )

        upstream_url = urljoin(f"{self.config.api.base_url}/", prepared.route.api_path.lstrip("/"))
        forwarded = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-BlackFox-Authority": "allow",
            "X-BlackFox-Subject-Digest": prepared.subject.digest,
        }
        raw_body = json.dumps(dict(arguments), sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            upstream = request_upstream(
                url=upstream_url,
                method=prepared.route.api_method,
                headers=forwarded,
                body=raw_body,
                timeout_seconds=self.config.server.upstream_timeout_seconds,
                max_response_bytes=self.config.server.max_response_bytes,
            )
        except UpstreamTransportError as exc:
            receipt = self._append_receipt(
                prepared=prepared,
                upstream_attempted=True,
                upstream_status=0,
                upstream_body=b"",
                upstream_error=str(exc),
                single_use_evidence_claims=claimed_evidence,
            )
            return _json_response(
                502,
                {
                    "error": "configured API upstream failed",
                    "detail": str(exc),
                    "receipt_id": receipt["receipt_id"],
                    "execution_state": "outcome_unknown",
                },
            )

        receipt = self._append_receipt(
            prepared=prepared,
            upstream_attempted=True,
            upstream_status=upstream.status,
            upstream_body=upstream.body,
            upstream_error="",
            single_use_evidence_claims=claimed_evidence,
        )
        result = _decode_upstream_body(upstream)
        return _json_response(
            upstream.status,
            {
                "status": "upstream_response_received",
                "receipt_id": receipt["receipt_id"],
                "subject_digest": prepared.subject.digest,
                "execution_state": "response_received",
                "upstream_status": upstream.status,
                "result": result,
            },
            extra_headers={"X-BlackFox-Receipt-Id": str(receipt["receipt_id"])},
        )

    def _proxy_mcp_passthrough(
        self,
        *,
        raw_body: bytes,
        headers: Mapping[str, str],
    ) -> GatewayHttpResponse:
        if self.config.mcp is None:
            return _json_response(503, {"error": "MCP upstream is not configured"})
        try:
            upstream = request_upstream(
                url=self.config.mcp.upstream_url,
                method="POST",
                headers=_forward_request_headers(headers),
                body=raw_body,
                timeout_seconds=self.config.server.upstream_timeout_seconds,
                max_response_bytes=self.config.server.max_response_bytes,
            )
        except UpstreamTransportError as exc:
            return _json_response(502, {"error": "configured MCP upstream failed", "detail": str(exc)})
        return GatewayHttpResponse(
            status=upstream.status,
            headers=tuple(_forward_response_headers(upstream).items()),
            body=upstream.body,
        )

    def _append_receipt(
        self,
        *,
        prepared: PreparedAuthorityRequest,
        upstream_attempted: bool,
        upstream_status: int,
        upstream_body: bytes,
        upstream_error: str,
        single_use_evidence_claims: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        return self.receipt_store.append(
            {
                "recorded_at": datetime.now(tz=UTC).isoformat(),
                "protocol": prepared.subject.protocol,
                "subject": prepared.subject.to_dict(),
                "authority_decision": prepared.decision.to_dict(),
                "evidence_refs": list(prepared.evidence_ids),
                "single_use_evidence_claims": list(single_use_evidence_claims),
                "upstream_attempted": upstream_attempted,
                "upstream_status": upstream_status,
                "upstream_response_sha256": hashlib.sha256(upstream_body).hexdigest() if upstream_body else "",
                "upstream_error": upstream_error,
                "execution_state": _execution_state(
                    upstream_attempted=upstream_attempted,
                    upstream_error=upstream_error,
                ),
                # "executed" is retained for receipt-schema compatibility.  It means
                # BlackFox received a response after an allowed upstream request; it
                # does not claim proof of arbitrary upstream side effects.
                "executed": upstream_attempted and not upstream_error and prepared.decision.allowed,
            }
        )

    def _append_preexecution_failure(
        self,
        *,
        agent_id: str,
        tool_name: str,
        protocol: str,
        reason: str,
        reason_code: str = "gateway_configuration_block",
    ) -> dict[str, Any]:
        return self.receipt_store.append(
            {
                "recorded_at": datetime.now(tz=UTC).isoformat(),
                "protocol": protocol,
                "subject": {"agent_id": agent_id, "tool_name": tool_name},
                "authority_decision": {"status": "block", "reason_codes": [reason_code]},
                "evidence_refs": [],
                "single_use_evidence_claims": [],
                "upstream_attempted": False,
                "upstream_status": 0,
                "upstream_response_sha256": "",
                "upstream_error": reason,
                "execution_state": "not_attempted",
                "executed": False,
            }
        )

    def authenticate_agent(
        self,
        *,
        headers: Mapping[str, str],
        claimed_agent_id: str,
    ) -> tuple[str, str]:
        token = _header(headers, "X-BlackFox-Agent-Token")
        if not token:
            return "", "BlackFox agent credential is required."
        token_bytes = token.encode("utf-8")
        matches = [
            agent_id
            for agent_id, expected in self.agent_tokens.items()
            if hmac.compare_digest(token_bytes, expected)
        ]
        if len(matches) != 1:
            return "", "BlackFox agent credential is invalid or ambiguously configured."
        authenticated_agent_id = matches[0]
        if claimed_agent_id:
            try:
                normalized_claim = normalize_identifier(claimed_agent_id, label="agent_id")
            except ValueError:
                return "", "Claimed BlackFox agent identity is invalid."
            if normalized_claim != authenticated_agent_id:
                return "", "Authenticated BlackFox agent identity does not match the claimed agent id."
        return authenticated_agent_id, ""

    def operator_authorized(self, headers: Mapping[str, str]) -> bool:
        """Authenticate access to operator-only receipt inspection endpoints."""

        if not self.operator_token:
            return False
        explicit = _header(headers, "X-BlackFox-Operator-Token")
        authorization = _header(headers, "Authorization")
        bearer = ""
        if authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()
        if explicit and bearer and not hmac.compare_digest(explicit.encode("utf-8"), bearer.encode("utf-8")):
            return False
        candidate = explicit or bearer
        return bool(candidate) and hmac.compare_digest(candidate.encode("utf-8"), self.operator_token)

    def _claim_single_use_evidence(
        self,
        prepared: PreparedAuthorityRequest,
    ) -> tuple[PreparedAuthorityRequest, tuple[str, ...], tuple[str, ...]]:
        single_use_kinds = set(prepared.evidence_policy.single_use_kinds)
        if not single_use_kinds:
            return prepared, (), ()
        claim_ids = tuple(
            sorted(
                verification.evidence_id
                for verification in prepared.decision.evidence.verifications
                if verification.passed and verification.kind in single_use_kinds
            )
        )
        if not claim_ids:
            return prepared, (), ()
        conflicts = self.receipt_store.claim_single_use_evidence(
            claim_ids,
            subject_digest=prepared.subject.digest,
            claimed_at=datetime.now(tz=UTC).isoformat(),
        )
        if not conflicts:
            return prepared, claim_ids, ()

        issues = tuple(
            EvidenceIssue(
                code="single_use_evidence_replayed",
                summary="Single-use evidence was already reserved by an earlier authority attempt.",
                evidence_id=evidence_id,
            )
            for evidence_id in conflicts
        )
        evidence = replace(
            prepared.decision.evidence,
            issues=(*prepared.decision.evidence.issues, *issues),
        )
        decision = LiveAuthorityDecision(
            subject=prepared.subject,
            status=LiveAuthorityStatus.EVIDENCE_REQUIRED,
            reason_codes=("single_use_evidence_replayed",),
            agent_authorization=prepared.decision.agent_authorization,
            evidence=evidence,
            decided_at=datetime.now(tz=UTC).isoformat(),
        )
        return replace(prepared, decision=decision), (), conflicts

    def _require_route(self, tool_name: str) -> ToolRoute:
        route = self.config.route_for(tool_name)
        if route is None:
            raise KeyError(f"Unconfigured tool route: {tool_name}")
        return route


def _credential_material_collisions(
    *,
    evidence_keys: Mapping[tuple[str, str], bytes],
    agent_tokens: Mapping[str, bytes],
    operator_token: bytes,
) -> list[list[str]]:
    groups: dict[bytes, list[str]] = {}
    for (issuer, key_id), material in evidence_keys.items():
        if material:
            groups.setdefault(material, []).append(f"evidence:{issuer}:{key_id}")
    for agent_id, material in agent_tokens.items():
        if material:
            groups.setdefault(material, []).append(f"agent:{agent_id}")
    if operator_token:
        groups.setdefault(operator_token, []).append("operator")
    return [sorted(labels) for labels in groups.values() if len(labels) > 1]


def _duplicate_token_bindings(agent_tokens: Mapping[str, bytes]) -> list[list[str]]:
    groups: dict[bytes, list[str]] = {}
    for agent_id, token in agent_tokens.items():
        groups.setdefault(token, []).append(agent_id)
    return [sorted(agent_ids) for agent_ids in groups.values() if len(agent_ids) > 1]


def _resolve_agent_id(headers: Mapping[str, str], params: Mapping[str, Any]) -> tuple[str, str]:
    header_value = _header(headers, "X-BlackFox-Agent-Id")
    metadata = params.get("_meta", {})
    meta_value = ""
    if isinstance(metadata, Mapping):
        candidate = metadata.get("io.ix-blackfox/agentId", "")
        if isinstance(candidate, str):
            meta_value = candidate.strip()
    try:
        normalized_header = (
            normalize_identifier(header_value, label="agent_id") if header_value else ""
        )
        normalized_meta = (
            normalize_identifier(meta_value, label="agent_id") if meta_value else ""
        )
    except ValueError:
        return header_value or meta_value, "BlackFox agent identity claim is invalid."
    if normalized_header and normalized_meta and normalized_header != normalized_meta:
        return normalized_header, "BlackFox agent identity header and MCP metadata disagree."
    return normalized_header or normalized_meta, ""


def _resolve_evidence_ids(headers: Mapping[str, str], params: Mapping[str, Any]) -> tuple[str, ...]:
    result: list[str] = []
    header_value = _header(headers, "X-BlackFox-Evidence")
    if header_value:
        result.extend(_split_evidence_header(header_value))
    metadata = params.get("_meta", {})
    if isinstance(metadata, Mapping):
        value = metadata.get("io.ix-blackfox/evidenceRefs", ())
        result.extend(_string_sequence(value))
    return tuple(dict.fromkeys(result))


def _split_evidence_header(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _bounded_evidence_ids(values: Sequence[str]) -> tuple[str, ...]:
    unique = tuple(dict.fromkeys(values))
    if len(unique) > _MAX_EVIDENCE_REFS:
        raise ValueError(
            f"At most {_MAX_EVIDENCE_REFS} evidence references may accompany one action."
        )
    if any(len(value) > _MAX_EVIDENCE_ID_LENGTH for value in unique):
        raise ValueError(
            f"Evidence references must not exceed {_MAX_EVIDENCE_ID_LENGTH} characters."
        )
    return unique


def _string_sequence(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if not isinstance(value, Sequence) or isinstance(value, bytes | bytearray):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _argument_text(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _denial_response(status: LiveAuthorityStatus) -> tuple[int, str, int]:
    if status is LiveAuthorityStatus.REVIEW_REQUIRED:
        return -32051, "Verified human authority is required before tool execution.", 428
    if status is LiveAuthorityStatus.EVIDENCE_REQUIRED:
        return -32052, "Required evidence conditions are not satisfied.", 428
    return -32050, "BlackFox denied authority before tool execution.", 403


_MCP_SAFE_INTEGER_MAX = (2**53) - 1
_MAX_EVIDENCE_REFS = 64
_MAX_EVIDENCE_ID_LENGTH = 128
_MISSING = object()


def _validate_mcp_parameter_headers(
    *,
    route: ToolRoute,
    arguments: Mapping[str, Any],
    headers: Mapping[str, str],
    require_configured_mirrors: bool,
) -> None:
    """Validate configured ``x-mcp-header`` mirrors against body arguments.

    The JSON-RPC body remains the authority source.  A configured mirror proves
    that routing metadata seen by HTTP intermediaries agrees with that body.
    Unconfigured ``Mcp-Param-*`` fields are forwarded as MCP intermediary data,
    but BlackFox never trusts them for an authority decision.
    """

    for binding in route.mcp_header_bindings:
        value = _nested_argument(arguments, binding.argument_path)
        present, raw_header = _header_value(headers, binding.full_header_name)
        if value is _MISSING:
            if present:
                raise McpProtocolError(
                    -32020,
                    f"{binding.full_header_name} is present but its bound tool argument is absent.",
                )
            continue
        if not require_configured_mirrors and not present:
            continue
        if not present:
            raise McpProtocolError(
                -32020,
                f"{binding.full_header_name} is required by the configured MCP route binding.",
            )
        expected = _canonical_mcp_primitive(value, label=".".join(binding.argument_path))
        actual = decode_mcp_header_value(raw_header, label=binding.full_header_name)
        if not hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8")):
            raise McpProtocolError(
                -32020,
                f"{binding.full_header_name} disagrees with its bound JSON-RPC tool argument.",
            )


def _nested_argument(arguments: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = arguments
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _canonical_mcp_primitive(value: Any, *, label: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > _MCP_SAFE_INTEGER_MAX:
            raise McpProtocolError(
                -32020,
                f"MCP header-bound integer {label!r} exceeds the interoperable safe integer range.",
            )
        return str(value)
    if isinstance(value, str):
        return value
    raise McpProtocolError(
        -32020,
        f"MCP header-bound argument {label!r} must be a string, integer, or boolean.",
    )


def _forward_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "authorization",
        "accept",
        "content-type",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        "mcp-session-id",
        "traceparent",
        "tracestate",
        "baggage",
        "user-agent",
    }
    return {
        key: value
        for key, value in headers.items()
        if key.lower() in allowed or key.lower().startswith("mcp-param-")
    }


def _forward_response_headers(upstream: UpstreamResponse) -> dict[str, str]:
    allowed = {
        "content-type",
        "mcp-session-id",
        "cache-control",
        "etag",
        "mcp-protocol-version",
    }
    return {key: value for key, value in upstream.headers if key.lower() in allowed}


def _decode_upstream_body(upstream: UpstreamResponse) -> Any:
    content_type = upstream.header("Content-Type").lower()
    if "json" in content_type:
        try:
            return json.loads(upstream.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    try:
        return {"text": upstream.body.decode("utf-8")}
    except UnicodeDecodeError:
        return {"body_base64": base64.b64encode(upstream.body).decode("ascii")}


def _json_response(
    status: int,
    payload: Mapping[str, Any],
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> GatewayHttpResponse:
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if extra_headers:
        headers.update(extra_headers)
    return GatewayHttpResponse(
        status=status,
        headers=tuple(headers.items()),
        body=(json.dumps(dict(payload), sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )


def _execution_state(*, upstream_attempted: bool, upstream_error: str) -> str:
    if not upstream_attempted:
        return "not_attempted"
    if upstream_error:
        # A transport failure after dispatch cannot prove whether the upstream
        # performed a side effect.  Preserve that uncertainty explicitly.
        return "outcome_unknown"
    return "response_received"


def _header_value(headers: Mapping[str, str], name: str) -> tuple[bool, str]:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return True, value
    return False, ""


def _header(headers: Mapping[str, str], name: str) -> str:
    present, value = _header_value(headers, name)
    return value.strip() if present else ""
