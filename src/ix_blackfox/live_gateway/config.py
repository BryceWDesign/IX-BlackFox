from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ix_blackfox.agents.models import (
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentLifecycleState,
    AgentTrustTier,
    CapabilityRiskTier,
)
from ix_blackfox.agents.registry import AgentRegistry
from ix_blackfox.live_gateway.evidence import EvidencePolicy, TrustedEvidenceIssuer
from ix_blackfox.operating.models import OperatingDomain
from ix_blackfox.tools.manifest import ToolCapability

_DEFAULT_MCP_PASSTHROUGH_METHODS = (
    "initialize",
    "notifications/initialized",
    "ping",
    "server/discover",
    "tools/list",
)
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True, slots=True)
class GatewayServerConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    max_request_bytes: int = 2 * 1024 * 1024
    max_response_bytes: int = 8 * 1024 * 1024
    upstream_timeout_seconds: float = 30.0
    operator_token_env: str = "BLACKFOX_WAVE14_OPERATOR_TOKEN"
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("server.host must not be empty.")
        if not 0 <= self.port <= 65535:
            raise ValueError("server.port must be between 0 and 65535.")
        if self.max_request_bytes <= 0 or self.max_response_bytes <= 0:
            raise ValueError("request/response size limits must be positive.")
        if self.upstream_timeout_seconds <= 0:
            raise ValueError("server.upstream_timeout_seconds must be positive.")
        if not self.operator_token_env.strip():
            raise ValueError("server.operator_token_env must not be empty.")
        normalized_origins = tuple(
            sorted({_normalize_origin(origin) for origin in self.allowed_origins})
        )
        object.__setattr__(self, "allowed_origins", normalized_origins)


@dataclass(frozen=True, slots=True)
class McpUpstreamConfig:
    upstream_url: str
    passthrough_methods: tuple[str, ...] = _DEFAULT_MCP_PASSTHROUGH_METHODS

    def __post_init__(self) -> None:
        _validate_http_url(self.upstream_url, label="mcp.upstream_url")
        normalized = tuple(sorted({method.strip() for method in self.passthrough_methods if method.strip()}))
        if "tools/call" in normalized:
            raise ValueError("mcp.passthrough_methods must not include governed tools/call.")
        object.__setattr__(self, "passthrough_methods", normalized)


@dataclass(frozen=True, slots=True)
class ApiUpstreamConfig:
    base_url: str

    def __post_init__(self) -> None:
        _validate_http_url(self.base_url, label="api.base_url")
        parsed = urlparse(self.base_url)
        if parsed.params or parsed.query or parsed.fragment:
            raise ValueError("api.base_url must not contain parameters, query, or fragment.")


@dataclass(frozen=True, slots=True)
class AgentCredential:
    """Environment-backed static credential binding for one registered agent."""

    agent_id: str
    secret_env: str

    def __post_init__(self) -> None:
        if not self.agent_id.strip() or not self.secret_env.strip():
            raise ValueError("AgentCredential fields must not be empty.")


@dataclass(frozen=True, slots=True)
class McpParameterHeaderBinding:
    """Configured x-mcp-header mirror used for modern MCP validation.

    BlackFox is an intermediary, not the source of an upstream tool schema. A
    binding therefore has to be configured only when the upstream tool's
    ``inputSchema`` actually carries the corresponding ``x-mcp-header``
    annotation. Unknown ``Mcp-Param-*`` headers are forwarded without being used
    for authority decisions.
    """

    argument_path: tuple[str, ...]
    header_name: str

    def __post_init__(self) -> None:
        path = tuple(part.strip() for part in self.argument_path if part.strip())
        if not path:
            raise ValueError("MCP parameter header argument_path must not be empty.")
        if len(path) != len(self.argument_path):
            raise ValueError("MCP parameter header argument_path parts must not be empty.")
        header_name = self.header_name.strip()
        if not header_name or not _HTTP_TOKEN.fullmatch(header_name):
            raise ValueError(
                "MCP parameter header_name must use RFC 9110 HTTP field-name token syntax."
            )
        object.__setattr__(self, "argument_path", path)
        object.__setattr__(self, "header_name", header_name)

    @property
    def full_header_name(self) -> str:
        return f"Mcp-Param-{self.header_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "argument_path": list(self.argument_path),
            "header_name": self.header_name,
        }


@dataclass(frozen=True, slots=True)
class ToolRoute:
    """Configured external tool route governed by Wave 14."""

    tool_name: str
    capability: ToolCapability
    repository_id: str
    path_argument: str = "path"
    revision_argument: str = "revision"
    repository_argument: str = ""
    risk_tier: CapabilityRiskTier = CapabilityRiskTier.MEDIUM
    evidence_policy_id: str = ""
    api_method: str = "POST"
    api_path: str = ""
    operating_domain: OperatingDomain = OperatingDomain.POLICY_GOVERNED
    mcp_header_bindings: tuple[McpParameterHeaderBinding, ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("tool_name", self.tool_name),
            ("repository_id", self.repository_id),
        ):
            if not value.strip():
                raise ValueError(f"route.{label} must not be empty.")
        object.__setattr__(self, "path_argument", self.path_argument.strip())
        object.__setattr__(self, "revision_argument", self.revision_argument.strip())
        object.__setattr__(self, "repository_argument", self.repository_argument.strip())
        method = self.api_method.strip().upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("route.api_method must be POST, PUT, PATCH, or DELETE.")
        object.__setattr__(self, "api_method", method)
        if self.api_path:
            _validate_api_path(self.api_path)
        header_names = [binding.header_name.lower() for binding in self.mcp_header_bindings]
        if len(header_names) != len(set(header_names)):
            raise ValueError("route MCP parameter header names must be unique case-insensitively.")
        argument_paths = [binding.argument_path for binding in self.mcp_header_bindings]
        if len(argument_paths) != len(set(argument_paths)):
            raise ValueError("route MCP parameter header argument paths must be unique.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "capability": self.capability.value,
            "repository_id": self.repository_id,
            "path_argument": self.path_argument,
            "revision_argument": self.revision_argument,
            "repository_argument": self.repository_argument,
            "risk_tier": self.risk_tier.value,
            "evidence_policy_id": self.evidence_policy_id,
            "api_method": self.api_method,
            "api_path": self.api_path,
            "operating_domain": self.operating_domain.value,
            "mcp_header_bindings": [
                binding.to_dict() for binding in self.mcp_header_bindings
            ],
        }


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    source_path: Path
    server: GatewayServerConfig
    mcp: McpUpstreamConfig | None
    api: ApiUpstreamConfig | None
    evidence_root: Path
    receipt_database: Path
    trusted_issuers: tuple[TrustedEvidenceIssuer, ...]
    agent_credentials: tuple[AgentCredential, ...]
    evidence_policies: tuple[EvidencePolicy, ...]
    routes: tuple[ToolRoute, ...]
    agent_registry: AgentRegistry

    def __post_init__(self) -> None:
        issuer_keys = [(issuer.issuer, issuer.key_id) for issuer in self.trusted_issuers]
        if len(issuer_keys) != len(set(issuer_keys)):
            raise ValueError("trusted issuer/key_id bindings must be unique.")
        route_names = [route.tool_name for route in self.routes]
        if len(route_names) != len(set(route_names)):
            raise ValueError("route tool_name values must be unique.")
        policy_ids = [policy.policy_id for policy in self.evidence_policies]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("evidence policy_id values must be unique.")
        credential_agent_ids = [item.agent_id for item in self.agent_credentials]
        if len(credential_agent_ids) != len(set(credential_agent_ids)):
            raise ValueError("agent credential bindings must have unique agent_id values.")
        registered_ids = {agent.agent_id for agent in self.agent_registry.agents}
        credential_ids = set(credential_agent_ids)
        missing_credentials = sorted(registered_ids - credential_ids)
        unknown_credentials = sorted(credential_ids - registered_ids)
        if missing_credentials:
            raise ValueError(
                "Every registered Wave 14 agent requires an ingress credential binding; "
                f"missing: {', '.join(missing_credentials)}."
            )
        if unknown_credentials:
            raise ValueError(
                "Agent credentials reference unregistered agents: "
                f"{', '.join(unknown_credentials)}."
            )
        if self.mcp is None and self.api is None:
            raise ValueError("Wave 14 requires at least one live MCP or API upstream.")
        if self.mcp is None:
            routes_without_api = [route.tool_name for route in self.routes if not route.api_path]
            if routes_without_api:
                raise ValueError(
                    "Routes without api_path require an MCP upstream; affected routes: "
                    + ", ".join(sorted(routes_without_api))
                    + "."
                )
        known_policies = set(policy_ids)
        for policy in self.evidence_policies:
            policy_issuers = (
                tuple(issuer for issuer in self.trusted_issuers if issuer.issuer in policy.allowed_issuers)
                if policy.allowed_issuers
                else self.trusted_issuers
            )
            for kind in policy.required_kinds:
                if not any(kind in issuer.allowed_kinds for issuer in policy_issuers):
                    raise ValueError(
                        f"evidence policy {policy.policy_id!r} requires kind {kind!r} but no "
                        "allowed trusted issuer/key is authorized to assert that kind."
                    )
            if policy.human_approval_kind and not any(
                issuer.issuer in policy.human_approval_issuers
                and policy.human_approval_kind in issuer.allowed_kinds
                for issuer in self.trusted_issuers
            ):
                raise ValueError(
                    f"evidence policy {policy.policy_id!r} requires human approval but no "
                    "configured human approval issuer/key may assert that evidence kind."
                )
        for route in self.routes:
            if route.evidence_policy_id and route.evidence_policy_id not in known_policies:
                raise ValueError(
                    f"route {route.tool_name!r} references unknown evidence policy "
                    f"{route.evidence_policy_id!r}."
                )
            if route.api_path and self.api is None:
                raise ValueError(
                    f"route {route.tool_name!r} declares api_path but [api] is not configured."
                )
            route_policy = self.evidence_policy_for(route.evidence_policy_id)
            if route_policy is not None and route_policy.require_revision_match and not route.revision_argument:
                raise ValueError(
                    f"route {route.tool_name!r} uses revision-bound evidence policy "
                    f"{route_policy.policy_id!r} but has no revision_argument."
                )
        if not self.routes:
            raise ValueError("At least one [[routes]] entry is required.")

    def route_for(self, tool_name: str) -> ToolRoute | None:
        return next((route for route in self.routes if route.tool_name == tool_name), None)

    def evidence_policy_for(self, policy_id: str) -> EvidencePolicy | None:
        if not policy_id:
            return None
        return next(
            (policy for policy in self.evidence_policies if policy.policy_id == policy_id),
            None,
        )

    def trusted_key_material(self) -> dict[tuple[str, str], bytes]:
        keys: dict[tuple[str, str], bytes] = {}
        for issuer in self.trusted_issuers:
            value = os.environ.get(issuer.secret_env, "")
            if not value:
                continue
            keys[(issuer.issuer, issuer.key_id)] = value.encode("utf-8")
        return keys

    def trusted_issuer_kind_map(self) -> dict[tuple[str, str], tuple[str, ...]]:
        return {
            (issuer.issuer, issuer.key_id): issuer.allowed_kinds
            for issuer in self.trusted_issuers
        }

    def operator_token_material(self) -> bytes:
        value = os.environ.get(self.server.operator_token_env, "")
        return value.encode("utf-8") if value else b""

    def agent_token_material(self) -> dict[str, bytes]:
        tokens: dict[str, bytes] = {}
        for credential in self.agent_credentials:
            value = os.environ.get(credential.secret_env, "")
            if value:
                tokens[credential.agent_id] = value.encode("utf-8")
        return tokens

    def issuer_for(self, issuer_name: str, key_id: str) -> TrustedEvidenceIssuer | None:
        return next(
            (
                issuer
                for issuer in self.trusted_issuers
                if issuer.issuer == issuer_name and issuer.key_id == key_id
            ),
            None,
        )

    def origin_allowed(self, origin: str) -> bool:
        """Return whether one supplied browser Origin is explicitly allowed.

        Requests without an Origin header are handled separately by the HTTP
        server. An Origin that is present must parse as a normal HTTP(S) origin
        and match the configured allowlist exactly after normalization.
        """

        try:
            normalized = _normalize_origin(origin)
        except ValueError:
            return False
        return normalized in set(self.server.allowed_origins)


def load_gateway_config(path: Path) -> GatewayConfig:
    """Load one typed Wave 14 gateway config from TOML."""

    source_path = path.resolve()
    payload = tomllib.loads(source_path.read_text(encoding="utf-8"))
    base = source_path.parent

    server_payload = _mapping(payload.get("server", {}), "server")
    server = GatewayServerConfig(
        host=str(server_payload.get("host", "127.0.0.1")),
        port=int(server_payload.get("port", 8765)),
        max_request_bytes=int(server_payload.get("max_request_bytes", 2 * 1024 * 1024)),
        max_response_bytes=int(server_payload.get("max_response_bytes", 8 * 1024 * 1024)),
        upstream_timeout_seconds=float(server_payload.get("upstream_timeout_seconds", 30.0)),
        operator_token_env=str(server_payload.get("operator_token_env", "BLACKFOX_WAVE14_OPERATOR_TOKEN")),
        allowed_origins=_string_tuple(server_payload.get("allowed_origins", ())),
    )

    mcp_payload = payload.get("mcp")
    if mcp_payload is not None and not isinstance(mcp_payload, Mapping):
        raise ValueError("mcp must be a TOML table when configured.")
    mcp = None
    if isinstance(mcp_payload, Mapping):
        mcp = McpUpstreamConfig(
            upstream_url=_required_text(mcp_payload, "upstream_url"),
            passthrough_methods=_string_tuple(
                mcp_payload.get("passthrough_methods", _DEFAULT_MCP_PASSTHROUGH_METHODS)
            ),
        )

    api_payload = payload.get("api")
    if api_payload is not None and not isinstance(api_payload, Mapping):
        raise ValueError("api must be a TOML table when configured.")
    api = None
    if isinstance(api_payload, Mapping):
        api = ApiUpstreamConfig(base_url=_required_text(api_payload, "base_url").rstrip("/"))

    evidence_payload = _mapping(payload.get("evidence", {}), "evidence")
    evidence_root = _resolve_path(base, str(evidence_payload.get("root", ".blackfox-artifacts/wave14/evidence")))
    receipt_database = _resolve_path(
        base,
        str(evidence_payload.get("receipt_database", ".blackfox-artifacts/wave14/authority-receipts.sqlite3")),
    )

    trusted_issuers = tuple(
        TrustedEvidenceIssuer(
            issuer=_required_text(item, "issuer"),
            key_id=_required_text(item, "key_id"),
            secret_env=_required_text(item, "secret_env"),
            allowed_kinds=_string_tuple(item.get("allowed_kinds", ())),
        )
        for item in _mapping_sequence(payload.get("trusted_issuers", []), "trusted_issuers")
    )

    agent_credentials = tuple(
        AgentCredential(
            agent_id=_required_text(item, "agent_id"),
            secret_env=_required_text(item, "secret_env"),
        )
        for item in _mapping_sequence(payload.get("agent_credentials", []), "agent_credentials")
    )

    evidence_policies = tuple(
        EvidencePolicy(
            policy_id=_required_text(item, "policy_id"),
            required_kinds=_string_tuple(item.get("required_kinds", ())),
            human_approval_kind=str(item.get("human_approval_kind", "")),
            target_bound_kinds=_string_tuple(item.get("target_bound_kinds", ())),
            single_use_kinds=_string_tuple(item.get("single_use_kinds", ())),
            accepted_statuses=_string_tuple(
                item.get("accepted_statuses", ("passed", "approved", "verified"))
            ),
            allowed_issuers=_string_tuple(item.get("allowed_issuers", ())),
            human_approval_issuers=_string_tuple(
                item.get("human_approval_issuers", ())
            ),
            max_age_seconds=int(item.get("max_age_seconds", 3600)),
            require_signature=_boolean(item.get("require_signature", True), "require_signature"),
            require_repository_match=_boolean(
                item.get("require_repository_match", True), "require_repository_match"
            ),
            require_revision_match=_boolean(
                item.get("require_revision_match", True), "require_revision_match"
            ),
        )
        for item in _mapping_sequence(payload.get("evidence_policies", []), "evidence_policies")
    )

    routes = tuple(
        ToolRoute(
            tool_name=_required_text(item, "tool_name"),
            capability=ToolCapability(_required_text(item, "capability")),
            repository_id=_required_text(item, "repository_id"),
            path_argument=str(item.get("path_argument", "path")),
            revision_argument=str(item.get("revision_argument", "revision")),
            repository_argument=str(item.get("repository_argument", "")),
            risk_tier=CapabilityRiskTier(str(item.get("risk_tier", "medium"))),
            evidence_policy_id=str(item.get("evidence_policy_id", "")),
            api_method=str(item.get("api_method", "POST")),
            api_path=str(item.get("api_path", "")),
            operating_domain=OperatingDomain(
                str(item.get("operating_domain", OperatingDomain.POLICY_GOVERNED.value))
            ),
            mcp_header_bindings=tuple(
                _parse_mcp_header_binding(binding)
                for binding in _mapping_sequence(
                    item.get("mcp_header_bindings", []),
                    "routes.mcp_header_bindings",
                )
            ),
        )
        for item in _mapping_sequence(payload.get("routes", []), "routes")
    )

    registry = AgentRegistry(
        registry_id=str(payload.get("registry_id", "wave14-live-authority-registry")),
        agents=tuple(
            _parse_agent(item)
            for item in _mapping_sequence(payload.get("agents", []), "agents")
        ),
        metadata={"source": str(source_path)},
    )

    return GatewayConfig(
        source_path=source_path,
        server=server,
        mcp=mcp,
        api=api,
        evidence_root=evidence_root,
        receipt_database=receipt_database,
        trusted_issuers=trusted_issuers,
        agent_credentials=agent_credentials,
        evidence_policies=evidence_policies,
        routes=routes,
        agent_registry=registry,
    )


def _parse_agent(item: Mapping[str, Any]) -> AgentIdentity:
    grants = tuple(
        _parse_grant(grant)
        for grant in _mapping_sequence(item.get("grants", []), "agents.grants")
    )
    return AgentIdentity(
        agent_id=_required_text(item, "agent_id"),
        display_name=_required_text(item, "display_name"),
        kind=AgentKind(_required_text(item, "kind")),
        trust_tier=AgentTrustTier(_required_text(item, "trust_tier")),
        lifecycle_state=AgentLifecycleState(str(item.get("lifecycle_state", "active"))),
        capability_grants=grants,
        issuer=str(item.get("issuer", "gateway-config")),
        subject=str(item.get("subject", item.get("agent_id", ""))),
        metadata=_plain_mapping(item.get("metadata", {}), "agents.metadata"),
    )


def _parse_grant(item: Mapping[str, Any]) -> AgentCapabilityGrant:
    scope_payload = _mapping(item.get("scope", {}), "agents.grants.scope")
    return AgentCapabilityGrant(
        grant_id=_required_text(item, "grant_id"),
        capability=AgentCapability(_required_text(item, "capability")),
        active=_boolean(item.get("active", True), "active"),
        rationale=str(item.get("rationale", "")),
        scope=AgentCapabilityScope(
            repository_ids=_string_tuple(scope_payload.get("repository_ids", ())),
            domains=tuple(
                OperatingDomain(value)
                for value in _string_tuple(scope_payload.get("domains", ()))
            ),
            tool_ids=_string_tuple(scope_payload.get("tool_ids", ())),
            pack_ids=_string_tuple(scope_payload.get("pack_ids", ())),
            path_roots=_string_tuple(scope_payload.get("path_roots", ())),
            max_risk_tier=CapabilityRiskTier(
                str(scope_payload.get("max_risk_tier", "medium"))
            ),
            requires_human_review=_boolean(
                scope_payload.get("requires_human_review", False), "requires_human_review"
            ),
            evidence_artifact_ids=_string_tuple(
                scope_payload.get("evidence_artifact_ids", ())
            ),
            delegated_by=str(scope_payload.get("delegated_by", "")),
            expires_at=str(scope_payload.get("expires_at", "")),
            metadata=_plain_mapping(scope_payload.get("metadata", {}), "scope.metadata"),
        ),
        metadata=_plain_mapping(item.get("metadata", {}), "grant.metadata"),
    )


def _parse_mcp_header_binding(item: Mapping[str, Any]) -> McpParameterHeaderBinding:
    raw_path = item.get("argument_path")
    argument_path: tuple[str, ...]
    if isinstance(raw_path, str):
        argument_path = (raw_path,)
    else:
        argument_path = _string_tuple(raw_path)
    return McpParameterHeaderBinding(
        argument_path=argument_path,
        header_name=_required_text(item, "header_name"),
    )


def _validate_api_path(value: str) -> None:
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError(
            "route.api_path must be an absolute path on the configured API upstream."
        )
    if "://" in value or "?" in value or "#" in value or "\\" in value or "%" in value:
        raise ValueError(
            "route.api_path must be a literal URL path without scheme, query, fragment, "
            "backslashes, or percent encoding."
        )
    parts = tuple(part for part in value.split("/") if part)
    if any(part in {".", ".."} for part in parts):
        raise ValueError("route.api_path must not contain dot path segments.")


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a TOML boolean.")
    return value


def _validate_http_url(value: str, *, label: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{label} must be an absolute http(s) URL.")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not embed credentials in the URL.")


def _normalize_origin(value: str) -> str:
    cleaned = value.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Origin must be an absolute http(s) origin.")
    if parsed.username or parsed.password:
        raise ValueError("Origin must not contain credentials.")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Origin must not contain a path, parameters, query, or fragment.")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a TOML table.")
    return value


def _plain_mapping(value: Any, label: str) -> dict[str, Any]:
    return dict(_mapping(value, label))


def _mapping_sequence(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array of TOML tables.")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"{label}[{index}] must be a TOML table.")
        result.append(item)
    return tuple(result)


def _required_text(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"Required config field {key!r} must be a non-empty string.")
    return item.strip()


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list | tuple):
        raise ValueError("Expected a string array.")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("String arrays may contain only strings.")
        if item.strip():
            result.append(item.strip())
    return tuple(result)
