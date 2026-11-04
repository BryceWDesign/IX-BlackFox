from __future__ import annotations

import ipaddress
import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ix_blackfox.authority_crypto.encoding import digest

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def endpoint(value: str, allow_loopback_http: bool) -> str:
    """Accept fixed HTTPS endpoints, with explicit literal-loopback test support."""
    if (
        any(ord(c) <= 32 or ord(c) >= 127 for c in value)
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
    ):
        raise ValueError("Connector URL must be an ASCII literal without escapes.")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid connector port.") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise ValueError(
            "Connector URL must have a host and no credentials, query or fragment."
        )
    if any(p in {".", ".."} for p in parsed.path.split("/")) or "//" in parsed.path:
        raise ValueError("Connector URL has ambiguous path segments.")
    if parsed.scheme == "https":
        return value.rstrip("/")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = False
    if parsed.scheme != "http" or not (allow_loopback_http and loopback):
        raise ValueError(
            "HTTPS is required except explicitly allowed literal loopback HTTP."
        )
    return value.rstrip("/")


@dataclass(frozen=True, slots=True)
class Connector:
    connector_id: str
    base_url: str
    kind: str = "json"
    credential_env: str = ""
    auth_scheme: str = "Bearer"
    allow_loopback_http: bool = False
    github_api_version: str = "2026-03-10"
    project_key: str = ""

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.connector_id):
            raise ValueError("Invalid connector_id.")
        if self.kind not in {"json", "github_check", "jira_issue", "mcp"}:
            raise ValueError("Unsupported connector kind.")
        if type(self.allow_loopback_http) is not bool:
            raise ValueError("allow_loopback_http must be a boolean.")
        object.__setattr__(
            self, "base_url", endpoint(self.base_url, self.allow_loopback_http)
        )
        if self.credential_env and not _ENV.fullmatch(self.credential_env):
            raise ValueError("Invalid connector credential_env.")
        if self.auth_scheme not in {"Bearer", "Basic"}:
            raise ValueError("Connector auth_scheme must be Bearer or Basic.")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.github_api_version):
            raise ValueError("Invalid GitHub API version.")
        if self.kind == "jira_issue" and not re.fullmatch(
            r"[A-Z][A-Z0-9_]{1,63}", self.project_key
        ):
            raise ValueError("jira_issue requires a fixed project_key.")

    def contract(self) -> dict[str, Any]:
        return asdict(self)

    def headers(self) -> dict[str, str]:
        result = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.credential_env:
            secret = os.environ.get(self.credential_env, "")
            if not secret or any(ord(c) <= 32 or ord(c) >= 127 for c in secret):
                raise ValueError("Connector credential unavailable or invalid.")
            result["Authorization"] = f"{self.auth_scheme} {secret}"
        if self.kind == "github_check":
            result["Accept"] = "application/vnd.github+json"
            result["X-GitHub-Api-Version"] = self.github_api_version
        return result

    def validate_route(self, path: str, method: str, repository: str) -> None:
        if self.kind == "mcp":
            if path or method != "POST":
                raise ValueError("MCP connector routes require POST and no api_path.")
        elif not path:
            raise ValueError("HTTP connector routes require api_path.")
        if self.kind == "github_check" and (
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or path != f"/repos/{repository}/check-runs"
            or method != "POST"
        ):
            raise ValueError(
                "github_check must POST to the configured repository check-runs endpoint."
            )
        if self.kind == "jira_issue" and (
            path != "/rest/api/3/issue" or method != "POST"
        ):
            raise ValueError("jira_issue must POST to /rest/api/3/issue.")

    def validate_body(self, body: dict[str, Any], revision: str) -> None:
        if self.kind == "github_check":
            if (
                not isinstance(body.get("name"), str)
                or not body["name"].strip()
                or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)
                or body.get("head_sha") != revision
            ):
                raise ValueError(
                    "Check run name and exact revision-bound head_sha are required."
                )
        if self.kind == "jira_issue":
            fields = body.get("fields")
            if not isinstance(fields, dict) or fields.get("project") != {
                "key": self.project_key
            }:
                raise ValueError(
                    "Issue project must match the configured project_key exactly."
                )
            if (
                not isinstance(fields.get("summary"), str)
                or not fields["summary"].strip()
            ):
                raise ValueError("Issue summary is required.")
            if not isinstance(fields.get("issuetype"), dict):
                raise ValueError("Issue issuetype is required.")


@dataclass(frozen=True, slots=True)
class AuditSink:
    sink_id: str
    url: str
    credential_env: str = ""
    allow_loopback_http: bool = False
    max_attempts: int = 8

    def __post_init__(self) -> None:
        if type(self.allow_loopback_http) is not bool:
            raise ValueError("allow_loopback_http must be a boolean.")
        if not _NAME.fullmatch(self.sink_id):
            raise ValueError("Invalid audit sink_id.")
        object.__setattr__(self, "url", endpoint(self.url, self.allow_loopback_http))
        if self.credential_env and not _ENV.fullmatch(self.credential_env):
            raise ValueError("Invalid sink credential_env.")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100.")

    @property
    def contract_digest(self) -> str:
        return digest(asdict(self))

    def headers(self) -> dict[str, str]:
        headers = Connector(
            self.sink_id,
            self.url,
            credential_env=self.credential_env,
            allow_loopback_http=self.allow_loopback_http,
        ).headers()
        headers["Content-Type"] = "application/cloudevents+json"
        return headers


@dataclass(frozen=True, slots=True)
class MeshConfig:
    database: Path
    connectors: tuple[Connector, ...]
    audit_sinks: tuple[AuditSink, ...] = ()
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        names = [c.connector_id for c in self.connectors]
        sinks = [s.sink_id for s in self.audit_sinks]
        if len(names) != len(set(names)) or len(sinks) != len(set(sinks)):
            raise ValueError("Mesh connector and sink identifiers must be unique.")
        if (
            isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 300
        ):
            raise ValueError("Mesh timeout_seconds must be finite and at most 300.")

    def connector(self, name: str) -> Connector:
        for connector in self.connectors:
            if connector.connector_id == name:
                return connector
        raise ValueError("Route references an unknown mesh connector.")

    @classmethod
    def parse(cls, payload: Any, base: Path) -> MeshConfig:
        if not isinstance(payload, dict):
            raise ValueError("mesh must be a TOML table.")
        unknown = set(payload) - {
            "database",
            "connectors",
            "audit_sinks",
            "timeout_seconds",
        }
        if unknown:
            raise ValueError(
                "Unknown mesh configuration fields: " + ", ".join(sorted(unknown))
            )

        def entries(
            key: str, model: type[Connector] | type[AuditSink]
        ) -> tuple[Any, ...]:
            raw = payload.get(key, [])
            if not isinstance(raw, list) or any(not isinstance(v, dict) for v in raw):
                raise ValueError(f"mesh.{key} must be an array of tables.")
            return tuple(model(**v) for v in raw)

        raw_timeout = payload.get("timeout_seconds", 15.0)
        if type(raw_timeout) not in {int, float}:
            raise ValueError("mesh.timeout_seconds must be a numeric duration.")
        return cls(
            database=(
                base
                / payload.get("database", ".blackfox-artifacts/wave17/mesh.sqlite3")
            ).resolve(),
            connectors=entries("connectors", Connector),
            audit_sinks=entries("audit_sinks", AuditSink),
            timeout_seconds=float(raw_timeout),
        )
