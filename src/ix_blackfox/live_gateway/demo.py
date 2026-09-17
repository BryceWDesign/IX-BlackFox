from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


@dataclass(slots=True)
class _UpstreamState:
    root: Path
    invocation_count: int = 0


class _DemoUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: _UpstreamState) -> None:
        self.state = state
        super().__init__(address, _DemoUpstreamHandler)


class _DemoUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        if not isinstance(server, _DemoUpstream):
            self.send_error(500)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "invalid json"})
            return
        server.state.invocation_count += 1

        if self.path == "/mcp":
            if not isinstance(payload, dict):
                self._json(400, {"error": "invalid request"})
                return
            params = payload.get("params", {})
            arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
            self._perform_write(server.state, arguments)
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": "upstream write executed"}],
                        "isError": False,
                    },
                },
            )
            return
        if self.path == "/tools/write":
            if not isinstance(payload, dict):
                self._json(400, {"error": "invalid request"})
                return
            self._perform_write(server.state, payload)
            self._json(200, {"written": payload.get("path", "")})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _perform_write(self, state: _UpstreamState, arguments: Any) -> None:
        if not isinstance(arguments, dict):
            return
        path_value = arguments.get("path")
        content = arguments.get("content", "")
        if not isinstance(path_value, str) or not path_value:
            return
        target = (state.root / path_value).resolve()
        if state.root.resolve() not in target.parents:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content), encoding="utf-8")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def run_demo(root: Path | None = None) -> dict[str, Any]:
    """Run the Wave 14 proof over real local HTTP sockets and upstream side effects."""

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if root is None:
        temporary = tempfile.TemporaryDirectory(prefix="blackfox-wave14-")
        work_root = Path(temporary.name)
    else:
        work_root = root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    demo_ci_secret = secrets.token_hex(32)
    demo_human_secret = secrets.token_hex(32)
    demo_agent_token = secrets.token_hex(32)
    demo_operator_token = secrets.token_hex(32)
    env_values = {
        "BLACKFOX_DEMO_CI_KEY": demo_ci_secret,
        "BLACKFOX_DEMO_HUMAN_KEY": demo_human_secret,
        "BLACKFOX_DEMO_AGENT_TOKEN": demo_agent_token,
        "BLACKFOX_DEMO_OPERATOR_TOKEN": demo_operator_token,
    }
    previous_env = {key: os.environ.get(key) for key in env_values}
    os.environ.update(env_values)

    upstream_root = work_root / "upstream-workspace"
    upstream_root.mkdir(parents=True, exist_ok=True)
    upstream_state = _UpstreamState(root=upstream_root)
    upstream_server = _DemoUpstream(("127.0.0.1", 0), upstream_state)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()
    upstream_port = int(upstream_server.server_address[1])

    gateway_server: BlackFoxGatewayHttpServer | None = None
    try:
        config_path = work_root / "blackfox.gateway.toml"
        config_path.write_text(_demo_config(upstream_port), encoding="utf-8")
        gateway = LiveAuthorityGateway.from_config(load_gateway_config(config_path))
        readiness = gateway.status()
        if not readiness["ready"]:
            raise RuntimeError(f"Wave 14 demo gateway is not ready: {readiness}")

        gateway_server = BlackFoxGatewayHttpServer(("127.0.0.1", 0), gateway)
        gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
        gateway_thread.start()
        gateway_port = int(gateway_server.server_address[1])

        revision = "demo-revision-001"
        unauthenticated = _mcp_call(
            gateway_port,
            request_id=0,
            path="docs/unauthenticated.txt",
            content="must not execute",
            revision=revision,
            evidence=(),
            agent_token="",
        )
        after_auth_block = upstream_state.invocation_count

        origin_blocked = _mcp_call(
            gateway_port,
            request_id=10,
            path="docs/origin-blocked.txt",
            content="must not execute",
            revision=revision,
            evidence=(),
            agent_token=demo_agent_token,
            extra_headers={"Origin": "https://attacker.example"},
        )
        after_origin_block = upstream_state.invocation_count

        blocked = _mcp_call(
            gateway_port,
            request_id=1,
            path="src/forbidden.py",
            content="must not execute",
            revision=revision,
            evidence=(),
            agent_token=demo_agent_token,
        )
        after_scope_block = upstream_state.invocation_count

        missing_evidence = _mcp_call(
            gateway_port,
            request_id=2,
            path="docs/allowed.txt",
            content="still must not execute",
            revision=revision,
            evidence=(),
            agent_token=demo_agent_token,
        )
        after_evidence_block = upstream_state.invocation_count

        test_evidence = issue_signed_evidence(
            evidence_id="demo-ci-tests",
            kind="test_result",
            issuer="demo-ci",
            key_id="ci-key",
            secret=demo_ci_secret.encode("utf-8"),
            status="passed",
            repository_id="ix-blackfox",
            revision=revision,
            payload={"suite": "wave14-demo", "passed": True},
        )
        gateway.evidence_store.write(test_evidence)

        mcp_arguments = {
            "path": "docs/allowed.txt",
            "content": "mcp executed",
            "revision": revision,
        }
        mcp_subject = gateway.build_subject(
            agent_id="coding-agent-07",
            tool_name="filesystem.write_file",
            arguments=mcp_arguments,
            protocol="mcp/2026-07-28",
        )
        mcp_approval = issue_signed_evidence(
            evidence_id="demo-human-mcp-approval",
            kind="human_approval",
            issuer="demo-human",
            key_id="human-key",
            secret=demo_human_secret.encode("utf-8"),
            status="approved",
            repository_id="ix-blackfox",
            revision=revision,
            target_digest=mcp_subject.digest,
            payload={
                "decision": "approve",
                "reviewer_kind": "human",
                "reviewer_id": "maintainer.demo",
            },
        )
        gateway.evidence_store.write(mcp_approval)
        allowed_mcp = _mcp_call(
            gateway_port,
            request_id=3,
            path=mcp_arguments["path"],
            content=mcp_arguments["content"],
            revision=revision,
            evidence=(test_evidence.evidence_id, mcp_approval.evidence_id),
            agent_token=demo_agent_token,
        )
        after_mcp_allow = upstream_state.invocation_count

        replayed_mcp = _mcp_call(
            gateway_port,
            request_id=4,
            path=mcp_arguments["path"],
            content=mcp_arguments["content"],
            revision=revision,
            evidence=(test_evidence.evidence_id, mcp_approval.evidence_id),
            agent_token=demo_agent_token,
        )
        after_replay_block = upstream_state.invocation_count

        api_arguments = {
            "path": "docs/api-allowed.txt",
            "content": "api executed",
            "revision": revision,
        }
        api_subject = gateway.build_subject(
            agent_id="coding-agent-07",
            tool_name="filesystem.write_file",
            arguments=api_arguments,
            protocol="blackfox-api/v1",
        )
        api_approval = issue_signed_evidence(
            evidence_id="demo-human-api-approval",
            kind="human_approval",
            issuer="demo-human",
            key_id="human-key",
            secret=demo_human_secret.encode("utf-8"),
            status="approved",
            repository_id="ix-blackfox",
            revision=revision,
            target_digest=api_subject.digest,
            payload={
                "decision": "approve",
                "reviewer_kind": "human",
                "reviewer_id": "maintainer.demo",
            },
        )
        gateway.evidence_store.write(api_approval)
        allowed_api = _api_call(
            gateway_port,
            api_arguments,
            evidence=(test_evidence.evidence_id, api_approval.evidence_id),
            agent_token=demo_agent_token,
        )
        after_api_allow = upstream_state.invocation_count

        unauthenticated_receipts = _http_get_json(gateway_port, "/v1/receipts/verify", {})
        operator_receipts = _http_get_json(
            gateway_port,
            "/v1/receipts/verify",
            {"X-BlackFox-Operator-Token": demo_operator_token},
        )
        chain = gateway.receipt_store.verify_chain()
        mcp_output = upstream_root / "docs" / "allowed.txt"
        api_output = upstream_root / "docs" / "api-allowed.txt"
        result = {
            "wave": 14,
            "gateway_ready": bool(readiness["ready"]),
            "auth_block_http_status": unauthenticated[0],
            "auth_block_upstream_count": after_auth_block,
            "origin_block_http_status": origin_blocked[0],
            "origin_block_upstream_count": after_origin_block,
            "scope_block_http_status": blocked[0],
            "scope_block_upstream_count": after_scope_block,
            "evidence_block_http_status": missing_evidence[0],
            "evidence_block_upstream_count": after_evidence_block,
            "mcp_allow_http_status": allowed_mcp[0],
            "mcp_allow_upstream_count": after_mcp_allow,
            "replay_block_http_status": replayed_mcp[0],
            "replay_block_upstream_count": after_replay_block,
            "api_allow_http_status": allowed_api[0],
            "api_allow_upstream_count": after_api_allow,
            "mcp_output_exists": mcp_output.is_file(),
            "mcp_output_matches": mcp_output.is_file()
            and mcp_output.read_text(encoding="utf-8") == "mcp executed",
            "api_output_exists": api_output.is_file(),
            "api_output_matches": api_output.is_file()
            and api_output.read_text(encoding="utf-8") == "api executed",
            "unauthenticated_receipt_inspection_status": unauthenticated_receipts[0],
            "operator_receipt_inspection_status": operator_receipts[0],
            "receipt_chain": chain.to_dict(),
            "passed": (
                readiness["ready"] is True
                and unauthenticated[0] == 401
                and after_auth_block == 0
                and origin_blocked[0] == 403
                and after_origin_block == 0
                and blocked[0] == 403
                and after_scope_block == 0
                and missing_evidence[0] == 428
                and after_evidence_block == 0
                and allowed_mcp[0] == 200
                and after_mcp_allow == 1
                and replayed_mcp[0] == 409
                and after_replay_block == 1
                and allowed_api[0] == 200
                and after_api_allow == 2
                and mcp_output.is_file()
                and mcp_output.read_text(encoding="utf-8") == "mcp executed"
                and api_output.is_file()
                and api_output.read_text(encoding="utf-8") == "api executed"
                and unauthenticated_receipts[0] == 401
                and operator_receipts[0] == 200
                and bool(operator_receipts[1].get("passed"))
                and chain.passed
            ),
        }
        return result
    finally:
        if gateway_server is not None:
            gateway_server.shutdown()
            gateway_server.server_close()
        upstream_server.shutdown()
        upstream_server.server_close()
        for key, previous in previous_env.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        if temporary is not None:
            temporary.cleanup()


def _mcp_call(
    port: int,
    *,
    request_id: int,
    path: str,
    content: str,
    revision: str,
    evidence: tuple[str, ...],
    agent_token: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": "filesystem.write_file",
            "arguments": {"path": path, "content": content, "revision": revision},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "wave14-demo", "version": "1.0"},
                "io.ix-blackfox/agentId": "coding-agent-07",
                "io.ix-blackfox/evidenceRefs": list(evidence),
            },
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "filesystem.write_file",
        "Mcp-Param-Revision": revision,
    }
    if extra_headers:
        headers.update(extra_headers)
    if agent_token:
        headers["X-BlackFox-Agent-Token"] = agent_token
    return _http_json(port, "/mcp", payload, headers)


def _api_call(
    port: int,
    arguments: dict[str, Any],
    *,
    evidence: tuple[str, ...],
    agent_token: str,
) -> tuple[int, dict[str, Any]]:
    payload = {
        "agent_id": "coding-agent-07",
        "tool_name": "filesystem.write_file",
        "arguments": arguments,
        "context": {"evidence_refs": list(evidence)},
    }
    return _http_json(
        port,
        "/v1/invoke",
        payload,
        {
            "Content-Type": "application/json",
            "X-BlackFox-Agent-Token": agent_token,
        },
    )


def _http_json(
    port: int,
    path: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers=headers,
        method="POST",
    )
    return _urlopen_json(request)


def _http_get_json(
    port: int,
    path: str,
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers=headers,
        method="GET",
    )
    return _urlopen_json(request)


def _urlopen_json(request: urllib.request.Request) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = int(response.status)
            raw = response.read()
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read()
    decoded = json.loads(raw.decode("utf-8"))
    return status, dict(decoded) if isinstance(decoded, dict) else {"value": decoded}


def _demo_config(upstream_port: int) -> str:
    return f'''\
registry_id = "wave14-demo-registry"

[server]
host = "127.0.0.1"
port = 0
max_request_bytes = 1048576
max_response_bytes = 1048576
upstream_timeout_seconds = 5
operator_token_env = "BLACKFOX_DEMO_OPERATOR_TOKEN"
allowed_origins = []

[mcp]
upstream_url = "http://127.0.0.1:{upstream_port}/mcp"
passthrough_methods = ["initialize", "notifications/initialized", "ping", "server/discover", "tools/list"]

[api]
base_url = "http://127.0.0.1:{upstream_port}"

[evidence]
root = ".blackfox-artifacts/wave14/evidence"
receipt_database = ".blackfox-artifacts/wave14/authority-receipts.sqlite3"

[[trusted_issuers]]
issuer = "demo-ci"
key_id = "ci-key"
secret_env = "BLACKFOX_DEMO_CI_KEY"
allowed_kinds = ["test_result"]

[[trusted_issuers]]
issuer = "demo-human"
key_id = "human-key"
secret_env = "BLACKFOX_DEMO_HUMAN_KEY"
allowed_kinds = ["human_approval"]

[[agent_credentials]]
agent_id = "coding-agent-07"
secret_env = "BLACKFOX_DEMO_AGENT_TOKEN"

[[evidence_policies]]
policy_id = "protected-write"
required_kinds = ["test_result"]
human_approval_kind = "human_approval"
target_bound_kinds = ["human_approval"]
single_use_kinds = ["human_approval"]
accepted_statuses = ["passed", "approved"]
allowed_issuers = ["demo-ci", "demo-human"]
human_approval_issuers = ["demo-human"]
max_age_seconds = 3600
require_signature = true
require_repository_match = true
require_revision_match = true

[[routes]]
tool_name = "filesystem.write_file"
capability = "file_write"
repository_id = "ix-blackfox"
path_argument = "path"
revision_argument = "revision"
risk_tier = "high"
evidence_policy_id = "protected-write"
api_method = "POST"
api_path = "/tools/write"
operating_domain = "policy_governed"

[[routes.mcp_header_bindings]]
argument_path = ["revision"]
header_name = "Revision"

[[agents]]
agent_id = "coding-agent-07"
display_name = "Wave 14 Demo Coding Agent"
kind = "external_agent"
trust_tier = "governed_automation"
lifecycle_state = "active"
issuer = "wave14-demo"
subject = "coding-agent-07"

[[agents.grants]]
grant_id = "write-docs"
capability = "write_workspace"
active = true
rationale = "Bounded demo write authority requiring human review."

[agents.grants.scope]
repository_ids = ["ix-blackfox"]
tool_ids = ["filesystem.write_file"]
path_roots = ["docs"]
max_risk_tier = "high"
requires_human_review = true
'''
