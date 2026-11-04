from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.authority_crypto.encoding import (
    canonical_bytes,
    read_document,
    strict_json,
)
from ix_blackfox.authority_crypto.verification import verify_bundle, verify_receipt
from ix_blackfox.integration_mesh.audit import AuditRelay
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.operating.models import digest_payload

REVISION = "a" * 40


class Witness(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, root: Path, tokens: dict[str, str]) -> None:
        self.root = root
        self.gateway: LiveAuthorityGateway | None = None
        self.tokens = tokens
        self.commands: list[dict[str, Any]] = []
        self.audit_ids: list[str] = []
        self.audit_events: dict[str, dict[str, Any]] = {}
        self.audit_outage = True
        self.credential_leaks = 0
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        assert isinstance(server, Witness) and server.gateway is not None
        gateway = server.gateway
        assert gateway.receipt_store.signing is not None
        body = strict_json(self.rfile.read(int(self.headers["Content-Length"])))
        assert not self.headers.get("X-BlackFox-Agent-Token")
        assert self.tokens_safe(server)
        if self.path == "/mcp" and body.get("method") in {
            "initialize",
            "notifications/initialized",
            "tools/list",
        }:
            assert (
                self.headers["Authorization"] == "Bearer " + server.tokens["MCP_TOKEN"]
            )
            method = body["method"]
            if method != "initialize":
                assert self.headers["Mcp-Session-Id"] == "mesh-proof-session"
            status = 204 if method == "notifications/initialized" else 200
            result = (
                {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "witness", "version": "1"},
                    },
                }
                if method == "initialize"
                else {"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": []}}
            )
        elif self.path == "/events":
            assert (
                self.headers["Authorization"]
                == "Bearer " + server.tokens["AUDIT_TOKEN"]
            )
            signed = verify_receipt(body["data"], gateway.receipt_store.signing.policy)
            assert signed["receipt_id"] == body["id"]
            server.audit_ids.append(body["id"])
            server.audit_events[body["id"]] = body
            status, result = (
                (503, {"retry": True})
                if server.audit_outage
                else (202, {"accepted": True})
            )
            server.audit_outage = False
        else:
            observer = AuthorityReceiptStore(gateway.config.receipt_database)
            try:
                receipt = observer.get(self.headers["X-BlackFox-Authorization-Receipt"])
            finally:
                observer.close()
            assert receipt is not None
            signed = verify_receipt(receipt, gateway.receipt_store.signing.policy)
            assert signed["record_type"] == "authorization"
            connector = signed["subject"]["metadata"]["integration_connector"]
            assert connector["base_url"].startswith(
                f"http://127.0.0.1:{server.server_port}"
            )
            kind = connector["kind"]
            token_name = {
                "github_check": "GITHUB_TOKEN",
                "jira_issue": "JIRA_BASIC",
                "json": "SERVICE_TOKEN",
                "mcp": "MCP_TOKEN",
            }[kind]
            expected = (
                "Basic " if kind == "jira_issue" else "Bearer "
            ) + server.tokens[token_name]
            assert self.headers["Authorization"] == expected
            arguments = (
                body["params"]["arguments"]
                if kind == "mcp"
                else {"revision": REVISION, "payload": body}
            )
            assert signed["subject"]["arguments_digest"] == digest_payload(arguments)
            if kind == "github_check":
                assert (
                    self.path == "/repos/example/engineering/check-runs"
                    and body["head_sha"] == REVISION
                )
                assert self.headers["X-GitHub-Api-Version"] == "2026-03-10"
            elif kind == "jira_issue":
                assert (
                    self.path == "/rest/api/3/issue"
                    and body["fields"]["project"]["key"] == "ENG"
                )
            elif kind == "mcp":
                assert self.path == "/mcp" and "_meta" not in body["params"]
                assert self.headers["Mcp-Session-Id"] == "mesh-proof-session"
            else:
                assert self.path == "/submit"
            # Persist a tangible provider-side effect after independently witnessing authorization.
            record = {"kind": kind, "authorization": signed["receipt_id"], "body": body}
            server.commands.append(record)
            (server.root / f"provider-record-{len(server.commands)}.json").write_bytes(
                canonical_bytes(record)
            )
            status = 200 if kind == "mcp" else 201
            result = (
                {"jsonrpc": "2.0", "id": body.get("id"), "result": {"recorded": True}}
                if kind == "mcp"
                else {"id": len(server.commands)}
            )
        raw = b"" if status == 204 else canonical_bytes(result)
        self.send_response(status)
        if body.get("method") == "initialize":
            self.send_header("Mcp-Session-Id", "mesh-proof-session")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def tokens_safe(self, server: Witness) -> bool:
        leaked = any(
            value in str(self.headers)
            for name, value in server.tokens.items()
            if name in {"AGENT_TOKEN", "OPERATOR_TOKEN", "CI_KEY", "HUMAN_KEY"}
        )
        server.credential_leaks += int(leaked)
        return not leaked

    def log_message(self, format: str, *args: Any) -> None:
        return


def post(
    url: str, payload: dict[str, Any], headers: dict[str, str]
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=canonical_bytes(payload),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            return response.status, strict_json(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, strict_json(exc.read())


def run(root: Path, samples: int = 25, output: Path | None = None) -> dict[str, Any]:
    output = (output or root / ".blackfox-artifacts/wave17").resolve()
    output.mkdir(parents=True, exist_ok=True)
    names = [
        "SIGNING_PASSWORD",
        "CI_KEY",
        "HUMAN_KEY",
        "AGENT_TOKEN",
        "OPERATOR_TOKEN",
        "GITHUB_TOKEN",
        "JIRA_BASIC",
        "SERVICE_TOKEN",
        "MCP_TOKEN",
        "AUDIT_TOKEN",
    ]
    tokens = {name: secrets.token_hex(32) for name in names}
    previous = {name: os.environ.get("BLACKFOX_" + name) for name in names}
    gateway: LiveAuthorityGateway | None = None
    witness: Witness | None = None
    ingress: BlackFoxGatewayHttpServer | None = None
    checks: dict[str, bool] = {}
    try:
        for name, value in tokens.items():
            os.environ["BLACKFOX_" + name] = value
        with tempfile.TemporaryDirectory(prefix="blackfox-wave17-") as temp:
            work = Path(temp)
            generate_keys(
                work / "receipt-keys",
                "BLACKFOX_SIGNING_PASSWORD",
                "enterprise-authority",
                "wave17-local-proof",
                "enterprise-stream",
            )
            config_path = work / "gateway.toml"
            config_path.write_text(
                (root / "examples/wave17/blackfox.gateway.toml").read_text()
            )
            config = load_gateway_config(config_path)
            assert config.mesh is not None
            witness = Witness(work, tokens)
            threading.Thread(target=witness.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{witness.server_port}"
            mesh = replace(
                config.mesh,
                connectors=tuple(
                    replace(
                        c,
                        base_url=base + ("/mcp" if c.kind == "mcp" else ""),
                        allow_loopback_http=True,
                    )
                    for c in config.mesh.connectors
                ),
                audit_sinks=tuple(
                    replace(s, url=base + "/events", allow_loopback_http=True)
                    for s in config.mesh.audit_sinks
                ),
            )
            gateway = LiveAuthorityGateway.from_config(replace(config, mesh=mesh))
            witness.gateway = gateway
            assert gateway.status()["ready"]
            ingress = BlackFoxGatewayHttpServer(("127.0.0.1", 0), gateway)
            threading.Thread(target=ingress.serve_forever, daemon=True).start()
            url = f"http://127.0.0.1:{ingress.server_port}"

            def approved(
                tool: str,
                body: dict[str, Any],
                key: str,
                protocol: str = "blackfox-api/v1",
            ) -> tuple[dict[str, Any], dict[str, str]]:
                arguments = {"revision": REVISION, "payload": body}
                subject = gateway.build_subject(
                    agent_id="engineering-agent",
                    tool_name=tool,
                    arguments=arguments,
                    protocol=protocol,
                )
                for evidence in [
                    issue_signed_evidence(
                        evidence_id="ci-" + key,
                        kind="test_result",
                        issuer="ci",
                        key_id="ci-hmac-v1",
                        secret=tokens["CI_KEY"].encode(),
                        status="passed",
                        repository_id="example/engineering",
                        revision=REVISION,
                        payload={"passed": True},
                    ),
                    issue_signed_evidence(
                        evidence_id="human-" + key,
                        kind="human_approval",
                        issuer="human-review",
                        key_id="human-hmac-v1",
                        secret=tokens["HUMAN_KEY"].encode(),
                        status="approved",
                        repository_id="example/engineering",
                        revision=REVISION,
                        target_digest=subject.digest,
                        payload={
                            "decision": "approve",
                            "reviewer_kind": "human",
                            "reviewer_id": "local-proof-reviewer",
                        },
                    ),
                ]:
                    gateway.evidence_store.write(evidence)
                return {
                    "agent_id": "engineering-agent",
                    "tool_name": tool,
                    "arguments": arguments,
                    "context": {"evidence_refs": ["ci-" + key, "human-" + key]},
                }, {
                    "X-BlackFox-Agent-Token": tokens["AGENT_TOKEN"],
                    "X-BlackFox-Idempotency-Key": key,
                }

            for tool, body in [
                (
                    "github.create_check_run",
                    {
                        "name": "BlackFox proof",
                        "head_sha": REVISION,
                        "status": "in_progress",
                    },
                ),
                (
                    "jira.create_issue",
                    {
                        "fields": {
                            "project": {"key": "ENG"},
                            "summary": "Review governed change",
                            "issuetype": {"id": "10001"},
                        }
                    },
                ),
                ("service.submit", {"message": "governed submission"}),
            ]:
                payload, headers = approved(tool, body, tool)
                status, _ = post(url + "/v1/invoke", payload, headers)
                checks[tool] = status == 201
            before = len(witness.commands)
            status, _ = post(url + "/v1/invoke", payload, headers)
            checks["duplicate_no_second_effect"] = (
                status == 201 and len(witness.commands) == before
            )
            payload["context"]["evidence_refs"] = []
            status, _ = post(url + "/v1/invoke", payload, headers)
            checks["denied_no_effect"] = (
                status in {403, 428} and len(witness.commands) == before
            )
            lifecycle_headers = {
                "X-BlackFox-Agent-Id": "engineering-agent",
                "X-BlackFox-Agent-Token": tokens["AGENT_TOKEN"],
                "MCP-Protocol-Version": "2025-03-26",
                "Content-Type": "application/json",
            }
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mesh-proof", "version": "1"},
                },
            }
            init_request = urllib.request.Request(
                url + "/mcp/mcp-tools",
                data=canonical_bytes(initialize),
                headers=lifecycle_headers,
                method="POST",
            )
            with urllib.request.urlopen(init_request, timeout=10) as initial:
                session_id = initial.headers.get("Mcp-Session-Id", "")
                checks["named_mcp_initialization"] = (
                    initial.status == 200 and session_id == "mesh-proof-session"
                )
                initial.read()
            lifecycle_headers["Mcp-Session-Id"] = session_id
            status, _ = post(
                url + "/mcp/mcp-tools",
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                lifecycle_headers,
            )
            checks["named_mcp_initialized_notification"] = status == 204
            status, _ = post(
                url + "/mcp/mcp-tools",
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                lifecycle_headers,
            )
            checks["named_mcp_discovery"] = status == 200
            payload, headers = approved(
                "workspace.write",
                {"content": "governed MCP write"},
                "mcp-write",
                "mcp/2025-03-26",
            )
            mcp = {
                "jsonrpc": "2.0",
                "id": 17,
                "method": "tools/call",
                "params": {
                    "name": payload["tool_name"],
                    "arguments": payload["arguments"],
                    "_meta": {
                        "io.ix-blackfox/agentId": payload["agent_id"],
                        "io.ix-blackfox/evidenceRefs": payload["context"][
                            "evidence_refs"
                        ],
                    },
                },
            }
            headers["MCP-Protocol-Version"] = "2025-03-26"
            headers["Mcp-Session-Id"] = session_id
            status, result = post(url + "/mcp/mcp-tools", mcp, headers)
            checks["mcp_named_route"] = (
                status == 200 and result.get("result", {}).get("recorded") is True
            )
            latencies = []
            for index in range(samples):
                payload, headers = approved(
                    "service.submit", {"sample": index}, f"latency-{index}"
                )
                start = time.perf_counter()
                status, _ = post(url + "/v1/invoke", payload, headers)
                latencies.append((time.perf_counter() - start) * 1000)
                assert status == 201
            checks["signed_before_every_effect"] = len(witness.commands) == 4 + samples
            checks["ingress_credentials_never_forwarded"] = (
                witness.credential_leaks == 0
            )
            relay = AuditRelay(mesh, gateway.receipt_store)
            sink = mesh.audit_sinks[0]
            added = relay.sync(sink, 1000)
            first = relay.deliver_one(sink, now=100)
            checks["audit_outage_durable"] = first["state"] == "pending"
            for _ in range(added):
                assert relay.deliver_one(sink, now=200)["state"] == "delivered"
            checks["audit_stable_id_on_retry"] = (
                witness.audit_ids[0] == witness.audit_ids[1]
            )
            checks["all_receipts_delivered"] = len(witness.audit_events) == added
            checks["audit_resync_no_duplicates"] = relay.sync(sink) == 0
            bundle = gateway.receipt_store.export_bundle()
            policy = gateway.receipt_store.signing.policy
            report = verify_bundle(
                bundle, policy, expected_checkpoint=bundle["checkpoint"]
            )
            checks["independent_bundle_verification"] = (
                report.passed and not report.unresolved_authorizations
            )
            for name, value in [
                ("receipt-bundle.json", bundle),
                ("expected-checkpoint.json", bundle["checkpoint"]),
                (
                    "public-trust.json",
                    read_document(work / "receipt-keys/trust-policy.json"),
                ),
            ]:
                (output / name).write_bytes(canonical_bytes(value))
            verify = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ix_blackfox.authority_crypto.cli",
                    "verify",
                    "--bundle",
                    str(output / "receipt-bundle.json"),
                    "--trust-policy",
                    str(output / "public-trust.json"),
                    "--checkpoint",
                    str(output / "expected-checkpoint.json"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            checks["separate_process_public_verifier"] = verify.returncode == 0
            (output / "public-verification.json").write_text(verify.stdout)
            ordered = sorted(latencies)
            result = {
                "schema_version": "wave17.integration_mesh_proof.v1",
                "passed": all(checks.values()),
                "checks": checks,
                "environment": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                },
                "provider_effects": len(witness.commands),
                "audit_unique_receipts": len(witness.audit_events),
                "audit_attempts": len(witness.audit_ids),
                "latency_ms": {
                    "samples": samples,
                    "median": statistics.median(latencies),
                    "p95": ordered[max(0, int(len(ordered) * 0.95 + 0.999) - 1)],
                    "maximum": max(latencies),
                },
                "scope": "Local loopback HTTP, SQLite FULL/WAL, software Ed25519; includes gateway and provider HTTP latency; excludes evidence issuance. No hosted vendor or production-throughput claim.",
            }
            (output / "wave17-integration-mesh-summary.json").write_bytes(
                canonical_bytes(result)
            )
            return result
    finally:
        for server in (ingress, witness):
            if server is not None:
                server.shutdown()
                server.server_close()
        if gateway is not None:
            gateway.receipt_store.close()
        for name, value in previous.items():
            if value is None:
                os.environ.pop("BLACKFOX_" + name, None)
            else:
                os.environ["BLACKFOX_" + name] = value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise the enterprise integration mesh over real local HTTP sockets."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.samples <= 1000:
        parser.error("--samples must be between 1 and 1000")
    result = run(args.root.resolve(), args.samples, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
