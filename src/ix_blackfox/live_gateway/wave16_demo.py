from __future__ import annotations

import copy
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    read_document,
    strict_json,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.authority_crypto.verification import verify_bundle, verify_receipt
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.demo import _http_json
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.wave15_demo import _token, _wave15_config
from ix_blackfox.operating.models import digest_payload


class _UnavailableSigner:
    key_id = "wave16-demo-key"
    algorithm = "Ed25519"

    def sign(self, data: bytes) -> bytes:
        raise AuthorityProofError("Deliberate demo signing outage.")


class _WitnessServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, root: Path) -> None:
        self.root = root
        self.store: AuthorityReceiptStore | None = None
        self.policy: TrustPolicy | None = None
        self.invocation_count = 0
        self.verified_before_write = 0
        super().__init__(("127.0.0.1", 0), _WitnessHandler)


class _WitnessHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        if (
            not isinstance(server, _WitnessServer)
            or server.store is None
            or server.policy is None
        ):
            self.send_error(503)
            return
        try:
            payload = strict_json(
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
            )
            arguments = (
                payload["params"]["arguments"] if self.path == "/mcp" else payload
            )
            receipt = server.store.get(
                self.headers.get("X-BlackFox-Authorization-Receipt", "")
            )
            if receipt is None:
                raise AuthorityProofError(
                    "Authorization is not independently visible before dispatch."
                )
            signed = verify_receipt(receipt, server.policy)
            if signed["record_type"] != "authorization" or signed["subject"][
                "arguments_digest"
            ] != digest_payload(arguments):
                raise AuthorityProofError(
                    "Authorization does not cover the dispatched arguments."
                )
            target = (server.root / arguments["path"]).resolve()
            if server.root.resolve() not in target.parents:
                raise AuthorityProofError("Witness rejects path escape.")
            server.verified_before_write += 1
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(arguments["content"], encoding="utf-8")
            server.invocation_count += 1
            result = (
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": "write witnessed"}],
                        "isError": False,
                    },
                }
                if self.path == "/mcp"
                else {"written": arguments["path"]}
            )
            raw = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (ValueError, KeyError, TypeError, OSError):
            self.send_error(403)

    def log_message(self, format: str, *args: Any) -> None:
        return


def run_wave16_demo(root: Path | None = None) -> dict[str, Any]:
    """Real local sockets, committed signed authorization, two witnessed file writes."""
    output = (root.resolve() / ".blackfox-artifacts" / "wave16") if root else None
    checks: dict[str, bool] = {}
    env_values = {
        "BLACKFOX_W15_CI_KEY": secrets.token_hex(32),
        "BLACKFOX_W15_HUMAN_KEY": secrets.token_hex(32),
        "BLACKFOX_W15_OPERATOR_TOKEN": secrets.token_hex(32),
        "BLACKFOX_W16_DEMO_PASSWORD": secrets.token_hex(32),
    }
    previous = {key: os.environ.get(key) for key in env_values}
    os.environ.update(env_values)
    public_files: dict[str, dict[str, Any]] = {}
    try:
        with tempfile.TemporaryDirectory(prefix="blackfox-wave16-") as directory:
            work = Path(directory)
            generate_keys(
                work / "receipt-keys",
                "BLACKFOX_W16_DEMO_PASSWORD",
                "wave16-demo-key",
                "wave16-local-demo",
                "wave16-demo-stream",
            )
            trust_path = work / "receipt-keys" / "trust-policy.json"
            policy = TrustPolicy.load(trust_path)
            idp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            jwk = json.loads(RSAAlgorithm.to_jwk(idp_key.public_key()))
            jwk.update(kid="wave15-rsa-1", alg="RS256", use="sig")
            jwks_path = work / "trusted-jwks.json"
            jwks_path.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")
            upstream = _WitnessServer(work / "upstream")
            upstream_thread = threading.Thread(
                target=upstream.serve_forever, daemon=True
            )
            upstream_thread.start()
            port = int(upstream.server_address[1])
            signing = '\n[receipt_signing]\nprovider = "local"\nkey_id = "wave16-demo-key"\nalgorithm = "Ed25519"\ntrust_policy = "receipt-keys/trust-policy.json"\nprivate_key = "receipt-keys/authority-signing-key.pem"\npassword_env = "BLACKFOX_W16_DEMO_PASSWORD"\n'
            config_path = work / "gateway.toml"
            config_path.write_text(
                _wave15_config(port, jwks_path)
                + f'\n[mcp]\nupstream_url = "http://127.0.0.1:{port}/mcp"\n'
                + signing,
                encoding="utf-8",
            )
            gateway = LiveAuthorityGateway.from_config(load_gateway_config(config_path))
            upstream.store = AuthorityReceiptStore(gateway.config.receipt_database)
            upstream.policy = policy
            server = BlackFoxGatewayHttpServer(("127.0.0.1", 0), gateway)
            gateway_thread = threading.Thread(target=server.serve_forever, daemon=True)
            gateway_thread.start()
            gateway_port = int(server.server_address[1])
            try:
                now = int(time.time())
                token = _token(
                    idp_key,
                    now=now,
                    jti="wave16-live-jti",
                    audience="blackfox-gateway",
                    delegation=[
                        {
                            "delegation_id": "owner-to-agent",
                            "delegated_by": "mission-owner",
                            "tools": ["filesystem.write_file"],
                            "repositories": ["ix-blackfox"],
                            "path_roots": ["docs"],
                            "expires_at": now + 300,
                        }
                    ],
                )
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                principal, error = gateway.authenticate_principal(
                    headers=headers, claimed_agent_id="coding-agent-07"
                )
                if principal is None or error:
                    raise RuntimeError("Demo workload identity did not authenticate.")

                def invoke(
                    path: str,
                    *,
                    evidence: tuple[str, ...] = (),
                    authenticated: bool = True,
                    mcp: bool = False,
                ) -> tuple[int, dict[str, Any]]:
                    args = {
                        "path": path,
                        "content": "wave16 witnessed file write",
                        "revision": "wave16-revision",
                    }
                    payload = (
                        {
                            "jsonrpc": "2.0",
                            "id": 16,
                            "method": "tools/call",
                            "params": {
                                "name": "filesystem.write_file",
                                "arguments": args,
                                "_meta": {
                                    "blackfox": {
                                        "agent_id": "coding-agent-07",
                                        "evidence_refs": list(evidence),
                                    }
                                },
                            },
                        }
                        if mcp
                        else {
                            "agent_id": "coding-agent-07",
                            "tool_name": "filesystem.write_file",
                            "arguments": args,
                            "context": {"evidence_refs": list(evidence)},
                        }
                    )
                    request_headers = (
                        dict(headers)
                        if authenticated
                        else {"Content-Type": "application/json"}
                    )
                    if mcp:
                        request_headers.update(
                            {
                                "MCP-Protocol-Version": "2025-03-26",
                                "X-BlackFox-Agent-Id": "coding-agent-07",
                                "X-BlackFox-Evidence": ",".join(evidence),
                            }
                        )
                    return _http_json(
                        gateway_port,
                        "/mcp" if mcp else "/v1/invoke",
                        payload,
                        request_headers,
                    )

                checks["signer_and_identity_ready"] = gateway.status()["ready"] is True
                unauth = invoke("docs/unauth.txt", authenticated=False)
                missing = invoke("docs/missing.txt")
                scope = invoke("src/escape.py")
                checks["unauthenticated_denied"] = unauth[0] == 401
                checks["missing_evidence_denied"] = missing[0] == 428
                checks["out_of_scope_denied"] = scope[0] == 403
                checks["denials_have_zero_upstream_calls"] = (
                    upstream.invocation_count == 0
                )
                test = issue_signed_evidence(
                    evidence_id="wave16-tests",
                    kind="test_result",
                    issuer="wave15-ci",
                    key_id="ci-key",
                    secret=env_values["BLACKFOX_W15_CI_KEY"].encode(),
                    status="passed",
                    repository_id="ix-blackfox",
                    revision="wave16-revision",
                    payload={"suite": "synthetic-local-demo", "passed": True},
                )
                gateway.evidence_store.write(test)
                allowed: list[tuple[int, dict[str, Any]]] = []
                for protocol, path, approval_id in (
                    ("blackfox-api/v1", "docs/api.txt", "wave16-api-approval"),
                    ("mcp/2025-03-26", "docs/mcp.txt", "wave16-mcp-approval"),
                ):
                    args = {
                        "path": path,
                        "content": "wave16 witnessed file write",
                        "revision": "wave16-revision",
                    }
                    subject = gateway.build_subject(
                        agent_id=principal.agent_id,
                        tool_name="filesystem.write_file",
                        arguments=args,
                        protocol=protocol,
                        principal=principal,
                    )
                    approval = issue_signed_evidence(
                        evidence_id=approval_id,
                        kind="human_approval",
                        issuer="wave15-human",
                        key_id="human-key",
                        secret=env_values["BLACKFOX_W15_HUMAN_KEY"].encode(),
                        status="approved",
                        repository_id="ix-blackfox",
                        revision="wave16-revision",
                        target_digest=subject.digest,
                        payload={
                            "decision": "approve",
                            "reviewer_kind": "human",
                            "reviewer_id": "synthetic-demo-reviewer",
                        },
                    )
                    gateway.evidence_store.write(approval)
                    allowed.append(
                        invoke(
                            path,
                            evidence=(test.evidence_id, approval_id),
                            mcp=protocol.startswith("mcp/"),
                        )
                    )
                checks["api_allowed_write"] = (
                    allowed[0][0] == 200
                    and (upstream.root / "docs/api.txt").read_text()
                    == "wave16 witnessed file write"
                )
                checks["mcp_allowed_write"] = (
                    allowed[1][0] == 200
                    and (upstream.root / "docs/mcp.txt").read_text()
                    == "wave16 witnessed file write"
                )
                checks["signatures_committed_before_both_writes"] = (
                    upstream.verified_before_write == 2
                )
                replay = invoke(
                    "docs/api.txt", evidence=(test.evidence_id, "wave16-api-approval")
                )
                checks["single_use_approval_replay_denied"] = (
                    replay[0] == 409 and upstream.invocation_count == 2
                )
                controller = gateway.receipt_store.signing
                if controller is None:
                    raise RuntimeError("Signed gateway configuration lost.")
                original_signer = controller.signer
                controller.signer = _UnavailableSigner()
                outage = invoke("docs/outage.txt")
                checks["signer_outage_readiness_false"] = (
                    gateway.status()["ready"] is False
                )
                checks["signer_outage_blocks_dispatch"] = (
                    outage[0] == 503
                    and outage[1].get("execution_state") == "not_attempted"
                    and upstream.invocation_count == 2
                )
                controller.signer = original_signer
                gateway.identity_verifier.revocations.revoke(
                    kind="jti", value="wave16-live-jti", reason="demo revocation"
                )
                revoked = invoke("docs/revoked.txt")
                checks["identity_revocation_denied"] = (
                    revoked[0] == 401 and upstream.invocation_count == 2
                )
                bundle = gateway.receipt_store.export_bundle()
                checks["stored_chain_valid"] = (
                    gateway.receipt_store.verify_chain().passed
                )
                checks["bundle_matches_expected_checkpoint"] = verify_bundle(
                    bundle, policy, expected_checkpoint=bundle["checkpoint"]
                ).passed
                tampered = copy.deepcopy(bundle)
                tampered["receipts"][0]["upstream_error"] = "modified"
                checks["tampered_record_rejected"] = not verify_bundle(
                    tampered, policy, expected_checkpoint=bundle["checkpoint"]
                ).passed
                truncated = copy.deepcopy(bundle)
                truncated["receipts"].pop()
                checks["truncated_snapshot_rejected"] = not verify_bundle(
                    truncated, policy, expected_checkpoint=bundle["checkpoint"]
                ).passed
                count = upstream.invocation_count
                public_files = {
                    "authority-bundle.json": bundle,
                    "external-checkpoint.json": bundle["checkpoint"],
                    "trust-policy.json": read_document(trust_path),
                }
            finally:
                server.shutdown()
                server.server_close()
                gateway_thread.join(timeout=5)
                gateway.receipt_store.close()
                upstream.shutdown()
                upstream.server_close()
                upstream_thread.join(timeout=5)
        # No private key, local receipt database or HMAC evidence remains available.
        with tempfile.TemporaryDirectory(
            prefix="blackfox-public-verifier-"
        ) as directory:
            public_root = Path(directory)
            for name, value in public_files.items():
                (public_root / name).write_text(
                    json.dumps(value, sort_keys=True), encoding="utf-8"
                )
            environment = dict(os.environ)
            for key in env_values:
                environment.pop(key, None)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ix_blackfox.authority_crypto.cli",
                    "verify",
                    "--bundle",
                    str(public_root / "authority-bundle.json"),
                    "--trust-policy",
                    str(public_root / "trust-policy.json"),
                    "--checkpoint",
                    str(public_root / "external-checkpoint.json"),
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            checks["standalone_public_verifier_after_private_state_removed"] = (
                result.returncode == 0
                and json.loads(result.stdout).get("passed") is True
            )
        summary = {
            "schema_version": "wave16.crypto_authority_ci_summary.v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "passed": all(checks.values()),
            "checks": checks,
            "check_count": len(checks),
            "receipt_count": len(public_files["authority-bundle.json"]["receipts"]),
            "upstream_invocation_count": count,
            "fixture_scope": "Ephemeral local IdP and synthetic HMAC reviewer/test evidence; real loopback sockets and independently witnessed file writes.",
            "external_services": {
                "aws_kms": "NOT_RUN",
                "physical_hsm": "NOT_RUN",
                "sigstore_issuance": "NOT_RUN",
            },
        }
        if output is not None:
            output.mkdir(parents=True, exist_ok=True)
            for name, value in {
                **public_files,
                "wave16-crypto-authority-summary.json": summary,
            }.items():
                (output / name).write_text(
                    json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
        return summary
    finally:
        for key, previous_value in previous.items():
            if previous_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous_value
