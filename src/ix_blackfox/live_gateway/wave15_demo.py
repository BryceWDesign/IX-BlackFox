from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.demo import _DemoUpstream, _http_json, _UpstreamState
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


def run_wave15_demo(root: Path | None = None) -> dict[str, Any]:
    """Prove federated workload identity and delegated authority over real sockets."""

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if root is None:
        temporary = tempfile.TemporaryDirectory(prefix="blackfox-wave15-")
        work_root = Path(temporary.name)
    else:
        work_root = root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    ci_secret = secrets.token_hex(32)
    human_secret = secrets.token_hex(32)
    operator_token = secrets.token_hex(32)
    env_values = {
        "BLACKFOX_W15_CI_KEY": ci_secret,
        "BLACKFOX_W15_HUMAN_KEY": human_secret,
        "BLACKFOX_W15_OPERATOR_TOKEN": operator_token,
    }
    previous_env = {key: os.environ.get(key) for key in env_values}
    os.environ.update(env_values)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "wave15-rsa-1", "alg": "RS256", "use": "sig"})
    jwks_path = work_root / "trusted-jwks.json"
    jwks_path.write_text(json.dumps({"keys": [public_jwk]}, sort_keys=True), encoding="utf-8")

    upstream_root = work_root / "upstream-workspace"
    upstream_root.mkdir(parents=True, exist_ok=True)
    upstream_state = _UpstreamState(root=upstream_root)
    upstream_server = _DemoUpstream(("127.0.0.1", 0), upstream_state)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()
    upstream_port = int(upstream_server.server_address[1])

    gateway_server: BlackFoxGatewayHttpServer | None = None
    try:
        config_path = work_root / "blackfox.wave15.gateway.toml"
        config_path.write_text(_wave15_config(upstream_port, jwks_path), encoding="utf-8")
        gateway = LiveAuthorityGateway.from_config(load_gateway_config(config_path))
        readiness = gateway.status()
        if not readiness["ready"]:
            raise RuntimeError(f"Wave 15 demo gateway is not ready: {readiness}")

        gateway_server = BlackFoxGatewayHttpServer(("127.0.0.1", 0), gateway)
        gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
        gateway_thread.start()
        gateway_port = int(gateway_server.server_address[1])

        now = int(time.time())
        delegation = [
            {
                "delegation_id": "mission-owner-to-agent",
                "delegated_by": "mission-owner",
                "tools": ["filesystem.write_file"],
                "repositories": ["ix-blackfox"],
                "path_roots": ["docs"],
                "expires_at": now + 300,
            }
        ]
        valid_token = _token(
            private_key,
            now=now,
            jti="wave15-valid-jti",
            audience="blackfox-gateway",
            delegation=delegation,
        )
        wrong_audience_token = _token(
            private_key,
            now=now,
            jti="wave15-wrong-aud",
            audience="other-service",
            delegation=delegation,
        )
        expired_token = _token(
            private_key,
            now=now - 900,
            jti="wave15-expired",
            audience="blackfox-gateway",
            delegation=delegation,
            lifetime=60,
        )
        missing_delegation_token = _token(
            private_key,
            now=now,
            jti="wave15-no-delegation",
            audience="blackfox-gateway",
            delegation=[],
        )

        static_rejected = _invoke(gateway_port, "docs/static.txt", "blocked", "rev-15", bearer="", static_token="legacy-static")
        wrong_audience = _invoke(gateway_port, "docs/wrong-aud.txt", "blocked", "rev-15", bearer=wrong_audience_token)
        expired = _invoke(gateway_port, "docs/expired.txt", "blocked", "rev-15", bearer=expired_token)
        missing_delegation = _invoke(
            gateway_port, "docs/no-delegation.txt", "blocked", "rev-15", bearer=missing_delegation_token
        )
        out_of_scope = _invoke(gateway_port, "src/escape.py", "blocked", "rev-15", bearer=valid_token)
        count_after_denials = upstream_state.invocation_count

        principal, principal_error = gateway.authenticate_principal(
            headers={"Authorization": f"Bearer {valid_token}"},
            claimed_agent_id="coding-agent-07",
        )
        if principal is None or principal_error:
            raise RuntimeError(f"Wave 15 principal verification failed: {principal_error}")
        arguments = {"path": "docs/federated.txt", "content": "federated executed", "revision": "rev-15"}
        subject = gateway.build_subject(
            agent_id=principal.agent_id,
            tool_name="filesystem.write_file",
            arguments=arguments,
            protocol="blackfox-api/v1",
            principal=principal,
        )
        test_evidence = issue_signed_evidence(
            evidence_id="wave15-ci-tests",
            kind="test_result",
            issuer="wave15-ci",
            key_id="ci-key",
            secret=ci_secret.encode("utf-8"),
            status="passed",
            repository_id="ix-blackfox",
            revision="rev-15",
            payload={"suite": "wave15-enterprise-identity", "passed": True},
        )
        approval = issue_signed_evidence(
            evidence_id="wave15-human-approval",
            kind="human_approval",
            issuer="wave15-human",
            key_id="human-key",
            secret=human_secret.encode("utf-8"),
            status="approved",
            repository_id="ix-blackfox",
            revision="rev-15",
            target_digest=subject.digest,
            payload={"decision": "approve", "reviewer_kind": "human", "reviewer_id": "wave15.demo"},
        )
        gateway.evidence_store.write(test_evidence)
        gateway.evidence_store.write(approval)
        allowed = _invoke(
            gateway_port,
            arguments["path"],
            arguments["content"],
            arguments["revision"],
            bearer=valid_token,
            evidence=(test_evidence.evidence_id, approval.evidence_id),
        )
        count_after_allow = upstream_state.invocation_count

        gateway.identity_verifier.revocations.revoke(kind="jti", value="wave15-valid-jti")
        revoked = _invoke(gateway_port, "docs/revoked.txt", "blocked", "rev-15", bearer=valid_token)
        count_after_revoked = upstream_state.invocation_count

        output = upstream_root / "docs" / "federated.txt"
        chain = gateway.receipt_store.verify_chain()
        result = {
            "wave": 15,
            "gateway_ready": bool(readiness["ready"]),
            "identity_mode": readiness["identity_mode"],
            "static_credential_status": static_rejected[0],
            "wrong_audience_status": wrong_audience[0],
            "expired_token_status": expired[0],
            "missing_delegation_status": missing_delegation[0],
            "delegation_scope_status": out_of_scope[0],
            "upstream_count_after_denials": count_after_denials,
            "allowed_status": allowed[0],
            "upstream_count_after_allow": count_after_allow,
            "revoked_token_status": revoked[0],
            "upstream_count_after_revocation": count_after_revoked,
            "output_exists": output.is_file(),
            "output_matches": output.is_file() and output.read_text(encoding="utf-8") == "federated executed",
            "identity_context_digest": principal.context_digest,
            "subject_identity_context_digest": str(subject.metadata.get("identity_context_digest", "")),
            "receipt_chain": chain.to_dict(),
        }
        result["passed"] = (
            result["gateway_ready"] is True
            and result["identity_mode"] == "federated_required"
            and static_rejected[0] == 401
            and wrong_audience[0] == 401
            and expired[0] == 401
            and missing_delegation[0] == 401
            and out_of_scope[0] == 403
            and count_after_denials == 0
            and allowed[0] == 200
            and count_after_allow == 1
            and revoked[0] == 401
            and count_after_revoked == 1
            and result["output_matches"] is True
            and result["identity_context_digest"] == result["subject_identity_context_digest"]
            and chain.passed
        )
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


def _token(
    private_key: Any,
    *,
    now: int,
    jti: str,
    audience: str,
    delegation: list[dict[str, Any]],
    lifetime: int = 300,
) -> str:
    return jwt.encode(
        {
            "iss": "https://issuer.blackfox.test",
            "sub": "workload/coding-agent-07",
            "aud": audience,
            "iat": now,
            "nbf": now - 1,
            "exp": now + lifetime,
            "jti": jti,
            "blackfox_delegation": delegation,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "wave15-rsa-1"},
    )


def _invoke(
    port: int,
    path: str,
    content: str,
    revision: str,
    *,
    bearer: str,
    static_token: str = "",
    evidence: tuple[str, ...] = (),
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if static_token:
        headers["X-BlackFox-Agent-Token"] = static_token
    return _http_json(
        port,
        "/v1/invoke",
        {
            "agent_id": "coding-agent-07",
            "tool_name": "filesystem.write_file",
            "arguments": {"path": path, "content": content, "revision": revision},
            "context": {"evidence_refs": list(evidence)},
        },
        headers,
    )


def _wave15_config(upstream_port: int, jwks_path: Path) -> str:
    escaped_jwks = str(jwks_path).replace("\\", "\\\\")
    return f'''registry_id = "wave15-enterprise-identity-registry"

[server]
host = "127.0.0.1"
port = 0
max_request_bytes = 1048576
max_response_bytes = 1048576
upstream_timeout_seconds = 5
operator_token_env = "BLACKFOX_W15_OPERATOR_TOKEN"
allowed_origins = []

[api]
base_url = "http://127.0.0.1:{upstream_port}"

[evidence]
root = ".blackfox-artifacts/wave15/evidence"
receipt_database = ".blackfox-artifacts/wave15/authority-receipts.sqlite3"

[identity]
mode = "federated_required"
require_delegation = true
revocation_database = ".blackfox-artifacts/wave15/identity-revocations.sqlite3"

[[identity_providers]]
issuer = "https://issuer.blackfox.test"
audience = "blackfox-gateway"
jwks_path = "{escaped_jwks}"
algorithms = ["RS256"]
max_token_age_seconds = 600
clock_skew_seconds = 5

[[identity_bindings]]
issuer = "https://issuer.blackfox.test"
subject = "workload/coding-agent-07"
agent_id = "coding-agent-07"

[[trusted_issuers]]
issuer = "wave15-ci"
key_id = "ci-key"
secret_env = "BLACKFOX_W15_CI_KEY"
allowed_kinds = ["test_result"]

[[trusted_issuers]]
issuer = "wave15-human"
key_id = "human-key"
secret_env = "BLACKFOX_W15_HUMAN_KEY"
allowed_kinds = ["human_approval"]

[[evidence_policies]]
policy_id = "protected-write"
required_kinds = ["test_result"]
human_approval_kind = "human_approval"
target_bound_kinds = ["human_approval"]
single_use_kinds = ["human_approval"]
accepted_statuses = ["passed", "approved"]
allowed_issuers = ["wave15-ci", "wave15-human"]
human_approval_issuers = ["wave15-human"]
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

[[agents]]
agent_id = "coding-agent-07"
display_name = "Wave 15 Federated Coding Agent"
kind = "external_agent"
trust_tier = "governed_automation"
lifecycle_state = "active"
issuer = "wave15-demo"
subject = "coding-agent-07"

[[agents.grants]]
grant_id = "write-docs"
capability = "write_workspace"
active = true
rationale = "Federated workload identity with delegated, human-reviewed write authority."

[agents.grants.scope]
repository_ids = ["ix-blackfox"]
tool_ids = ["filesystem.write_file"]
path_roots = ["docs"]
max_risk_tier = "high"
requires_human_review = true
'''
