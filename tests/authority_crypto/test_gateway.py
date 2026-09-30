from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from ix_blackfox.authority_crypto.encoding import AuthorityProofError
from ix_blackfox.authority_crypto.signing import SigningController
from ix_blackfox.authority_crypto.verification import verify_bundle, verify_receipt
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.upstream import UpstreamResponse, UpstreamTransportError


@pytest.fixture
def signed_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, controller: SigningController
) -> LiveAuthorityGateway:
    root = Path(__file__).resolve().parents[2]
    for key, value in {
        "BLACKFOX_WAVE14_CI_KEY": "c" * 64,
        "BLACKFOX_WAVE14_HUMAN_KEY": "h" * 64,
        "BLACKFOX_WAVE14_AGENT_TOKEN": "a" * 64,
        "BLACKFOX_WAVE14_OPERATOR_TOKEN": "o" * 64,
    }.items():
        monkeypatch.setenv(key, value)
    config = replace(
        load_gateway_config(root / "examples/wave14/blackfox.gateway.toml"),
        evidence_root=tmp_path / "evidence",
        receipt_database=tmp_path / "receipts.sqlite3",
        identity_revocation_database=tmp_path / "revocations.sqlite3",
    )
    gateway = LiveAuthorityGateway.from_config(config)
    gateway.receipt_store = AuthorityReceiptStore(config.receipt_database, controller)
    return gateway


def request(
    gateway: LiveAuthorityGateway,
    *,
    protocol: str = "blackfox-api/v1",
    approval_id: str = "human-approval",
) -> tuple[dict[str, Any], dict[str, str]]:
    args = {"path": "docs/test.txt", "content": "changed", "revision": "abc123"}
    headers = {"X-BlackFox-Agent-Token": "a" * 64}
    principal, error = gateway.authenticate_principal(
        headers=headers, claimed_agent_id="coding-agent-07"
    )
    assert principal is not None and not error
    subject = gateway.build_subject(
        agent_id=principal.agent_id,
        tool_name="filesystem.write_file",
        arguments=args,
        protocol=protocol,
        principal=principal,
    )
    for evidence in (
        issue_signed_evidence(
            evidence_id="ci-tests",
            kind="test_result",
            issuer="ci",
            key_id="ci-hmac-v1",
            secret=b"c" * 64,
            status="passed",
            repository_id="ix-blackfox",
            revision="abc123",
            payload={"passed": True},
        ),
        issue_signed_evidence(
            evidence_id=approval_id,
            kind="human_approval",
            issuer="human-review",
            key_id="human-hmac-v1",
            secret=b"h" * 64,
            status="approved",
            repository_id="ix-blackfox",
            revision="abc123",
            target_digest=subject.digest,
            payload={
                "decision": "approve",
                "reviewer_kind": "human",
                "reviewer_id": "synthetic-test-reviewer",
            },
        ),
    ):
        gateway.evidence_store.write(evidence)
    return {
        "agent_id": "coding-agent-07",
        "tool_name": "filesystem.write_file",
        "arguments": args,
        "context": {"evidence_refs": ["ci-tests", approval_id]},
    }, headers


class _FailSigner:
    key_id = "test-key"
    algorithm = "Ed25519"

    def sign(self, data: bytes) -> bytes:
        raise AuthorityProofError("Injected provider outage.")


@pytest.mark.parametrize("protocol", ["blackfox-api/v1", "mcp/2025-03-26"])
def test_signed_authorization_is_committed_before_dispatch(
    signed_gateway: LiveAuthorityGateway,
    controller: SigningController,
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
) -> None:
    payload, headers = request(signed_gateway, protocol=protocol)
    calls = []

    def upstream(**kwargs: Any) -> UpstreamResponse:
        independent = AuthorityReceiptStore(signed_gateway.config.receipt_database)
        authorization = independent.get(
            kwargs["headers"]["X-BlackFox-Authorization-Receipt"]
        )
        assert authorization is not None
        assert (
            verify_receipt(authorization, controller.policy)["record_type"]
            == "authorization"
        )
        calls.append(kwargs)
        return UpstreamResponse(
            status=200,
            headers=(("Content-Type", "application/json"),),
            body=b'{"result":{}}',
        )

    monkeypatch.setattr("ix_blackfox.live_gateway.service.request_upstream", upstream)
    if protocol.startswith("mcp"):
        mcp = {
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": payload["tool_name"],
                "arguments": payload["arguments"],
                "_meta": {
                    "io.ix-blackfox/agentId": "coding-agent-07",
                    "io.ix-blackfox/evidenceRefs": payload["context"]["evidence_refs"],
                },
            },
        }
        headers.update({"MCP-Protocol-Version": "2025-03-26"})
        response = signed_gateway.handle_mcp(
            payload=mcp, headers=headers, raw_body=json.dumps(mcp).encode()
        )
    else:
        response = signed_gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 200
    assert len(calls) == 1
    bundle = signed_gateway.receipt_store.export_bundle()
    report = verify_bundle(
        bundle, controller.policy, expected_checkpoint=bundle["checkpoint"]
    )
    assert report.passed and not report.unresolved_authorizations
    assert [r["record_type"] for r in bundle["receipts"]] == [
        "authorization",
        "outcome",
    ]
    assert signed_gateway.receipt_store.verify_chain().passed


def test_signer_outage_blocks_before_dispatch_and_fails_readiness(
    signed_gateway: LiveAuthorityGateway,
    controller: SigningController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, headers = request(signed_gateway)
    controller.signer = _FailSigner()
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: pytest.fail("upstream must not be called"),
    )
    response = signed_gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 503
    assert json.loads(response.body)["execution_state"] == "not_attempted"
    assert not signed_gateway.status()["ready"]
    assert signed_gateway.receipt_store.verify_chain().receipt_count == 0


@pytest.mark.parametrize("after_dispatch", [False, True])
def test_receipt_disk_failure_reports_correct_execution_uncertainty(
    signed_gateway: LiveAuthorityGateway,
    monkeypatch: pytest.MonkeyPatch,
    controller: SigningController,
    after_dispatch: bool,
) -> None:
    payload, headers = request(signed_gateway)
    append = AuthorityReceiptStore.append
    calls = []

    def fail_store(self: AuthorityReceiptStore, body: dict[str, Any]) -> dict[str, Any]:
        if not after_dispatch or body.get("record_type") == "outcome":
            raise sqlite3.OperationalError("Injected disk-full condition")
        return append(self, body)

    def upstream(**kwargs: Any) -> UpstreamResponse:
        calls.append(kwargs)
        return UpstreamResponse(status=200, headers=(), body=b"done")

    monkeypatch.setattr(AuthorityReceiptStore, "append", fail_store)
    monkeypatch.setattr("ix_blackfox.live_gateway.service.request_upstream", upstream)
    response = signed_gateway.handle_api(payload=payload, headers=headers)
    data = json.loads(response.body)
    assert response.status == 503 and data["retry_safe"] is False
    assert data["execution_state"] == (
        "outcome_unknown" if after_dispatch else "not_attempted"
    )
    assert len(calls) == int(after_dispatch)
    if after_dispatch:
        report = verify_bundle(
            signed_gateway.receipt_store.export_bundle(), controller.policy
        )
        assert report.passed and len(report.unresolved_authorizations) == 1
        assert data["authorization_receipt_id"] == report.unresolved_authorizations[0]
    monkeypatch.setattr(AuthorityReceiptStore, "append", append)
    replay = signed_gateway.handle_api(payload=payload, headers=headers)
    assert replay.status == 409
    assert len(calls) == int(after_dispatch)


def test_transport_failure_is_signed_as_unknown(
    signed_gateway: LiveAuthorityGateway,
    monkeypatch: pytest.MonkeyPatch,
    controller: SigningController,
) -> None:
    payload, headers = request(signed_gateway)

    def fail(**kwargs: Any) -> UpstreamResponse:
        raise UpstreamTransportError("Injected connection loss after dispatch")

    monkeypatch.setattr("ix_blackfox.live_gateway.service.request_upstream", fail)
    response = signed_gateway.handle_api(payload=payload, headers=headers)
    assert (
        response.status == 502
        and json.loads(response.body)["execution_state"] == "outcome_unknown"
    )
    bundle = signed_gateway.receipt_store.export_bundle()
    assert verify_bundle(bundle, controller.policy).passed
    assert bundle["receipts"][-1]["executed"] is False


def test_evidence_changes_while_signing_block_dispatch(
    signed_gateway: LiveAuthorityGateway,
    controller: SigningController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, headers = request(signed_gateway)
    original = controller.signer

    class ChangeEvidenceSigner:
        key_id = original.key_id
        algorithm = original.algorithm

        def sign(self, data: bytes) -> bytes:
            for file in signed_gateway.config.evidence_root.rglob("*.json"):
                file.unlink()
            return original.sign(data)

    controller.signer = ChangeEvidenceSigner()
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: pytest.fail("stale evidence must not dispatch"),
    )
    response = signed_gateway.handle_api(payload=payload, headers=headers)
    assert (
        response.status == 503
        and json.loads(response.body)["execution_state"] == "not_attempted"
    )
    assert signed_gateway.receipt_store.verify_chain().receipt_count == 1


def test_signed_denial_has_zero_upstream_calls(
    signed_gateway: LiveAuthorityGateway,
    controller: SigningController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, _ = request(signed_gateway)
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: pytest.fail("unauthenticated dispatch"),
    )
    assert signed_gateway.handle_api(payload=payload, headers={}).status == 401
    denial = signed_gateway.receipt_store.recent()[0]
    assert verify_receipt(denial, controller.policy)["record_type"] == "denial"


def test_http_duplicate_argument_rejected_before_authentication_or_dispatch(
    signed_gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    import http.client
    import threading

    from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer

    payload, headers = request(signed_gateway)
    raw = (
        json.dumps(payload)
        .replace(
            '"path": "docs/test.txt"',
            '"path": "src/escape.py", "path": "docs/test.txt"',
        )
        .encode()
    )
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: pytest.fail("duplicate JSON cannot dispatch"),
    )
    server = BlackFoxGatewayHttpServer(("127.0.0.1", 0), signed_gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=10
    )
    try:
        connection.request(
            "POST",
            "/v1/invoke",
            raw,
            headers={**headers, "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 400
        response.read()
        assert signed_gateway.receipt_store.verify_chain().receipt_count == 0
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_signed_mcp_rejects_transport_body_mismatch(
    signed_gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = request(signed_gateway, protocol="mcp/2025-03-26")
    mcp = {
        "jsonrpc": "2.0",
        "id": 16,
        "method": "tools/call",
        "params": {"name": payload["tool_name"], "arguments": payload["arguments"]},
    }
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: pytest.fail("unbound body must not dispatch"),
    )
    changed = {
        **mcp,
        "params": {
            "name": payload["tool_name"],
            "arguments": {"path": "src/escape.py"},
        },
    }
    response = signed_gateway.handle_mcp(
        payload=mcp, headers=headers, raw_body=json.dumps(changed).encode()
    )
    assert (
        response.status == 503
        and signed_gateway.receipt_store.verify_chain().receipt_count == 0
    )
