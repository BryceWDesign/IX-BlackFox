from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest

from ix_blackfox.authority_crypto.encoding import AuthorityProofError
from ix_blackfox.authority_crypto.verification import verify_bundle, verify_receipt
from ix_blackfox.integration_mesh.ledger import MeshLedger
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.upstream import UpstreamResponse, UpstreamTransportError

from .conftest import REVISION, authorized


@pytest.mark.parametrize(
    ("tool", "body", "path", "auth"),
    [
        ("service.submit", {"x": 3}, "/submit", "Bearer " + "s" * 64),
        (
            "github.create_check_run",
            {"name": "BlackFox", "head_sha": REVISION, "status": "in_progress"},
            "/repos/example/engineering/check-runs",
            "Bearer " + "g" * 64,
        ),
        (
            "jira.create_issue",
            {
                "fields": {
                    "project": {"key": "ENG"},
                    "summary": "Review",
                    "issuetype": {"id": "10001"},
                }
            },
            "/rest/api/3/issue",
            "Basic " + "j" * 64,
        ),
    ],
)
def test_native_routing_signs_before_dispatch_and_separates_credentials(
    gateway: LiveAuthorityGateway,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    body: dict[str, Any],
    path: str,
    auth: str,
) -> None:
    payload, headers = authorized(gateway, tool, body=body)
    seen = []

    def send(**kwargs: Any) -> UpstreamResponse:
        seen.append(kwargs)
        assert kwargs["url"] == "http://127.0.0.1:1" + path
        assert json.loads(kwargs["body"]) == body
        assert kwargs["headers"]["Authorization"] == auth
        assert "X-BlackFox-Agent-Token" not in kwargs["headers"]
        receipt = gateway.receipt_store.get(
            kwargs["headers"]["X-BlackFox-Authorization-Receipt"]
        )
        assert receipt is not None and gateway.receipt_store.signing is not None
        signed = verify_receipt(receipt, gateway.receipt_store.signing.policy)
        assert signed["record_type"] == "authorization"
        assert (
            signed["subject"]["metadata"]["integration_connector"]["connector_id"]
            == gateway.config.route_for(tool).connector_id
        )
        if tool.startswith("github"):
            assert kwargs["headers"]["X-GitHub-Api-Version"] == "2026-03-10"
        return UpstreamResponse(
            201, (("Content-Type", "application/json"),), b'{"id":42}'
        )

    monkeypatch.setattr("ix_blackfox.integration_mesh.runtime.request_upstream", send)
    response = gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 201 and len(seen) == 1
    bundle = gateway.receipt_store.export_bundle()
    assert verify_bundle(bundle, gateway.receipt_store.signing.policy).passed
    again = gateway.handle_api(payload=payload, headers=headers)
    assert again.status == 201 and len(seen) == 1
    assert dict(again.headers)["X-BlackFox-Replayed"] == "true"


def test_idempotency_survives_restart_and_changed_payload_conflicts(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    calls = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: (calls.append(kw) or UpstreamResponse(200, (), b"{}")),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 200
    restarted = LiveAuthorityGateway.from_config(gateway.config)
    try:
        assert restarted.handle_api(payload=payload, headers=headers).status == 200
        changed, _ = authorized(restarted, body={"changed": True}, approval="human-2")
        assert restarted.handle_api(payload=changed, headers=headers).status == 409
        assert len(calls) == 1
    finally:
        restarted.receipt_store.close()


def test_concurrent_same_key_gets_one_attempt(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def send(**kw: Any) -> UpstreamResponse:
        calls.append(kw)
        entered.set()
        assert release.wait(5)
        return UpstreamResponse(200, (), b"{}")

    monkeypatch.setattr("ix_blackfox.integration_mesh.runtime.request_upstream", send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(gateway.handle_api, payload=payload, headers=headers)
        try:
            assert entered.wait(5)
            assert gateway.handle_api(payload=payload, headers=headers).status == 409
        finally:
            release.set()
        assert future.result().status == 200
    assert len(calls) == 1


def test_transport_ambiguity_never_reexecutes(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    calls = []

    def send(**kw: Any) -> UpstreamResponse:
        calls.append(kw)
        raise UpstreamTransportError("secret-token-must-not-escape")

    monkeypatch.setattr("ix_blackfox.integration_mesh.runtime.request_upstream", send)
    response = gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 502 and b"secret-token" not in response.body
    assert json.loads(response.body)["execution_state"] == "outcome_unknown"
    assert gateway.handle_api(payload=payload, headers=headers).status == 409
    assert len(calls) == 1
    assert gateway.receipt_store.recent()[0]["execution_state"] == "outcome_unknown"


@pytest.mark.parametrize(
    "failure",
    [
        "missing_key",
        "missing_evidence",
        "bad_auth",
        "credential_reuse",
        "missing_credential",
        "bad_payload",
        "signer_outage",
    ],
)
def test_failures_do_not_dispatch(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    payload, headers = authorized(gateway)
    if failure == "missing_key":
        headers.pop("X-BlackFox-Idempotency-Key")
    if failure == "missing_evidence":
        payload["context"]["evidence_refs"] = []
    if failure == "bad_auth":
        headers["X-BlackFox-Agent-Token"] = "wrong"
    if failure == "credential_reuse":
        monkeypatch.setenv("BLACKFOX_SERVICE_TOKEN", "a" * 64)
    if failure == "missing_credential":
        monkeypatch.delenv("BLACKFOX_SERVICE_TOKEN")
    if failure == "bad_payload":
        payload, headers = authorized(
            gateway,
            "github.create_check_run",
            body={"name": "wrong-revision", "head_sha": "b" * 40},
        )
    if failure == "signer_outage":
        monkeypatch.setattr(
            gateway.receipt_store.signing,
            "envelope",
            lambda *_: (_ for _ in ()).throw(AuthorityProofError("unavailable")),
        )
    calls = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: calls.append(kw),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status >= 400
    assert not calls


def test_changed_destination_invalidates_approval(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    mesh = gateway.config.mesh
    assert mesh is not None
    gateway.config = replace(
        gateway.config,
        mesh=replace(
            mesh,
            connectors=tuple(
                replace(c, base_url="http://127.0.0.1:2")
                if c.connector_id == "service"
                else c
                for c in mesh.connectors
            ),
        ),
    )
    calls = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: calls.append(kw),
    )
    assert (
        gateway.handle_api(payload=payload, headers=headers).status >= 400 and not calls
    )


def test_mcp_routes_to_named_service_without_ingress_metadata(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway, "workspace.write", protocol="mcp/2025-03-26")
    mcp = {
        "jsonrpc": "2.0",
        "id": 17,
        "method": "tools/call",
        "params": {
            "name": payload["tool_name"],
            "arguments": payload["arguments"],
            "_meta": {
                "io.ix-blackfox/agentId": payload["agent_id"],
                "io.ix-blackfox/evidenceRefs": payload["context"]["evidence_refs"],
            },
        },
    }
    headers["MCP-Protocol-Version"] = "2025-03-26"
    seen = []

    def send(**kw: Any) -> UpstreamResponse:
        seen.append(kw)
        assert kw["url"] == "http://127.0.0.1:1/mcp"
        assert "_meta" not in json.loads(kw["body"])["params"]
        assert kw["headers"]["Authorization"] == "Bearer " + "m" * 64
        return UpstreamResponse(
            200, (), b'{"jsonrpc":"2.0","id":17,"result":{"ok":true}}'
        )

    monkeypatch.setattr("ix_blackfox.integration_mesh.runtime.request_upstream", send)
    assert (
        gateway.handle_mcp(
            payload=mcp, headers=headers, raw_body=json.dumps(mcp).encode()
        ).status
        == 200
    )
    mcp["id"] = 18
    replay = gateway.handle_mcp(
        payload=mcp, headers=headers, raw_body=json.dumps(mcp).encode()
    )
    assert (
        replay.status == 200 and json.loads(replay.body)["id"] == 18 and len(seen) == 1
    )


def test_ledger_reservations_are_atomic_across_connections(tmp_path: Any) -> None:
    path = tmp_path / "mesh.sqlite3"
    ledger = MeshLedger(path)

    def reserve(_: int) -> str:
        return MeshLedger(path).reserve("same-key", "same-subject")[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(40)))
    assert results.count("new") == 1 and results.count("reserved") == 39
    assert ledger.reserve("same-key", "other-subject")[0] == "conflict"


def test_failure_to_cache_after_dispatch_reports_unknown_and_blocks_retry(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    calls = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: (calls.append(kw) or UpstreamResponse(201, (), b"{}")),
    )

    def fail(*_: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(MeshLedger, "complete", fail)
    response = gateway.handle_api(payload=payload, headers=headers)
    assert (
        response.status == 503
        and json.loads(response.body)["execution_state"] == "outcome_unknown"
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 409
    assert len(calls) == 1


def test_mutated_cached_body_is_rejected_before_returning_a_forged_result(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b'{"id":42}'),
    )
    response = gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 201
    assert gateway.config.mesh is not None
    with MeshLedger(gateway.config.mesh.database).connect() as db:
        row = db.execute("SELECT response_json FROM mesh_requests").fetchone()
        cached = json.loads(row[0])
        import base64

        cached["body_base64"] = base64.b64encode(b'{"id":999}').decode()
        db.execute("UPDATE mesh_requests SET response_json=?", (json.dumps(cached),))
    response = gateway.handle_api(payload=payload, headers=headers)
    assert response.status == 503 and b"999" not in response.body


def test_cached_result_still_requires_current_authority(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b"{}"),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 201
    headers["X-BlackFox-Agent-Token"] = "revoked"
    assert gateway.handle_api(payload=payload, headers=headers).status == 401


def test_jira_project_escape_and_wrong_transport_do_not_dispatch(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(
        gateway,
        "jira.create_issue",
        body={
            "fields": {
                "project": {"key": "OTHER"},
                "summary": "escape",
                "issuetype": {"id": "1"},
            }
        },
    )
    calls = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **kw: calls.append(kw),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status >= 400
    payload, headers = authorized(gateway, "workspace.write", approval="human-2")
    assert gateway.handle_api(payload=payload, headers=headers).status == 400
    assert not calls


def test_no_content_upstream_returns_readable_api_observation(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(204, (), b""),
    )
    response = gateway.handle_api(payload=payload, headers=headers)
    assert (
        response.status == 200 and json.loads(response.body)["upstream_status"] == 204
    )


def test_malformed_cache_is_a_controlled_failure(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b"{}"),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 201
    assert gateway.config.mesh is not None
    with MeshLedger(gateway.config.mesh.database).connect() as db:
        db.execute(
            "UPDATE mesh_requests SET response_json=?",
            ('{"body_base64":"not-base64"}',),
        )
    assert gateway.handle_api(payload=payload, headers=headers).status == 503
