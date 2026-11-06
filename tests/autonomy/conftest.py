from __future__ import annotations

import os
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.authority_crypto.encoding import canonical_bytes, strict_json
from ix_blackfox.authority_crypto.verification import verify_receipt
from ix_blackfox.live_gateway.config import GatewayConfig, load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway

ROOT = Path(__file__).resolve().parents[2]
OP = {"operation_id": "release-1"}
REVISION = "a" * 40
FIRST = {**OP, "step_id": "stage"}
SECOND = {**OP, "step_id": "publish"}
AGENTS = {
    "stage": {"X-BlackFox-Agent-Token": "a" * 64},
    "publish": {"X-BlackFox-Agent-Token": "b" * 64},
}
OPERATOR = {"X-BlackFox-Operator-Token": "o" * 64}


def future(seconds: int = 300) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def plan(**changes: Any) -> dict[str, Any]:
    steps = [
        {
            "step_id": step,
            "agent_id": agent,
            "tool_name": tool,
            "arguments": {"revision": REVISION, "payload": {"state": result}},
            "depends_on": depends,
            "preconditions": {"freeze": False},
            "expected_outcome": {"state": result},
            "cost": 2,
            "recovery": {
                "instruction": "Restore the previous provider state and verify it.",
                "expected_outcome": {"state": "restored"},
            },
        }
        for step, agent, tool, depends, result in [
            ("stage", "engineering-agent", "service.submit", [], "staged"),
            ("publish", "release-agent", "service.publish", ["stage"], "published"),
        ]
    ]
    return {
        **OP,
        "expires_at": future(),
        "max_attempts": 2,
        "max_cost": 4,
        "steps": steps,
        **changes,
    }


def post(
    port: int, path: str, payload: dict[str, Any], headers: dict[str, str]
) -> tuple[int, dict[str, Any]]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=canonical_bytes(payload),
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        response = urlopen(request, timeout=12)
    except HTTPError as exc:
        response = exc
    with response:
        return response.code, strict_json(response.read())


@contextmanager
def listener(server: ThreadingHTTPServer) -> Iterator[int]:
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class Provider(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        self.commands: dict[str, dict[str, Any]] = {}
        self.receipts: list[dict[str, Any]] = []
        self.drop_response = False
        self.config: GatewayConfig
        super().__init__(("127.0.0.1", 0), ProviderHandler)


class ProviderHandler(BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        pass

    def _send(self, result: dict[str, Any]) -> None:
        body = canonical_bytes(result)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        provider = self.server
        assert isinstance(provider, Provider)
        assert self.headers["Authorization"] == "Bearer " + "s" * 64
        assert self.headers.get("X-BlackFox-Agent-Token") is None
        store = AuthorityReceiptStore(provider.config.receipt_database)
        try:
            envelope = store.get(self.headers["X-BlackFox-Authorization-Receipt"])
        finally:
            store.close()
        assert envelope and provider.config.receipt_signing
        receipt = verify_receipt(
            envelope, provider.config.receipt_signing.build().current_policy()
        )
        assert receipt["record_type"] == "authorization"
        assert (
            receipt["subject"]["metadata"]["operation"]["operation_id"] == "release-1"
        )
        assert receipt["subject"]["digest"] == self.headers["X-BlackFox-Subject-Digest"]
        effect = strict_json(self.rfile.read(int(self.headers["Content-Length"])))
        provider.commands[self.headers["Idempotency-Key"]] = effect
        provider.receipts.append(receipt)
        if provider.drop_response:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        self._send(
            {"message": "accepted", "request_id": self.headers["Idempotency-Key"]}
        )

    def do_GET(self) -> None:  # noqa: N802
        assert self.headers["Authorization"] == "Bearer " + "r" * 64
        provider = self.server
        assert isinstance(provider, Provider)
        value = provider.commands.get(self.path.removeprefix("/effects/"))
        if value is None:
            self.send_error(404)
            return
        self._send(value)


class Client:
    def __init__(self, provider: Provider, config: GatewayConfig) -> None:
        self.provider = provider
        self.config = config
        self.gateway: LiveAuthorityGateway
        self.port: int

    @contextmanager
    def running(self) -> Iterator[Client]:
        self.gateway = LiveAuthorityGateway.from_config(self.config)
        assert self.gateway.status()["ready"]
        try:
            with listener(
                BlackFoxGatewayHttpServer(("127.0.0.1", 0), self.gateway)
            ) as self.port:
                yield self
        finally:
            self.gateway.receipt_store.close()

    def call(
        self, action: str, payload: dict[str, Any], step: str = ""
    ) -> tuple[int, dict[str, Any]]:
        return post(
            self.port,
            "/v1/operations/" + action,
            payload,
            AGENTS[step] if step else OPERATOR,
        )

    def ok(
        self, action: str, payload: dict[str, Any], step: str = ""
    ) -> dict[str, Any]:
        status, body = self.call(action, payload, step)
        assert 200 <= status < 300, (status, body)
        return body

    def activate(self, **changes: Any) -> None:
        self.ok("propose", plan(**changes), "stage")
        self.approve(self.conditions())

    def conditions(self, *, freeze: Any = False) -> dict[str, Any]:
        state = self.ok("inspect", OP)
        return self.ok(
            "conditions",
            {
                **OP,
                "epoch": state["epoch"],
                "facts": {"freeze": freeze},
                "valid_until": future(),
                "reason": "Current change window.",
            },
        )

    def approve(self, state: dict[str, Any]) -> dict[str, Any]:
        return self.ok(
            "approve",
            {
                **OP,
                "snapshot_digest": state["snapshot_digest"],
                "reviewer": "operator-1",
            },
        )

    def step_evidence(self, step: dict[str, Any], ref: str) -> dict[str, Any]:
        subject = self.ok("subject", step, step["step_id"])
        self.evidence(
            subject,
            "ci-result",
            "ci",
            "ci-hmac-v1",
            "CI_KEY",
            "test_result",
            "passed",
            {"passed": True},
        )
        self.evidence(
            subject,
            ref,
            "human-review",
            "human-hmac-v1",
            "HUMAN_KEY",
            "human_approval",
            "approved",
            {
                "decision": "approve",
                "reviewer_kind": "human",
                "reviewer_id": "operator-1",
            },
        )
        return {**step, "evidence_refs": ["ci-result", ref]}

    def evidence(
        self,
        target: dict[str, Any],
        ref: str,
        issuer: str,
        key: str,
        secret: str,
        kind: str,
        status: str,
        payload: dict[str, Any],
        *,
        produced_at: str | None = None,
    ) -> None:
        self.gateway.evidence_store.write(
            issue_signed_evidence(
                evidence_id=ref,
                kind=kind,
                issuer=issuer,
                key_id=key,
                secret=os.environ["BLACKFOX_" + secret].encode(),
                status=status,
                repository_id=target["repository_id"],
                revision=target["revision"],
                target_digest=target["digest"],
                payload=payload,
                produced_at=produced_at,
            )
        )

    def observation(
        self,
        step: dict[str, Any],
        ref: str,
        *,
        kind: str = "outcome",
        value: dict[str, Any] | None = None,
        produced_at: str | None = None,
    ) -> dict[str, Any]:
        target = self.ok("observation-target", step)
        if value is None:
            request = Request(
                f"http://127.0.0.1:{self.provider.server_port}/effects/{target['metadata']['request_id']}",
                headers={"Authorization": "Bearer " + "r" * 64},
            )
            with urlopen(request, timeout=3) as response:
                value = strict_json(response.read())
        self.evidence(
            target,
            ref,
            "service-observer",
            "observer-hmac-v1",
            "OBSERVER_KEY",
            "operation_observation",
            "verified",
            {"kind": kind, "value": value},
            produced_at=produced_at,
        )
        return {**step, "evidence_ref": ref}


@pytest.fixture
def system(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Client]:
    for name, value in {
        "SIGNING_PASSWORD": "p",
        "CI_KEY": "c",
        "HUMAN_KEY": "h",
        "OBSERVER_KEY": "w",
        "AGENT_TOKEN": "a",
        "RELEASE_AGENT_TOKEN": "b",
        "OPERATOR_TOKEN": "o",
        "SERVICE_TOKEN": "s",
    }.items():
        monkeypatch.setenv("BLACKFOX_" + name, value * 64)
    generate_keys(
        tmp_path / "receipt-keys",
        "BLACKFOX_SIGNING_PASSWORD",
        "enterprise-authority",
        "operations-test",
        "operations-stream",
    )
    path = tmp_path / "gateway.toml"
    path.write_text(
        (ROOT / "examples/wave18/blackfox.gateway.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config = load_gateway_config(path)
    provider = Provider()
    with listener(provider) as port:
        assert config.mesh is not None
        connector = replace(
            config.mesh.connectors[0],
            base_url=f"http://127.0.0.1:{port}",
            allow_loopback_http=True,
        )
        config = replace(
            config,
            mesh=replace(config.mesh, connectors=(connector,), timeout_seconds=3),
        )
        provider.config = config
        yield Client(provider, config)
