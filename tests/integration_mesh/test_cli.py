from __future__ import annotations

import json
from typing import Any

import pytest

from ix_blackfox.integration_mesh.cli import main
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.upstream import UpstreamResponse

from .conftest import authorized


def test_operator_status_request_lookup_and_audit_delivery(
    gateway: LiveAuthorityGateway,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b"{}"),
    )
    response = gateway.handle_api(payload=payload, headers=headers)
    request_id = json.loads(response.body)["request_id"]
    common = ["--config", str(gateway.config.source_path)]
    assert main(["status", *common]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["mesh"]["requests"]["complete"] == 1
    assert main(["inspect-request", *common, "--request-id", request_id]) == 0
    assert json.loads(capsys.readouterr().out)["request"]["authorization_id"]
    assert main(["inspect-request", *common, "--request-id", "missing"]) == 1
    capsys.readouterr()
    deliveries = []

    def send(**kw: Any) -> UpstreamResponse:
        deliveries.append(kw)
        return UpstreamResponse(401, (), b"")

    monkeypatch.setattr("ix_blackfox.integration_mesh.audit.request_upstream", send)
    assert main(["relay", *common, "--limit", "10"]) == 1
    assert json.loads(capsys.readouterr().out)["mesh"]["outbox"]["dead"] == 1
    assert (
        main(
            [
                "requeue-audit",
                *common,
                "--sink-id",
                "security-events",
                "--sequence",
                "1",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["requeued"]
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.audit.request_upstream",
        lambda **_: UpstreamResponse(204, (), b""),
    )
    assert main(["relay", *common, "--limit", "10"]) == 0
    assert json.loads(capsys.readouterr().out)["mesh"]["outbox"]["delivered"] == 2


def test_unrelated_service_credential_loss_does_not_block_an_authorized_route(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, headers = authorized(gateway)
    monkeypatch.delenv("BLACKFOX_GITHUB_TOKEN")
    monkeypatch.delenv("BLACKFOX_AUDIT_TOKEN")
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b"{}"),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 201
