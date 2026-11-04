from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from ix_blackfox.authority_crypto.encoding import AuthorityProofError
from ix_blackfox.integration_mesh.audit import AuditRelay
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.live_gateway.upstream import UpstreamResponse, UpstreamTransportError

from .conftest import authorized


def populate(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> AuditRelay:
    payload, headers = authorized(gateway)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.runtime.request_upstream",
        lambda **_: UpstreamResponse(201, (), b'{"id":42}'),
    )
    assert gateway.handle_api(payload=payload, headers=headers).status == 201
    assert gateway.config.mesh is not None
    return AuditRelay(gateway.config.mesh, gateway.receipt_store)


def test_audit_sync_is_durable_and_duplicate_free(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = populate(gateway, monkeypatch)
    sink = relay.config.audit_sinks[0]
    assert relay.sync(sink, 1) == 1
    assert relay.sync(sink, 1) == 1
    assert relay.sync(sink) == 0
    restarted = AuditRelay(relay.config, gateway.receipt_store)
    assert restarted.sync(sink) == 0
    seen = []

    def send(**kw: Any) -> UpstreamResponse:
        seen.append(kw)
        event = json.loads(kw["body"])
        assert kw["headers"]["Content-Type"] == "application/cloudevents+json"
        assert kw["headers"]["Authorization"] == "Bearer " + "e" * 64
        assert kw["headers"]["Idempotency-Key"] == event["id"]
        assert event["specversion"] == "1.0" and "attestation" in event["data"]
        assert "payload" not in event["data"]["subject"]
        return UpstreamResponse(204, (), b"")

    monkeypatch.setattr("ix_blackfox.integration_mesh.audit.request_upstream", send)
    assert restarted.deliver_one(sink)["state"] == "delivered"
    assert restarted.deliver_one(sink)["state"] == "delivered"
    assert restarted.deliver_one(sink)["state"] == "idle"
    assert [json.loads(s["body"])["data"]["record_type"] for s in seen] == [
        "authorization",
        "outcome",
    ]


@pytest.mark.parametrize("status", [0, 408, 429, 500, 503])
def test_transient_audit_failures_retry_with_same_event_id(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    relay = populate(gateway, monkeypatch)
    sink = relay.config.audit_sinks[0]
    relay.sync(sink)
    seen = []

    def send(**kw: Any) -> UpstreamResponse:
        seen.append(json.loads(kw["body"])["id"])
        if len(seen) == 1:
            if not status:
                raise UpstreamTransportError("unavailable")
            return UpstreamResponse(status, (("Retry-After", "60"),), b"")
        return UpstreamResponse(202, (), b"")

    monkeypatch.setattr("ix_blackfox.integration_mesh.audit.request_upstream", send)
    assert relay.deliver_one(sink, now=100)["state"] == "pending"
    assert relay.deliver_one(sink, now=101)["state"] == "waiting"
    assert relay.deliver_one(sink, now=161)["state"] == "delivered"
    assert len(seen) == 2 and seen[0] == seen[1]


@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 404, 422])
def test_permanent_failures_stop_ordered_delivery_until_requeued(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    relay = populate(gateway, monkeypatch)
    sink = relay.config.audit_sinks[0]
    relay.sync(sink)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.audit.request_upstream",
        lambda **_: UpstreamResponse(status, (), b""),
    )
    assert relay.deliver_one(sink)["state"] == "dead"
    assert relay.deliver_one(sink)["state"] == "dead"
    relay.requeue(sink, 1)
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.audit.request_upstream",
        lambda **_: UpstreamResponse(204, (), b""),
    )
    assert relay.deliver_one(sink)["state"] == "delivered"
    with pytest.raises(ValueError):
        relay.requeue(sink, 1)


def test_attempt_budget_and_expired_leases(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = populate(gateway, monkeypatch)
    sink = replace(relay.config.audit_sinks[0], max_attempts=2)
    relay.sync(sink)
    with relay.ledger.connect() as db:
        db.execute(
            "UPDATE mesh_outbox SET state='leased',attempts=1,due=100,lease_token='crashed' WHERE sequence=1"
        )
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.audit.request_upstream",
        lambda **_: UpstreamResponse(503, (), b""),
    )
    assert relay.deliver_one(sink, now=99)["state"] == "waiting"
    assert relay.deliver_one(sink, now=101)["state"] == "dead"
    assert relay.deliver_one(sink, now=1000)["state"] == "dead"


@pytest.mark.parametrize(
    "mutation", ["destination", "source", "rollback", "event_data", "event_type"]
)
def test_audit_rejects_contract_and_integrity_changes(
    gateway: LiveAuthorityGateway, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    relay = populate(gateway, monkeypatch)
    sink = relay.config.audit_sinks[0]
    relay.sync(sink)
    seen = []
    monkeypatch.setattr(
        "ix_blackfox.integration_mesh.audit.request_upstream",
        lambda **kw: seen.append(kw),
    )
    if mutation == "destination":
        with pytest.raises(AuthorityProofError):
            relay.sync(replace(sink, url="http://127.0.0.1:2/events"))
    elif mutation == "source":
        with relay.ledger.connect() as db:
            db.execute("UPDATE mesh_sinks SET source_id='changed'")
        with pytest.raises(AuthorityProofError):
            relay.sync(sink)
    elif mutation == "rollback":
        with relay.ledger.connect() as db:
            db.execute("UPDATE mesh_sinks SET sequence=9999")
        with pytest.raises(AuthorityProofError):
            relay.sync(sink)
    else:
        with relay.ledger.connect() as db:
            row = db.execute(
                "SELECT event_json FROM mesh_outbox WHERE sequence=1"
            ).fetchone()
            event = json.loads(row[0])
            if mutation == "event_data":
                event["data"]["upstream_status"] = 999
            else:
                event["type"] = "forged-type"
            db.execute(
                "UPDATE mesh_outbox SET event_json=? WHERE sequence=1",
                (json.dumps(event),),
            )
        with pytest.raises(AuthorityProofError):
            relay.deliver_one(sink)
    assert not seen
