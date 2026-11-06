from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace

import pytest

from ix_blackfox.autonomy.contracts import OperationError, parse_plan
from ix_blackfox.autonomy.store import OperationStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway

from .conftest import AGENTS, FIRST, OP, SECOND, Client, future, plan, post


def test_multi_agent_http_operation_requires_independently_verified_dependencies(
    system: Client,
) -> None:
    with system.running() as client:
        client.activate()
        assert client.call("subject", FIRST, "publish")[0] == 404
        assert client.call("subject", SECOND, "publish")[0] == 409
        first = client.step_evidence(FIRST, "approval-stage")
        assert (
            client.call("dispatch", {**first, "evidence_refs": ["ci-result"]}, "stage")[
                0
            ]
            == 403
        )
        assert client.ok("inspect", OP)["attempts"] == 0
        bypass = {
            "tool_name": "service.submit",
            "arguments": plan()["steps"][0]["arguments"],
            "context": {"evidence_refs": first["evidence_refs"], "operation": FIRST},
        }
        assert post(client.port, "/v1/invoke", bypass, AGENTS["stage"])[0] == 403
        rpc = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "service.submit", "arguments": bypass["arguments"]},
        }
        assert post(client.port, "/mcp", rpc, AGENTS["stage"])[0] == 403
        provider_response = client.ok("dispatch", first, "stage")
        assert provider_response["execution_state"] == "response_received"
        assert client.ok("inspect", OP)["step_status"]["stage"] == "attempted"
        assert client.call("subject", SECOND, "publish")[0] == 409
        assert client.call("dispatch", first, "stage")[0] == 409
        assert len(client.provider.receipts) == 1
        assert client.call("observe", {**FIRST, "evidence_ref": "ci-result"})[0] == 403
        stage_observation = client.observation(FIRST, "observed-stage")
        assert client.call("observe", stage_observation, "stage")[0] == 401
        client.ok("observe", stage_observation)
        second = client.step_evidence(SECOND, "approval-publish")
        client.ok("dispatch", second, "publish")
        bound = client.provider.receipts[-1]["subject"]["metadata"]["operation"]
        assert bound["dependency_observations"]["stage"]
        assert bound["snapshot_digest"] == client.ok("inspect", OP)["snapshot_digest"]
        final = client.ok("observe", client.observation(SECOND, "observed-publish"))
        assert final["complete"]
        assert final["step_status"] == {"publish": "verified", "stage": "verified"}
        assert final["attempts"] == 2 and final["cost_spent"] == 4
        assert len(client.provider.receipts) == 2
        assert client.gateway.receipt_store.verify_chain().passed
        events = client.ok("events", {**OP, "after": 0})["events"]
        assert [event["event"] for event in events] == [
            "proposed",
            "conditions",
            "approved",
            "reserved",
            "authorized",
            "attempted",
            "transport_reported",
            "observed",
            "reserved",
            "authorized",
            "attempted",
            "transport_reported",
            "observed",
        ]
        assert (
            client.ok("events", {**OP, "after": events[-2]["sequence"]})["events"]
            == events[-1:]
        )


def test_changed_conditions_stale_prior_evidence_and_require_fresh_authority(
    system: Client,
) -> None:
    with system.running() as client:
        client.activate()
        client.ok("dispatch", client.step_evidence(FIRST, "stage-initial"), "stage")
        observation = client.observation(FIRST, "stage-observed")
        client.ok("observe", observation)
        old_step = client.step_evidence(SECOND, "publish-initial")
        previous = client.ok("inspect", OP)
        changed = client.conditions(freeze=True)
        assert changed["epoch"] == previous["epoch"] + 1
        assert (
            not changed["approved"]
            and changed["step_status"]["stage"] == "observation_stale"
        )
        assert (
            client.call(
                "approve",
                {
                    **OP,
                    "snapshot_digest": previous["snapshot_digest"],
                    "reviewer": "operator-1",
                },
            )[0]
            == 409
        )
        client.approve(changed)
        assert client.call("observe", observation)[0] == 403
        assert client.call("dispatch", old_step, "publish")[0] == 409
        client.approve(client.conditions())
        client.ok("observe", client.observation(FIRST, "stage-observed-again"))
        assert client.call("dispatch", old_step, "publish")[0] == 403
        client.ok(
            "dispatch", client.step_evidence(SECOND, "publish-renewed"), "publish"
        )
        assert len(client.provider.receipts) == 2


def test_network_ambiguity_retained_after_restart_without_duplicate(
    system: Client,
) -> None:
    with system.running() as client:
        client.activate()
        first = client.step_evidence(FIRST, "stage-ambiguous")
        client.provider.drop_response = True
        status, body = client.call("dispatch", first, "stage")
        assert status == 502 and body["execution_state"] == "outcome_unknown"
    with system.running() as client:
        state = client.ok("inspect", OP)
        assert (
            state["steps"]["stage"]["attempt"]["transport_state"] == "outcome_unknown"
        )
        assert client.call("dispatch", first, "stage")[0] == 409
        assert client.call("subject", SECOND, "publish")[0] == 409
        client.ok("observe", client.observation(FIRST, "ambiguous-reconciled"))
        assert client.call("subject", SECOND, "publish")[0] == 200
        assert len(client.provider.receipts) == 1


def test_suspension_committed_after_authorization_blocks_transport(
    system: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = LiveAuthorityGateway._commit_authorization
    signed, proceed = threading.Event(), threading.Event()

    def pause(self, prepared, claims):
        result = original(self, prepared, claims)
        signed.set()
        assert proceed.wait(8)
        return result

    monkeypatch.setattr(LiveAuthorityGateway, "_commit_authorization", pause)
    with system.running() as client:
        client.activate()
        first = client.step_evidence(FIRST, "stage-suspended")
        with ThreadPoolExecutor() as executor:
            dispatch = executor.submit(client.call, "dispatch", first, "stage")
            try:
                assert signed.wait(6)
                state = client.ok("inspect", OP)
                assert state["step_status"]["stage"] == "outcome_unknown"
                client.ok(
                    "suspend",
                    {**OP, "epoch": state["epoch"], "reason": "External freeze."},
                )
            finally:
                proceed.set()
            assert dispatch.result(timeout=8)[0] == 409
        assert not client.provider.receipts
        assert client.ok("inspect", OP)["step_status"]["stage"] == "not_attempted"


def test_one_effect_when_two_agents_or_workers_compete(system: Client) -> None:
    with system.running() as client:
        client.activate()
        first = client.step_evidence(FIRST, "stage-concurrent")
        with ThreadPoolExecutor() as executor:
            requests = [
                executor.submit(client.call, "dispatch", first, "stage")
                for _ in range(8)
            ]
        assert sorted(request.result()[0] for request in requests) == [200] + [409] * 7
        assert len(client.provider.receipts) == 1
        assert client.ok("inspect", OP)["attempts"] == 1


def test_storage_failure_after_provider_write_preserves_unknown_reservation(
    system: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = OperationStore.save

    def fail(db, state, event, **details):
        if event == "attempted":
            raise sqlite3.OperationalError("injected loss before attempt commit")
        original(db, state, event, **details)

    with system.running() as client, monkeypatch.context() as scoped:
        client.activate()
        first = client.step_evidence(FIRST, "stage-storage")
        scoped.setattr(OperationStore, "save", staticmethod(fail))
        status, body = client.call("dispatch", first, "stage")
        assert status == 503 and body["execution_state"] == "outcome_unknown"
    with system.running() as client:
        assert client.call("dispatch", first, "stage")[0] == 409
        assert client.ok("inspect", OP)["step_status"]["stage"] == "outcome_unknown"
        assert len(client.provider.receipts) == 1
        client.ok("observe", client.observation(FIRST, "observed-storage"))
        assert client.call("subject", SECOND, "publish")[0] == 200


def test_mismatched_outcome_requires_recovery_and_cannot_unlock_dependency(
    system: Client,
) -> None:
    with system.running() as client:
        custom = plan()
        custom["steps"][0]["expected_outcome"] = {
            "state": "provider-did-not-reach-this"
        }
        client.activate(steps=custom["steps"])
        client.ok("dispatch", client.step_evidence(FIRST, "stage-mismatch"), "stage")
        mismatch = client.ok("observe", client.observation(FIRST, "stage-unexpected"))
        assert mismatch["step_status"]["stage"] == "mismatch"
        assert client.call("subject", SECOND, "publish")[0] == 409
        wrong = client.observation(
            FIRST, "recovery-wrong", kind="recovery", value={"state": "bad"}
        )
        assert client.call("observe", wrong)[0] == 409
        recovery = client.observation(
            FIRST, "recovery-correct", kind="recovery", value={"state": "restored"}
        )
        result = client.ok("observe", recovery)
        assert result["step_status"]["stage"] == "recovered" and not result["complete"]
        assert client.call("subject", SECOND, "publish")[0] == 409


@pytest.mark.parametrize("max_attempts,max_cost", [(1, 4), (2, 3)])
def test_operation_budget_blocks_second_effect(
    system: Client, max_attempts: int, max_cost: int
) -> None:
    with system.running() as client:
        client.activate(max_attempts=max_attempts, max_cost=max_cost)
        client.ok("dispatch", client.step_evidence(FIRST, "stage-budget"), "stage")
        client.ok("observe", client.observation(FIRST, "observed-budget"))
        status, body = client.call("subject", SECOND, "publish")
        assert status == 409 and "budget" in body["error"]
        assert len(client.provider.receipts) == 1


def test_observation_removed_or_future_dated_cannot_authorize_dependency(
    system: Client,
) -> None:
    with system.running() as client:
        client.activate()
        client.ok("dispatch", client.step_evidence(FIRST, "stage-freshness"), "stage")
        future_evidence = client.observation(
            FIRST, "observed-future", produced_at=future()
        )
        assert client.call("observe", future_evidence)[0] == 403
        current = client.observation(FIRST, "observed-fresh")
        client.ok("observe", current)
        second = client.step_evidence(SECOND, "publish-freshness")
        (client.gateway.evidence_store.root / "observed-fresh.json").unlink()
        assert client.call("dispatch", second, "publish")[0] == 409
        assert len(client.provider.receipts) == 1


def test_operator_only_and_strict_inputs(system: Client) -> None:
    with system.running() as client:
        assert client.call("propose", plan())[0] == 401
        assert client.call("approve", OP, "stage")[0] == 401
        client.ok("propose", plan(), "stage")
        assert client.call("propose", plan(), "stage")[0] == 409
        assert client.call("inspect", OP, "stage")[0] == 401
        assert (
            client.call(
                "approve", {**OP, "snapshot_digest": "forged", "reviewer": "x"}
            )[0]
            == 409
        )
        client.approve(client.conditions(freeze=0))
        assert client.call("subject", FIRST, "stage")[0] == 409
        state = client.ok("inspect", OP)
        client.ok(
            "close", {**OP, "epoch": state["epoch"], "reason": "Cancelled by operator."}
        )
        assert (
            client.call(
                "conditions",
                {
                    **OP,
                    "epoch": state["epoch"],
                    "facts": {},
                    "valid_until": future(),
                    "reason": "reopen",
                },
            )[0]
            == 409
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "cycle",
        "unknown_dep",
        "duplicate_step",
        "bool_budget",
        "naive_expiry",
        "unknown_field",
        "no_recovery",
        "oversize_cost",
    ],
)
def test_plan_validation(mutation: str) -> None:
    candidate = deepcopy(plan())
    first, second = candidate["steps"]
    if mutation == "cycle":
        first["depends_on"] = ["publish"]
    elif mutation == "unknown_dep":
        second["depends_on"] = ["absent"]
    elif mutation == "duplicate_step":
        second["step_id"] = first["step_id"]
    elif mutation == "bool_budget":
        candidate["max_attempts"] = True
    elif mutation == "naive_expiry":
        candidate["expires_at"] = "2026-11-01T12:00:00"
    elif mutation == "unknown_field":
        first["authority"] = "self"
    elif mutation == "no_recovery":
        del first["recovery"]
    else:
        second["cost"] = 1000001
    with pytest.raises(OperationError):
        parse_plan(candidate)


def test_route_alias_cannot_bypass_managed_boundary(system: Client) -> None:
    config = system.config
    alias = replace(config.routes[0], tool_name="service.bypass")
    with pytest.raises(ValueError, match="aliases a managed destination"):
        replace(config, routes=(*config.routes, alias))


def test_dependency_removed_during_final_authority_check_blocks_transport(
    system: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with system.running() as client:
        client.activate()
        client.ok("dispatch", client.step_evidence(FIRST, "stage-guard"), "stage")
        client.ok("observe", client.observation(FIRST, "stage-guard-observation"))
        second = client.step_evidence(SECOND, "publish-guard")
        original = LiveAuthorityGateway._revalidate_before_dispatch

        def remove_evidence(self, prepared, headers, arguments, authorization):
            original(self, prepared, headers, arguments, authorization)
            (self.evidence_store.root / "stage-guard-observation.json").unlink()

        monkeypatch.setattr(
            LiveAuthorityGateway, "_revalidate_before_dispatch", remove_evidence
        )
        assert client.call("dispatch", second, "publish")[0] == 409
        assert len(client.provider.receipts) == 1
        state = client.ok("inspect", OP)
        assert state["step_status"]["publish"] == "not_attempted"
        assert state["steps"]["publish"]["attempt"]["authorization_receipt_id"]


def test_expired_conditions_deny_before_dispatch(
    system: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import datetime, timedelta

    from ix_blackfox.autonomy import coordinator

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(seconds=301)

    with system.running() as client:
        client.activate(expires_at=future(600))
        first = client.step_evidence(FIRST, "stage-expiry")
        monkeypatch.setattr(coordinator, "datetime", Later)
        assert client.call("dispatch", first, "stage")[0] == 409
        assert not client.provider.receipts
        assert client.ok("inspect", OP)["attempts"] == 0


@pytest.mark.parametrize("revoke_after_signing", [False, True])
def test_federated_operation_authority_is_rechecked_before_transport(
    system: Client,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    revoke_after_signing: bool,
) -> None:
    import json
    import time

    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    from ix_blackfox.live_gateway.enterprise_identity import (
        IdentityBinding,
        OidcProvider,
    )
    from ix_blackfox.live_gateway.wave15_demo import _token

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    public_jwk.update(kid="wave15-rsa-1", alg="RS256", use="sig")
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [public_jwk]}), encoding="utf-8")
    issuer = "https://issuer.blackfox.test"
    audience = "blackfox-operations"
    system.config = replace(
        system.config,
        identity_mode="static_or_federated",
        identity_require_delegation=True,
        identity_providers=(OidcProvider(issuer, audience, jwks),),
        identity_bindings=(
            IdentityBinding(issuer, "workload/coding-agent-07", "engineering-agent"),
        ),
    )
    now = int(time.time())
    credential = _token(
        key,
        now=now,
        jti="operation-token",
        audience=audience,
        delegation=[
            {
                "delegation_id": "operation-delegation",
                "delegated_by": "release-owner",
                "tools": ["service.submit"],
                "repositories": ["example/engineering"],
                "path_roots": [],
                "expires_at": now + 120,
            }
        ],
    )
    monkeypatch.setitem(AGENTS, "stage", {"Authorization": "Bearer " + credential})
    original = LiveAuthorityGateway._commit_authorization

    def authorize(self, prepared, claims):
        receipt = original(self, prepared, claims)
        self.identity_verifier.revocations.revoke(kind="jti", value="operation-token")
        return receipt

    if revoke_after_signing:
        monkeypatch.setattr(LiveAuthorityGateway, "_commit_authorization", authorize)
    with system.running() as client:
        client.activate()
        request = client.step_evidence(FIRST, "federated-stage-approval")
        if revoke_after_signing:
            assert client.call("dispatch", request, "stage")[0] == 503
            assert not client.provider.receipts
            assert client.ok("inspect", OP)["steps"]["stage"]["attempt"][
                "authorization_receipt_id"
            ]
        else:
            client.ok("dispatch", request, "stage")
            assert len(client.provider.receipts) == 1
            receipt = client.provider.receipts[0]
            assert (
                receipt["authenticated_principal"]["authentication_type"] == "oidc_jwt"
            )
            assert receipt["subject"]["metadata"]["operation"]["step_id"] == "stage"
