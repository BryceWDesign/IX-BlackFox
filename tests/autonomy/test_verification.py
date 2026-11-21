from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.authority_crypto.encoding import AuthorityProofError, digest
from ix_blackfox.authority_crypto.signing import LocalSigner, SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.verification.contracts import CONTRACT, SOURCES, VerificationConfig
from ix_blackfox.verification.proof import EVIDENCE_TYPE, verify_bundle

from .conftest import FIRST, OP, SECOND, Client, future, plan

SIGNING_ENV = "BLACKFOX_SIGNING_PASSWORD"


def enable(system: Client, directory: Path) -> dict[str, SigningController]:
    policies: dict[str, Path] = {}
    signers: dict[str, SigningController] = {}
    for role in SOURCES:
        home = directory / role
        generate_keys(home, SIGNING_ENV, role, role, "verification-test")
        policies[role] = home / "trust-policy.json"
        signer = LocalSigner.load(
            home / "authority-signing-key.pem", SIGNING_ENV, role, "Ed25519"
        )
        signers[role] = SigningController(signer, TrustPolicy.load(policies[role]))
    assert system.config.autonomy is not None
    system.config = replace(
        system.config,
        autonomy=replace(
            system.config.autonomy, verification=VerificationConfig(**policies)
        ),
    )
    system.provider.allowed_operations.update({"release-recovery", "competing"})
    system.provider.config = system.config
    return signers


@pytest.fixture
def verified_system(
    system: Client, tmp_path: Path
) -> tuple[Client, dict[str, SigningController]]:
    return system, enable(system, tmp_path)


def criterion(
    name: str, source: str, value: dict[str, Any], step: str = "stage"
) -> dict[str, Any]:
    return {
        "id": name,
        "version": 1,
        "description": name,
        "step_id": step,
        "source": source,
        "check": name,
        "expected": value,
    }


def change(name: str = "quota") -> dict[str, Any]:
    return {
        "id": name,
        "version": 1,
        "summary": name,
        "artifact_sha256": digest({"change": name}),
    }


def contract(two: bool = False) -> dict[str, Any]:
    result = {
        "schema_version": CONTRACT,
        "change": change(),
        "requirements": [
            criterion("state", "provider", {"state": "staged"}),
            criterion("test", "test", {"passed": 2}),
            criterion("sim", "simulation", {"safe": True}),
        ],
        "rollback_requirements": [
            criterion("rollback", "provider", {"state": "restored"})
        ],
    }
    if two:
        result["requirements"].append(
            criterion("published", "provider", {"state": "published"}, "publish")
        )
        result["rollback_requirements"].append(
            criterion("unpublished", "provider", {"state": "staged"}, "publish")
        )
    return result


def one(
    operation: str = OP["operation_id"], *, expected: str = "staged"
) -> dict[str, Any]:
    result = plan(operation_id=operation)
    result["steps"] = result["steps"][:1]
    result["steps"][0]["arguments"]["payload"] = {"state": expected}
    result["steps"][0]["expected_outcome"] = {"state": expected}
    return result


def activate(system: Client, *, two: bool = False) -> None:
    proposal = plan() if two else one()
    if two:
        proposal["steps"][1]["recovery"]["expected_outcome"] = {"state": "staged"}
    system.ok(
        "propose-verification", {"plan": proposal, "contract": contract(two)}, "stage"
    )
    system.approve(system.conditions())


def evidence(
    system: Client,
    signers: dict[str, SigningController],
    name: str,
    value: dict[str, Any],
    *,
    role: str | None = None,
    status: str = "pass",
    observed_at: str | None = None,
    target_digest: str | None = None,
    operation: str = OP["operation_id"],
) -> dict[str, Any]:
    target = system.ok(
        "verification-target", {"operation_id": operation, "requirement_id": name}
    )
    proof = signers[role or target["criterion"]["source"]].envelope(
        EVIDENCE_TYPE,
        {
            "target_digest": target_digest or target["digest"],
            "observed_at": observed_at or datetime.now(UTC).isoformat(),
            "artifact_sha256": digest(value),
            "status": status,
            "value": value,
        },
    )
    return {"operation_id": operation, "requirement_id": name, "envelope": proof}


def complete(system: Client, signers: dict[str, SigningController]) -> None:
    for name, value in [
        ("state", {"state": "staged"}),
        ("test", {"passed": 2}),
        ("sim", {"safe": True}),
    ]:
        system.ok("verification-evidence", evidence(system, signers, name, value))


def assessment(system: Client, operation: str = OP["operation_id"]) -> dict[str, Any]:
    return system.ok("verification-assess", {"operation_id": operation})


def review(
    system: Client, decision: str, operation: str = OP["operation_id"]
) -> dict[str, Any]:
    report = assessment(system, operation)
    return {
        "operation_id": operation,
        "epoch": report["epoch"],
        "assessment_digest": report["assessment_digest"],
        "decision": decision,
        "reviewer": "operator-1",
        "reason": "Reviewed exact requirement results.",
    }


def test_independent_closure_requires_every_source_and_pins_signed_bundle(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, signers = verified_system
    with system.running():
        assert system.call("propose", one(), "stage")[0] == 409
        activate(system)
        assert system.call("close", {**OP, "epoch": 1, "reason": "bypass"})[0] == 409
        assert (
            system.call("verification-target", {**OP, "requirement_id": "state"})[0]
            == 409
        )
        assert system.call("verification-close", review(system, "verified"))[0] == 409
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        assert system.call("observation-target", FIRST)[0] == 409
        stale_review = review(system, "verified")
        complete(system, signers)
        assert assessment(system)["status"] == "verified"
        assert system.call("verification-close", stale_review)[0] == 409
        assert (
            system.call("verification-close", review(system, "verified"), "stage")[0]
            == 401
        )
        final = system.ok("verification-close", review(system, "verified"))
        assert final["current"]
        assert (
            system.call(
                "verification-evidence",
                {**OP, "requirement_id": "state", "envelope": {}},
            )[0]
            == 409
        )
        bundle = system.ok("verification-export", OP)

    assert system.config.receipt_signing
    authority = system.config.receipt_signing.build().current_policy()
    policies = {role: signer.policy for role, signer in signers.items()}
    assert verify_bundle(bundle, authority, policies, operation_id=OP["operation_id"])[
        "current"
    ]
    stale = verify_bundle(
        bundle,
        authority,
        policies,
        operation_id=OP["operation_id"],
        now=datetime.now(UTC) + timedelta(hours=2),
    )
    assert stale["outcome_at_closure"] == "verified" and not stale["current"]
    with pytest.raises(AuthorityProofError, match="another operation"):
        verify_bundle(bundle, authority, policies, operation_id="different")
    bundle["records"][0]["content"]["assessment"]["plan"]["max_cost"] += 1
    with pytest.raises(AuthorityProofError, match="Closure signature"):
        verify_bundle(bundle, authority, policies, operation_id=OP["operation_id"])


@pytest.mark.parametrize(
    "attack",
    ["wrong-role", "wrong-target", "stale", "future", "tampered", "unknown-field"],
)
def test_evidence_rejection(
    verified_system: tuple[Client, dict[str, SigningController]],
    attack: str,
) -> None:
    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        args = {
            "wrong-role": {"role": "test"},
            "wrong-target": {"target_digest": "f" * 64},
            "stale": {"observed_at": future(-7200)},
            "future": {"observed_at": future(10)},
        }.get(attack, {})
        submission = evidence(system, signers, "state", {"state": "staged"}, **args)
        if attack == "tampered":
            submission["envelope"]["signatures"][0]["sig"] = "AA=="
        if attack == "unknown-field":
            submission["envelope"]["extra"] = True
        assert system.call("verification-evidence", submission)[0] == 403
        assert assessment(system)["requirements"]["state"]["status"] == "missing"
        assert system.call("verification-close", review(system, "verified"))[0] == 409


def test_dependencies_and_conflicts_remain_blocked_across_restart(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, signers = verified_system
    with system.running():
        activate(system, two=True)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        first = evidence(system, signers, "state", {"state": "staged"})
        system.ok("verification-evidence", first)
        assert system.call("subject", SECOND, "publish")[0] == 409
        complete(system, signers)
        dispatch = system.step_evidence(SECOND, "human-publish")
        conflict = evidence(system, signers, "state", {"state": "different"})
        with ThreadPoolExecutor(max_workers=4) as executor:
            codes = list(
                executor.map(
                    lambda item: system.call("verification-evidence", item)[0],
                    [first, conflict, first, conflict],
                )
            )
        assert codes == [200] * 4
        assert assessment(system)["requirements"]["state"]["status"] == "contradictory"

    with system.running():
        assert assessment(system)["status"] == "failed"
        unresolved = system.ok("verification-unresolved", {"after": "", "limit": 10})
        assert (
            unresolved["unresolved"][0]["unresolved_requirements"]["state"]
            == "contradictory"
        )
        assert unresolved["next_after"] is None
        assert system.call("dispatch", dispatch, "publish")[0] == 409
        assert (
            system.call(
                "conditions",
                {
                    **OP,
                    "epoch": 1,
                    "facts": {},
                    "valid_until": future(),
                    "reason": "cannot discard conflict",
                },
            )[0]
            == 409
        )
        assert len(system.provider.commands) == 1


def test_epoch_renewal_rejects_old_proof_and_requires_fresh_read(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        old = evidence(system, signers, "state", {"state": "staged"})
        system.ok("verification-evidence", old)
        system.conditions()
        assert system.call("verification-evidence", old)[0] == 403
        assert assessment(system)["status"] == "pending"
        complete(system, signers)
        assert assessment(system)["status"] == "verified"


@pytest.mark.parametrize(
    ("mode", "outcome"), [("rollback", "rolled_back"), ("remediation", "verified")]
)
def test_failure_followup_uses_new_authority_and_inherited_criteria(
    verified_system: tuple[Client, dict[str, SigningController]],
    mode: str,
    outcome: str,
) -> None:
    system, signers = verified_system
    child = {"operation_id": "release-recovery"}
    step = {**child, "step_id": "stage"}
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        system.ok(
            "verification-evidence",
            evidence(system, signers, "state", {"state": "incorrect"}),
        )
        assert assessment(system)["status"] == "failed"
        proposal = {
            "plan": one(
                child["operation_id"],
                expected="restored" if mode == "rollback" else "staged",
            ),
            "change": change(mode),
            "mode": mode,
            "parent_operation_id": OP["operation_id"],
        }
        system.ok("propose-followup", proposal, "stage")
        competing = deepcopy(proposal)
        competing["plan"]["operation_id"] = "competing"
        system.ok("propose-followup", competing, "stage")
        assert system.call("subject", step, "stage")[0] == 409
        assert system.call("verification-close", review(system, "followup"))[0] == 409

        def approve(op: str) -> tuple[int, dict[str, Any]]:
            snapshot = system.ok(
                "conditions",
                {
                    "operation_id": op,
                    "epoch": 0,
                    "facts": {"freeze": False},
                    "valid_until": future(),
                    "reason": "Authorized review window.",
                },
            )
            return system.call(
                "approve",
                {
                    "operation_id": op,
                    "snapshot_digest": snapshot["snapshot_digest"],
                    "reviewer": "operator-1",
                },
            )

        # Both proposals are valid, but only one response can be selected.
        assert approve(child["operation_id"])[0] == 200
        assert approve("competing")[0] == 409
        assert (
            assessment(system, child["operation_id"])["feedback"]["requirement_id"]
            == "state"
        )
        system.ok("dispatch", system.step_evidence(step, "human-recovery"), "stage")
        assert system.call("verification-close", review(system, "followup"))[0] == 409
        for row in (
            contract()["rollback_requirements"]
            if mode == "rollback"
            else contract()["requirements"]
        ):
            system.ok(
                "verification-evidence",
                evidence(
                    system,
                    signers,
                    row["id"],
                    row["expected"],
                    operation=child["operation_id"],
                ),
            )
        stale_parent_review = review(system, "followup")
        system.ok(
            "verification-close", review(system, "verified", child["operation_id"])
        )
        assert system.call("verification-close", stale_parent_review)[0] == 409
        assert (
            system.ok("verification-close", review(system, "followup"))[
                "outcome_at_closure"
            ]
            == outcome
        )
        bundle = system.ok("verification-export", OP)
        assert len(bundle["records"]) == 2
        assert system.ok("verification-assess", OP)["current"]
        assert len(system.ok("verification-chain", OP)["chain"]) == 2


def test_role_pins_are_distinct_and_revocation_blocks_success(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        complete(system, signers)
        assert system.config.autonomy and system.config.autonomy.verification
        policy_path = system.config.autonomy.verification.provider
        document = policy_path.read_text(encoding="utf-8")
        policy_path.write_text(
            document.replace('"revoked": false', '"revoked": true'), encoding="utf-8"
        )
        assert assessment_status(system) == 503
        assert not system.gateway.status()["ready"]
        policy_path.write_text(document, encoding="utf-8")
        assert assessment(system)["status"] == "verified"
        policy_path.write_bytes(system.config.autonomy.verification.test.read_bytes())
        assert assessment_status(system) == 503


def assessment_status(system: Client) -> int:
    return system.call("verification-assess", OP)[0]


def test_ambiguous_provider_write_survives_gateway_restart_and_real_read(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    from urllib.request import Request, urlopen

    from ix_blackfox.authority_crypto.encoding import strict_json

    system, signers = verified_system
    system.provider.drop_response = True
    with system.running():
        activate(system)
        dispatch = system.step_evidence(FIRST, "human-stage")
        status, body = system.call("dispatch", dispatch, "stage")
        assert status == 502 and body["execution_state"] == "outcome_unknown"
        assert assessment(system)["status"] == "pending"

    with system.running():
        assert system.call("dispatch", dispatch, "stage")[0] == 409
        target = system.ok("verification-target", {**OP, "requirement_id": "state"})
        request = Request(
            f"http://127.0.0.1:{system.provider.server_port}/effects/{target['request_id']}",
            headers={"Authorization": "Bearer " + "r" * 64},
        )
        with urlopen(request, timeout=3) as response:
            actual = strict_json(response.read())
        assert actual == {"state": "staged"}
        system.ok("verification-evidence", evidence(system, signers, "state", actual))
        complete(system, signers)
        assert system.ok("verification-close", review(system, "verified"))["current"]
        assert len(system.provider.commands) == 1


def test_missing_evidence_can_trigger_human_failure_and_abandonment(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, _ = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        command = review(system, "abandoned")
        command.pop("decision")
        assert system.ok("verification-fail", command)["status"] == "failed"
        assert system.call("verification-close", review(system, "verified"))[0] == 409
        result = system.ok("verification-close", review(system, "abandoned"))
        assert result["outcome_at_closure"] == "abandoned"
        assert not result["current"]


def test_offline_verifier_recomputes_requirements_even_with_valid_closure_signature(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    from ix_blackfox.verification.proof import CLOSURE_TYPE

    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        complete(system, signers)
        system.ok("verification-close", review(system, "verified"))
        bundle = system.ok("verification-export", OP)
    assert system.config.receipt_signing
    signer = system.config.receipt_signing.build()
    record = bundle["records"][0]
    record["content"]["assessment"]["proofs"].pop("sim")
    record["signature"] = signer.envelope(
        CLOSURE_TYPE, {"content_sha256": digest(record["content"])}
    )
    with pytest.raises(AuthorityProofError, match="recomputed criteria"):
        verify_bundle(
            bundle,
            signer.current_policy(),
            {role: s.policy for role, s in signers.items()},
            operation_id=OP["operation_id"],
        )


def test_parallel_followup_approval_selects_one_and_failed_rollback_cannot_close_verified(
    verified_system: tuple[Client, dict[str, SigningController]],
) -> None:
    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        system.ok(
            "verification-evidence",
            evidence(system, signers, "state", {"state": "wrong"}),
        )
        candidates = []
        for op in ("release-recovery", "competing"):
            system.ok(
                "propose-followup",
                {
                    "plan": one(op, expected="restored"),
                    "change": change(op),
                    "mode": "rollback",
                    "parent_operation_id": OP["operation_id"],
                },
                "stage",
            )
            state = system.ok(
                "conditions",
                {
                    "operation_id": op,
                    "epoch": 0,
                    "facts": {"freeze": False},
                    "valid_until": future(),
                    "reason": "Operator change window.",
                },
            )
            candidates.append(
                {
                    "operation_id": op,
                    "snapshot_digest": state["snapshot_digest"],
                    "reviewer": "operator-1",
                }
            )
        with ThreadPoolExecutor(max_workers=2) as executor:
            codes = list(
                executor.map(lambda item: system.call("approve", item)[0], candidates)
            )
        assert sorted(codes) == [200, 409]
        selected = candidates[codes.index(200)]["operation_id"]
        step = {"operation_id": selected, "step_id": "stage"}
        system.ok("dispatch", system.step_evidence(step, "human-recovery"), "stage")
        system.ok(
            "verification-evidence",
            evidence(
                system,
                signers,
                "rollback",
                {"state": "still-wrong"},
                operation=selected,
            ),
        )
        assert (
            system.call("verification-close", review(system, "verified", selected))[0]
            == 409
        )
        assert system.call("verification-close", review(system, "followup"))[0] == 409
        system.ok("verification-close", review(system, "abandoned", selected))
        assert (
            system.ok("verification-close", review(system, "abandoned"))[
                "outcome_at_closure"
            ]
            == "abandoned"
        )
        assert not system.ok("verification-assess", OP)["current"]


def test_expired_valid_proofs_cannot_close_and_are_visible_in_unresolved_queue(
    verified_system: tuple[Client, dict[str, SigningController]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ix_blackfox.verification import loop

    system, signers = verified_system
    with system.running():
        activate(system)
        system.ok("dispatch", system.step_evidence(FIRST, "human-stage"), "stage")
        complete(system, signers)
        close_request = review(system, "verified")

        class Later(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> datetime:
                return datetime.now(tz) + timedelta(hours=2)

        monkeypatch.setattr(loop, "datetime", Later)
        assert assessment(system)["status"] == "pending"
        pending = system.ok("verification-unresolved", {"after": "", "limit": 1})
        assert set(pending["unresolved"][0]["unresolved_requirements"].values()) == {
            "stale"
        }
        assert system.call("verification-close", close_request)[0] == 409
