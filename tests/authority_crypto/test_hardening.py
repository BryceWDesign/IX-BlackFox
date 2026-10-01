from __future__ import annotations

import copy
import json
import math
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    RECEIPT_TYPE,
    AuthorityProofError,
    canonical_bytes,
    digest,
)
from ix_blackfox.authority_crypto.signing import SigningController
from ix_blackfox.authority_crypto.verification import (
    checkpoint_body,
    verify_bundle,
    verify_receipt,
)
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.operating.models import digest_payload
from tests.authority_crypto.conftest import denial
from tests.authority_crypto.test_gateway import request


def resign(receipt: dict[str, Any], controller: SigningController) -> dict[str, Any]:
    body = {
        k: copy.deepcopy(v)
        for k, v in receipt.items()
        if k not in {"receipt_digest", "receipt_id", "attestation"}
    }
    body["receipt_id"] = "wave16-receipt-" + digest(body)
    body["receipt_digest"] = digest(body)
    body["attestation"] = controller.envelope(RECEIPT_TYPE, body.copy())
    return body


def test_older_checkpoint_accepts_valid_extension(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    older = store.export_bundle()
    for _ in range(4):
        store.append(denial())
    current = store.export_bundle()
    report = verify_bundle(
        current, controller.policy, expected_checkpoint=older["checkpoint"]
    )
    assert report.passed and report.checkpoint_matched and report.receipt_count == 5
    assert "latestness beyond" in report.to_dict()["completeness"]


@pytest.mark.parametrize("count", [True, -1, 1.0, "1", 10])
def test_malformed_retained_count_rejected(
    store: AuthorityReceiptStore, controller: SigningController, count: Any
) -> None:
    store.append(denial())
    bundle = store.export_bundle()
    retained = checkpoint_body(bundle["receipts"], controller.policy)
    retained["receipt_count"] = count
    assert not verify_bundle(
        bundle,
        controller.policy,
        expected_checkpoint=controller.envelope(CHECKPOINT_TYPE, retained),
    ).passed


def test_empty_retained_prefix(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    retained = store.export_bundle()["checkpoint"]
    store.append(denial())
    assert verify_bundle(
        store.export_bundle(), controller.policy, expected_checkpoint=retained
    ).passed


@pytest.mark.parametrize(
    "field",
    ["head_digest", "receipts_sha256", "stream_id", "deployment_id", "schema_version"],
)
def test_retained_prefix_fields_must_match(
    store: AuthorityReceiptStore, controller: SigningController, field: str
) -> None:
    store.append(denial())
    bundle = store.export_bundle()
    retained = checkpoint_body(bundle["receipts"], controller.policy)
    retained[field] = "wrong"
    assert not verify_bundle(
        bundle,
        controller.policy,
        expected_checkpoint=controller.envelope(CHECKPOINT_TYPE, retained),
    ).passed


def test_signed_fork_cannot_extend_old_checkpoint(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    old = store.export_bundle()
    fork = copy.deepcopy(old)
    fork["receipts"][0]["upstream_error"] = "different history"
    fork["receipts"][0] = resign(fork["receipts"][0], controller)
    fork["checkpoint"] = controller.envelope(
        CHECKPOINT_TYPE, checkpoint_body(fork["receipts"], controller.policy)
    )
    assert verify_bundle(fork, controller.policy).passed
    assert not verify_bundle(
        fork, controller.policy, expected_checkpoint=old["checkpoint"]
    ).passed


@pytest.mark.parametrize(
    "attack",
    [
        "allow",
        "allowed",
        "subject",
        "principal",
        "evidence",
        "status",
        "response",
        "claims",
    ],
)
def test_signed_minimal_denial_semantics(
    store: AuthorityReceiptStore, controller: SigningController, attack: str
) -> None:
    record = store.append(denial())
    if attack == "allow":
        record["authority_decision"]["status"] = "allow"
    elif attack == "allowed":
        record["authority_decision"]["allowed"] = True
    elif attack == "subject":
        record["subject"]["digest"] = "a" * 64
    elif attack == "principal":
        record["authenticated_principal"] = {"agent_id": "test-agent"}
    elif attack == "evidence":
        record["evaluated_evidence_digests"] = {"ev": "a" * 64}
    elif attack == "status":
        record["upstream_status"] = 200
    elif attack == "response":
        record["upstream_response_sha256"] = "a" * 64
    else:
        record["single_use_evidence_claims"] = ["ev"]
    with pytest.raises(AuthorityProofError):
        verify_receipt(resign(record, controller), controller.policy)


@pytest.mark.parametrize(
    "attack",
    [
        "allow",
        "subject_digest",
        "decision_digest",
        "principal",
        "evidence",
        "decision_subject",
        "schema",
    ],
)
def test_signed_evaluated_denial_semantics(
    signed_gateway: LiveAuthorityGateway, controller: SigningController, attack: str
) -> None:
    payload, headers = request(signed_gateway)
    payload["context"]["evidence_refs"] = []
    response = signed_gateway.handle_api(payload=payload, headers=headers)
    assert response.status != 200
    record = signed_gateway.receipt_store.recent()[0]
    assert record["record_type"] == "denial"
    assert "schema_version" in record["subject"]
    if attack == "allow":
        record["authority_decision"].update(allowed=True, status="allow")
        record["authority_decision"]["digest"] = digest_payload(
            {k: v for k, v in record["authority_decision"].items() if k != "digest"}
        )
    elif attack == "subject_digest":
        record["subject"]["digest"] = "a" * 64
    elif attack == "decision_digest":
        record["authority_decision"]["digest"] = "a" * 64
    elif attack == "principal":
        record["authenticated_principal"]["agent_id"] = "wrong"
    elif attack == "evidence":
        record["evaluated_evidence_digests"] = {"extra": "a" * 64}
    elif attack == "decision_subject":
        record["authority_decision"]["subject"]["agent_id"] = "wrong"
        record["authority_decision"]["digest"] = digest_payload(
            {k: v for k, v in record["authority_decision"].items() if k != "digest"}
        )
    else:
        record["authority_decision"]["schema_version"] = "wrong"
        record["authority_decision"]["digest"] = digest_payload(
            {k: v for k, v in record["authority_decision"].items() if k != "digest"}
        )
    with pytest.raises(AuthorityProofError):
        verify_receipt(resign(record, controller), controller.policy)


def test_steady_append_does_not_load_history(
    store: AuthorityReceiptStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any) -> Any:
        pytest.fail("Steady append replayed history")

    monkeypatch.setattr(AuthorityReceiptStore, "_signed_records", forbidden)
    for _ in range(1000):
        store.append(denial())
    assert store.recent(1)[0]["sequence"] == 1000


def test_restart_rebuilds_state(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    for _ in range(20):
        store.append(denial())
    path = store.path
    store.close()
    recovered = AuthorityReceiptStore(path, controller)
    assert recovered.append(denial())["sequence"] == 21
    assert recovered.verify_chain().passed
    recovered.close()


def test_other_writer_is_reconciled(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    peer = AuthorityReceiptStore(store.path, controller)
    assert store.append(denial())["sequence"] == 1
    assert peer.append(denial())["sequence"] == 2
    assert store.append(denial())["sequence"] == 3
    assert store.verify_chain().passed
    peer.close()


@pytest.mark.parametrize("attack", ["payload", "index", "delete", "claim"])
def test_external_old_history_edit_invalidates_cache(
    store: AuthorityReceiptStore, attack: str
) -> None:
    for _ in range(10):
        store.append(denial())
    with sqlite3.connect(store.path) as connection:
        if attack == "payload":
            connection.execute("UPDATE receipts SET payload_json='{}' WHERE sequence=1")
        elif attack == "index":
            connection.execute(
                "UPDATE receipts SET receipt_digest='wrong' WHERE sequence=1"
            )
        elif attack == "delete":
            connection.execute("DELETE FROM receipts WHERE sequence=10")
        else:
            # A claim-table commit also invalidates the observer. The receipt
            # history is still valid, so a replay followed by append is allowed.
            connection.execute(
                "INSERT INTO evidence_claims VALUES ('ev','sub','time','wrong')"
            )
    if attack == "claim":
        assert store.append(denial())["sequence"] == 11
        assert not store.verify_chain().passed
    else:
        with pytest.raises(AuthorityProofError):
            store.append(denial())


def test_remote_signer_does_not_hold_sqlite_write_lock(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    underlying = controller.signer

    class WitnessSigner:
        key_id = underlying.key_id
        algorithm = underlying.algorithm

        def sign(self, data: bytes) -> bytes:
            with sqlite3.connect(store.path, timeout=0.1) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            return underlying.sign(data)

    controller.signer = WitnessSigner()
    assert store.append(denial())["sequence"] == 1


def test_external_commit_during_signing_retries(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    underlying = controller.signer
    peer = AuthorityReceiptStore(
        store.path, SigningController(underlying, controller.policy)
    )

    class RacingSigner:
        key_id = underlying.key_id
        algorithm = underlying.algorithm
        once = False

        def sign(self, data: bytes) -> bytes:
            if not self.once:
                self.once = True
                assert peer.append(denial())["sequence"] == 1
            return underlying.sign(data)

    controller.signer = RacingSigner()
    assert store.append(denial())["sequence"] == 2
    assert store.verify_chain().passed
    peer.close()


def test_failed_insert_does_not_advance_cache(store: AuthorityReceiptStore) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected failure'); END"
        )
    with pytest.raises(sqlite3.Error):
        store.append(denial())
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER fail_insert")
    assert store.append(denial())["sequence"] == 1


def test_concurrent_independent_stores(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    peers = [
        store,
        AuthorityReceiptStore(store.path, controller),
        AuthorityReceiptStore(store.path, controller),
    ]
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda i: peers[i % 3].append(denial()), range(45)))
    assert sorted(r["sequence"] for r in results) == list(range(1, 46))
    assert store.verify_chain().passed
    for peer in peers[1:]:
        peer.close()


def test_revoked_history_cannot_be_hidden_by_cache(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    controller.policy = replace(
        controller.policy, keys=(replace(controller.policy.keys[0], revoked=True),)
    )
    with pytest.raises(AuthorityProofError):
        store.append(denial())


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_legacy_digest_rejects_nonfinite(value: float) -> None:
    with pytest.raises(ValueError):
        digest_payload({"nested": [value]})


def test_fixed_canonicalization_vectors() -> None:
    vectors = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "examples/wave16/canonicalization-vectors.json"
        ).read_text(encoding="utf-8")
    )
    for vector in vectors["vectors"]:
        value = vector["value"]
        assert canonical_bytes(value).hex() == vector["v1_utf8_hex"]
        assert digest(value) == vector["v1_sha256"]
        legacy = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        assert legacy.hex() == vector["legacy_utf8_hex"]
        assert digest_payload(value) == vector["legacy_sha256"]


def _receipt_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in record.items()
        if key
        not in {
            "schema_version",
            "deployment_id",
            "stream_id",
            "sequence",
            "previous_receipt_digest",
            "receipt_id",
            "receipt_digest",
            "attestation",
        }
    }


@pytest.mark.parametrize(
    "attack", ["duplicate_outcome", "duplicate_approval", "parent_mutation"]
)
def test_incremental_authorization_state(
    signed_gateway: LiveAuthorityGateway,
    controller: SigningController,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    tmp_path: Path,
) -> None:
    from ix_blackfox.live_gateway.upstream import UpstreamResponse

    payload, headers = request(signed_gateway)
    monkeypatch.setattr(
        "ix_blackfox.live_gateway.service.request_upstream",
        lambda **kwargs: UpstreamResponse(status=200, headers=(), body=b"done"),
    )
    assert signed_gateway.handle_api(payload=payload, headers=headers).status == 200
    outcome, authorization = signed_gateway.receipt_store.recent()
    if attack == "duplicate_outcome":
        with pytest.raises(AuthorityProofError):
            signed_gateway.receipt_store.append(_receipt_payload(outcome))
    elif attack == "duplicate_approval":
        with pytest.raises(AuthorityProofError):
            signed_gateway.receipt_store.append(_receipt_payload(authorization))
    else:
        other = AuthorityReceiptStore(tmp_path / "detached.sqlite3", controller)
        returned = other.append(_receipt_payload(authorization))
        returned["subject"]["agent_id"] = "caller mutation"
        new_outcome = _receipt_payload(outcome)
        original = other.recent()[0]
        new_outcome["authorization_receipt_id"] = original["receipt_id"]
        new_outcome["authorization_receipt_digest"] = original["receipt_digest"]
        assert other.append(new_outcome)["sequence"] == 2
        other.close()
    assert signed_gateway.receipt_store.verify_chain().passed


def test_corrupt_history_rejected_on_startup(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE receipts SET payload_json='{}'")
    with pytest.raises(AuthorityProofError):
        AuthorityReceiptStore(store.path, controller)


def test_external_tamper_during_signing_cannot_commit(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    underlying = controller.signer

    class TamperingSigner:
        key_id = underlying.key_id
        algorithm = underlying.algorithm

        def sign(self, data: bytes) -> bytes:
            with sqlite3.connect(store.path) as connection:
                connection.execute(
                    "UPDATE receipts SET payload_json='{}' WHERE sequence=1"
                )
            return underlying.sign(data)

    controller.signer = TamperingSigner()
    with pytest.raises(AuthorityProofError):
        store.append(denial())
    assert len(store.recent()) == 1


def test_close_releases_database(store: AuthorityReceiptStore) -> None:
    store.append(denial())
    store.close()
    store.path.unlink()
    with pytest.raises(AuthorityProofError):
        store.append(denial())
