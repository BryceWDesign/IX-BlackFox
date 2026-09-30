from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    RECEIPT_TYPE,
    AuthorityProofError,
    canonical_bytes,
    decode64,
    digest,
    encode64,
    pae,
    strict_json,
)
from ix_blackfox.authority_crypto.signing import SigningController
from ix_blackfox.authority_crypto.verification import (
    checkpoint_body,
    verify_bundle,
    verify_receipt,
)
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from tests.authority_crypto.conftest import denial


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b"[]",
        b'{"a":"\\ud800"}',
        b'{"\\udfff":1}',
        b"\xff",
        b'{"a":9007199254740992}',
        b"{",
    ],
)
def test_ambiguous_json_is_rejected(raw: bytes) -> None:
    with pytest.raises(AuthorityProofError):
        strict_json(raw)


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), 2**53, {1: "x"}, (1, 2), "\ud800"]
)
def test_invalid_canonical_values_rejected(value: object) -> None:
    with pytest.raises(AuthorityProofError):
        canonical_bytes(value)


def test_dsse_uses_utf8_byte_lengths() -> None:
    assert pae("é", b"abc") == b"DSSEv1 2 \xc3\xa9 3 abc"
    assert canonical_bytes({"z": 1, "a": "é"}) == b'{"a":"\xc3\xa9","z":1}'


@pytest.mark.parametrize("value", ["YQ", "YR==", "YQ==\n", "***=", 42])
def test_noncanonical_base64_rejected(value: object) -> None:
    with pytest.raises(AuthorityProofError):
        decode64(value)


@pytest.mark.parametrize(
    "field",
    [
        "subject",
        "authority_decision",
        "record_type",
        "protocol",
        "recorded_at",
        "executed",
        "upstream_error",
        "sequence",
        "previous_receipt_digest",
        "receipt_digest",
        "receipt_id",
        "deployment_id",
        "stream_id",
        "evidence_refs",
    ],
)
def test_tampering_rejected_even_after_hash_recomputed(
    store: AuthorityReceiptStore, controller: SigningController, field: str
) -> None:
    receipt = store.append(denial())
    receipt[field] = "tampered"
    if field != "receipt_digest":
        receipt["receipt_digest"] = digest(
            {
                k: v
                for k, v in receipt.items()
                if k not in {"receipt_digest", "attestation"}
            }
        )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, controller.policy)


@pytest.mark.parametrize(
    "mutation",
    ["type", "signature", "key", "extra", "multi", "payload", "noncanonical"],
)
def test_envelope_attack_rejected(
    store: AuthorityReceiptStore, controller: SigningController, mutation: str
) -> None:
    receipt = store.append(denial())
    env = receipt["attestation"]
    if mutation == "type":
        env["payloadType"] = CHECKPOINT_TYPE
    elif mutation == "signature":
        env["signatures"][0]["sig"] = encode64(b"x" * 64)
    elif mutation == "key":
        env["signatures"][0]["keyid"] = "untrusted"
    elif mutation == "extra":
        env["public_key"] = "self asserted"
    elif mutation == "multi":
        env["signatures"].append(copy.deepcopy(env["signatures"][0]))
    elif mutation == "payload":
        env["payload"] = encode64(b"{}")
    else:
        env["payload"] = encode64(
            json.dumps(strict_json(decode64(env["payload"])), indent=2).encode()
        )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, controller.policy)


def test_current_revocation_rejects_previously_signed_history(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    receipt = store.append(denial())
    revoked = replace(
        controller.policy, keys=(replace(controller.policy.keys[0], revoked=True),)
    )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, revoked)


def test_expired_policy_rejects_history(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    receipt = store.append(denial())
    expired = replace(
        controller.policy, expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, expired)


def test_independent_checkpoint_detects_rollback_of_valid_snapshot(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    old = store.export_bundle()
    store.append(denial())
    current = store.export_bundle()
    assert verify_bundle(old, controller.policy).passed
    assert not verify_bundle(
        old, controller.policy, expected_checkpoint=current["checkpoint"]
    ).passed
    assert verify_bundle(
        current, controller.policy, expected_checkpoint=current["checkpoint"]
    ).passed


def test_same_snapshot_can_be_resigned_against_retained_checkpoint(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    first = store.export_bundle()
    second = store.export_bundle()
    assert first["checkpoint"] != second["checkpoint"]
    assert verify_bundle(
        second, controller.policy, expected_checkpoint=first["checkpoint"]
    ).passed


def test_exact_typed_checkpoint_comparison(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    bundle = store.export_bundle()
    body = checkpoint_body(bundle["receipts"], controller.policy)
    body["receipt_count"] = True
    bundle["checkpoint"] = controller.envelope(CHECKPOINT_TYPE, body)
    assert not verify_bundle(bundle, controller.policy).passed


@pytest.mark.parametrize(
    "attack", ["delete", "reorder", "duplicate", "unsigned", "checkpoint", "extra"]
)
def test_bundle_attack_rejected(
    store: AuthorityReceiptStore, controller: SigningController, attack: str
) -> None:
    for _ in range(3):
        store.append(denial())
    bundle = store.export_bundle()
    if attack == "delete":
        bundle["receipts"].pop()
    elif attack == "reorder":
        bundle["receipts"].reverse()
    elif attack == "duplicate":
        bundle["receipts"][1] = bundle["receipts"][0]
    elif attack == "unsigned":
        del bundle["receipts"][0]["attestation"]
    elif attack == "checkpoint":
        del bundle["checkpoint"]
    else:
        bundle["public_keys"] = []
    assert not verify_bundle(bundle, controller.policy).passed


@pytest.mark.parametrize(
    "column,value",
    [
        ("receipt_digest", "tampered"),
        ("previous_digest", "tampered"),
        ("payload_json", "{}"),
    ],
)
def test_database_tamper_blocks_future_append_and_export(
    store: AuthorityReceiptStore, column: str, value: str
) -> None:
    store.append(denial())
    with sqlite3.connect(store.path) as connection:
        connection.execute(f"UPDATE receipts SET {column}=?", (value,))
    assert not store.verify_chain().passed
    with pytest.raises(AuthorityProofError):
        store.append(denial())
    with pytest.raises(AuthorityProofError):
        store.export_bundle()


def test_concurrent_writes_have_one_valid_order(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(lambda _: store.append(denial()), range(16)))
    assert sorted(r["sequence"] for r in receipts) == list(range(1, 17))
    assert store.verify_chain().passed
    assert verify_bundle(store.export_bundle(), controller.policy).passed


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "sequence",
        "receipt_id",
        "receipt_digest",
        "attestation",
        "stream_id",
        "deployment_id",
        "previous_receipt_digest",
    ],
)
def test_payload_cannot_override_reserved_fields(
    store: AuthorityReceiptStore, field: str
) -> None:
    with pytest.raises(AuthorityProofError):
        store.append({**denial(), field: "override"})
    assert store.verify_chain().receipt_count == 0


def test_history_cannot_be_relabelled_as_signed(store: AuthorityReceiptStore) -> None:
    legacy = AuthorityReceiptStore(store.path)
    legacy.append(denial())
    with pytest.raises(AuthorityProofError):
        store.append(denial())
    with pytest.raises(AuthorityProofError):
        legacy.export_bundle()


def test_receipt_domain_cannot_verify_checkpoint(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    store.append(denial())
    checkpoint = store.export_bundle()["checkpoint"]
    with pytest.raises(AuthorityProofError):
        controller.policy.verify(checkpoint, RECEIPT_TYPE)


def test_untrusted_signing_key_with_matching_id_is_rejected(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from ix_blackfox.authority_crypto.signing import LocalSigner

    receipt = store.append(denial())
    body = {k: v for k, v in receipt.items() if k != "attestation"}
    raw = strict_json(decode64(receipt["attestation"]["payload"]))
    attacker = LocalSigner("test-key", "Ed25519", ed25519.Ed25519PrivateKey.generate())
    raw["body"] = body
    data = canonical_bytes(raw)
    receipt["attestation"]["payload"] = encode64(data)
    receipt["attestation"]["signatures"][0]["sig"] = encode64(
        attacker.sign(pae(RECEIPT_TYPE, data))
    )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, controller.policy)


@pytest.mark.parametrize(
    "change", ["deployment", "stream", "algorithm", "expired_key", "future"]
)
def test_signed_statement_trust_constraints_are_checked(
    store: AuthorityReceiptStore, controller: SigningController, change: str
) -> None:
    receipt = store.append(denial())
    env = receipt["attestation"]
    statement = strict_json(decode64(env["payload"]))
    if change == "deployment":
        statement["deployment_id"] = "other"
    elif change == "stream":
        statement["stream_id"] = "other"
    elif change == "algorithm":
        statement["algorithm"] = "RSA-PSS-SHA256"
    elif change == "expired_key":
        statement["signed_at"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    else:
        statement["signed_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    data = canonical_bytes(statement)
    env["payload"] = encode64(data)
    env["signatures"][0]["sig"] = encode64(
        controller.signer.sign(pae(RECEIPT_TYPE, data))
    )
    with pytest.raises(AuthorityProofError):
        verify_receipt(receipt, controller.policy)


def test_key_rotation_keeps_history_until_explicit_current_revocation(
    store: AuthorityReceiptStore, controller: SigningController
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from ix_blackfox.authority_crypto.cli import public_trust_document
    from ix_blackfox.authority_crypto.signing import LocalSigner
    from ix_blackfox.authority_crypto.trust import TrustPolicy

    store.append(denial())
    second = ed25519.Ed25519PrivateKey.generate()
    pem = (
        second.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    second_policy = TrustPolicy.from_dict(
        public_trust_document(pem, "second-key", "deployment", "stream")
    )
    controller.policy = replace(
        controller.policy, keys=(*controller.policy.keys, *second_policy.keys)
    )
    controller.signer = LocalSigner("second-key", "Ed25519", second)
    store.append(denial())
    assert verify_bundle(store.export_bundle(), controller.policy).passed
    controller.policy = replace(
        controller.policy,
        keys=(
            replace(controller.policy.keys[0], revoked=True),
            controller.policy.keys[1],
        ),
    )
    assert not store.verify_chain().passed
    with pytest.raises(AuthorityProofError):
        store.append(denial())


def test_malformed_signed_database_returns_failed_chain_report(
    store: AuthorityReceiptStore,
) -> None:
    store.append(denial())
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE receipts SET payload_json=?", ('{"sequence":NaN}',))
    assert not store.verify_chain().passed
