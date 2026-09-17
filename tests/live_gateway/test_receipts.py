from __future__ import annotations

import sqlite3
from pathlib import Path

from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore


def _payload(index: int) -> dict[str, object]:
    return {
        "recorded_at": f"2026-09-17T00:00:0{index}+00:00",
        "protocol": "test/v1",
        "subject": {"index": index},
        "authority_decision": {"status": "allow"},
        "evidence_refs": [],
        "single_use_evidence_claims": [],
        "upstream_attempted": True,
        "upstream_status": 200,
        "upstream_response_sha256": "",
        "upstream_error": "",
        "execution_state": "response_received",
        "executed": True,
    }


def test_sqlite_receipts_are_hash_chained_and_reverified(tmp_path: Path) -> None:
    store = AuthorityReceiptStore(tmp_path / "receipts.sqlite3")
    first = store.append(_payload(1))
    second = store.append(_payload(2))
    result = store.verify_chain()

    assert first["sequence"] == 1
    assert second["sequence"] == 2
    assert second["previous_receipt_digest"] == first["receipt_digest"]
    assert result.passed is True
    assert result.receipt_count == 2


def test_receipt_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "receipts.sqlite3"
    store = AuthorityReceiptStore(path)
    receipt = store.append(_payload(1))
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE receipts SET payload_json = ? WHERE receipt_id = ?",
            ('{"receipt_id":"tampered"}', receipt["receipt_id"]),
        )
        connection.commit()

    result = store.verify_chain()
    assert result.passed is False
    assert result.issues


def test_single_use_evidence_claim_is_atomic_and_replay_safe(tmp_path: Path) -> None:
    store = AuthorityReceiptStore(tmp_path / "receipts.sqlite3")
    first = store.claim_single_use_evidence(
        ("human-approval-1",), subject_digest="a" * 64, claimed_at="2026-09-17T00:00:00+00:00"
    )
    second = store.claim_single_use_evidence(
        ("human-approval-1",), subject_digest="a" * 64, claimed_at="2026-09-17T00:00:01+00:00"
    )
    assert first == ()
    assert second == ("human-approval-1",)


def test_reserved_single_use_evidence_survives_crash_without_breaking_receipt_chain(
    tmp_path: Path,
) -> None:
    store = AuthorityReceiptStore(tmp_path / "receipts.sqlite3")
    assert store.claim_single_use_evidence(
        ("human-approval-crash",),
        subject_digest="b" * 64,
        claimed_at="2026-09-17T00:00:00+00:00",
    ) == ()
    # A process can fail after the atomic reservation but before a receipt append. The
    # approval remains consumed (safe), while receipt-chain integrity still verifies.
    result = store.verify_chain()
    assert result.passed is True
    assert store.claim_single_use_evidence(
        ("human-approval-crash",),
        subject_digest="b" * 64,
        claimed_at="2026-09-17T00:00:01+00:00",
    ) == ("human-approval-crash",)
