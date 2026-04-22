from __future__ import annotations

from dataclasses import replace

from ix_blackfox.governance import (
    GovernanceReceiptLedger,
    ReceiptEventType,
)


def test_receipt_ledger_appends_chained_records() -> None:
    ledger = GovernanceReceiptLedger()

    first = ledger.append(
        intent_id="  INTENT-123  ",
        event_type=ReceiptEventType.POLICY_REVIEW_REQUIRED,
        summary="  Policy evaluation requires review.  ",
        actor="  governance.policy  ",
        metadata={"reason": "high-risk"},
    )
    second = ledger.append(
        intent_id="intent-123",
        event_type=ReceiptEventType.APPROVAL_RECORDED,
        summary="Approval was recorded for the governed action.",
        actor="governance.approval",
        metadata={"approval_id": "approval-1"},
    )

    assert first.intent_id == "intent-123"
    assert first.summary == "Policy evaluation requires review."
    assert first.actor == "governance.policy"
    assert first.previous_receipt_id is None
    assert first.previous_chain_digest is None

    assert second.previous_receipt_id == first.receipt_id
    assert second.previous_chain_digest == first.chain_digest
    assert ledger.count() == 2


def test_receipt_snapshot_filters_and_returns_latest_for_intent() -> None:
    ledger = GovernanceReceiptLedger()

    ledger.append(
        intent_id="intent-a",
        event_type=ReceiptEventType.POLICY_ALLOWED,
        summary="Action is allowed by policy.",
    )
    last_for_a = ledger.append(
        intent_id="intent-a",
        event_type=ReceiptEventType.EXECUTION_COMPLETED,
        summary="Action executed successfully.",
    )
    ledger.append(
        intent_id="intent-b",
        event_type=ReceiptEventType.POLICY_BLOCKED,
        summary="Action was blocked.",
    )

    snapshot = ledger.snapshot()

    intent_a_records = snapshot.filter_by_intent(" intent-a ")
    assert len(intent_a_records) == 2
    assert snapshot.latest_for_intent("intent-a") == last_for_a
    assert snapshot.latest_for_intent("intent-missing") is None


def test_receipt_chain_verification_detects_tampering() -> None:
    ledger = GovernanceReceiptLedger()

    ledger.append(
        intent_id="intent-9",
        event_type=ReceiptEventType.POLICY_ALLOWED,
        summary="Action is allowed by policy.",
        metadata={"rule": "low-risk-default"},
    )
    ledger.append(
        intent_id="intent-9",
        event_type=ReceiptEventType.EXECUTION_COMPLETED,
        summary="Action completed successfully.",
        metadata={"exit_code": 0},
    )

    assert ledger.verify_intent_chain("intent-9") is True

    snapshot = ledger.snapshot()
    tampered = replace(
        snapshot.records[1],
        summary="Tampered summary",
    )
    ledger._records[1] = tampered

    assert ledger.verify_intent_chain("intent-9") is False


def test_receipt_chain_verification_is_independent_per_intent() -> None:
    ledger = GovernanceReceiptLedger()

    ledger.append(
        intent_id="intent-alpha",
        event_type=ReceiptEventType.POLICY_ALLOWED,
        summary="Alpha action allowed.",
    )
    ledger.append(
        intent_id="intent-beta",
        event_type=ReceiptEventType.POLICY_BLOCKED,
        summary="Beta action blocked.",
    )
    ledger.append(
        intent_id="intent-alpha",
        event_type=ReceiptEventType.VERIFICATION_PASSED,
        summary="Alpha verification passed.",
    )

    assert ledger.verify_intent_chain("intent-alpha") is True
    assert ledger.verify_intent_chain("intent-beta") is True
