from __future__ import annotations

from dataclasses import replace

import pytest

from ix_blackfox.vault import ProvenanceLedger


def test_provenance_ledger_appends_chain_per_subject() -> None:
    ledger = ProvenanceLedger()

    first = ledger.append(
        subject="Patch Report",
        action="created",
        fingerprint="abc123",
        actor="forge",
        metadata={"size": 120},
    )
    second = ledger.append(
        subject="patch report",
        action="updated",
        fingerprint="def456",
        actor="forge",
        metadata={"size": 180},
    )

    assert first.subject == "patch report"
    assert first.action == "created"
    assert first.previous_record_id is None
    assert first.previous_chain_digest is None

    assert second.subject == "patch report"
    assert second.previous_record_id == first.record_id
    assert second.previous_chain_digest == first.chain_digest
    assert second.chain_digest != first.chain_digest
    assert ledger.verify_subject_chain("patch report") is True


def test_provenance_snapshot_filters_and_latest() -> None:
    ledger = ProvenanceLedger()
    first = ledger.append(
        subject="artifact-a",
        action="created",
        fingerprint="aaa111",
    )
    second = ledger.append(
        subject="artifact-b",
        action="created",
        fingerprint="bbb222",
    )
    third = ledger.append(
        subject="artifact-a",
        action="verified",
        fingerprint="ccc333",
    )

    snapshot = ledger.snapshot()

    assert snapshot.filter_by_subject("artifact-a") == (first, third)
    assert snapshot.latest_for_subject("artifact-b") == second
    assert snapshot.latest_for_subject("missing") is None


def test_provenance_chain_verification_detects_tampering() -> None:
    ledger = ProvenanceLedger()
    ledger.append(
        subject="artifact-a",
        action="created",
        fingerprint="aaa111",
    )
    original = ledger.append(
        subject="artifact-a",
        action="updated",
        fingerprint="bbb222",
    )

    tampered = replace(original, fingerprint="tampered")
    ledger._records[-1] = tampered

    assert ledger.verify_subject_chain("artifact-a") is False


def test_provenance_clear_resets_ledger() -> None:
    ledger = ProvenanceLedger()
    ledger.append(
        subject="artifact-a",
        action="created",
        fingerprint="aaa111",
    )
    ledger.append(
        subject="artifact-b",
        action="created",
        fingerprint="bbb222",
    )

    assert ledger.count() == 2

    ledger.clear()

    assert ledger.count() == 0
    assert ledger.snapshot().records == ()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "subject": "   ",
                "action": "created",
                "fingerprint": "abc123",
            },
            "Vault provenance subject must not be empty",
        ),
        (
            {
                "subject": "artifact-a",
                "action": "   ",
                "fingerprint": "abc123",
            },
            "Vault provenance action must not be empty",
        ),
        (
            {
                "subject": "artifact-a",
                "action": "created",
                "fingerprint": "   ",
            },
            "Vault provenance fingerprint must not be empty",
        ),
    ],
)
def test_provenance_rejects_invalid_inputs(
    kwargs: dict[str, str],
    message: str,
) -> None:
    ledger = ProvenanceLedger()

    with pytest.raises(ValueError, match=message):
        ledger.append(**kwargs)
