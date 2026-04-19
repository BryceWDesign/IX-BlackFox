from __future__ import annotations

import base64

import pytest

from ix_blackfox.vault import (
    SealedPayload,
    fingerprint_bytes,
    seal_payload,
    verify_seal,
    zeroize_text,
)


def test_seal_payload_and_verify_round_trip() -> None:
    sealed = seal_payload(
        {"task_id": "task-001", "status": "ready"},
        secret="blackfox-secret",
        purpose="runtime-state",
    )

    assert sealed.algorithm == "hmac-sha256"
    assert sealed.purpose == "runtime-state"
    assert verify_seal(sealed, secret="blackfox-secret") is True
    assert sealed.payload_dict() == {"status": "ready", "task_id": "task-001"}


def test_verify_seal_detects_tampering() -> None:
    sealed = seal_payload(
        {"task_id": "task-001", "status": "ready"},
        secret="blackfox-secret",
        purpose="runtime-state",
    )

    tampered = SealedPayload(
        purpose=sealed.purpose,
        payload_b64=base64.b64encode(
            b'{"status":"compromised","task_id":"task-001"}'
        ).decode("ascii"),
        digest=sealed.digest,
        created_at=sealed.created_at,
        algorithm=sealed.algorithm,
    )

    assert verify_seal(tampered, secret="blackfox-secret") is False


def test_fingerprint_bytes_is_stable() -> None:
    first = fingerprint_bytes(b"blackfox")
    second = fingerprint_bytes(b"blackfox")
    third = fingerprint_bytes(b"blackfox-v2")

    assert first == second
    assert first != third
    assert len(first) == 64


def test_zeroize_text_returns_same_length_mask() -> None:
    masked = zeroize_text("super-secret")
    assert masked == "************"
    assert len(masked) == len("super-secret")


@pytest.mark.parametrize(
    ("payload", "purpose", "secret", "message"),
    [
        (
            {"ok": object()},
            "runtime-state",
            "secret",
            "not JSON-serializable",
        ),
        (
            {"ok": True},
            "   ",
            "secret",
            "Vault purpose must not be empty",
        ),
        (
            {"ok": True},
            "runtime-state",
            "",
            "Vault secret must not be empty",
        ),
    ],
)
def test_vault_helpers_reject_invalid_inputs(
    payload: dict[str, object],
    purpose: str,
    secret: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        seal_payload(payload, secret=secret, purpose=purpose)
