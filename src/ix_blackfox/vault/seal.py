from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class SealedPayload:
    """
    Integrity-sealed payload for BlackFox vault operations.

    This structure provides tamper-evident sealing, not confidentiality.
    Later vault layers can add encrypted storage on top of the same
    normalized envelope shape.

    Attributes
    ----------
    purpose:
        Logical purpose for the sealed payload.
    payload_b64:
        Base64-encoded canonical JSON payload bytes.
    digest:
        HMAC-SHA256 digest of the sealed payload bytes.
    created_at:
        UTC timestamp when the seal was created.
    algorithm:
        Signature algorithm identifier.
    """

    purpose: str
    payload_b64: str
    digest: str
    created_at: datetime
    algorithm: str = "hmac-sha256"

    def payload_bytes(self) -> bytes:
        """
        Return the decoded raw payload bytes.
        """
        return base64.b64decode(self.payload_b64.encode("ascii"))

    def payload_dict(self) -> dict[str, Any]:
        """
        Return the decoded payload as a JSON object.
        """
        raw = self.payload_bytes()
        return json.loads(raw.decode("utf-8"))


def seal_payload(
    payload: dict[str, Any],
    *,
    secret: str | bytes,
    purpose: str,
) -> SealedPayload:
    """
    Create a tamper-evident seal for a payload.

    Parameters
    ----------
    payload:
        Structured JSON-serializable payload.
    secret:
        HMAC secret used for integrity protection.
    purpose:
        Logical purpose label bound into the seal.

    Returns
    -------
    SealedPayload
        Integrity-sealed payload envelope.
    """
    normalized_purpose = _normalize_text(purpose, label="purpose")
    payload_bytes = _canonical_json_bytes(payload)
    digest = _compute_digest(
        payload_bytes=payload_bytes,
        secret=_secret_bytes(secret),
        purpose=normalized_purpose,
    )

    return SealedPayload(
        purpose=normalized_purpose,
        payload_b64=base64.b64encode(payload_bytes).decode("ascii"),
        digest=digest,
        created_at=_utc_now(),
    )


def verify_seal(
    sealed: SealedPayload,
    *,
    secret: str | bytes,
) -> bool:
    """
    Verify the integrity of a sealed payload.
    """
    expected = _compute_digest(
        payload_bytes=sealed.payload_bytes(),
        secret=_secret_bytes(secret),
        purpose=sealed.purpose,
    )
    return hmac.compare_digest(sealed.digest, expected)


def fingerprint_bytes(data: bytes) -> str:
    """
    Compute a stable SHA-256 hex digest for arbitrary bytes.
    """
    return hashlib.sha256(data).hexdigest()


def zeroize_text(value: str) -> str:
    """
    Return a same-length mask for sensitive text.

    Python strings are immutable, so this is a logical redaction helper
    rather than guaranteed in-memory erasure.
    """
    return "*" * len(value)


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except TypeError as exc:
        raise ValueError(f"Payload is not JSON-serializable: {exc}") from exc

    return encoded.encode("utf-8")


def _compute_digest(
    *,
    payload_bytes: bytes,
    secret: bytes,
    purpose: str,
) -> str:
    material = purpose.encode("utf-8") + b"\x00" + payload_bytes
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, bytes):
        secret_bytes = secret
    else:
        secret_bytes = secret.encode("utf-8")

    if not secret_bytes:
        raise ValueError("Vault secret must not be empty.")
    return secret_bytes


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Vault {label} must not be empty.")
    return cleaned


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
