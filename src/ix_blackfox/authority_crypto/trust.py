from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    decode64,
    fields,
    pae,
    read_document,
    strict_json,
    text_field,
)

PublicKey = ed25519.Ed25519PublicKey | rsa.RSAPublicKey | ec.EllipticCurvePublicKey
ALGORITHMS = {"Ed25519", "RSA-PSS-SHA256", "RSA-PKCS1-SHA256", "ECDSA-P256-SHA256"}


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise AuthorityProofError("Timestamp must be a string.")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityProofError("Invalid timestamp.") from exc
    if result.tzinfo is None:
        raise AuthorityProofError("Timestamp requires timezone.")
    return result.astimezone(UTC)


def public_key(pem: str, algorithm: str) -> PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise AuthorityProofError("Invalid pinned public key.") from exc
    if algorithm == "Ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
        return key
    if (
        algorithm in {"RSA-PSS-SHA256", "RSA-PKCS1-SHA256"}
        and isinstance(key, rsa.RSAPublicKey)
        and key.key_size >= 2048
    ):
        return key
    if (
        algorithm == "ECDSA-P256-SHA256"
        and isinstance(key, ec.EllipticCurvePublicKey)
        and isinstance(key.curve, ec.SECP256R1)
    ):
        return key
    raise AuthorityProofError("Key type, size or algorithm is not supported.")


def fingerprint(key: PublicKey) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def verify_signature(
    key: PublicKey, algorithm: str, signature: bytes, data: bytes
) -> None:
    try:
        if isinstance(key, ed25519.Ed25519PublicKey) and algorithm == "Ed25519":
            key.verify(signature, data)
        elif isinstance(key, rsa.RSAPublicKey) and algorithm == "RSA-PSS-SHA256":
            key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif isinstance(key, rsa.RSAPublicKey) and algorithm == "RSA-PKCS1-SHA256":
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif (
            isinstance(key, ec.EllipticCurvePublicKey)
            and algorithm == "ECDSA-P256-SHA256"
        ):
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise AuthorityProofError("Unsupported verification algorithm.")
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityProofError("Invalid authority signature.") from exc


@dataclass(frozen=True)
class TrustKey:
    key_id: str
    algorithm: str
    key: PublicKey
    not_before: datetime
    not_after: datetime
    revoked: bool


@dataclass(frozen=True)
class TrustPolicy:
    deployment_id: str
    stream_id: str
    keys: tuple[TrustKey, ...]
    expires_at: datetime
    clock_skew_seconds: int

    @classmethod
    def load(cls, path: Path) -> TrustPolicy:
        return cls.from_dict(read_document(path))

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TrustPolicy:
        fields(
            payload,
            {
                "schema_version",
                "deployment_id",
                "stream_id",
                "keys",
                "expires_at",
                "clock_skew_seconds",
            },
        )
        if payload["schema_version"] != "wave16.trust_policy.v1":
            raise AuthorityProofError("Wrong trust policy schema.")
        skew = payload["clock_skew_seconds"]
        if type(skew) is not int or not 0 <= skew <= 300:
            raise AuthorityProofError("Clock skew must be 0..300 seconds.")
        raw_keys = payload["keys"]
        if not isinstance(raw_keys, list) or not raw_keys:
            raise AuthorityProofError("Trust policy requires pinned keys.")
        keys: list[TrustKey] = []
        seen: set[str] = set()
        for item in raw_keys:
            fields(
                item,
                {
                    "key_id",
                    "algorithm",
                    "public_key_pem",
                    "spki_sha256",
                    "not_before",
                    "not_after",
                    "revoked",
                },
            )
            key_id = text_field(item, "key_id")
            algorithm = text_field(item, "algorithm")
            key = public_key(text_field(item, "public_key_pem"), algorithm)
            if (
                fingerprint(key) != item["spki_sha256"]
                or key_id in seen
                or type(item["revoked"]) is not bool
            ):
                raise AuthorityProofError("Invalid or duplicate trust key binding.")
            before, after = timestamp(item["not_before"]), timestamp(item["not_after"])
            if before >= after:
                raise AuthorityProofError("Invalid signing key validity interval.")
            seen.add(key_id)
            keys.append(
                TrustKey(key_id, algorithm, key, before, after, item["revoked"])
            )
        return cls(
            text_field(payload, "deployment_id"),
            text_field(payload, "stream_id"),
            tuple(keys),
            timestamp(payload["expires_at"]),
            skew,
        )

    def verify(
        self, envelope: Any, payload_type: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        fields(envelope, {"payloadType", "payload", "signatures"})
        if envelope["payloadType"] != payload_type or now >= self.expires_at:
            raise AuthorityProofError("Wrong signature domain or expired trust policy.")
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise AuthorityProofError("Exactly one authority signature is required.")
        sig = fields(signatures[0], {"keyid", "sig"})
        key = next((item for item in self.keys if item.key_id == sig["keyid"]), None)
        if key is None or key.revoked:
            raise AuthorityProofError("Signing key is untrusted or currently revoked.")
        raw = decode64(envelope["payload"])
        statement = strict_json(raw)
        fields(
            statement,
            {
                "schema_version",
                "deployment_id",
                "stream_id",
                "key_id",
                "algorithm",
                "signed_at",
                "body",
            },
        )
        if raw != canonical_bytes(statement):
            raise AuthorityProofError("Signed payload is not canonical.")
        if (
            statement["schema_version"] != "wave16.signed_statement.v1"
            or statement["deployment_id"] != self.deployment_id
            or statement["stream_id"] != self.stream_id
            or statement["key_id"] != key.key_id
            or statement["algorithm"] != key.algorithm
        ):
            raise AuthorityProofError("Signing authority domain mismatch.")
        signed_at = timestamp(statement["signed_at"])
        if (
            not key.not_before <= signed_at < key.not_after
            or (signed_at - now).total_seconds() > self.clock_skew_seconds
        ):
            raise AuthorityProofError("Signature is outside the trusted time interval.")
        verify_signature(
            key.key, key.algorithm, decode64(sig["sig"]), pae(payload_type, raw)
        )
        if not isinstance(statement["body"], dict):
            raise AuthorityProofError("Signed body must be an object.")
        return dict(statement["body"])
