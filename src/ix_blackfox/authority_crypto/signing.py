from __future__ import annotations

import hashlib
import importlib
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    AuthorityProofError,
    canonical_bytes,
    encode64,
    pae,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    def sign(self, data: bytes) -> bytes: ...


@dataclass
class LocalSigner:
    key_id: str
    algorithm: str
    key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

    @classmethod
    def load(
        cls, path: Path, password_env: str, key_id: str, algorithm: str
    ) -> LocalSigner:
        password = os.environ.get(password_env, "").encode("utf-8")
        if len(password) < 16:
            raise AuthorityProofError(
                "Signing key password requires at least 16 bytes."
            )
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise AuthorityProofError("Signing key permissions must be owner-only.")
        raw = path.read_bytes()
        if not raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            raise AuthorityProofError(
                "Only encrypted PKCS8 keys are accepted from disk."
            )
        try:
            key = serialization.load_pem_private_key(raw, password)
        except (ValueError, TypeError) as exc:
            raise AuthorityProofError("Cannot load encrypted signing key.") from exc
        if not isinstance(
            key,
            ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        ):
            raise AuthorityProofError("Unsupported private key.")
        return cls(key_id, algorithm, key)

    def sign(self, data: bytes) -> bytes:
        if self.algorithm == "Ed25519" and isinstance(
            self.key, ed25519.Ed25519PrivateKey
        ):
            return self.key.sign(data)
        if isinstance(self.key, rsa.RSAPrivateKey) and self.key.key_size >= 2048:
            if self.algorithm == "RSA-PSS-SHA256":
                return self.key.sign(
                    data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256(),
                )
            if self.algorithm == "RSA-PKCS1-SHA256":
                return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        if (
            self.algorithm == "ECDSA-P256-SHA256"
            and isinstance(self.key, ec.EllipticCurvePrivateKey)
            and isinstance(self.key.curve, ec.SECP256R1)
        ):
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        raise AuthorityProofError("Unsupported signing key or algorithm.")


class KmsClient(Protocol):
    def sign(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass
class AwsKmsSigner:
    key_id: str
    algorithm: str
    kms_key_arn: str
    client: KmsClient

    def __post_init__(self) -> None:
        if not re.fullmatch(
            r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[a-fA-F0-9-]{36}",
            self.kms_key_arn,
        ):
            raise AuthorityProofError(
                "KMS requires an immutable key ARN, not an alias."
            )
        if self.algorithm not in {
            "RSA-PSS-SHA256",
            "RSA-PKCS1-SHA256",
            "ECDSA-P256-SHA256",
        }:
            raise AuthorityProofError("Unsupported KMS algorithm.")

    def sign(self, data: bytes) -> bytes:
        mapping = {
            "RSA-PSS-SHA256": "RSASSA_PSS_SHA_256",
            "RSA-PKCS1-SHA256": "RSASSA_PKCS1_V1_5_SHA_256",
            "ECDSA-P256-SHA256": "ECDSA_SHA_256",
        }
        algorithm = mapping[self.algorithm]
        try:
            result = self.client.sign(
                KeyId=self.kms_key_arn,
                Message=hashlib.sha256(data).digest(),
                MessageType="DIGEST",
                SigningAlgorithm=algorithm,
            )
        except Exception as exc:
            raise AuthorityProofError("KMS signing is unavailable.") from exc
        signature = result.get("Signature")
        if (
            result.get("KeyId") != self.kms_key_arn
            or result.get("SigningAlgorithm") != algorithm
            or not isinstance(signature, bytes)
            or not signature
        ):
            raise AuthorityProofError("KMS response binding is invalid.")
        return signature


@dataclass
class Pkcs11Signer:
    key_id: str
    algorithm: str
    module_path: str
    token_label: str
    private_key_label: str
    pin_env: str

    def sign(self, data: bytes) -> bytes:
        if self.algorithm != "RSA-PKCS1-SHA256":
            raise AuthorityProofError("PKCS11 profile requires RSA-PKCS1-SHA256.")
        pin = os.environ.get(self.pin_env, "")
        if not pin:
            raise AuthorityProofError("PKCS11 PIN is unavailable.")
        try:
            api = importlib.import_module("pkcs11")
            token = api.lib(self.module_path).get_token(token_label=self.token_label)
            with token.open(user_pin=pin) as session:
                key = session.get_key(
                    object_class=api.ObjectClass.PRIVATE_KEY,
                    key_type=api.KeyType.RSA,
                    label=self.private_key_label,
                )
                if (
                    key[api.Attribute.SENSITIVE] is not True
                    or key[api.Attribute.EXTRACTABLE] is not False
                ):
                    raise AuthorityProofError(
                        "Token key must be sensitive and non-extractable."
                    )
                signature = key.sign(data, mechanism=api.Mechanism.SHA256_RSA_PKCS)
                if not isinstance(signature, bytes) or not signature:
                    raise AuthorityProofError("Token returned an invalid signature.")
                return signature
        except Exception as exc:
            raise AuthorityProofError(
                "PKCS11 signing is unavailable or key policy is invalid."
            ) from exc


@dataclass
class SigningController:
    signer: Signer
    policy: TrustPolicy
    policy_path: Path | None = None

    def current_policy(self) -> TrustPolicy:
        policy = TrustPolicy.load(self.policy_path) if self.policy_path else self.policy
        if (policy.deployment_id, policy.stream_id) != (
            self.policy.deployment_id,
            self.policy.stream_id,
        ):
            raise AuthorityProofError(
                "Signing trust domain changed without stream migration."
            )
        return policy

    def envelope(self, payload_type: str, body: dict[str, Any]) -> dict[str, Any]:
        policy = self.current_policy()
        statement = {
            "schema_version": "wave16.signed_statement.v1",
            "deployment_id": policy.deployment_id,
            "stream_id": policy.stream_id,
            "key_id": self.signer.key_id,
            "algorithm": self.signer.algorithm,
            "signed_at": datetime.now(UTC).isoformat(),
            "body": body,
        }
        raw = canonical_bytes(statement)
        try:
            signature = self.signer.sign(pae(payload_type, raw))
        except Exception as exc:
            raise AuthorityProofError(
                "Required authority signing is unavailable."
            ) from exc
        result = {
            "payloadType": payload_type,
            "payload": encode64(raw),
            "signatures": [{"keyid": self.signer.key_id, "sig": encode64(signature)}],
        }
        self.current_policy().verify(result, payload_type)
        return result

    def health(self) -> None:
        self.envelope(CHECKPOINT_TYPE, {"probe": secrets.token_hex(16)})


@dataclass(frozen=True)
class SigningConfig:
    provider: str
    key_id: str
    algorithm: str
    trust_policy: Path
    options: Mapping[str, str]

    @classmethod
    def parse(cls, payload: Any, base: Path) -> SigningConfig:
        if not isinstance(payload, dict):
            raise AuthorityProofError("receipt_signing must be a TOML table.")
        common = {"provider", "key_id", "algorithm", "trust_policy"}
        extra = {
            "local": {"private_key", "password_env"},
            "aws_kms": {"kms_key_arn", "aws_region"},
            "pkcs11": {"module_path", "token_label", "private_key_label", "pin_env"},
        }
        provider = payload.get("provider")
        if (
            not isinstance(provider, str)
            or provider not in extra
            or set(payload) != common | extra[provider]
            or any(not isinstance(v, str) or not v.strip() for v in payload.values())
        ):
            raise AuthorityProofError(
                "Invalid provider-specific signing configuration."
            )
        options = {key: str(payload[key]) for key in extra[provider]}
        if provider == "local":
            options["private_key"] = str((base / options["private_key"]).resolve())
        if provider == "pkcs11":
            options["module_path"] = str((base / options["module_path"]).resolve())
        return cls(
            provider,
            str(payload["key_id"]),
            str(payload["algorithm"]),
            (base / str(payload["trust_policy"])).resolve(),
            options,
        )

    def build(self) -> SigningController:
        policy = TrustPolicy.load(self.trust_policy)
        signer: Signer
        if self.provider == "local":
            signer = LocalSigner.load(
                Path(self.options["private_key"]),
                self.options["password_env"],
                self.key_id,
                self.algorithm,
            )
        elif self.provider == "aws_kms":
            boto3 = importlib.import_module("boto3")
            config = importlib.import_module("botocore.config").Config(
                connect_timeout=5, read_timeout=10, retries={"total_max_attempts": 2}
            )
            client = boto3.client(
                "kms", region_name=self.options["aws_region"], config=config
            )
            signer = AwsKmsSigner(
                self.key_id, self.algorithm, self.options["kms_key_arn"], client
            )
        elif self.provider == "pkcs11":
            signer = Pkcs11Signer(
                self.key_id,
                self.algorithm,
                self.options["module_path"],
                self.options["token_label"],
                self.options["private_key_label"],
                self.options["pin_env"],
            )
        else:
            raise AuthorityProofError("Unsupported signing provider.")
        controller = SigningController(signer, policy, self.trust_policy)
        controller.health()
        return controller
