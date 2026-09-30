from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from ix_blackfox.authority_crypto.cli import public_trust_document
from ix_blackfox.authority_crypto.encoding import RECEIPT_TYPE, AuthorityProofError
from ix_blackfox.authority_crypto.signing import (
    AwsKmsSigner,
    LocalSigner,
    Pkcs11Signer,
    SigningController,
)
from ix_blackfox.authority_crypto.sigstore import CosignAdapter
from ix_blackfox.authority_crypto.trust import TrustPolicy, verify_signature

ARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"


@pytest.mark.parametrize(
    "algorithm", ["RSA-PSS-SHA256", "RSA-PKCS1-SHA256", "ECDSA-P256-SHA256"]
)
def test_kms_digest_protocol_produces_real_verifiable_signature(algorithm: str) -> None:
    key = (
        ec.generate_private_key(ec.SECP256R1())
        if algorithm.startswith("ECDSA")
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    requests: list[dict[str, Any]] = []

    class KmsFixture:
        def sign(self, **kwargs: Any) -> dict[str, Any]:
            requests.append(kwargs)
            if isinstance(key, ec.EllipticCurvePrivateKey):
                signature = key.sign(
                    kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                )
            else:
                scheme = (
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
                    if algorithm == "RSA-PSS-SHA256"
                    else padding.PKCS1v15()
                )
                signature = key.sign(
                    kwargs["Message"], scheme, utils.Prehashed(hashes.SHA256())
                )
            return {
                "KeyId": ARN,
                "SigningAlgorithm": kwargs["SigningAlgorithm"],
                "Signature": signature,
            }

    signer = AwsKmsSigner("kms-key", algorithm, ARN, KmsFixture())
    data = b"a" * 8192
    signature = signer.sign(data)
    verify_signature(key.public_key(), algorithm, signature, data)
    assert requests[0]["MessageType"] == "DIGEST"
    assert requests[0]["Message"] == hashlib.sha256(data).digest()
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    policy = TrustPolicy.from_dict(
        public_trust_document(pem, "kms-key", "test", "test", algorithm)
    )
    controller = SigningController(signer, policy)
    env = controller.envelope(RECEIPT_TYPE, {"large_payload": "b" * 16384})
    assert policy.verify(env, RECEIPT_TYPE)["large_payload"] == "b" * 16384


@pytest.mark.parametrize(
    "failure", ["error", "arn", "algorithm", "empty", "invalid_signature"]
)
def test_kms_never_falls_back_when_response_or_provider_is_invalid(
    failure: str,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    policy = TrustPolicy.from_dict(
        public_trust_document(pem, "kms-key", "test", "test", "RSA-PSS-SHA256")
    )

    class KmsFixture:
        def sign(self, **kwargs: Any) -> dict[str, Any]:
            if failure == "error":
                raise RuntimeError("fixture unavailable")
            return {
                "KeyId": ARN + "wrong" if failure == "arn" else ARN,
                "SigningAlgorithm": "ECDSA_SHA_256"
                if failure == "algorithm"
                else "RSASSA_PSS_SHA_256",
                "Signature": b"" if failure == "empty" else b"invalid",
            }

    with pytest.raises(AuthorityProofError):
        SigningController(
            AwsKmsSigner("kms-key", "RSA-PSS-SHA256", ARN, KmsFixture()), policy
        ).envelope(RECEIPT_TYPE, {"proof": "test"})


def test_kms_alias_is_rejected() -> None:
    with pytest.raises(AuthorityProofError):
        AwsKmsSigner("key", "RSA-PSS-SHA256", "alias/receipt-key", SimpleNamespace())


def test_real_botocore_sign_api_contract() -> None:
    boto3 = pytest.importorskip("boto3")
    client = boto3.client(
        "kms",
        region_name="us-east-1",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    data = b"dsse fixture"
    stub = pytest.importorskip("botocore.stub")
    with stub.Stubber(client) as stubber:
        stubber.add_response(
            "sign",
            {
                "KeyId": ARN,
                "SigningAlgorithm": "RSASSA_PSS_SHA_256",
                "Signature": b"fixture-signature",
            },
            {
                "KeyId": ARN,
                "SigningAlgorithm": "RSASSA_PSS_SHA_256",
                "MessageType": "DIGEST",
                "Message": hashlib.sha256(data).digest(),
            },
        )
        assert (
            AwsKmsSigner("key", "RSA-PSS-SHA256", ARN, client).sign(data)
            == b"fixture-signature"
        )
        stubber.assert_no_pending_responses()


@pytest.mark.parametrize(
    "sensitive,extractable", [(True, False), (False, False), (True, True)]
)
def test_pkcs11_session_contract_and_key_policy(
    monkeypatch: pytest.MonkeyPatch, sensitive: bool, extractable: bool
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    closed = []
    observed = []

    class TokenKey:
        def __getitem__(self, item: str) -> bool:
            return sensitive if item == "sensitive" else extractable

        def sign(self, data: bytes, *, mechanism: str) -> bytes:
            assert mechanism == "sha256_rsa_pkcs"
            return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    class Session:
        def __enter__(self) -> Session:
            return self

        def __exit__(self, *args: Any) -> None:
            closed.append(True)

        def get_key(self, **kwargs: Any) -> TokenKey:
            observed.append(kwargs)
            return TokenKey()

    class Token:
        def open(self, *, user_pin: str) -> Session:
            assert user_pin == "fixture-pin"
            return Session()

    api = SimpleNamespace(
        lib=lambda path: SimpleNamespace(get_token=lambda **kwargs: Token()),
        ObjectClass=SimpleNamespace(PRIVATE_KEY="private"),
        KeyType=SimpleNamespace(RSA="rsa"),
        Attribute=SimpleNamespace(SENSITIVE="sensitive", EXTRACTABLE="extractable"),
        Mechanism=SimpleNamespace(SHA256_RSA_PKCS="sha256_rsa_pkcs"),
    )
    monkeypatch.setenv("FIXTURE_PIN", "fixture-pin")
    monkeypatch.setattr(
        "ix_blackfox.authority_crypto.signing.importlib.import_module", lambda name: api
    )
    signer = Pkcs11Signer(
        "token-key",
        "RSA-PKCS1-SHA256",
        "/fixture/module",
        "token",
        "key",
        "FIXTURE_PIN",
    )
    if sensitive and not extractable:
        verify_signature(
            key.public_key(), signer.algorithm, signer.sign(b"proof"), b"proof"
        )
    else:
        with pytest.raises(AuthorityProofError):
            signer.sign(b"proof")
    assert closed == [True] and observed[0]["object_class"] == "private"


@pytest.mark.parametrize(
    "algorithm", ["Ed25519", "RSA-PSS-SHA256", "RSA-PKCS1-SHA256", "ECDSA-P256-SHA256"]
)
def test_local_algorithm_profiles_match_public_verifier(algorithm: str) -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = (
        ed25519.Ed25519PrivateKey.generate()
        if algorithm == "Ed25519"
        else (
            ec.generate_private_key(ec.SECP256R1())
            if algorithm.startswith("ECDSA")
            else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )
    )
    signature = LocalSigner("test", algorithm, key).sign(b"signed bytes")
    verify_signature(key.public_key(), algorithm, signature, b"signed bytes")
    with pytest.raises(AuthorityProofError):
        verify_signature(key.public_key(), algorithm, signature, b"different")


def cosign_fixture(tmp_path: Path) -> tuple[CosignAdapter, Path, Path]:
    executable = tmp_path / "cosign"
    executable.write_text("fixture executable")
    root = tmp_path / "root.json"
    root.write_text("{}")
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"signed":"artifact"}')
    bundle = tmp_path / "sigstore.json"
    bundle.write_text("{}")
    return (
        CosignAdapter(
            executable, root, "reviewed-identity", "https://issuer.example.test", 10
        ),
        artifact,
        bundle,
    )


def test_cosign_verification_requires_exact_identity_root_and_offline_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, artifact, bundle = cosign_fixture(tmp_path)
    calls = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("ix_blackfox.authority_crypto.sigstore.subprocess.run", run)
    adapter.verify(artifact, bundle)
    args, kwargs = calls[0]
    assert "--offline" in args and "--trusted-root" in args
    assert args[args.index("--certificate-identity") + 1] == "reviewed-identity"
    assert (
        args[args.index("--certificate-oidc-issuer") + 1]
        == "https://issuer.example.test"
    )
    assert not any("ignore" in arg or "insecure" in arg for arg in args)
    assert kwargs["timeout"] == 10 and kwargs["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("failure", ["exit", "timeout", "missing_executable"])
def test_cosign_failure_is_not_reported_as_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    adapter, artifact, bundle = cosign_fixture(tmp_path)
    if failure == "missing_executable":
        adapter.executable.unlink()

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 10)
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setattr("ix_blackfox.authority_crypto.sigstore.subprocess.run", run)
    with pytest.raises(AuthorityProofError):
        adapter.verify(artifact, bundle)


def test_cosign_sign_checks_identity_before_publishing_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, artifact, _ = cosign_fixture(tmp_path)
    monkeypatch.setenv("SIGSTORE_ID_TOKEN", "fixture-secret-token")
    calls = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        if args[1] == "sign-blob":
            Path(args[args.index("--bundle") + 1]).write_text(
                json.dumps({"fixture": True})
            )
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("ix_blackfox.authority_crypto.sigstore.subprocess.run", run)
    output = tmp_path / "published.json"
    adapter.sign(artifact, output)
    assert output.exists() and [args[1] for args in calls] == [
        "sign-blob",
        "verify-blob",
    ]
    assert all("fixture-secret-token" not in arg for args in calls for arg in args)
