from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ix_blackfox.authority_crypto.encoding import AuthorityProofError, read_document
from ix_blackfox.authority_crypto.sigstore import CosignAdapter
from ix_blackfox.authority_crypto.trust import (
    ALGORITHMS,
    TrustPolicy,
    fingerprint,
    public_key,
)
from ix_blackfox.authority_crypto.verification import verify_bundle


def public_trust_document(
    pem: str,
    key_id: str,
    deployment_id: str,
    stream_id: str,
    algorithm: str = "Ed25519",
) -> dict[str, Any]:
    key = public_key(pem, algorithm)
    now = datetime.now(UTC)
    document = {
        "schema_version": "wave16.trust_policy.v1",
        "deployment_id": deployment_id,
        "stream_id": stream_id,
        "expires_at": (now + timedelta(days=365)).isoformat(),
        "clock_skew_seconds": 30,
        "keys": [
            {
                "key_id": key_id,
                "algorithm": algorithm,
                "public_key_pem": pem,
                "spki_sha256": fingerprint(key),
                "not_before": (now - timedelta(minutes=5)).isoformat(),
                "not_after": (now + timedelta(days=365)).isoformat(),
                "revoked": False,
            }
        ],
    }
    TrustPolicy.from_dict(document)
    return document


def write_new_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(
            payload,
            stream,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        stream.write("\n")


def generate_keys(
    directory: Path, password_env: str, key_id: str, deployment_id: str, stream_id: str
) -> None:
    password = os.environ.get(password_env, "").encode("utf-8")
    if len(password) < 16:
        raise AuthorityProofError(
            "Set a signing password of at least 16 bytes in the named environment variable."
        )
    key = ed25519.Ed25519PrivateKey.generate()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = directory / "authority-signing-key.pem"
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password),
            )
        )
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("ascii")
    )
    write_new_json(
        directory / "trust-policy.json",
        public_trust_document(pem, key_id, deployment_id, stream_id),
    )


def _cosign_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--certificate-identity")
    parser.add_argument("--oidc-issuer")


def _adapter(args: argparse.Namespace) -> CosignAdapter:
    if (
        args.cosign is None
        or args.trusted_root is None
        or not args.certificate_identity
        or not args.oidc_issuer
    ):
        raise AuthorityProofError(
            "Cosign path, trusted root, exact certificate identity and issuer are required."
        )
    return CosignAdapter(
        args.cosign, args.trusted_root, args.certificate_identity, args.oidc_issuer
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Wave 16 authority receipts, public verification and external anchors."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen")
    keygen.add_argument("--directory", type=Path, required=True)
    keygen.add_argument("--password-env", required=True)
    for name in ("key-id", "deployment-id", "stream-id"):
        keygen.add_argument("--" + name, required=True)
    trust = commands.add_parser("trust-init")
    trust.add_argument("--public-key", type=Path, required=True)
    trust.add_argument("--algorithm", choices=sorted(ALGORITHMS), required=True)
    trust.add_argument("--output", type=Path, required=True)
    for name in ("key-id", "deployment-id", "stream-id"):
        trust.add_argument("--" + name, required=True)
    export = commands.add_parser("export")
    export.add_argument("--config", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--checkpoint-output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--trust-policy", type=Path, required=True)
    anchor = verify.add_mutually_exclusive_group(required=True)
    anchor.add_argument("--checkpoint", type=Path)
    anchor.add_argument("--allow-unanchored", action="store_true")
    anchor.add_argument("--sigstore-bundle", type=Path)
    _cosign_options(verify)
    sign = commands.add_parser("sigstore-sign")
    sign.add_argument("--bundle", type=Path, required=True)
    sign.add_argument("--trust-policy", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    _cosign_options(sign)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generate_keys(
                args.directory,
                args.password_env,
                args.key_id,
                args.deployment_id,
                args.stream_id,
            )
            result: dict[str, Any] = {"passed": True, "directory": str(args.directory)}
        elif args.command == "trust-init":
            write_new_json(
                args.output,
                public_trust_document(
                    args.public_key.read_text(encoding="ascii"),
                    args.key_id,
                    args.deployment_id,
                    args.stream_id,
                    args.algorithm,
                ),
            )
            result = {
                "passed": True,
                "trust_policy": str(args.output),
                "scope": "Operator must independently authenticate this public key before distribution.",
            }
        elif args.command == "export":
            from ix_blackfox.live_gateway.config import load_gateway_config
            from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore

            config = load_gateway_config(args.config)
            if config.receipt_signing is None:
                raise AuthorityProofError("Required signing configuration is absent.")
            if (
                args.output.resolve() == args.checkpoint_output.resolve()
                or args.output.exists()
                or args.checkpoint_output.exists()
            ):
                raise AuthorityProofError(
                    "Export requires two distinct new file paths."
                )
            store = AuthorityReceiptStore(
                config.receipt_database, config.receipt_signing.build()
            )
            chain = store.verify_chain()
            if not chain.passed:
                raise AuthorityProofError(
                    "Stored receipt chain or evidence claims are invalid."
                )
            bundle = store.export_bundle()
            write_new_json(args.output, bundle)
            write_new_json(args.checkpoint_output, bundle["checkpoint"])
            result = {
                "passed": True,
                "receipt_count": len(bundle["receipts"]),
                "scope": "Retain the expected checkpoint independently; a co-packaged copy alone establishes no latestness.",
            }
        else:
            bundle = read_document(args.bundle)
            policy = TrustPolicy.load(args.trust_policy)
            expected = (
                read_document(args.checkpoint)
                if args.command == "verify" and args.checkpoint
                else None
            )
            report = verify_bundle(bundle, policy, expected_checkpoint=expected)
            if not report.passed:
                raise AuthorityProofError("; ".join(report.issues))
            result = report.to_dict()
            if args.command == "sigstore-sign":
                _adapter(args).sign(args.bundle, args.output)
                result["sigstore_signed_and_verified"] = True
            elif args.sigstore_bundle is not None:
                _adapter(args).verify(args.bundle, args.sigstore_bundle)
                result["sigstore_identity_and_inclusion_verified"] = True
                result["completeness"] = (
                    "Verified Sigstore attestation of these bytes; stream latestness still requires a retained expected checkpoint."
                )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AuthorityProofError, ValueError, OSError) as exc:
        print(json.dumps({"passed": False, "issues": [str(exc)]}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
