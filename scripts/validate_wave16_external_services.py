from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    AuthorityProofError,
    read_document,
)
from ix_blackfox.authority_crypto.sigstore import CosignAdapter
from ix_blackfox.live_gateway.config import load_gateway_config


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute configured external signing/verification; unrequested services remain NOT_RUN."
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sigstore-artifact", type=Path)
    parser.add_argument("--sigstore-bundle", type=Path)
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--certificate-identity")
    parser.add_argument("--oidc-issuer")
    args = parser.parse_args()
    services: dict[str, dict[str, Any]] = {
        name: {"status": "NOT_RUN"} for name in ("aws_kms", "pkcs11", "sigstore")
    }
    requested: list[bool] = []
    if args.config:
        name = "signing_configuration"
        try:
            config = load_gateway_config(args.config)
            if (
                config.receipt_signing is None
                or config.receipt_signing.provider == "local"
            ):
                raise AuthorityProofError(
                    "An external signing provider must be explicitly configured."
                )
            name = config.receipt_signing.provider
            controller = config.receipt_signing.build()
            probe = {
                "validation_nonce": secrets.token_hex(32),
                "scope": "External provider signature round trip.",
            }
            envelope = controller.envelope(CHECKPOINT_TYPE, probe)
            assert (
                controller.current_policy().verify(envelope, CHECKPOINT_TYPE) == probe
            )
            services[name] = {
                "status": "PASS",
                "scope": "Configured provider produced a signature matching independently pinned public key.",
                "key_id": config.receipt_signing.key_id,
                "physical_custody": "NOT_ESTABLISHED_BY_THIS_SCRIPT",
            }
            requested.append(True)
        except Exception:
            services[name] = {
                "status": "FAIL",
                "issue": "External signing or independent public verification failed.",
            }
            requested.append(False)
    sigstore_requested = any(
        (
            args.sigstore_artifact,
            args.sigstore_bundle,
            args.cosign,
            args.trusted_root,
            args.certificate_identity,
            args.oidc_issuer,
        )
    )
    if sigstore_requested:
        try:
            if not all(
                (
                    args.sigstore_artifact,
                    args.sigstore_bundle,
                    args.cosign,
                    args.trusted_root,
                    args.certificate_identity,
                    args.oidc_issuer,
                )
            ):
                raise AuthorityProofError(
                    "Incomplete Sigstore validation configuration."
                )
            artifact = args.sigstore_artifact
            bundle = args.sigstore_bundle
            if (
                artifact is None
                or bundle is None
                or args.cosign is None
                or args.trusted_root is None
            ):
                raise AuthorityProofError("Missing required files.")
            read_document(artifact)
            CosignAdapter(
                args.cosign,
                args.trusted_root,
                args.certificate_identity,
                args.oidc_issuer,
            ).verify(artifact, bundle)
            services["sigstore"] = {
                "status": "PASS",
                "scope": "Configured Cosign verified exact identity, issuer, trusted root and bundle offline.",
            }
            requested.append(True)
        except Exception:
            services["sigstore"] = {
                "status": "FAIL",
                "issue": "External Sigstore verification failed.",
            }
            requested.append(False)
    report = {
        "schema_version": "wave16.external_services_validation.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "passed": bool(requested) and all(requested),
        "services": services,
        "scope": "Operator-run external validation; physical custody, production authorization, benchmarks and certification require independent evidence.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
