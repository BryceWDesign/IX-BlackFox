from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.enterprise_identity import IdentityRevocationStore
from ix_blackfox.live_gateway.evidence import EvidenceStore, issue_signed_evidence
from ix_blackfox.live_gateway.http_server import serve_gateway
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command is None:
        parser.print_help()
        return 0

    config = load_gateway_config(Path(args.config))

    if args.command == "serve":
        gateway = LiveAuthorityGateway.from_config(config)
        status = gateway.status()
        if args.print_status:
            print(json.dumps(status, indent=2, sort_keys=True))
        if not status["ready"]:
            if not args.print_status:
                print(json.dumps(status, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        serve_gateway(gateway)
        return 0

    if args.command == "check":
        gateway = LiveAuthorityGateway.from_config(config)
        status = gateway.status()
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0 if status["ready"] else 1

    if args.command == "subject":
        gateway = LiveAuthorityGateway.from_config(config)
        arguments = _load_json_object(args.arguments_json, args.arguments_file)
        subject = gateway.build_subject(
            agent_id=args.agent_id,
            tool_name=args.tool_name,
            arguments=arguments,
            protocol=args.protocol,
        )
        print(json.dumps(subject.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "issue-evidence":
        issuer = config.issuer_for(args.issuer, args.key_id)
        if issuer is None:
            raise ValueError("issuer/key_id is not configured as a trusted evidence issuer")
        secret_text = os.environ.get(issuer.secret_env, "")
        if not secret_text:
            raise ValueError(f"required signing secret environment variable is unset: {issuer.secret_env}")
        if len(secret_text.encode("utf-8")) < 32:
            raise ValueError("configured evidence signing secret must be at least 32 bytes")
        if issuer.allowed_kinds and args.kind not in issuer.allowed_kinds:
            raise ValueError(
                f"issuer/key_id is not authorized to issue evidence kind {args.kind!r}"
            )
        payload = _load_json_object(args.payload_json, args.payload_file)
        artifact = issue_signed_evidence(
            evidence_id=args.evidence_id,
            kind=args.kind,
            issuer=args.issuer,
            key_id=args.key_id,
            secret=secret_text.encode("utf-8"),
            status=args.status,
            repository_id=args.repository_id,
            revision=args.revision,
            target_digest=args.target_digest,
            payload=payload,
        )
        store = EvidenceStore(
            root=config.evidence_root,
            trusted_keys=config.trusted_key_material(),
        )
        output = store.write(artifact)
        print(
            json.dumps(
                {
                    "evidence_id": artifact.evidence_id,
                    "kind": artifact.kind,
                    "digest": artifact.digest,
                    "issuer": artifact.issuer,
                    "key_id": artifact.key_id,
                    "output": str(output),
                    "target_digest": artifact.target_digest,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "revoke-identity":
        if args.kind not in {"jti", "delegation"}:
            raise ValueError("revocation kind must be 'jti' or 'delegation'")
        value = str(args.value).strip()
        if not value:
            raise ValueError("revocation value must not be empty")
        reason = str(args.reason).strip() or "operator_revoked"
        revocation_store = IdentityRevocationStore(config.identity_revocation_database)
        revocation_store.revoke(kind=args.kind, value=value, reason=reason)
        print(
            json.dumps(
                {
                    "revoked": True,
                    "kind": args.kind,
                    "value": value,
                    "reason": reason,
                    "database": str(config.identity_revocation_database),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox gateway",
        description="Wave 15 enterprise identity and live authority gateway operator commands.",
    )
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Run the live MCP/API authority gateway.")
    serve.add_argument("--config", required=True)
    serve.add_argument("--print-status", action="store_true")

    check = sub.add_parser("check", help="Validate gateway configuration and receipt chain.")
    check.add_argument("--config", required=True)

    subject = sub.add_parser(
        "subject",
        help="Compute the exact action subject digest used for target-bound approvals.",
    )
    subject.add_argument("--config", required=True)
    subject.add_argument("--agent-id", required=True)
    subject.add_argument("--tool-name", required=True)
    subject.add_argument("--protocol", default="blackfox-api/v1")
    subject.add_argument("--arguments-json", default="{}")
    subject.add_argument("--arguments-file", default=None)

    evidence = sub.add_parser(
        "issue-evidence",
        help="Issue one HMAC-authenticated evidence artifact using a configured trusted issuer.",
    )
    evidence.add_argument("--config", required=True)
    evidence.add_argument("--evidence-id", required=True)
    evidence.add_argument("--kind", required=True)
    evidence.add_argument("--issuer", required=True)
    evidence.add_argument("--key-id", required=True)
    evidence.add_argument("--status", required=True)
    evidence.add_argument("--repository-id", required=True)
    evidence.add_argument("--revision", required=True)
    evidence.add_argument("--target-digest", default="")
    evidence.add_argument("--payload-json", default="{}")
    evidence.add_argument("--payload-file", default=None)

    revoke = sub.add_parser(
        "revoke-identity",
        help="Persistently revoke a federated token jti or delegation id.",
    )
    revoke.add_argument("--config", required=True)
    revoke.add_argument("--kind", choices=("jti", "delegation"), required=True)
    revoke.add_argument("--value", required=True)
    revoke.add_argument("--reason", default="operator_revoked")

    return parser


def _load_json_object(inline: str, file_path: str | None) -> dict[str, Any]:
    raw = Path(file_path).read_text(encoding="utf-8") if file_path else inline
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    return dict(payload)


if __name__ == "__main__":
    raise SystemExit(main())
