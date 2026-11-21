from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ix_blackfox.authority_crypto.encoding import (
    MAX_DOCUMENT_BYTES,
    AuthorityProofError,
    canonical_bytes,
    read_document,
    strict_json,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.autonomy.contracts import OperationError, identifier
from ix_blackfox.verification.contracts import SOURCES
from ix_blackfox.verification.proof import verify_bundle


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def gateway_request(
    origin: str,
    action: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> dict[str, Any]:
    url = urlsplit(origin)
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.path not in ("", "/")
        or url.query
        or url.fragment
        or (url.scheme == "http" and url.hostname not in {"127.0.0.1", "::1"})
    ):
        raise OperationError(
            "Use an HTTPS gateway origin or a numeric loopback HTTP origin."
        )
    request = Request(
        origin.rstrip("/") + "/v1/operations/" + identifier(action),
        data=canonical_bytes(payload),
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            return strict_json(response.read(MAX_DOCUMENT_BYTES + 1))
    except HTTPError as exc:
        with exc:
            body = strict_json(exc.read(16385))
        raise OperationError(
            f"Gateway {exc.code}: {body.get('error', 'request rejected')}", exc.code
        ) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blackfox verification")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("assess", "chain", "target", "export", "events"):
        sub = commands.add_parser(command)
        sub.add_argument("operation")
        sub.add_argument("--gateway", required=True)
        sub.add_argument("--token-env", default="BLACKFOX_OPERATOR_TOKEN")
        if command == "target":
            sub.add_argument("--requirement", required=True)
        if command == "events":
            sub.add_argument("--after", type=int, default=0)
        if command == "export":
            sub.add_argument("--output", type=Path, required=True)
    unresolved = commands.add_parser("unresolved")
    unresolved.add_argument("--gateway", required=True)
    unresolved.add_argument("--token-env", default="BLACKFOX_OPERATOR_TOKEN")
    unresolved.add_argument("--after", default="")
    unresolved.add_argument("--limit", type=int, default=25)
    verify = commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--operation", required=True)
    verify.add_argument("--authority", type=Path, required=True)
    for role in SOURCES:
        verify.add_argument("--" + role, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            verdict = verify_bundle(
                read_document(args.bundle),
                TrustPolicy.load(args.authority),
                {role: TrustPolicy.load(getattr(args, role)) for role in SOURCES},
                operation_id=args.operation,
            )
            print(canonical_bytes(verdict).decode())
            return 0 if verdict["current"] else 1

        token = os.environ.get(args.token_env, "")
        if not token:
            raise OperationError(
                "The operator credential environment variable is empty."
            )
        payload: dict[str, Any] = (
            {"after": args.after, "limit": args.limit}
            if args.command == "unresolved"
            else {"operation_id": identifier(args.operation)}
        )
        if args.command == "target":
            payload["requirement_id"] = identifier(args.requirement)
        if args.command == "events":
            payload["after"] = args.after
        action = (
            "events" if args.command == "events" else "verification-" + args.command
        )
        result = gateway_request(
            args.gateway,
            action,
            payload,
            {"X-BlackFox-Operator-Token": token},
        )
        if args.command == "export":
            with args.output.open("xb") as stream:
                stream.write(canonical_bytes(result) + b"\n")
        else:
            print(canonical_bytes(result).decode())
        return 0
    except (AuthorityProofError, OperationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
