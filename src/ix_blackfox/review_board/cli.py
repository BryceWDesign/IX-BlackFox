from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.review_board.admission import admit_wave12_package
from ix_blackfox.review_board.package import build_review_board_package
from ix_blackfox.review_board.parsing import (
    parse_evidence_challenges,
    parse_human_reviews,
    parse_machine_advisories,
)
from ix_blackfox.review_board.policy import (
    build_machine_advisory,
    default_wave13_review_policy,
)
from ix_blackfox.review_board.verify import verify_review_board_package

_DEFAULT_OUTPUT = Path(".blackfox-artifacts/wave13/wave13-human-machine-review-board.zip")


def main(argv: Sequence[str] | None = None) -> int:
    """Run Wave 13 human-machine review-board operator commands."""

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "build":
            return _run_build(args)
        if args.command == "verify":
            return _run_verify(args)
        if args.command == "gate":
            return _run_gate(args)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Wave 13 review-board input error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _run_build(args: argparse.Namespace) -> int:
    wave12_path = Path(args.wave12_package)
    admitted_at = _normalize_timestamp(args.admitted_at)
    admission = admit_wave12_package(wave12_path, admitted_at=admitted_at)
    policy = default_wave13_review_policy()

    if args.machine_advisories:
        machine_payload = _load_mapping(Path(args.machine_advisories))
        advisories = parse_machine_advisories(machine_payload)
    else:
        advisories = (
            build_machine_advisory(
                advisory_id="wave13-local-advisory",
                producer_agent_id="wave13-rule-engine",
                subject=admission.subject,
                policy=policy,
                produced_at=admitted_at,
                upstream_verification_passed=admission.verification.passed,
                upstream_readiness_status=admission.verification.readiness_status,
                metadata={"generated_by": "blackfox review-board build"},
            ),
        )

    reviews = (
        parse_human_reviews(_load_mapping(Path(args.human_reviews)))
        if args.human_reviews
        else ()
    )
    challenges = (
        parse_evidence_challenges(_load_mapping(Path(args.challenges)))
        if args.challenges
        else ()
    )

    result = build_review_board_package(
        output_path=Path(args.output),
        wave12_package_path=wave12_path,
        subject=admission.subject,
        policy=policy,
        machine_advisories=advisories,
        human_reviews=reviews,
        challenges=challenges,
        metadata={"cli": True},
    )
    verification = verify_review_board_package(Path(args.output), metadata={"cli": True})
    payload = result.to_dict()
    payload["verification_passed"] = verification.passed
    payload["verification_issue_count"] = len(verification.issues)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if verification.passed else 1


def _run_verify(args: argparse.Namespace) -> int:
    verification = verify_review_board_package(Path(args.package))
    print(json.dumps(verification.to_dict(), indent=2, sort_keys=True))
    return 0 if verification.passed else 1


def _run_gate(args: argparse.Namespace) -> int:
    verification = verify_review_board_package(Path(args.package))
    payload = verification.to_dict()
    allowed_statuses = {"approved_for_next_gate"}
    if args.allow_human_review_required:
        allowed_statuses.add("human_review_required")
    gate_passed = verification.passed and verification.status in allowed_statuses
    payload["gate_passed"] = gate_passed
    payload["allowed_statuses"] = sorted(allowed_statuses)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if gate_passed else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox review-board",
        description=(
            "Wave 13 role-based human-machine review board over a verified Wave 12 package."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    build = subparsers.add_parser("build", help="Build a deterministic Wave 13 review package.")
    build.add_argument("--wave12-package", required=True)
    build.add_argument("--output", default=str(_DEFAULT_OUTPUT))
    build.add_argument(
        "--admitted-at",
        default=None,
        help="ISO-8601 timestamp. Defaults to the current UTC time.",
    )
    build.add_argument(
        "--machine-advisories",
        default=None,
        help="Optional canonical machine-advisory-set JSON. A rule advisory is generated otherwise.",
    )
    build.add_argument(
        "--human-reviews",
        default=None,
        help="Optional canonical human-review-set JSON supplied by a human identity boundary.",
    )
    build.add_argument(
        "--challenges",
        default=None,
        help="Optional canonical evidence-challenge-set JSON.",
    )

    verify = subparsers.add_parser("verify", help="Independently verify a Wave 13 package.")
    verify.add_argument("--package", required=True)

    gate = subparsers.add_parser("gate", help="Require a verified Wave 13 board disposition.")
    gate.add_argument("--package", required=True)
    gate.add_argument(
        "--allow-human-review-required",
        action="store_true",
        help="Allow the intentional offline human-review-required state.",
    )
    return parser


def _load_mapping(path: Path) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return payload


def _normalize_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(tz=UTC).isoformat()
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("admitted_at must include a timezone offset.")
    return parsed.isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
