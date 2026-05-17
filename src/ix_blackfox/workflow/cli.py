from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ix_blackfox.workflow.ci_evidence import CiEvidenceBundle, CiEvidenceNormalizer
from ix_blackfox.workflow.pr_evidence_io import load_pr_evidence_pack
from ix_blackfox.workflow.pr_gate import PullRequestGate, PullRequestGateDecision


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "pr-gate":
        return _run_pr_gate(args)

    parser.error(f"Unsupported workflow command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox workflow",
        description="Wave 5 organization workflow commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    gate_parser = subparsers.add_parser(
        "pr-gate",
        help="Evaluate a Wave 5 pull-request evidence pack before review or merge.",
    )
    gate_parser.add_argument(
        "--evidence-pack",
        required=True,
        help="Path to a PR evidence-pack JSON file.",
    )
    gate_parser.add_argument(
        "--ci-evidence",
        required=True,
        help="Path to a CI evidence JSON file bound to the same repository and head SHA.",
    )
    gate_parser.add_argument(
        "--required-check",
        action="append",
        default=[],
        help="Required CI check name. May be supplied multiple times.",
    )
    gate_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full Wave 5 gate decision as JSON.",
    )
    return parser


def _run_pr_gate(args: argparse.Namespace) -> int:
    try:
        pack = load_pr_evidence_pack(Path(args.evidence_pack))
        ci_bundle = _load_ci_bundle(Path(args.ci_evidence))
        required_checks = (
            tuple(args.required_check) if args.required_check else pack.requested_checks
        )
        decision = PullRequestGate(required_ci_checks=required_checks).evaluate(
            pack,
            ci_bundle=ci_bundle,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Wave 5 PR gate input error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_human_summary(decision)
    return 0 if decision.passed else 1


def _load_ci_bundle(path: Path) -> CiEvidenceBundle:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CI evidence JSON must be an object.")
    return CiEvidenceNormalizer().from_mapping(payload)


def _print_human_summary(decision: PullRequestGateDecision) -> None:
    print(f"Wave 5 PR gate: {decision.status.value}")
    print(f"Pack: {decision.pack_id}")
    print(f"Passed: {decision.passed}")
    print(f"Errors: {decision.error_count}")
    print(f"Warnings: {decision.warning_count}")
    print(f"Evidence pack passed: {decision.evidence_report.passed}")
    print(f"Approval policy passed: {decision.approval_policy_decision.passed}")
    if decision.ci_report is not None:
        print(f"CI evidence passed: {decision.ci_report.passed}")
    else:
        print("CI evidence passed: not evaluated")
    if decision.issue_codes:
        print("Issue codes:")
        for code in decision.issue_codes:
            print(f"- {code}")
