from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


_KIND_CHOICES = tuple(kind.value for kind in TaskKind)


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the IX-BlackFox command-line interface.
    """
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "run":
        metadata = _load_runtime_metadata(args)
        runtime = BlackFoxRuntime.create_default(
            root_dir=Path(args.root_dir).resolve() if args.root_dir is not None else None,
        )
        report = runtime.run_prompt(
            prompt=args.prompt,
            kind=TaskKind(args.kind),
            labels=tuple(args.label),
            metadata=metadata,
        )
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
        else:
            _print_human_summary(report)
        return 0 if report.status != RuntimeRunStatus.FAILED else 1

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox",
        description="IX-BlackFox sovereign runtime CLI.",
    )
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser(
        "run",
        help="Execute one prompt through the BlackFox runtime.",
    )
    run_parser.add_argument(
        "--prompt",
        required=True,
        help="Primary task prompt to execute.",
    )
    run_parser.add_argument(
        "--kind",
        default=TaskKind.UNKNOWN.value,
        choices=_KIND_CHOICES,
        help="Optional explicit task kind. Defaults to unknown for runtime inference.",
    )
    run_parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Optional routing label. May be provided multiple times.",
    )
    run_parser.add_argument(
        "--root-dir",
        default=None,
        help="Optional runtime root directory for artifacts, logs, and state.",
    )
    run_parser.add_argument(
        "--approval-file",
        default=None,
        help=(
            "Optional JSON file containing governance approval artifacts. "
            "Accepted shapes: a list of approval mappings, or an object with "
            "a 'governance_approvals' list."
        ),
    )
    run_parser.add_argument(
        "--metadata-file",
        default=None,
        help=(
            "Optional JSON file containing additional task metadata. When both "
            "--metadata-file and --approval-file are supplied, governance "
            "approvals are merged into the metadata payload."
        ),
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full run report as JSON.",
    )

    return parser


def _load_runtime_metadata(args: argparse.Namespace) -> dict[str, Any] | None:
    metadata: dict[str, Any] = {}

    if args.metadata_file is not None:
        payload = _load_json_file(Path(args.metadata_file))
        if not isinstance(payload, dict):
            raise ValueError("--metadata-file must point to a JSON object.")
        metadata.update(payload)

    if args.approval_file is not None:
        payload = _load_json_file(Path(args.approval_file))
        approvals: list[dict[str, Any]]

        if isinstance(payload, list):
            approvals = _normalize_approval_entries(payload)
        elif isinstance(payload, dict):
            raw_approvals = payload.get("governance_approvals")
            if not isinstance(raw_approvals, list):
                raise ValueError(
                    "--approval-file JSON object must contain a 'governance_approvals' list."
                )
            approvals = _normalize_approval_entries(raw_approvals)
        else:
            raise ValueError(
                "--approval-file must point to a JSON list or object containing "
                "'governance_approvals'."
            )

        metadata["governance_approvals"] = approvals

    return metadata or None


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_approval_entries(entries: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Approval entry at index {index} must be a JSON object."
            )
        normalized.append(dict(entry))

    return normalized


def _print_human_summary(report) -> None:
    print(f"Run ID: {report.run_id}")
    print(f"Task ID: {report.task_id}")
    print(f"Task kind: {report.task_kind.value}")
    print(f"Status: {report.status.value}")
    print(f"Pack: {report.pack_name or 'none'}")
    if report.route is not None:
        print(
            "Route: "
            f"{report.route.capability_name} "
            f"(confidence={report.route.confidence:.2f}, reason={report.route.reason.value})"
        )
    print(f"Summary: {report.task_summary}")
    print(
        "Evaluation: "
        f"{report.evaluation_result.status.value} "
        f"(score={report.evaluation_result.score:.2f})"
    )
    print(f"Verification: {report.verification_report.status.value}")
    print(f"Sentinel issues: {len(report.sentinel_report.issues)}")

    if report.governance_preflight is not None:
        print(
            "Governance: "
            f"{report.governance_preflight.decision.decision.value} "
            f"(risk={report.governance_preflight.risk.risk_level.value}, "
            f"action={report.governance_preflight.intent.action_kind.value})"
        )
        print(
            "Ticket: "
            f"{report.governance_preflight.ticket.ticket_id} "
            f"({report.governance_preflight.ticket.disposition.value})"
        )

    if report.approval_resolution is not None:
        if report.approval_resolution.required:
            gate_state = (
                "satisfied" if report.approval_resolution.satisfied else "pending"
            )
            print(
                "Approval gate: "
                f"{gate_state} "
                f"(ids={', '.join(report.approval_resolution.approval_ids) or 'none'})"
            )
            if report.approval_resolution.issues:
                print(
                    "Approval issues: "
                    + "; ".join(report.approval_resolution.issues)
                )
        else:
            print("Approval gate: not required")

    if report.governance_receipts is not None:
        print(
            "Governance receipts: "
            f"{report.governance_receipts.receipt_count} "
            f"(chain_verified={report.governance_receipts.chain_verified})"
        )
        if report.governance_receipts.artifact_path is not None:
            print(f"Governance receipt path: {report.governance_receipts.artifact_path}")

    print(
        "Artifacts: "
        f"{', '.join(report.produced_artifacts) if report.produced_artifacts else 'none'}"
    )
    if report.report_path is not None:
        print(f"Report path: {report.report_path}")


if __name__ == "__main__":
    raise SystemExit(main())
