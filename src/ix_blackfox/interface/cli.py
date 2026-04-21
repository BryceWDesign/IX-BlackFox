from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

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
        runtime = BlackFoxRuntime.create_default(
            root_dir=Path(args.root_dir).resolve() if args.root_dir is not None else None,
        )
        report = runtime.run_prompt(
            prompt=args.prompt,
            kind=TaskKind(args.kind),
            labels=tuple(args.label),
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
        "--json",
        action="store_true",
        help="Print the full run report as JSON.",
    )

    return parser


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
    print(f"Artifacts: {', '.join(report.produced_artifacts) if report.produced_artifacts else 'none'}")
    if report.report_path is not None:
        print(f"Report path: {report.report_path}")


if __name__ == "__main__":
    raise SystemExit(main())
