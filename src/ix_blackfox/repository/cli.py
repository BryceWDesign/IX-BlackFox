from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ix_blackfox.repository.architecture_memory import build_architecture_memory
from ix_blackfox.repository.coverage_map import build_coverage_map
from ix_blackfox.repository.dependencies import build_dependency_map
from ix_blackfox.repository.impact import analyze_repository_impact
from ix_blackfox.repository.inventory import RepositoryInventoryScanner
from ix_blackfox.repository.models import (
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryFileRole,
    RepositoryNodeKind,
)
from ix_blackfox.repository.python_graph import build_python_code_graph
from ix_blackfox.repository.report import build_repository_intelligence_report


def main(argv: Sequence[str] | None = None) -> int:
    """Run Wave 8 repository-intelligence CLI commands."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "impact":
            return _run_impact(args)
        if args.command == "report":
            return _run_report(args)
    except (OSError, ValueError) as exc:
        print(f"Wave 8 repository-intelligence input error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"Unsupported repository command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox repository",
        description="Wave 8 repository-intelligence commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Generate a deterministic repository inventory and code-graph summary.",
    )
    scan_parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the scan summary as JSON.",
    )

    impact_parser = subparsers.add_parser(
        "impact",
        help="Analyze conservative impact for one or more changed paths.",
    )
    impact_parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan.",
    )
    impact_parser.add_argument(
        "--changed",
        action="append",
        required=True,
        help=(
            "Changed path relative to repository root. "
            "May be supplied multiple times."
        ),
    )
    impact_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the impact report as JSON.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Build a complete Wave 8 repository-intelligence report.",
    )
    report_parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan.",
    )
    report_parser.add_argument(
        "--changed",
        action="append",
        required=True,
        help=(
            "Changed path relative to repository root. "
            "May be supplied multiple times."
        ),
    )
    report_parser.add_argument(
        "--head-sha",
        default="local",
        help="Head SHA or local label to bind into the report evidence.",
    )
    report_parser.add_argument(
        "--run-id",
        default="wave8-local",
        help="Run identifier for Wave 8 receipt chaining.",
    )
    report_parser.add_argument(
        "--output",
        default=None,
        help="Optional JSON output path for the report.",
    )
    report_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Omit full inventory, graph, dependency, coverage, and memory details.",
    )
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report payload as JSON instead of a human summary.",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    snapshot = RepositoryInventoryScanner().scan(root)
    graph = build_python_code_graph(root, snapshot)
    payload = _scan_payload(snapshot=snapshot, graph=graph)

    if args.json:
        print_json(payload)
    else:
        print(f"Files: {payload['file_count']}")
        print(f"Source files: {payload['source_file_count']}")
        print(f"Test files: {payload['test_file_count']}")
        print(f"Python modules: {payload['module_count']}")
        print(f"Python symbols: {payload['symbol_count']}")
        print(f"Graph edges: {payload['edge_count']}")
        print(f"Internal import edges: {payload['internal_import_edge_count']}")
        print(f"Sensitive files: {payload['sensitive_file_count']}")
        print(f"Syntax errors: {payload['syntax_error_count']}")

    return 0 if not graph.syntax_error_paths else 1


def _run_impact(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    snapshot = RepositoryInventoryScanner().scan(root)
    graph = build_python_code_graph(root, snapshot)
    dependency_map = build_dependency_map(root, snapshot, graph)
    coverage_map = build_coverage_map(snapshot, graph)
    architecture_memory = build_architecture_memory(snapshot, coverage_map)
    report = analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=architecture_memory,
        changed_paths=tuple(args.changed),
    )

    if args.json:
        print_json(report.to_dict())
    else:
        print(f"Max severity: {report.max_severity.value}")
        print(f"Requires human review: {report.requires_human_review}")
        print(f"Changed paths: {len(report.changed_paths)}")
        print(f"Impacted paths: {len(report.impacted_paths)}")
        print(f"Impacted tests: {len(report.impacted_tests)}")
        print(
            "Impacted subsystems: "
            f"{', '.join(report.impacted_subsystems) or 'none'}"
        )
        print("Recommended commands:")
        for command in report.recommended_commands:
            print(f"- {command}")

    return 0


def _run_report(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    report = build_repository_intelligence_report(
        root=root,
        changed_paths=tuple(args.changed),
        head_sha=args.head_sha,
        run_id=args.run_id,
        metadata={"cli": True},
    )
    include_full = not args.summary_only

    if args.output is not None:
        report.write_json(Path(args.output), include_full=include_full)

    payload = report.to_dict(include_full=include_full)
    if args.json:
        print_json(payload)
    else:
        print(f"Wave: {payload['wave']}")
        print(f"Run ID: {payload['run_id']}")
        print(f"Head SHA: {payload['head_sha']}")
        print(f"Passed: {payload['passed']}")
        print(f"Files: {payload['summary']['file_count']}")
        print(f"Source files: {payload['summary']['source_file_count']}")
        print(f"Test files: {payload['summary']['test_file_count']}")
        print(f"Syntax errors: {payload['summary']['syntax_error_count']}")
        print(f"Evidence receipts: {payload['summary']['receipt_count']}")
        print(
            "Evidence chain valid: "
            f"{payload['summary']['evidence_chain_valid']}"
        )
        print(
            "Requires human review: "
            f"{payload['summary']['requires_human_review']}"
        )
        print(f"Max severity: {payload['summary']['max_severity']}")
        if args.output is not None:
            print(f"Report path: {Path(args.output)}")

    return 0 if report.passed else 1


def _scan_payload(*, snapshot: Any, graph: Any) -> dict[str, Any]:
    module_count = sum(
        1 for symbol in graph.symbols if symbol.kind is RepositoryNodeKind.MODULE
    )
    internal_import_edge_count = sum(
        1
        for edge in graph.edges
        if edge.kind is RepositoryEdgeKind.IMPORTS
        and edge.scope is RepositoryDependencyScope.INTERNAL
    )
    sensitive_file_count = sum(
        1
        for file_record in snapshot.files
        if file_record.sensitivity.value != "normal"
    )

    return {
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_digest": snapshot.digest,
        "code_graph_digest": graph.digest,
        "file_count": snapshot.file_count,
        "total_bytes": snapshot.total_bytes,
        "source_file_count": len(snapshot.paths_by_role(RepositoryFileRole.SOURCE)),
        "test_file_count": len(snapshot.paths_by_role(RepositoryFileRole.TEST)),
        "documentation_file_count": len(
            snapshot.paths_by_role(RepositoryFileRole.DOCUMENTATION)
        ),
        "workflow_file_count": len(snapshot.paths_by_role(RepositoryFileRole.WORKFLOW)),
        "script_file_count": len(snapshot.paths_by_role(RepositoryFileRole.SCRIPT)),
        "sensitive_file_count": sensitive_file_count,
        "module_count": module_count,
        "symbol_count": graph.symbol_count,
        "edge_count": graph.edge_count,
        "internal_import_edge_count": internal_import_edge_count,
        "syntax_error_count": len(graph.syntax_error_paths),
        "syntax_error_paths": list(graph.syntax_error_paths),
    }


def print_json(payload: MappingLike) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


MappingLike = dict[str, Any]
