from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.repository import (
    RepositoryIntelligenceReport,
    build_repository_intelligence_report,
    validate_repository_evidence_snapshot,
)

_DEFAULT_OUTPUT = Path(
    ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json"
)
_DEFAULT_EVIDENCE_OUTPUT_NAME = "wave8-repository-intelligence-evidence.json"
_DEFAULT_CHANGED_PATHS = (
    "src/ix_blackfox/repository/report.py",
    "scripts/run_wave8_repository_intelligence_ci.py",
)


def build_wave8_repository_intelligence_ci_report(
    *,
    root: Path,
    head_sha: str,
    changed_paths: tuple[str, ...] | None = None,
    run_id: str | None = None,
) -> RepositoryIntelligenceReport:
    """
    Build deterministic offline Wave 8 repository-intelligence evidence.

    This CI scenario binds repository inventory, Python code graph extraction,
    dependency mapping, source-test coverage mapping, architectural memory,
    conservative impact analysis, and digest-chained evidence into one report.
    It does not require network access, model credentials, or live model calls.
    """
    normalized_head_sha = _normalize_head_sha(head_sha)
    normalized_changed_paths = changed_paths or _DEFAULT_CHANGED_PATHS
    normalized_run_id = run_id or f"wave8-ci-{normalized_head_sha[:12]}"

    return build_repository_intelligence_report(
        root=root,
        changed_paths=normalized_changed_paths,
        head_sha=normalized_head_sha,
        run_id=normalized_run_id,
        metadata={
            "ci": True,
            "script": "scripts/run_wave8_repository_intelligence_ci.py",
            "claim": "offline_static_repository_intelligence_not_production_certification",
        },
    )


def build_ci_payload(
    *,
    head_sha: str,
    report: RepositoryIntelligenceReport,
    include_full: bool = False,
) -> dict[str, Any]:
    """
    Build the top-level Wave 8 CI payload.
    """
    normalized_head_sha = _normalize_head_sha(head_sha)
    evidence_validation = validate_repository_evidence_snapshot(report.evidence_snapshot)
    passed = report.passed and evidence_validation["valid"] is True

    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "wave": "8",
        "head_sha": normalized_head_sha,
        "passed": passed,
        "run_id": report.run_id,
        "changed_paths": list(report.impact_report.changed_paths),
        "report_digest": report.digest,
        "evidence_snapshot_digest": report.evidence_snapshot.digest,
        "evidence_validation": evidence_validation,
        "summary": report.to_dict(include_full=False)["summary"],
        "report": report.to_dict(include_full=include_full),
        "scope_note": (
            "This CI payload verifies Wave 8 repository-intelligence contracts: "
            "deterministic inventory, Python code graph extraction, dependency "
            "mapping, source-test mapping, architectural memory, conservative "
            "impact analysis, digest-chained evidence, and JSON report export. "
            "It is not production certification, formal compliance approval, "
            "defense approval, or authorization for autonomous execution."
        ),
    }


def write_ci_payload(
    *,
    root: Path,
    head_sha: str,
    output_path: Path,
    evidence_output_path: Path | None = None,
    changed_paths: tuple[str, ...] | None = None,
    include_full: bool = False,
) -> dict[str, Any]:
    """
    Write Wave 8 CI repository-intelligence evidence and return the payload.
    """
    normalized_head_sha = _normalize_head_sha(head_sha)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = build_wave8_repository_intelligence_ci_report(
        root=root,
        head_sha=normalized_head_sha,
        changed_paths=changed_paths,
    )
    payload = build_ci_payload(
        head_sha=normalized_head_sha,
        report=report,
        include_full=include_full,
    )

    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    evidence_path = evidence_output_path or output_path.with_name(
        _DEFAULT_EVIDENCE_OUTPUT_NAME
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(report.evidence_snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Wave 8 repository-intelligence CI evidence for IX-BlackFox."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to analyze.",
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="The commit SHA that the Wave 8 CI evidence is bound to.",
    )
    parser.add_argument(
        "--changed",
        action="append",
        default=None,
        help=(
            "Repository-relative changed path to analyze. "
            "May be supplied multiple times. Defaults to the Wave 8 report runner "
            "and CI runner paths."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(_DEFAULT_OUTPUT),
        help="Path to write the Wave 8 CI report JSON payload.",
    )
    parser.add_argument(
        "--evidence-output",
        default=None,
        help=(
            "Optional path to write the digest-chained Wave 8 evidence snapshot. "
            "Defaults to wave8-repository-intelligence-evidence.json next to --output."
        ),
    )
    parser.add_argument(
        "--include-full",
        action="store_true",
        help=(
            "Include full inventory, graph, dependency, coverage, and architecture "
            "memory details in the CI report payload."
        ),
    )
    args = parser.parse_args(argv)

    payload = write_ci_payload(
        root=Path(args.root).resolve(),
        head_sha=args.head_sha,
        output_path=Path(args.output),
        evidence_output_path=(
            Path(args.evidence_output) if args.evidence_output is not None else None
        ),
        changed_paths=tuple(args.changed) if args.changed else None,
        include_full=args.include_full,
    )

    print(f"Wave 8 repository-intelligence CI report written to {args.output}")
    evidence_path = (
        Path(args.evidence_output)
        if args.evidence_output is not None
        else Path(args.output).with_name(_DEFAULT_EVIDENCE_OUTPUT_NAME)
    )
    print(f"Wave 8 repository-intelligence evidence written to {evidence_path}")
    print(f"Passed: {payload['passed']}")
    print(f"Evidence chain valid: {payload['summary']['evidence_chain_valid']}")
    print(f"Receipts: {payload['summary']['receipt_count']}")

    return 0 if payload["passed"] else 1


def _normalize_head_sha(head_sha: str) -> str:
    normalized = head_sha.strip()
    if not normalized:
        raise ValueError("head_sha must not be empty.")
    return normalized


if __name__ == "__main__":
    raise SystemExit(main())
