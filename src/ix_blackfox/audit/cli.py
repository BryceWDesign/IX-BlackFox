from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ix_blackfox.audit.evidence_bridges import collect_known_wave_evidence
from ix_blackfox.audit.evidence_standard import build_evidence_manifest
from ix_blackfox.audit.models import (
    AuditDisposition,
    AuditReviewDecision,
    AuditReviewerKind,
    AuditReviewerSignoff,
    AuditSubject,
    digest_payload,
)
from ix_blackfox.audit.policy_packs import default_wave9_policy_pack
from ix_blackfox.audit.report import (
    build_governance_report,
    load_governance_report_payload,
    validate_governance_report_payload_shape,
    write_governance_report,
)

_DEFAULT_OUTPUT_PATH = ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json"


def main(argv: Sequence[str] | None = None) -> int:
    """Run Wave 9 compliance/audit attestation CLI commands."""

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "report":
            return _run_report(args)
        if args.command == "validate":
            return _run_validate(args)
        if args.command == "gate":
            return _run_gate(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Wave 9 audit input error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"Unsupported audit command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox audit",
        description="Wave 9 compliance/audit attestation commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    report_parser = subparsers.add_parser(
        "report",
        help="Build a Wave 9 governance report from current audit evidence.",
    )
    report_parser.add_argument(
        "--root",
        default=".",
        help="Repository root to inspect for generated Wave 6-8 evidence.",
    )
    report_parser.add_argument(
        "--repository",
        default="IX-BlackFox",
        help="Repository label bound into the Wave 9 audit subject.",
    )
    report_parser.add_argument(
        "--head-sha",
        default="local",
        help="Reviewed commit SHA or local label bound into the audit subject.",
    )
    report_parser.add_argument(
        "--scope",
        default=(
            "ai-assisted code-change governance audit for policy, evidence, "
            "repository intelligence, and human review"
        ),
        help="Declared audit scope for conditional Wave 9 controls.",
    )
    report_parser.add_argument(
        "--changed",
        action="append",
        default=[],
        help="Changed path relative to repository root. May be supplied multiple times.",
    )
    report_parser.add_argument(
        "--claim",
        action="append",
        default=[],
        help="Audit claim to evaluate. May be supplied multiple times.",
    )
    report_parser.add_argument(
        "--signoff-file",
        default=None,
        help=(
            "Optional JSON file containing reviewer signoffs. Accepted shapes: "
            "a list of signoff mappings or an object with a 'reviewer_signoffs' list."
        ),
    )
    report_parser.add_argument(
        "--no-require-human-approval",
        action="store_true",
        help=(
            "Generate the report without requiring human approval. Intended for "
            "diagnostic/local modes only; default Wave 9 audit-ready gating requires human approval."
        ),
    )
    report_parser.add_argument(
        "--strict-existing-evidence",
        action="store_true",
        help="Fail immediately if a known generated Wave 6-8 evidence path is missing.",
    )
    report_parser.add_argument(
        "--run-id",
        default="",
        help="Optional run ID. Defaults to a deterministic digest-derived Wave 9 run ID.",
    )
    report_parser.add_argument(
        "--generated-at",
        default=None,
        help="Optional ISO-8601 timestamp for deterministic report generation.",
    )
    report_parser.add_argument(
        "--output",
        default=_DEFAULT_OUTPUT_PATH,
        help="JSON output path for the Wave 9 governance report.",
    )
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full Wave 9 governance report as JSON.",
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate the shape and digest of an exported Wave 9 governance report.",
    )
    validate_parser.add_argument(
        "--report",
        required=True,
        help="Path to a Wave 9 governance-report JSON artifact.",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Print validation result as JSON.",
    )

    gate_parser = subparsers.add_parser(
        "gate",
        help="Gate on a Wave 9 governance-report disposition.",
    )
    gate_parser.add_argument(
        "--report",
        required=True,
        help="Path to a Wave 9 governance-report JSON artifact.",
    )
    gate_parser.add_argument(
        "--allow-warning",
        action="store_true",
        help="Return success for warning disposition as well as audit_ready.",
    )
    gate_parser.add_argument(
        "--json",
        action="store_true",
        help="Print gate result as JSON.",
    )

    return parser


def _run_report(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    subject = AuditSubject(
        repository=args.repository,
        head_sha=args.head_sha,
        scope=args.scope,
        changed_paths=tuple(args.changed),
        metadata={"cli": True},
    )
    artifacts = collect_known_wave_evidence(
        root,
        head_sha=args.head_sha,
        require_existing=args.strict_existing_evidence,
    )
    manifest = build_evidence_manifest(
        manifest_id=f"wave9:{subject.digest[:16]}",
        subject=subject,
        artifacts=artifacts,
        metadata={
            "collector": "blackfox audit report",
            "known_wave_evidence_count": len(artifacts),
            "strict_existing_evidence": args.strict_existing_evidence,
        },
    )
    policy_pack = default_wave9_policy_pack()
    reviewer_signoffs = _load_signoffs(args.signoff_file) if args.signoff_file else ()
    report = build_governance_report(
        subject,
        manifest,
        generated_at=_parse_generated_at(args.generated_at),
        policy_pack=policy_pack,
        reviewer_signoffs=reviewer_signoffs,
        claims=tuple(args.claim),
        run_id=args.run_id,
        require_human_approval=not args.no_require_human_approval,
        metadata={"cli": True, "root": str(root)},
    )
    output_path = write_governance_report(report, Path(args.output))

    if args.json:
        _print_json(report.to_dict())
    else:
        _print_report_summary(report.to_dict(), output_path=output_path)
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    payload = load_governance_report_payload(Path(args.report))
    result = _validate_report_payload(payload)
    if args.json:
        _print_json(result)
    else:
        _print_validation_summary(result)
    return 0 if result["passed"] else 1


def _run_gate(args: argparse.Namespace) -> int:
    payload = load_governance_report_payload(Path(args.report))
    validation = _validate_report_payload(payload)
    disposition_value = payload.get("disposition")
    allowed = {AuditDisposition.AUDIT_READY.value}
    if args.allow_warning:
        allowed.add(AuditDisposition.WARNING.value)
    passed = bool(validation["passed"] and disposition_value in allowed)
    result = {
        "passed": passed,
        "validation_passed": validation["passed"],
        "disposition": disposition_value,
        "allowed_dispositions": sorted(allowed),
        "report": str(Path(args.report)),
        "issues": list(validation["issues"]),
    }
    if args.json:
        _print_json(result)
    else:
        print(f"Wave 9 gate: {'passed' if passed else 'blocked'}")
        print(f"Disposition: {disposition_value}")
        print(f"Validation passed: {validation['passed']}")
        if validation["issues"]:
            print("Issues:")
            for issue in validation["issues"]:
                print(f"- {issue}")
    return 0 if passed else 1


def _load_signoffs(path: str) -> tuple[AuditReviewerSignoff, ...]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        raw_signoffs = payload
    elif isinstance(payload, dict):
        value = payload.get("reviewer_signoffs")
        if not isinstance(value, list):
            raise ValueError("signoff JSON object must contain a 'reviewer_signoffs' list.")
        raw_signoffs = value
    else:
        raise ValueError("signoff file must contain a JSON list or object.")

    signoffs: list[AuditReviewerSignoff] = []
    for index, item in enumerate(raw_signoffs):
        if not isinstance(item, dict):
            raise ValueError(f"signoff entry at index {index} must be a JSON object.")
        signoffs.append(_signoff_from_mapping(item))
    return tuple(sorted(signoffs, key=lambda signoff: signoff.signoff_id))


def _signoff_from_mapping(payload: Mapping[str, Any]) -> AuditReviewerSignoff:
    try:
        signed_at_raw = payload["signed_at"]
        if not isinstance(signed_at_raw, str):
            raise ValueError("signed_at must be an ISO-8601 string.")
        return AuditReviewerSignoff(
            signoff_id=_string_field(payload, "signoff_id"),
            reviewer_id=_string_field(payload, "reviewer_id"),
            reviewer_kind=AuditReviewerKind(_string_field(payload, "reviewer_kind")),
            decision=AuditReviewDecision(_string_field(payload, "decision")),
            subject_digest=_string_field(payload, "subject_digest"),
            policy_pack_digest=_string_field(payload, "policy_pack_digest"),
            signed_at=_parse_iso_datetime(signed_at_raw),
            role=_string_field(payload, "role"),
            notes=str(payload.get("notes", "")),
            metadata=_mapping_field(payload.get("metadata", {}), "metadata"),
        )
    except KeyError as exc:
        raise ValueError(f"signoff entry is missing required field: {exc.args[0]}") from exc


def _validate_report_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    issues = list(validate_governance_report_payload_shape(payload))
    recorded_digest = payload.get("report_digest")
    if isinstance(recorded_digest, str):
        recomputed_payload = dict(payload)
        recomputed_payload.pop("report_digest", None)
        recomputed_digest = digest_payload(recomputed_payload)
        if recorded_digest != recomputed_digest:
            issues.append("report_digest does not match the exported report payload")
    return {
        "passed": not issues,
        "issue_count": len(issues),
        "issues": issues,
        "schema_version": payload.get("schema_version"),
        "wave": payload.get("wave"),
        "disposition": payload.get("disposition"),
        "report_digest": recorded_digest,
    }


def _parse_generated_at(value: str | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    return _parse_iso_datetime(value)


def _parse_iso_datetime(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("datetime values must include timezone information.")
    return parsed


def _string_field(payload: Mapping[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string.")
    return value


def _mapping_field(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    return cast(Mapping[str, Any], value)


def _print_report_summary(payload: Mapping[str, Any], *, output_path: Path) -> None:
    subject = _mapping_field(payload.get("subject", {}), "subject")
    evidence_manifest = _mapping_field(payload.get("evidence_manifest", {}), "evidence_manifest")
    control_evaluation = _mapping_field(payload.get("control_evaluation", {}), "control_evaluation")
    signoff_authority = _mapping_field(payload.get("signoff_authority", {}), "signoff_authority")
    print("Wave 9 governance report generated")
    print(f"Run ID: {payload.get('run_id')}")
    print(f"Repository: {subject.get('repository')}")
    print(f"Head SHA: {subject.get('head_sha')}")
    print(f"Disposition: {payload.get('disposition')}")
    print(f"Evidence artifacts: {evidence_manifest.get('artifact_count')}")
    print(f"Control findings: {control_evaluation.get('finding_count')}")
    print(f"Blocked controls: {control_evaluation.get('blocked_count')}")
    print(
        "Human approval: "
        f"{signoff_authority.get('has_authoritative_human_approval')}"
    )
    print(f"Report digest: {payload.get('report_digest')}")
    print(f"Report path: {output_path}")


def _print_validation_summary(result: Mapping[str, Any]) -> None:
    print(f"Wave 9 report validation: {'passed' if result['passed'] else 'failed'}")
    print(f"Disposition: {result.get('disposition')}")
    print(f"Report digest: {result.get('report_digest')}")
    if result["issues"]:
        print("Issues:")
        for issue in result["issues"]:
            print(f"- {issue}")


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
