from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.audit.evidence_standard import inspect_evidence_file, validate_evidence_manifest
from ix_blackfox.audit.models import (
    AuditDisposition,
    AuditEvidenceKind,
    AuditEvidenceManifest,
    AuditEvidenceSourceWave,
    AuditSubject,
    digest_payload,
)
from ix_blackfox.audit.policy_packs import default_wave9_policy_pack
from ix_blackfox.audit.report import (
    Wave9GovernanceReport,
    build_governance_report,
    load_governance_report_payload,
    validate_governance_report_payload_shape,
    write_governance_report,
)

_DEFAULT_OUTPUT = Path(".blackfox-artifacts/wave9/wave9-compliance-audit-report.json")
_DEFAULT_ENGINE_EVIDENCE_OUTPUT = Path(
    ".blackfox-artifacts/wave9/wave9-ci-engine-evidence.json"
)
_DEFAULT_SUMMARY_OUTPUT = Path(
    ".blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json"
)
_DEFAULT_SCOPE = "Wave 9 compliance/audit attestation engine diagnostic"
_DEFAULT_CLAIMS = (
    "policy digest review",
    "wave9 audit engine diagnostic",
)
_DEFAULT_CHANGED_PATHS = (
    "src/ix_blackfox/audit/report.py",
    "scripts/run_wave9_compliance_audit_ci.py",
)


def build_wave9_compliance_audit_ci_report(
    *,
    root: Path,
    head_sha: str,
    output_path: Path | None = None,
    engine_evidence_output_path: Path | None = None,
    changed_paths: tuple[str, ...] | None = None,
    claims: tuple[str, ...] | None = None,
    run_id: str | None = None,
    generated_at: datetime | None = None,
    require_human_approval: bool = True,
) -> Wave9GovernanceReport:
    """
    Build deterministic offline Wave 9 compliance/audit evidence.

    The default CI scenario intentionally produces a valid blocked governance
    report: it proves the audit engine, policy pack, evidence manifest,
    deterministic digests, report export, and fail-closed human-approval gate
    without inventing human signoff. That blocked disposition is expected and
    should not make CI red when the report is structurally valid.
    """

    normalized_head_sha = _normalize_head_sha(head_sha)
    normalized_generated_at = generated_at or datetime.now(tz=UTC)
    normalized_run_id = run_id or f"wave9-ci-{normalized_head_sha[:12]}"
    normalized_changed_paths = changed_paths or _DEFAULT_CHANGED_PATHS
    normalized_claims = claims or _DEFAULT_CLAIMS
    report_output = output_path or _DEFAULT_OUTPUT
    engine_evidence_output = engine_evidence_output_path or _DEFAULT_ENGINE_EVIDENCE_OUTPUT

    subject = AuditSubject(
        repository="IX-BlackFox",
        head_sha=normalized_head_sha,
        scope=_DEFAULT_SCOPE,
        changed_paths=normalized_changed_paths,
        metadata={
            "ci": True,
            "script": "scripts/run_wave9_compliance_audit_ci.py",
            "output_path": str(report_output),
        },
    )
    policy_pack = default_wave9_policy_pack()

    engine_evidence_path = write_ci_engine_evidence(
        root=root,
        output_path=engine_evidence_output,
        head_sha=normalized_head_sha,
        run_id=normalized_run_id,
        generated_at=normalized_generated_at,
        require_human_approval=require_human_approval,
        claims=normalized_claims,
    )
    engine_artifact = inspect_evidence_file(
        root,
        _relative_to_root(engine_evidence_path, root),
        kind=AuditEvidenceKind.POLICY_DECISION,
        source_wave=AuditEvidenceSourceWave.WAVE9,
        artifact_id="wave9:ci-engine-evidence",
        producer="scripts/run_wave9_compliance_audit_ci.py",
        head_sha=normalized_head_sha,
        schema_version="wave9.ci_engine_evidence.v1",
        verified=True,
        metadata={
            "ci": True,
            "purpose": "wave9_audit_engine_diagnostic_evidence",
        },
    )
    manifest = AuditEvidenceManifest(
        manifest_id=f"wave9:{normalized_run_id}:manifest",
        subject=subject,
        artifacts=(engine_artifact,),
        generated_at=normalized_generated_at,
        metadata={
            "ci": True,
            "collector": "scripts/run_wave9_compliance_audit_ci.py",
            "engine_evidence_path": _relative_to_root(engine_evidence_path, root),
        },
    )
    evidence_validation = validate_evidence_manifest(manifest, repo_root=root)
    return build_governance_report(
        subject,
        manifest,
        generated_at=normalized_generated_at,
        policy_pack=policy_pack,
        reviewer_signoffs=(),
        claims=normalized_claims,
        run_id=normalized_run_id,
        require_human_approval=require_human_approval,
        evidence_validation=evidence_validation,
        metadata={
            "ci": True,
            "script": "scripts/run_wave9_compliance_audit_ci.py",
            "claim": "offline_wave9_audit_attestation_engine_check_not_compliance_certification",
        },
    )


def build_ci_summary_payload(
    *,
    head_sha: str,
    report_payload: dict[str, Any],
    report_output_path: Path,
    engine_evidence_output_path: Path,
    expected_disposition: AuditDisposition,
) -> dict[str, Any]:
    """Build the top-level Wave 9 CI summary payload."""

    normalized_head_sha = _normalize_head_sha(head_sha)
    validation = validate_exported_report_payload(report_payload)
    disposition = str(report_payload.get("disposition", ""))
    passed = validation["passed"] is True and disposition == expected_disposition.value
    control_evaluation = _mapping(report_payload.get("control_evaluation", {}))
    evidence_manifest = _mapping(report_payload.get("evidence_manifest", {}))
    signoff_authority = _mapping(report_payload.get("signoff_authority", {}))
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "wave": "9",
        "head_sha": normalized_head_sha,
        "passed": passed,
        "expected_disposition": expected_disposition.value,
        "disposition": disposition,
        "run_id": report_payload.get("run_id"),
        "report_digest": report_payload.get("report_digest"),
        "attestation_subject_digest": report_payload.get("attestation_subject_digest"),
        "policy_pack_digest": _mapping(report_payload.get("policy_pack", {})).get("digest"),
        "evidence_manifest_digest": evidence_manifest.get("digest"),
        "control_evaluation_digest": control_evaluation.get("digest"),
        "report_validation": validation,
        "summary": {
            "report_path": str(report_output_path),
            "engine_evidence_path": str(engine_evidence_output_path),
            "evidence_artifact_count": evidence_manifest.get("artifact_count"),
            "control_finding_count": control_evaluation.get("finding_count"),
            "blocked_control_count": control_evaluation.get("blocked_count"),
            "warning_control_count": control_evaluation.get("warning_count"),
            "has_authoritative_human_approval": signoff_authority.get(
                "has_authoritative_human_approval"
            ),
        },
        "scope_note": (
            "This CI payload verifies the Wave 9 audit-attestation engine, policy-pack binding, "
            "evidence manifest validation, deterministic governance report export, report digest "
            "validation, and fail-closed human-approval boundary. A blocked disposition is expected "
            "in default CI because the runner does not fabricate human signoff. This is not production "
            "certification, formal compliance approval, ATO/cATO, DoD endorsement, procurement approval, "
            "or authorization for autonomous execution."
        ),
    }


def write_ci_payload(
    *,
    root: Path,
    head_sha: str,
    output_path: Path,
    engine_evidence_output_path: Path | None = None,
    summary_output_path: Path | None = None,
    changed_paths: tuple[str, ...] | None = None,
    claims: tuple[str, ...] | None = None,
    run_id: str | None = None,
    generated_at: datetime | None = None,
    require_human_approval: bool = True,
    expected_disposition: AuditDisposition = AuditDisposition.BLOCKED,
) -> dict[str, Any]:
    """Write Wave 9 governance report and CI summary artifacts."""

    resolved_root = root.resolve()
    report_output = output_path
    engine_evidence_output = engine_evidence_output_path or _DEFAULT_ENGINE_EVIDENCE_OUTPUT
    summary_output = summary_output_path or _DEFAULT_SUMMARY_OUTPUT

    report = build_wave9_compliance_audit_ci_report(
        root=resolved_root,
        head_sha=head_sha,
        output_path=report_output,
        engine_evidence_output_path=engine_evidence_output,
        changed_paths=changed_paths,
        claims=claims,
        run_id=run_id,
        generated_at=generated_at,
        require_human_approval=require_human_approval,
    )
    write_governance_report(report, report_output)
    report_payload = dict(load_governance_report_payload(report_output))
    summary = build_ci_summary_payload(
        head_sha=head_sha,
        report_payload=report_payload,
        report_output_path=report_output,
        engine_evidence_output_path=engine_evidence_output,
        expected_disposition=expected_disposition,
    )
    summary_output.parent.mkdir(parents=True, exist_ok=True)
    summary_output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def write_ci_engine_evidence(
    *,
    root: Path,
    output_path: Path,
    head_sha: str,
    run_id: str,
    generated_at: datetime,
    require_human_approval: bool,
    claims: tuple[str, ...],
) -> Path:
    """Write a real, digestable Wave 9 CI engine-evidence artifact."""

    resolved_root = root.resolve()
    if output_path.is_absolute():
        resolved_output = output_path.resolve()
    else:
        resolved_output = (resolved_root / output_path).resolve()
    try:
        resolved_output.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("engine evidence output must stay inside the repository root") from exc
    payload = {
        "schema_version": "wave9.ci_engine_evidence.v1",
        "wave": "9",
        "head_sha": _normalize_head_sha(head_sha),
        "run_id": run_id,
        "generated_at": generated_at.isoformat(),
        "require_human_approval": require_human_approval,
        "claims": list(claims),
        "script": "scripts/run_wave9_compliance_audit_ci.py",
        "evidence_role": "audit_engine_diagnostic_input",
        "authority_boundary": "AI proposes. Humans decide.",
        "non_claims": [
            "This CI evidence does not certify production readiness.",
            "This CI evidence does not grant ATO, cATO, procurement approval, or deployment authority.",
            "This CI evidence does not prove DoD endorsement, affiliation, acceptance, or certification.",
            "This CI evidence does not authorize autonomous code changes or autonomous release decisions.",
            "This CI evidence does not fabricate human signoff.",
        ],
    }
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return resolved_output


def validate_exported_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate exported Wave 9 report shape and digest without extra dependencies."""

    issues = list(validate_governance_report_payload_shape(payload))
    recorded_digest = payload.get("report_digest")
    if isinstance(recorded_digest, str):
        recomputed_payload = dict(payload)
        recomputed_payload.pop("report_digest", None)
        if digest_payload(recomputed_payload) != recorded_digest:
            issues.append("report_digest does not match the exported report payload")
    else:
        issues.append("report_digest must be present for Wave 9 CI validation")
    return {
        "passed": not issues,
        "issue_count": len(issues),
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Wave 9 compliance/audit attestation CI evidence for IX-BlackFox."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root used to write and inspect Wave 9 CI evidence.",
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="The commit SHA that the Wave 9 CI evidence is bound to.",
    )
    parser.add_argument(
        "--changed",
        action="append",
        default=None,
        help=(
            "Repository-relative changed path to bind into the audit subject. "
            "May be supplied multiple times. Defaults to the Wave 9 report and CI runner paths."
        ),
    )
    parser.add_argument(
        "--claim",
        action="append",
        default=None,
        help="Claim to evaluate in the Wave 9 report. May be supplied multiple times.",
    )
    parser.add_argument(
        "--output",
        default=str(_DEFAULT_OUTPUT),
        help="Path to write the Wave 9 governance report JSON artifact.",
    )
    parser.add_argument(
        "--engine-evidence-output",
        default=str(_DEFAULT_ENGINE_EVIDENCE_OUTPUT),
        help="Path to write the Wave 9 CI engine-evidence JSON artifact.",
    )
    parser.add_argument(
        "--summary-output",
        default=str(_DEFAULT_SUMMARY_OUTPUT),
        help="Path to write the Wave 9 CI summary JSON payload.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run ID. Defaults to wave9-ci-<head-sha-prefix>.",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Optional timezone-aware ISO-8601 timestamp for deterministic report generation.",
    )
    parser.add_argument(
        "--no-require-human-approval",
        action="store_true",
        help="Diagnostic mode only: do not require human approval in the generated report.",
    )
    parser.add_argument(
        "--expected-disposition",
        default=AuditDisposition.BLOCKED.value,
        choices=tuple(disposition.value for disposition in AuditDisposition),
        help="Expected report disposition for CI pass/fail. Defaults to blocked.",
    )
    args = parser.parse_args(argv)

    expected_disposition = AuditDisposition(args.expected_disposition)
    summary = write_ci_payload(
        root=Path(args.root),
        head_sha=args.head_sha,
        output_path=Path(args.output),
        engine_evidence_output_path=Path(args.engine_evidence_output),
        summary_output_path=Path(args.summary_output),
        changed_paths=tuple(args.changed) if args.changed else None,
        claims=tuple(args.claim) if args.claim else None,
        run_id=args.run_id,
        generated_at=_parse_generated_at(args.generated_at),
        require_human_approval=not args.no_require_human_approval,
        expected_disposition=expected_disposition,
    )

    print(f"Wave 9 governance report written to {args.output}")
    print(f"Wave 9 CI engine evidence written to {args.engine_evidence_output}")
    print(f"Wave 9 CI summary written to {args.summary_output}")
    print(f"Passed: {summary['passed']}")
    print(f"Disposition: {summary['disposition']}")
    print(f"Expected disposition: {summary['expected_disposition']}")
    print(f"Report validation passed: {summary['report_validation']['passed']}")

    return 0 if summary["passed"] else 1


def _normalize_head_sha(head_sha: str) -> str:
    normalized = head_sha.strip()
    if not normalized:
        raise ValueError("head_sha must not be empty.")
    return normalized


def _parse_generated_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("generated_at must include timezone information.")
    return parsed


def _relative_to_root(path: Path, root: Path) -> str:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    return resolved_path.relative_to(resolved_root).as_posix()


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


if __name__ == "__main__":
    raise SystemExit(main())
