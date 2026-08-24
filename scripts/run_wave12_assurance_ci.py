from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.assurance import (
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    AssuranceManifest,
    AssuranceReadinessStatus,
    AssuranceSubject,
    EvidenceInputSpec,
    QualityGateResult,
    build_assurance_crosswalk,
    build_assurance_package,
    build_assurance_readiness_report,
    canonical_json_bytes,
    collect_evidence,
    default_wave12_assurance_profile,
    default_wave12_claims,
    quality_gates_passed,
    run_wave12_quality_gates,
    verify_assurance_package,
    write_package_verification,
)

_DEFAULT_PACKAGE = Path(
    ".blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip"
)
_DEFAULT_VERIFICATION = Path(
    ".blackfox-artifacts/wave12/wave12-package-verification.json"
)
_DEFAULT_READINESS = Path(
    ".blackfox-artifacts/wave12/wave12-assurance-readiness-report.json"
)
_DEFAULT_CROSSWALK = Path(
    ".blackfox-artifacts/wave12/wave12-assurance-crosswalk.json"
)
_DEFAULT_MANIFEST = Path(
    ".blackfox-artifacts/wave12/wave12-assurance-manifest.json"
)
_DEFAULT_EVIDENCE_SPEC = Path(
    ".blackfox-artifacts/wave12/wave12-evidence-spec.json"
)
_DEFAULT_SUMMARY = Path(
    ".blackfox-artifacts/wave12/wave12-assurance-ci-summary.json"
)
_HEAD_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")
_WAVE12_CHANGED_PATHS = (
    ".github/workflows/wave12-assurance-evidence.yml",
    "README.md",
    "docs/system-architecture.md",
    "docs/wave12-certification-ready-evidence.md",
    "schemas",
    "scripts/run_wave12_assurance_ci.py",
    "src/ix_blackfox/assurance",
    "src/ix_blackfox/interface/cli.py",
    "tests/assurance",
    "tests/ci/test_wave12_assurance_workflow_contract.py",
    "tests/docs/test_wave12_assurance_docs.py",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    try:
        summary = run_wave12_assurance_ci(
            root=Path(args.root),
            head_sha=args.head_sha,
            generated_at=_parse_generated_at(args.generated_at),
            package_output=Path(args.package_output),
            verification_output=Path(args.verification_output),
            readiness_output=Path(args.readiness_output),
            crosswalk_output=Path(args.crosswalk_output),
            manifest_output=Path(args.manifest_output),
            evidence_spec_output=Path(args.evidence_spec_output),
            summary_output=Path(args.summary_output),
            expected_status=AssuranceReadinessStatus(args.expected_status),
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Wave 12 assurance CI error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def run_wave12_assurance_ci(
    *,
    root: Path,
    head_sha: str,
    generated_at: str,
    package_output: Path = _DEFAULT_PACKAGE,
    verification_output: Path = _DEFAULT_VERIFICATION,
    readiness_output: Path = _DEFAULT_READINESS,
    crosswalk_output: Path = _DEFAULT_CROSSWALK,
    manifest_output: Path = _DEFAULT_MANIFEST,
    evidence_spec_output: Path = _DEFAULT_EVIDENCE_SPEC,
    summary_output: Path = _DEFAULT_SUMMARY,
    expected_status: AssuranceReadinessStatus = (
        AssuranceReadinessStatus.REVIEW_REQUIRED
    ),
) -> dict[str, Any]:
    """Regenerate real evidence, package it, reopen it, and gate the result."""

    resolved_root = root.resolve(strict=True)
    if not (resolved_root / ".blackfox-workspace").is_file():
        raise ValueError("Wave 12 CI root must contain .blackfox-workspace.")
    normalized_head_sha = _normalize_head_sha(head_sha)
    outputs = {
        "package": _resolve_output(resolved_root, package_output),
        "verification": _resolve_output(resolved_root, verification_output),
        "readiness": _resolve_output(resolved_root, readiness_output),
        "crosswalk": _resolve_output(resolved_root, crosswalk_output),
        "manifest": _resolve_output(resolved_root, manifest_output),
        "evidence_spec": _resolve_output(resolved_root, evidence_spec_output),
        "summary": _resolve_output(resolved_root, summary_output),
    }
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    prerequisite_results = _run_prerequisite_evidence(
        root=resolved_root,
        head_sha=normalized_head_sha,
        generated_at=generated_at,
    )
    if not all(item["passed"] for item in prerequisite_results):
        raise ValueError("A prerequisite wave evidence generator failed.")

    quality_dir = resolved_root / ".blackfox-artifacts/wave12/quality"
    quality_results = run_wave12_quality_gates(
        root=resolved_root,
        head_sha=normalized_head_sha,
        generated_at=generated_at,
        output_dir=quality_dir,
    )
    if not quality_gates_passed(quality_results):
        raise ValueError("A Wave 12 quality gate failed; evidence was retained.")

    evidence_specs = _wave12_evidence_specs(
        root=resolved_root,
        quality_results=quality_results,
    )
    _write_json(
        outputs["evidence_spec"],
        {
            "schema_version": "wave12.evidence_input_spec.v1",
            "head_sha": normalized_head_sha,
            "evidence": [spec.to_dict() for spec in evidence_specs],
        },
    )
    collected = collect_evidence(
        resolved_root,
        evidence_specs,
        expected_revision=normalized_head_sha,
    )
    subject = AssuranceSubject(
        repository="IX-BlackFox",
        revision=normalized_head_sha,
        scope=(
            "Wave 12 certification-ready evidence packaging for governed "
            "AI-assisted software-change controls"
        ),
        producer_agent_id="wave12-ci-runner",
        generated_at=generated_at,
        metadata={
            "ci": True,
            "script": "scripts/run_wave12_assurance_ci.py",
        },
    )
    profile = default_wave12_assurance_profile()
    manifest = AssuranceManifest(
        manifest_id=f"wave12-ci-{normalized_head_sha[:16]}",
        subject=subject,
        profile=profile,
        evidence=tuple(item.artifact for item in collected),
        claims=default_wave12_claims(),
        metadata={
            "ci": True,
            "prerequisite_generator_count": len(prerequisite_results),
            "quality_gate_count": len(quality_results),
            "human_review_supplied": False,
        },
    )
    crosswalk = build_assurance_crosswalk(
        subject=subject,
        profile=profile,
        artifacts=manifest.evidence,
        metadata={"ci": True},
    )
    readiness = build_assurance_readiness_report(
        manifest=manifest,
        crosswalk=crosswalk,
        reviews=(),
        metadata={
            "ci": True,
            "expected_status": expected_status.value,
        },
    )
    _write_json(outputs["manifest"], manifest.to_dict())
    _write_json(outputs["crosswalk"], crosswalk.to_dict())
    _write_json(outputs["readiness"], readiness.to_dict())

    build_result = build_assurance_package(
        output_path=outputs["package"],
        manifest=manifest,
        crosswalk=crosswalk,
        readiness=readiness,
        evidence=collected,
        reviews=(),
        metadata={"ci": True},
    )
    verification = verify_assurance_package(
        outputs["package"],
        metadata={"ci": True, "head_sha": normalized_head_sha},
    )
    write_package_verification(verification, outputs["verification"])

    passed = (
        crosswalk.mandatory_evidence_complete
        and readiness.status is expected_status
        and verification.passed
        and verification.readiness_status == expected_status.value
        and quality_gates_passed(quality_results)
        and all(item["passed"] for item in prerequisite_results)
    )
    summary: dict[str, Any] = {
        "schema_version": "wave12.assurance_ci_summary.v1",
        "wave": "12",
        "head_sha": normalized_head_sha,
        "generated_at": generated_at,
        "passed": passed,
        "expected_status": expected_status.value,
        "readiness_status": readiness.status.value,
        "ready_for_external_assessment": readiness.ready_for_external_assessment,
        "mandatory_evidence_complete": crosswalk.mandatory_evidence_complete,
        "quality_gates_run": True,
        "quality_gate_count": len(quality_results),
        "quality_gates_passed": quality_gates_passed(quality_results),
        "prerequisites_run": True,
        "prerequisite_results": list(prerequisite_results),
        "evidence_artifact_count": len(collected),
        "manifest_digest": manifest.digest,
        "profile_digest": profile.digest,
        "crosswalk_digest": crosswalk.digest,
        "readiness_digest": readiness.digest,
        "archive_sha256": build_result.archive_sha256,
        "bundle_index_digest": build_result.bundle_index_digest,
        "verification_passed": verification.passed,
        "verification_issue_count": len(verification.issues),
        "outputs": {key: str(path) for key, path in outputs.items()},
        "scope_note": (
            "A passing Wave 12 CI result proves deterministic evidence collection, "
            "mandatory profile coverage, package construction, tamper verification, "
            "and an intentionally open human-review gate. It is not certification, "
            "compliance approval, ATO/cATO, procurement approval, deployment approval, "
            "production authority, or autonomous approval authority."
        ),
    }
    _write_json(outputs["summary"], summary)
    return summary


def _run_prerequisite_evidence(
    *,
    root: Path,
    head_sha: str,
    generated_at: str,
) -> tuple[dict[str, Any], ...]:
    python = sys.executable
    commands: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "wave6-sandbox",
            (
                python,
                "scripts/run_wave6_sandbox_ci.py",
                "--head-sha",
                head_sha,
                "--output",
                ".blackfox-artifacts/wave6/sandbox-ci-report.json",
            ),
        ),
        (
            "wave7-model-repair",
            (
                python,
                "scripts/run_wave7_model_repair_ci.py",
                "--head-sha",
                head_sha,
                "--output",
                ".blackfox-artifacts/wave7/model-repair-ci-report.json",
            ),
        ),
        (
            "wave8-repository-intelligence",
            (
                python,
                "scripts/run_wave8_repository_intelligence_ci.py",
                "--root",
                ".",
                "--head-sha",
                head_sha,
                *_changed_path_arguments(),
                "--output",
                ".blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json",
                "--evidence-output",
                ".blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json",
            ),
        ),
        (
            "wave11-agent-identity",
            (
                python,
                "scripts/run_wave11_agent_identity_ci.py",
                "--root",
                ".",
                "--head-sha",
                head_sha,
                "--generated-at",
                generated_at,
                "--output",
                ".blackfox-artifacts/wave11/wave11-agent-readiness-report.json",
                "--engine-evidence-output",
                ".blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json",
                "--summary-output",
                ".blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json",
                "--expected-status",
                "warning",
            ),
        ),
    )
    results = [_run_command(root, name, argv) for name, argv in commands]
    if not all(item["passed"] for item in results):
        return tuple(results)

    wave9 = _run_command(
        root,
        "wave9-compliance-audit",
        (
            python,
            "scripts/run_wave9_compliance_audit_ci.py",
            "--root",
            ".",
            "--head-sha",
            head_sha,
            *_changed_path_arguments(),
            "--generated-at",
            generated_at,
            "--output",
            ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json",
            "--engine-evidence-output",
            ".blackfox-artifacts/wave9/wave9-compliance-audit-engine-evidence.json",
            "--summary-output",
            ".blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json",
            "--expected-disposition",
            "blocked",
        ),
    )
    return (*results, wave9)


def _run_command(root: Path, name: str, argv: tuple[str, ...]) -> dict[str, Any]:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    completed = subprocess.run(
        argv,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )
    return {
        "name": name,
        "passed": completed.returncode == 0,
        "exit_code": completed.returncode,
        "stdout_sha256": _text_sha256(completed.stdout),
        "stderr_sha256": _text_sha256(completed.stderr),
    }


def _changed_path_arguments() -> tuple[str, ...]:
    return tuple(
        argument
        for path in _WAVE12_CHANGED_PATHS
        for argument in ("--changed", path)
    )


def _wave12_evidence_specs(
    *,
    root: Path,
    quality_results: Sequence[tuple[QualityGateResult, Path]],
) -> tuple[EvidenceInputSpec, ...]:
    specs: list[EvidenceInputSpec] = []
    for result, path in quality_results:
        relative = path.relative_to(root).as_posix()
        specs.append(
            EvidenceInputSpec(
                artifact_id=result.gate_id,
                source_wave=AssuranceEvidenceSource.WAVE12,
                evidence_kind=result.evidence_kind,
                source_path=relative,
                package_path=f"evidence/wave12-quality/{path.name}",
                media_type="application/json",
                producer="IX-BlackFox Wave 12 quality capture",
                schema_version="wave12.quality_gate_evidence.v1",
                revision_json_pointer="/head_sha",
            )
        )

    specs.extend(
        (
            _spec(
                artifact_id="wave6-sandbox-ci",
                source_wave=AssuranceEvidenceSource.WAVE6,
                kind=AssuranceEvidenceKind.SANDBOX_EVIDENCE,
                source_path=".blackfox-artifacts/wave6/sandbox-ci-report.json",
                package_path="evidence/wave6/sandbox-ci-report.json",
                producer="IX-BlackFox Wave 6 CI runner",
                schema_version="wave6.sandbox_ci_evidence.v1",
                pointer="/head_sha",
            ),
            _spec(
                artifact_id="wave7-model-repair-ci",
                source_wave=AssuranceEvidenceSource.WAVE7,
                kind=AssuranceEvidenceKind.OTHER,
                source_path=".blackfox-artifacts/wave7/model-repair-ci-report.json",
                package_path="evidence/wave7/model-repair-ci-report.json",
                producer="IX-BlackFox Wave 7 CI runner",
                schema_version="wave7.model_repair_ci_evidence.v1",
                pointer="/head_sha",
                required=False,
            ),
            _spec(
                artifact_id="wave8-repository-intelligence-ci",
                source_wave=AssuranceEvidenceSource.WAVE8,
                kind=AssuranceEvidenceKind.REPOSITORY_INTELLIGENCE,
                source_path=(
                    ".blackfox-artifacts/wave8/"
                    "wave8-repository-intelligence-ci-report.json"
                ),
                package_path=(
                    "evidence/wave8/wave8-repository-intelligence-ci-report.json"
                ),
                producer="IX-BlackFox Wave 8 CI runner",
                schema_version="wave8.repository_intelligence_ci.v1",
                pointer="/head_sha",
            ),
            _spec(
                artifact_id="wave9-compliance-audit-report",
                source_wave=AssuranceEvidenceSource.WAVE9,
                kind=AssuranceEvidenceKind.POLICY_EVALUATION,
                source_path=(
                    ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json"
                ),
                package_path="evidence/wave9/wave9-compliance-audit-report.json",
                producer="IX-BlackFox Wave 9 audit engine",
                schema_version="wave9.compliance_audit_attestation.v1",
                pointer="/subject/head_sha",
            ),
            _spec(
                artifact_id="wave11-agent-identity-engine",
                source_wave=AssuranceEvidenceSource.WAVE11,
                kind=AssuranceEvidenceKind.AGENT_IDENTITY,
                source_path=(
                    ".blackfox-artifacts/wave11/"
                    "wave11-agent-identity-engine-evidence.json"
                ),
                package_path=(
                    "evidence/wave11/wave11-agent-identity-engine-evidence.json"
                ),
                producer="IX-BlackFox Wave 11 agent identity CI runner",
                schema_version="wave11.agent_identity_engine_evidence.v1",
                pointer="/head_sha",
            ),
            _spec(
                artifact_id="wave11-agent-provenance-readiness",
                source_wave=AssuranceEvidenceSource.WAVE11,
                kind=AssuranceEvidenceKind.PROVENANCE,
                source_path=(
                    ".blackfox-artifacts/wave11/wave11-agent-readiness-report.json"
                ),
                package_path=(
                    "evidence/wave11/wave11-agent-readiness-report.json"
                ),
                producer="IX-BlackFox Wave 11 agent identity CI runner",
                schema_version="wave11.agent_readiness_report.v1",
                pointer="/metadata/head_sha",
            ),
        )
    )
    return tuple(specs)


def _spec(
    *,
    artifact_id: str,
    source_wave: AssuranceEvidenceSource,
    kind: AssuranceEvidenceKind,
    source_path: str,
    package_path: str,
    producer: str,
    schema_version: str,
    pointer: str,
    required: bool = True,
) -> EvidenceInputSpec:
    return EvidenceInputSpec(
        artifact_id=artifact_id,
        source_wave=source_wave,
        evidence_kind=kind,
        source_path=source_path,
        package_path=package_path,
        media_type="application/json",
        producer=producer,
        schema_version=schema_version,
        required=required,
        revision_json_pointer=pointer,
    )


def _resolve_output(root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError("Wave 12 CI outputs must remain inside the repository root.")
    return resolved_parent / candidate.name


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError("Wave 12 CI output must not be a symlink.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))


def _normalize_head_sha(value: str) -> str:
    cleaned = value.strip().lower()
    if not _HEAD_SHA_PATTERN.fullmatch(cleaned):
        raise ValueError("head_sha must be a 7-64 character hexadecimal revision.")
    return cleaned


def _parse_generated_at(value: str | None) -> str:
    if value is None:
        return datetime.now(tz=UTC).isoformat()
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("generated_at must include a timezone offset.")
    return parsed.isoformat()


def _text_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline Wave 12 certification-ready evidence campaign."
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--package-output", default=str(_DEFAULT_PACKAGE))
    parser.add_argument("--verification-output", default=str(_DEFAULT_VERIFICATION))
    parser.add_argument("--readiness-output", default=str(_DEFAULT_READINESS))
    parser.add_argument("--crosswalk-output", default=str(_DEFAULT_CROSSWALK))
    parser.add_argument("--manifest-output", default=str(_DEFAULT_MANIFEST))
    parser.add_argument("--evidence-spec-output", default=str(_DEFAULT_EVIDENCE_SPEC))
    parser.add_argument("--summary-output", default=str(_DEFAULT_SUMMARY))
    parser.add_argument(
        "--expected-status",
        choices=tuple(status.value for status in AssuranceReadinessStatus),
        default=AssuranceReadinessStatus.REVIEW_REQUIRED.value,
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
