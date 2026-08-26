from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.assurance.package import canonical_json_bytes
from ix_blackfox.review_board.admission import admit_wave12_package
from ix_blackfox.review_board.models import ReviewBoardStatus
from ix_blackfox.review_board.package import (
    build_machine_advisory_set,
    build_review_board_package,
    build_review_case,
)
from ix_blackfox.review_board.policy import (
    build_machine_advisory,
    default_wave13_review_policy,
)
from ix_blackfox.review_board.verify import (
    verify_review_board_package,
    write_review_board_verification,
)

_DEFAULT_WAVE12_PACKAGE = Path(
    ".blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip"
)
_DEFAULT_PACKAGE = Path(
    ".blackfox-artifacts/wave13/wave13-human-machine-review-board.zip"
)
_DEFAULT_VERIFICATION = Path(
    ".blackfox-artifacts/wave13/wave13-package-verification.json"
)
_DEFAULT_CASE = Path(".blackfox-artifacts/wave13/wave13-review-case.json")
_DEFAULT_ADVISORIES = Path(".blackfox-artifacts/wave13/wave13-machine-advisories.json")
_DEFAULT_EVALUATION = Path(".blackfox-artifacts/wave13/wave13-board-evaluation.json")
_DEFAULT_SUMMARY = Path(".blackfox-artifacts/wave13/wave13-review-board-ci-summary.json")
_HEAD_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    try:
        summary = run_wave13_review_board_ci(
            root=Path(args.root),
            head_sha=args.head_sha,
            generated_at=_parse_generated_at(args.generated_at),
            wave12_package=Path(args.wave12_package),
            package_output=Path(args.package_output),
            verification_output=Path(args.verification_output),
            case_output=Path(args.case_output),
            advisory_output=Path(args.advisory_output),
            evaluation_output=Path(args.evaluation_output),
            summary_output=Path(args.summary_output),
            expected_status=ReviewBoardStatus(args.expected_status),
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"Wave 13 review-board CI error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def run_wave13_review_board_ci(
    *,
    root: Path,
    head_sha: str,
    generated_at: str,
    wave12_package: Path = _DEFAULT_WAVE12_PACKAGE,
    package_output: Path = _DEFAULT_PACKAGE,
    verification_output: Path = _DEFAULT_VERIFICATION,
    case_output: Path = _DEFAULT_CASE,
    advisory_output: Path = _DEFAULT_ADVISORIES,
    evaluation_output: Path = _DEFAULT_EVALUATION,
    summary_output: Path = _DEFAULT_SUMMARY,
    expected_status: ReviewBoardStatus = ReviewBoardStatus.HUMAN_REVIEW_REQUIRED,
) -> dict[str, Any]:
    """Consume verified Wave 12 evidence and prove the Wave 13 human gate stays real."""

    resolved_root = root.resolve(strict=True)
    if not (resolved_root / ".blackfox-workspace").is_file():
        raise ValueError("Wave 13 CI root must contain .blackfox-workspace.")
    normalized_head_sha = _normalize_head_sha(head_sha)
    wave12_path = _resolve_input(resolved_root, wave12_package)
    outputs = {
        "package": _resolve_output(resolved_root, package_output),
        "verification": _resolve_output(resolved_root, verification_output),
        "case": _resolve_output(resolved_root, case_output),
        "advisories": _resolve_output(resolved_root, advisory_output),
        "evaluation": _resolve_output(resolved_root, evaluation_output),
        "summary": _resolve_output(resolved_root, summary_output),
    }
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    admission = admit_wave12_package(wave12_path, admitted_at=generated_at)
    if admission.manifest.subject.revision != normalized_head_sha:
        raise ValueError(
            "Wave 12 package revision does not match the Wave 13 CI head_sha."
        )

    policy = default_wave13_review_policy()
    advisory = build_machine_advisory(
        advisory_id=f"wave13-ci-{normalized_head_sha[:16]}",
        producer_agent_id="wave13-rule-engine",
        subject=admission.subject,
        policy=policy,
        produced_at=generated_at,
        upstream_verification_passed=admission.verification.passed,
        upstream_readiness_status=admission.verification.readiness_status,
        evidence_refs=("wave12-certification-ready-evidence",),
        metadata={
            "ci": True,
            "rule_based": True,
            "machine_authority": False,
        },
    )

    _write_json(outputs["case"], build_review_case(admission.subject, policy))
    _write_json(
        outputs["advisories"],
        build_machine_advisory_set(admission.subject, policy, (advisory,)),
    )

    build_result = build_review_board_package(
        output_path=outputs["package"],
        wave12_package_path=wave12_path,
        subject=admission.subject,
        policy=policy,
        machine_advisories=(advisory,),
        human_reviews=(),
        challenges=(),
        metadata={"ci": True, "head_sha": normalized_head_sha},
    )
    _write_json(outputs["evaluation"], build_result.evaluation.to_dict())

    verification = verify_review_board_package(
        outputs["package"],
        metadata={"ci": True, "head_sha": normalized_head_sha},
    )
    write_review_board_verification(verification, outputs["verification"])

    passed = (
        admission.verification.passed
        and verification.passed
        and verification.upstream_wave12_verification_passed
        and build_result.evaluation.status is expected_status
        and verification.status == expected_status.value
        and build_result.evaluation.human_review_count == 0
        and build_result.evaluation.external_verification_count == 0
        and len(build_result.evaluation.qualifying_review_ids) == 0
    )
    summary: dict[str, Any] = {
        "schema_version": "wave13.review_board_ci_summary.v1",
        "wave": "13",
        "head_sha": normalized_head_sha,
        "generated_at": generated_at,
        "passed": passed,
        "expected_status": expected_status.value,
        "board_status": build_result.evaluation.status.value,
        "human_review_supplied": False,
        "external_verification_supplied": False,
        "external_verification_count": (
            build_result.evaluation.external_verification_count
        ),
        "external_verification_context_digest": (
            build_result.evaluation.external_verification_context_digest
        ),
        "qualifying_human_approval_count": len(
            build_result.evaluation.qualifying_review_ids
        ),
        "required_roles": [role.value for role in policy.required_roles],
        "missing_required_roles": [
            role.value for role in build_result.evaluation.missing_required_roles
        ],
        "machine_advisory_count": build_result.evaluation.machine_advisory_count,
        "machine_vote_weight": 0,
        "upstream_wave12_verification_passed": admission.verification.passed,
        "upstream_wave12_readiness_status": admission.verification.readiness_status,
        "upstream_wave12_sha256": admission.verification.archive_sha256,
        "subject_digest": admission.subject.digest,
        "policy_digest": policy.digest,
        "evaluation_digest": build_result.evaluation.digest,
        "archive_sha256": build_result.archive_sha256,
        "bundle_index_digest": build_result.bundle_index_digest,
        "verification_passed": verification.passed,
        "verification_issue_count": len(verification.issues),
        "outputs": {key: str(path) for key, path in outputs.items()},
        "scope_note": (
            "A passing Wave 13 CI result proves that verified Wave 12 evidence can be "
            "admitted into a role-based review package and that machine analysis cannot "
            "silently satisfy human quorum. The expected offline state is "
            "human_review_required. No human identity, role authority, review decision, "
            "or external verification context is fabricated."
        ),
    }
    _write_json(outputs["summary"], summary)
    return summary


def _resolve_input(root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("Wave 13 CI inputs must remain inside the repository root.")
    return resolved


def _resolve_output(root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError("Wave 13 CI outputs must remain inside the repository root.")
    return resolved_parent / candidate.name


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError("Wave 13 CI output must not be a symlink.")
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline Wave 13 human-machine review-board campaign."
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--wave12-package", default=str(_DEFAULT_WAVE12_PACKAGE))
    parser.add_argument("--package-output", default=str(_DEFAULT_PACKAGE))
    parser.add_argument("--verification-output", default=str(_DEFAULT_VERIFICATION))
    parser.add_argument("--case-output", default=str(_DEFAULT_CASE))
    parser.add_argument("--advisory-output", default=str(_DEFAULT_ADVISORIES))
    parser.add_argument("--evaluation-output", default=str(_DEFAULT_EVALUATION))
    parser.add_argument("--summary-output", default=str(_DEFAULT_SUMMARY))
    parser.add_argument(
        "--expected-status",
        choices=tuple(status.value for status in ReviewBoardStatus),
        default=ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value,
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
