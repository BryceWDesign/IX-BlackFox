from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.crosswalk import build_assurance_crosswalk
from ix_blackfox.assurance.evidence import collect_evidence, load_evidence_specs
from ix_blackfox.assurance.models import (
    AssuranceManifest,
    AssuranceSubject,
    AuthorityReview,
    AuthorityReviewDecision,
    ReviewAuthenticationState,
    default_wave12_claims,
)
from ix_blackfox.assurance.package import build_assurance_package
from ix_blackfox.assurance.profiles import default_wave12_assurance_profile
from ix_blackfox.assurance.report import (
    AssuranceReadinessStatus,
    build_assurance_readiness_report,
)
from ix_blackfox.assurance.verify import (
    verify_assurance_package,
    write_package_verification,
)

_DEFAULT_PACKAGE = ".blackfox-artifacts/wave12/wave12-assurance-package.zip"
_DEFAULT_VERIFICATION = (
    ".blackfox-artifacts/wave12/wave12-assurance-package-verification.json"
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run Wave 12 assurance package commands."""

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
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Wave 12 assurance input error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"Unsupported assurance command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox assurance",
        description="Wave 12 certification-ready evidence packaging commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    build_parser = subparsers.add_parser(
        "build",
        help="Collect evidence and build a deterministic Wave 12 package.",
    )
    build_parser.add_argument("--root", default=".")
    build_parser.add_argument("--repository", default="IX-BlackFox")
    build_parser.add_argument("--revision", required=True)
    build_parser.add_argument(
        "--scope",
        default="IX-BlackFox governed AI-assisted software-change assurance evidence",
    )
    build_parser.add_argument(
        "--producer-agent-id",
        default="wave12-package-builder",
    )
    build_parser.add_argument("--generated-at", default=None)
    build_parser.add_argument("--evidence-spec", required=True)
    build_parser.add_argument("--review-file", default=None)
    build_parser.add_argument("--output", default=_DEFAULT_PACKAGE)
    build_parser.add_argument("--verification-output", default=_DEFAULT_VERIFICATION)
    build_parser.add_argument("--summary-output", default=None)
    build_parser.add_argument("--json", action="store_true")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Independently verify a serialized Wave 12 package.",
    )
    verify_parser.add_argument("--package", required=True)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--json", action="store_true")

    gate_parser = subparsers.add_parser(
        "gate",
        help="Gate a package on integrity and readiness status.",
    )
    gate_parser.add_argument("--package", required=True)
    gate_parser.add_argument(
        "--allow-review-required",
        action="store_true",
        help=(
            "Permit a verified review-required package. This is appropriate for "
            "offline CI evidence generation, not external-assessment approval."
        ),
    )
    gate_parser.add_argument("--json", action="store_true")
    return parser


def _run_build(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve(strict=True)
    generated_at = _parse_generated_at(args.generated_at)
    subject = AssuranceSubject(
        repository=args.repository,
        revision=args.revision,
        scope=args.scope,
        producer_agent_id=args.producer_agent_id,
        generated_at=generated_at,
        metadata={"cli": True},
    )
    profile = default_wave12_assurance_profile()
    specs = load_evidence_specs(_resolve_input(root, args.evidence_spec))
    evidence = collect_evidence(
        root,
        specs,
        expected_revision=subject.revision,
    )
    manifest = AssuranceManifest(
        manifest_id=f"wave12-{subject.digest[:20]}",
        subject=subject,
        profile=profile,
        evidence=tuple(item.artifact for item in evidence),
        claims=default_wave12_claims(),
        metadata={"cli": True, "evidence_spec_count": len(specs)},
    )
    reviews = (
        _load_reviews(_resolve_input(root, args.review_file))
        if args.review_file
        else ()
    )
    crosswalk = build_assurance_crosswalk(
        subject=subject,
        profile=profile,
        artifacts=manifest.evidence,
        metadata={"cli": True},
    )
    readiness = build_assurance_readiness_report(
        manifest=manifest,
        crosswalk=crosswalk,
        reviews=reviews,
        metadata={"cli": True},
    )
    output_path = _resolve_output(root, args.output)
    verification_output = _resolve_output(root, args.verification_output)
    build_result = build_assurance_package(
        output_path=output_path,
        manifest=manifest,
        crosswalk=crosswalk,
        readiness=readiness,
        evidence=evidence,
        reviews=reviews,
        metadata={"cli": True},
    )
    verification = verify_assurance_package(output_path, metadata={"cli": True})
    write_package_verification(verification, verification_output)
    summary = {
        "schema_version": "wave12.assurance_cli_summary.v1",
        "passed": verification.passed
        and readiness.status is not AssuranceReadinessStatus.BLOCKED,
        "readiness_status": readiness.status.value,
        "ready_for_external_assessment": readiness.ready_for_external_assessment,
        "mandatory_evidence_complete": crosswalk.mandatory_evidence_complete,
        "build": build_result.to_dict(),
        "verification": verification.to_dict(),
        "package": str(output_path),
        "verification_report": str(verification_output),
    }
    if args.summary_output:
        summary_path = _resolve_output(root, args.summary_output)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    if args.json:
        _print_json(summary)
    else:
        _print_build_summary(summary)
    return 0 if summary["passed"] else 1


def _run_verify(args: argparse.Namespace) -> int:
    package_path = Path(args.package).resolve(strict=True)
    verification = verify_assurance_package(package_path, metadata={"cli": True})
    if args.output:
        write_package_verification(verification, Path(args.output).resolve())
    if args.json:
        _print_json(verification.to_dict())
    else:
        print(f"Wave 12 package verification: {'passed' if verification.passed else 'failed'}")
        print(f"Archive SHA-256: {verification.archive_sha256}")
        print(f"Readiness status: {verification.readiness_status or 'unavailable'}")
        for issue in verification.issues:
            print(f"- {issue.code.value}: {issue.summary}")
    return 0 if verification.passed else 1


def _run_gate(args: argparse.Namespace) -> int:
    package_path = Path(args.package).resolve(strict=True)
    verification = verify_assurance_package(package_path, metadata={"cli": True})
    allowed = {AssuranceReadinessStatus.READY_FOR_EXTERNAL_ASSESSMENT.value}
    if args.allow_review_required:
        allowed.add(AssuranceReadinessStatus.REVIEW_REQUIRED.value)
    passed = verification.passed and verification.readiness_status in allowed
    payload = {
        "passed": passed,
        "verification_passed": verification.passed,
        "readiness_status": verification.readiness_status,
        "allowed_readiness_statuses": sorted(allowed),
        "archive_sha256": verification.archive_sha256,
        "scope_note": (
            "Allowing review_required proves the package gate remains open and "
            "human authority is still required."
        ),
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"Wave 12 assurance gate: {'passed' if passed else 'blocked'}")
        print(f"Readiness status: {verification.readiness_status or 'unavailable'}")
    return 0 if passed else 1


def _load_reviews(path: Path) -> tuple[AuthorityReview, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_reviews = payload.get("reviews") if isinstance(payload, dict) else payload
    if not isinstance(raw_reviews, list):
        raise ValueError("Review file must be a list or contain a reviews list.")
    reviews: list[AuthorityReview] = []
    for index, item in enumerate(raw_reviews):
        if not isinstance(item, dict):
            raise ValueError(f"Review at index {index} must be an object.")
        reviews.append(_review_from_mapping(item))
    return tuple(sorted(reviews, key=lambda review: review.review_id))


def _review_from_mapping(payload: Mapping[str, Any]) -> AuthorityReview:
    return AuthorityReview(
        review_id=_string_field(payload, "review_id"),
        reviewer_agent_id=_string_field(payload, "reviewer_agent_id"),
        reviewer_kind=AgentKind(_string_field(payload, "reviewer_kind")),
        decision=AuthorityReviewDecision(_string_field(payload, "decision")),
        subject_digest=_string_field(payload, "subject_digest"),
        profile_digest=_string_field(payload, "profile_digest"),
        reviewed_at=_string_field(payload, "reviewed_at"),
        authentication_state=ReviewAuthenticationState(
            _string_field(payload, "authentication_state")
        ),
        verification_artifact_ids=_string_tuple_field(
            payload.get("verification_artifact_ids", ()),
            "verification_artifact_ids",
        ),
        notes=str(payload.get("notes", "")),
        metadata=_mapping_field(payload.get("metadata", {}), "metadata"),
    )


def _resolve_input(root: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("Input path must remain inside the repository root.")
    return resolved


def _resolve_output(root: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError("Output path must remain inside the repository root.")
    return resolved_parent / candidate.name


def _parse_generated_at(value: str | None) -> str:
    if value is None:
        return datetime.now(tz=UTC).isoformat()
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--generated-at must include a timezone offset.")
    return parsed.isoformat()


def _string_field(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    return value


def _string_tuple_field(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or any(
        not isinstance(item, str) for item in value
    ):
        raise ValueError(f"{label} must be a list of strings.")
    return tuple(value)


def _mapping_field(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    return value


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _print_build_summary(payload: Mapping[str, Any]) -> None:
    print(f"Wave 12 assurance package: {'passed' if payload['passed'] else 'blocked'}")
    print(f"Readiness status: {payload['readiness_status']}")
    print(f"Mandatory evidence complete: {payload['mandatory_evidence_complete']}")
    print(f"Package: {payload['package']}")
    print(f"Verification report: {payload['verification_report']}")


if __name__ == "__main__":
    raise SystemExit(main())
