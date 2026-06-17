from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.agents import (
    AgentAction,
    AgentAuthorizationEvaluator,
    AgentAuthorizationRequest,
    AgentAuthorizationStatus,
    AgentAuthorizationTarget,
    AgentCapability,
    AgentCapabilityGrant,
    AgentCapabilityScope,
    AgentIdentity,
    AgentKind,
    AgentProvenanceLedger,
    AgentReadinessReport,
    AgentReadinessStatus,
    AgentRegistry,
    AgentTrustTier,
    CapabilityRiskTier,
    build_agent_readiness_report,
    evaluate_human_authority,
)
from ix_blackfox.operating import OperatingDomain

_DEFAULT_OUTPUT = Path(".blackfox-artifacts/wave11/wave11-agent-readiness-report.json")
_DEFAULT_ENGINE_EVIDENCE_OUTPUT = Path(
    ".blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json"
)
_DEFAULT_SUMMARY_OUTPUT = Path(
    ".blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json"
)
_DEFAULT_EXPECTED_STATUS = AgentReadinessStatus.WARNING


def build_wave11_agent_identity_ci_report(
    *,
    head_sha: str,
    generated_at: datetime | None = None,
    run_id: str | None = None,
) -> AgentReadinessReport:
    """Build deterministic offline Wave 11 agent-identity evidence.

    The default CI scenario intentionally records one allowed model proposal and
    one review-required CI process request. That produces a WARNING readiness
    report, not a failure: the warning proves the review gate exists while the
    matching human-authority evaluation and provenance ledger prove the decision
    remained evidence-bound and human-authority preserving.
    """

    normalized_head_sha = _normalize_head_sha(head_sha)
    normalized_generated_at = generated_at or datetime.now(tz=UTC)
    normalized_run_id = run_id or f"wave11-ci-{normalized_head_sha[:12]}"

    registry = _build_ci_registry()
    evaluator = AgentAuthorizationEvaluator(
        registry=registry,
        default_reviewer_agent_id="release-owner",
    )

    model_request = _authorization_request(
        request_id="wave11-model-propose",
        agent_id="model-proposer",
        action=AgentAction.PROPOSE,
        capability=AgentCapability.PROPOSE_PATCH,
        risk_tier=CapabilityRiskTier.LOW,
        evidence_artifact_ids=("wave11:model-proposal-evidence",),
    )
    ci_request = _authorization_request(
        request_id="wave11-ci-run-process",
        agent_id="ci-runner",
        action=AgentAction.RUN,
        capability=AgentCapability.RUN_PROCESS,
        risk_tier=CapabilityRiskTier.HIGH,
        evidence_artifact_ids=("wave11:ci-runner-evidence",),
    )

    model_decision = evaluator.evaluate(
        model_request,
        decided_at=normalized_generated_at.isoformat(),
    )
    ci_decision = evaluator.evaluate(
        ci_request,
        decided_at=normalized_generated_at.isoformat(),
        reviewer_agent_id="release-owner",
        evidence_artifact_ids=("wave11:human-review-ticket",),
    )
    authority = evaluate_human_authority(
        registry=registry,
        request=ci_request,
        decision=ci_decision,
    )
    ledger = (
        AgentProvenanceLedger(
            ledger_id="wave-11-agent-identity-ci-ledger",
            metadata={
                "ci": True,
                "script": "scripts/run_wave11_agent_identity_ci.py",
                "head_sha": normalized_head_sha,
                "run_id": normalized_run_id,
            },
        )
        .append(
            model_decision,
            recorded_at=normalized_generated_at.isoformat(),
            evidence_artifact_ids=("wave11:model-decision-provenance",),
        )
        .append(
            ci_decision,
            recorded_at=normalized_generated_at.isoformat(),
            evidence_artifact_ids=("wave11:ci-decision-provenance",),
        )
    )

    return build_agent_readiness_report(
        registry=registry,
        report_id="wave-11-agent-identity-ci-report",
        authorization_decisions=(model_decision, ci_decision),
        authority_evaluations=(authority,),
        provenance_ledger=ledger,
        generated_at=normalized_generated_at.isoformat(),
        metadata={
            "ci": True,
            "wave": "11",
            "head_sha": normalized_head_sha,
            "run_id": normalized_run_id,
            "script": "scripts/run_wave11_agent_identity_ci.py",
            "claim": (
                "offline_wave11_agent_identity_capability_registry_check_not_"
                "production_authorization_or_autonomous_agent_approval"
            ),
        },
    )


def build_engine_evidence_payload(
    *,
    head_sha: str,
    report: AgentReadinessReport,
    generated_at: datetime,
    run_id: str,
) -> dict[str, Any]:
    """Build a compact evidence payload for CI artifact inspection."""

    return {
        "schema_version": "wave11.agent_identity_engine_evidence.v1",
        "generated_at": generated_at.isoformat(),
        "wave": "11",
        "head_sha": _normalize_head_sha(head_sha),
        "run_id": run_id,
        "report_id": report.report_id,
        "report_digest": report.digest,
        "registry_id": report.registry_snapshot.registry_id,
        "registry_snapshot_digest": report.registry_snapshot.digest,
        "status": report.status.value,
        "ready": report.ready,
        "authorization_decision_count": len(report.authorization_decisions),
        "authority_evaluation_count": len(report.authority_evaluations),
        "provenance_record_count": (
            report.provenance_ledger.record_count
            if report.provenance_ledger is not None
            else 0
        ),
        "human_authority_preserved": all(
            evaluation.authority_preserved for evaluation in report.authority_evaluations
        ),
        "scope_note": (
            "This evidence validates the offline Wave 11 agent identity, scoped "
            "capability, authorization, human-authority, and provenance chain. "
            "It is not production authorization, model safety certification, "
            "government approval, procurement approval, or autonomous agent authority."
        ),
    }


def build_ci_summary_payload(
    *,
    head_sha: str,
    report_payload: dict[str, Any],
    report_output_path: Path,
    engine_evidence_output_path: Path,
    expected_status: AgentReadinessStatus,
) -> dict[str, Any]:
    """Build the top-level Wave 11 CI summary payload."""

    status = str(report_payload.get("status", ""))
    validation = validate_report_payload(report_payload)
    passed = validation["passed"] is True and status == expected_status.value
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "wave": "11",
        "head_sha": _normalize_head_sha(head_sha),
        "passed": passed,
        "expected_status": expected_status.value,
        "status": status,
        "ready": report_payload.get("ready"),
        "run_id": report_payload.get("metadata", {}).get("run_id"),
        "report_digest": report_payload.get("digest"),
        "registry_snapshot_digest": report_payload.get("registry_snapshot_digest"),
        "provenance_head_digest": report_payload.get("provenance_head_digest"),
        "report_validation": validation,
        "summary": {
            "report_path": str(report_output_path),
            "engine_evidence_path": str(engine_evidence_output_path),
            "active_agent_count": report_payload.get("active_agent_count"),
            "authorization_decision_count": report_payload.get(
                "authorization_decision_count"
            ),
            "authority_evaluation_count": report_payload.get(
                "authority_evaluation_count"
            ),
            "provenance_record_count": report_payload.get("provenance_record_count"),
            "blocking_finding_count": report_payload.get("blocking_finding_count"),
            "warning_finding_count": report_payload.get("warning_finding_count"),
        },
        "scope_note": (
            "This CI payload verifies the Wave 11 agent identity and capability "
            "registry, authorization evaluator, human-authority boundary, provenance "
            "ledger, readiness report, and deterministic JSON artifact export. It is "
            "not production deployment approval, model safety certification, ATO/cATO, "
            "DoD endorsement, procurement approval, or permission for autonomous execution."
        ),
    }


def validate_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the exported report shape used by CI."""

    required = {
        "report_id",
        "status",
        "ready",
        "generated_at",
        "registry_snapshot_digest",
        "registry_id",
        "active_agent_count",
        "authorization_decision_count",
        "authority_evaluation_count",
        "provenance_record_count",
        "provenance_head_digest",
        "blocking_finding_count",
        "warning_finding_count",
        "findings",
        "authorization_decisions",
        "authority_evaluations",
        "digest",
    }
    missing = tuple(sorted(required.difference(payload)))
    passed = not missing and bool(payload.get("digest")) and bool(
        payload.get("registry_snapshot_digest")
    )
    return {
        "passed": passed,
        "missing_keys": list(missing),
        "has_digest": bool(payload.get("digest")),
        "has_registry_snapshot_digest": bool(payload.get("registry_snapshot_digest")),
        "has_provenance_head_digest": bool(payload.get("provenance_head_digest")),
    }


def write_ci_payload(
    *,
    root: Path,
    head_sha: str,
    output_path: Path,
    engine_evidence_output_path: Path | None = None,
    summary_output_path: Path | None = None,
    generated_at: datetime | None = None,
    run_id: str | None = None,
    expected_status: AgentReadinessStatus = _DEFAULT_EXPECTED_STATUS,
) -> dict[str, Any]:
    """Write Wave 11 readiness report, engine evidence, and CI summary artifacts."""

    resolved_root = root.resolve()
    report_output = _resolve_output_path(resolved_root, output_path)
    engine_evidence_output = _resolve_output_path(
        resolved_root,
        engine_evidence_output_path or _DEFAULT_ENGINE_EVIDENCE_OUTPUT,
    )
    summary_output = _resolve_output_path(
        resolved_root,
        summary_output_path or _DEFAULT_SUMMARY_OUTPUT,
    )
    normalized_generated_at = generated_at or datetime.now(tz=UTC)
    normalized_head_sha = _normalize_head_sha(head_sha)
    normalized_run_id = run_id or f"wave11-ci-{normalized_head_sha[:12]}"

    report = build_wave11_agent_identity_ci_report(
        head_sha=normalized_head_sha,
        generated_at=normalized_generated_at,
        run_id=normalized_run_id,
    )
    report_payload = report.to_dict()
    engine_evidence = build_engine_evidence_payload(
        head_sha=normalized_head_sha,
        report=report,
        generated_at=normalized_generated_at,
        run_id=normalized_run_id,
    )
    summary = build_ci_summary_payload(
        head_sha=normalized_head_sha,
        report_payload=report_payload,
        report_output_path=report_output,
        engine_evidence_output_path=engine_evidence_output,
        expected_status=expected_status,
    )

    _write_json(report_output, report_payload)
    _write_json(engine_evidence_output, engine_evidence)
    _write_json(summary_output, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the offline Wave 11 agent identity CI diagnostic."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument(
        "--engine-evidence-output",
        type=Path,
        default=_DEFAULT_ENGINE_EVIDENCE_OUTPUT,
    )
    parser.add_argument("--summary-output", type=Path, default=_DEFAULT_SUMMARY_OUTPUT)
    parser.add_argument(
        "--expected-status",
        choices=tuple(status.value for status in AgentReadinessStatus),
        default=_DEFAULT_EXPECTED_STATUS.value,
    )
    args = parser.parse_args(argv)

    generated_at = (
        _parse_generated_at(args.generated_at) if args.generated_at else None
    )
    expected_status = AgentReadinessStatus(args.expected_status)
    summary = write_ci_payload(
        root=args.root,
        head_sha=args.head_sha,
        output_path=args.output,
        engine_evidence_output_path=args.engine_evidence_output,
        summary_output_path=args.summary_output,
        generated_at=generated_at,
        run_id=args.run_id or None,
        expected_status=expected_status,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] is True else 1


def _build_ci_registry() -> AgentRegistry:
    model = AgentIdentity(
        agent_id="model-proposer",
        display_name="Model Proposer",
        kind=AgentKind.MODEL_BRAIN,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                agent_id="model-proposer",
                capability=AgentCapability.PROPOSE_PATCH,
                risk_tier=CapabilityRiskTier.LOW,
                requires_human_review=False,
            ),
        ),
    )
    ci_runner = AgentIdentity(
        agent_id="ci-runner",
        display_name="CI Runner",
        kind=AgentKind.CI_RUNNER,
        trust_tier=AgentTrustTier.GOVERNED_AUTOMATION,
        capability_grants=(
            _grant(
                agent_id="ci-runner",
                capability=AgentCapability.RUN_PROCESS,
                risk_tier=CapabilityRiskTier.HIGH,
                requires_human_review=True,
            ),
        ),
    )
    human = AgentIdentity(
        agent_id="release-owner",
        display_name="Release Owner",
        kind=AgentKind.HUMAN_OPERATOR,
        trust_tier=AgentTrustTier.HUMAN_AUTHORITY,
        capability_grants=(
            _grant(
                agent_id="release-owner",
                capability=AgentCapability.APPROVE_RELEASE,
                risk_tier=CapabilityRiskTier.CRITICAL,
                requires_human_review=False,
            ),
        ),
    )
    return AgentRegistry(
        registry_id="wave-11-agent-identity-ci-registry",
        agents=(model, ci_runner, human),
        metadata={
            "ci": True,
            "script": "scripts/run_wave11_agent_identity_ci.py",
        },
    )


def _grant(
    *,
    agent_id: str,
    capability: AgentCapability,
    risk_tier: CapabilityRiskTier,
    requires_human_review: bool,
) -> AgentCapabilityGrant:
    return AgentCapabilityGrant(
        grant_id=f"{agent_id}-{capability.value}",
        capability=capability,
        scope=AgentCapabilityScope(
            repository_ids=("ix-blackfox",),
            domains=(OperatingDomain.POLICY_GOVERNED,),
            path_roots=("src/ix_blackfox",),
            max_risk_tier=risk_tier,
            requires_human_review=requires_human_review,
            evidence_artifact_ids=("wave11:agent-identity-ci-registry",),
        ),
        rationale="Wave 11 CI diagnostic scoped capability grant.",
    )


def _authorization_request(
    *,
    request_id: str,
    agent_id: str,
    action: AgentAction,
    capability: AgentCapability,
    risk_tier: CapabilityRiskTier,
    evidence_artifact_ids: tuple[str, ...],
) -> AgentAuthorizationRequest:
    return AgentAuthorizationRequest(
        request_id=request_id,
        agent_id=agent_id,
        action=action,
        capability=capability,
        target=AgentAuthorizationTarget(
            repository_id="ix-blackfox",
            domain=OperatingDomain.POLICY_GOVERNED,
            path="src/ix_blackfox",
            risk_tier=risk_tier,
        ),
        requested_at="2026-06-15T12:00:00+00:00",
        evidence_artifact_ids=evidence_artifact_ids,
        justification="Wave 11 CI diagnostic authorization request.",
    )


def _normalize_head_sha(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("head_sha is required")
    return normalized


def _parse_generated_at(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _resolve_output_path(root: Path, path: Path) -> Path:
    resolved = path if path.is_absolute() else root / path
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"output path must remain under root: {path}") from exc
    return resolved


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
