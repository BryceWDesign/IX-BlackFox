from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.authoring import (
    AuthoringMode,
    PatchAuthoringPromptContract,
    PatchAuthoringResponseSchema,
    PromptContractMessage,
    PromptMessageRole,
)
from ix_blackfox.brains import (
    BrainComparisonScore,
    BrainRole,
    BrainTribunalAssignment,
    BrainTribunalIdentity,
    BrainTribunalRole,
    BrainTribunalRoleKind,
)
from ix_blackfox.runtime.authoring_repair import StaticPatchProposalProvider
from ix_blackfox.runtime.brain_repair import (
    BrainRepairCandidateSource,
    BrainRepairSelectionReport,
    MultiBrainRepairProposalProvider,
)
from ix_blackfox.runtime.brain_repair_evidence import (
    BrainRepairEvidenceExport,
    BrainRepairEvidenceExporter,
    BrainRepairEvidenceLedger,
    BrainRepairEvidenceSnapshot,
)

_DEFAULT_OUTPUT = Path(".blackfox-artifacts/wave7/wave7-model-repair-ci-report.json")
_SELECTION_EVIDENCE_NAME = "wave7-model-repair-selection-evidence.json"


def build_wave7_selection_report() -> BrainRepairSelectionReport:
    """
    Build deterministic offline Wave 7 repair-selection evidence.

    This CI scenario uses static provider outputs so GitHub Actions can verify
    Wave 7 model-comparison, separated review, and evidence-export wiring
    without requiring network access, model credentials, or local model servers.
    """
    provider = MultiBrainRepairProposalProvider(
        sources=(
            _candidate_source(
                source_id="fast-local",
                raw_response=_proposal_json(
                    proposal_id="fast-local-proposal",
                    rationale="Fast local proposal with weaker evidence support.",
                ),
                score=BrainComparisonScore(
                    correctness_score=62,
                    evidence_score=58,
                    safety_score=80,
                    policy_score=82,
                    maintainability_score=68,
                    latency_score=95,
                    notes=("fast fallback proposal",),
                ),
            ),
            _candidate_source(
                source_id="reasoned-local",
                raw_response=_proposal_json(
                    proposal_id="reasoned-local-proposal",
                    rationale=(
                        "Reasoned local proposal with stronger evidence, safety, "
                        "policy, and maintainability support."
                    ),
                ),
                score=BrainComparisonScore(
                    correctness_score=92,
                    evidence_score=96,
                    safety_score=97,
                    policy_score=94,
                    maintainability_score=90,
                    latency_score=72,
                    notes=("highest evidence-backed repair candidate",),
                ),
            ),
        ),
        tribunal_assignments=(_critic_assignment(),),
        metadata={
            "ci_scenario": "wave7_model_agnostic_repair_selection",
            "claim": "offline_unit_evidence_not_production_certification",
        },
    )
    return provider.select(_contract())


def build_ci_payload(
    *,
    head_sha: str,
    selection_report: BrainRepairSelectionReport | None = None,
    export: BrainRepairEvidenceExport | None = None,
    ledger_snapshot: BrainRepairEvidenceSnapshot | None = None,
) -> dict[str, Any]:
    """
    Build the top-level Wave 7 CI payload.
    """
    normalized_head_sha = _normalize_head_sha(head_sha)
    report = selection_report or build_wave7_selection_report()
    passed = _report_passed(report) and (
        export is None or (export.chain_valid and export.receipt.blocked is False)
    )
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "wave": "7",
        "head_sha": normalized_head_sha,
        "passed": passed,
        "selected_source_id": report.to_dict()["selected_source_id"],
        "selected_brain_name": report.to_dict()["selected_brain_name"],
        "review_routed": report.review_routed,
        "blocked": report.blocked,
        "selection_report": report.to_dict(),
        "evidence_export": None if export is None else export.to_dict(),
        "ledger_snapshot": None if ledger_snapshot is None else ledger_snapshot.to_dict(),
        "scope_note": (
            "This CI payload verifies Wave 7 model-agnostic repair-selection "
            "contracts, deterministic model comparison, separated tribunal review, "
            "and chained evidence export. It is not a production certification, "
            "formal safety approval, or authorization for autonomous execution."
        ),
    }


def write_ci_payload(*, head_sha: str, output_path: Path) -> dict[str, Any]:
    """
    Write Wave 7 CI evidence and return the final payload.
    """
    normalized_head_sha = _normalize_head_sha(head_sha)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    selection_report = build_wave7_selection_report()
    ledger = BrainRepairEvidenceLedger()
    selection_evidence_path = output_path.with_name(_SELECTION_EVIDENCE_NAME)

    export = BrainRepairEvidenceExporter().export(
        path=selection_evidence_path,
        run_id=f"wave7-ci-{normalized_head_sha[:12]}",
        task_id="wave7-model-repair-ci",
        contract_id="wave7-ci-contract",
        report=selection_report,
        ledger=ledger,
        metadata={
            "head_sha": normalized_head_sha,
            "ci": True,
            "artifact": _SELECTION_EVIDENCE_NAME,
        },
    )

    payload = build_ci_payload(
        head_sha=normalized_head_sha,
        selection_report=selection_report,
        export=export,
        ledger_snapshot=ledger.snapshot(),
    )
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Wave 7 model-repair CI evidence for IX-BlackFox."
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="The commit SHA that the Wave 7 CI evidence is bound to.",
    )
    parser.add_argument(
        "--output",
        default=str(_DEFAULT_OUTPUT),
        help="Path to write the Wave 7 model-repair CI evidence JSON payload.",
    )
    args = parser.parse_args(argv)

    payload = write_ci_payload(
        head_sha=args.head_sha,
        output_path=Path(args.output),
    )
    print(f"Wave 7 model-repair CI evidence written to {args.output}")
    print(f"Passed: {payload['passed']}")
    return 0 if payload["passed"] else 1


def _candidate_source(
    *,
    source_id: str,
    raw_response: str,
    score: BrainComparisonScore,
) -> BrainRepairCandidateSource:
    return BrainRepairCandidateSource(
        source_id=source_id,
        provider=StaticPatchProposalProvider(
            responses=(raw_response,),
            provider_name="static-wave7-provider",
            model_name=f"{source_id}-model",
        ),
        brain_name=f"{source_id}-brain",
        provider_name="static-wave7-provider",
        model_name=f"{source_id}-model",
        role=BrainRole.PRIMARY,
        score=score,
        metadata={
            "ci": "true",
            "source_kind": "offline_static_model_output",
        },
    )


def _critic_assignment() -> BrainTribunalAssignment:
    return BrainTribunalAssignment(
        assignment_id="wave7-ci-critic-assignment",
        role=BrainTribunalRole(
            role_id="wave7-ci-critic-role",
            role_kind=BrainTribunalRoleKind.CRITIC,
            description="Deterministic separated critic for Wave 7 CI evidence.",
            may_review=True,
        ),
        identity=BrainTribunalIdentity(
            brain_name="wave7-ci-critic-brain",
            provider_name="static-wave7-review-provider",
            model_name="wave7-ci-critic-model",
            metadata={
                "ci": "true",
                "role": "separated_reviewer",
            },
        ),
    )


def _contract() -> PatchAuthoringPromptContract:
    return PatchAuthoringPromptContract(
        contract_id="wave7-ci-contract",
        request_id="wave7-model-repair-ci",
        objective_id="wave7-ci-objective",
        prompt_version="wave7-model-repair-ci-v1",
        mode=AuthoringMode.MODEL_ASSISTED,
        messages=(
            PromptContractMessage(
                role=PromptMessageRole.SYSTEM,
                content=(
                    "You are producing an untrusted IX-BlackFox patch proposal. "
                    "Return JSON only. Do not approve your own proposal."
                ),
                metadata={"purpose": "wave7_ci_rules"},
            ),
            PromptContractMessage(
                role=PromptMessageRole.USER,
                content=(
                    "Produce a deterministic offline proposal for Wave 7 CI "
                    "model-comparison evidence."
                ),
                metadata={"purpose": "wave7_ci_task"},
            ),
        ),
        response_schema=PatchAuthoringResponseSchema(),
        context_digest="0" * 64,
        evidence_digest="1" * 64,
        metadata={
            "wave": 7,
            "ci": True,
        },
    )


def _proposal_json(*, proposal_id: str, rationale: str) -> str:
    return json.dumps(
        {
            "schema_version": "wave7.ci_static_patch_proposal.v1",
            "proposal_id": proposal_id,
            "rationale": rationale,
            "mutations": [],
            "governance_note": (
                "Static CI proposal used only to exercise model comparison, "
                "tribunal review, and evidence export wiring."
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _report_passed(report: BrainRepairSelectionReport) -> bool:
    payload = report.to_dict()
    return (
        payload["selected_source_id"] == "reasoned-local"
        and payload["selected_brain_name"] == "reasoned-local-brain"
        and report.selected_raw_response is not None
        and report.review_routed
        and not report.blocked
        and report.tribunal_decision is not None
        and report.tribunal_decision.selected_brain_name == "wave7-ci-critic-brain"
    )


def _normalize_head_sha(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("head_sha must not be empty.")
    return cleaned


if __name__ == "__main__":
    sys.exit(main())
