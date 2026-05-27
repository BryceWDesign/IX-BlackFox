from __future__ import annotations

import json

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
from ix_blackfox.runtime import (
    BrainRepairCandidateSource,
    BrainRepairEvidenceEventType,
    BrainRepairEvidenceExporter,
    BrainRepairEvidenceLedger,
    MultiBrainRepairProposalProvider,
    StaticPatchProposalProvider,
)


def test_evidence_ledger_records_selected_wave7_report_chain() -> None:
    report = _selected_report()
    ledger = BrainRepairEvidenceLedger()

    receipt = ledger.record_selection_report(
        run_id="run-1",
        task_id="task-1",
        contract_id="contract-1",
        report=report,
        metadata={"operator": "test"},
    )

    assert receipt.event_type is BrainRepairEvidenceEventType.SELECTION_RECORDED
    assert receipt.selected_source_id == "reasoned-local"
    assert receipt.selected_brain_name == "reasoned-local-brain"
    assert receipt.selected_raw_response_digest is not None
    assert receipt.review_routed is True
    assert receipt.blocked is False
    assert receipt.comparison_result_count == 2
    assert receipt.record_count == 2
    assert receipt.metadata["operator"] == "test"
    assert receipt.metadata["tribunal_disposition"] == "routed"
    assert ledger.count() == 1
    assert ledger.verify_run_chain("run-1") is True

    snapshot = ledger.snapshot()
    assert snapshot.latest_for_run("run-1") == receipt
    assert snapshot.filter_by_task("task-1") == (receipt,)
    assert snapshot.filter_by_contract("contract-1") == (receipt,)
    assert snapshot.to_dict()["receipt_count"] == 1


def test_evidence_ledger_records_blocked_wave7_report() -> None:
    generator = _source(
        source_id="generator",
        raw_response='{"proposal_id":"blocked"}',
        provider_name="ollama",
        model_name="gpt-oss:20b",
        score=BrainComparisonScore(correctness_score=95, safety_score=95),
    )
    self_reviewer = BrainTribunalAssignment(
        assignment_id="self-reviewer",
        role=_critic_role(),
        identity=BrainTribunalIdentity(
            brain_name="generator-brain",
            provider_name="ollama",
            model_name="gpt-oss:20b",
        ),
    )
    report = MultiBrainRepairProposalProvider(
        sources=(generator,),
        tribunal_assignments=(self_reviewer,),
    ).select(_contract())
    ledger = BrainRepairEvidenceLedger()

    receipt = ledger.record_selection_report(
        run_id="run-blocked",
        task_id="task-blocked",
        contract_id="contract-1",
        report=report,
    )

    assert receipt.event_type is BrainRepairEvidenceEventType.SELECTION_BLOCKED
    assert receipt.selected_source_id is None
    assert receipt.selected_brain_name is None
    assert receipt.selected_raw_response_digest is None
    assert receipt.blocked is True
    assert receipt.review_routed is False
    assert receipt.metadata["tribunal_disposition"] == "blocked"
    assert ledger.verify_run_chain("run-blocked") is True


def test_evidence_ledger_chains_multiple_receipts_for_same_run() -> None:
    report = _selected_report()
    ledger = BrainRepairEvidenceLedger()

    first = ledger.record_selection_report(
        run_id="run-chain",
        task_id="task-1",
        contract_id="contract-1",
        report=report,
    )
    second = ledger.record_selection_report(
        run_id="run-chain",
        task_id="task-2",
        contract_id="contract-2",
        report=report,
    )

    assert second.previous_receipt_id == first.receipt_id
    assert second.previous_chain_digest == first.chain_digest
    assert ledger.verify_run_chain("run-chain") is True
    assert len(ledger.snapshot().filter_by_run("run-chain")) == 2


def test_evidence_exporter_writes_report_and_export_receipt(tmp_path) -> None:
    report = _selected_report()
    ledger = BrainRepairEvidenceLedger()
    output_path = tmp_path / "wave7" / "evidence.json"

    export = BrainRepairEvidenceExporter().export(
        path=output_path,
        run_id="run-export",
        task_id="task-export",
        contract_id="contract-1",
        report=report,
        ledger=ledger,
        metadata={"ci": True},
    )

    assert output_path.exists()
    assert export.path == output_path
    assert export.digest == export.receipt.metadata["export_digest"]
    assert export.receipt.event_type is BrainRepairEvidenceEventType.REPORT_EXPORTED
    assert export.receipt.metadata["selection_receipt_id"].startswith(
        "wave7-repair-evidence-"
    )
    assert export.chain_valid is True
    assert ledger.count() == 2
    assert ledger.verify_run_chain("run-export") is True

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "wave7.brain_repair_evidence.v1"
    assert payload["run_id"] == "run-export"
    assert payload["chain_valid"] is True
    assert payload["selection_report"]["selected_source_id"] == "reasoned-local"
    assert payload["receipt"]["event_type"] == "selection_recorded"
    assert payload["metadata"] == {"ci": True}


def test_evidence_receipt_serializes_operator_review_fields() -> None:
    receipt = BrainRepairEvidenceLedger().record_selection_report(
        run_id="run-json",
        task_id="task-json",
        contract_id="contract-1",
        report=_selected_report(),
    )

    payload = receipt.to_dict()

    assert payload["event_type"] == "selection_recorded"
    assert payload["selected_source_id"] == "reasoned-local"
    assert payload["selected_brain_name"] == "reasoned-local-brain"
    assert payload["blocked"] is False
    assert payload["review_routed"] is True
    assert payload["metadata"]["selection_report_digest"]


def _selected_report():
    return MultiBrainRepairProposalProvider(
        sources=(
            _source(
                source_id="fast-local",
                raw_response='{"proposal_id":"fast"}',
                score=BrainComparisonScore(correctness_score=60, safety_score=80),
            ),
            _source(
                source_id="reasoned-local",
                raw_response='{"proposal_id":"reasoned"}',
                score=BrainComparisonScore(correctness_score=95, safety_score=95),
            ),
        ),
        tribunal_assignments=(_critic_assignment(),),
    ).select(_contract())


def _source(
    *,
    source_id: str,
    raw_response: str,
    provider_name: str = "ollama",
    model_name: str | None = None,
    score: BrainComparisonScore,
) -> BrainRepairCandidateSource:
    return BrainRepairCandidateSource(
        source_id=source_id,
        provider=StaticPatchProposalProvider(
            responses=(raw_response,),
            provider_name=provider_name,
            model_name=model_name or f"{source_id}-model",
        ),
        brain_name=f"{source_id}-brain",
        provider_name=provider_name,
        model_name=model_name or f"{source_id}-model",
        role=BrainRole.PRIMARY,
        score=score,
    )


def _critic_assignment() -> BrainTribunalAssignment:
    return BrainTribunalAssignment(
        assignment_id="critic-assignment",
        role=_critic_role(),
        identity=BrainTribunalIdentity(
            brain_name="critic-brain",
            provider_name="vllm",
            model_name="critic-model",
        ),
    )


def _critic_role() -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id="critic-role",
        role_kind=BrainTribunalRoleKind.CRITIC,
        description="Reviews generated repair candidates.",
        may_review=True,
    )


def _contract() -> PatchAuthoringPromptContract:
    return PatchAuthoringPromptContract(
        contract_id="contract-1",
        request_id="request-1",
        objective_id="objective-1",
        prompt_version="wave3-patch-authoring-v1",
        mode=AuthoringMode.MODEL_ASSISTED,
        messages=(
            PromptContractMessage(
                role=PromptMessageRole.SYSTEM,
                content="System rules.",
            ),
            PromptContractMessage(
                role=PromptMessageRole.USER,
                content="User repair request.",
            ),
        ),
        response_schema=PatchAuthoringResponseSchema(),
        context_digest="0" * 64,
        evidence_digest="1" * 64,
    )
