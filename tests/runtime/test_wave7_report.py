from __future__ import annotations

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
    BrainRepairEvidenceExporter,
    BrainRepairEvidenceLedger,
    MultiBrainRepairProposalProvider,
    StaticPatchProposalProvider,
    VerificationSummaryStatus,
    Wave7ModelRepairReportRenderer,
)


def test_wave7_report_renderer_creates_operator_and_verification_summaries(
    tmp_path,
) -> None:
    report = _selected_report()
    ledger = BrainRepairEvidenceLedger()
    export = BrainRepairEvidenceExporter().export(
        path=tmp_path / "wave7-selection.json",
        run_id="run-1",
        task_id="task-1",
        contract_id="contract-1",
        report=report,
        ledger=ledger,
    )

    bundle = Wave7ModelRepairReportRenderer().render(
        run_id="run-1",
        task_id="task-1",
        contract_id="contract-1",
        selection_report=report,
        evidence_export=export,
        ledger_snapshot=ledger.snapshot(),
    )

    assert bundle.operator_summary.status == "wave7-review-ready"
    assert bundle.operator_summary.error_count == 0
    assert bundle.operator_summary.warning_count == 0
    assert "Wave 7 Model Selection Outcome" in bundle.operator_summary.section_titles
    assert "Human Review Boundaries" in bundle.operator_summary.section_titles
    assert "Human authority is still required" in bundle.operator_summary.executive_summary
    assert bundle.verification_summary.status is VerificationSummaryStatus.PARTIAL
    assert bundle.verification_summary.evidence_count == 4
    assert bundle.verification_summary.error_count == 0
    assert bundle.verification_summary.warning_count == 0
    assert bundle.selection_report_digest in bundle.operator_summary.to_markdown()

    payload = bundle.to_dict()
    assert payload["selection_report_digest"] == bundle.selection_report_digest
    assert payload["operator_summary"]["status"] == "wave7-review-ready"
    assert payload["verification_summary"]["status"] == "partial"


def test_wave7_report_renderer_marks_blocked_selection_as_blocked() -> None:
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

    bundle = Wave7ModelRepairReportRenderer().render(
        run_id="blocked-run",
        task_id="task-1",
        contract_id="contract-1",
        selection_report=report,
    )

    assert bundle.operator_summary.status == "wave7-blocked"
    assert bundle.operator_summary.error_count == 2
    assert bundle.operator_summary.warning_count == 1
    assert bundle.verification_summary.status is VerificationSummaryStatus.BLOCKED
    assert bundle.verification_summary.error_count == 2
    assert bundle.verification_summary.warning_count == 1
    assert "selection was blocked" in bundle.operator_summary.executive_summary


def test_wave7_report_renderer_includes_export_chain_error() -> None:
    report = _selected_report()
    ledger = BrainRepairEvidenceLedger()
    export = BrainRepairEvidenceExporter().export(
        path="/tmp/wave7-selection-for-report-test.json",
        run_id="run-chain",
        task_id="task-1",
        contract_id="contract-1",
        report=report,
        ledger=ledger,
    )
    broken_export = type(export)(
        path=export.path,
        digest=export.digest,
        receipt=export.receipt,
        chain_valid=False,
    )

    bundle = Wave7ModelRepairReportRenderer().render(
        run_id="run-chain",
        task_id="task-1",
        contract_id="contract-1",
        selection_report=report,
        evidence_export=broken_export,
        ledger_snapshot=ledger.snapshot(),
    )

    assert bundle.operator_summary.status == "wave7-evidence-error"
    assert bundle.operator_summary.error_count == 1
    assert bundle.verification_summary.status is VerificationSummaryStatus.FAILED
    assert bundle.verification_summary.error_count == 1


def test_wave7_report_renderer_exports_lazy_runtime_imports() -> None:
    from ix_blackfox.runtime import (  # noqa: PLC0415
        Wave7ModelRepairOperatorReportRenderer,
        Wave7ModelRepairReportBundle,
    )

    assert Wave7ModelRepairOperatorReportRenderer is Wave7ModelRepairReportRenderer
    assert Wave7ModelRepairReportBundle.__name__ == "Wave7ModelRepairReportBundle"


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
