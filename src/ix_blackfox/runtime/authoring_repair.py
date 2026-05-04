from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Protocol

from ix_blackfox.authoring import (
    AuthoringContextBuilder,
    AuthoringContextBuilderConfig,
    AuthoringContextSnapshot,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringMode,
    AuthoringPolicyGate,
    AuthoringPolicyReport,
    AuthoringReceiptLedger,
    AuthoringReceiptSnapshot,
    AuthoringRequest,
    CompiledPatchCandidate,
    FailureEvidenceExtractor,
    FailureEvidenceExtractorConfig,
    FailureEvidenceReport,
    PatchAuthoringPromptContract,
    PatchAuthoringPromptRenderer,
    PatchAuthoringPromptRendererConfig,
    PatchAuthoringProposal,
    PatchAuthoringResponseParser,
    PatchAuthoringResponseParserConfig,
    PatchProposalCompiler,
    PatchProposalCompilerConfig,
    RankedRepairCandidate,
    RepairCandidateRanker,
    RepairCandidateRankerConfig,
    RepairCandidateSelectionReport,
    RepairDecompositionPlan,
    RepairHypothesisEngine,
    RepairHypothesisEngineConfig,
    RepairHypothesisReport,
    RepairTaskDecomposer,
    RepairTaskDecomposerConfig,
)
from ix_blackfox.authoring.errors import AuthoringError
from ix_blackfox.tools.manifest import ToolPathPolicy
from ix_blackfox.tools.patch import PatchDiff


class AuthoredRepairStatus(StrEnum):
    """
    Top-level status for a Wave 3 authored repair run.

    This status describes the authoring path only. A selected patch candidate
    still has to go through the existing Wave 2 patch-test-verify-bundle runtime.
    """

    AUTHORED = auto()
    NO_CANDIDATE = auto()
    REQUIRES_REVIEW = auto()
    BLOCKED = auto()
    FAILED = auto()


class PatchProposalProvider(Protocol):
    """
    Provider interface for model-assisted or deterministic Wave 3 proposal output.

    Providers return raw JSON strings matching the Wave 3 patch-authoring
    response schema. The runtime treats every returned string as untrusted.
    """

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        """
        Return one or more raw proposal responses for a rendered prompt contract.
        """


@dataclass(frozen=True, slots=True)
class StaticPatchProposalProvider:
    """
    Test and replay provider for already-known raw proposal responses.

    This provider is useful for deterministic tests, offline replay, and manual
    model-output import. It does not call a remote model or execute commands.
    """

    responses: tuple[str, ...]
    provider_name: str = "static-proposal-provider"
    model_name: str = "static-replay"

    def __post_init__(self) -> None:
        responses = tuple(response.strip() for response in self.responses)
        if not responses:
            raise ValueError(
                "StaticPatchProposalProvider requires at least one response."
            )
        if any(not response for response in responses):
            raise ValueError("StaticPatchProposalProvider responses must not be empty.")

        object.__setattr__(self, "responses", responses)
        object.__setattr__(
            self,
            "provider_name",
            _normalize_token(self.provider_name, label="provider_name"),
        )
        object.__setattr__(
            self,
            "model_name",
            _normalize_token(self.model_name, label="model_name"),
        )

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        return self.responses


@dataclass(frozen=True, slots=True)
class NullPatchProposalProvider:
    """
    Provider that intentionally produces no patch proposals.

    This makes no-candidate behavior testable and explicit.
    """

    provider_name: str = "null-proposal-provider"
    model_name: str = "none"

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        return ()


@dataclass(frozen=True, slots=True)
class AuthoredRepairRuntimeConfig:
    """
    Configuration for the Wave 3 authored repair runtime.
    """

    workspace_root: Path
    include_paths: tuple[str, ...] = (".",)
    mode: AuthoringMode = AuthoringMode.MODEL_ASSISTED
    require_selected_candidate: bool = True
    max_raw_proposals: int = 4
    context_config: AuthoringContextBuilderConfig = field(
        default_factory=AuthoringContextBuilderConfig
    )
    evidence_config: FailureEvidenceExtractorConfig = field(
        default_factory=FailureEvidenceExtractorConfig
    )
    decomposer_config: RepairTaskDecomposerConfig = field(
        default_factory=RepairTaskDecomposerConfig
    )
    hypothesis_config: RepairHypothesisEngineConfig = field(
        default_factory=RepairHypothesisEngineConfig
    )
    prompt_config: PatchAuthoringPromptRendererConfig = field(
        default_factory=PatchAuthoringPromptRendererConfig
    )
    response_parser_config: PatchAuthoringResponseParserConfig = field(
        default_factory=PatchAuthoringResponseParserConfig
    )
    compiler_config: PatchProposalCompilerConfig = field(
        default_factory=PatchProposalCompilerConfig
    )
    ranker_config: RepairCandidateRankerConfig = field(
        default_factory=RepairCandidateRankerConfig
    )
    path_policy: ToolPathPolicy | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "workspace_root",
            self.workspace_root.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "include_paths",
            _normalize_path_tuple(self.include_paths, field_name="include_paths"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.max_raw_proposals <= 0:
            raise ValueError("max_raw_proposals must be positive.")


@dataclass(frozen=True, slots=True)
class AuthoredRepairRunReport:
    """
    Complete Wave 3 authored repair runtime report.

    The selected patch, when present, is a candidate for Wave 2. It is not proof
    of repair and it is not execution evidence.
    """

    task_id: str
    run_id: str
    objective: str
    status: AuthoredRepairStatus
    request: AuthoringRequest
    context_snapshot: AuthoringContextSnapshot | None = None
    evidence_reports: tuple[FailureEvidenceReport, ...] = field(default_factory=tuple)
    decomposition: RepairDecompositionPlan | None = None
    hypotheses: RepairHypothesisReport | None = None
    prompt_contract: PatchAuthoringPromptContract | None = None
    proposals: tuple[PatchAuthoringProposal, ...] = field(default_factory=tuple)
    compiled_candidates: tuple[CompiledPatchCandidate, ...] = field(
        default_factory=tuple
    )
    policy_reports: tuple[AuthoringPolicyReport, ...] = field(default_factory=tuple)
    selection_report: RepairCandidateSelectionReport | None = None
    receipt_snapshot: AuthoringReceiptSnapshot = field(
        default_factory=AuthoringReceiptSnapshot
    )
    errors: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        object.__setattr__(
            self, "run_id", _normalize_identifier(self.run_id, label="run_id")
        )
        object.__setattr__(
            self, "objective", _normalize_text(self.objective, label="objective")
        )
        object.__setattr__(self, "evidence_reports", tuple(self.evidence_reports))
        object.__setattr__(self, "proposals", tuple(self.proposals))
        object.__setattr__(self, "compiled_candidates", tuple(self.compiled_candidates))
        object.__setattr__(self, "policy_reports", tuple(self.policy_reports))
        object.__setattr__(
            self,
            "errors",
            tuple(_normalize_text(error, label="error") for error in self.errors),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def selected_ranked_candidate(self) -> RankedRepairCandidate | None:
        if self.selection_report is None:
            return None
        return self.selection_report.selected_candidate

    @property
    def selected_candidate(self) -> CompiledPatchCandidate | None:
        ranked = self.selected_ranked_candidate
        if ranked is None:
            return None
        return ranked.candidate

    @property
    def selected_patch(self) -> PatchDiff | None:
        candidate = self.selected_candidate
        if candidate is None:
            return None
        return candidate.patch_diff

    @property
    def selected_patch_candidates(self) -> tuple[PatchDiff, ...]:
        patch = self.selected_patch
        if patch is None:
            return ()
        return (patch,)

    @property
    def requires_review(self) -> bool:
        if self.status is AuthoredRepairStatus.REQUIRES_REVIEW:
            return True
        if self.selection_report is None:
            return False
        return bool(self.selection_report.review_required_candidates)

    @property
    def blocked(self) -> bool:
        return self.status is AuthoredRepairStatus.BLOCKED

    @property
    def succeeded(self) -> bool:
        return (
            self.status is AuthoredRepairStatus.AUTHORED
            and self.selected_patch is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "run_id": self.run_id,
            "objective": self.objective,
            "status": self.status.value,
            "succeeded": self.succeeded,
            "blocked": self.blocked,
            "requires_review": self.requires_review,
            "selected_candidate_id": None
            if self.selected_candidate is None
            else self.selected_candidate.candidate_id,
            "selected_patch_id": None
            if self.selected_patch is None
            else self.selected_patch.patch_id,
            "request": self.request.to_dict(),
            "context_snapshot": None
            if self.context_snapshot is None
            else self.context_snapshot.to_manifest_dict(),
            "evidence_reports": [report.to_dict() for report in self.evidence_reports],
            "decomposition": None
            if self.decomposition is None
            else self.decomposition.to_dict(),
            "hypotheses": None
            if self.hypotheses is None
            else self.hypotheses.to_dict(),
            "prompt_contract": None
            if self.prompt_contract is None
            else self.prompt_contract.to_dict(),
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "compiled_candidates": [
                candidate.to_dict() for candidate in self.compiled_candidates
            ],
            "policy_reports": [report.to_dict() for report in self.policy_reports],
            "selection_report": None
            if self.selection_report is None
            else self.selection_report.to_dict(),
            "receipt_snapshot": self.receipt_snapshot.to_dict(),
            "errors": list(self.errors),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class AuthoredRepairRuntime:
    """
    Wave 3 governed patch-authoring runtime.

    This runtime creates patch candidates. It does not apply them and it does not
    run tests. The existing Wave 2 engineering control plane remains responsible
    for patch-test-verify-bundle execution.
    """

    config: AuthoredRepairRuntimeConfig
    provider: PatchProposalProvider = field(default_factory=NullPatchProposalProvider)
    receipt_ledger: AuthoringReceiptLedger = field(
        default_factory=AuthoringReceiptLedger
    )

    def run(
        self,
        *,
        task_id: str,
        run_id: str,
        objective: str,
        raw_test_output: str | None = None,
        test_command: tuple[str, ...] = ("python", "-m", "pytest", "-q"),
        test_return_code: int = 1,
        test_timed_out: bool = False,
        evidence: Iterable[AuthoringEvidence] = (),
        raw_proposal_responses: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoredRepairRunReport:
        request = AuthoringRequest.create(
            task_id=task_id,
            objective=objective,
            mode=self.config.mode,
            requested_by="runtime.authoring_repair",
            metadata={
                "run_id": run_id,
                "runtime": "AuthoredRepairRuntime",
                **dict(metadata or {}),
            },
        )

        errors: list[str] = []
        context_snapshot: AuthoringContextSnapshot | None = None
        evidence_reports: list[FailureEvidenceReport] = []
        decomposition: RepairDecompositionPlan | None = None
        hypotheses: RepairHypothesisReport | None = None
        prompt_contract: PatchAuthoringPromptContract | None = None
        proposals: list[PatchAuthoringProposal] = []
        compiled_candidates: list[CompiledPatchCandidate] = []
        policy_reports: list[AuthoringPolicyReport] = []
        selection_report: RepairCandidateSelectionReport | None = None

        try:
            context_snapshot = self._collect_context(request=request)
            request = AuthoringRequest(
                request_id=request.request_id,
                objective=request.objective,
                mode=request.mode,
                status=request.status,
                context=context_snapshot.context,
                evidence=request.evidence,
                subtasks=request.subtasks,
                findings=request.findings,
                metadata=request.metadata,
            )

            evidence_reports = self._collect_evidence_reports(
                request=request,
                raw_test_output=raw_test_output,
                test_command=test_command,
                test_return_code=test_return_code,
                test_timed_out=test_timed_out,
                evidence=tuple(evidence),
            )
            request = self._attach_evidence(
                request=request,
                evidence_reports=tuple(evidence_reports),
                extra_evidence=tuple(evidence),
            )

            decomposition = self._decompose(request)
            request = decomposition.apply_to_request(request)

            hypotheses = self._generate_hypotheses(
                request=request,
                decomposition=decomposition,
            )

            prompt_contract = self._render_prompt(
                request=request,
                context_snapshot=context_snapshot,
                decomposition=decomposition,
                hypotheses=hypotheses,
            )

            raw_responses = self._proposal_responses(
                prompt_contract=prompt_contract,
                raw_proposal_responses=tuple(raw_proposal_responses),
            )

            if not raw_responses:
                self.receipt_ledger.record_authoring_failed(
                    request_id=request.request_id,
                    failure_phase="proposal_provider",
                    failure_reason="No raw proposal responses were produced.",
                )
                return self._report(
                    task_id=task_id,
                    run_id=run_id,
                    objective=objective,
                    status=AuthoredRepairStatus.NO_CANDIDATE,
                    request=request,
                    context_snapshot=context_snapshot,
                    evidence_reports=evidence_reports,
                    decomposition=decomposition,
                    hypotheses=hypotheses,
                    prompt_contract=prompt_contract,
                    errors=("No raw proposal responses were produced.",),
                    metadata=metadata,
                )

            proposals = self._parse_proposals(
                request=request,
                raw_responses=raw_responses,
            )

            compiled_candidates = self._compile_proposals(
                request=request,
                proposals=tuple(proposals),
            )

            policy_reports = self._evaluate_policy(
                request=request,
                proposals=tuple(proposals),
                candidates=tuple(compiled_candidates),
                evidence=request.evidence,
            )

            if compiled_candidates:
                selection_report = self._rank_candidates(
                    candidates=tuple(compiled_candidates),
                    proposals=tuple(proposals),
                    policy_reports=tuple(policy_reports),
                    evidence=request.evidence,
                    hypotheses=hypotheses,
                )

            status = self._status_from_selection(selection_report)

            return self._report(
                task_id=task_id,
                run_id=run_id,
                objective=objective,
                status=status,
                request=request,
                context_snapshot=context_snapshot,
                evidence_reports=evidence_reports,
                decomposition=decomposition,
                hypotheses=hypotheses,
                prompt_contract=prompt_contract,
                proposals=proposals,
                compiled_candidates=compiled_candidates,
                policy_reports=policy_reports,
                selection_report=selection_report,
                metadata=metadata,
            )

        except AuthoringError as exc:
            errors.append(str(exc))
            self.receipt_ledger.record_authoring_failed(
                request_id=request.request_id,
                failure_phase="authoring_runtime",
                failure_reason=str(exc),
            )
        except Exception as exc:
            errors.append(str(exc))
            self.receipt_ledger.record_authoring_failed(
                request_id=request.request_id,
                failure_phase="unexpected_authoring_runtime_error",
                failure_reason=str(exc),
            )

        return self._report(
            task_id=task_id,
            run_id=run_id,
            objective=objective,
            status=AuthoredRepairStatus.FAILED,
            request=request,
            context_snapshot=context_snapshot,
            evidence_reports=evidence_reports,
            decomposition=decomposition,
            hypotheses=hypotheses,
            prompt_contract=prompt_contract,
            proposals=proposals,
            compiled_candidates=compiled_candidates,
            policy_reports=policy_reports,
            selection_report=selection_report,
            errors=tuple(errors),
            metadata=metadata,
        )

    def _collect_context(
        self,
        *,
        request: AuthoringRequest,
    ) -> AuthoringContextSnapshot:
        builder = AuthoringContextBuilder(
            workspace_root=self.config.workspace_root,
            config=self.config.context_config,
            path_policy=self.config.path_policy,
        )
        snapshot = builder.build(include_paths=self.config.include_paths)
        self.receipt_ledger.record_context_collected(
            request_id=request.request_id,
            snapshot=snapshot,
        )
        return snapshot

    def _collect_evidence_reports(
        self,
        *,
        request: AuthoringRequest,
        raw_test_output: str | None,
        test_command: tuple[str, ...],
        test_return_code: int,
        test_timed_out: bool,
        evidence: tuple[AuthoringEvidence, ...],
    ) -> list[FailureEvidenceReport]:
        extractor = FailureEvidenceExtractor(config=self.config.evidence_config)
        reports: list[FailureEvidenceReport] = []

        if raw_test_output is not None and raw_test_output.strip():
            report = extractor.from_pytest_text(
                text=raw_test_output,
                command=test_command,
                return_code=test_return_code,
                timed_out=test_timed_out,
                metadata={"source": "authored_repair_runtime"},
            )
            reports.append(report)
            self.receipt_ledger.record_evidence_extracted(
                request_id=request.request_id,
                report=report,
            )
            return reports

        if not evidence:
            report = extractor.from_objective_only(
                objective=request.objective.summary,
                metadata={"source": "authored_repair_runtime"},
            )
            reports.append(report)
            self.receipt_ledger.record_evidence_extracted(
                request_id=request.request_id,
                report=report,
            )

        return reports

    def _attach_evidence(
        self,
        *,
        request: AuthoringRequest,
        evidence_reports: tuple[FailureEvidenceReport, ...],
        extra_evidence: tuple[AuthoringEvidence, ...],
    ) -> AuthoringRequest:
        evidence_items = (
            tuple(report.evidence for report in evidence_reports) + extra_evidence
        )
        return AuthoringRequest(
            request_id=request.request_id,
            objective=request.objective,
            mode=request.mode,
            status=request.status,
            context=request.context,
            evidence=evidence_items,
            subtasks=request.subtasks,
            findings=request.findings,
            metadata={
                **dict(request.metadata),
                "evidence_count": len(evidence_items),
                "has_direct_evidence": any(
                    item.strength is AuthoringEvidenceStrength.DIRECT
                    for item in evidence_items
                ),
            },
        )

    def _decompose(self, request: AuthoringRequest) -> RepairDecompositionPlan:
        decomposer = RepairTaskDecomposer(config=self.config.decomposer_config)
        plan = decomposer.decompose_request(request)
        self.receipt_ledger.record_decomposition_created(
            request_id=request.request_id,
            plan=plan,
        )
        return plan

    def _generate_hypotheses(
        self,
        *,
        request: AuthoringRequest,
        decomposition: RepairDecompositionPlan,
    ) -> RepairHypothesisReport:
        engine = RepairHypothesisEngine(config=self.config.hypothesis_config)
        report = engine.generate(
            request=request,
            decomposition=decomposition,
        )
        self.receipt_ledger.record_hypotheses_generated(
            request_id=request.request_id,
            report=report,
        )
        return report

    def _render_prompt(
        self,
        *,
        request: AuthoringRequest,
        context_snapshot: AuthoringContextSnapshot,
        decomposition: RepairDecompositionPlan,
        hypotheses: RepairHypothesisReport,
    ) -> PatchAuthoringPromptContract:
        renderer = PatchAuthoringPromptRenderer(config=self.config.prompt_config)
        contract = renderer.render(
            request=request,
            context_snapshot=context_snapshot,
            decomposition=decomposition,
            hypotheses=hypotheses,
        )
        self.receipt_ledger.record_prompt_contract_rendered(
            request_id=request.request_id,
            contract=contract,
        )
        return contract

    def _proposal_responses(
        self,
        *,
        prompt_contract: PatchAuthoringPromptContract,
        raw_proposal_responses: tuple[str, ...],
    ) -> tuple[str, ...]:
        direct_responses = tuple(
            response.strip() for response in raw_proposal_responses if response.strip()
        )
        provider_responses = tuple(
            response.strip()
            for response in self.provider.generate(prompt_contract)
            if response.strip()
        )

        combined = direct_responses + provider_responses
        if len(combined) > self.config.max_raw_proposals:
            return combined[: self.config.max_raw_proposals]
        return combined

    def _parse_proposals(
        self,
        *,
        request: AuthoringRequest,
        raw_responses: tuple[str, ...],
    ) -> list[PatchAuthoringProposal]:
        parser = PatchAuthoringResponseParser(config=self.config.response_parser_config)
        proposals: list[PatchAuthoringProposal] = []

        for index, raw_response in enumerate(raw_responses, start=1):
            self.receipt_ledger.record_model_response_received(
                request_id=request.request_id,
                raw_response=raw_response,
                provider_name=getattr(self.provider, "provider_name", None),
                model_name=getattr(self.provider, "model_name", None),
            )

            try:
                proposal = parser.parse(raw_response)
            except AuthoringError as exc:
                self.receipt_ledger.record_candidate_rejected(
                    request_id=request.request_id,
                    candidate_id=f"unparsed-{index}",
                    rejection_phase="response_parser",
                    rejection_reason=str(exc),
                )
                continue

            proposals.append(proposal)
            self.receipt_ledger.record_response_parsed(
                request_id=request.request_id,
                proposal=proposal,
            )
            self.receipt_ledger.record_proposal_validated(
                request_id=request.request_id,
                proposal=proposal,
            )

        return proposals

    def _compile_proposals(
        self,
        *,
        request: AuthoringRequest,
        proposals: tuple[PatchAuthoringProposal, ...],
    ) -> list[CompiledPatchCandidate]:
        compiler = PatchProposalCompiler(
            workspace_root=self.config.workspace_root,
            config=self.config.compiler_config,
            path_policy=self.config.path_policy,
        )
        candidates: list[CompiledPatchCandidate] = []

        for proposal in proposals:
            try:
                candidate = compiler.compile(proposal)
            except AuthoringError as exc:
                self.receipt_ledger.record_candidate_rejected(
                    request_id=request.request_id,
                    candidate_id=f"uncompiled-{proposal.proposal_id}",
                    rejection_phase="patch_compiler",
                    rejection_reason=str(exc),
                    proposal_digest=proposal.digest,
                    affected_paths=proposal.affected_paths,
                )
                continue

            candidates.append(candidate)
            self.receipt_ledger.record_patch_compiled(
                request_id=request.request_id,
                candidate=candidate,
            )

        return candidates

    def _evaluate_policy(
        self,
        *,
        request: AuthoringRequest,
        proposals: tuple[PatchAuthoringProposal, ...],
        candidates: tuple[CompiledPatchCandidate, ...],
        evidence: tuple[AuthoringEvidence, ...],
    ) -> list[AuthoringPolicyReport]:
        proposal_by_id = {proposal.proposal_id: proposal for proposal in proposals}
        gate = AuthoringPolicyGate()
        policy_reports: list[AuthoringPolicyReport] = []

        for candidate in candidates:
            proposal = proposal_by_id.get(candidate.proposal_id)
            if proposal is None:
                continue

            report = gate.evaluate(
                proposal=proposal,
                candidate=candidate,
                evidence=evidence,
            )
            policy_reports.append(report)
            self.receipt_ledger.record_policy_decided(
                request_id=request.request_id,
                report=report,
            )

        return policy_reports

    def _rank_candidates(
        self,
        *,
        candidates: tuple[CompiledPatchCandidate, ...],
        proposals: tuple[PatchAuthoringProposal, ...],
        policy_reports: tuple[AuthoringPolicyReport, ...],
        evidence: tuple[AuthoringEvidence, ...],
        hypotheses: RepairHypothesisReport,
    ) -> RepairCandidateSelectionReport:
        ranker = RepairCandidateRanker(config=self.config.ranker_config)
        return ranker.rank(
            candidates=candidates,
            proposals=proposals,
            policy_reports=policy_reports,
            evidence=evidence,
            hypotheses=hypotheses,
        )

    def _status_from_selection(
        self,
        selection_report: RepairCandidateSelectionReport | None,
    ) -> AuthoredRepairStatus:
        if selection_report is None:
            return AuthoredRepairStatus.NO_CANDIDATE

        if selection_report.selected_candidate is not None:
            return AuthoredRepairStatus.AUTHORED

        if selection_report.blocked_candidates and len(
            selection_report.blocked_candidates
        ) == len(selection_report.ranked_candidates):
            return AuthoredRepairStatus.BLOCKED

        if selection_report.review_required_candidates:
            return AuthoredRepairStatus.REQUIRES_REVIEW

        if self.config.require_selected_candidate:
            return AuthoredRepairStatus.NO_CANDIDATE

        return AuthoredRepairStatus.AUTHORED

    def _report(
        self,
        *,
        task_id: str,
        run_id: str,
        objective: str,
        status: AuthoredRepairStatus,
        request: AuthoringRequest,
        context_snapshot: AuthoringContextSnapshot | None = None,
        evidence_reports: Iterable[FailureEvidenceReport] = (),
        decomposition: RepairDecompositionPlan | None = None,
        hypotheses: RepairHypothesisReport | None = None,
        prompt_contract: PatchAuthoringPromptContract | None = None,
        proposals: Iterable[PatchAuthoringProposal] = (),
        compiled_candidates: Iterable[CompiledPatchCandidate] = (),
        policy_reports: Iterable[AuthoringPolicyReport] = (),
        selection_report: RepairCandidateSelectionReport | None = None,
        errors: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthoredRepairRunReport:
        if selection_report is not None:
            if selection_report.selected_candidate is not None:
                self.receipt_ledger.record_candidate_selected(
                    request_id=request.request_id,
                    selected_candidate_id=selection_report.selected_candidate.candidate_id,
                    candidate_ids=tuple(
                        candidate.candidate_id
                        for candidate in selection_report.ranked_candidates
                    ),
                    selection_reason="Candidate selected by RepairCandidateRanker.",
                )

            for ranked_candidate in selection_report.rejected_candidates:
                self.receipt_ledger.record_candidate_rejected(
                    request_id=request.request_id,
                    candidate_id=ranked_candidate.candidate_id,
                    rejection_phase="candidate_ranker",
                    rejection_reason=", ".join(
                        reason.value for reason in ranked_candidate.rejection_reasons
                    )
                    or ranked_candidate.disposition.value,
                    proposal_digest=ranked_candidate.proposal_digest,
                    affected_paths=ranked_candidate.candidate.changed_paths,
                )

        return AuthoredRepairRunReport(
            task_id=task_id,
            run_id=run_id,
            objective=objective,
            status=status,
            request=request,
            context_snapshot=context_snapshot,
            evidence_reports=tuple(evidence_reports),
            decomposition=decomposition,
            hypotheses=hypotheses,
            prompt_contract=prompt_contract,
            proposals=tuple(proposals),
            compiled_candidates=tuple(compiled_candidates),
            policy_reports=tuple(policy_reports),
            selection_report=selection_report,
            receipt_snapshot=self.receipt_ledger.snapshot(),
            errors=tuple(errors),
            metadata={
                "runtime": "AuthoredRepairRuntime",
                "wave": 3,
                "workspace_root": str(self.config.workspace_root),
                **dict(self.config.metadata),
                **dict(metadata or {}),
            },
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_path_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().replace("\\", "/")
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty paths.")
        normalized.append(cleaned)
    return tuple(normalized)
