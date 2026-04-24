from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from ix_blackfox.brains import (
    BrainEscalationDecision,
    BrainEscalationPolicy,
    BrainInvocationReceiptLedger,
    SafeguardAssessment,
)
from ix_blackfox.config import RuntimeConfig, load_runtime_config
from ix_blackfox.eval import (
    EvaluationContext,
    EvaluationFinding,
    EvaluationResult,
    EvaluationSeverity,
    EvaluationStatus,
    EvidenceRecorder,
    OutputVerifier,
    VerificationContext,
    VerificationReport,
)
from ix_blackfox.governance import GovernanceReceiptLedger
from ix_blackfox.kernel import (
    BlackFoxKernel,
    SharedStateStore,
    TaskKind,
    TaskPriority,
    TaskRecord,
    TaskRequest,
    TaskState,
)
from ix_blackfox.memory import (
    ArtifactMemoryStore,
    EpisodicMemoryStore,
    SemanticMemoryStore,
    TraceMemoryStore,
)
from ix_blackfox.observability import JsonlStructuredLogger
from ix_blackfox.packs import (
    BasePack,
    PackBrainContext,
    PackContext,
    PackLoader,
    PackManifest,
    PackManifestRegistry,
)
from ix_blackfox.packs.architecture import build_architecture_manifest
from ix_blackfox.packs.programming import build_programming_manifest
from ix_blackfox.runtime.approval import (
    RuntimeApprovalResolution,
    RuntimeApprovalResolver,
)
from ix_blackfox.runtime.governance import (
    RuntimeGovernancePreflightEngine,
    RuntimeGovernancePreflightResult,
)
from ix_blackfox.runtime.inference import (
    DeterministicTaskClassifier,
    PrimaryBrainRuntime,
    TaskInference,
)
from ix_blackfox.runtime.receipts import (
    RuntimeGovernanceReceiptRecorder,
    RuntimeGovernanceReceiptReport,
)
from ix_blackfox.runtime.replay import ReplayObservation, TaskReplayGuard
from ix_blackfox.runtime.safeguard import SafeguardRuntime
from ix_blackfox.sentinel import (
    SentinelContext,
    SentinelReport,
    SentinelRuntime,
    SentinelSeverity,
)
from ix_blackfox.switchboard import (
    CapabilityRoute,
    CapabilitySwitchboard,
    RoutingDecision,
)
from ix_blackfox.vault import (
    ProvenanceLedger,
    VaultStateStore,
)


class RuntimeRunStatus(StrEnum):
    """
    High-level run outcome classification.
    """

    PASSED = auto()
    NEEDS_REVIEW = auto()
    FAILED = auto()


@dataclass(frozen=True, slots=True)
class RuntimeRunReport:
    """
    Immutable end-to-end runtime run report.
    """

    session_id: str
    run_id: str
    task_id: str
    task_kind: TaskKind
    status: RuntimeRunStatus
    route: RoutingDecision | None
    pack_name: str | None
    task_summary: str
    evaluation_result: EvaluationResult
    verification_report: VerificationReport
    sentinel_report: SentinelReport
    replay_observation: ReplayObservation
    task_inference: TaskInference | None = None
    escalation_decision: BrainEscalationDecision | None = None
    safeguard_assessment: SafeguardAssessment | None = None
    governance_preflight: RuntimeGovernancePreflightResult | None = None
    approval_resolution: RuntimeApprovalResolution | None = None
    governance_receipts: RuntimeGovernanceReceiptReport | None = None
    produced_artifacts: tuple[str, ...] = field(default_factory=tuple)
    artifact_paths: dict[str, str] = field(default_factory=dict)
    trace_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    report_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        route = None
        if self.route is not None:
            route = {
                "capability_name": self.route.capability_name,
                "confidence": self.route.confidence,
                "reason": self.route.reason.value,
                "task_id": self.route.task_id,
                "matched_labels": self.route.matched_labels,
            }

        inference = None
        if self.task_inference is not None:
            inference = {
                "kind": self.task_inference.kind.value,
                "confidence": self.task_inference.confidence,
                "reason": self.task_inference.reason.value,
                "matched_terms": self.task_inference.matched_terms,
                "matched_labels": self.task_inference.matched_labels,
            }

        escalation = None
        if self.escalation_decision is not None:
            escalation = _escalation_to_dict(self.escalation_decision)

        safeguard_assessment = None
        if self.safeguard_assessment is not None:
            safeguard_assessment = _safeguard_assessment_to_dict(self.safeguard_assessment)

        governance_preflight = None
        if self.governance_preflight is not None:
            governance_preflight = self.governance_preflight.to_dict()

        approval_resolution = None
        if self.approval_resolution is not None:
            approval_resolution = self.approval_resolution.to_dict()

        governance_receipts = None
        if self.governance_receipts is not None:
            governance_receipts = self.governance_receipts.to_dict()

        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "task_kind": self.task_kind.value,
            "status": self.status.value,
            "route": route,
            "pack_name": self.pack_name,
            "task_summary": self.task_summary,
            "evaluation_result": _evaluation_to_dict(self.evaluation_result),
            "verification_report": _verification_to_dict(self.verification_report),
            "sentinel_report": _sentinel_to_dict(self.sentinel_report),
            "replay_observation": asdict(self.replay_observation),
            "task_inference": inference,
            "escalation_decision": escalation,
            "safeguard_assessment": safeguard_assessment,
            "governance_preflight": governance_preflight,
            "approval_resolution": approval_resolution,
            "governance_receipts": governance_receipts,
            "produced_artifacts": self.produced_artifacts,
            "artifact_paths": self.artifact_paths,
            "trace_ids": self.trace_ids,
            "evidence_ids": self.evidence_ids,
            "report_path": self.report_path,
        }


class BlackFoxRuntime:
    """
    End-to-end deterministic runtime composition for IX-BlackFox.

    This is the missing execution spine that turns the existing sovereign
    subsystems into one auditable run path.
    """

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        kernel: BlackFoxKernel,
        bus: InMemoryEventBus,
        shared_state: SharedStateStore,
        switchboard: CapabilitySwitchboard,
        manifest_registry: PackManifestRegistry,
        pack_loader: PackLoader,
        trace_memory: TraceMemoryStore,
        artifact_memory: ArtifactMemoryStore,
        episodic_memory: EpisodicMemoryStore,
        semantic_memory: SemanticMemoryStore,
        sentinel: SentinelRuntime,
        evidence: EvidenceRecorder,
        verifier: OutputVerifier,
        logger: JsonlStructuredLogger,
        provenance: ProvenanceLedger,
        state_store: VaultStateStore,
        replay_guard: TaskReplayGuard,
        classifier: DeterministicTaskClassifier,
        governance_preflight: RuntimeGovernancePreflightEngine,
        approval_resolver: RuntimeApprovalResolver,
        receipt_recorder: RuntimeGovernanceReceiptRecorder,
        primary_brain: PrimaryBrainRuntime | None = None,
        safeguard_runtime: SafeguardRuntime | None = None,
        escalation_policy: BrainEscalationPolicy | None = None,
    ) -> None:
        self._config = config
        self._kernel = kernel
        self._bus = bus
        self._shared_state = shared_state
        self._switchboard = switchboard
        self._manifest_registry = manifest_registry
        self._pack_loader = pack_loader
        self._trace_memory = trace_memory
        self._artifact_memory = artifact_memory
        self._episodic_memory = episodic_memory
        self._semantic_memory = semantic_memory
        self._sentinel = sentinel
        self._evidence = evidence
        self._verifier = verifier
        self._logger = logger
        self._provenance = provenance
        self._state_store = state_store
        self._replay_guard = replay_guard
        self._classifier = classifier
        self._governance_preflight = governance_preflight
        self._approval_resolver = approval_resolver
        self._receipt_recorder = receipt_recorder
        self._primary_brain = primary_brain or PrimaryBrainRuntime(config=config)
        self._safeguard_runtime = safeguard_runtime or SafeguardRuntime(config=config)
        self._brain_providers = self._primary_brain.build_providers()
        self._escalation_policy = escalation_policy or BrainEscalationPolicy()
        self._session_id = f"session-{uuid4().hex}"
        self._loaded_packs: dict[str, BasePack] = {}

    @classmethod
    def create_default(
        cls,
        *,
        root_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> BlackFoxRuntime:
        """
        Build a default fully-wired BlackFox runtime.
        """
        config = load_runtime_config(root_dir=root_dir, env=env or {})
        kernel = BlackFoxKernel(config)
        bus = InMemoryEventBus()
        shared_state = SharedStateStore()
        switchboard = CapabilitySwitchboard()
        registry = PackManifestRegistry()
        loader = PackLoader()
        trace_memory = TraceMemoryStore()
        artifact_memory = ArtifactMemoryStore()
        episodic_memory = EpisodicMemoryStore()
        semantic_memory = SemanticMemoryStore()
        sentinel = SentinelRuntime()
        evidence = EvidenceRecorder()
        verifier = OutputVerifier()
        logger = JsonlStructuredLogger(config)
        provenance = ProvenanceLedger()
        state_secret = os.environ.get(
            "BLACKFOX_STATE_SECRET",
            "blackfox-development-state-secret",
        )
        state_store = VaultStateStore(
            root_dir=config.paths.state_dir / "vault",
            secret=state_secret,
        )
        replay_guard = TaskReplayGuard()
        classifier = DeterministicTaskClassifier()
        governance_preflight = RuntimeGovernancePreflightEngine()
        approval_resolver = RuntimeApprovalResolver()
        receipt_recorder = RuntimeGovernanceReceiptRecorder()
        primary_brain = PrimaryBrainRuntime(config=config)
        safeguard_runtime = SafeguardRuntime(config=config)
        escalation_policy = BrainEscalationPolicy()

        runtime = cls(
            config=config,
            kernel=kernel,
            bus=bus,
            shared_state=shared_state,
            switchboard=switchboard,
            manifest_registry=registry,
            pack_loader=loader,
            trace_memory=trace_memory,
            artifact_memory=artifact_memory,
            episodic_memory=episodic_memory,
            semantic_memory=semantic_memory,
            sentinel=sentinel,
            evidence=evidence,
            verifier=verifier,
            logger=logger,
            provenance=provenance,
            state_store=state_store,
            replay_guard=replay_guard,
            classifier=classifier,
            governance_preflight=governance_preflight,
            approval_resolver=approval_resolver,
            receipt_recorder=receipt_recorder,
            primary_brain=primary_brain,
            safeguard_runtime=safeguard_runtime,
            escalation_policy=escalation_policy,
        )
        kernel.initialize()
        runtime._register_default_manifests()
        return runtime

    def run_prompt(
        self,
        *,
        prompt: str,
        kind: TaskKind = TaskKind.UNKNOWN,
        labels: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> RuntimeRunReport:
        """
        Convenience API to create and execute a task in one call.
        """
        request = TaskRequest.create(
            prompt=prompt,
            kind=kind,
            priority=priority,
            metadata=metadata or {},
            labels=labels,
        )
        task = TaskRecord(request=request)
        return self.execute_task(task)

    def execute_task(self, task: TaskRecord) -> RuntimeRunReport:
        """
        Execute one task end-to-end through the runtime.
        """
        replay_observation = self._replay_guard.observe(task.request)
        if replay_observation.duplicate_detected:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="runtime",
                message="Replay guard flagged duplicate task fingerprint.",
                level="warning",
                source="runtime",
            )

        task = task.mark_ready().mark_running()

        inference = self._classifier.infer(
            prompt=task.request.input.prompt,
            labels=task.request.labels,
        )
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="inference",
            message=(
                f"Classified task as {inference.kind.value} "
                f"(reason={inference.reason.value}, confidence={inference.confidence:.2f})."
            ),
            level="info",
            source="classifier",
        )

        if task.request.kind == TaskKind.UNKNOWN and inference.kind != TaskKind.UNKNOWN:
            task = replace(task, request=replace(task.request, kind=inference.kind))

        route = self._switchboard.route(task.request)
        if route is None:
            raise RuntimeError("No capability route matched the submitted task.")

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="routing",
            message=(
                f"Routed task to capability '{route.capability_name}' "
                f"(confidence={route.confidence:.2f}, reason={route.reason.value})."
            ),
            level="info",
            source="switchboard",
        )

        governance_receipt_ledger = self._receipt_recorder.create_ledger()
        brain_receipt_ledger = BrainInvocationReceiptLedger()

        safeguard_plan = self._safeguard_runtime.plan(
            task=task,
            route=route,
            pack_name=route.capability_name,
        )
        safeguard_outcome = self._safeguard_runtime.invoke(
            plan=safeguard_plan,
            providers=self._brain_providers,
            receipt_ledger=brain_receipt_ledger,
        )

        if safeguard_outcome.skipped:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="safeguard",
                message=(
                    f"Safeguard brain '{safeguard_plan.manifest.brain_name}' was planned "
                    f"but not invoked: {safeguard_outcome.failure_message}"
                ),
                level="warning",
                source="brain.safeguard",
            )
        elif safeguard_outcome.succeeded:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="safeguard",
                message=(
                    f"Safeguard brain '{safeguard_plan.manifest.brain_name}' completed "
                    f"through provider '{safeguard_outcome.provider_name}' with advisory "
                    f"disposition '{safeguard_outcome.assessment.advisory_disposition.value}'."
                ),
                level="info",
                source="brain.safeguard",
            )
        elif safeguard_outcome.assessment is not None:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="safeguard",
                message=(
                    f"Safeguard brain '{safeguard_plan.manifest.brain_name}' produced a "
                    f"fallback advisory disposition '{safeguard_outcome.assessment.advisory_disposition.value}' "
                    f"after a non-success provider outcome."
                ),
                level="warning",
                source="brain.safeguard",
            )
        else:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="safeguard",
                message=(
                    f"Safeguard brain '{safeguard_plan.manifest.brain_name}' invocation failed: "
                    f"{safeguard_outcome.failure_message}"
                ),
                level="warning",
                source="brain.safeguard",
            )

        governance_preflight = self._governance_preflight.evaluate(
            task=task,
            route=route,
            safeguard_assessment=safeguard_outcome.assessment,
        )
        approval_resolution = self._approval_resolver.resolve(
            task=task,
            preflight=governance_preflight,
        )

        self._receipt_recorder.record_preflight(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
        )
        self._receipt_recorder.record_approval_resolution(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
            resolution=approval_resolution,
        )

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="governance",
            message=(
                f"Preflight decision={governance_preflight.decision.decision.value}, "
                f"risk={governance_preflight.risk.risk_level.value}, "
                f"approval_required={approval_resolution.required}, "
                f"approval_satisfied={approval_resolution.satisfied}."
            ),
            level="info",
            source="governance",
        )

        if governance_preflight.blocked:
            failed_task = task.mark_failed(error=governance_preflight.decision.rationale)
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=failed_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=False,
                        ),
                    },
                )
            )
            evaluation = self._evaluate_run(
                task=failed_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
                )
            )
            escalation_decision = self._evaluate_reasoning_escalation(
                task=failed_task,
                route=route,
                sentinel_report=sentinel_report,
                verification=verification,
                approval_resolution=approval_resolution,
            )
            return self._finalize_run(
                task=failed_task,
                route=route,
                pack_name=None,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                escalation_decision=escalation_decision,
                safeguard_assessment=safeguard_outcome.assessment,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
                brain_receipt_ledger=brain_receipt_ledger,
            )

        if governance_preflight.requires_review and not approval_resolution.satisfied:
            paused_task = task.mark_completed(
                result_summary="Run paused pending governance approval."
            )
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=paused_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=False,
                        ),
                    },
                )
            )
            evaluation = self._evaluate_run(
                task=paused_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
                )
            )
            escalation_decision = self._evaluate_reasoning_escalation(
                task=paused_task,
                route=route,
                sentinel_report=sentinel_report,
                verification=verification,
                approval_resolution=approval_resolution,
            )
            return self._finalize_run(
                task=paused_task,
                route=route,
                pack_name=None,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                escalation_decision=escalation_decision,
                safeguard_assessment=safeguard_outcome.assessment,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
                brain_receipt_ledger=brain_receipt_ledger,
            )

        manifest = self._manifest_registry.get(route.capability_name)
        if manifest is None:
            raise RuntimeError(
                f"Route target '{route.capability_name}' has no registered manifest."
            )

        pack = self._load_pack(manifest)
        primary_brain_plan = self._primary_brain.plan(
            task=task,
            route=route,
            pack_name=pack.pack_name,
        )
        primary_brain_outcome = self._primary_brain.invoke(
            plan=primary_brain_plan,
            providers=self._brain_providers,
            receipt_ledger=brain_receipt_ledger,
        )

        if primary_brain_outcome.skipped:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="brain",
                message=(
                    f"Primary brain '{primary_brain_plan.manifest.brain_name}' was planned "
                    f"but not invoked: {primary_brain_outcome.failure_message}"
                ),
                level="warning",
                source="brain.primary",
            )
        elif primary_brain_outcome.succeeded:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="brain",
                message=(
                    f"Primary brain '{primary_brain_plan.manifest.brain_name}' completed "
                    f"through provider '{primary_brain_outcome.provider_name}'."
                ),
                level="info",
                source="brain.primary",
            )
        else:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="brain",
                message=(
                    f"Primary brain '{primary_brain_plan.manifest.brain_name}' invocation failed: "
                    f"{primary_brain_outcome.failure_message}"
                ),
                level="warning",
                source="brain.primary",
            )

        self._receipt_recorder.record_execution_started(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
            pack_name=pack.pack_name,
        )

        pack_context = PackContext(
            config=self._config,
            bus=self._bus,
            shared_state=self._shared_state,
            brain=_pack_brain_context(plan=primary_brain_plan, outcome=primary_brain_outcome),
            metadata={
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "session_id": self._session_id,
                "approval_ids": approval_resolution.approval_ids,
            },
        )

        try:
            pack_result = pack.execute(task=task, context=pack_context)
        except Exception as exc:
            self._receipt_recorder.record_execution_failed(
                ledger=governance_receipt_ledger,
                preflight=governance_preflight,
                pack_name=pack.pack_name,
                error=str(exc),
            )
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="pack",
                message=f"Pack execution failed: {exc}",
                level="error",
                source=route.capability_name,
            )
            failed_task = task.mark_failed(error=str(exc))
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=failed_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=True,
                        ),
                    },
                )
            )
            evaluation = self._evaluate_run(
                task=failed_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
                )
            )
            escalation_decision = self._evaluate_reasoning_escalation(
                task=failed_task,
                route=route,
                sentinel_report=sentinel_report,
                verification=verification,
                approval_resolution=approval_resolution,
            )
            return self._finalize_run(
                task=failed_task,
                route=route,
                pack_name=pack.pack_name,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                escalation_decision=escalation_decision,
                safeguard_assessment=safeguard_outcome.assessment,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
                brain_receipt_ledger=brain_receipt_ledger,
            )

        artifact_materializations = self._materialize_pack_artifacts(
            task=task,
            pack_name=pack.pack_name,
            pack_result=pack_result,
        )

        completed_task = task.mark_completed(result_summary=pack_result.summary)
        self._receipt_recorder.record_execution_completed(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
            pack_name=pack.pack_name,
            artifact_count=len(pack_result.artifacts),
        )
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="pack",
            message=(
                f"Pack '{pack.pack_name}' completed with "
                f"{len(pack_result.artifacts)} artifact(s)."
            ),
            level="info",
            source=route.capability_name,
        )

        sentinel_report = self._sentinel.evaluate(
            SentinelContext(
                task=completed_task,
                trace_records=self._task_traces(task.request.task_id),
                metadata={
                    "governance_observations": _build_governance_observations(
                        governance_preflight=governance_preflight,
                        approval_resolution=approval_resolution,
                        executed=True,
                    ),
                },
            )
        )
        evaluation = self._evaluate_run(
            task=completed_task,
            route=route,
            artifacts=pack_result.artifacts,
            replay_observation=replay_observation,
            sentinel_report=sentinel_report,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )
        (
            required_signals,
            observed_signals,
            governance_chain_verified,
            approval_required,
            approval_satisfied,
        ) = _verification_signal_state(
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipt_ledger=governance_receipt_ledger,
        )
        verification = self._verifier.verify(
            VerificationContext(
                subject_id=task.request.task_id,
                expected_artifacts=tuple(pack_result.artifacts),
                produced_artifacts=tuple(pack_result.artifacts),
                evaluation_results=(evaluation,),
                required_signals=required_signals,
                observed_signals=observed_signals,
                governance_chain_verified=governance_chain_verified,
                approval_required=approval_required,
                approval_satisfied=approval_satisfied,
            )
        )
        escalation_decision = self._evaluate_reasoning_escalation(
            task=completed_task,
            route=route,
            sentinel_report=sentinel_report,
            verification=verification,
            approval_resolution=approval_resolution,
        )
        return self._finalize_run(
            task=completed_task,
            route=route,
            pack_name=pack.pack_name,
            pack_result=pack_result,
            artifact_materializations=artifact_materializations,
            replay_observation=replay_observation,
            task_inference=inference,
            escalation_decision=escalation_decision,
            safeguard_assessment=safeguard_outcome.assessment,
            sentinel_report=sentinel_report,
            evaluation=evaluation,
            verification=verification,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipt_ledger=governance_receipt_ledger,
            brain_receipt_ledger=brain_receipt_ledger,
        )

    def _finalize_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        pack_name: str | None,
        pack_result: Any | None,
        artifact_materializations: dict[str, Path] | None = None,
        replay_observation: ReplayObservation,
        task_inference: TaskInference,
        escalation_decision: BrainEscalationDecision | None,
        safeguard_assessment: SafeguardAssessment | None,
        sentinel_report: SentinelReport,
        evaluation: EvaluationResult,
        verification: VerificationReport,
        governance_preflight: RuntimeGovernancePreflightResult,
        approval_resolution: RuntimeApprovalResolution,
        governance_receipt_ledger: GovernanceReceiptLedger,
        brain_receipt_ledger: BrainInvocationReceiptLedger,
    ) -> RuntimeRunReport:
        status = _status_from_reports(
            evaluation=evaluation,
            verification=verification,
            sentinel=sentinel_report,
        )

        self._receipt_recorder.record_verification_outcome(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
            verification_status=verification.status.value,
            issue_count=len(verification.issues),
        )

        governance_receipts = self._persist_governance_receipts(
            task=task,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipt_ledger=governance_receipt_ledger,
            brain_receipt_ledger=brain_receipt_ledger,
        )

        produced_artifacts: list[str] = []
        artifact_paths: dict[str, str] = {}
        evidence_ids: list[str] = []
        if pack_result is not None:
            materializations = artifact_materializations or {}
            for artifact_name in pack_result.artifacts:
                artifact_path = materializations.get(artifact_name)
                if artifact_path is None:
                    raise RuntimeError(
                        f"Runtime artifact '{artifact_name}' was not materialized."
                    )
                produced_artifacts.append(artifact_name)
                artifact_paths[artifact_name] = str(artifact_path)
                evidence_record = self._evidence.record(
                    subject_id=task.request.task_id,
                    evidence_type="artifact",
                    summary=f"Produced runtime artifact {artifact_name}.",
                    source="runtime.orchestrator",
                    artifact_refs=(artifact_name,),
                    trace_ids=self._task_trace_ids(task.request.task_id),
                    metadata={"artifact_path": str(artifact_path)},
                )
                evidence_ids.append(evidence_record.evidence_id)
                self._artifact_memory.upsert(
                    logical_name=artifact_name,
                    path=artifact_path,
                    artifact_type="runtime_artifact",
                    source="runtime.orchestrator",
                    metadata={"task_id": task.request.task_id},
                )

        if (
            governance_receipts is not None
            and governance_receipts.artifact_path is not None
        ):
            receipt_name = Path(governance_receipts.artifact_path).name
            if receipt_name not in artifact_paths:
                produced_artifacts.append(receipt_name)
                artifact_paths[receipt_name] = governance_receipts.artifact_path

        report = RuntimeRunReport(
            session_id=self._session_id,
            run_id=f"run-{uuid4().hex}",
            task_id=task.request.task_id,
            task_kind=task.request.kind,
            status=status,
            route=route,
            pack_name=pack_name,
            task_summary=self._build_summary(task, evaluation, verification),
            evaluation_result=evaluation,
            verification_report=verification,
            sentinel_report=sentinel_report,
            replay_observation=replay_observation,
            task_inference=task_inference,
            escalation_decision=escalation_decision,
            safeguard_assessment=safeguard_assessment,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipts=governance_receipts,
            produced_artifacts=tuple(produced_artifacts),
            artifact_paths=artifact_paths,
            trace_ids=self._task_trace_ids(task.request.task_id),
            evidence_ids=tuple(evidence_ids),
        )

        report_path = self._write_run_report(report)
        report = replace(report, report_path=str(report_path))
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="runtime",
            message=f"Run finalized with status={report.status.value}.",
            level="info",
            source="runtime",
        )
        return report

    def _materialize_pack_artifacts(
        self,
        *,
        task: TaskRecord,
        pack_name: str,
        pack_result: Any,
    ) -> dict[str, Path]:
        artifacts_dir = self._config.paths.artifacts_dir / task.request.task_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        materialized: dict[str, Path] = {}
        for artifact_name in pack_result.artifacts:
            artifact_path = (artifacts_dir / artifact_name).resolve()
            payload = _materialized_artifact_payload(
                artifact_name=artifact_name,
                pack_name=pack_name,
                task=task,
                pack_result=pack_result,
            )
            _safe_json_dump(artifact_path, payload)
            materialized[artifact_name] = artifact_path

        return materialized

    def _persist_governance_receipts(
        self,
        *,
        task: TaskRecord,
        governance_preflight: RuntimeGovernancePreflightResult,
        approval_resolution: RuntimeApprovalResolution,
        governance_receipt_ledger: GovernanceReceiptLedger,
        brain_receipt_ledger: BrainInvocationReceiptLedger,
    ) -> RuntimeGovernanceReceiptReport:
        receipts_root = self._config.paths.artifacts_dir / "governance"
        receipt_path = (
            receipts_root / task.request.task_id / "blackfox-governance-receipts.json"
        )
        receipt_report = self._receipt_recorder.report_from_ledger(
            ledger=governance_receipt_ledger,
            intent_id=governance_preflight.intent.intent_id,
            artifact_path=str(receipt_path),
        )
        receipt_report = self._receipt_recorder.attach_brain_receipts(
            report=receipt_report,
            ledger=brain_receipt_ledger,
            task_id=task.request.task_id,
        )
        _safe_json_dump(receipt_path, receipt_report.to_dict())
        self._artifact_memory.upsert(
            logical_name=receipt_path.name,
            path=receipt_path,
            artifact_type="governance_receipt",
            source="runtime.receipts",
            metadata={
                "task_id": task.request.task_id,
                "kind": "governance_receipt",
            },
        )
        self._trace_memory.append(
            correlation_id=task.request.task_id,
            stage="governance",
            message=(
                f"Persisted governance receipt chain with "
                f"{receipt_report.receipt_count} record(s)."
            ),
            level="info",
            source="receipt_recorder",
        )
        return receipt_report

    def _evaluate_reasoning_escalation(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        sentinel_report: SentinelReport,
        verification: VerificationReport,
        approval_resolution: RuntimeApprovalResolution,
    ) -> BrainEscalationDecision:
        repeated_failures = 1 if task.state == TaskState.FAILED else 0
        current_escalation_hops = _coerce_non_negative_int(
            task.request.metadata.get("reasoning_escalation_hops", 0)
        )
        explicit_deep_reasoning = _explicit_deep_reasoning_requested(
            task.request.input.prompt
        )

        decision = self._escalation_policy.evaluate(
            route_confidence=route.confidence,
            contradiction_detected=sentinel_report.has_contradiction_signal(),
            verification_failed=verification.failed(),
            repeated_failures=repeated_failures,
            explicit_deep_reasoning=explicit_deep_reasoning,
            approval_required=approval_resolution.required,
            budget=self._config.brains.execution_profile.budget.escalation,
            current_escalation_hops=current_escalation_hops,
        )

        if decision.has_reasons:
            if decision.should_escalate:
                level = "warning"
                message = (
                    f"Reasoning escalation requested (score={decision.score}, "
                    f"triggers={', '.join(decision.trigger_codes())})."
                )
            elif decision.blocked_by_budget:
                level = "warning"
                message = (
                    f"Reasoning escalation was justified but blocked by budget "
                    f"(score={decision.score}, blocked_reason={decision.blocked_reason})."
                )
            else:
                level = "info"
                message = (
                    f"Reasoning escalation signals were observed but stayed below threshold "
                    f"(score={decision.score}, triggers={', '.join(decision.trigger_codes())})."
                )

            self._append_trace(
                correlation_id=task.request.task_id,
                stage="escalation",
                message=message,
                level=level,
                source="brain.escalation",
            )

        return decision

    def _evaluate_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        artifacts: tuple[Any, ...],
        replay_observation: ReplayObservation,
        sentinel_report: SentinelReport,
        governance_preflight: RuntimeGovernancePreflightResult | None,
        approval_resolution: RuntimeApprovalResolution | None,
    ) -> EvaluationResult:
        findings: list[EvaluationFinding] = []

        if replay_observation.duplicate_detected:
            findings.append(
                EvaluationFinding(
                    code="replay_guard",
                    severity=EvaluationSeverity.WARNING,
                    summary="Replay guard detected a duplicate task fingerprint.",
                    data={"fingerprint": replay_observation.fingerprint},
                )
            )

        if governance_preflight is not None:
            findings.append(
                EvaluationFinding(
                    code="governance_decision",
                    severity=(
                        EvaluationSeverity.ERROR
                        if governance_preflight.blocked
                        else (
                            EvaluationSeverity.WARNING
                            if (
                                governance_preflight.requires_review
                                and (
                                    approval_resolution is None
                                    or not approval_resolution.satisfied
                                )
                            )
                            else EvaluationSeverity.INFO
                        )
                    ),
                    summary=governance_preflight.decision.rationale,
                    data={
                        "policy_decision": governance_preflight.decision.decision.value,
                        "risk_level": governance_preflight.risk.risk_level.value,
                        "ticket_id": governance_preflight.ticket.ticket_id,
                        "approval_required": (
                            False
                            if approval_resolution is None
                            else approval_resolution.required
                        ),
                        "approval_satisfied": (
                            False
                            if approval_resolution is None
                            else approval_resolution.satisfied
                        ),
                    },
                )
            )

        if route is None:
            findings.append(
                EvaluationFinding(
                    code="routing",
                    severity=EvaluationSeverity.ERROR,
                    summary="Runtime did not resolve a capability route.",
                )
            )
        else:
            findings.append(
                EvaluationFinding(
                    code="routing",
                    severity=EvaluationSeverity.INFO,
                    summary=(
                        f"Task routed to capability '{route.capability_name}' "
                        f"with confidence {route.confidence:.2f}."
                    ),
                    data={
                        "capability_name": route.capability_name,
                        "reason": route.reason.value,
                    },
                )
            )

        if sentinel_report.has_severity(SentinelSeverity.CRITICAL) or sentinel_report.has_severity(
            SentinelSeverity.ERROR
        ):
            findings.append(
                EvaluationFinding(
                    code="sentinel",
                    severity=EvaluationSeverity.ERROR,
                    summary="Sentinel reported a blocking runtime issue.",
                    data={
                        "highest_severity": _sentinel_highest_severity(sentinel_report).value
                    },
                )
            )

        if task.state == TaskState.FAILED:
            findings.append(
                EvaluationFinding(
                    code="task_outcome",
                    severity=EvaluationSeverity.ERROR,
                    summary=task.error or "Task failed during runtime execution.",
                )
            )
        elif (
            task.state == TaskState.COMPLETED
            and governance_preflight is not None
            and governance_preflight.requires_review
            and approval_resolution is not None
            and not approval_resolution.satisfied
        ):
            findings.append(
                EvaluationFinding(
                    code="approval_gate",
                    severity=EvaluationSeverity.WARNING,
                    summary="Execution paused pending governance approval.",
                )
            )
        else:
            findings.append(
                EvaluationFinding(
                    code="task_outcome",
                    severity=EvaluationSeverity.INFO,
                    summary="Task completed successfully.",
                )
            )

        for artifact in artifacts:
            findings.append(
                EvaluationFinding(
                    code="artifact",
                    severity=EvaluationSeverity.INFO,
                    summary=f"Produced artifact '{artifact}'.",
                )
            )

        _ = EvaluationContext(
            task=task,
            artifacts=cast(tuple[str, ...], tuple(artifacts)),
            metadata={
                "route": None if route is None else route.capability_name,
                "governance_decision": (
                    None
                    if governance_preflight is None
                    else governance_preflight.decision.decision.value
                ),
                "approval_required": (
                    False
                    if approval_resolution is None
                    else approval_resolution.required
                ),
                "approval_satisfied": (
                    False
                    if approval_resolution is None
                    else approval_resolution.satisfied
                ),
            },
        )
        status = _evaluation_status_from_findings(tuple(findings))
        score = _evaluation_score_for_status(status)
        return EvaluationResult(
            evaluator_name="runtime_run",
            evaluated_at=_utc_now(),
            status=status,
            score=score,
            findings=tuple(findings),
        )

    def _register_default_manifests(self) -> None:
        architecture = build_architecture_manifest()
        programming = build_programming_manifest()
        self._manifest_registry.register(architecture)
        self._manifest_registry.register(programming)
        self._switchboard.register(
            CapabilityRoute(
                capability_name=architecture.pack_name,
                supported_kinds=architecture.supported_kinds,
                labels=architecture.labels,
                description=architecture.description,
            )
        )
        self._switchboard.register(
            CapabilityRoute(
                capability_name=programming.pack_name,
                supported_kinds=programming.supported_kinds,
                labels=programming.labels,
                description=programming.description,
            )
        )

    def _load_pack(self, manifest: PackManifest) -> BasePack:
        pack_name = manifest.pack_name
        if pack_name in self._loaded_packs:
            return self._loaded_packs[pack_name]

        loaded = self._pack_loader.load(manifest)
        implementation = loaded.implementation
        pack = implementation() if isinstance(implementation, type) else implementation
        self._loaded_packs[pack_name] = pack
        return cast(BasePack, pack)

    def _append_trace(
        self,
        *,
        correlation_id: str,
        stage: str,
        message: str,
        level: str,
        source: str,
    ) -> None:
        self._trace_memory.append(
            correlation_id=correlation_id,
            stage=stage,
            message=message,
            level=level,
            source=source,
        )

    def _task_traces(self, task_id: str) -> tuple[Any, ...]:
        return self._trace_memory.snapshot().filter_by_correlation(task_id)

    def _task_trace_ids(self, task_id: str) -> tuple[str, ...]:
        return tuple(record.trace_id for record in self._task_traces(task_id))

    def _build_summary(
        self,
        task: TaskRecord,
        evaluation: EvaluationResult,
        verification: VerificationReport,
    ) -> str:
        if task.state == TaskState.FAILED:
            return task.error or "Task failed during runtime execution."
        if verification.status.value == "needs_review":
            return "Run paused pending governance approval."
        if task.result_summary:
            return task.result_summary
        if evaluation.findings:
            return evaluation.findings[0].summary
        return f"Evaluation completed with status {evaluation.status.value}."

    def _write_run_report(self, report: RuntimeRunReport) -> Path:
        reports_dir = self._config.paths.artifacts_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / f"{report.task_id}.json"
        report_path.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return report_path


def _pack_brain_context(
    *,
    plan: Any,
    outcome: Any,
) -> PackBrainContext:
    result_status = None
    output_text = None
    if outcome.result is not None:
        result_status = outcome.result.status.value
        output_text = outcome.result.output_text

    return PackBrainContext(
        brain_name=plan.manifest.brain_name,
        provider_name=plan.manifest.provider_name,
        model_name=plan.manifest.model_name,
        invocation_id=plan.request.invocation_id,
        rendered_prompt=plan.rendered_prompt,
        invoked=outcome.invoked,
        result_status=result_status,
        output_text=output_text,
        failure_message=outcome.failure_message,
    )


def _status_from_reports(
    *,
    evaluation: EvaluationResult,
    verification: VerificationReport,
    sentinel: SentinelReport,
) -> RuntimeRunStatus:
    if sentinel.has_severity(SentinelSeverity.CRITICAL) or sentinel.has_severity(
        SentinelSeverity.ERROR
    ):
        return RuntimeRunStatus.FAILED
    if verification.status.value == "failed":
        return RuntimeRunStatus.FAILED
    if verification.status.value == "needs_review":
        return RuntimeRunStatus.NEEDS_REVIEW
    return RuntimeRunStatus.PASSED


def _verification_signal_state(
    *,
    governance_preflight: RuntimeGovernancePreflightResult,
    approval_resolution: RuntimeApprovalResolution,
    governance_receipt_ledger: GovernanceReceiptLedger,
) -> tuple[tuple[str, ...], tuple[str, ...], bool, bool, bool]:
    required_signals = ["policy_preflight"]
    observed_signals = ["policy_preflight"]

    if governance_preflight.requires_review:
        required_signals.append("policy_review_required")
        observed_signals.append("policy_review_required")
        if approval_resolution.satisfied:
            required_signals.append("approval_recorded")
            observed_signals.append("approval_recorded")

    if governance_preflight.blocked:
        required_signals.append("verification_failed")
        observed_signals.append("verification_failed")
    else:
        required_signals.append("execution_started")
        required_signals.append("execution_completed")
        observed_signals.extend(["execution_started", "execution_completed"])

    governance_chain_verified = governance_receipt_ledger.verify_intent_chain(
        governance_preflight.intent.intent_id
    )

    return (
        tuple(required_signals),
        tuple(observed_signals),
        governance_chain_verified,
        approval_resolution.required,
        approval_resolution.satisfied,
    )


def _evaluation_to_dict(result: EvaluationResult) -> dict[str, Any]:
    return {
        "evaluator_name": result.evaluator_name,
        "status": result.status.value,
        "score": result.score,
        "evaluated_at": result.evaluated_at.isoformat(),
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity.value,
                "summary": finding.summary,
                "details": finding.details,
                "data": finding.data,
            }
            for finding in result.findings
        ],
    }


def _verification_to_dict(report: VerificationReport) -> dict[str, Any]:
    return {
        "subject_id": report.subject_id,
        "status": report.status.value,
        "verified_at": report.verified_at.isoformat(),
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "summary": issue.summary,
                "details": issue.details,
            }
            for issue in report.issues
        ],
    }


def _sentinel_to_dict(report: SentinelReport) -> dict[str, Any]:
    highest_severity = _sentinel_highest_severity(report)
    return {
        "check_count": report.check_count,
        "issue_count": len(report.issues),
        "highest_severity": highest_severity.value,
        "evaluated_at": report.evaluated_at.isoformat(),
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "summary": issue.summary,
                "details": issue.details,
                "source": issue.source,
                "data": issue.data,
            }
            for issue in report.issues
        ],
    }


def _escalation_to_dict(decision: BrainEscalationDecision) -> dict[str, Any]:
    return {
        "should_escalate": decision.should_escalate,
        "score": decision.score,
        "trigger_codes": decision.trigger_codes(),
        "blocked_by_budget": decision.blocked_by_budget,
        "blocked_reason": decision.blocked_reason,
        "current_escalation_hops": decision.current_escalation_hops,
        "remaining_hops": decision.remaining_hops,
        "reasons": [
            {
                "trigger": reason.trigger.value,
                "score": reason.score,
                "summary": reason.summary,
                "metadata": reason.metadata,
            }
            for reason in decision.reasons
        ],
    }


def _safeguard_assessment_to_dict(assessment: SafeguardAssessment) -> dict[str, Any]:
    return {
        "brain_name": assessment.brain_name,
        "invocation_id": assessment.invocation_id,
        "advisory_disposition": assessment.advisory_disposition.value,
        "highest_severity": None
        if assessment.highest_severity is None
        else assessment.highest_severity.value,
        "finding_codes": assessment.finding_codes(),
        "policy_tags": assessment.policy_tags(),
        "findings": [
            {
                "finding_id": finding.finding_id,
                "code": finding.code,
                "severity": finding.severity.value,
                "summary": finding.summary,
                "policy_tags": finding.policy_tags,
                "confidence": finding.confidence,
                "uncertainty": finding.uncertainty,
                "evidence": [
                    {
                        "kind": evidence.kind.value,
                        "value": evidence.value,
                        "locator": evidence.locator,
                        "excerpt": evidence.excerpt,
                        "metadata": evidence.metadata,
                    }
                    for evidence in finding.evidence
                ],
                "metadata": finding.metadata,
            }
            for finding in assessment.findings
        ],
        "metadata": assessment.metadata,
    }


def _evaluation_status_from_findings(
    findings: tuple[EvaluationFinding, ...],
) -> EvaluationStatus:
    severities = {finding.severity for finding in findings}
    if EvaluationSeverity.ERROR in severities:
        return EvaluationStatus.FAILED
    if EvaluationSeverity.WARNING in severities:
        return EvaluationStatus.NEEDS_REVIEW
    return EvaluationStatus.PASSED


def _evaluation_score_for_status(status: EvaluationStatus) -> float:
    if status == EvaluationStatus.PASSED:
        return 1.0
    if status == EvaluationStatus.NEEDS_REVIEW:
        return 0.5
    return 0.0


def _sentinel_highest_severity(report: SentinelReport) -> SentinelSeverity:
    highest = report.highest_severity()
    if highest is None:
        return SentinelSeverity.INFO
    return highest


def _materialized_artifact_payload(
    *,
    artifact_name: str,
    pack_name: str,
    task: TaskRecord,
    pack_result: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if isinstance(pack_result.data, dict):
        payload.update(pack_result.data)

    if "pack" in payload and "pack_name" not in payload:
        payload["pack_name"] = payload.pop("pack")

    payload.setdefault("pack_name", pack_name)
    payload.setdefault("task_id", task.request.task_id)
    payload.setdefault("task_kind", task.request.kind.value)
    payload.setdefault("artifact_name", artifact_name)
    payload.setdefault("summary", pack_result.summary)
    payload.setdefault("metrics", pack_result.metrics)
    return payload


def _safe_json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _build_governance_observations(
    *,
    governance_preflight: RuntimeGovernancePreflightResult | None,
    approval_resolution: RuntimeApprovalResolution | None,
    executed: bool,
) -> tuple[dict[str, object], ...]:
    if governance_preflight is None:
        return ()

    approval_required = (
        False if approval_resolution is None else approval_resolution.required
    )
    approval_satisfied = (
        False if approval_resolution is None else approval_resolution.satisfied
    )

    if not approval_required:
        approval_satisfied = False

    return (
        {
            "action": "runtime_pack_dispatch",
            "decision": governance_preflight.decision.decision.value,
            "executed": executed,
            "approval_required": approval_required,
            "approval_satisfied": approval_satisfied,
            "source": "runtime",
            "reason": governance_preflight.decision.rationale,
        },
    )


def _explicit_deep_reasoning_requested(prompt: str) -> bool:
    normalized = prompt.strip().lower()
    indicators = (
        "deep reasoning",
        "reason deeply",
        "think hard",
        "step by step",
        "carefully reason",
        "heavy reasoning",
    )
    return any(indicator in normalized for indicator in indicators)


def _coerce_non_negative_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(parsed, 0)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
